// msvcrt_stdio.cpp - FILE streams, the _iob table and the file-system calls
// of the C runtime.
//
// A guest FILE is the 32-byte msvcrt structure in guest memory, so a program
// that reads _flag or _file directly (the feof, ferror and _fileno macros)
// sees what it expects; the stream itself is a host descriptor kept beside
// it. Paths resolve through the runtime's guest file system, with the
// operation that is about to happen (read, write, delete), so the CRT sees the
// same files, overlays and case-insensitive matching as CreateFileA does.
//
// Text mode is msvcrt's: CR LF reads as LF and LF writes as CR LF, and a
// Ctrl-Z byte ends the input. Binary mode and _fmode follow fopen's rules.
// Positions are raw file offsets in both modes, as ftell reports on Windows.
//
// stdin is always at end of file. stdout and stderr belong to a program that
// has no console, so what it prints goes nowhere, as it would on Windows;
// RECOMP_CRT_CONSOLE=1 (or RECOMP_LOG=2) copies it to the host's stderr.
#include "msvcrt_internal.h"
#include "kernel32_internal.h"
#include "win32.h"
#include "../platform/os.h"
#include <algorithm>
#include <map>
#include <string>
#include <vector>

namespace crt {
namespace {

// FILE._flag bits.
enum : uint32_t {
    IOREAD = 0x1,
    IOWRT = 0x2,
    IOEOF = 0x10,
    IOERR = 0x20,
    IORW = 0x80,
};
constexpr uint32_t FILE_SIZE = 32;
constexpr uint32_t IOB_ENTRIES = 20;
constexpr uint32_t F_FLAG = 12, F_FILE = 16;

struct Stream {
    int fd = -1;      // host descriptor; -1 for the console streams
    int console = -1; // 0 stdin, 1 stdout, 2 stderr
    bool text = true;
    bool readable = false, writable = false, append = false;
    bool eof = false, err = false;
    bool owned = false; // the FILE block came from fopen and is freed by fclose
    std::string delete_on_close;
    std::vector<uint8_t> rbuf; // raw bytes read ahead from fd
    size_t rpos = 0;
    std::vector<uint8_t> pushback; // ungetc, last in first out
    // The file bytes each pushed-back character stands for: ungetc puts the
    // character where the last one read was, and a CR LF read as '\n' took two
    // bytes, so ftell steps back two. The last read's count is kept for that.
    std::vector<uint8_t> pushback_raw;
    uint8_t last_raw = 1;
    int64_t pushback_bytes() const {
        int64_t n = 0;
        for (uint8_t r : pushback_raw)
            n += r;
        return n;
    }
};

struct Table {
    std::map<uint32_t, Stream> streams; // keyed by the guest FILE address
    uint32_t iob = 0;
    uint32_t epoch = 0;
    int next_fd = 3;
};
Table &table() {
    static auto *t = new Table();
    return *t;
}

void sync_flags(uint32_t file, const Stream &s) {
    uint32_t flag = 0;
    if (s.readable && s.writable)
        flag |= IORW;
    else if (s.readable)
        flag |= IOREAD;
    else if (s.writable)
        flag |= IOWRT;
    if (s.eof)
        flag |= IOEOF;
    if (s.err)
        flag |= IOERR;
    wr32(file + F_FLAG, flag);
}

void init_iob(uint32_t addr) {
    Table &t = table();
    t.iob = addr;
    for (int i = 0; i < 3; ++i) {
        uint32_t file = addr + FILE_SIZE * i;
        Stream s;
        s.console = i;
        s.readable = i == 0;
        s.writable = i != 0;
        s.eof = false;
        t.streams[file] = s;
        wr32(file + F_FILE, (uint32_t)i);
        sync_flags(file, t.streams[file]);
    }
}

// The stream behind a guest FILE*, or null. A FILE* the table does not know
// is an error the caller reports as EOF/-1 with errno EBADF... unless it is
// one of the first three _iob entries, which exist before the import is bound
// in a test that never loaded an image.
Stream *stream_of(uint32_t file) {
    Table &t = table();
    auto it = t.streams.find(file);
    if (it != t.streams.end())
        return &it->second;
    set_errno(E_BADF);
    return nullptr;
}

bool console_echo() {
    static const bool on = recomp_env("CRT_CONSOLE") != nullptr;
    return on || log_level() >= 2;
}

// Discards read-ahead so the descriptor's position is the logical one again.
void drop_readahead(Stream &s) {
    size_t unread = (s.rbuf.size() - s.rpos) + (size_t)s.pushback_bytes();
    if (unread && s.fd >= 0)
        os_fd_seek(s.fd, -(int64_t)unread, OS_SEEK_CUR);
    s.rbuf.clear();
    s.rpos = 0;
    s.pushback.clear();
    s.pushback_raw.clear();
}

bool refill(Stream &s) {
    if (s.fd < 0)
        return false;
    s.rbuf.resize(4096);
    int64_t n = os_fd_read(s.fd, s.rbuf.data(), s.rbuf.size());
    if (n < 0) {
        s.err = true;
        n = 0;
    }
    s.rbuf.resize((size_t)n);
    s.rpos = 0;
    return n > 0;
}

int raw_peek(Stream &s) {
    if (s.rpos >= s.rbuf.size() && !refill(s))
        return -1;
    return s.rbuf[s.rpos];
}

// One logical byte, with text-mode translation; -1 at end of file.
int stream_getc(uint32_t file, Stream &s) {
    if (!s.pushback.empty()) {
        int ch = s.pushback.back();
        s.pushback.pop_back();
        s.last_raw = s.pushback_raw.back();
        s.pushback_raw.pop_back();
        return ch;
    }
    if (!s.readable) {
        s.err = true;
        sync_flags(file, s);
        return -1;
    }
    if (s.console >= 0) { // stdin: a program without a console reads nothing
        s.eof = true;
        sync_flags(file, s);
        return -1;
    }
    if (s.eof)
        return -1;
    int ch = raw_peek(s);
    if (ch < 0) {
        s.eof = true;
        sync_flags(file, s);
        return -1;
    }
    if (s.text && ch == 0x1a) {
        // Ctrl-Z ends a text file. msvcrt's read stops there but has already
        // taken the whole chunk from the file, so the position (and ftell) is
        // the end of that chunk and the bytes after the Ctrl-Z are gone until
        // a seek.
        s.rpos = s.rbuf.size();
        s.eof = true;
        sync_flags(file, s);
        return -1;
    }
    ++s.rpos;
    s.last_raw = 1;
    if (s.text && ch == '\r') {
        int next = raw_peek(s);
        if (next == '\n') {
            ++s.rpos;
            s.last_raw = 2;
            return '\n';
        }
    }
    return ch;
}

void stream_ungetc(uint32_t file, Stream &s, int ch) {
    s.pushback.push_back((uint8_t)ch);
    s.pushback_raw.push_back(s.last_raw);
    s.last_raw = 1;
    s.eof = false;
    sync_flags(file, s);
}

int64_t stream_write(uint32_t file, Stream &s, const uint8_t *data, size_t n) {
    if (s.console >= 0) {
        if (!s.writable)
            return -1;
        if (console_echo() && n)
            fprintf(stderr, "%.*s", (int)n, (const char *)data);
        return (int64_t)n;
    }
    if (!s.writable || s.fd < 0) {
        s.err = true;
        sync_flags(file, s);
        return -1;
    }
    drop_readahead(s);
    if (s.append)
        os_fd_seek(s.fd, 0, OS_SEEK_END);
    std::vector<uint8_t> out;
    const uint8_t *p = data;
    size_t len = n;
    if (s.text) {
        out.reserve(n + n / 8);
        for (size_t i = 0; i < n; ++i) {
            if (data[i] == '\n')
                out.push_back('\r');
            out.push_back(data[i]);
        }
        p = out.data();
        len = out.size();
    }
    int64_t w = len ? os_fd_write(s.fd, p, len) : 0;
    if (w != (int64_t)len) {
        s.err = true;
        sync_flags(file, s);
        return -1;
    }
    return (int64_t)n;
}

int64_t stream_tell(Stream &s) {
    if (s.fd < 0)
        return s.console >= 0 ? 0 : -1;
    int64_t pos = os_fd_seek(s.fd, 0, OS_SEEK_CUR);
    if (pos < 0)
        return -1;
    return pos - (int64_t)(s.rbuf.size() - s.rpos) - s.pushback_bytes();
}

int stream_seek(uint32_t file, Stream &s, int64_t off, int whence) {
    if (whence < 0 || whence > 2 || s.fd < 0) {
        set_errno(E_INVAL);
        return -1;
    }
    if (whence == 1) {
        int64_t here = stream_tell(s);
        if (here < 0)
            return -1;
        off += here;
        whence = 0;
    }
    s.rbuf.clear();
    s.rpos = 0;
    s.pushback.clear();
    s.pushback_raw.clear();
    int64_t r = os_fd_seek(s.fd, off, whence == 0 ? OS_SEEK_SET : OS_SEEK_END);
    if (r < 0) {
        set_errno(E_INVAL);
        return -1;
    }
    s.eof = false;
    sync_flags(file, s);
    return 0;
}

// fopen's mode string: r, w, a with + for update, b or t for the
// translation, and the Microsoft letters c, n, S, R, T, D that change
// nothing here.
bool parse_mode(const std::string &mode, Stream &s, int &flags, int &op) {
    if (mode.empty())
        return false;
    switch (mode[0]) {
    case 'r':
        s.readable = true;
        flags = OS_O_RDONLY;
        op = WIN32_FILE_READ;
        break;
    case 'w':
        s.writable = true;
        flags = OS_O_WRONLY | OS_O_CREAT | OS_O_TRUNC;
        op = WIN32_FILE_WRITE;
        break;
    case 'a':
        s.writable = true;
        s.append = true;
        flags = OS_O_WRONLY | OS_O_CREAT;
        op = WIN32_FILE_WRITE;
        break;
    default:
        return false;
    }
    s.text = !(fmode_value() & 0x8000); // _O_BINARY
    for (size_t i = 1; i < mode.size(); ++i) {
        switch (mode[i]) {
        case '+':
            s.readable = s.writable = true;
            flags = (flags & ~(OS_O_WRONLY | OS_O_RDONLY)) | OS_O_RDWR;
            op = WIN32_FILE_WRITE;
            break;
        case 'b':
            s.text = false;
            break;
        case 't':
            s.text = true;
            break;
        default:
            break;
        }
    }
    return true;
}

uint32_t new_file_block(Table &t, Stream &&s) {
    uint32_t file = mem_alloc(FILE_SIZE);
    if (!file)
        return 0;
    memset(g_mem + file, 0, FILE_SIZE);
    s.owned = true;
    wr32(file + F_FILE, (uint32_t)t.next_fd++);
    t.streams[file] = std::move(s);
    sync_flags(file, t.streams[file]);
    return file;
}

void crt_fopen(X86 *c) {
    std::string path(gchars(arg(c, 0)), gstrlen(arg(c, 0)));
    std::string mode(gchars(arg(c, 1)), gstrlen(arg(c, 1)));
    Stream s;
    int flags = 0, op = 0;
    if (!arg(c, 0) || !parse_mode(mode, s, flags, op)) {
        set_errno(E_INVAL);
        set_eax(c, 0);
        return;
    }
    std::string host = win32_host_path_op(path, op);
    if (recomp_env("TRACE_FILES"))
        LOGW("file: fopen \"%s\" (%s) -> \"%s\"", path.c_str(), mode.c_str(), host.c_str());
    OsStat st{};
    if (!host.empty() && os_stat(host.c_str(), &st) == 0 && st.is_dir) {
        set_errno(E_ACCES);
        set_eax(c, 0);
        return;
    }
    int fd = host.empty() ? -1 : os_fd_open(host.c_str(), flags);
    if (fd < 0) {
        set_errno(s.readable && !s.writable ? E_NOENT : E_ACCES);
        LOGV("msvcrt: fopen(\"%s\", \"%s\") failed (host \"%s\")", path.c_str(), mode.c_str(),
             host.c_str());
        set_eax(c, 0);
        return;
    }
    s.fd = fd;
    set_eax(c, new_file_block(table(), std::move(s)));
}

int close_stream(uint32_t file) {
    Table &t = table();
    auto it = t.streams.find(file);
    if (it == t.streams.end()) {
        set_errno(E_BADF);
        return -1;
    }
    Stream &s = it->second;
    int r = s.err ? -1 : 0;
    if (s.fd >= 0 && os_fd_close(s.fd) != 0)
        r = -1;
    if (!s.delete_on_close.empty())
        os_unlink(s.delete_on_close.c_str());
    bool owned = s.owned;
    if (s.console >= 0) {
        s.readable = s.writable = false; // a closed standard stream stays closed
        sync_flags(file, s);
        return r;
    }
    t.streams.erase(it);
    if (owned)
        mem_free(file, "fclose");
    return r;
}

void crt_fclose(X86 *c) {
    set_eax(c, (uint32_t)close_stream(arg(c, 0)));
}

void crt_fflush(X86 *c) {
    uint32_t file = arg(c, 0);
    if (file && !stream_of(file)) {
        set_eax(c, 0xffffffffu);
        return;
    }
    set_eax(c, 0); // writes go straight through; nothing is buffered
}

void crt_fgetc(X86 *c) {
    uint32_t file = arg(c, 0);
    Stream *s = stream_of(file);
    set_eax(c, s ? (uint32_t)stream_getc(file, *s) : 0xffffffffu);
}

void crt_ungetc(X86 *c) {
    int ch = (int)arg(c, 0);
    uint32_t file = arg(c, 1);
    Stream *s = stream_of(file);
    if (!s || ch == -1) {
        set_eax(c, 0xffffffffu);
        return;
    }
    stream_ungetc(file, *s, ch & 0xff);
    set_eax(c, (uint32_t)(ch & 0xff));
}

// char *fgets(char *buf, int n, FILE *f): at most n-1 bytes, through the
// first newline; NULL when nothing was read.
void crt_fgets(X86 *c) {
    uint32_t buf = arg(c, 0), file = arg(c, 2);
    int n = (int)arg(c, 1);
    Stream *s = stream_of(file);
    if (!s || n <= 0 || !buf) {
        set_eax(c, 0);
        return;
    }
    int i = 0;
    while (i < n - 1) {
        int ch = stream_getc(file, *s);
        if (ch < 0) {
            if (i == 0) {
                set_eax(c, 0);
                return;
            }
            break;
        }
        wr8(buf + i++, (uint8_t)ch);
        if (ch == '\n')
            break;
    }
    wr8(buf + i, 0);
    set_eax(c, buf);
}

void crt_fread(X86 *c) {
    uint32_t buf = arg(c, 0), size = arg(c, 1), count = arg(c, 2), file = arg(c, 3);
    Stream *s = stream_of(file);
    uint64_t total = (uint64_t)size * count;
    if (!s || !total || !gm_valid(buf, (uint32_t)std::min<uint64_t>(total, GUEST_SIZE))) {
        set_eax(c, 0);
        return;
    }
    uint64_t got = 0;
    if (!s->text && s->pushback.empty() && s->fd >= 0 && s->readable) {
        // Binary: what is buffered, then straight from the descriptor.
        size_t have = std::min<uint64_t>(s->rbuf.size() - s->rpos, total);
        memcpy(g_mem + buf, s->rbuf.data() + s->rpos, have);
        s->rpos += have;
        got = have;
        while (got < total) {
            int64_t n = os_fd_read(s->fd, g_mem + buf + got, (size_t)(total - got));
            if (n <= 0) {
                if (n < 0)
                    s->err = true;
                else
                    s->eof = true;
                sync_flags(file, *s);
                break;
            }
            got += (uint64_t)n;
        }
    } else {
        while (got < total) {
            int ch = stream_getc(file, *s);
            if (ch < 0)
                break;
            wr8(buf + (uint32_t)got++, (uint8_t)ch);
        }
    }
    set_eax(c, (uint32_t)(got / size));
}

void crt_fwrite(X86 *c) {
    uint32_t buf = arg(c, 0), size = arg(c, 1), count = arg(c, 2), file = arg(c, 3);
    Stream *s = stream_of(file);
    uint64_t total = (uint64_t)size * count;
    if (!s || !total || !gm_valid(buf, (uint32_t)std::min<uint64_t>(total, GUEST_SIZE))) {
        set_eax(c, 0);
        return;
    }
    int64_t n = stream_write(file, *s, g_mem + buf, (size_t)total);
    set_eax(c, n < 0 ? 0 : count);
}

void crt_fputc(X86 *c) {
    uint8_t ch = (uint8_t)arg(c, 0);
    uint32_t file = arg(c, 1);
    Stream *s = stream_of(file);
    set_eax(c, s && stream_write(file, *s, &ch, 1) == 1 ? ch : 0xffffffffu);
}

void crt_fputs(X86 *c) {
    uint32_t str = arg(c, 0), file = arg(c, 1);
    Stream *s = stream_of(file);
    uint32_t len = gstrlen(str);
    set_eax(c, s && stream_write(file, *s, g_mem + str, len) == (int64_t)len ? 0 : 0xffffffffu);
}

// Wide-character stream I/O: a text stream holds multibyte (here single-byte)
// characters converted through LC_CTYPE; a binary stream holds UTF-16 units.
void crt_fgetwc(X86 *c) {
    uint32_t file = arg(c, 0);
    Stream *s = stream_of(file);
    if (!s) {
        set_eax(c, 0xffff);
        return;
    }
    int a = stream_getc(file, *s);
    if (a < 0) {
        set_eax(c, 0xffff); // WEOF
        return;
    }
    if (s->text) {
        set_eax(c, (uint32_t)mb_to_wide((uint8_t)a));
        return;
    }
    int b = stream_getc(file, *s);
    set_eax(c, b < 0 ? 0xffff : (uint32_t)(a | (b << 8)));
}

void crt_fputwc(X86 *c) {
    uint32_t w = arg(c, 0) & 0xffff, file = arg(c, 1);
    Stream *s = stream_of(file);
    if (!s) {
        set_eax(c, 0xffff);
        return;
    }
    uint8_t bytes[2];
    size_t n;
    if (s->text) {
        int b = wide_to_mb(w);
        if (b < 0) {
            set_errno(42); // EILSEQ
            set_eax(c, 0xffff);
            return;
        }
        bytes[0] = (uint8_t)b;
        n = 1;
    } else {
        bytes[0] = (uint8_t)w;
        bytes[1] = (uint8_t)(w >> 8);
        n = 2;
    }
    set_eax(c, stream_write(file, *s, bytes, n) == (int64_t)n ? w : 0xffff);
}

void crt_ungetwc(X86 *c) {
    uint32_t w = arg(c, 0) & 0xffff, file = arg(c, 1);
    Stream *s = stream_of(file);
    if (!s || w == 0xffff) {
        set_eax(c, 0xffff);
        return;
    }
    if (s->text) {
        int b = wide_to_mb(w);
        if (b < 0) {
            set_eax(c, 0xffff);
            return;
        }
        stream_ungetc(file, *s, b);
    } else {
        stream_ungetc(file, *s, (int)(w >> 8));
        stream_ungetc(file, *s, (int)(w & 0xff));
    }
    set_eax(c, w);
}

void crt_fseek(X86 *c) {
    uint32_t file = arg(c, 0);
    Stream *s = stream_of(file);
    set_eax(c,
            s ? (uint32_t)stream_seek(file, *s, (int32_t)arg(c, 1), (int)arg(c, 2)) : 0xffffffffu);
}

void crt_ftell(X86 *c) {
    Stream *s = stream_of(arg(c, 0));
    int64_t pos = s ? stream_tell(*s) : -1;
    set_eax(c, pos < 0 || pos > 0x7fffffff ? 0xffffffffu : (uint32_t)pos);
}

void crt_rewind(X86 *c) {
    uint32_t file = arg(c, 0);
    if (Stream *s = stream_of(file)) {
        stream_seek(file, *s, 0, 0);
        s->err = false;
        sync_flags(file, *s);
    }
}

// fpos_t is a 64-bit offset.
void crt_fgetpos(X86 *c) {
    Stream *s = stream_of(arg(c, 0));
    int64_t pos = s ? stream_tell(*s) : -1;
    if (pos < 0) {
        set_eax(c, 0xffffffffu);
        return;
    }
    wr64(arg(c, 1), (uint64_t)pos);
    set_eax(c, 0);
}

void crt_fsetpos(X86 *c) {
    uint32_t file = arg(c, 0);
    Stream *s = stream_of(file);
    set_eax(c, s ? (uint32_t)stream_seek(file, *s, (int64_t)rd64(arg(c, 1)), 0) : 0xffffffffu);
}

void crt_setvbuf(X86 *c) {
    int mode = (int)arg(c, 2);
    // _IOFBF 0, _IOLBF 0x40, _IONBF 4. Unbuffered I/O is all there is here.
    set_eax(c,
            (stream_of(arg(c, 0)) && (mode == 0 || mode == 0x40 || mode == 4)) ? 0 : 0xffffffffu);
}

// _getw/_putw move an int through the stream a byte at a time, so a text
// stream translates any 0x0a byte in it, as on Windows.
void crt_getw(X86 *c) {
    uint32_t file = arg(c, 0);
    Stream *s = stream_of(file);
    if (!s) {
        set_eax(c, 0xffffffffu);
        return;
    }
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) {
        int ch = stream_getc(file, *s);
        if (ch < 0) {
            set_eax(c, 0xffffffffu);
            return;
        }
        v |= (uint32_t)ch << (8 * i);
    }
    set_eax(c, v);
}

void crt_putw(X86 *c) {
    uint32_t v = arg(c, 0), file = arg(c, 1);
    Stream *s = stream_of(file);
    uint8_t bytes[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24)};
    set_eax(c, s && stream_write(file, *s, bytes, 4) == 4 ? v : 0xffffffffu);
}

void crt_tmpfile(X86 *c) {
    std::string path = std::string(os_temp_dir()) + "/recomp-crt-XXXXXX";
    std::vector<char> buf(path.begin(), path.end());
    buf.push_back(0);
    int fd = os_mkstemp(buf.data());
    if (fd < 0) {
        set_errno(E_ACCES);
        set_eax(c, 0);
        return;
    }
    Stream s;
    s.fd = fd;
    s.readable = s.writable = true;
    s.text = false; // "w+b"
    s.delete_on_close = buf.data();
    set_eax(c, new_file_block(table(), std::move(s)));
}

void crt_remove(X86 *c) {
    std::string path(gchars(arg(c, 0)), gstrlen(arg(c, 0)));
    std::string host = win32_host_path_op(path, WIN32_FILE_DELETE);
    OsStat st{};
    if (host.empty() || os_stat(host.c_str(), &st) != 0) {
        set_errno(E_NOENT);
        set_eax(c, 0xffffffffu);
        return;
    }
    if (st.is_dir || os_unlink(host.c_str()) != 0) {
        set_errno(E_ACCES);
        set_eax(c, 0xffffffffu);
        return;
    }
    win32_invalidate_dir_cache();
    set_eax(c, 0);
}

// int _stat(const char *path, struct _stat *buf): the 36-byte structure of
// the 32-bit time_t CRT. st_dev and st_rdev are the drive number (C: is 2).
void crt_stat(X86 *c) {
    std::string path(gchars(arg(c, 0)), gstrlen(arg(c, 0)));
    uint32_t out = arg(c, 1);
    std::string host = win32_host_path_op(path, WIN32_FILE_READ);
    OsStat st{};
    if (path.empty() || path.find_first_of("*?") != std::string::npos || host.empty() ||
        os_stat(host.c_str(), &st) != 0) {
        set_errno(E_NOENT);
        set_eax(c, 0xffffffffu);
        return;
    }
    uint32_t mode;
    if (st.is_dir) {
        mode = 0x4000 | 0x0100 | 0x0040 | (st.is_readonly ? 0 : 0x0080);
    } else {
        mode = 0x8000 | 0x0100 | (st.is_readonly ? 0 : 0x0080);
        std::string ext = path.size() >= 4 ? path.substr(path.size() - 4) : std::string();
        for (char &ch : ext)
            ch = (char)tolower((unsigned char)ch);
        if (ext == ".exe" || ext == ".com" || ext == ".bat" || ext == ".cmd")
            mode |= 0x0040;
    }
    mode |= (mode & 0x01c0) >> 3;
    mode |= (mode & 0x01c0) >> 6;
    int drive = 2;
    if (path.size() >= 2 && path[1] == ':')
        drive = tolower((unsigned char)path[0]) - 'a';
    memset(g_mem + out, 0, 36);
    wr32(out + 0, (uint32_t)drive);     // st_dev
    wr16(out + 6, (uint16_t)mode);      // st_mode
    wr16(out + 8, 1);                   // st_nlink
    wr32(out + 16, (uint32_t)drive);    // st_rdev
    wr32(out + 20, (uint32_t)st.size);  // st_size
    wr32(out + 24, (uint32_t)st.atime); // st_atime
    wr32(out + 28, (uint32_t)st.mtime); // st_mtime
    wr32(out + 32, (uint32_t)st.ctime); // st_ctime
    set_eax(c, 0);
}

// int _utime(const char *path, struct _utimbuf *times): NULL means now.
void crt_utime(X86 *c) {
    std::string path(gchars(arg(c, 0)), gstrlen(arg(c, 0)));
    uint32_t times = arg(c, 1);
    std::string host = win32_host_path_op(path, WIN32_FILE_WRITE);
    OsStat st{};
    if (host.empty() || os_stat(host.c_str(), &st) != 0) {
        set_errno(E_NOENT);
        set_eax(c, 0xffffffffu);
        return;
    }
    int64_t mtime = times ? (int32_t)rd32(times + 4) : (int64_t)(os_wall_time_us() / 1000000);
    if (os_set_mtime(host.c_str(), mtime) != 0) {
        set_errno(E_ACCES);
        set_eax(c, 0xffffffffu);
        return;
    }
    set_eax(c, 0);
}

// _chmod only toggles the read-only attribute on Windows; succeed for any
// existing file.
void crt_chmod(X86 *c) {
    std::string path(gchars(arg(c, 0)), gstrlen(arg(c, 0)));
    std::string host = win32_host_path_op(path, WIN32_FILE_READ);
    OsStat st{};
    if (host.empty() || os_stat(host.c_str(), &st) != 0) {
        set_errno(E_NOENT);
        set_eax(c, 0xffffffffu);
        return;
    }
    set_eax(c, 0);
}

// char *_fullpath(char *buf, const char *path, size_t max): a NULL buffer is
// allocated (with room for _MAX_PATH).
void crt_fullpath(X86 *c) {
    uint32_t buf = arg(c, 0), path = arg(c, 1), max = arg(c, 2);
    std::string rel = path ? std::string(gchars(path), gstrlen(path)) : std::string();
    if (rel.empty())
        rel = ".";
    std::string full = full_path_named(rel);
    if (!buf) {
        max = std::max<uint32_t>(260, (uint32_t)full.size() + 1);
        buf = mem_alloc(max);
        if (!buf) {
            set_errno(E_NOMEM);
            set_eax(c, 0);
            return;
        }
    }
    if (full.empty() || full.size() + 1 > max) {
        set_errno(E_RANGE);
        set_eax(c, 0);
        return;
    }
    gm_put_str(buf, full.c_str(), max);
    set_eax(c, buf);
}

// fscanf over a stream.
struct FileSource : CharSource {
    uint32_t file;
    Stream &s;
    FileSource(uint32_t f, Stream &st) : file(f), s(st) {}
    int get() override {
        return stream_getc(file, s);
    }
    void unget(int ch) override {
        if (ch >= 0)
            stream_ungetc(file, s, ch);
    }
};
void crt_fscanf(X86 *c) {
    uint32_t file = arg(c, 0);
    Stream *s = stream_of(file);
    if (!s) {
        set_eax(c, 0xffffffffu);
        return;
    }
    FileSource src(file, *s);
    set_eax(c, (uint32_t)scan_guest(src, gchars(arg(c, 1)), c->r[R_ESP] + 12));
}

const ImportShim shims[] = {
    {"msvcrt.dll", "fopen", ARGC_CDECL, crt_fopen},
    {"msvcrt.dll", "fclose", ARGC_CDECL, crt_fclose},
    {"msvcrt.dll", "fflush", ARGC_CDECL, crt_fflush},
    {"msvcrt.dll", "fgetc", ARGC_CDECL, crt_fgetc},
    {"msvcrt.dll", "ungetc", ARGC_CDECL, crt_ungetc},
    {"msvcrt.dll", "fgets", ARGC_CDECL, crt_fgets},
    {"msvcrt.dll", "fread", ARGC_CDECL, crt_fread},
    {"msvcrt.dll", "fwrite", ARGC_CDECL, crt_fwrite},
    {"msvcrt.dll", "fputc", ARGC_CDECL, crt_fputc},
    {"msvcrt.dll", "fputs", ARGC_CDECL, crt_fputs},
    {"msvcrt.dll", "fgetwc", ARGC_CDECL, crt_fgetwc},
    {"msvcrt.dll", "fputwc", ARGC_CDECL, crt_fputwc},
    {"msvcrt.dll", "ungetwc", ARGC_CDECL, crt_ungetwc},
    {"msvcrt.dll", "fseek", ARGC_CDECL, crt_fseek},
    {"msvcrt.dll", "ftell", ARGC_CDECL, crt_ftell},
    {"msvcrt.dll", "rewind", ARGC_CDECL, crt_rewind},
    {"msvcrt.dll", "fgetpos", ARGC_CDECL, crt_fgetpos},
    {"msvcrt.dll", "fsetpos", ARGC_CDECL, crt_fsetpos},
    {"msvcrt.dll", "setvbuf", ARGC_CDECL, crt_setvbuf},
    {"msvcrt.dll", "_getw", ARGC_CDECL, crt_getw},
    {"msvcrt.dll", "_putw", ARGC_CDECL, crt_putw},
    {"msvcrt.dll", "tmpfile", ARGC_CDECL, crt_tmpfile},
    {"msvcrt.dll", "remove", ARGC_CDECL, crt_remove},
    {"msvcrt.dll", "_stat", ARGC_CDECL, crt_stat},
    {"msvcrt.dll", "_utime", ARGC_CDECL, crt_utime},
    {"msvcrt.dll", "_chmod", ARGC_CDECL, crt_chmod},
    {"msvcrt.dll", "_fullpath", ARGC_CDECL, crt_fullpath},
    {"msvcrt.dll", "fscanf", ARGC_CDECL, crt_fscanf},
};

} // namespace

void stdio_reset() {
    Table &t = table();
    for (auto &kv : t.streams) {
        if (kv.second.fd >= 0)
            os_fd_close(kv.second.fd);
        if (!kv.second.delete_on_close.empty())
            os_unlink(kv.second.delete_on_close.c_str());
    }
    t.streams.clear();
    t.iob = 0;
    t.next_fd = 3;
}

void stdio_flush_all() {
    // Writes go straight to the descriptor, so there is nothing to flush.
}

int64_t stdio_write(uint32_t file, const char *data, size_t n) {
    Stream *s = stream_of(file);
    if (!s)
        return -1;
    return stream_write(file, *s, (const uint8_t *)data, n);
}

void register_stdio() {
    imports_register(shims, sizeof shims / sizeof shims[0]);
    imports_register_data_init("msvcrt.dll", "_iob", FILE_SIZE * IOB_ENTRIES, init_iob);
}

} // namespace crt
