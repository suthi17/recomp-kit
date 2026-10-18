#include "seh.h"
#include "loader.h"

// From the generated table (tools/recomp/translate.py); absent in hosts
// without one.
// Weak defaults, which the generated table replaces.
extern "C" {
extern const uint32_t recomp_operand_redirect_pairs[];
extern const uint32_t recomp_operand_redirect_count;
__attribute__((weak)) const uint32_t recomp_operand_redirect_pairs[2] = {0, 0};
__attribute__((weak)) const uint32_t recomp_operand_redirect_count = 0;
extern const uint32_t recomp_data_seed_pairs[];
extern const uint32_t recomp_data_seed_count;
__attribute__((weak)) const uint32_t recomp_data_seed_pairs[2] = {0, 0};
__attribute__((weak)) const uint32_t recomp_data_seed_count = 0;
}
#include "memory.h"
#include "imports.h"
#include "win32.h"
#include "layout.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <vector>
#include <string>
#include <algorithm>
#include "../platform/os.h"

const char *const LOADER_DEFAULT_EXE = RECOMP_DEVELOPER_EXE;
// The digest of the image actually mapped, recorded by loader_load.
static std::string g_exe_sha;

const char *const LOADER_EXPECTED_SHA256 = RECOMP_EXE_SHA256;

namespace {

std::string g_error;
std::string g_exe_path;
uint32_t g_base = 0, g_size = 0, g_entry = 0, g_iat_patched = 0, g_iat_data = 0;
std::vector<SectionInfo> g_sections;
LoaderModule g_main;
X86 g_ctx;
LoaderTls g_tls = {0, 0, 0, 0, 0, 0xffffffffu};

// --------------------------------------------------------------------------
// SHA-256 (FIPS 180-4), just enough to fingerprint the image.
// --------------------------------------------------------------------------
struct Sha256 {
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint64_t len = 0;
    uint8_t buf[64];
    size_t have = 0;

    static uint32_t ror(uint32_t x, int n) {
        return (x >> n) | (x << (32 - n));
    }

    void block(const uint8_t *p) {
        static const uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2};
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
                   ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + k[i] + w[i];
            uint32_t S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }

    void update(const uint8_t *p, size_t n) {
        len += n;
        while (n) {
            size_t take = 64 - have;
            if (take > n)
                take = n;
            memcpy(buf + have, p, take);
            have += take;
            p += take;
            n -= take;
            if (have == 64) {
                block(buf);
                have = 0;
            }
        }
    }

    std::string hex() {
        uint64_t bits = len * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t z = 0;
        while (have != 56)
            update(&z, 1);
        uint8_t tail[8];
        for (int i = 0; i < 8; ++i)
            tail[i] = (uint8_t)(bits >> (56 - 8 * i));
        update(tail, 8);
        char out[65];
        for (int i = 0; i < 8; ++i)
            snprintf(out + i * 8, 9, "%08x", h[i]);
        return std::string(out, 64);
    }
};

std::string sha256_hex(const std::vector<uint8_t> &data) {
    Sha256 s;
    s.update(data.data(), data.size());
    return s.hex();
}

bool read_file(const char *path, std::vector<uint8_t> &out) {
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0) {
        fclose(f);
        return false;
    }
    out.resize((size_t)n);
    size_t got = fread(out.data(), 1, (size_t)n, f);
    fclose(f);
    return got == (size_t)n;
}

std::string dirname_of(const std::string &p) {
    size_t s = p.find_last_of("\\/");
    if (s == std::string::npos)
        return ".";
    if (s == 0)
        return "/";
    return p.substr(0, s);
}

template <typename T> T rd(const std::vector<uint8_t> &d, size_t off) {
    T v{};
    if (off + sizeof(T) <= d.size())
        memcpy(&v, d.data() + off, sizeof(T));
    return v;
}

// True when [rva, rva+len) lies inside an image of `size` bytes.
bool rva_in(uint32_t size, uint32_t rva, uint32_t len) {
    return rva < size && len <= size - rva;
}
// True when [rva, rva+len) lies inside the mapped main image.
bool rva_ok(uint32_t rva, uint32_t len) {
    return rva_in(g_size, rva, len);
}

// Resolve the PE import table of the image mapped at [base, base+size) to
// another mapped module's exports, runtime trampolines or registered guest data
// storage. Every module is mapped before any is bound, so an import from a
// module later in the configuration binds to its export like any other. Bound
// every descriptor and RVA by the image before reading or patching it.
// `imports` receives the mapped modules the image imports, in import order.
bool patch_iat(uint32_t g_base, uint32_t g_size, uint32_t imp_rva, uint32_t imp_size,
               std::vector<std::string> *imports) {
    auto rva_ok = [g_size](uint32_t rva, uint32_t len) { return rva_in(g_size, rva, len); };
    if (!imp_rva || !imp_size) {
        // A self-contained auxiliary module (pure code, no imports) is fine;
        // the game's executable always imports at least kernel32.
        if (g_base != loader_image_base())
            return true;
        g_error = "image has no import directory";
        return false;
    }
    if (!rva_ok(imp_rva, imp_size)) {
        g_error = "import directory lies outside the image";
        return false;
    }

    // One descriptor per DLL, bounded by the directory size.
    uint32_t max_desc = imp_size / 20 + 1;
    uint32_t desc_rva = imp_rva;
    for (uint32_t d = 0; d < max_desc; ++d, desc_rva += 20) {
        if (!rva_ok(desc_rva, 20)) {
            g_error = "import descriptor runs past the image";
            return false;
        }
        uint32_t desc = g_base + desc_rva;
        uint32_t orig_thunk = rd32(desc + 0);
        uint32_t name_rva = rd32(desc + 12);
        uint32_t first_thunk = rd32(desc + 16);
        if (!name_rva && !first_thunk && !orig_thunk)
            break;
        if (!rva_ok(name_rva, 1) || !rva_ok(first_thunk, 4)) {
            g_error = "import descriptor points outside the image";
            return false;
        }
        std::string dll = gm_str(g_base + name_rva, 260);
        if (const LoaderModule *module = loader_module_named(dll.c_str()))
            if (imports && module->base != g_base &&
                std::find(imports->begin(), imports->end(), module->name) == imports->end())
                imports->push_back(module->name);

        uint32_t lookup_rva = orig_thunk ? orig_thunk : first_thunk;
        uint32_t slot_rva = first_thunk;
        for (;; lookup_rva += 4, slot_rva += 4) {
            if (!rva_ok(lookup_rva, 4) || !rva_ok(slot_rva, 4)) {
                g_error = "import thunk array runs past the image";
                return false;
            }
            uint32_t lookup = g_base + lookup_rva;
            uint32_t slot = g_base + slot_rva;
            uint32_t t = rd32(lookup);
            if (!t)
                break;
            // C++ decorations run long (512 characters in one game's engine):
            // a name is read whole, never cut at MAX_PATH, or two exports that
            // share a long prefix would bind to whichever comes first.
            char namebuf[4096];
            if (t & 0x80000000u) {
                snprintf(namebuf, sizeof namebuf, "ord%u", t & 0xffff);
                // A Winsock ordinal is a documented export: bind it by that name,
                // where its shim and stdcall count are, unless a shim answers to
                // the ordinal itself.
                if (!imports_has_shim(dll.c_str(), namebuf))
                    if (const char *known = imports_ordinal_name(dll.c_str(), t & 0xffff))
                        snprintf(namebuf, sizeof namebuf, "%s", known);
            } else {
                if (!rva_ok(t, 3)) {
                    g_error = "import name lies outside the image";
                    return false;
                }
                std::string n = gm_str(g_base + t + 2, sizeof namebuf - 1);
                snprintf(namebuf, sizeof namebuf, "%s", n.c_str());
            }
            // DLLs can import code AND data from the executable. Both slots
            // must hold the original guest address, not a host trampoline or
            // a separately allocated copy of an exported global.
            if (const LoaderModule *module = loader_module_named(dll.c_str())) {
                uint32_t address = (t & 0x80000000u)
                                       ? loader_module_export_ordinal(*module, t & 0xffff)
                                       : loader_module_export(*module, namebuf);
                if (!address) {
                    g_error = "missing mapped export " + dll + "!" + namebuf;
                    return false;
                }
                wr32(slot, address);
                ++g_iat_patched;
                continue;
            }
            uint32_t data = imports_alloc_data(dll.c_str(), namebuf);
            if (data) {
                // An imported variable, not a function: the slot holds the
                // address of zeroed guest storage.
                wr32(slot, data);
                ++g_iat_patched;
                ++g_iat_data;
                continue;
            }
            uint32_t tramp = imports_alloc_trampoline(dll.c_str(), namebuf, nullptr, ARGC_UNKNOWN);
            if (!tramp) {
                g_error = "ran out of import trampolines";
                return false;
            }
            wr32(slot, tramp);
            ++g_iat_patched;
        }
    }
    return true;
}

// Applies the base relocations of the image mapped at [base, base+size) for a
// load `delta` bytes away from its preferred base: the .reloc blocks name every
// place the linker stored an absolute address. HIGHLOW (3) is what a 32-bit
// image uses; HIGH (1) and LOW (2) are handled for completeness and ABSOLUTE
// (0) is block padding. Anything else, or a block that leaves the table or the
// image, fails the load rather than leave an address half moved.
bool apply_relocations(uint32_t base, uint32_t size, uint32_t delta, uint32_t reloc_rva,
                       uint32_t reloc_size, uint32_t *applied) {
    *applied = 0;
    // No table at all is an image with no absolute addresses in it (or one
    // flagged as stripped, which the caller has refused already).
    if (!delta || !reloc_rva || !reloc_size)
        return true;
    if (!rva_in(size, reloc_rva, reloc_size)) {
        g_error = "has a relocation table outside the image";
        return false;
    }
    uint32_t off = 0;
    while (off + 8 <= reloc_size) {
        const uint32_t block = base + reloc_rva + off;
        const uint32_t page = rd32(block), bytes = rd32(block + 4);
        if (bytes < 8 || bytes > reloc_size - off) {
            if (bytes == 0)
                break; // a zero block ends some linkers' tables early
            g_error = "has a relocation block that runs past its table";
            return false;
        }
        for (uint32_t k = 8; k + 2 <= bytes; k += 2) {
            const uint16_t e = rd16(block + k);
            const uint32_t type = e >> 12, rva = page + (e & 0xfffu);
            if (type == 0)
                continue;
            const uint32_t width = type == 3 ? 4 : 2;
            if (!rva_in(size, rva, width)) {
                g_error = "has a relocation outside the image";
                return false;
            }
            const uint32_t at = base + rva;
            if (type == 3)
                wr32(at, rd32(at) + delta);
            else if (type == 2)
                wr16(at, (uint16_t)(rd16(at) + (delta & 0xffffu)));
            else if (type == 1)
                wr16(at, (uint16_t)(rd16(at) + (delta >> 16)));
            else {
                char buf[96];
                snprintf(buf, sizeof buf, "has relocation type %u, which a PE32 load cannot apply",
                         type);
                g_error = buf;
                return false;
            }
            ++*applied;
        }
        off += bytes;
    }
    return true;
}

// The TLS directory of the image mapped at [base, base+size), validated; a
// directory-less image gets index 0xffffffff and zero fields.
bool read_tls_directory(uint32_t base, uint32_t size, uint32_t tls_rva, uint32_t tls_size,
                        LoaderTls *out) {
    *out = LoaderTls{0, 0, 0, 0, 0, 0xffffffffu};
    if (!tls_rva)
        return true;
    if (tls_size < 24 || !rva_in(size, tls_rva, tls_size)) {
        g_error = "TLS directory is truncated or lies outside the image";
        return false;
    }
    const uint32_t d = base + tls_rva;
    out->raw_start = rd32(d + 0);
    out->raw_end = rd32(d + 4);
    out->index_addr = rd32(d + 8);
    out->callbacks = rd32(d + 12);
    out->zero_fill = rd32(d + 16);
    if (out->raw_end < out->raw_start ||
        (out->raw_end > out->raw_start &&
         !rva_in(size, out->raw_start - base, out->raw_end - out->raw_start)) ||
        !rva_in(size, out->index_addr - base, 4) ||
        (out->callbacks && !rva_in(size, out->callbacks - base, 4))) {
        g_error = "TLS directory points outside the image";
        return false;
    }
    return true;
}

// --------------------------------------------------------------------------
// Auxiliary modules: DLLs game.toml names, mapped beside the main image at
// their configured base - relocated there when the PE prefers another - and
// verified by content hash like it. Preserve configured installation
// subfolders when the executable and its game directory have moved onto
// another device.
// --------------------------------------------------------------------------
const LoaderModuleSpec g_aux_specs[] = RECOMP_AUX_MODULES;
std::vector<LoaderModule> g_aux;

// A digest the module may have: its configured sha256 or one of accept_sha256.
static bool digest_accepted(const LoaderModuleSpec &spec, const std::string &digest) {
    if (digest == spec.sha256)
        return true;
    if (!spec.accept_sha256)
        return false;
    const std::string list = spec.accept_sha256;
    size_t pos = 0;
    while (pos < list.size()) {
        size_t end = list.find(' ', pos);
        if (end == std::string::npos)
            end = list.size();
        if (end > pos && list.compare(pos, end - pos, digest) == 0)
            return true;
        pos = end + 1;
    }
    return false;
}

bool load_aux_module(const LoaderModuleSpec &spec) {
    LoaderModule m;
    m.name = spec.name;
    std::vector<uint8_t> file;
    // The player's profile overlays the install: a module placed there (a
    // replaced language DLL) is taken first, under the same hash gate.
    const std::string &profile = host_layout().profile_dir;
    bool have = false;
    if (!profile.empty()) {
        m.path = profile + "/" + spec.name;
        have = read_file(m.path.c_str(), file);
    }
    if (!have)
        m.path = dirname_of(g_exe_path) + "/" + spec.name;
    if (!have && !read_file(m.path.c_str(), file)) {
        const std::string root = std::string(RECOMP_DEVELOPER_GAME_DIR) + "/";
        const std::string configured = spec.path;
        bool found = false;
        if (configured.compare(0, root.size(), root) == 0) {
            m.path = dirname_of(g_exe_path) + "/" + configured.substr(root.size());
            found = read_file(m.path.c_str(), file);
        }
        if (!found) {
            // Modules kept outside the install still have a developer fallback.
            m.path = configured;
            found = read_file(m.path.c_str(), file);
        }
        if (!found) {
            g_error =
                std::string("cannot read auxiliary module ") + spec.name + " beside " + g_exe_path;
            return false;
        }
    }
    std::string digest = sha256_hex(file);
    if (!digest_accepted(spec, digest)) {
        g_error = m.path + " has SHA-256 " + digest + ", expected " + spec.sha256;
        if (spec.accept_sha256)
            g_error += std::string(" (or ") + spec.accept_sha256 + ")";
        return false;
    }
    if (file.size() < 0x40 || rd<uint16_t>(file, 0) != 0x5a4d) {
        g_error = m.path + " is not an MZ image";
        return false;
    }
    uint32_t pe_off = rd<uint32_t>(file, 0x3c);
    if (pe_off + 24 > file.size() || rd<uint32_t>(file, pe_off) != 0x00004550) {
        g_error = m.path + " is not a PE image";
        return false;
    }
    size_t fh_off = pe_off + 4;
    uint16_t nsections = rd<uint16_t>(file, fh_off + 2);
    uint16_t opt_size = rd<uint16_t>(file, fh_off + 16);
    size_t opt_off = fh_off + 20;
    uint16_t opt_magic = rd<uint16_t>(file, opt_off);
    if (opt_magic != 0x10b || opt_size < 96) {
        g_error = m.path + " is not a PE32 image";
        return false;
    }
    size_t sh_off = opt_off + opt_size;
    if (nsections == 0 || sh_off + 40ull * nsections > file.size()) {
        g_error = m.path + " has a truncated section table";
        return false;
    }
    uint32_t entry_rva = rd<uint32_t>(file, opt_off + 16);
    const uint32_t preferred = rd<uint32_t>(file, opt_off + 28);
    const uint32_t image_base = spec.base; // relocated there below when they differ
    uint32_t size_image = rd<uint32_t>(file, opt_off + 56);
    uint32_t size_hdrs = rd<uint32_t>(file, opt_off + 60);
    const uint32_t ndirs = opt_size >= 96 ? rd<uint32_t>(file, opt_off + 92) : 0;
    auto dir = [&](uint32_t i, uint32_t field) -> uint32_t {
        return i < ndirs && 96 + 8 * i + 8 <= opt_size
                   ? rd<uint32_t>(file, opt_off + 96 + 8 * i + field)
                   : 0;
    };
    if (preferred != spec.base && (rd<uint16_t>(file, fh_off + 18) & 0x0001u)) {
        char buf[200];
        snprintf(buf, sizeof buf,
                 "%s: image base %08x is not the configured %08x and the image has no "
                 "relocations to move it",
                 spec.name, preferred, spec.base);
        g_error = buf;
        return false;
    }
    if (size_image > spec.size || image_base < GUEST_SHIM_END ||
        (uint64_t)image_base + spec.size > GUEST_SIZE) {
        char buf[200];
        snprintf(
            buf, sizeof buf,
            "%s: [%08x, %08x) does not fit the configured [%08x, %08x) above the arena's shims",
            spec.name, image_base, image_base + size_image, spec.base, spec.base + spec.size);
        g_error = buf;
        return false;
    }
    for (const LoaderModule &other : g_aux)
        if (image_base < other.base + other.size && other.base < image_base + spec.size) {
            g_error = std::string(spec.name) + " overlaps " + other.name;
            return false;
        }
    if (image_base < g_base + g_size && g_base < image_base + spec.size) {
        g_error = std::string(spec.name) + " overlaps the main image";
        return false;
    }
    m.base = image_base;
    m.size = spec.size;
    m.entry = entry_rva ? image_base + entry_rva : 0;
    m.attached = false;
    m.preferred_base = preferred;
    m.is_dll = (rd<uint16_t>(file, fh_off + 18) & 0x2000u) != 0;
    m.export_rva = dir(0, 0);
    m.export_size = dir(0, 4);
    m.import_rva = dir(1, 0);
    m.import_size = dir(1, 4);
    if (m.export_rva && !rva_in(size_image, m.export_rva, m.export_size)) {
        g_error = std::string(spec.name) + ": export directory lies outside the image";
        return false;
    }
    if (m.import_rva && !rva_in(size_image, m.import_rva, m.import_size)) {
        g_error = std::string(spec.name) + ": import directory lies outside the image";
        return false;
    }
    if (!mem_commit(image_base, spec.size)) {
        g_error = std::string(spec.name) + ": cannot open its range of the guest arena";
        return false;
    }

    size_t hdr_copy = size_hdrs < file.size() ? size_hdrs : file.size();
    memcpy(g_mem + image_base, file.data(), hdr_copy);
    for (uint16_t i = 0; i < nsections; ++i) {
        size_t s = sh_off + 40 * i;
        char nm[9] = {0};
        memcpy(nm, file.data() + s, 8);
        uint32_t vsize = rd<uint32_t>(file, s + 8);
        uint32_t va = image_base + rd<uint32_t>(file, s + 12);
        uint32_t raw_size = rd<uint32_t>(file, s + 16);
        uint32_t raw_ptr = rd<uint32_t>(file, s + 20);
        uint32_t span = vsize ? vsize : raw_size;
        m.sections.push_back({nm, va, vsize, raw_size, raw_ptr, rd<uint32_t>(file, s + 36)});
        if (va < image_base || (uint64_t)va + span > (uint64_t)image_base + size_image) {
            g_error = std::string(spec.name) + ": section " + nm + " lies outside the image";
            return false;
        }
        uint32_t copy = raw_size;
        if (vsize && copy > vsize)
            copy = vsize;
        if (raw_ptr && copy) {
            if ((uint64_t)raw_ptr + copy > file.size()) {
                g_error = std::string(spec.name) + ": section " + nm + " raw data is truncated";
                return false;
            }
            memcpy(g_mem + va, file.data() + raw_ptr, copy);
        }
    }
    if (!apply_relocations(image_base, size_image, image_base - preferred, dir(5, 0), dir(5, 4),
                           &m.relocations) ||
        !read_tls_directory(image_base, size_image, dir(9, 0), dir(9, 4), &m.tls)) {
        g_error = std::string(spec.name) + ": " + g_error;
        return false;
    }
    // Imports are bound, and the pristine image snapshotted, once every
    // module is mapped (bind_modules).
    g_aux.push_back(m);
    LOGV("mapped auxiliary module %s: base %08x (prefers %08x, %u relocations) size %08x entry "
         "%08x",
         spec.name, m.base, preferred, m.relocations, size_image, m.entry);
    return true;
}

// Binds every mapped image's imports - the main image's and each module's -
// now that all of them exist, then keeps each module's pristine image.
bool bind_modules() {
    g_main.imports.clear();
    if (!patch_iat(g_base, g_size, g_main.import_rva, g_main.import_size, &g_main.imports))
        return false;
    for (LoaderModule &m : g_aux) {
        m.imports.clear();
        if (!patch_iat(m.base, m.size, m.import_rva, m.import_size, &m.imports)) {
            g_error = m.name + ": " + g_error;
            return false;
        }
        m.initial_image.assign(g_mem + m.base, g_mem + m.base + m.size);
    }
    return true;
}

} // namespace

uint32_t loader_module_count() {
    return (uint32_t)g_aux.size();
}
const LoaderModule *loader_module(uint32_t i) {
    return i < g_aux.size() ? &g_aux[i] : nullptr;
}
LoaderModule *loader_module_named(const char *name) {
    if (!name)
        return nullptr;
    if (g_main.base && os_strcasecmp(g_main.name.c_str(), name) == 0)
        return &g_main;
    for (LoaderModule &m : g_aux)
        if (os_strcasecmp(m.name.c_str(), name) == 0)
            return &m;
    return nullptr;
}
const LoaderModule *loader_module_containing(uint32_t addr) {
    if (g_main.base && addr >= g_main.base && addr - g_main.base < g_main.size)
        return &g_main;
    for (const LoaderModule &m : g_aux)
        if (addr >= m.base && addr < m.base + m.size)
            return &m;
    return nullptr;
}
bool loader_in_image(uint32_t addr) {
    return (addr >= g_base && addr < g_base + g_size) || loader_module_containing(addr) != nullptr;
}

// The PE export directory read from guest memory, so a lookup sees the mapped
// bytes. Names are compared case sensitively, as GetProcAddress does.
uint32_t loader_module_export(const LoaderModule &m, const char *name) {
    if (!m.export_rva || !name || !rva_in(m.size, m.export_rva, 40))
        return 0;
    auto in = [&](uint32_t rva, uint32_t len) { return rva_in(m.size, rva, len); };
    uint32_t dir = m.base + m.export_rva;
    uint32_t nfuncs = rd32(dir + 20), nnames = rd32(dir + 24);
    uint32_t funcs = rd32(dir + 28), names = rd32(dir + 32), ords = rd32(dir + 36);
    if (nfuncs > m.size / 4 || nnames > m.size / 4 || !in(funcs, 4 * nfuncs) ||
        !in(names, 4 * nnames) || !in(ords, 2 * nnames))
        return 0;
    for (uint32_t i = 0; i < nnames; ++i) {
        uint32_t name_rva = rd32(m.base + names + 4 * i);
        if (!in(name_rva, 1) ||
            gm_str(m.base + name_rva, std::min(4096u, m.size - name_rva)) != name)
            continue;
        uint32_t ordinal = rd16(m.base + ords + 2 * i);
        if (ordinal >= nfuncs)
            return 0;
        uint32_t rva = rd32(m.base + funcs + 4 * ordinal);
        // A forwarder (an RVA inside the export directory) is not served.
        if (!rva || !in(rva, 1) || rva_in(m.export_size, rva - m.export_rva, 1))
            return 0;
        return m.base + rva;
    }
    return 0;
}

// Ordinals index the same address table as names, offset by the directory's
// ordinal base. Missing entries and forwarded exports are not executable.
uint32_t loader_module_export_ordinal(const LoaderModule &m, uint32_t ordinal) {
    if (!m.export_rva || !rva_in(m.size, m.export_rva, 40))
        return 0;
    uint32_t dir = m.base + m.export_rva;
    uint32_t first = rd32(dir + 16), count = rd32(dir + 20), table = rd32(dir + 28);
    if (ordinal < first || ordinal - first >= count || count > m.size / 4 ||
        !rva_in(m.size, table, 4 * count))
        return 0;
    uint32_t rva = rd32(m.base + table + 4 * (ordinal - first));
    if (!rva || !rva_in(m.size, rva, 1) || rva_in(m.export_size, rva - m.export_rva, 1))
        return 0;
    return m.base + rva;
}

LoaderModule *loader_module_at_base(uint32_t base) {
    if (g_main.base && base == g_main.base)
        return &g_main;
    for (LoaderModule &m : g_aux)
        if (m.base == base)
            return &m;
    return nullptr;
}

// --------------------------------------------------------------------------
// Module lifetimes: DllMain, static TLS and reference counts, in the order the
// Windows loader keeps - dependencies attach before the modules that import
// them and detach after them.
// --------------------------------------------------------------------------
namespace {

uint32_t g_attach_seq = 0;
bool g_detached_all = false;

const uint32_t DLL_PROCESS_DETACH = 0, DLL_PROCESS_ATTACH = 1, DLL_THREAD_ATTACH = 2,
               DLL_THREAD_DETACH = 3;

bool translated(uint32_t addr) {
    return recomp_module_lookup(addr) >= 0 || recomp_index_of(addr) >= 0;
}

// A module's static TLS callbacks for `reason`, then nothing else: the caller
// runs DllMain. A callback no translation covers is skipped with a notice (and
// stops a strict run, through recomp_call).
void run_tls_callbacks(X86 *c, const LoaderModule &m, uint32_t reason, uint32_t reserved) {
    if (m.tls.index == 0xffffffffu || !m.tls.callbacks)
        return;
    for (uint32_t p = m.tls.callbacks; rva_in(m.size, p - m.base, 4); p += 4) {
        const uint32_t cb = rd32(p);
        if (!cb)
            break;
        guest_call(c, cb, m.base, reason, reserved);
    }
}

// DllMain(base, reason, reserved), its result; 1 for a module without an entry
// (a resource DLL) or, outside strict mode, one whose entry was not translated.
uint32_t dll_main(X86 *c, const LoaderModule &m, uint32_t reason, uint32_t reserved) {
    if (!m.entry)
        return 1;
    if (!translated(m.entry) && !recomp_strict()) {
        LOGW("%s: DllMain %08x is not translated, not run", m.name.c_str(), m.entry);
        return 1;
    }
    const uint32_t result = guest_call(c, m.entry, m.base, reason, reserved);
    LOGV("%s: DllMain(%08x, %u, %u) at %08x -> %08x (x87 CW %04x)", m.name.c_str(), m.base, reason,
         reserved, m.entry, result, c->fpu_cw);
    return result;
}

// Static TLS for a module being attached: a slot, its index where the image
// reads it, and a block for every live thread.
bool tls_attach(LoaderModule &m) {
    if (m.tls.index_addr == 0 && m.tls.raw_end == m.tls.raw_start && !m.tls.callbacks)
        return true; // no directory
    m.tls.index = tls_reserve_slot();
    if (m.tls.index == 0xffffffffu) {
        g_error = m.name + ": no TLS slot left for its static TLS";
        return false;
    }
    wr32(m.tls.index_addr, m.tls.index);
    for (uint32_t array : win32_thread_tls_arrays())
        if (!loader_tls_block(m.tls, array)) {
            g_error = m.name + ": no guest heap for its static TLS";
            return false;
        }
    return true;
}

void tls_detach(LoaderModule &m) {
    if (m.tls.index == 0xffffffffu)
        return;
    for (uint32_t array : win32_thread_tls_arrays())
        if (uint32_t block = rd32(array + 4 * m.tls.index))
            heap_free(block);
    tls_release_slot(m.tls.index);
    m.tls.index = 0xffffffffu;
}

uint32_t module_release(X86 *c, LoaderModule &m);

// One reference to `m`; attaches it, and first everything it imports, when
// this is its first. `visiting` breaks import cycles, which Windows tolerates
// by attaching the cycle in discovery order. 0 or a Win32 error.
uint32_t module_acquire(X86 *c, LoaderModule &m, std::vector<const LoaderModule *> &visiting,
                        bool pin) {
    if (&m == &g_main && !g_main.is_dll)
        return 0; // an executable is the process, never a DLL
    if (m.attached && m.attach_seq) {
        ++m.load_refs;
        m.pinned = m.pinned || pin;
        return 0;
    }
    if (std::find(visiting.begin(), visiting.end(), &m) != visiting.end())
        return 0; // a cycle: the outer acquisition finishes this one
    visiting.push_back(&m);
    // Dependencies first, each by one reference this module owns until it is
    // unloaded.
    std::vector<LoaderModule *> taken;
    for (const std::string &name : m.imports) {
        LoaderModule *dep = loader_module_named(name.c_str());
        // A module on the way in (an import cycle) is finished by the outer
        // acquisition; taking no reference here keeps the counts balanced.
        if (!dep || dep == &m || std::find(visiting.begin(), visiting.end(), dep) != visiting.end())
            continue;
        if (uint32_t err = module_acquire(c, *dep, visiting, pin)) {
            for (auto it = taken.rbegin(); it != taken.rend(); ++it)
                module_release(c, **it);
            visiting.pop_back();
            return err;
        }
        taken.push_back(dep);
    }
    visiting.pop_back();
    // A module unloaded before starts again from its pristine image, as a
    // fresh mapping of the DLL would.
    if (&m != &g_main && !m.initial_image.empty())
        memcpy(g_mem + m.base, m.initial_image.data(), m.initial_image.size());
    m.thread_calls = true;
    if (!tls_attach(m)) {
        LOGW("%s", g_error.c_str());
        for (auto it = taken.rbegin(); it != taken.rend(); ++it)
            module_release(c, **it);
        return 8; // ERROR_NOT_ENOUGH_MEMORY
    }
    m.attached = true;
    m.load_refs = 1;
    m.pinned = pin;
    m.attach_seq = ++g_attach_seq;
    m.held.clear();
    for (const LoaderModule *dep : taken)
        m.held.push_back(dep->name);
    run_tls_callbacks(c, m, DLL_PROCESS_ATTACH, pin ? 1 : 0);
    if (!dll_main(c, m, DLL_PROCESS_ATTACH, pin ? 1 : 0)) {
        // Windows detaches a DLL whose attach failed, then unloads it.
        dll_main(c, m, DLL_PROCESS_DETACH, 0);
        run_tls_callbacks(c, m, DLL_PROCESS_DETACH, 0);
        tls_detach(m);
        m.attached = false;
        m.load_refs = 0;
        m.attach_seq = 0;
        m.pinned = false;
        m.held.clear();
        for (auto it = taken.rbegin(); it != taken.rend(); ++it)
            module_release(c, **it);
        g_error = m.name + ": DllMain refused DLL_PROCESS_ATTACH";
        return 1114; // ERROR_DLL_INIT_FAILED
    }
    return 0;
}

// One reference less; detaches at zero (never a pinned module), then releases
// what the module imports. The return is the Win32 error, 0 on success.
uint32_t module_release(X86 *c, LoaderModule &m) {
    if ((&m == &g_main && !g_main.is_dll) || !m.attached || !m.load_refs)
        return 6; // ERROR_INVALID_HANDLE
    if (--m.load_refs || m.pinned) {
        if (m.pinned && !m.load_refs)
            m.load_refs = 1; // a static import keeps its own reference
        return 0;
    }
    dll_main(c, m, DLL_PROCESS_DETACH, 0);
    run_tls_callbacks(c, m, DLL_PROCESS_DETACH, 0);
    tls_detach(m);
    m.attached = false;
    m.attach_seq = 0;
    // Exactly the references its attach took, last first.
    const std::vector<std::string> held = std::move(m.held);
    m.held.clear();
    for (auto it = held.rbegin(); it != held.rend(); ++it)
        if (LoaderModule *dep = loader_module_named(it->c_str()))
            module_release(c, *dep);
    return 0;
}

} // namespace

bool loader_attach_static(X86 *c) {
    std::vector<const LoaderModule *> visiting;
    for (const std::string &name : g_main.imports) {
        LoaderModule *m = loader_module_named(name.c_str());
        if (!m || m == &g_main)
            continue;
        if (module_acquire(c, *m, visiting, true)) {
            g_error = "static import " + g_error;
            return false;
        }
    }
    if (g_main.is_dll && !g_main.attach_seq) {
        // A DLL serving as the main image has a DllMain, not a process entry.
        g_main.attach_seq = ++g_attach_seq;
        g_main.pinned = true;
        g_main.load_refs = 1;
        run_tls_callbacks(c, g_main, DLL_PROCESS_ATTACH, 1);
        if (!dll_main(c, g_main, DLL_PROCESS_ATTACH, 1)) {
            g_error = g_main.name + ": DllMain refused DLL_PROCESS_ATTACH";
            return false;
        }
    }
    return true;
}

uint32_t loader_module_load(X86 *c, LoaderModule *m) {
    if (!m)
        return 126; // ERROR_MOD_NOT_FOUND
    if (m == &g_main)
        return 0;
    std::vector<const LoaderModule *> visiting;
    return module_acquire(c, *m, visiting, false);
}

bool loader_module_free(X86 *c, LoaderModule *m) {
    return m && module_release(c, *m) == 0;
}

// Attached modules in attach order.
static std::vector<LoaderModule *> attached_in_order() {
    std::vector<LoaderModule *> v;
    if (g_main.attach_seq)
        v.push_back(&g_main);
    for (LoaderModule &m : g_aux)
        if (m.attached && m.attach_seq)
            v.push_back(&m);
    std::sort(v.begin(), v.end(), [](const LoaderModule *a, const LoaderModule *b) {
        return a->attach_seq < b->attach_seq;
    });
    return v;
}

void loader_thread_notify(X86 *c, uint32_t reason) {
    std::vector<LoaderModule *> order = attached_in_order();
    if (reason == DLL_THREAD_DETACH)
        std::reverse(order.begin(), order.end());
    for (LoaderModule *m : order) {
        run_tls_callbacks(c, *m, reason, 0);
        if (m->thread_calls)
            dll_main(c, *m, reason, 0);
    }
}

void loader_detach_all(X86 *c) {
    if (g_detached_all)
        return;
    g_detached_all = true;
    std::vector<LoaderModule *> order = attached_in_order();
    for (auto it = order.rbegin(); it != order.rend(); ++it) {
        dll_main(c, **it, DLL_PROCESS_DETACH, 1);
        run_tls_callbacks(c, **it, DLL_PROCESS_DETACH, 1);
    }
}

const char *loader_error() {
    return g_error.c_str();
}
uint32_t loader_image_base() {
    return g_base;
}
uint32_t loader_image_size() {
    return g_size;
}
uint32_t loader_image_limit() {
    return g_base && g_size ? g_base + g_size : 0;
}
uint32_t loader_entry_point() {
    return g_entry;
}
const std::vector<SectionInfo> &loader_sections() {
    return g_sections;
}
const std::string &loader_exe_path() {
    return g_exe_path;
}
uint32_t loader_iat_patched() {
    return g_iat_patched;
}
uint32_t loader_iat_data_imports() {
    return g_iat_data;
}
X86 *loader_context() {
    return &g_ctx;
}
const LoaderTls &loader_tls() {
    return g_tls;
}

// Verify the supported executable hash, map PE sections and bind its imports.
// All later address-based translation assumes this exact image; a mismatch is a hard failure.
bool loader_load(const char *exe_path) {
    return loader_load_config(exe_path && *exe_path ? exe_path : LOADER_DEFAULT_EXE,
                              LOADER_EXPECTED_SHA256, g_aux_specs, RECOMP_AUX_MODULE_COUNT);
}

bool loader_load_config(const char *exe_path, const char *expected_sha256,
                        const LoaderModuleSpec *specs, uint32_t spec_count) {
    g_error.clear();
    g_sections.clear();
    g_aux.clear();
    g_main = LoaderModule{};
    g_attach_seq = 0;
    g_detached_all = false;
    g_iat_patched = 0;
    g_iat_data = 0;
    g_exe_path = exe_path && *exe_path ? exe_path : LOADER_DEFAULT_EXE;
    const char *const expected = expected_sha256 ? expected_sha256 : "";

    std::vector<uint8_t> file;
    if (!read_file(g_exe_path.c_str(), file)) {
        g_error = "cannot read " + g_exe_path;
        return false;
    }

    // The content hash is a hard gate: there is no override. Everything below
    // trusts the layout of this exact image.
    std::string digest = sha256_hex(file);
    // Kept so a mod can key its manifest to the exact image it was built
    // against. It is the digest of what was really mapped, not of what was
    // expected, which is why it is recorded here and not made a constant.
    g_exe_sha = digest;
    if (digest != expected) {
        g_error = g_exe_path + " has SHA-256 " + digest + ", expected " + expected;
        return false;
    }

    if (file.size() < 0x40 || rd<uint16_t>(file, 0) != 0x5a4d) {
        g_error = "not an MZ image";
        return false;
    }
    uint32_t pe_off = rd<uint32_t>(file, 0x3c);
    if (pe_off + 24 > file.size() || rd<uint32_t>(file, pe_off) != 0x00004550) {
        g_error = "not a PE image";
        return false;
    }

    size_t fh_off = pe_off + 4;
    uint16_t machine = rd<uint16_t>(file, fh_off + 0);
    uint16_t nsections = rd<uint16_t>(file, fh_off + 2);
    uint16_t opt_size = rd<uint16_t>(file, fh_off + 16);
    size_t opt_off = fh_off + 20;
    if (opt_off + opt_size > file.size() || opt_size < 96) {
        g_error = "PE optional header is truncated";
        return false;
    }
    uint16_t opt_magic = rd<uint16_t>(file, opt_off);
    if (machine != 0x014c || opt_magic != 0x10b) {
        g_error = "expected a 32-bit x86 PE image";
        return false;
    }
    size_t sh_off = opt_off + opt_size;
    if (nsections == 0 || sh_off + 40ull * nsections > file.size()) {
        g_error = "PE section headers are truncated";
        return false;
    }

    uint32_t entry_rva = rd<uint32_t>(file, opt_off + 16);
    // The configured base. A PE that prefers another is relocated there; one
    // whose relocations were stripped (an EXE, usually) cannot be.
    const uint32_t preferred = rd<uint32_t>(file, opt_off + 28);
    const uint32_t image_base = IMAGE_BASE;
    uint32_t size_image = rd<uint32_t>(file, opt_off + 56);
    uint32_t size_hdrs = rd<uint32_t>(file, opt_off + 60);
    const uint16_t file_flags = rd<uint16_t>(file, fh_off + 18);
    const uint32_t ndirs = rd<uint32_t>(file, opt_off + 92);
    auto dir = [&](uint32_t i, uint32_t field) -> uint32_t {
        return i < ndirs && 96 + 8 * i + 8 <= opt_size
                   ? rd<uint32_t>(file, opt_off + 96 + 8 * i + field)
                   : 0;
    };

    if (preferred != image_base && (file_flags & 0x0001u)) {
        char buf[160];
        snprintf(buf, sizeof buf,
                 "image base %08x is not the expected %08x and the image has no relocations to "
                 "move it",
                 preferred, image_base);
        g_error = buf;
        return false;
    }
    // Below the heap, as an executable is; or above the trampolines, where a
    // DLL serving as the main image (a harness without its executable) sits
    // at its own base.
    if ((uint64_t)image_base + size_image > HEAP_BASE &&
        (image_base < GUEST_SHIM_END || (uint64_t)image_base + size_image > GUEST_SIZE)) {
        char buf[160];
        snprintf(buf, sizeof buf,
                 "image ends at %08x, above the heap arena start %08x; raise [game] heap_base",
                 image_base + size_image, HEAP_BASE);
        g_error = buf;
        return false;
    }

    mem_init();
    // Module places are fixed by the configuration, loaded or not: heap growth
    // must never take one.
    mem_reserve_range(image_base, size_image);
    for (uint32_t i = 0; i < spec_count; ++i)
        mem_reserve_range(specs[i].base, specs[i].size);
    if (!mem_commit(image_base, size_image)) {
        g_error = "cannot open the image's range of the guest arena";
        return false;
    }
    g_base = image_base;
    g_size = size_image;
    g_entry = image_base + entry_rva;
    g_main.name = RECOMP_EXECUTABLE;
    g_main.path = g_exe_path;
    g_main.base = g_base;
    g_main.size = g_size;
    g_main.entry = g_entry;
    g_main.attached = true; // Its process entry must never run as DllMain.
    g_main.preferred_base = preferred;
    g_main.is_dll = (file_flags & 0x2000u) != 0;
    g_main.import_rva = dir(1, 0);
    g_main.import_size = dir(1, 4);
    if (g_main.import_rva && !rva_in(g_size, g_main.import_rva, g_main.import_size)) {
        g_error = "import directory lies outside the image";
        return false;
    }
    if (opt_size >= 104 && rd<uint32_t>(file, opt_off + 92) > 0) {
        g_main.export_rva = rd<uint32_t>(file, opt_off + 96);
        g_main.export_size = rd<uint32_t>(file, opt_off + 100);
        if (g_main.export_rva && !rva_in(g_size, g_main.export_rva, g_main.export_size)) {
            g_error = "main export directory lies outside the image";
            return false;
        }
    }

    // PE headers, then each section at its virtual address. The arena is zero
    // filled by mmap, so the tail of a section past SizeOfRawData (.bss) is
    // already zero.
    size_t hdr_copy = size_hdrs < file.size() ? size_hdrs : file.size();
    memcpy(g_mem + g_base, file.data(), hdr_copy);

    for (uint16_t i = 0; i < nsections; ++i) {
        size_t s = sh_off + 40 * i;
        char nm[9] = {0};
        memcpy(nm, file.data() + s, 8);
        SectionInfo si;
        si.name = nm;
        si.vsize = rd<uint32_t>(file, s + 8);
        si.va = image_base + rd<uint32_t>(file, s + 12);
        si.raw_size = rd<uint32_t>(file, s + 16);
        si.raw_ptr = rd<uint32_t>(file, s + 20);
        si.characteristics = rd<uint32_t>(file, s + 36);

        uint32_t span = si.vsize ? si.vsize : si.raw_size;
        if (si.va < image_base || (uint64_t)si.va + span > (uint64_t)image_base + size_image) {
            g_error = "section " + si.name + " lies outside the image";
            return false;
        }
        uint32_t copy = si.raw_size;
        if (si.vsize && copy > si.vsize)
            copy = si.vsize;
        if (si.raw_ptr && copy) {
            if ((uint64_t)si.raw_ptr + copy > file.size()) {
                g_error = "section " + si.name + " raw data is truncated";
                return false;
            }
            memcpy(g_mem + si.va, file.data() + si.raw_ptr, copy);
        }
        g_sections.push_back(si);
    }
    if (!apply_relocations(image_base, size_image, image_base - preferred, dir(5, 0), dir(5, 4),
                           &g_main.relocations)) {
        g_error = "the image " + g_error;
        return false;
    }

    // game.toml operand_redirects: each new location starts with the value of
    // the one it replaces (8 bytes, enough for a double).
    for (uint32_t i = 0; i < recomp_operand_redirect_count; ++i) {
        uint32_t from = recomp_operand_redirect_pairs[2 * i],
                 to = recomp_operand_redirect_pairs[2 * i + 1];
        if ((uint64_t)from + 8 <= GUEST_SIZE && (uint64_t)to + 8 <= GUEST_SIZE)
            memcpy(g_mem + to, g_mem + from, 8);
    }

    // game.toml data_seeds: slots the translation's patches read.
    for (uint32_t i = 0; i < recomp_data_seed_count; ++i) {
        uint32_t addr = recomp_data_seed_pairs[2 * i];
        if ((uint64_t)addr + 4 <= GUEST_SIZE)
            memcpy(g_mem + addr, &recomp_data_seed_pairs[2 * i + 1], 4);
    }

    imports_init();
    win32_init(dirname_of(g_exe_path));

    // TLS directory (data directory 9). Reserve after win32_init, which clears
    // the slot map, and before IAT binding or any guest code can call TlsAlloc.
    g_tls = LoaderTls{0, 0, 0, 0, 0, 0xffffffffu};
    if (rd<uint32_t>(file, opt_off + 92) > 9) {
        size_t dd_tls = opt_off + 96 + 9 * 8;
        if (opt_size < 96 + 10 * 8) {
            g_error = "PE TLS data directory is truncated";
            return false;
        }
        uint32_t tls_rva = rd<uint32_t>(file, dd_tls);
        uint32_t tls_size = rd<uint32_t>(file, dd_tls + 4);
        if (tls_rva) {
            if (tls_size < 24 || !rva_ok(tls_rva, tls_size)) {
                g_error = "TLS directory is truncated or lies outside the image";
                return false;
            }
            uint32_t d = image_base + tls_rva;
            g_tls.raw_start = rd32(d + 0);
            g_tls.raw_end = rd32(d + 4);
            g_tls.index_addr = rd32(d + 8);
            g_tls.callbacks = rd32(d + 12);
            g_tls.zero_fill = rd32(d + 16);
            if (g_tls.raw_end < g_tls.raw_start ||
                (g_tls.raw_end > g_tls.raw_start &&
                 !rva_ok(g_tls.raw_start - image_base, g_tls.raw_end - g_tls.raw_start)) ||
                !rva_ok(g_tls.index_addr - image_base, 4) ||
                (g_tls.callbacks && !rva_ok(g_tls.callbacks - image_base, 4))) {
                g_error = "TLS directory points outside the image";
                return false;
            }
            g_tls.index = tls_reserve_slot();
            if (g_tls.index == 0xffffffffu) {
                g_error = "no TLS slot available for the image";
                return false;
            }
            wr32(g_tls.index_addr, g_tls.index);
        }
    }

    // RECOMP_IMPORT_STATS=1 prints the implemented / not-reached / logging-only
    // classification at exit, which is how the "not reached" column of the
    // coverage table gets filled in from a real run.
    if (recomp_env("IMPORT_STATS")) {
        static bool hooked = false;
        if (!hooked) {
            hooked = true;
            atexit([] { imports_dump_report(stderr); });
        }
    }

    // Map every module first, then bind every image: the main image's
    // imports from a module (an executable's from its engine DLL) need that
    // module's exports in place, and so do modules importing each other.
    for (uint32_t i = 0; i < spec_count; ++i)
        if (!load_aux_module(specs[i]))
            return false;
    if (!bind_modules())
        return false;
    g_main.tls = g_tls;
    if (recomp_strict()) {
        uint32_t unknown = 0;
        imports_coverage(nullptr, nullptr, &unknown);
        if (unknown)
            LOGW("strict: %u imports have no known stdcall argument count; calling one stops "
                 "the run (RECOMP_IMPORT_STATS=1 lists them)",
                 unknown);
    }

    if (g_entry != LOADER_EXPECTED_ENTRY)
        LOGW("entry point is %08x, expected %08x", g_entry, LOADER_EXPECTED_ENTRY);

    loader_init_context(&g_ctx);
    if (g_tls.index != 0xffffffffu && !rd32(TLS_BASE + 4 * g_tls.index)) {
        g_error = "cannot allocate the main thread TLS block";
        return false;
    }
    LOGV("loaded %s: base %08x size %08x entry %08x, %u IAT slots, %u trampolines",
         g_exe_path.c_str(), g_base, g_size, g_entry, g_iat_patched, imports_count());
    return true;
}

void loader_init_context(X86 *c) {
    recomp_seh_reset(c);
    memset(c, 0, sizeof(*c));
    // Process-start CPU state. The x87 values are the ones Windows gives a new
    // thread: control word GUEST_INITIAL_FPU_CW (0x027f: round to nearest,
    // 53-bit precision, all exceptions masked), clear status word, all-empty
    // tag word. __ftol, __ctrlfp and __statfp diverge immediately if these are
    // wrong.
    x87_set_cw(c, GUEST_INITIAL_FPU_CW);
    c->fpu_sw = 0;
    c->fpu_tag = 0xffff;
    c->fpu_top = 0;
    // EFLAGS with only the reserved bit 1 and IF set, so PUSHFD reads 0x202.
    c->eflags_misc = 0x00000202u;
    c->fs_base = TEB_BASE;

    // TEB: FS:[0] SEH chain head (empty = -1), FS:[4] stack base (high),
    // FS:[8] stack limit (low), FS:[0x18] TEB self pointer, FS:[0x2c] TLS array.
    memset(g_mem + TEB_BASE, 0, TEB_SIZE);
    wr32(TEB_BASE + 0x00, 0xffffffffu);
    wr32(TEB_BASE + 0x04, STACK_TOP);
    wr32(TEB_BASE + 0x08, STACK_LIMIT);
    wr32(TEB_BASE + 0x18, TEB_BASE);
    wr32(TEB_BASE + 0x2c, TLS_BASE);
    wr32(TEB_BASE + 0x30, TEB_BASE - 0x1000); // PEB placeholder (zeroed page)
    memset(g_mem + TLS_BASE, 0, TLS_SLOTS * 4);
    loader_tls_block_for_thread(TLS_BASE);

    // Stack: 16-byte aligned, sentinel return address on top so a RET from the
    // entry point lands somewhere recognisable.
    uint32_t esp = (STACK_TOP - 0x20) & ~0xfu;
    esp -= 4;
    wr32(esp, GUEST_RETURN_SENTINEL);
    c->r[R_ESP] = esp;
    c->r[R_EBP] = 0;
    c->eip = g_entry;
}

const char *loader_exe_sha256() {
    return g_exe_sha.c_str();
}

std::string loader_hash_file(const char *path) {
    std::vector<uint8_t> file;
    if (!path || !read_file(path, file))
        return "";
    return sha256_hex(file);
}

void run_entry(X86 *c) {
    if (!g_entry) {
        LOGW("run_entry: no image loaded");
        return;
    }
    c->eip = g_entry;
    // This is threads()[0], and it is a guest thread for as long as guest code
    // runs on it. Registered rather than inferred, for the reason in
    // kernel32.cpp: t_self defaults to 0, so inference would make every host
    // thread claim to be this one.
    sched_set_guest_thread(true);
    // ExitProcess/TerminateProcess/ExitThread-outside-a-thread longjmp here.
    if (setjmp(*process_exit_jmp()) == 0) {
        // Windows initialises every statically imported DLL, dependencies
        // first, before the image's TLS callbacks and entry point run.
        if (!loader_attach_static(c)) {
            LOGW("process start failed: %s", g_error.c_str());
            sched_set_guest_thread(false);
            return;
        }
        if (g_main.is_dll) {
            // A DLL as the main image: its DllMain was the start; there is no
            // process entry to run.
            sched_set_guest_thread(false);
            return;
        }
        uint32_t count = 0;
        for (uint32_t p = g_tls.callbacks; p && rva_ok(p - g_base, 4); p += 4) {
            uint32_t cb = rd32(p);
            if (!cb)
                break;
            // The guest sees a pushed call frame, never host pointers. Restore
            // ESP explicitly so both caller and callee cleanup leave the entry
            // point's original frame intact.
            uint32_t esp = c->r[R_ESP];
            wr32(esp - 4, 0);
            wr32(esp - 8, 1); // DLL_PROCESS_ATTACH
            wr32(esp - 12, g_base);
            wr32(esp - 16, GUEST_RETURN_SENTINEL);
            c->r[R_ESP] = esp - 16;
            c->eip = cb;
            recomp_run(c, cb);
            c->r[R_ESP] = esp;
            ++count;
        }
        LOGV("ran %u TLS process-attach callbacks", count);
        c->eip = g_entry;
        recomp_run(c, g_entry);
    } else
        LOGW("guest process exited with code %u", process_exit_code());
    sched_set_guest_thread(false);
}

void run_entry() {
    run_entry(&g_ctx);
}
