// loader_tests.cpp - the multi-module loader on synthetic PE images built here:
// relocation to a configured base, import binding across modules in any
// configuration order, dependency-ordered DllMain and static TLS for static and
// LoadLibrary'd modules, thread notifications, reference counts and failure
// paths; a mapped DLL's resources; file views; Winsock start-up; the rest of
// a 2001 game's kernel32/advapi32/winmm imports; then the
// guarded arena, heap growth, strict mode, the initial x87 control word and
// the import argument counts. Needs no game: every image is
// written to a temporary directory and its DllMain is a native stand-in
// registered as a translated module.
//
//   .venv/bin/python tools/test.py --compile-only && build/recomp/loader_tests
#include "../imports.h"
#include "../loader.h"
#include "../memory.h"
#include "../resources.h"
#include "../win32.h"
#include "../../platform/os.h"
#include "game_config.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>
#include <string>
#include <vector>

static int g_checks = 0, g_failures = 0;

static bool check(bool ok, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static bool check(bool ok, const char *fmt, ...) {
    ++g_checks;
    va_list ap;
    va_start(ap, fmt);
    char msg[512];
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    if (!ok)
        ++g_failures;
    printf("  [%s] %s\n", ok ? "ok" : "FAIL", msg);
    return ok;
}

static void section(const char *s) {
    printf("\n== %s\n", s);
}

// ---------------------------------------------------------------------------
// A minimal PE32 image: headers, then one read/write/execute section at RVA
// 0x1000 holding code stand-ins, data, the export and import directories, the
// base relocations and optionally a TLS directory.
// ---------------------------------------------------------------------------
namespace pe {

const uint32_t SECTION_RVA = 0x1000, SECTION_SIZE = 0x3000, IMAGE_SIZE = 0x4000;
// The export area holds names of C++ length (two of 313 characters).
const uint32_t EXPORTS = 0x2000, IMPORTS = 0x2600, RELOCS = 0x3000, TLS = 0x3800, RSRC = 0x3c00;

struct Import {
    std::string dll;
    std::vector<std::string> names; // "#N" imports ordinal N
};

struct Image {
    uint32_t preferred = 0x10000000;
    bool dll = true, strip = false, tls = false;
    uint32_t entry = 0x1000; // RVA, 0 for none
    std::string name = "image.dll";
    std::vector<std::pair<std::string, uint32_t>> exports; // name, RVA (ordinals from 1)
    std::vector<Import> imports;
    std::vector<uint32_t> relocs; // RVAs of HIGHLOW sites
    std::vector<uint8_t> rsrc;    // a resource directory, laid out for RVA RSRC
    std::vector<uint8_t> sec = std::vector<uint8_t>(SECTION_SIZE);

    uint32_t va(uint32_t rva) const {
        return preferred + rva;
    }
    void put32(uint32_t rva, uint32_t v) {
        memcpy(&sec[rva - SECTION_RVA], &v, 4);
    }
    void put_str(uint32_t rva, const std::string &s) {
        memcpy(&sec[rva - SECTION_RVA], s.c_str(), s.size() + 1);
    }
    // An absolute address of this image stored at `rva`, which the linker
    // would have listed as a relocation.
    void pointer(uint32_t rva, uint32_t target_rva) {
        put32(rva, va(target_rva));
        relocs.push_back(rva);
    }
    // The IAT slot RVA of the k-th name of the d-th imported DLL.
    static uint32_t iat_slot(size_t d, size_t k) {
        return IMPORTS + 0x200 + 0x40 * (uint32_t)d + 4 * (uint32_t)k;
    }
    static uint32_t tls_index_slot() {
        return TLS + 0x60;
    }

    std::vector<uint8_t> build() {
        std::vector<uint32_t> rel = relocs;
        uint32_t dirs[16][2] = {};
        if (!exports.empty()) {
            const uint32_t funcs = EXPORTS + 0x40, names = EXPORTS + 0x100, ords = EXPORTS + 0x180;
            uint32_t str = EXPORTS + 0x200;
            put_str(str, name);
            put32(EXPORTS + 12, str);
            str += (uint32_t)name.size() + 1;
            put32(EXPORTS + 16, 1);
            put32(EXPORTS + 20, (uint32_t)exports.size());
            put32(EXPORTS + 24, (uint32_t)exports.size());
            put32(EXPORTS + 28, funcs);
            put32(EXPORTS + 32, names);
            put32(EXPORTS + 36, ords);
            for (size_t i = 0; i < exports.size(); ++i) {
                put32(funcs + 4 * (uint32_t)i, exports[i].second);
                put32(names + 4 * (uint32_t)i, str);
                uint16_t ord = (uint16_t)i;
                memcpy(&sec[ords + 2 * i - SECTION_RVA], &ord, 2);
                put_str(str, exports[i].first);
                str += (uint32_t)exports[i].first.size() + 1;
            }
            dirs[0][0] = EXPORTS;
            dirs[0][1] = IMPORTS - EXPORTS;
        }
        if (!imports.empty()) {
            uint32_t str = IMPORTS + 0x800;
            for (size_t d = 0; d < imports.size(); ++d) {
                const uint32_t desc = IMPORTS + 20 * (uint32_t)d;
                const uint32_t ilt = IMPORTS + 0x100 + 0x20 * (uint32_t)d;
                put32(desc + 0, ilt);
                put_str(str, imports[d].dll);
                put32(desc + 12, str);
                str += (uint32_t)imports[d].dll.size() + 1;
                put32(desc + 16, iat_slot(d, 0));
                for (size_t k = 0; k < imports[d].names.size(); ++k) {
                    const std::string &n = imports[d].names[k];
                    uint32_t thunk;
                    if (n[0] == '#') {
                        thunk = 0x80000000u | (uint32_t)atoi(n.c_str() + 1);
                    } else {
                        thunk = str;
                        put_str(str + 2, n); // hint 0, then the name
                        str += (uint32_t)n.size() + 4;
                        str = (str + 1) & ~1u;
                    }
                    put32(ilt + 4 * (uint32_t)k, thunk);
                    put32(iat_slot(d, k), thunk);
                }
            }
            dirs[1][0] = IMPORTS;
            dirs[1][1] = 20 * (uint32_t)(imports.size() + 1);
        }
        if (tls) {
            // Directory, raw template, index slot, callback array: all VAs, so
            // all relocated like any other stored address.
            put32(TLS + 0, va(TLS + 0x40));
            put32(TLS + 4, va(TLS + 0x50));
            put32(TLS + 8, va(tls_index_slot()));
            put32(TLS + 12, va(TLS + 0x70));
            put32(TLS + 16, 16); // zero fill
            for (uint32_t i = 0; i < 16; ++i)
                sec[TLS + 0x40 + i - SECTION_RVA] = (uint8_t)(0xa0 + i);
            put32(tls_index_slot(), 0xdead);
            put32(TLS + 0x70, va(0x1080)); // the callback; a null ends the array
            for (uint32_t f : {0u, 4u, 8u, 12u, 0x70u})
                rel.push_back(TLS + f);
            dirs[9][0] = TLS;
            dirs[9][1] = 24;
        }
        if (!rsrc.empty()) {
            memcpy(&sec[RSRC - SECTION_RVA], rsrc.data(), rsrc.size());
            dirs[2][0] = RSRC;
            dirs[2][1] = (uint32_t)rsrc.size();
        }
        if (!rel.empty() && !strip) {
            std::sort(rel.begin(), rel.end());
            uint32_t at = RELOCS;
            for (size_t i = 0; i < rel.size();) {
                const uint32_t page = rel[i] & ~0xfffu;
                const uint32_t block = at;
                at += 8;
                for (; i < rel.size() && (rel[i] & ~0xfffu) == page; ++i) {
                    uint16_t e = (uint16_t)(0x3000 | (rel[i] & 0xfff));
                    memcpy(&sec[at - SECTION_RVA], &e, 2);
                    at += 2;
                }
                if ((at - block) % 4)
                    at += 2; // an ABSOLUTE entry pads the block
                put32(block, page);
                put32(block + 4, at - block);
            }
            dirs[5][0] = RELOCS;
            dirs[5][1] = at - RELOCS;
        }
        // Headers: DOS stub pointer, PE signature, file header, optional
        // header with 16 data directories, one section header.
        std::vector<uint8_t> f(0x400 + SECTION_SIZE);
        auto w16 = [&](size_t o, uint16_t v) { memcpy(&f[o], &v, 2); };
        auto w32 = [&](size_t o, uint32_t v) { memcpy(&f[o], &v, 4); };
        w16(0, 0x5a4d);
        w32(0x3c, 0x40);
        w32(0x40, 0x00004550);
        const size_t fh = 0x44, opt = fh + 20;
        w16(fh + 0, 0x014c);
        w16(fh + 2, 1);
        w16(fh + 16, 224);
        w16(fh + 18, (uint16_t)(0x0102 | (dll ? 0x2000 : 0) | (strip ? 0x0001 : 0)));
        w16(opt + 0, 0x10b);
        w32(opt + 16, entry);
        w32(opt + 28, preferred);
        w32(opt + 32, 0x1000);
        w32(opt + 36, 0x200);
        w32(opt + 56, IMAGE_SIZE);
        w32(opt + 60, 0x400);
        w32(opt + 92, 16);
        for (int i = 0; i < 16; ++i) {
            w32(opt + 96 + 8 * i, dirs[i][0]);
            w32(opt + 100 + 8 * i, dirs[i][1]);
        }
        const size_t sh = opt + 224;
        memcpy(&f[sh], ".text", 5);
        w32(sh + 8, SECTION_SIZE);
        w32(sh + 12, SECTION_RVA);
        w32(sh + 16, SECTION_SIZE);
        w32(sh + 20, 0x400);
        w32(sh + 36, 0xe0000060u);
        memcpy(&f[0x400], sec.data(), sec.size());
        return f;
    }
};

// A resource directory at RVA `rva`: RT_STRING block 1 (strings 0-15) in
// German (0x407) and US English (0x409), string 3 "Hallo" / "Hello", and an
// RT_RCDATA resource named "INTRO" holding "film".
static std::vector<uint8_t> resource_blob(uint32_t rva) {
    std::vector<uint8_t> b(0x130);
    auto w16 = [&](uint32_t o, uint16_t v) { memcpy(&b[o], &v, 2); };
    auto w32 = [&](uint32_t o, uint32_t v) { memcpy(&b[o], &v, 4); };
    auto dir = [&](uint32_t o, uint16_t named, uint16_t ids) {
        w16(o + 12, named);
        w16(o + 14, ids);
    };
    const uint32_t D = 0x80000000u;
    dir(0x000, 0, 2); // types
    w32(0x010, 6), w32(0x014, D | 0x020);
    w32(0x018, 10), w32(0x01c, D | 0x058);
    dir(0x020, 0, 1); // RT_STRING: block 1
    w32(0x030, 1), w32(0x034, D | 0x038);
    dir(0x038, 0, 2); // block 1: languages, ascending
    w32(0x048, 0x407), w32(0x04c, 0x088);
    w32(0x050, 0x409), w32(0x054, 0x098);
    dir(0x058, 1, 0); // RT_RCDATA: "INTRO"
    w32(0x068, D | 0x0b8), w32(0x06c, D | 0x070);
    dir(0x070, 0, 1);
    w32(0x080, 0x409), w32(0x084, 0x0a8);
    auto data = [&](uint32_t o, uint32_t at, uint32_t size) {
        w32(o, rva + at);
        w32(o + 4, size);
    };
    data(0x088, 0x0f4, 42);
    data(0x098, 0x0c8, 42);
    data(0x0a8, 0x120, 4);
    w16(0x0b8, 5);
    const char *intro = "INTRO";
    for (int i = 0; i < 5; ++i)
        w16(0x0ba + 2 * i, (uint16_t)intro[i]);
    auto table = [&](uint32_t o, const char *s3) {
        // 16 counted strings; only #3 has text.
        uint32_t at = o;
        for (int i = 0; i < 16; ++i) {
            uint16_t n = i == 3 ? (uint16_t)strlen(s3) : 0;
            w16(at, n);
            at += 2;
            for (uint16_t k = 0; k < n; ++k, at += 2)
                w16(at, (uint16_t)s3[k]);
        }
    };
    table(0x0c8, "Hello");
    table(0x0f4, "Hallo");
    memcpy(&b[0x120], "film", 4);
    return b;
}

} // namespace pe

static std::string g_dir;
static std::vector<std::string> g_written; // removed again at the end

static std::string write_image(const std::string &file, pe::Image &img) {
    std::string path = g_dir + "/" + file;
    g_written.push_back(path);
    std::vector<uint8_t> bytes = img.build();
    FILE *f = fopen(path.c_str(), "wb");
    if (!f || fwrite(bytes.data(), 1, bytes.size(), f) != bytes.size()) {
        fprintf(stderr, "cannot write %s\n", path.c_str());
        exit(2);
    }
    fclose(f);
    return path;
}

// ---------------------------------------------------------------------------
// Native stand-ins for the modules' DllMains and TLS callbacks, registered as
// translated code at the addresses the images name.
// ---------------------------------------------------------------------------
struct Event {
    std::string who;
    uint32_t reason, reserved;
};
static std::vector<Event> g_events;
static std::vector<std::string> g_fail; // modules whose DllMain refuses the attach

static uint32_t g_fake_ret = 0x00401000;

static void stdcall_return(X86 *c, uint32_t args) {
    c->eip = rd32(c->r[R_ESP]);
    c->r[R_ESP] += 4 + 4 * args;
    recomp_return(c);
}

struct Stub {
    const char *module;
    uint32_t base;
};
// Modules in configuration order; their DllMain is at base + 0x1000 and
// their TLS callback at base + 0x1080.
static const Stub kStubs[] = {{"alpha.dll", 0x10100000},
                              {"beta.dll", 0x10000000},
                              {"gamma.dll", 0x10180000},
                              {"delta.dll", 0x101c0000},
                              {"omega.dll", IMAGE_BASE}};

template <int N> static void dll_main(X86 *c) {
    const char *who = kStubs[N].module;
    const uint32_t reason = arg(c, 1);
    g_events.push_back({who, reason, arg(c, 2)});
    check(arg(c, 0) == kStubs[N].base, "%s DllMain gets its own base as the handle", who);
    const bool refuse = reason == 1 && std::find(g_fail.begin(), g_fail.end(), who) != g_fail.end();
    c->r[R_EAX] = refuse ? 0 : 1;
    stdcall_return(c, 3);
}
template <int N> static void tls_callback(X86 *c) {
    g_events.push_back({std::string("tls:") + kStubs[N].module, arg(c, 1), arg(c, 2)});
    stdcall_return(c, 3);
}

template <int N> static void register_stub() {
    static const uint32_t addrs[] = {kStubs[N].base + 0x1000, kStubs[N].base + 0x1080};
    static void (*const fns[])(X86 *) = {dll_main<N>, tls_callback<N>};
    static RecompHookFn hooks[2]{};
    static uint8_t hooked[2]{};
    static const RecompModule m = {kStubs[N].module,
                                   kStubs[N].base,
                                   kStubs[N].base + pe::IMAGE_SIZE,
                                   addrs,
                                   2,
                                   fns,
                                   hooks,
                                   hooked,
                                   nullptr,
                                   0,
                                   nullptr};
    recomp_module_register(&m);
}

static std::string events() {
    std::string s;
    for (const Event &e : g_events) {
        char buf[96];
        snprintf(buf, sizeof buf, "%s%s:%u/%u", s.empty() ? "" : " ", e.who.c_str(), e.reason,
                 e.reserved);
        s += buf;
    }
    return s;
}

// ---------------------------------------------------------------------------
// Calling imports as the guest does.
// ---------------------------------------------------------------------------
static uint32_t call_import(X86 *c, const char *dll, const char *name,
                            const std::vector<uint32_t> &args) {
    uint32_t tramp = imports_resolve(dll, name);
    if (!check(tramp != 0, "%s!%s has a trampoline", dll, name))
        return 0;
    const uint32_t before = c->r[R_ESP];
    uint32_t esp = before;
    for (size_t i = args.size(); i-- > 0;) {
        esp -= 4;
        wr32(esp, args[i]);
    }
    esp -= 4;
    wr32(esp, g_fake_ret);
    c->r[R_ESP] = esp;
    imports_dispatch(c, tramp);
    c->r[R_ESP] = before;
    return c->r[R_EAX];
}

static uint32_t g_scratch = 0x00300000;
static uint32_t guest_str(const char *s) {
    const uint32_t a = g_scratch;
    gm_put_str(a, s, 256);
    g_scratch += 256;
    return a;
}

// ---------------------------------------------------------------------------
// The test images.
// ---------------------------------------------------------------------------
struct Config {
    std::string main;
    std::vector<std::string> paths;
    std::vector<std::string> shas;
    std::vector<LoaderModuleSpec> specs;
};

// Two exports whose names agree for their first 300 characters, as C++
// decorations of one template's overloads do: a loader that cuts names at
// MAX_PATH binds both to whichever comes first.
static std::string long_export_name(char last) {
    return "?LongDecoration@" + std::string(296, 'x') + last;
}

static Config build_world() {
    Config cfg;
    // The executable: at its preferred base, relocations stripped. Imports
    // alpha by name and by ordinal, a shimmed KERNEL32 function and a Winsock
    // function by ordinal.
    pe::Image exe;
    exe.preferred = IMAGE_BASE;
    exe.dll = false;
    exe.strip = true;
    exe.name = "main.exe";
    exe.imports = {{"alpha.dll", {"AlphaFn", "#2", long_export_name('B')}},
                   {"KERNEL32.dll", {"GetTickCount"}},
                   {"WS2_32.dll", {"#11", "#10"}},
                   {"WSOCK32.dll", {"#11"}}};
    cfg.main = write_image("main.exe", exe);

    // alpha prefers 0x10000000 like every DLL of its kind and is configured
    // elsewhere; it imports beta, which comes after it in the configuration.
    pe::Image alpha;
    alpha.name = "alpha.dll";
    alpha.exports = {{"AlphaFn", 0x1010},
                     {"AlphaData", 0x1100},
                     {long_export_name('A'), 0x1050},
                     {long_export_name('B'), 0x1060}};
    alpha.imports = {{"beta.dll", {"BetaFn"}}};
    alpha.pointer(0x1104, 0x1100);   // a pointer to its own data
    alpha.put32(0x1108, 0x10000000); // a constant that only looks like an address
    alpha.pointer(0x1ffe, 0x1010);   // a relocation straddling a page boundary
    // beta stays at its preferred base.
    pe::Image beta;
    beta.name = "beta.dll";
    beta.exports = {{"BetaFn", 0x1020}};
    beta.pointer(0x1100, 0x1020);
    beta.rsrc = pe::resource_blob(pe::RSRC); // data entries hold RVAs
    // gamma and delta are loaded only by LoadLibrary; gamma imports both
    // beta (already loaded) and delta (not yet); delta has static TLS.
    pe::Image gamma;
    gamma.name = "gamma.dll";
    gamma.exports = {{"GammaFn", 0x1030}};
    gamma.imports = {{"beta.dll", {"BetaFn"}}, {"delta.dll", {"DeltaFn"}}};
    pe::Image delta;
    delta.name = "delta.dll";
    delta.exports = {{"DeltaFn", 0x1040}};
    delta.tls = true;

    pe::Image *images[] = {&alpha, &beta, &gamma, &delta};
    for (int i = 0; i < 4; ++i) {
        cfg.paths.push_back(write_image(kStubs[i].module, *images[i]));
        cfg.shas.push_back(loader_hash_file(cfg.paths.back().c_str()));
    }
    for (int i = 0; i < 4; ++i)
        cfg.specs.push_back(
            {kStubs[i].module, cfg.paths[i].c_str(), cfg.shas[i].c_str(), kStubs[i].base, 0x10000});
    return cfg;
}

static bool load(Config &cfg) {
    const std::string sha = loader_hash_file(cfg.main.c_str());
    const bool ok = loader_load_config(cfg.main.c_str(), sha.c_str(), cfg.specs.data(),
                                       (uint32_t)cfg.specs.size());
    if (!ok)
        printf("  loader_error: %s\n", loader_error());
    return ok;
}

// ---------------------------------------------------------------------------

static void test_relocation_and_binding(Config &cfg) {
    section("relocation to the configured base, binding across modules");
    if (!check(load(cfg), "the executable and four DLLs load"))
        exit(1);
    const LoaderModule *alpha = loader_module_named("ALPHA.DLL");
    const LoaderModule *beta = loader_module_named("beta.dll");
    check(alpha && alpha->base == 0x10100000 && alpha->preferred_base == 0x10000000,
          "alpha sits at its configured base, not the 0x10000000 it prefers");
    check(alpha && alpha->relocations == 2, "alpha applied its two relocations (%u)",
          alpha ? alpha->relocations : 0);
    check(rd32(0x10101104) == 0x10101100, "a stored pointer moved with the image (%08x)",
          rd32(0x10101104));
    check(rd32(0x10101108) == 0x10000000, "a constant no relocation names stayed (%08x)",
          rd32(0x10101108));
    check(rd16(0x10101ffe) == 0x1010 && rd16(0x10102000) == 0x1010,
          "a relocation across a page boundary moved as one dword (%08x)", rd32(0x10101ffe));
    check(beta && beta->relocations == 0 && rd32(0x10001100) == 0x10001020,
          "beta at its preferred base needed no relocation");

    const uint32_t exe_iat = IMAGE_BASE + pe::Image::iat_slot(0, 0);
    check(rd32(exe_iat) == 0x10101010, "the executable's AlphaFn slot holds alpha's export (%08x)",
          rd32(exe_iat));
    check(rd32(exe_iat + 4) == 0x10101100, "ordinal 2 binds to AlphaData (%08x)",
          rd32(exe_iat + 4));
    check(rd32(exe_iat + 8) == 0x10101060,
          "a 313-character export binds by its whole name, past a shared 300-character "
          "prefix (%08x)",
          rd32(exe_iat + 8));
    check(rd32(0x10100000 + pe::Image::iat_slot(0, 0)) == 0x10001020,
          "alpha binds BetaFn although beta is configured after it");
    check(rd32(0x10180000 + pe::Image::iat_slot(1, 0)) == 0x101c1040,
          "gamma binds DeltaFn at delta's configured base");
    const uint32_t tick = rd32(IMAGE_BASE + pe::Image::iat_slot(1, 0));
    check(imports_is_trampoline(tick) &&
              !strcmp(imports_describe(tick), "KERNEL32.dll!GetTickCount"),
          "a Win32 import still binds to its shim");
    const uint32_t ws2_11 = rd32(IMAGE_BASE + pe::Image::iat_slot(2, 0));
    const uint32_t ws2_10 = rd32(IMAGE_BASE + pe::Image::iat_slot(2, 1));
    const uint32_t wsock_11 = rd32(IMAGE_BASE + pe::Image::iat_slot(3, 0));
    check(imports_describe(ws2_11) && !strcmp(imports_describe(ws2_11), "WS2_32.dll!inet_addr") &&
              imports_argc(ws2_11) == 1,
          "WS2_32 ordinal 11 binds as inet_addr, one argument (%s)", imports_describe(ws2_11));
    check(imports_describe(ws2_10) && !strcmp(imports_describe(ws2_10), "WS2_32.dll!ioctlsocket") &&
              imports_argc(ws2_10) == 3,
          "WS2_32 ordinal 10 is ioctlsocket (%s)", imports_describe(ws2_10));
    check(imports_describe(wsock_11) &&
              (!strcmp(imports_describe(wsock_11), "WSOCK32.dll!ord11") ||
               !strcmp(imports_describe(wsock_11), "WSOCK32.dll!inet_ntoa")) &&
              imports_argc(wsock_11) == 1,
          "WSOCK32 ordinal 11 is inet_ntoa (%s)", imports_describe(wsock_11));
    const LoaderModule *main = loader_module_named(RECOMP_EXECUTABLE);
    check(main && main->imports == std::vector<std::string>{"alpha.dll"},
          "the executable imports one mapped module");
    check(alpha && alpha->imports == std::vector<std::string>{"beta.dll"}, "alpha imports beta");
    check(loader_module_at_base(0x10180000) == loader_module_named("gamma.dll") &&
              loader_module_at_base(0x10180010) == nullptr,
          "a module handle is its base and nothing else");
}

static void test_static_attach(X86 *c) {
    section("process start: static imports attach, dependencies first");
    g_events.clear();
    check(loader_attach_static(c), "loader_attach_static succeeds");
    check(events() == "beta.dll:1/1 alpha.dll:1/1",
          "beta (alpha's dependency) attaches before alpha, lpReserved nonzero: %s",
          events().c_str());
    check(c->fpu_cw == GUEST_INITIAL_FPU_CW && GUEST_INITIAL_FPU_CW == 0x027f,
          "the process starts with x87 control word %04x", c->fpu_cw);
    const uint32_t alpha_name = guest_str("Alpha.dll");
    check(call_import(c, "KERNEL32.dll", "GetModuleHandleA", {alpha_name}) == 0x10100000,
          "GetModuleHandleA finds the statically loaded alpha");
    g_events.clear();
    check(call_import(c, "KERNEL32.dll", "LoadLibraryA", {alpha_name}) == 0x10100000 &&
              call_import(c, "KERNEL32.dll", "FreeLibrary", {0x10100000}) == 1 &&
              call_import(c, "KERNEL32.dll", "FreeLibrary", {0x10100000}) == 1 &&
              g_events.empty() && loader_module_named("alpha.dll")->attached,
          "FreeLibrary never unloads a static import, even past its own references");
}

static void test_dynamic_load(X86 *c) {
    section("LoadLibrary of a translated module and what it imports");
    g_events.clear();
    const uint32_t path = guest_str("C:\\Stub\\GAMMA.DLL");
    const uint32_t h = call_import(c, "KERNEL32.dll", "LoadLibraryExA", {path, 0, 8});
    check(h == 0x10180000, "LoadLibraryExA(path, LOAD_WITH_ALTERED_SEARCH_PATH) -> %08x", h);
    check(events() == "tls:delta.dll:1/0 delta.dll:1/0 gamma.dll:1/0",
          "delta (not yet loaded) attaches first, its TLS callback before its DllMain; beta, "
          "already loaded, does not attach again: %s",
          events().c_str());
    const LoaderModule *delta = loader_module_named("delta.dll");
    const uint32_t index = delta ? delta->tls.index : 0xffffffffu;
    check(index < TLS_SLOTS && rd32(0x101c0000 + pe::Image::tls_index_slot()) == index,
          "delta's TLS index (%u) is where its code reads it", index);
    const uint32_t block = index < TLS_SLOTS ? rd32(TLS_BASE + 4 * index) : 0;
    check(block && rd8(block) == 0xa0 && rd8(block + 15) == 0xaf && rd32(block + 16) == 0,
          "the running thread got a TLS block: the template, then zero fill");
    check(loader_module_named("beta.dll")->load_refs == 2,
          "beta holds a reference for each module importing it, alpha and gamma (%u)",
          loader_module_named("beta.dll")->load_refs);
    const uint32_t gamma_fn = guest_str("GammaFn");
    check(call_import(c, "KERNEL32.dll", "GetProcAddress", {h, gamma_fn}) == 0x10181030,
          "GetProcAddress answers from gamma's export directory");
    const uint32_t buf = g_scratch;
    g_scratch += 256;
    call_import(c, "KERNEL32.dll", "GetModuleFileNameA", {h, buf, 256});
    check(gm_str(buf) == std::string(RECOMP_GUEST_ROOT) + "\\gamma.dll",
          "GetModuleFileNameA names the module beside the image: %s", gm_str(buf).c_str());

    section("thread attach and detach");
    g_events.clear();
    loader_thread_notify(c, 2);
    check(events() == "beta.dll:2/0 alpha.dll:2/0 tls:delta.dll:2/0 delta.dll:2/0 gamma.dll:2/0",
          "DLL_THREAD_ATTACH in load order: %s", events().c_str());
    call_import(c, "KERNEL32.dll", "DisableThreadLibraryCalls", {0x10100000});
    g_events.clear();
    loader_thread_notify(c, 3);
    check(events() == "gamma.dll:3/0 tls:delta.dll:3/0 delta.dll:3/0 beta.dll:3/0",
          "DLL_THREAD_DETACH in reverse, without alpha after DisableThreadLibraryCalls: %s",
          events().c_str());

    section("a guest thread starts at control word 0x027f and notifies the DLLs");
    {
        static uint32_t thread_cw = 0, thread_ran = 0;
        static void (*body)(X86 *) = [](X86 *t) {
            thread_cw = t->fpu_cw;
            thread_ran = 1;
            t->r[R_EAX] = 7;
        };
        const uint32_t start = imports_alloc_trampoline("test", "thread_body", body, 1);
        g_events.clear();
        const uint32_t th = call_import(c, "KERNEL32.dll", "CreateThread", {0, 0, start, 0, 0, 0});
        const uint32_t code = g_scratch;
        g_scratch += 16;
        for (int i = 0;
             i < 2000 && call_import(c, "KERNEL32.dll", "GetExitCodeThread", {th, code}) &&
             rd32(code) == 259;
             ++i)
            call_import(c, "KERNEL32.dll", "Sleep", {1});
        check(thread_ran && thread_cw == 0x027f, "the thread ran at control word %04x", thread_cw);
        check(rd32(code) == 7, "and exited with its body's result (%u)", rd32(code));
        check(events() == "beta.dll:2/0 tls:delta.dll:2/0 delta.dll:2/0 gamma.dll:2/0 "
                          "gamma.dll:3/0 tls:delta.dll:3/0 delta.dll:3/0 beta.dll:3/0",
              "on it: attach before the body, detach after, alpha opted out: %s", events().c_str());
    }

    section("FreeLibrary unloads in reverse and releases the dependencies");
    g_events.clear();
    check(call_import(c, "KERNEL32.dll", "FreeLibrary", {h}) == 1, "FreeLibrary(gamma) -> 1");
    check(events() == "gamma.dll:0/0 delta.dll:0/0 tls:delta.dll:0/0",
          "gamma detaches, then delta, which only gamma held: %s", events().c_str());
    check(!loader_module_named("gamma.dll")->attached &&
              !loader_module_named("delta.dll")->attached &&
              loader_module_named("delta.dll")->tls.index == 0xffffffffu &&
              loader_module_named("beta.dll")->load_refs == 1,
          "both are gone, delta's TLS slot is free, beta keeps alpha's reference");
    const uint32_t gamma_name = guest_str("gamma.dll");
    check(call_import(c, "KERNEL32.dll", "GetModuleHandleA", {gamma_name}) == 0 &&
              call_import(c, "KERNEL32.dll", "FreeLibrary", {h}) == 0,
          "an unloaded module has no handle and cannot be freed twice");

    section("a DllMain that refuses");
    g_fail = {"gamma.dll"};
    g_events.clear();
    check(call_import(c, "KERNEL32.dll", "LoadLibraryA", {gamma_name}) == 0 &&
              call_import(c, "KERNEL32.dll", "GetLastError", {}) == 1114,
          "LoadLibrary fails with ERROR_DLL_INIT_FAILED");
    check(events() == "tls:delta.dll:1/0 delta.dll:1/0 gamma.dll:1/0 gamma.dll:0/0 delta.dll:0/0 "
                      "tls:delta.dll:0/0",
          "the refusing module is detached and what it loaded is unloaded again: %s",
          events().c_str());
    g_fail.clear();
    check(!loader_module_named("gamma.dll")->attached &&
              !loader_module_named("delta.dll")->attached,
          "nothing stays loaded");
    g_events.clear();
    check(call_import(c, "KERNEL32.dll", "LoadLibraryA", {gamma_name}) == 0x10180000 &&
              events() == "tls:delta.dll:1/0 delta.dll:1/0 gamma.dll:1/0",
          "a later load starts again from the pristine image: %s", events().c_str());

    section("a DLL the runtime cannot serve fails the way a missing one does");
    const uint32_t missing = guest_str("C:\\Stub\\Missing Plugin.dll");
    check(call_import(c, "KERNEL32.dll", "LoadLibraryExA", {missing, 0, 8}) == 0 &&
              call_import(c, "KERNEL32.dll", "GetLastError", {}) == 126,
          "LoadLibraryExA -> NULL, ERROR_MOD_NOT_FOUND");

    section("process exit detaches everything, last attached first");
    g_events.clear();
    loader_detach_all(c);
    check(events() == "gamma.dll:0/1 delta.dll:0/1 tls:delta.dll:0/1 alpha.dll:0/1 beta.dll:0/1",
          "DLL_PROCESS_DETACH in reverse attach order with lpReserved set: %s", events().c_str());
}

// gamma and delta importing each other: the cycle attaches once, in
// discovery order, and every reference taken is the one given back.
// ---------------------------------------------------------------------------
// Resources of a mapped DLL: the kernel32 resource functions take the module
// handle, as a game's resource-only language DLL needs.
// ---------------------------------------------------------------------------
static std::vector<std::string> g_res_names;
static std::vector<uint32_t> g_res_langs;
static uint32_t g_res_module = 0;
static void res_names_cb(X86 *c) {
    g_res_module = arg(c, 0);
    uint32_t name = arg(c, 2);
    g_res_names.push_back(name <= 0xffff ? "#" + std::to_string(name) : gm_str(name, 64));
    set_eax(c, 1);
}
static void res_langs_cb(X86 *c) {
    g_res_langs.push_back(arg(c, 3));
    set_eax(c, 1);
}

static void test_module_resources(X86 *c) {
    section("resources of a mapped DLL (FindResource, EnumResource*, LoadString's lookup)");
    const uint32_t beta = 0x10000000;
    check(call_import(c, "KERNEL32.dll", "GetUserDefaultLangID", {}) == 0x409 &&
              call_import(c, "KERNEL32.dll", "GetSystemDefaultLangID", {}) == 0x409,
          "the user's and the system's language are US English");
    const uint32_t entry = call_import(c, "KERNEL32.dll", "FindResourceA", {beta, 1, 6});
    const uint32_t size = call_import(c, "KERNEL32.dll", "SizeofResource", {beta, entry});
    const uint32_t data = call_import(c, "KERNEL32.dll", "LoadResource", {beta, entry});
    check(entry && size == 42 && data == beta + pe::RSRC + 0x0c8,
          "FindResourceA(beta, 1, RT_STRING) finds the US English table in beta (%08x, %u bytes)",
          data, size);
    const uint32_t de = call_import(c, "KERNEL32.dll", "FindResourceExA", {beta, 6, 1, 0x407});
    check(de &&
              call_import(c, "KERNEL32.dll", "LoadResource", {beta, de}) == beta + pe::RSRC + 0x0f4,
          "FindResourceExA(beta, RT_STRING, 1, de-DE) finds the German table");
    const uint32_t intro =
        call_import(c, "KERNEL32.dll", "FindResourceA", {beta, guest_str("intro"), 10});
    const uint32_t intro_data = call_import(c, "KERNEL32.dll", "LoadResource", {beta, intro});
    check(intro && intro_data && !memcmp(g_mem + intro_data, "film", 4),
          "FindResourceA by ANSI name, case-insensitively: \"intro\" is INTRO");
    check(call_import(c, "KERNEL32.dll", "FindResourceA",
                      {beta, guest_str("#1"), guest_str("#6")}) == entry,
          "\"#1\" and \"#6\" are the integer identifiers");
    set_last_error(0);
    check(call_import(c, "KERNEL32.dll", "FindResourceA", {0x12340000, 1, 6}) == 0 &&
              call_import(c, "KERNEL32.dll", "GetLastError", {}) == 1812,
          "a handle that is no module finds nothing (ERROR_RESOURCE_DATA_NOT_FOUND)");

    const uint32_t names = imports_alloc_trampoline("test", "res_names_cb", res_names_cb, 4);
    const uint32_t langs = imports_alloc_trampoline("test", "res_langs_cb", res_langs_cb, 5);
    g_res_names.clear();
    check(call_import(c, "KERNEL32.dll", "EnumResourceNamesA", {beta, 10, names, 0}) == 1 &&
              g_res_names == std::vector<std::string>{"INTRO"} && g_res_module == beta,
          "EnumResourceNamesA hands a string name over as ANSI, with the module");
    g_res_names.clear();
    check(call_import(c, "KERNEL32.dll", "EnumResourceNamesA", {beta, 6, names, 0}) == 1 &&
              g_res_names == std::vector<std::string>{"#1"},
          "...and an integer name as itself");
    set_last_error(0);
    check(call_import(c, "KERNEL32.dll", "EnumResourceNamesA", {beta, 3, names, 0}) == 0 &&
              call_import(c, "KERNEL32.dll", "GetLastError", {}) == 1813,
          "a type the module lacks is ERROR_RESOURCE_TYPE_NOT_FOUND");
    g_res_langs.clear();
    check(call_import(c, "KERNEL32.dll", "EnumResourceLanguagesA", {beta, 6, 1, langs, 0}) == 1 &&
              g_res_langs == std::vector<uint32_t>{0x407, 0x409},
          "EnumResourceLanguagesA lists both languages in directory order");

    std::u16string s;
    check(resource_string_in(beta, 3, &s) && s == u"Hello", "string 3 in the user's language");
    check(resource_string_in(beta, 3, &s, 0x407) && s == u"Hallo", "string 3 in German");
    check(resource_string_in(beta, 4, &s) && s.empty(), "string 4 exists and is empty");
    check(!resource_string_in(beta, 0x20, &s), "string 0x20 is in a block the module lacks");
}

// ---------------------------------------------------------------------------
// File views are the file's pages, mapped at the view's guest address.
// ---------------------------------------------------------------------------
static void test_file_views(X86 *c) {
    section("file views: MapViewOfFile maps the file, aligned, privately");
    const size_t page = os_vm_page_size();
    check(page >= 4096 && !(page & (page - 1)), "the host page size is a power of two (%zu)", page);
    const uint32_t bytes = 3 * 0x10000 + 123;
    std::vector<uint8_t> want(bytes);
    for (uint32_t i = 0; i < bytes; ++i)
        want[i] = (uint8_t)(i * 7 + (i >> 16));
    const std::string path = g_dir + "/view.bin";
    g_written.push_back(path);
    FILE *f = fopen(path.c_str(), "wb");
    fwrite(want.data(), 1, want.size(), f);
    fclose(f);

    const uint32_t name = guest_str((std::string(RECOMP_GUEST_ROOT) + "\\VIEW.BIN").c_str());
    const uint32_t h =
        call_import(c, "KERNEL32.dll", "CreateFileA", {name, 0x80000000u, 1, 0, 3, 0, 0});
    const uint32_t m = call_import(c, "KERNEL32.dll", "CreateFileMappingA", {h, 0, 2, 0, 0, 0});
    const uint32_t v = call_import(c, "KERNEL32.dll", "MapViewOfFile", {m, 4, 0, 0, 0});
    check(h != 0xffffffffu && m && v && !memcmp(g_mem + v, want.data(), bytes),
          "a whole-file FILE_MAP_READ view reads the file (%u bytes at %08x)", bytes, v);
    check(v && !((uintptr_t)(g_mem + v) % page) && rd8(v + bytes) == 0,
          "the view starts on a host page and reads zero past the end of the file");
    const uint32_t v2 = call_import(c, "KERNEL32.dll", "MapViewOfFile", {m, 4, 0, 0x10000, 0x100});
    check(v2 && v2 != v && !memcmp(g_mem + v2, want.data() + 0x10000, 0x100),
          "a second view from 64 KB in reads from there");
    set_last_error(0);
    check(call_import(c, "KERNEL32.dll", "MapViewOfFile", {m, 4, 0, 0x1000, 0x100}) == 0 &&
              call_import(c, "KERNEL32.dll", "GetLastError", {}) == 1132,
          "an offset off the 64 KB granularity is ERROR_MAPPED_ALIGNMENT");
    const uint32_t copy = call_import(c, "KERNEL32.dll", "MapViewOfFile", {m, 1, 0, 0, 0});
    if (copy)
        wr32(copy, 0xdeadbeefu);
    std::vector<uint8_t> disk(4);
    f = fopen(path.c_str(), "rb");
    fread(disk.data(), 1, 4, f);
    fclose(f);
    check(copy && rd32(copy) == 0xdeadbeefu && !memcmp(disk.data(), want.data(), 4) &&
              !memcmp(g_mem + v, want.data(), 4),
          "a FILE_MAP_COPY view is writable, and neither the file nor another view sees it");
    check(call_import(c, "KERNEL32.dll", "UnmapViewOfFile", {v}) == 1 && rd32(v) == 0,
          "an unmapped view is zeroed memory again");
    call_import(c, "KERNEL32.dll", "UnmapViewOfFile", {v2});
    call_import(c, "KERNEL32.dll", "UnmapViewOfFile", {copy});
    call_import(c, "KERNEL32.dll", "CloseHandle", {m});
    call_import(c, "KERNEL32.dll", "CloseHandle", {h});
}

// ---------------------------------------------------------------------------
// Winsock start-up, byte order and name resolution without DNS.
// ---------------------------------------------------------------------------
static void test_winsock_startup(X86 *c) {
    section("Winsock: start-up, clean-up, byte order, addresses, no-DNS resolution");
    const uint32_t data = g_scratch;
    g_scratch += 512;
    for (const char *dll : {"WS2_32.dll", "WSOCK32.dll"}) {
        check(call_import(c, dll, "WSAStartup", {0x0002, data}) == 0 && rd16(data) == 0x0002 &&
                  rd16(data + 2) == 0x0202,
              "%s: WSAStartup(2.0) grants 2.0, the highest 2.2", dll);
        check(call_import(c, dll, "WSAStartup", {0x0101, data}) == 0 && rd16(data) == 0x0101,
              "%s: WSAStartup(1.1) grants 1.1", dll);
        check(call_import(c, dll, "WSAStartup", {0x0303, data}) == 0 && rd16(data) == 0x0202,
              "%s: WSAStartup(3.3) grants 2.2", dll);
        check(call_import(c, dll, "WSAStartup", {0x0000, data}) == 10092,
              "%s: WSAStartup(0.0) is WSAVERNOTSUPPORTED", dll);
        bool cleaned = true;
        for (int i = 0; i < 3; ++i)
            cleaned &= call_import(c, dll, "WSACleanup", {}) == 0;
        check(cleaned && call_import(c, dll, "WSACleanup", {}) == 0xffffffffu &&
                  call_import(c, dll, "WSAGetLastError", {}) == 10093,
              "%s: one WSACleanup per start-up, then WSANOTINITIALISED", dll);
        check(call_import(c, dll, "htons", {0x1234}) == 0x3412 &&
                  call_import(c, dll, "ntohs", {0x3412}) == 0x1234 &&
                  call_import(c, dll, "htonl", {0x11223344}) == 0x44332211u &&
                  call_import(c, dll, "ntohl", {0x44332211}) == 0x11223344u,
              "%s: byte order", dll);
        // inet_addr's grammar is BSD's: one to four parts, the last filling
        // the bytes the others left (winsock_tests has the rest).
        check(call_import(c, dll, "inet_addr", {guest_str("192.168.1.2")}) == 0x0201a8c0u &&
                  call_import(c, dll, "inet_addr", {guest_str("1.2.3")}) == 0x03000201u &&
                  call_import(c, dll, "inet_addr", {guest_str("256.1.1.1")}) == 0xffffffffu &&
                  call_import(c, dll, "inet_addr", {guest_str("host.example")}) == 0xffffffffu,
              "%s: inet_addr takes dotted addresses and nothing else", dll);
        // Name resolution needs a start-up, as on Windows.
        check(call_import(c, dll, "gethostbyname", {guest_str("10.0.0.7")}) == 0 &&
                  call_import(c, dll, "WSAGetLastError", {}) == 10093,
              "%s: gethostbyname before WSAStartup is WSANOTINITIALISED", dll);
        call_import(c, dll, "WSAStartup", {0x0101, data});
        const uint32_t he = call_import(c, dll, "gethostbyname", {guest_str("10.0.0.7")});
        check(he && rd16(he + 8) == 2 && rd16(he + 10) == 4 &&
                  rd32(rd32(rd32(he + 12))) == 0x0700000au && rd32(rd32(he + 12) + 4) == 0,
              "%s: gethostbyname of a dotted quad is that address, without DNS", dll);
        // A server long gone is named in [network] offline_hosts (or here,
        // RECOMP_NET_OFFLINE_HOSTS) and fails without asking a resolver.
        os_setenv("RECOMP_NET_OFFLINE_HOSTS", "gone.server.example");
        const uint64_t t0 = os_monotonic_ns();
        const uint32_t gone =
            call_import(c, dll, "gethostbyname", {guest_str("gone.server.example")});
        const double ms = (os_monotonic_ns() - t0) / 1e6;
        os_unsetenv("RECOMP_NET_OFFLINE_HOSTS");
        check(gone == 0 && call_import(c, dll, "WSAGetLastError", {}) == 11001 && ms < 50,
              "%s: an offline host fails at once with WSAHOST_NOT_FOUND (%.2f ms)", dll, ms);
        call_import(c, dll, "WSACleanup", {});
    }
}

// ---------------------------------------------------------------------------
// The rest of what a 2001 game imports from kernel32, advapi32 and winmm:
// file times, temporary files, short paths, the Windows directory, lstrcpyn,
// GlobalSize, alertable waits, deleting registry keys and values, and no
// auxiliary audio devices.
// ---------------------------------------------------------------------------
static void test_more_win32(X86 *c) {
    section("kernel32/advapi32/winmm: file times, temp files, paths, registry deletes, aux");
    const std::string path = g_dir + "/times.bin";
    g_written.push_back(path);
    FILE *f = fopen(path.c_str(), "wb");
    fputs("times", f);
    fclose(f);
    const std::string root = RECOMP_GUEST_ROOT;
    const uint32_t name = guest_str((root + "\\TIMES.BIN").c_str());
    const uint32_t h =
        call_import(c, "KERNEL32.dll", "CreateFileA", {name, 0x80000000u, 1, 0, 3, 0, 0});
    const uint32_t ft = g_scratch;
    g_scratch += 64;
    memset(g_mem + ft, 0, 24);
    check(call_import(c, "KERNEL32.dll", "GetFileTime", {h, ft, 0, ft + 16}) == 1 &&
              rd32(ft + 20) != 0 && rd32(ft + 12) == 0,
          "GetFileTime fills the times asked for and leaves a null pointer alone");
    wr32(ft + 24, rd32(ft + 16) + 1);
    wr32(ft + 28, rd32(ft + 20));
    check(call_import(c, "KERNEL32.dll", "CompareFileTime", {ft + 16, ft + 24}) == 0xffffffffu &&
              call_import(c, "KERNEL32.dll", "CompareFileTime", {ft + 24, ft + 16}) == 1 &&
              call_import(c, "KERNEL32.dll", "CompareFileTime", {ft + 16, ft + 16}) == 0,
          "CompareFileTime orders FILETIMEs");
    call_import(c, "KERNEL32.dll", "CloseHandle", {h});
    const uint32_t attrs = g_scratch;
    g_scratch += 64;
    check(call_import(c, "KERNEL32.dll", "GetFileAttributesExA", {name, 0, attrs}) == 1 &&
              rd32(attrs + 32) == 5,
          "GetFileAttributesExA reports the size");

    const uint32_t buf = g_scratch;
    g_scratch += 512;
    const uint32_t n = call_import(c, "KERNEL32.dll", "GetTempPathA", {260, buf});
    const std::string tmp = gm_str(buf, 260);
    OsStat st{};
    check(n == tmp.size() && tmp == root + "\\Temp\\" &&
              os_stat((g_dir + "/Temp").c_str(), &st) == 0 && st.is_dir,
          "GetTempPathA is Temp under the guest root, and exists: %s", tmp.c_str());
    check(call_import(c, "KERNEL32.dll", "GetTempPathA", {3, buf}) == tmp.size() + 1,
          "...and asks for the room it needs");

    // A file opened with no access at all: CREATE_NEW still creates it, as
    // on Windows (Empire Earth makes each save file so, then opens it to
    // write), and a second CREATE_NEW finds it there. OPEN_ALWAYS with read
    // access only creates a missing file too.
    const uint32_t fresh = guest_str((root + "\\FRESH.EES").c_str());
    const uint32_t hf = call_import(c, "KERNEL32.dll", "CreateFileA", {fresh, 0, 0, 0, 1, 0x80, 0});
    check(hf != 0xffffffffu &&
              call_import(c, "KERNEL32.dll", "GetFileAttributesA", {fresh}) != 0xffffffffu,
          "CreateFileA(no access, CREATE_NEW) creates the file");
    call_import(c, "KERNEL32.dll", "CloseHandle", {hf});
    check(call_import(c, "KERNEL32.dll", "CreateFileA", {fresh, 0, 0, 0, 1, 0x80, 0}) ==
                  0xffffffffu &&
              call_import(c, "KERNEL32.dll", "GetLastError", {}) == 80,
          "...and CREATE_NEW again: ERROR_FILE_EXISTS");
    const uint32_t always = guest_str((root + "\\ALWAYS.EES").c_str());
    const uint32_t ha =
        call_import(c, "KERNEL32.dll", "CreateFileA", {always, 0x80000000u, 0, 0, 4, 0x80, 0});
    check(ha != 0xffffffffu &&
              call_import(c, "KERNEL32.dll", "GetFileAttributesA", {always}) != 0xffffffffu,
          "CreateFileA(GENERIC_READ, OPEN_ALWAYS) creates a missing file");
    call_import(c, "KERNEL32.dll", "CloseHandle", {ha});
    check(call_import(c, "KERNEL32.dll", "DeleteFileA", {fresh}) == 1 &&
              call_import(c, "KERNEL32.dll", "DeleteFileA", {always}) == 1,
          "...and both delete again");
    const uint32_t made =
        call_import(c, "KERNEL32.dll", "GetTempFileNameA", {buf, guest_str("eex"), 0, buf + 260});
    const std::string temp_file = gm_str(buf + 260, 260);
    const std::string host_temp = g_dir + "/Temp/" + temp_file.substr(temp_file.rfind('\\') + 1);
    g_written.push_back(host_temp);
    check(made && temp_file.find("\\Temp\\eex") != std::string::npos && temp_file.size() > 4 &&
              temp_file.substr(temp_file.size() - 4) == ".TMP" &&
              os_stat(host_temp.c_str(), &st) == 0,
          "GetTempFileNameA(unique 0) makes the file: %s", temp_file.c_str());
    check(call_import(c, "KERNEL32.dll", "GetTempFileNameA",
                      {buf, guest_str("eex"), 0x1a2b, buf + 260}) == 0x1a2b &&
              gm_str(buf + 260, 260) == tmp + "eex1A2B.TMP",
          "...and with a unique number only names it");
    check(call_import(c, "KERNEL32.dll", "GetShortPathNameA", {name, buf, 260}) ==
                  root.size() + 10 &&
              gm_str(buf, 260) == root + "\\TIMES.BIN",
          "GetShortPathNameA answers with the long path");
    check(call_import(c, "KERNEL32.dll", "GetShortPathNameA",
                      {guest_str((root + "\\nope.bin").c_str()), buf, 260}) == 0 &&
              call_import(c, "KERNEL32.dll", "GetLastError", {}) == 2,
          "...and ERROR_FILE_NOT_FOUND for a missing file");
    check(call_import(c, "KERNEL32.dll", "GetWindowsDirectoryA", {buf, 260}) == 10 &&
              gm_str(buf, 260) == "C:\\Windows",
          "GetWindowsDirectoryA");

    const uint32_t src = guest_str("abcdef");
    memset(g_mem + buf, 'x', 16);
    check(call_import(c, "KERNEL32.dll", "lstrcpynA", {buf, src, 4}) == buf &&
              gm_str(buf, 16) == "abc",
          "lstrcpynA copies n - 1 characters and a NUL");
    wr8(buf, 'x');
    check(call_import(c, "KERNEL32.dll", "lstrcpynA", {buf, src, 0}) == buf && rd8(buf) == 'x',
          "...and nothing for n 0");
    const uint32_t block = call_import(c, "KERNEL32.dll", "GlobalAlloc", {0, 100});
    check(call_import(c, "KERNEL32.dll", "GlobalSize", {block}) >= 100 &&
              call_import(c, "KERNEL32.dll", "GlobalSize", {0x12345678}) == 0,
          "GlobalSize of a block, and 0 for what is none");
    call_import(c, "KERNEL32.dll", "GlobalFree", {block});
    const uint32_t ev = call_import(c, "KERNEL32.dll", "CreateEventA", {0, 1, 1, 0});
    check(call_import(c, "KERNEL32.dll", "WaitForSingleObjectEx", {ev, 0, 1}) == 0,
          "WaitForSingleObjectEx waits as WaitForSingleObject");
    call_import(c, "KERNEL32.dll", "CloseHandle", {ev});

    const uint32_t key = g_scratch;
    g_scratch += 16;
    const uint32_t sub = guest_str("Software\\RecompTest\\Gone");
    check(call_import(c, "ADVAPI32.dll", "RegCreateKeyExA",
                      {0x80000001u, sub, 0, 0, 0, 0xf003f, 0, key, 0}) == 0,
          "RegCreateKeyExA");
    const uint32_t val = guest_str("Value"), dword = g_scratch;
    g_scratch += 16;
    wr32(dword, 7);
    call_import(c, "ADVAPI32.dll", "RegSetValueExA", {rd32(key), val, 0, 4, dword, 4});
    check(call_import(c, "ADVAPI32.dll", "RegDeleteValueA", {rd32(key), val}) == 0 &&
              call_import(c, "ADVAPI32.dll", "RegDeleteValueA", {rd32(key), val}) == 2,
          "RegDeleteValueA deletes once, then ERROR_FILE_NOT_FOUND");
    call_import(c, "ADVAPI32.dll", "RegCloseKey", {rd32(key)});
    check(call_import(c, "ADVAPI32.dll", "RegDeleteKeyA",
                      {0x80000001u, guest_str("Software\\RecompTest")}) == 5,
          "RegDeleteKeyA refuses a key with subkeys (ERROR_ACCESS_DENIED)");
    check(call_import(c, "ADVAPI32.dll", "RegDeleteKeyA", {0x80000001u, sub}) == 0 &&
              call_import(c, "ADVAPI32.dll", "RegOpenKeyExA",
                          {0x80000001u, sub, 0, 0x20019, key}) == 2,
          "RegDeleteKeyA deletes a leaf key");

    const uint32_t caps = g_scratch;
    g_scratch += 64;
    check(call_import(c, "WINMM.dll", "auxGetNumDevs", {}) == 0 &&
              call_import(c, "WINMM.dll", "auxGetDevCapsA", {0, caps, 48}) == 2 &&
              call_import(c, "WINMM.dll", "auxGetVolume", {0, caps}) == 2 &&
              call_import(c, "WINMM.dll", "auxSetVolume", {0, 0xffffffffu}) == 2,
          "no auxiliary audio devices: MMSYSERR_BADDEVICEID");
}

static void test_import_cycle(Config &cfg) {
    section("an import cycle");
    const std::string saved = g_dir;
    g_dir += "/cycle";
    os_mkdir(g_dir.c_str());
    os_setenv("RECOMP_REGISTRY", (g_dir + "/registry.json").c_str());
    g_written.push_back(g_dir + "/registry.json");
    pe::Image exe;
    exe.preferred = IMAGE_BASE;
    exe.dll = false;
    exe.strip = true;
    exe.imports = {{"KERNEL32.dll", {"GetTickCount"}}};
    const std::string main = write_image("main.exe", exe);
    pe::Image gamma, delta;
    gamma.exports = {{"GammaFn", 0x1030}};
    gamma.imports = {{"delta.dll", {"DeltaFn"}}};
    delta.exports = {{"DeltaFn", 0x1040}};
    delta.imports = {{"gamma.dll", {"GammaFn"}}};
    const std::string gp = write_image("gamma.dll", gamma), dp = write_image("delta.dll", delta);
    const std::string gs = loader_hash_file(gp.c_str()), ds = loader_hash_file(dp.c_str());
    const std::string ms = loader_hash_file(main.c_str());
    g_dir = saved;
    LoaderModuleSpec specs[2] = {{"gamma.dll", gp.c_str(), gs.c_str(), kStubs[2].base, 0x10000},
                                 {"delta.dll", dp.c_str(), ds.c_str(), kStubs[3].base, 0x10000}};
    (void)cfg;
    if (!check(loader_load_config(main.c_str(), ms.c_str(), specs, 2),
               "two DLLs importing each other load"))
        return;
    X86 *c = loader_context();
    g_events.clear();
    const uint32_t g = call_import(c, "KERNEL32.dll", "LoadLibraryA", {guest_str("gamma.dll")});
    const uint32_t d = call_import(c, "KERNEL32.dll", "LoadLibraryA", {guest_str("delta.dll")});
    check(g == kStubs[2].base && d == kStubs[3].base && events() == "delta.dll:1/0 gamma.dll:1/0",
          "loading one attaches the other first, each once: %s", events().c_str());
    g_events.clear();
    check(call_import(c, "KERNEL32.dll", "FreeLibrary", {g}) == 1 && events() == "gamma.dll:0/0" &&
              loader_module_named("delta.dll")->attached,
          "freeing gamma detaches it and leaves delta its own reference: %s", events().c_str());
    g_events.clear();
    check(call_import(c, "KERNEL32.dll", "FreeLibrary", {d}) == 1 && events() == "delta.dll:0/0" &&
              !loader_module_named("gamma.dll")->load_refs &&
              !loader_module_named("delta.dll")->load_refs,
          "freeing delta detaches it, and gives back nothing it never took: %s", events().c_str());
}

static void test_dll_main_image(Config &cfg) {
    section("a DLL as the main image, relocated to the image base");
    pe::Image omega;
    omega.name = "omega.dll";
    omega.preferred = 0x10000000;
    omega.imports = {{"beta.dll", {"BetaFn"}}};
    omega.pointer(0x1100, 0x1100);
    const std::string path = write_image("omega.dll", omega);
    const std::string sha = loader_hash_file(path.c_str());
    std::vector<LoaderModuleSpec> specs = {cfg.specs[1]}; // beta
    if (!check(loader_load_config(path.c_str(), sha.c_str(), specs.data(), 1), "loads at %08x: %s",
               IMAGE_BASE, loader_error()))
        return;
    check(rd32(IMAGE_BASE + 0x1100) == IMAGE_BASE + 0x1100,
          "relocated from 0x10000000 to the image base");
    X86 *c = loader_context();
    g_events.clear();
    run_entry(c);
    check(events() == "beta.dll:1/1 omega.dll:1/1",
          "run_entry attaches its imports, then runs its DllMain rather than a process entry: %s",
          events().c_str());

    section("images that cannot be placed");
    pe::Image fixed;
    fixed.preferred = 0x00800000;
    fixed.dll = false;
    fixed.strip = true;
    const std::string fixed_path = write_image("fixed.exe", fixed);
    const std::string fixed_sha = loader_hash_file(fixed_path.c_str());
    check(!loader_load_config(fixed_path.c_str(), fixed_sha.c_str(), nullptr, 0) &&
              strstr(loader_error(), "no relocations"),
          "an executable without relocations away from its base: %s", loader_error());
    LoaderModuleSpec moved = cfg.specs[0];
    pe::Image stripped;
    stripped.strip = true;
    const std::string stripped_path = write_image("stripped.dll", stripped);
    const std::string stripped_sha = loader_hash_file(stripped_path.c_str());
    moved.name = "stripped.dll";
    moved.path = stripped_path.c_str();
    moved.sha256 = stripped_sha.c_str();
    const std::string main_sha = loader_hash_file(cfg.main.c_str());
    check(!loader_load_config(cfg.main.c_str(), main_sha.c_str(), &moved, 1) &&
              strstr(loader_error(), "no relocations"),
          "a DLL without relocations away from its base: %s", loader_error());
    LoaderModuleSpec twice[2] = {cfg.specs[0], cfg.specs[0]};
    twice[1].name = "beta.dll";
    twice[1].path = cfg.specs[1].path;
    twice[1].sha256 = cfg.specs[1].sha256;
    check(!loader_load_config(cfg.main.c_str(), main_sha.c_str(), twice, 2) &&
              strstr(loader_error(), "overlaps"),
          "two modules in one place: %s", loader_error());
}

static void test_accepted_digests(Config &cfg) {
    section("accept_sha256: further digests a module may have, and the profile overlay");
    const std::string main_sha = loader_hash_file(cfg.main.c_str());
    const std::string zeros(64, '0'), ones(64, '1');
    LoaderModuleSpec beta = cfg.specs[1];
    beta.sha256 = zeros.c_str();
    const std::string accept = ones + " " + cfg.shas[1];
    beta.accept_sha256 = accept.c_str();
    check(loader_load_config(cfg.main.c_str(), main_sha.c_str(), &beta, 1),
          "a module whose digest is in accept_sha256 loads: %s", loader_error());
    const std::string wrong = ones + " " + zeros;
    beta.accept_sha256 = wrong.c_str();
    check(!loader_load_config(cfg.main.c_str(), main_sha.c_str(), &beta, 1) &&
              strstr(loader_error(), "expected") && strstr(loader_error(), "(or "),
          "one matching neither is refused, naming both: %s", loader_error());

    // The profile overlay: a beta.dll in RECOMP_PROFILE_DIR is read instead of
    // the installed one, under the same gate.
    const std::string profile = g_dir + "/profile";
    os_mkdir(profile.c_str());
    std::vector<uint8_t> bytes;
    if (FILE *f = fopen(cfg.paths[1].c_str(), "rb")) {
        uint8_t buf[4096];
        size_t n;
        while ((n = fread(buf, 1, sizeof buf, f)) != 0)
            bytes.insert(bytes.end(), buf, buf + n);
        fclose(f);
    }
    bytes.push_back('\n'); // a different file, still the same image
    const std::string overlaid = profile + "/beta.dll";
    if (FILE *f = fopen(overlaid.c_str(), "wb")) {
        fwrite(bytes.data(), 1, bytes.size(), f);
        fclose(f);
    }
    g_written.push_back(overlaid);
    const std::string overlaid_sha = loader_hash_file(overlaid.c_str());
    os_setenv("RECOMP_PROFILE_DIR", profile.c_str());
    LoaderModuleSpec installed = cfg.specs[1];
    check(!loader_load_config(cfg.main.c_str(), main_sha.c_str(), &installed, 1) &&
              strstr(loader_error(), "/profile/beta.dll"),
          "the overlay file is taken first and gated by hash: %s", loader_error());
    installed.accept_sha256 = overlaid_sha.c_str();
    check(loader_load_config(cfg.main.c_str(), main_sha.c_str(), &installed, 1) &&
              loader_module_named("beta.dll") &&
              loader_module_named("beta.dll")->path == overlaid,
          "an accepted overlay file loads from the profile: %s", loader_error());
    os_unsetenv("RECOMP_PROFILE_DIR");
    os_rmdir(profile.c_str());
}

static void test_heap_growth(Config &cfg) {
    section("the heap grows past its base arena, around module places");
    if (!load(cfg))
        return;
    if (GUEST_SIZE <= GUEST_SHIM_END) {
        check(true, "guest_size leaves no room to grow (skipped)");
        return;
    }
    const uint32_t big = heap_alloc(HEAP_LIMIT - HEAP_BASE - 0x100000);
    check(big != 0, "one block takes nearly all of the base arena (%08x)", big);
    const uint32_t grown = heap_alloc(0x01000000, true);
    check(grown >= GUEST_SHIM_END && grown + 0x01000000 <= GUEST_SIZE,
          "the next 16 MB comes from above the trampolines (%08x)", grown);
    bool clear = true;
    for (const LoaderModuleSpec &s : cfg.specs)
        clear &= grown + 0x01000000 <= s.base || grown >= s.base + s.size;
    check(clear, "and stays clear of every configured module place");
    check(heap_check().empty(), "the heap is consistent: %s", heap_check().c_str());
    check(heap_span() > (uint64_t)(HEAP_LIMIT - HEAP_BASE), "the heap now spans %llu MB",
          (unsigned long long)(heap_span() >> 20));
    wr32(grown + 0x00fffffc, 0x12345678);
    check(rd32(grown + 0x00fffffc) == 0x12345678, "grown memory is ordinary guest memory");
    check(heap_free(grown) && heap_free(big) && heap_check().empty(),
          "freeing both leaves a consistent heap");
}

// What a replay of recorded guest calls needs: memory at the exact addresses
// the recording names, above guest_size included, and a heap that keeps out
// of it while guest code allocates around it.
static void test_exact_ranges(Config &cfg) {
    section("memory at exact addresses: mem_open, heap_exclude");
    if (!load(cfg))
        return;
    if (!mem_guarded()) {
        check(true, "no guarded arena on this host (skipped)");
        return;
    }
    const uint32_t high = 0x40001234u;
    check(!gm_valid(high, 4) && !mem_committed(high, 4) && mem_readable_end(high) == high,
          "%08x, above guest_size, is shut", high);
    check(mem_open(high, 0x2000), "mem_open opens %08x+0x2000", high);
    check(gm_valid(high, 0x2000) && mem_committed(high, 0x2000),
          "the shims' checks accept the opened range");
    wr32(high, 0xfeedfaceu);
    gm_put_str(high + 4, "replayed", 16);
    check(rd32(high) == 0xfeedfaceu && gm_str(high + 4) == "replayed",
          "it is ordinary guest memory, strings included");
    check(mem_readable_end(high) == 0x40010000u, "readable to the end of its 64 KB grain (%08x)",
          mem_readable_end(high));
    check(!gm_valid(0x40010000u, 1) && !gm_valid(high, 0x10000) &&
              mem_readable_end(0x50000000u) == 0x50000000u,
          "and nothing past it");
    check(mem_open(GUEST_SIZE - 0x10, 0x20) && gm_valid(GUEST_SIZE - 8, 16) &&
              mem_readable_end(0x00400000u) > GUEST_SIZE,
          "a range across guest_size continues the arena (readable to %08x)",
          mem_readable_end(0x00400000u));
    check(!mem_open(0xffff8000u, 0x100) && !mem_open(high, 0),
          "nothing past 0xffff0000, and no empty range");

    const uint32_t hole = heap_alloc(0x20000, false, 0x1000);
    const uint64_t span = heap_span();
    check(hole != 0 && heap_free(hole), "a free stretch of the base arena at %08x", hole);
    check(heap_exclude(hole + 0x10, 0x1fff0) && heap_span() == span - 0x20000,
          "heap_exclude takes it, in whole pages");
    std::vector<uint32_t> blocks;
    bool clear = true;
    for (uint32_t i = 0; i < 96; ++i) {
        const uint32_t size = 0x800u * (1 + i % 7);
        const uint32_t b = heap_alloc(size);
        blocks.push_back(b);
        clear &= b != 0 && (b + size <= hole || b >= hole + 0x20000);
    }
    check(clear, "no allocation lands in it");
    check(heap_check().empty(), "the heap is consistent around the hole: %s", heap_check().c_str());
    check(!heap_exclude(blocks[5] + 0x10, 0x10), "a range over a live block is refused");
    for (uint32_t b : blocks)
        heap_free(b);
    const uint32_t again = heap_alloc(0x20000);
    check(heap_check().empty() && (again + 0x20000 <= hole || again >= hole + 0x20000),
          "freeing everything never bridges it: %s", heap_check().c_str());
    heap_free(again);
    if (GUEST_SIZE > GUEST_SHIM_END) {
        check(heap_exclude(GUEST_SHIM_END, GUEST_SIZE - GUEST_SHIM_END),
              "excluding everything above the trampolines");
        check(heap_alloc(HEAP_LIMIT - HEAP_BASE) == 0,
              "leaves growth nowhere to go for a block the base arena cannot hold");
    }
    load(cfg);
    check(!gm_valid(high, 4) && !mem_committed(high, 4), "mem_init shuts what was opened");
    check(heap_span() == (uint64_t)(HEAP_LIMIT - HEAP_BASE) && heap_check().empty(),
          "and gives the heap its whole base arena back");
}

// ---------------------------------------------------------------------------
// Children: the guarded arena and strict mode end the process by design, so
// they run in a copy of this binary. A stop through abort() would also wake
// the system crash reporter; the child turns SIGABRT into a plain exit.
// ---------------------------------------------------------------------------
static void abort_exits(const char *) {
    os_exit_immediately(77);
}

static int child(const char *which, const char *log) {
    if (!freopen(log, "w", stderr))
        return 2;
    os_install_fault_handlers(abort_exits);
    mem_init();
    imports_init();
    X86 c;
    loader_init_context(&c);
    if (!strcmp(which, "--child-wild-read"))
        return (int)rd32(0xf0000000u);
    if (!strcmp(which, "--child-null-read"))
        return (int)rd32(0x00000010u);
    if (!strcmp(which, "--child-strict-call")) {
        c.r[R_ESP] -= 4;
        wr32(c.r[R_ESP], 0x00401234);
        recomp_unknown_call(&c, 0x00987654);
        return 3; // not reached in strict mode
    }
    if (!strcmp(which, "--child-strict-argc")) {
        const uint32_t t =
            imports_alloc_trampoline("mystery.dll", "Mystery", nullptr, ARGC_UNKNOWN);
        c.r[R_ESP] -= 4;
        wr32(c.r[R_ESP], 0x00401234);
        imports_dispatch(&c, t);
        return 3;
    }
    if (!strcmp(which, "--child-lenient-call")) {
        c.r[R_ESP] -= 4;
        wr32(c.r[R_ESP], 0x00401234);
        c.r[R_EAX] = 5;
        recomp_unknown_call(&c, 0x00987654);
        return c.eip == 0x00401234 && c.r[R_EAX] == 0 ? 0 : 4;
    }
    return 2;
}

// Runs a child of this binary with one switch set; its exit code, and its
// stderr in *err.
static int run_child(const char *exe, const char *which, const char *env_name,
                     const char *env_value, std::string *err) {
    const std::string log = g_dir + "/child.log";
    remove(log.c_str());
    if (env_name)
        os_setenv(env_name, env_value);
    const char *args[] = {exe, which, log.c_str(), nullptr};
    int64_t pid = 0;
    int code = -1;
    if (os_spawn(args, &pid) != 0 || os_wait(pid, &code) != 0)
        code = -1;
    if (env_name)
        os_unsetenv(env_name);
    *err = "";
    if (FILE *f = fopen(log.c_str(), "rb")) {
        char buf[4096];
        size_t n = fread(buf, 1, sizeof buf - 1, f);
        buf[n] = 0;
        *err = buf;
        fclose(f);
    }
    return code;
}

static void test_guards_and_strict(const char *exe) {
    section("the guarded arena");
    check(sizeof(void *) < 8 || mem_guarded(), "a 64-bit host reserves the 4 GB guest space");
    std::string err;
    int code = run_child(exe, "--child-wild-read", nullptr, nullptr, &err);
    check(code == 5 && err.find("guest memory fault") != std::string::npos &&
              err.find("f0000000") != std::string::npos &&
              err.find("outside the guest arena") != std::string::npos,
          "a read past the arena is reported with its guest address (exit %d)", code);
    code = run_child(exe, "--child-null-read", "RECOMP_NULL_GUARD", "1", &err);
    check(code == 5 && err.find("null page") != std::string::npos,
          "with the null guard armed, a read of guest 0x10 faults as on Windows (exit %d)", code);

    section("strict mode");
    code = run_child(exe, "--child-strict-call", "RECOMP_STRICT", "1", &err);
    check(code == 77 && err.find("strict: call 00987654") != std::string::npos &&
              err.find("from 00401234") != std::string::npos,
          "an undeliverable call stops the run with its target and caller (exit %d)", code);
    code = run_child(exe, "--child-strict-argc", "RECOMP_STRICT", "1", &err);
    check(code == 77 && err.find("unknown stdcall argument count") != std::string::npos &&
              err.find("mystery.dll!Mystery") != std::string::npos,
          "a call through an import of unknown argument count stops it (exit %d)", code);
    code = run_child(exe, "--child-lenient-call", "RECOMP_STRICT", "0", &err);
    check(code == 0, "without strict mode the call returns 0 and the run continues (exit %d)",
          code);
}

// ---------------------------------------------------------------------------
// Import argument counts.
// ---------------------------------------------------------------------------
static void registered_agrees(const ImportShim &s, void *user) {
    std::vector<std::string> &bad = *static_cast<std::vector<std::string> *>(user);
    if (s.argc_stdcall == ARGC_UNKNOWN)
        return;
    const uint8_t known = imports_known_win32_argc(s.dll, s.name);
    if (known != ARGC_UNKNOWN && known != s.argc_stdcall)
        bad.push_back(std::string(s.dll) + "!" + s.name);
}

static void test_argc() {
    section("stdcall argument counts without a shim");
    struct Case {
        const char *dll, *name;
        uint8_t want;
    } cases[] = {
        {"KERNEL32.dll", "CreateFileA", 7},
        {"kernel32", "GetVolumeInformationA", 8},
        {"USER32.dll", "wsprintfA", ARGC_CDECL},
        {"USER32.dll", "WindowFromPoint", 2},
        {"GDI32.dll", "CreateFontA", 14},
        {"WS2_32.dll", "recvfrom", 6},
        {"wsock32.dll", "__WSAFDIsSet", 2},
        {"IPHLPAPI.DLL", "GetAdaptersInfo", 2},
        {"mss32.dll", "_AIL_open_digital_driver@16", ARGC_UNKNOWN}, // decoration: imports.cpp
        {"msvcrt.dll", "strlen", ARGC_CDECL},
        {"MSVCRT.dll", "_CxxThrowException", 2},
        {"msvcrt.dll", "__CxxLongjmpUnwind", 1},
        {"MSVCP60.dll", "_Getctype", ARGC_CDECL},
        {"MSVCP60.dll", "??0_Lockit@std@@QAE@XZ", 0},
        {"MSVCP60.dll", "??1bad_cast@std@@UAE@XZ", 0},
        {"MSVCP60.dll", "??0bad_cast@std@@QAE@PBD@Z", 1},
        {"MSVCP60.dll", "??4_Lockit@std@@QAEAAV01@ABV01@@Z", 1},
        {"MSVCP60.dll", "??_7bad_cast@std@@6B@", ARGC_UNKNOWN}, // a vftable is data
        {"engine.dll", "?f@@YAXH@Z", ARGC_CDECL},
        {"engine.dll", "?g@@YGHHPAD@Z", 2},
        {"engine.dll", "?h@@YGXN_J@Z", 4},
        {"engine.dll", "?v@C@@QAEXHZZ", ARGC_CDECL},
        {"engine.dll", "?k@@YGXVfoo@@@Z", ARGC_UNKNOWN}, // a class by value has no known size
        {"engine.dll", "?m@C@@QAEXPAV1@0@Z", 2},         // a back reference to a parameter
        {"engine.dll", "?n@?$T@H@@QAEXH@Z", 1},          // a template's member
        {"engine.dll", "?p@@YGXP6GHH@ZH@Z", 2},          // a function pointer parameter
        {"KERNEL32.dll", "NoSuchFunction", ARGC_UNKNOWN},
    };
    for (const Case &k : cases) {
        const uint8_t got = imports_infer_argc(k.dll, k.name);
        check(got == k.want, "%s!%s -> %u (want %u)", k.dll, k.name, got, k.want);
    }
    check(imports_known_win32_sorted(), "the Win32 table is sorted (%zu entries)",
          imports_known_win32_count());
    imports_init();
    std::vector<std::string> bad;
    imports_for_each_registered(registered_agrees, &bad);
    std::string list;
    for (const std::string &b : bad)
        list += " " + b;
    check(bad.empty(), "every shim's own count agrees with the table:%s", list.c_str());
    const uint32_t t =
        imports_alloc_trampoline("mss32.dll", "_AIL_open_digital_driver@16", nullptr, ARGC_UNKNOWN);
    check(imports_argc(t) == 4, "a decorated name still gives its count through the trampoline");
    check(!strcmp(imports_ordinal_name("WS2_32.dll", 12), "inet_ntoa") &&
              !strcmp(imports_ordinal_name("WSOCK32.dll", 12), "ioctlsocket") &&
              !strcmp(imports_ordinal_name("ws2_32", 115), "WSAStartup") &&
              !strcmp(imports_ordinal_name("wsock32", 151), "__WSAFDIsSet") &&
              imports_ordinal_name("KERNEL32.dll", 1) == nullptr,
          "Winsock ordinals name their functions, and differ where the two DLLs differ");
}

// The registry's dispatch cache (cpu.cpp) answers what the binary searches
// over the modules' tables would, hit or miss, collision or not, before and
// after another module registers. Two synthetic modules above everything
// else this suite registers; the second registers only after the first's
// answers are cached, including "no module here" for its own range.
template <int K> static void cache_fn(X86 *c) {
    c->r[R_EAX] = 0xc0de0000u + K;
}
static int32_t ref_index(const std::vector<uint32_t> &v, uint32_t t) {
    auto it = std::lower_bound(v.begin(), v.end(), t);
    return it != v.end() && *it == t ? int32_t(it - v.begin()) : -1;
}
static void test_dispatch_cache() {
    const uint32_t base_a = 0x30000000u, base_b = 0x30100000u, span = 0x100000u;
    uint64_t seed = 0x9e3779b97f4a7c15ull;
    auto next = [&seed]() {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        return uint32_t(seed);
    };
    auto table = [&next](uint32_t base, size_t n) {
        std::vector<uint32_t> v;
        while (v.size() < n) {
            v.push_back(base + (next() % 0x100000u));
            std::sort(v.begin(), v.end());
            v.erase(std::unique(v.begin(), v.end()), v.end());
        }
        return v;
    };
    static std::vector<uint32_t> fa, ra, fb, rb;
    fa = table(base_a, 3000);
    ra = table(base_a, 5000);
    fb = table(base_b, 2000);
    rb = table(base_b, 4000);
    // Some entries are CALL continuations too (an alternate entry after a call).
    for (size_t i = 0; i < 200; ++i)
        ra.push_back(fa[i * 7]);
    std::sort(ra.begin(), ra.end());
    ra.erase(std::unique(ra.begin(), ra.end()), ra.end());
    static void (*const pool[])(X86 *) = {cache_fn<0>, cache_fn<1>, cache_fn<2>, cache_fn<3>};
    static std::vector<void (*)(X86 *)> pa, pb;
    pa.assign(fa.size(), nullptr);
    pb.assign(fb.size(), nullptr);
    for (size_t i = 0; i < pa.size(); ++i)
        pa[i] = pool[i % 4];
    for (size_t i = 0; i < pb.size(); ++i)
        pb[i] = pool[(i + 1) % 4];
    static std::vector<RecompHookFn> ha, hb;
    static std::vector<uint8_t> ka, kb;
    ha.assign(fa.size(), nullptr);
    hb.assign(fb.size(), nullptr);
    ka.assign(fa.size(), 0);
    kb.assign(fb.size(), 0);
    static RecompModule ma = {
        "cache-a.dll", base_a,    base_a + span, fa.data(), uint32_t(fa.size()),
        pa.data(),     ha.data(), ka.data(),     ra.data(), uint32_t(ra.size()),
        nullptr};
    static RecompModule mb = {
        "cache-b.dll", base_b,    base_b + span, fb.data(), uint32_t(fb.size()),
        pb.data(),     hb.data(), kb.data(),     rb.data(), uint32_t(rb.size()),
        nullptr};
    auto pick = [&]() {
        switch (next() % 6) {
        case 0:
            return fa[next() % fa.size()];
        case 1:
            return ra[next() % ra.size()];
        case 2:
            return fb[next() % fb.size()];
        case 3:
            return rb[next() % rb.size()];
        case 4:
            return base_a + next() % (2 * span);
        default:
            return next(); // anywhere, mostly no module
        }
    };
    auto verify = [&](bool with_b, int rounds, const char *when) {
        int bad = 0;
        X86 c{};
        for (int i = 0; i < rounds; ++i) {
            const uint32_t t = pick();
            const bool in_a = t >= base_a && t < base_a + span;
            const bool in_b = with_b && t >= base_b && t < base_b + span;
            const int32_t want = in_a ? ref_index(fa, t) : in_b ? ref_index(fb, t) : -1;
            const bool want_ret = in_a   ? ref_index(ra, t) >= 0
                                  : in_b ? ref_index(rb, t) >= 0
                                         : false;
            const bool other = !in_a && !(t >= base_b && t < base_b + span);
            for (int pass = 0; pass < 2; ++pass) { // a miss, then (mostly) a hit
                if (other)
                    continue; // another suite module may own it; not this test's to say
                if (recomp_module_lookup(t) != want ||
                    !!recomp_module_is_call_return(t) != want_ret ||
                    !!recomp_call_return_any(t) != want_ret)
                    ++bad;
                c.r[R_EAX] = 0;
                const int called = recomp_module_call(&c, t);
                if (called != (want >= 0))
                    ++bad;
                else if (called) {
                    void (*fn)(X86 *) = in_a ? pa[size_t(want)] : pb[size_t(want)];
                    X86 ref{};
                    fn(&ref);
                    if (c.r[R_EAX] != ref.r[R_EAX])
                        ++bad;
                }
            }
        }
        check(bad == 0, "dispatch cache %s: %d wrong answers in %d lookups", when, bad, rounds * 2);
    };
    recomp_module_register(&ma);
    verify(false, 200000, "with one module");
    recomp_module_register(&mb); // empties the cache: b's range was cached as "no module"
    verify(true, 200000, "after a second module registered");
}

int main(int argc, char **argv) {
    if (argc == 3 && !strncmp(argv[1], "--child-", 8))
        return child(argv[1], argv[2]);
    os_setenv("RECOMP_LOG", "1");
    os_unsetenv("RECOMP_STRICT");
    os_unsetenv("RECOMP_NULL_GUARD");
    char tmpl[512];
    snprintf(tmpl, sizeof tmpl, "%s/recomp-loader-%08x", os_temp_dir(),
             (unsigned)(os_monotonic_ns() & 0xffffffffu));
    g_dir = tmpl;
    os_mkdir(g_dir.c_str());

    register_stub<0>();
    register_stub<1>();
    register_stub<2>();
    register_stub<3>();
    register_stub<4>();

    test_argc();
    Config cfg = build_world();
    test_relocation_and_binding(cfg);
    X86 *c = loader_context();
    test_static_attach(c);
    test_dynamic_load(c);
    test_module_resources(c);
    test_file_views(c);
    test_winsock_startup(c);
    test_more_win32(c);
    test_heap_growth(cfg);
    test_exact_ranges(cfg);
    test_import_cycle(cfg);
    test_dll_main_image(cfg);
    test_accepted_digests(cfg);
    test_guards_and_strict(argv[0]);
    test_dispatch_cache();

    for (auto it = g_written.rbegin(); it != g_written.rend(); ++it)
        os_unlink(it->c_str());
    os_unlink((g_dir + "/child.log").c_str());
    os_unlink((g_dir + "/cycle/child.log").c_str());
    os_rmdir((g_dir + "/cycle").c_str());
    os_rmdir((g_dir + "/Temp").c_str());
    os_rmdir(g_dir.c_str());
    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
