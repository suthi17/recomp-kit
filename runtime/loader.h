// loader.h - maps the original PE into the guest arena and starts it.
#pragma once
#include "game_config.h"
#include "guest.h"
#include <string>
#include <vector>

struct SectionInfo {
    std::string name;
    uint32_t va;       // guest virtual address
    uint32_t vsize;    // Misc_VirtualSize
    uint32_t raw_size; // SizeOfRawData
    uint32_t raw_ptr;  // PointerToRawData
    uint32_t characteristics;
};

// Default image and its expected content hash.
extern const char *const LOADER_DEFAULT_EXE; // RECOMP_DEVELOPER_EXE from game.toml
extern const char *const LOADER_EXPECTED_SHA256;
// The SHA-256 of the image loader_load actually mapped, as lowercase hex, or
// "" before a load. Equal to LOADER_EXPECTED_SHA256 on a successful load; kept
// separate because it is a fact about this run rather than a build constant.
const char *loader_exe_sha256();
// The SHA-256 of the file at `path` as lowercase hex, or "" when unreadable.
std::string loader_hash_file(const char *path);
static const uint32_t LOADER_EXPECTED_ENTRY = RECOMP_ENTRY_POINT;

// Maps the PE at `exe_path` (nullptr => LOADER_DEFAULT_EXE) into a freshly
// initialised guest arena: sections at their virtual addresses, tail of each
// section zero filled (.bss), PE headers at the image base, IAT patched with
// import trampolines, TEB/TLS/stack prepared. Refuses any image whose SHA-256
// does not match LOADER_EXPECTED_SHA256. There is no hash bypass.
// Returns false and leaves loader_error() set on failure.
bool loader_load(const char *exe_path = nullptr);

// A module the loader maps beside the image, as game.toml [modules.aux.*]
// describes it: the file name the guest asks for, the developer copy's path,
// its SHA-256, the configured base and the size reserved there (at least
// SizeOfImage). loader_load maps RECOMP_AUX_MODULES. A module is read from
// the player's profile directory when a file of its name is there (an
// overlay for a replaced language DLL), else from beside the executable.
struct LoaderModuleSpec {
    const char *name, *path, *sha256;
    uint32_t base, size;
    // Further SHA-256 digests the loader accepts for this module, separated
    // by spaces; 0 when only sha256 is accepted. For a module a player may
    // replace with a known alternative (a language DLL).
    const char *accept_sha256;
};
// loader_load with an explicit image, hash and module list instead of the
// build's configuration: for tests and tools. Everything else is the same,
// the hash gates included.
bool loader_load_config(const char *exe_path, const char *sha256, const LoaderModuleSpec *modules,
                        uint32_t count);

const char *loader_error();
uint32_t loader_image_base();
uint32_t loader_image_size();
// IMAGE_BASE + SizeOfImage, i.e. one past the last image byte. 0 before a load.
uint32_t loader_image_limit();
uint32_t loader_entry_point();
const std::vector<SectionInfo> &loader_sections();

// The PE TLS directory, if the image has one. index is the slot the loader
// reserved in every thread's TLS array; 0xffffffff when there is none.
struct LoaderTls {
    uint32_t raw_start, raw_end, index_addr, callbacks, zero_fill, index;
};

// A mapped PE module. Auxiliary modules come from game.toml [modules.aux.*].
// The main executable is already attached and also serves code/data exports.
// Auxiliary load references own DllMain attach/detach. The verified, relocated,
// IAT-patched image is retained so a later load starts with fresh globals and
// CRT state.
//
// Every module sits at its configured base. A PE whose preferred ImageBase
// differs is relocated there from its .reloc table as it is mapped - the
// translation was made for the same configured base - so two DLLs that both
// prefer 0x10000000 load side by side without rebased copies.
struct LoaderModule {
    std::string name, path;
    uint32_t base = 0, size = 0, entry = 0, export_rva = 0, export_size = 0;
    bool attached = false;
    uint32_t load_refs = 0;
    std::vector<uint8_t> initial_image;
    std::vector<SectionInfo> sections;
    uint32_t preferred_base = 0; // the PE's ImageBase
    uint32_t relocations = 0;    // base relocations applied while mapping
    uint32_t import_rva = 0, import_size = 0;
    bool is_dll = false;              // IMAGE_FILE_DLL: an entry that is DllMain
    bool thread_calls = true;         // false after DisableThreadLibraryCalls
    bool pinned = false;              // loaded as a static import: never unloaded
    uint32_t attach_seq = 0;          // order of its DLL_PROCESS_ATTACH; 0 = not attached
    std::vector<std::string> imports; // the mapped modules it imports, in import order
    std::vector<std::string> held;    // those it holds a reference on while attached
    LoaderTls tls = {0, 0, 0, 0, 0, 0xffffffffu};
};
uint32_t loader_module_count();
const LoaderModule *loader_module(uint32_t i);
// Count/index enumerate auxiliary modules; name/address lookups include the EXE.
LoaderModule *loader_module_named(const char *name); // case-insensitive, nullptr when unknown
const LoaderModule *loader_module_containing(uint32_t addr);
// The guest address of a named export, 0 when the module has none by that name.
uint32_t loader_module_export(const LoaderModule &m, const char *name);
uint32_t loader_module_export_ordinal(const LoaderModule &m, uint32_t ordinal);
// The module whose handle (base) is `base`, main image included; nullptr otherwise.
LoaderModule *loader_module_at_base(uint32_t base);

// Module lifetimes, the Windows loader's order. Each DllMain and TLS callback
// runs on `c`'s thread, holding the scheduler baton, through guest_call.
//
// Process start: every mapped module the main image imports, directly or
// through another module, dependencies first, and then the main image itself
// when it is a DLL. Each gets its TLS slot and callbacks and
// DllMain(DLL_PROCESS_ATTACH) once and stays for the life of the process. False
// when one fails, as Windows refuses to start; loader_error() names it. run_entry
// does this before the entry point; call it directly to drive a DLL-only image.
bool loader_attach_static(X86 *c);
// LoadLibrary of a mapped module: one reference more. The first loads every
// mapped module it imports (one reference each, dependencies first) and then
// attaches it; a DllMain that refuses is detached again and everything it took
// is released. 0, or the Win32 error (ERROR_DLL_INIT_FAILED).
uint32_t loader_module_load(X86 *c, LoaderModule *m);
// FreeLibrary: one reference less; the last runs DLL_PROCESS_DETACH and then
// releases what the load took. A static import is never unloaded. False for a
// module that holds no reference (or the main image).
bool loader_module_free(X86 *c, LoaderModule *m);
// DLL_THREAD_ATTACH (2) in attach order or DLL_THREAD_DETACH (3) in reverse, for
// every attached module that has not called DisableThreadLibraryCalls, plus
// every attached module's TLS callbacks.
void loader_thread_notify(X86 *c, uint32_t reason);
// DLL_PROCESS_DETACH for every attached module, last attached first, with
// lpReserved nonzero as ExitProcess gives it. Runs once.
void loader_detach_all(X86 *c);
// True inside the main image or any auxiliary module.
bool loader_in_image(uint32_t addr);
const std::string &loader_exe_path();
// IAT slots patched: trampolines for code imports, guest storage for data ones.
uint32_t loader_iat_patched();
uint32_t loader_iat_data_imports();

const LoaderTls &loader_tls();
// Allocates and initialises one thread's TLS block (raw data plus zero fill)
// from the guest heap and stores its address in slot `index` of `tls_array`,
// and does the same for every attached module with a TLS directory.
// Returns the main image's block, 0 when the image has no TLS directory or the
// heap is full.
uint32_t loader_tls_block_for_thread(uint32_t tls_array);
// The same for one TLS directory: the block, or 0.
uint32_t loader_tls_block(const LoaderTls &tls, uint32_t tls_array);

// Resets `c` to the process-start state: zeroed registers, ESP just below
// STACK_TOP with a sentinel return address pushed, FS base at the TEB, x87
// control word GUEST_INITIAL_FPU_CW (0x027f).
void loader_init_context(X86 *c);

// Process-wide context used by run_entry() and by hosts that do not keep their
// own X86 instance.
X86 *loader_context();

// Calls the PE entry point through recomp_call using loader_context().
void run_entry();
void run_entry(X86 *c);
