"""Load a game directory: games/<id>/game.toml plus its curated globals file.

This module is the only place that knows the schema. Python 3.9 has no
tomllib, so the pinned tomli is the fallback."""

from pathlib import Path
import re

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib

REQUIRED_GAME_KEYS = ("id", "name", "app_name", "bundle_id", "executable", "sha256",
                      "image_base", "entry_point", "guest_root", "developer_exe")

HEAP_BASE_DEFAULT = 0x01000000

# The settings page's rows, in mods/display_settings.h DisplayRow order; the
# controls' seven rows are one entry. [settings] rows names the ones a game
# shows. Without the key a game shows every row. "keypad" is the pre-touch-
# controls spelling of "controls"; SETTINGS_ROW_ALIASES keeps it loading.
SETTINGS_ROWS = ("rendering", "ui_scale", "wide_view", "window", "resolution", "frame_limit",
                 "performance_overlay", "textures", "filtering", "controls")
SETTINGS_ROW_ALIASES = {"keypad": "controls"}
# [settings] key: the key that opens and closes the settings page (default F10),
# by its DirectInput scan code; "none" leaves every function key to the game, and
# the page opens only the platform's own way (Command-comma on a Mac, the
# on-screen controls' button). F11 is the performance overlay's.
SETTINGS_KEYS = {"F1": 0x3B, "F2": 0x3C, "F3": 0x3D, "F4": 0x3E, "F5": 0x3F, "F6": 0x40, "F7": 0x41,
                 "F8": 0x42, "F9": 0x43, "F10": 0x44, "F12": 0x58, "none": 0}
# [settings] frame_limit and performance_overlay: what a fresh profile starts
# with, by the rows' own values (mods/display_settings.cpp). Without the key the
# host's default stands (a windowed desktop host: 60 FPS and the graph).
SETTINGS_FRAME_LIMITS = ("original", 40, 60, 120)
SETTINGS_OVERLAYS = ("off", "counters", "graph")

# [controls] default_layout and the on-screen layout picker's choices.
CONTROLS_LAYOUTS = ("pad", "keys", "pad+keys", "hidden")
# [controls.mapped] left_stick/right_stick/dpad modes.
STICK_MODES = ("cursor", "arrows", "horizontal_arrows", "wasd", "scroll", "wheel", "none")
# [controls.native] buttons: the pad button names a physical button maps to.
PAD_BUTTONS = ("cross", "circle", "square", "triangle", "l1", "r1", "l2", "r2", "l3", "r3",
               "select", "start", "ps")
MAPPED_DEFAULTS = {"left_stick": "arrows", "right_stick": "cursor", "dpad": "arrows",
                   "cursor_speed": 900, "cross": "mouse_left", "circle": "mouse_right",
                   "square": "key:Space", "triangle": "key:Tab", "l1": "key:PageUp",
                   "r1": "key:PageDown", "l2": "mouse_middle", "r2": "key:LShift",
                   "start": "key:Escape", "select": "key:F10", "l3": "none", "r3": "none",
                   "ps": "action:settings"}
# [controls.native] axes: the six DirectInput/XInput axis names a physical
# axis maps to.
NATIVE_AXES = ("x", "y", "z", "rx", "ry", "rz")
# Mirrors the name column of host/controls/layout.cpp's kScancodes table (its
# scancode_from_name); keep both lists in sync.
KEY_NAMES = (
    "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S",
    "T", "U", "V", "W", "X", "Y", "Z", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "Return",
    "Escape", "Backspace", "Tab", "Space", "Minus", "Equals", "LeftBracket", "RightBracket",
    "Backslash", "Semicolon", "Apostrophe", "Grave", "Comma", "Period", "Slash", "F1", "F2", "F3",
    "F4", "F5", "F6", "F7", "F8", "F9", "F10", "F11", "F12", "Insert", "Home", "PageUp", "Delete",
    "End", "PageDown", "Right", "Left", "Down", "Up", "LCtrl", "LShift", "LAlt",
)
# key:<name>, mouse_left/right/middle, wheel_up/down, action:<name> or none.
BUTTON_TARGET_RE = re.compile(
    r"^(key:[A-Za-z0-9]+|mouse_(left|right|middle)|wheel_(up|down)|"
    r"action:(settings|system_keyboard|edit_layout)|none)$")
HEAP_END = 0x0e000000        # runtime/x86.h GUEST_HEAP_END; the mods' heap starts there
GUEST_SIZE_DEFAULT = 0x10000000   # runtime/x86.h GUEST_SIZE: the arena, 256 MB unless a module needs more
AUX_REQUIRED_KEYS = ("name", "path", "sha256", "base", "size")


def windows_version(value):
    """Decode major.minor[.build]; keep the historical 9x default and 6.1 SP1."""
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", value):
        raise ValueError("[game] windows_version must be major.minor[.build]")
    parts = [int(part) for part in value.split(".")]
    major, minor = parts[:2]
    build = parts[2] if len(parts) == 3 else {(4, 10): 2222, (6, 1): 7601}.get((major, minor), 0)
    if major > 255 or minor > 255 or build > 32767:
        raise ValueError("[game] windows_version requires byte-sized major/minor and a 15-bit build")
    return major, minor, build, 2 if major >= 5 else 1


def validate_heap_base(value):
    """The heap arena start: page aligned, above the image base, below the arena end."""
    if value % 0x1000 or not (0x00400000 < value < HEAP_END):
        raise ValueError("[game] heap_base %#x must be page aligned and between 0x00400000 and %#x" % (value, HEAP_END))
    return value


def load_controls(controls, touch, source):
    """Validate [controls], merging [controls.mapped]/[controls.native] over their
    defaults. `touch` is the already-defaulted [touch] table: its `keypad` knob
    only sets `default_layout` when the game has not named one itself."""
    controls = dict(controls)
    if "default_layout" not in controls:
        controls["default_layout"] = {"auto": "keys", "hidden": "hidden"}[touch["keypad"]]
    if controls["default_layout"] not in CONTROLS_LAYOUTS:
        raise ValueError("%s: [controls] default_layout must be one of %s, not %r"
                         % (source, ", ".join(CONTROLS_LAYOUTS), controls["default_layout"]))
    pad = controls.setdefault("pad", "mapped")
    if pad not in ("native", "mapped", "off"):
        raise ValueError('%s: [controls] pad must be "native", "mapped" or "off", not %r' % (source, pad))

    mapped = dict(MAPPED_DEFAULTS)
    mapped.update(controls.get("mapped", {}))
    unknown = sorted(k for k in mapped if k not in MAPPED_DEFAULTS)
    if unknown:
        raise ValueError("%s: [controls.mapped] may name only %s, not %s"
                         % (source, ", ".join(sorted(MAPPED_DEFAULTS)), ", ".join(unknown)))
    for key, value in mapped.items():
        if key == "cursor_speed":
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError("%s: [controls.mapped] cursor_speed must be a positive integer, not %r"
                                 % (source, value))
        elif key in ("left_stick", "right_stick"):
            if value not in STICK_MODES:
                raise ValueError("%s: [controls.mapped] %s must be one of %s, not %r"
                                 % (source, key, ", ".join(STICK_MODES), value))
        elif key == "dpad":
            if value not in ("arrows", "wasd", "none"):
                raise ValueError('%s: [controls.mapped] dpad must be "arrows", "wasd" or "none", not %r'
                                 % (source, value))
        elif not isinstance(value, str) or not BUTTON_TARGET_RE.match(value):
            raise ValueError("%s: [controls.mapped] %s is not a valid target: %r" % (source, key, value))
        elif value.startswith("key:") and value[len("key:"):] not in KEY_NAMES:
            raise ValueError("%s: [controls.mapped] %s names no key: %r" % (source, key, value))
    controls["mapped"] = mapped

    native = dict(controls.get("native", {}))
    unknown_native = sorted(k for k in native if k not in ("xinput", "dinput", "axes", "buttons"))
    if unknown_native:
        raise ValueError("%s: [controls.native] may name only xinput, dinput, axes, buttons, not %s"
                         % (source, ", ".join(unknown_native)))
    native.setdefault("xinput", True)
    native.setdefault("dinput", True)
    if not isinstance(native["xinput"], bool) or not isinstance(native["dinput"], bool):
        raise ValueError("%s: [controls.native] xinput and dinput must be booleans" % source)
    axes = native.setdefault("axes", ["x", "y", "z", "rz", "rx", "ry"])
    if not isinstance(axes, list) or sorted(axes) != sorted(NATIVE_AXES):
        raise ValueError("%s: [controls.native] axes must list all six of %s exactly once, not %r"
                         % (source, ", ".join(NATIVE_AXES), axes))
    buttons = native.setdefault(
        "buttons", ["square", "cross", "circle", "triangle", "l1", "r1", "l2", "r2", "select",
                   "start", "l3", "r3", "ps"])
    if not isinstance(buttons, list) or sorted(buttons) != sorted(PAD_BUTTONS):
        raise ValueError("%s: [controls.native] buttons must list all thirteen of %s exactly once, not %r"
                         % (source, ", ".join(PAD_BUTTONS), buttons))
    controls["native"] = native
    return controls


def function_db_path(game_dir, value, where, source):
    """A function database (tools/recomp/translate.py FunctionDB) named
    relative to game.toml, or None. It lives with the listings in the ignored
    analysis/ tree, so it need not exist until a translation reads it."""
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError("%s: %s function_db must be a path, not %r" % (source, where, value))
    return (Path(game_dir) / value).resolve()


def load(game_dir):
    """Return the parsed config with `globals` merged in and `dir`/`source` recorded."""
    game_dir = Path(game_dir)
    source = game_dir / "game.toml"
    with source.open("rb") as fh:
        cfg = tomllib.load(fh)
    game = cfg.get("game", {})
    missing = [key for key in REQUIRED_GAME_KEYS if key not in game]
    if missing:
        raise ValueError("%s: missing [game] keys: %s" % (source, ", ".join(missing)))
    game["heap_base"] = validate_heap_base(int(game.get("heap_base", HEAP_BASE_DEFAULT)))
    windows_version(game.setdefault("windows_version", "4.10"))
    translate = cfg.setdefault("translate", {})
    resumable = translate.setdefault("resumable_stacks", False)
    if not isinstance(resumable, bool):
        raise ValueError("%s: [translate] resumable_stacks must be a boolean" % source)
    alignment = translate.setdefault("function_alignment", 16)
    if type(alignment) is not int or alignment <= 0:
        raise ValueError("%s: [translate] function_alignment must be a positive integer" % source)
    tracks = cfg.setdefault("media", {}).setdefault("cd_tracks", [])
    if not isinstance(tracks, list) or not all(isinstance(v, str) for v in tracks):
        raise ValueError("%s: [media] cd_tracks must be a list of strings" % source)
    # [network] offline_hosts: names gethostbyname fails at once rather than
    # ask a resolver about, such as a long-gone server (runtime/winsock.cpp).
    offline = cfg.setdefault("network", {}).setdefault("offline_hosts", [])
    if not isinstance(offline, list) or not all(isinstance(v, str) and v for v in offline):
        raise ValueError("%s: [network] offline_hosts must be a list of host names" % source)
    cfg.setdefault("hooks", {})
    cfg.setdefault("bundle", {}).setdefault("exclude", [])
    touch = cfg.setdefault("touch", {})
    touch.setdefault("keypad", "auto")
    if touch["keypad"] not in ("auto", "hidden"):
        raise ValueError('%s: [touch] keypad must be "auto" or "hidden", not %r' % (source, touch["keypad"]))
    cfg["controls"] = load_controls(cfg.get("controls", {}), touch, source)
    settings = cfg.setdefault("settings", {})
    rows = settings.setdefault("rows", list(SETTINGS_ROWS))
    if not isinstance(rows, list):
        raise ValueError("%s: [settings] rows must be a list, not %r" % (source, rows))
    rows = [SETTINGS_ROW_ALIASES.get(row, row) for row in rows]
    unknown = [row for row in rows if row not in SETTINGS_ROWS]
    if unknown:
        raise ValueError("%s: [settings] rows may name only %s, not %s"
                         % (source, ", ".join(SETTINGS_ROWS), ", ".join(map(repr, unknown))))
    settings["rows"] = rows
    key = settings.setdefault("key", "F10")
    if key not in SETTINGS_KEYS:
        raise ValueError("%s: [settings] key must be one of %s, not %r"
                         % (source, ", ".join(SETTINGS_KEYS), key))
    limit = settings.get("frame_limit")
    if limit is not None and (isinstance(limit, bool) or limit not in SETTINGS_FRAME_LIMITS):
        raise ValueError("%s: [settings] frame_limit must be one of %s, not %r"
                         % (source, ", ".join(map(str, SETTINGS_FRAME_LIMITS)), limit))
    overlay = settings.get("performance_overlay")
    if overlay is not None and overlay not in SETTINGS_OVERLAYS:
        raise ValueError("%s: [settings] performance_overlay must be one of %s, not %r"
                         % (source, ", ".join(SETTINGS_OVERLAYS), overlay))
    launcher = cfg.setdefault("launcher", {})
    launcher.setdefault("title", game["name"])
    launcher.setdefault("store", "")
    for key in ("install_names", "gog_ids", "steam_ids"):
        value = launcher.setdefault(key, [])
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ValueError("%s: [launcher] %s must be a list of strings" % (source, key))
    for key in ("title", "store"):
        if not isinstance(launcher[key], str):
            raise ValueError("%s: [launcher] %s must be a string" % (source, key))
    min_free = launcher.setdefault("min_free_mb", 0)
    if not isinstance(min_free, int) or min_free < 0:
        raise ValueError("%s: [launcher] min_free_mb must be a non-negative integer" % source)
    setup_dirs = cfg.setdefault("setup", {}).setdefault("required_dirs", [])
    if not isinstance(setup_dirs, list):
        raise ValueError("%s: [setup] required_dirs must be a list" % source)
    globals_path = game_dir / translate.get("globals", "globals.toml")
    with globals_path.open("rb") as fh:
        cfg["globals"] = tomllib.load(fh).get("globals", {})
    cfg["dir"] = game_dir
    cfg["source"] = str(source)
    # Developer inputs live beside game.toml: a game repository holds its own
    # ignored original/ and analysis/ directories.
    cfg["developer_exe_path"] = (game_dir / game["developer_exe"]).resolve()
    cfg["listings_path"] = (game_dir / translate.get("listings", "analysis")).resolve()
    cfg["function_db_path"] = function_db_path(game_dir, translate.get("function_db"), "[translate]", source)
    # [translate] overrides: a header the generated sources include before they
    # define FN_<addr>, so a game can replace one translated function with a
    # native one (translate.py's RECOMP_OVERRIDE_HEADER). Absent by default,
    # and required to exist when named: a path that silently does not resolve
    # would leave the build looking replaced while running the original.
    overrides = translate.get("overrides")
    cfg["overrides_header"] = None
    if overrides is not None:
        path = (game_dir / overrides).resolve()
        if not path.is_file():
            raise ValueError("%s: [translate] overrides names no file: %s" % (source, path))
        cfg["overrides_header"] = path
    cfg["aux_modules"] = load_aux_modules(cfg, game_dir, source)
    load_runtime(cfg, source)
    return cfg


def load_runtime(cfg, source):
    """[runtime] strict: the default of the runtime's strict mode (RECOMP_STRICT
    overrides it at run time). [runtime] ddraw7: whether DirectDraw 7 is offered
    (RECOMP_DDRAW7 overrides it). relative_mouse: a DirectInput mouse acquired
    exclusively takes raw relative motion with the system pointer hidden, as on
    Windows, instead of motion derived from window positions
    (RECOMP_RELATIVE_MOUSE). system_fonts: GDI draws a Windows face the game
    did not supply with the platform's own copy of it, measured as Windows
    measures it, instead of the bundled stand-in (RECOMP_SYSTEM_FONTS).
    dmusic: CoCreateInstance makes DirectMusic's classes (RECOMP_DMUSIC).
    [imports.argc]: "DLL!name" = the stdcall argument count (dwords) of an
    import no shim and no built-in table describes, or "cdecl" - what a game
    knows from its own symbol data."""
    runtime = cfg.setdefault("runtime", {})
    strict = runtime.setdefault("strict", False)
    if not isinstance(strict, bool):
        raise ValueError("%s: [runtime] strict must be a boolean" % source)
    # [runtime] ddraw7: DirectDrawCreateEx serves IID_IDirectDraw7 (dx/ddraw7.cpp).
    # Off by default, because a game that probes for version 7 and falls back to
    # DirectDrawCreate when it is refused takes the version 7 path once offered.
    ddraw7 = runtime.setdefault("ddraw7", False)
    if not isinstance(ddraw7, bool):
        raise ValueError("%s: [runtime] ddraw7 must be a boolean" % source)
    # [runtime] dmusic: CoCreateInstance makes DirectMusic's loader, composer and
    # performance (dx/dmusic.cpp). Off by default: a game that copes without
    # DirectMusic keeps doing so until it asks.
    for key in ("relative_mouse", "system_fonts", "dmusic"):
        if not isinstance(runtime.setdefault(key, False), bool):
            raise ValueError("%s: [runtime] %s must be a boolean" % (source, key))
    argc = cfg.setdefault("imports", {}).setdefault("argc", {})
    if not isinstance(argc, dict):
        raise ValueError("%s: [imports.argc] must be a table" % source)
    for key, value in argc.items():
        dll, bang, name = key.partition("!")
        if not bang or not dll or not name:
            raise ValueError('%s: [imports.argc] key %r must be "DLL!name"' % (source, key))
        if value != "cdecl" and (type(value) is not int or not 0 <= value < 0xfe):
            raise ValueError('%s: [imports.argc] %r must be a dword count below 254 or "cdecl"'
                             % (source, key))


def load_aux_modules(cfg, game_dir, source):
    """[modules.aux.<key>]: a DLL the guest loads (LoadLibrary or a static
    import) that the kit translates as a second image and maps at `base`, so
    its code runs as translated code and its exports answer GetProcAddress.
    Keys: name (the file name the guest asks for), path (developer copy,
    relative to game.toml), sha256, base and size (where it is translated for
    and mapped - the loader and the translator both apply the module's base
    relocations when it prefers another base - and at least its SizeOfImage),
    listings (Ghidra export directory, relative), function_db (an
    authoritative function database, relative; see translate.py FunctionDB),
    function_alignment (default 4) and accept_sha256 (optional: further
    digests the loader accepts for this module at run time, for a
    resource-only module a player may replace, such as a language DLL; the
    translation is still made from the file `sha256` names). [game] guest_size must reach past
    every module; the default arena is 0x10000000."""
    game = cfg["game"]
    guest_size = int(game.setdefault("guest_size", GUEST_SIZE_DEFAULT))
    if guest_size % 0x1000 or guest_size < GUEST_SIZE_DEFAULT:
        raise ValueError("%s: [game] guest_size %#x must be page aligned and at least %#x"
                         % (source, guest_size, GUEST_SIZE_DEFAULT))
    game["guest_size"] = guest_size
    modules = []
    for key, entry in sorted(cfg.get("modules", {}).get("aux", {}).items()):
        missing = [k for k in AUX_REQUIRED_KEYS if k not in entry]
        if missing:
            raise ValueError("%s: [modules.aux.%s] missing keys: %s" % (source, key, ", ".join(missing)))
        base, size = int(entry["base"]), int(entry["size"])
        if base % 0x1000 or size <= 0 or base + size > guest_size:
            raise ValueError("%s: [modules.aux.%s] base %#x size %#x must fit below guest_size %#x"
                             % (source, key, base, size, guest_size))
        alignment = entry.get("function_alignment", 4)
        if type(alignment) is not int or alignment <= 0:
            raise ValueError("%s: [modules.aux.%s] function_alignment must be a positive integer" % (source, key))
        entries = entry.get("entry_points", [])
        if not isinstance(entries, list) or any(type(a) is not int or not base <= a < base + size
                                               for a in entries):
            raise ValueError("%s: [modules.aux.%s] entry_points must be addresses inside the module"
                             % (source, key))
        accept = entry.get("accept_sha256", [])
        if not isinstance(accept, list) or any(not isinstance(h, str) or len(h) != 64 for h in accept):
            raise ValueError("%s: [modules.aux.%s] accept_sha256 must be a list of SHA-256 hex digests"
                             % (source, key))
        modules.append({
            "key": key, "name": entry["name"], "sha256": entry["sha256"], "accept_sha256": accept,
            "base": base, "size": size,
            "path": (game_dir / entry["path"]).resolve(),
            "listings_path": (game_dir / entry.get("listings", "analysis/" + entry["name"])).resolve(),
            "function_alignment": alignment,
            "entry_points": entries,
            "function_db_path": function_db_path(game_dir, entry.get("function_db"),
                                                 "[modules.aux.%s]" % key, source),
        })
    return modules
