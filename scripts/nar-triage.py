#!/usr/bin/env python3
"""nar-triage.py: first-5-minutes APK triage for the NAR Skill.

Stdlib-only, no pip dependencies. Reads the APK as a ZIP (never executes it)
and reports identity, inventory, and structure.

Usage:
    python3 nar-triage.py app.apk [--json]
    python3 nar-triage.py app.aab [--json]     # AABs are ZIPs too; flagged as such
    python3 nar-triage.py app.xapk [--json]    # XAPK/APKM containers: manifest + contents
    python3 nar-triage.py main.123.com.game.obb [--json]  # OBB expansion files

Output: SHA-256, size, ZIP entry breakdown (DEX files, .so per ABI,
resources.arsc, AndroidManifest.xml, META-INF cert files, assets/res counts),
DEX list with sizes and DEX format versions (035/037/038/039/040/041, read
from each DEX header), native library list, signing files and signature
schemes (via `apksigner verify --verbose` when apksigner is available),
game-engine hints (Unity / Unreal / Godot / Cocos / Flutter / libGDX /
Adobe AIR / React Native old and new architecture, from path signatures
only), engine version hints from binary headers (Unity IL2CPP metadata
version, Godot PCK pack format and engine version, Unreal version from
the libUE4/libUnreal build string), DEX content markers
(Kotlin, Jetpack Compose, AndroidX, legacy support library, Play
Integrity, legacy Apache HttpClient, and more, from string fingerprints
inside the DEX files), library versions from META-INF/*.version files,
Rust markers in native libs (Rust runtime strings inside .so files),
baseline profiles, game asset-bundle inventory (.pak / .bundle /
.unity3d / .obb / .pck), XAPK/APKM container handling (identity and
splits from the container manifest.json), split-APK detection, and
protection systems (named commercial packers and VM protectors,
obfuscation evidence, anti-tamper / RASP markers, SSL pinning, licensing
and DRM, code and asset encryption, native hardening posture — from
ZIP entry names, DEX bytes, and ELF headers only; detection and
reporting, never bypass).
When aapt2 is available, package name / version / SDK levels from
`aapt2 dump badging` are included (first <uses-sdk> wins, duplicates
and platform-implied permissions are reported, not hidden); otherwise
those fields report why badging is unavailable.

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import glob
import hashlib
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import zipfile

DEX_RE = re.compile(r"^(base/dex/)?classes\d*\.dex$")
SO_RE = re.compile(r"^(base/)?lib/([^/]+)/(.+\.so)$")
SPLIT_RE = re.compile(r"(^|[._-])config\.|split_config|^split\.", re.IGNORECASE)
OBB_RE = re.compile(r"^(main|patch)\.(\d+)\.(.+)\.obb$", re.IGNORECASE)

# Game-engine / framework signatures: simple path-substring matching on ZIP
# entry names. A hit is a HINT, not proof. Confirm with the native guide.
ENGINE_SIGNATURES = [
    ("Unity (IL2CPP)", ["libil2cpp.so", "global-metadata.dat"]),
    ("Unity (Mono)", ["assembly-csharp.dll", "libmono.so"]),
    ("Unreal Engine", ["libue4.so", "libunreal.so", ".pak"]),
    ("Godot", ["libgodot"]),
    ("Cocos2d-x", ["libcocos2dcpp.so", "libcocos2djs.so"]),
    ("Flutter", ["libflutter.so", "libapp.so"]),
    ("React Native", ["libreactnativejni.so", "libhermes.so"]),
    # New architecture (Fabric renderer + TurboModules). libfabricjni.so and
    # libturbomodulejsijni.so ship with React Native 0.68+; newer releases
    # consolidate into libreactnative.so. Presence of the libs means the
    # new-arch code is in the APK; the deciding check is the
    # IS_NEW_ARCHITECTURE_ENABLED flag in BuildConfig (see the DEX markers
    # below and references/modern-analysis.md).
    ("React Native (new architecture)", ["libfabricjni.so", "libturbomodulejsijni.so",
                                         "libreact_nativemodule_core.so",
                                         "libreact_render_core.so", "libreactnative.so"]),
    ("libGDX", ["libgdx.so", "libgdx-freetype.so", "libgdx-bullet.so"]),
    # Adobe AIR: the descriptor is the ONLY reliable entry marker.
    # A bare .swf is not one: unrelated apps bundle Flash files as
    # web-content fallbacks (media-player / JS-library assets) and
    # were misattributed to AIR by the old ".swf" substring pattern.
    # Real AIR apps always ship the descriptor; the com/adobe/air
    # DEX marker below corroborates.
    ("Adobe AIR", ["META-INF/AIR/application.xml"]),
    # Xamarin / .NET for Android (incl. .NET MAUI): the Mono runtime
    # library, the app-model library, and the managed assemblies
    # directory at the zip root are the shipped fingerprints.
    ("Xamarin / .NET", ["libmonodroid.so", "libxamarin-app.so",
                        "libmonosgen", "assemblies/"]),
    # Hybrid web frameworks. Cordova's shipped runtime script is the
    # strong marker; Capacitor ships its config + plugin registry and
    # serves the app from assets/public/. Ionic is a UI layer on top
    # of one of these two, so it is attributed to its container.
    # Legacy Cordova / PhoneGap (pre-3.0) shipped the runtime
    # under a versioned name (cordova-2.5.0.js, phonegap-1.4.js);
    # the exact-name marker alone misses those builds entirely
    # even when the org/apache/cordova DEX marker is present.
    ("Cordova (hybrid)", ["assets/www/cordova.js",
                          "assets/www/cordova-1.",
                          "assets/www/cordova-2.",
                          "assets/www/phonegap.js",
                          "assets/www/phonegap-"]),
    ("Capacitor (hybrid)", ["capacitor.config.json",
                            "capacitor.plugins.json", "assets/public/"]),
    # Qt for Android: every Qt deployment ships the Core library for
    # the Qt major it links (libQt5Core / libQt6Core) plus the Android
    # platform plugin library.
    ("Qt for Android", ["libqt5core.so", "libqt6core.so",
                        "libqtforandroid.so"]),
    # Defold: the engine ships as a single native library.
    ("Defold", ["libdmengine.so"]),
    # Ren'Py: compiled script files (.rpyc) are unique to the engine;
    # its native Python runtime library is the second marker.
    ("Ren'Py", [".rpyc", "librenpython.so"]),
    # RPG Maker MV / MZ Android exports are web exports: their core
    # runtime scripts have engine-specific names inside assets/www.
    ("RPG Maker (web export)", ["rpg_core.js", "rmmz_core.js"]),
    # Embedded CPython: python-for-android (Kivy, Ren'Py) and other
    # embedders link libpython. The DEX markers below say whose
    # runtime it is when that is knowable.
    ("Embedded Python", ["libpython3", "libpython2.7.so"]),
    # Any app bundling a web tree under assets/www: a hybrid
    # framework, a WebView wrapper, or bundled web content. A content
    # hint only; the framework markers above say more when they hit.
    ("Web assets (assets/www)", ["assets/www/"]),
]
# DEX content markers: byte fingerprints searched inside each DEX file.
# These are string occurrences in the DEX string/type tables, so a hit
# means the framework's classes are referenced, not that they run.
# Kotlin deliberately does NOT rely on `kotlin/Metadata` alone: R8
# strips that annotation in release builds, so type descriptors
# (`Lkotlin/...`) and the coroutines package are the durable evidence.
DEX_MARKERS = [
    ("Kotlin", [b"kotlin/Metadata", b"Lkotlin/", b"kotlinx/coroutines"]),
    ("Jetpack Compose", [b"androidx/compose"]),
    ("Compose Multiplatform", [b"org/jetbrains/compose"]),
    ("AndroidX", [b"androidx/"]),
    ("Android support library (legacy)", [b"android/support/"]),
    ("Play Integrity API", [b"com/google/android/play/core/integrity"]),
    ("Apache HttpClient (legacy)", [b"org/apache/http"]),
    ("Adobe AIR", [b"com/adobe/air"]),
    ("libGDX", [b"com/badlogic/gdx"]),
    ("Flutter", [b"io/flutter/embedding"]),
    ("Unity player wrapper", [b"com/unity3d/player"]),
    ("Godot wrapper", [b"org/godotengine/godot"]),
    ("Cocos2d-x wrapper", [b"org/cocos2dx/lib"]),
    ("Xamarin / .NET runtime", [b"mono/android/"]),
    ("Cordova", [b"org/apache/cordova"]),
    ("Capacitor", [b"com/getcapacitor/"]),
    ("Qt for Android", [b"org/qtproject/qt"]),
    ("Kivy", [b"org/kivy/android"]),
    ("Ren'Py runtime", [b"org/renpy/android"]),
    ("EasyRPG Player", [b"org/easyrpg/player"]),
    # The flag string existing says nothing about its value. Read
    # BuildConfig.smali (apktool) to see true/false.
    ("React Native new-arch flag", [b"IS_NEW_ARCHITECTURE_ENABLED"]),
]
# Rust markers: byte fingerprints searched inside each .so file. A hit
# suggests Rust code is linked into the library. Absence proves nothing:
# stripped release builds can hide every one of these strings.
RUST_PATTERNS = [b"panicked at", b"rustc version", b"rust_begin_unwind", b".rustc"]
# Total .so bytes scanned for Rust markers before the scan stops. Triage
# must stay fast on games with hundreds of MB of native code.
RUST_SCAN_BUDGET_BYTES = 512 * 1024 * 1024

# ---------------------------------------------------------------------
# Protection systems. Detection and reporting ONLY: a hit means
# protection artifacts or protection code ship inside the package. It
# says nothing about whether a check passed at runtime, and NAR never
# uses this to bypass anything (see the legitimate-use boundary in
# SKILL.md).
#
# The signatures themselves — categories, named packers, RASP and
# licensing DEX markers, the Widevine UUID forms, the pin/stub
# patterns and the stub thresholds — live in the versioned data
# artifact scripts/protection-signatures.json (database schema 1)
# and are loaded via narlib.signatures (Evolution Phase 5). The
# artifact carries the attribution discipline in its own notes: a
# finding is attributed to a named product only when a marker is
# dedicated to that product, and protection kinds with no reliable
# static marker are deliberately absent rather than guessed.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from narlib import signatures as _signatures
    _SIG = _signatures.load_signatures()
except Exception as _sig_err:  # missing/corrupt DB: fail loudly
    raise SystemExit(
        "nar-triage: protection signature database unusable: "
        f"{_sig_err} (run nar-doctor to diagnose the install)")

PROTECTION_SIGNATURES_VERSION = _SIG["database_version"]
PROTECTION_CATEGORIES = _SIG["categories"]
PROTECTION_CATEGORY_LABELS = _SIG["category_labels"]
PROTECTION_CATEGORY_ORDER = _SIG["category_order"]
# Named commercial packers / VM protectors: (product name, .so
# matchers, DEX byte patterns, other entry-name substrings).
PACKER_MARKERS = _SIG["packer_markers"]
# Anti-tamper / RASP DEX markers: (finding name, byte patterns,
# note). Presence shows the check ships in the app; it does not
# show the check firing.
RASP_DEX_MARKERS = _SIG["rasp_dex_markers"]
# Licensing / DRM DEX markers: (finding name, byte patterns, note).
LICENSING_DEX_MARKERS = _SIG["licensing_dex_markers"]
# Widevine's MediaDrm scheme UUID in its four byte forms (see the
# database artifact for the full note; the finding fires on the
# string form, the raw bytes, or BOTH long halves in the SAME dex).
WIDEVINE_UUID_STRING = _SIG["widevine"]["uuid_string"]
WIDEVINE_UUID_RAW = _SIG["widevine"]["uuid_raw"]
WIDEVINE_UUID_MSB_LE = _SIG["widevine"]["uuid_msb_le"]
WIDEVINE_UUID_LSB_LE = _SIG["widevine"]["uuid_lsb_le"]
WIDEVINE_DEX_PATTERNS = _SIG["widevine"]["dex_patterns"]
# OkHttp pin constants and network-security-config pins share the
# "sha256/<base64>" shape.
PIN_CONSTANT_RE = _SIG["pin_constant_re"]
# Class descriptors ending in StubApp: the classic packer stub
# shape. Attributed stubs are claimed by PACKER_MARKERS first;
# whatever is left over is reported unattributed, never guessed.
STUB_DESCRIPTOR_RE = _SIG["stub_descriptor_re"]
# A primary DEX below this size, inside an app whose bulk is
# native or asset payload, is the shell pattern.
STUB_DEX_MAX_BYTES = _SIG["stub_dex_max_bytes"]
STUB_APP_MIN_BYTES = _SIG["stub_app_min_bytes"]
STUB_PAYLOAD_MIN_BYTES = _SIG["stub_payload_min_bytes"]
# DEX files larger than this are byte-scanned as streams (as before)
# but not held in memory for the string-table parse.
DEX_STRING_PARSE_MAX_BYTES = 96 * 1024 * 1024
# Symbol-table reads for the stripped check are skipped on very large
# libraries (their section headers sit at the end of a long deflate
# stream); the posture then reports stripped as unknown for them.
ELF_SYMTAB_MAX_BYTES = 32 * 1024 * 1024
PAK_MAGIC_BYTES = struct.pack("<I", 0x5A6F12E1)
# Unity IL2CPP metadata format version -> engine era. From builds checked
# in REA's il2cpp-metadata docs (2019.4.41f1 -> 24, 2020.3.49f1 -> 27,
# 2022.3.30f1 -> 29, 2022.3.62f3 -> 31, 6000.4.2f1 -> 39). The mapping is
# by example build, not a strict rule: always report the raw version.
UNITY_METADATA_ERAS = {
    24: "Unity 2019 era",
    27: "Unity 2020 era",
    29: "Unity 2021/2022 era",
    31: "Unity 2022 (late) era",
    39: "Unity 6 (6000.x) era",
}
UNITY_METADATA_MAGIC = 0xFAB11BAF
# Unreal build string embedded in libUE4.so / libUnreal.so, e.g.
# "++UE4+Release-4.16+Compile...". The branch suffix varies; the
# engine generation and release number are the stable part.
UE_VERSION_RE = re.compile(rb"\+\+(UE[45])\+Release-(\d+\.\d+(?:\.\d+)?)")
# Godot PCK pack format version -> engine line (GodotPckTool constants).
GODOT_PCK_ERAS = {
    1: "Godot 3.x",
    2: "Godot 4.0-4.4",
    3: "Godot 4.5+",
    4: "Godot 4.7 era",
}
BUNDLE_EXTS = (".pak", ".bundle", ".unity3d", ".obb", ".assets", ".resource", ".pck")
DEX_MAGIC_RE = re.compile(rb"^dex\n(\d{3})\x00$")
APKSIGNER_SCHEME_PATTERNS = {
    "v1": re.compile(r"^Verified using v1 scheme \(JAR signing\): (true|false)"),
    "v2": re.compile(r"^Verified using v2 scheme \(APK Signature Scheme v2\): (true|false)"),
    "v3": re.compile(r"^Verified using v3 scheme \(APK Signature Scheme v3\): (true|false)"),
    "v3_1": re.compile(r"^Verified using v3\.1 scheme \(APK Signature Scheme v3\.1\): (true|false)"),
    "v4": re.compile(r"^Verified using v4 scheme \(APK Signature Scheme v4\): (true|false)"),
    "source_stamp": re.compile(r"^Verified for SourceStamp: (true|false)"),
}
BADGING_PATTERNS = {
    "package": re.compile(r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']*)'"),
    "sdk": re.compile(r"^(?:minSdkVersion|sdkVersion):'([^']+)'"),
    "target_sdk": re.compile(r"^targetSdkVersion:'([^']+)'"),
    "app_label": re.compile(r"^application-label:'([^']*)'"),
}


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def count_patterns_in_stream(stream, patterns, budget=None):
    """Count byte-pattern occurrences in a stream, chunk by chunk.

    Memory-bounded: only one 1 MB chunk plus a small overlap tail is held
    at a time. A match that straddles a chunk boundary is still counted
    exactly once, using absolute end offsets. Returns (counts, bytes_read,
    truncated), where truncated is True when the byte budget stopped the
    scan before end of stream.
    """
    maxlen = max(len(p) for p in patterns)
    counts = {p: 0 for p in patterns}
    buf = b""
    buf_base = 0          # absolute offset of buf[0]
    counted_through = 0   # matches ending at or before this offset are counted
    bytes_read = 0
    truncated = False
    while True:
        if budget is not None and bytes_read >= budget:
            truncated = True
            break
        to_read = 1 << 20
        if budget is not None:
            to_read = min(to_read, budget - bytes_read)
        chunk = stream.read(to_read)
        if not chunk:
            # End of stream: everything left in the buffer is countable.
            for p in patterns:
                start = 0
                while True:
                    i = buf.find(p, start)
                    if i < 0:
                        break
                    if buf_base + i + len(p) > counted_through:
                        counts[p] += 1
                    start = i + 1
            break
        bytes_read += len(chunk)
        buf += chunk
        # Only count matches ending before the last (maxlen - 1) bytes:
        # a match ending later may be cut in half by the chunk edge.
        safe_end = buf_base + len(buf) - (maxlen - 1)
        for p in patterns:
            start = 0
            while True:
                i = buf.find(p, start)
                if i < 0:
                    break
                abs_end = buf_base + i + len(p)
                if abs_end > safe_end:
                    break  # later matches end even later
                if abs_end > counted_through:
                    counts[p] += 1
                start = i + 1
        counted_through = max(counted_through, safe_end)
        # Keep enough tail for a match that starts before counted_through
        # but ends after it.
        keep_from = max(0, counted_through - maxlen - buf_base)
        buf = buf[keep_from:]
        buf_base += keep_from
    return counts, bytes_read, truncated


def dex_version_of(zf, name):
    """DEX format version from the 8-byte header magic, e.g. "037".

    Returns None when the entry cannot be read or has no DEX magic.
    """
    try:
        with zf.open(name) as f:
            head = f.read(8)
    except (KeyError, OSError, zipfile.BadZipFile):
        return None
    m = DEX_MAGIC_RE.match(head)
    return m.group(1).decode("ascii") if m else None


def unity_metadata_version_of(zf, name):
    """IL2CPP metadata format version from global-metadata.dat.

    Header is magic 0xFAB11BAF (little-endian) then a uint32 version.
    Returns None when the entry is missing, short, or has no IL2CPP magic
    (for example, encrypted or obfuscated metadata).
    """
    try:
        with zf.open(name) as f:
            head = f.read(8)
    except (KeyError, OSError, zipfile.BadZipFile):
        return None
    if len(head) < 8:
        return None
    magic, version = struct.unpack("<II", head)
    if magic != UNITY_METADATA_MAGIC:
        return None
    return version


def godot_pck_info_of(zf, name):
    """Godot PCK pack format version and engine version from the header.

    Header is magic "GDPC", then uint32 pack format version, then uint32
    engine major/minor/patch. Pack format 2+ (Godot 4) adds a uint32
    pack_flags field whose bit 0 marks an encrypted pack. Returns None
    when the entry is missing, short, or has no GDPC magic.
    """
    try:
        with zf.open(name) as f:
            head = f.read(24)
    except (KeyError, OSError, zipfile.BadZipFile):
        return None
    if len(head) < 20 or head[:4] != b"GDPC":
        return None
    pack_version, major, minor, patch = struct.unpack("<IIII", head[4:20])
    info = {"pack_format_version": pack_version,
            "pack_format_era": GODOT_PCK_ERAS.get(pack_version),
            "engine_version": f"{major}.{minor}.{patch}"}
    if pack_version >= 2 and len(head) >= 24:
        (flags,) = struct.unpack("<I", head[20:24])
        info["encrypted"] = bool(flags & 1)
    return info


def unreal_version_of(zf, name):
    """Unreal engine version from the build string inside libUE4.so /
    libUnreal.so (e.g. "++UE4+Release-4.16+Compile...").

    Streams the library with a small overlap so a match straddling a
    chunk boundary is still found. Returns {"engine": "UE4",
    "version": "4.16"} or None.
    """
    try:
        with zf.open(name) as f:
            tail = b""
            while True:
                chunk = f.read(1 << 20)
                if not chunk:
                    return None
                data = tail + chunk
                m = UE_VERSION_RE.search(data)
                if m:
                    return {"engine": m.group(1).decode("ascii"),
                            "version": m.group(2).decode("ascii")}
                tail = data[-64:]
    except (KeyError, OSError, zipfile.BadZipFile):
        return None


def dex_string_stats(data):
    """Parse a DEX string table for protection evidence.

    Returns a dict with class-descriptor statistics (total count,
    count whose simple name is <= 2 chars, up to 3 examples of the
    short ones), SSL pin constants (strings of the form
    "sha256/<base64>"), and StubApp class descriptors — or None when
    the header is not a parseable DEX or any offset is inconsistent.
    Only cheap byte checks run per string; nothing is decoded unless
    it is a candidate.
    """
    if len(data) < 0x70 or not data.startswith(b"dex\n"):
        return None
    try:
        string_ids_size, string_ids_off = struct.unpack_from("<II", data, 0x38)
        if string_ids_size > 2_000_000:
            return None
        if string_ids_off + 4 * string_ids_size > len(data):
            return None
        total = 0
        short = 0
        examples = []
        pins = set()
        stubs = set()
        for i in range(string_ids_size):
            (off,) = struct.unpack_from("<I", data, string_ids_off + 4 * i)
            if off <= 0 or off >= len(data):
                return None
            # Skip the ULEB128 UTF-16 length prefix (1-5 bytes).
            pos = off
            steps = 0
            while pos < len(data) and steps < 5:
                b = data[pos]
                pos += 1
                steps += 1
                if not (b & 0x80):
                    break
            end = data.find(b"\x00", pos)
            if end < 0:
                return None
            raw = data[pos:end]
            if (len(raw) >= 3 and raw[:1] == b"L" and raw[-1:] == b";"
                    and b" " not in raw):
                total += 1
                simple = raw[1:-1].rsplit(b"/", 1)[-1]
                if len(simple) <= 2:
                    short += 1
                    if len(examples) < 3:
                        examples.append(raw.decode("ascii", "replace"))
                if STUB_DESCRIPTOR_RE.match(raw):
                    stubs.add(raw.decode("ascii", "replace"))
            elif b"sha256/" in raw:
                m = PIN_CONSTANT_RE.search(raw)
                if m:
                    pins.add(m.group(0).decode("ascii", "replace"))
        return {"class_descriptors": total,
                "short_class_names": short,
                "short_examples": examples,
                "pin_constants": sorted(pins),
                "stub_descriptors": sorted(stubs)}
    except (struct.error, IndexError, ValueError):
        return None


def pak_index_encrypted_flag(zf, name):
    """Unreal .pak index-encryption flag from the FPakInfo footer.

    The footer layout ends with the 16-byte encryption key GUID, a
    1-byte bEncryptedIndex flag, then the 4-byte magic — so the flag
    is the byte immediately before the magic. Returns True/False, or
    None when no footer magic is found in the file tail (not a pak,
    or a layout this cheap check cannot read; nar-pak.py does the
    full parse).
    """
    try:
        size = zf.getinfo(name).file_size
        if size < 64:
            return None
        with zf.open(name) as f:
            f.seek(max(0, size - 512))
            tail = f.read()
    except (KeyError, OSError, zipfile.BadZipFile):
        return None
    idx = tail.rfind(PAK_MAGIC_BYTES)
    if idx < 1:
        return None
    return tail[idx - 1] != 0


def elf_hardening_of(zf, name, size_bytes):
    """Native hardening facts for one .so, from its ELF headers.

    Stdlib-only header parse: ELF class, e_type (ET_DYN = PIE-style
    position-independent library), PT_GNU_RELRO presence, BIND_NOW
    (via DT_BIND_NOW, DT_FLAGS, or DT_FLAGS_1 in the dynamic segment),
    and SHT_SYMTAB presence (its absence means the library is
    stripped). Returns None when the entry is not a readable ELF;
    individual facts are None when that part of the header could not
    be read.
    """
    try:
        with zf.open(name) as f:
            head = f.read(64)
            if len(head) < 52 or head[:4] != b"\x7fELF":
                return None
            is64 = head[4] == 2
            e_type = struct.unpack_from("<H", head, 16)[0]
            if is64:
                e_phoff = struct.unpack_from("<Q", head, 32)[0]
                e_shoff = struct.unpack_from("<Q", head, 40)[0]
                e_phentsize, e_phnum = struct.unpack_from("<HH", head, 54)
                e_shentsize, e_shnum = struct.unpack_from("<HH", head, 58)
            else:
                e_phoff = struct.unpack_from("<I", head, 28)[0]
                e_shoff = struct.unpack_from("<I", head, 32)[0]
                e_phentsize, e_phnum = struct.unpack_from("<HH", head, 42)
                e_shentsize, e_shnum = struct.unpack_from("<HH", head, 46)
            info = {"elf_class": 64 if is64 else 32,
                    "elf_type": {2: "ET_EXEC", 3: "ET_DYN"}.get(
                        e_type, f"ET_{e_type}"),
                    "pie": e_type == 3,
                    "relro": None,
                    "bind_now": None,
                    "stripped": None}
            relro = None
            dynamic = None  # (offset, filesz)
            load_aligns = []
            if e_phoff and 0 < e_phnum <= 128 and e_phentsize >= 32:
                relro = False
                f.seek(e_phoff)
                ph = f.read(e_phentsize * e_phnum)
                for i in range(e_phnum):
                    off = i * e_phentsize
                    if off + 32 > len(ph):
                        break
                    p_type = struct.unpack_from("<I", ph, off)[0]
                    if is64:
                        p_offset = struct.unpack_from("<Q", ph, off + 8)[0]
                        p_filesz = struct.unpack_from("<Q", ph, off + 32)[0]
                        p_align = (struct.unpack_from("<Q", ph, off + 48)[0]
                                   if off + 56 <= len(ph) else None)
                    else:
                        p_offset = struct.unpack_from("<I", ph, off + 4)[0]
                        p_filesz = struct.unpack_from("<I", ph, off + 16)[0]
                        p_align = (struct.unpack_from("<I", ph, off + 28)[0]
                                   if off + 32 <= len(ph) else None)
                    if p_type == 0x6474E552:  # PT_GNU_RELRO
                        relro = True
                    elif p_type == 2:  # PT_DYNAMIC
                        dynamic = (p_offset, p_filesz)
                    elif p_type == 1 and p_align is not None:  # PT_LOAD
                        load_aligns.append(p_align)
            info["relro"] = relro
            if load_aligns:
                # 16 KB page-size readiness (Android 15+): every LOAD
                # segment must be aligned to at least 16 KB. Report
                # the weakest segment, not the strongest.
                info["load_align_min"] = min(load_aligns)
                info["load_align_max"] = max(load_aligns)
                info["aligned_16k"] = min(load_aligns) >= 16384
            else:
                info["load_align_min"] = None
                info["load_align_max"] = None
                info["aligned_16k"] = None
            if dynamic is not None:
                bind_now = False
                d_off, d_filesz = dynamic
                entsize = 16 if is64 else 8
                fmt = "<qQ" if is64 else "<iI"
                if 0 < d_filesz <= 65536:
                    f.seek(d_off)
                    dyn = f.read(d_filesz)
                    for off in range(0, len(dyn) - entsize + 1, entsize):
                        tag, val = struct.unpack_from(fmt, dyn, off)
                        if tag == 0:  # DT_NULL
                            break
                        if tag == 24:  # DT_BIND_NOW
                            bind_now = True
                        elif tag == 30 and (val & 0x8):  # DT_FLAGS BIND_NOW
                            bind_now = True
                        elif tag == 0x6FFFFFFB and (val & 0x1):  # FLAGS_1 NOW
                            bind_now = True
                info["bind_now"] = bind_now
            if (e_shoff and 0 < e_shnum <= 1024 and e_shentsize >= 40
                    and size_bytes <= ELF_SYMTAB_MAX_BYTES):
                f.seek(e_shoff)
                sh = f.read(e_shentsize * e_shnum)
                has_symtab = False
                for i in range(e_shnum):
                    off = i * e_shentsize
                    if off + 8 > len(sh):
                        break
                    # sh_type sits at offset 4 in both ELF classes.
                    if struct.unpack_from("<I", sh, off + 4)[0] == 2:
                        has_symtab = True  # SHT_SYMTAB
                        break
                info["stripped"] = not has_symtab
            return info
    except (KeyError, OSError, zipfile.BadZipFile, struct.error):
        return None


def find_sdk_tool(name):
    """Locate a build-tools binary: PATH first, then the newest versioned
    build-tools directory under the usual Android SDK locations."""
    tool = shutil.which(name)
    if tool:
        return tool
    for root in filter(None, [
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        os.path.expanduser("~/workspace/android-sdk"),
        os.path.expanduser("~/Android/Sdk"),
    ]):
        bt = os.path.join(root, "build-tools")
        if os.path.isdir(bt):
            def _ver_key(v):
                try:
                    return tuple(int(x) for x in v.split("."))
                except ValueError:
                    return (0,)
            for ver in sorted(os.listdir(bt), key=_ver_key, reverse=True):
                cand = os.path.join(bt, ver, name)
                if os.path.isfile(cand) and os.access(cand, os.X_OK):
                    return cand
    return None


def _tool_env():
    """Environment for subprocess tools. apksigner is a wrapper script
    that execs `java`, so when java is not on PATH but a JDK exists in
    a known location, prepend its bin directory to PATH. Returns None
    (inherit the environment) when java is already on PATH or no JDK
    was found."""
    if shutil.which("java"):
        return None
    java_home = os.environ.get("JAVA_HOME")
    if java_home and os.path.isfile(os.path.join(java_home, "bin", "java")):
        java_dir = os.path.join(java_home, "bin")
    else:
        java_dir = None
        for pattern in (
            os.path.expanduser("~/workspace/jdk-*/bin/java"),
            os.path.expanduser("~/workspace/tools/rea-engines/jdk*/bin/java"),
            "/usr/lib/jvm/*/bin/java",
        ):
            for cand in sorted(glob.glob(pattern)):
                if os.access(cand, os.X_OK):
                    java_dir = os.path.dirname(cand)
                    break
            if java_dir:
                break
    if not java_dir:
        return None
    env = dict(os.environ)
    env["PATH"] = java_dir + os.pathsep + env.get("PATH", "")
    return env


def uses_sdk_count_of(apk_path):
    """Count <uses-sdk> elements in the binary manifest via xmltree.

    aapt2 badging prints only the first SDK pair, so a duplicate
    <uses-sdk> (old manifests sometimes carry a second one, even
    nested inside a component) is invisible there. Returns None when
    the count cannot be determined.
    """
    aapt2 = find_aapt2()
    if not aapt2:
        return None
    try:
        out = subprocess.run([aapt2, "dump", "xmltree", apk_path,
                              "--file", "AndroidManifest.xml"],
                             capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return sum(1 for line in out.stdout.splitlines()
               if line.strip().startswith("E: uses-sdk"))


def apksigner_verify(apk_path):
    """Signature schemes via `apksigner verify --verbose`.

    Returns (info_dict, status) where status is one of "ok",
    "not-found" (no apksigner binary), "unreadable" (apksigner ran but
    its output could not be parsed), or "not-applicable" (AAB/OBB/XAPK/
    APKM: apksigner only verifies APKs; on an AAB it throws
    ApkFormatException). An unsigned APK is a normal "ok" result with
    verifies=False. apksigner WARNING lines (for example JAR entries
    not protected by a signature) are collected into info["warnings"].
    """
    if apk_path.lower().endswith((".aab", ".obb", ".xapk", ".apkm")):
        return {}, "not-applicable"
    apksigner = find_sdk_tool("apksigner")
    if not apksigner:
        return {}, "not-found"
    try:
        out = subprocess.run(
            [apksigner, "verify", "--verbose", apk_path],
            capture_output=True, text=True, timeout=300, env=_tool_env(),
        )
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
        return {}, "unreadable"
    info = {}
    errors = []
    warnings = []
    parsed = False
    for line in (out.stdout + out.stderr).splitlines():
        if line == "Verifies":
            info["verifies"] = True
            parsed = True
            continue
        if line == "DOES NOT VERIFY":
            info["verifies"] = False
            parsed = True
            continue
        matched = False
        for key, pat in APKSIGNER_SCHEME_PATTERNS.items():
            m = pat.match(line)
            if m:
                info[key] = (m.group(1) == "true")
                parsed = True
                matched = True
                break
        if matched:
            continue
        m = re.match(r"^Number of signers: (\d+)", line)
        if m:
            info["signers"] = int(m.group(1))
            parsed = True
            continue
        m = re.match(r"^ERROR: (.*)", line)
        if m:
            errors.append(m.group(1))
            parsed = True
            continue
        m = re.match(r"^WARNING: (.*)", line)
        if m:
            warnings.append(m.group(1))
            parsed = True
    if errors:
        info["errors"] = errors
    if warnings:
        info["warnings"] = warnings
    if not parsed:
        return {}, "unreadable"
    return info, "ok"


def _find_bundletool():
    """Locate bundletool. Returns the command prefix list, or None.

    Prefers a PATH binary, then $BUNDLETOOL_JAR, then the jar under the
    usual tools directory (run with java -jar)."""
    tool = shutil.which("bundletool")
    if tool:
        return [tool]
    jar = os.environ.get("BUNDLETOOL_JAR")
    if jar and os.path.isfile(jar):
        return ["java", "-jar", jar]
    for pattern in (
        os.path.expanduser("~/workspace/tools/bundletool/bundletool-all-*.jar"),
        os.path.expanduser("~/tools/bundletool/bundletool-all-*.jar"),
    ):
        for cand in sorted(glob.glob(pattern), reverse=True):
            return ["java", "-jar", cand]
    return None


def bundletool_manifest(aab_path):
    """Package identity for .aab bundles via `bundletool dump manifest`.

    Returns (info_dict, status) like aapt2_badging. aapt2 cannot read
    AAB badging at all, so bundles take this path instead.
    """
    cmd = _find_bundletool()
    if not cmd:
        return {}, "not-found"
    try:
        out = subprocess.run(
            cmd + ["dump", "manifest", "--bundle", aab_path],
            capture_output=True, text=True, timeout=120, env=_tool_env(),
        )
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
        return {}, "unreadable"
    if out.returncode != 0:
        return {}, "unreadable"
    xml = out.stdout
    info = {}
    m = re.search(r"<manifest[^>]*\bpackage=\"([^\"]+)\"", xml)
    if m:
        info["package"] = m.group(1)
    m = re.search(r"android:versionCode=\"([^\"]+)\"", xml)
    if m:
        info["version_code"] = m.group(1)
    m = re.search(r"android:versionName=\"([^\"]+)\"", xml)
    if m:
        info["version_name"] = m.group(1)
    m = re.search(r"<uses-sdk[^>]*android:minSdkVersion=\"([^\"]+)\"", xml)
    if m:
        info["min_sdk"] = m.group(1)
    m = re.search(r"<uses-sdk[^>]*android:targetSdkVersion=\"([^\"]+)\"", xml)
    if m:
        info["target_sdk"] = m.group(1)
    perms = sorted(set(
        re.findall(r"<uses-permission[^>]*android:name=\"([^\"]+)\"", xml)))
    if perms:
        info["permissions"] = perms
    m = re.search(r"<application[^>]*android:label=\"([^\"]+)\"", xml)
    if m and not m.group(1).startswith("@"):
        info["app_label"] = m.group(1)
    if not info:
        return {}, "unreadable"
    return info, "ok"


def container_manifest_of(zf):
    """Identity from an XAPK/APKM container's manifest.json, if present.

    XAPK (APKPure) and APKM (APKMirror) are ZIP containers of APKs with
    a JSON manifest at the root: package_name, version_code/name,
    min/target SDK, permissions, split_configs, and split_apks entries
    ({file, id}). Returns a dict (possibly partial) or None when there
    is no readable manifest.json.
    """
    if "manifest.json" not in zf.namelist():
        return None
    try:
        data = json.loads(zf.read("manifest.json").decode("utf-8", "replace"))
    except (KeyError, OSError, zipfile.BadZipFile, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    info = {}
    for src, dst in (("xapk_version", "xapk_version"),
                     ("package_name", "package"),
                     ("name", "app_label"),
                     ("version_code", "version_code"),
                     ("version_name", "version_name"),
                     ("min_sdk_version", "min_sdk"),
                     ("target_sdk_version", "target_sdk"),
                     ("total_size", "total_size")):
        if data.get(src) is not None:
            info[dst] = data[src]
    if isinstance(data.get("permissions"), list):
        info["permissions"] = sorted({str(p) for p in data["permissions"]})
    if isinstance(data.get("split_configs"), list):
        info["split_configs"] = [str(s) for s in data["split_configs"]]
    splits = []
    if isinstance(data.get("split_apks"), list):
        for entry in data["split_apks"]:
            if isinstance(entry, dict) and entry.get("file"):
                splits.append({"file": str(entry["file"]),
                               "id": str(entry.get("id", ""))})
    if splits:
        info["split_apks"] = splits
    return info


def find_aapt2():
    """Locate aapt2: PATH first, then common Android SDK locations."""
    aapt2 = shutil.which("aapt2")
    if aapt2:
        return aapt2
    for root in filter(None, [
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        os.path.expanduser("~/workspace/android-sdk"),
        os.path.expanduser("~/Android/Sdk"),
    ]):
        bt = os.path.join(root, "build-tools")
        if os.path.isdir(bt):
            def _ver_key(v):
                try:
                    return tuple(int(x) for x in v.split("."))
                except ValueError:
                    return (0,)
            for ver in sorted(os.listdir(bt), key=_ver_key, reverse=True):
                cand = os.path.join(bt, ver, "aapt2")
                if os.path.isfile(cand) and os.access(cand, os.X_OK):
                    return cand
    return None


def aapt2_badging(apk_path):
    """Best-effort package identity via aapt2.

    Returns (info_dict, status) where status is one of "ok", "not-found",
    or "unreadable" (aapt2 ran but could not read badging). For .aab
    bundles, identity comes from `bundletool dump manifest` instead,
    because aapt2 cannot read AAB badging at all.
    """
    if apk_path.lower().endswith(".aab"):
        return bundletool_manifest(apk_path)
    aapt2 = find_aapt2()
    if not aapt2:
        return {}, "not-found"
    try:
        out = subprocess.run(
            [aapt2, "dump", "badging", apk_path],
            capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
        return {}, "unreadable"
    if out.returncode != 0:
        return {}, "unreadable"
    info = {}
    permissions = []
    implied = []
    form_factors = set()
    sdk_pairs = []       # every (min, target) pair badging prints, in order
    pending_min = None
    for line in out.stdout.splitlines():
        # Form factors are declared as features/libraries, not as
        # separate badging fields: a watch feature or the wearable
        # support library means a Wear OS build; the leanback feature
        # means an Android TV build.
        if "android.hardware.type.watch" in line \
                or "com.google.android.wearable" in line:
            form_factors.add("Wear OS")
        if "android.software.leanback" in line:
            form_factors.add("Android TV")
        m = BADGING_PATTERNS["package"].match(line)
        if m:
            info["package"] = m.group(1)
            info["version_code"] = m.group(2)
            info["version_name"] = m.group(3)
            # compileSdkVersion rides on the package line itself
            # (compileSdkVersion='34'); the Codename variant is a
            # different field and is not matched by this pattern.
            cm = re.search(r"compileSdkVersion='([^']+)'", line)
            if cm:
                info["compile_sdk"] = cm.group(1)
            continue
        m = BADGING_PATTERNS["sdk"].match(line)
        if m:
            pending_min = m.group(1)
            continue
        m = BADGING_PATTERNS["target_sdk"].match(line)
        if m:
            sdk_pairs.append((pending_min, m.group(1)))
            pending_min = None
            continue
        m = BADGING_PATTERNS["app_label"].match(line)
        if m:
            info["app_label"] = m.group(1)
            continue
        if line.startswith("uses-implied-permission:"):
            pm = re.search(r"name='([^']+)'", line)
            rm = re.search(r"reason='([^']*)'", line)
            if pm:
                implied.append({"name": pm.group(1),
                                "reason": rm.group(1) if rm else ""})
            continue
        if line.startswith("uses-permission:"):
            pm = re.search(r"name='([^']+)'", line)
            if pm:
                permissions.append(pm.group(1))
    if form_factors:
        info["form_factors"] = sorted(form_factors)
    if pending_min is not None:
        sdk_pairs.append((pending_min, None))
    if sdk_pairs:
        # FIRST <uses-sdk> wins, in agreement with nar-perms. A manifest
        # can declare <uses-sdk> twice (seen in the wild in legacy
        # apps); record every pair and flag the duplicate instead of
        # silently overwriting.
        info["min_sdk"] = sdk_pairs[0][0]
        info["target_sdk"] = sdk_pairs[0][1]
        if len(sdk_pairs) > 1:
            info["sdk_pairs"] = [{"min_sdk": mn, "target_sdk": tg}
                                 for mn, tg in sdk_pairs]
    if permissions:
        info["permissions"] = sorted(set(permissions))
    if implied:
        # aapt2 lists platform-implied permissions as uses-permission
        # lines too; keep them labeled so they are never mistaken for
        # permissions the manifest declares.
        info["implied_permissions"] = sorted(implied, key=lambda i: i["name"])
    return info, "ok"


def _traversal_name(name):
    """True when an archive entry name is absolute or
    escapes its extraction root through '..' components
    (either separator). Such names are never recorded as
    contained APKs/OBBs a consumer may extract by name
    (2.6.1 deep-audit remediation, defense in depth:
    nar-analyze's extraction layer refuses them too)."""
    if name.startswith(("/", "\\")):
        return True
    parts = name.replace("\\", "/").split("/")
    return ".." in parts


def triage(apk_path):
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"not a file: {apk_path}")
    size = os.path.getsize(apk_path)
    basename = os.path.basename(apk_path)
    obb_match = OBB_RE.match(basename)
    result = {
        "file": basename,
        "path": os.path.abspath(apk_path),
        "sha256": sha256_of(apk_path),
        "size_bytes": size,
        "is_aab": apk_path.lower().endswith(".aab"),
        "is_obb": apk_path.lower().endswith(".obb"),
        "is_xapk": apk_path.lower().endswith(".xapk"),
        "is_apkm": apk_path.lower().endswith(".apkm"),
        "is_apks": apk_path.lower().endswith(".apks"),
        "obb_kind": obb_match.group(1) if obb_match else None,
        "obb_version_code": obb_match.group(2) if obb_match else None,
        "obb_package": obb_match.group(3) if obb_match else None,
        "looks_like_split": bool(SPLIT_RE.search(basename)),
        # Protection signature database provenance (Phase 5):
        # which signature set produced the protections below.
        "protection_signatures": {
            "database_version": PROTECTION_SIGNATURES_VERSION,
            "counts": _SIG["counts"]},
    }
    try:
        zf = zipfile.ZipFile(apk_path)
    except zipfile.BadZipFile:
        result["error"] = "not a valid ZIP/APK container"
        return result

    with zf:
        names = zf.namelist()
        infos = {i.filename: i for i in zf.infolist()}
        dex, native, meta_inf, assets, res, other = [], {}, [], [], [], []
        has_manifest = ("AndroidManifest.xml" in infos
                        or "base/manifest/AndroidManifest.xml" in infos)
        has_arsc = ("resources.arsc" in infos
                    or "base/resources.pb" in infos)  # AABs carry resources.pb
        modules = sorted({n.split("/")[0] for n in names
                          if "/" in n and not n.startswith("META-INF/")})
        for name in names:
            info = infos[name]
            if DEX_RE.match(name):
                dex.append({"name": name, "size_bytes": info.file_size,
                            "compressed_bytes": info.compress_size})
            elif (m := SO_RE.match(name)):
                native.setdefault(m.group(2), []).append(
                    {"name": m.group(3), "path": name, "size_bytes": info.file_size})
            elif name.startswith("META-INF/"):
                meta_inf.append(name)
            elif re.match(r"^(base/)?assets/", name) and not name.endswith("/"):
                assets.append(name)
            elif re.match(r"^(base/)?res/", name) and not name.endswith("/"):
                res.append(name)
            elif not name.endswith("/"):
                other.append(name)

        # DEX format versions, from each DEX header magic.
        for d in dex:
            d["dex_version"] = dex_version_of(zf, d["name"])

        # DEX content markers: read each DEX file once and count
        # framework fingerprints (Compose, Play Integrity, legacy
        # HttpClient, ...) plus protection-system fingerprints
        # (packer runtimes, RASP code, licensing). One pass per DEX,
        # all patterns together. Files up to the parse cap are held
        # in memory so the same bytes feed the string-table parse
        # (obfuscation statistics, pin constants, stub descriptors);
        # larger files stream exactly as before.
        packer_dex_patterns = [p for _, _, pats, _ in PACKER_MARKERS
                               for p in pats]
        rasp_dex_patterns = [p for _, pats, _ in RASP_DEX_MARKERS
                             for p in pats]
        licensing_dex_patterns = [p for _, pats, _ in LICENSING_DEX_MARKERS
                                  for p in pats] + WIDEVINE_DEX_PATTERNS
        prot_dex_patterns = (packer_dex_patterns + rasp_dex_patterns
                             + licensing_dex_patterns)
        all_dex_patterns = list(dict.fromkeys(
            [p for _, pats in DEX_MARKERS for p in pats] + prot_dex_patterns))
        marker_totals = {}
        prot_hits = {}          # protection pattern -> {dex name: hits}
        all_pattern_totals = {}  # any pattern -> hits across all DEX
        string_stats = []        # (dex name, dex_string_stats dict)
        for d in dex:
            data = None
            if d["size_bytes"] <= DEX_STRING_PARSE_MAX_BYTES:
                try:
                    data = zf.read(d["name"])
                except (KeyError, OSError, RuntimeError, zipfile.BadZipFile):
                    data = None
            try:
                if data is not None:
                    counts, _, _ = count_patterns_in_stream(
                        io.BytesIO(data), all_dex_patterns)
                else:
                    with zf.open(d["name"]) as f:
                        counts, _, _ = count_patterns_in_stream(
                            f, all_dex_patterns)
            except (KeyError, OSError, zipfile.BadZipFile):
                continue
            for p, c in counts.items():
                if c:
                    all_pattern_totals[p] = all_pattern_totals.get(p, 0) + c
            for label, pats in DEX_MARKERS:
                hits = sum(counts[p] for p in pats)
                if hits:
                    marker_totals.setdefault(label, []).append(
                        {"name": d["name"], "hits": hits})
            for p in prot_dex_patterns:
                if counts.get(p):
                    prot_hits.setdefault(p, {})[d["name"]] = counts[p]
            if data is not None:
                stats = dex_string_stats(data)
                if stats is not None:
                    string_stats.append((d["name"], stats))
        dex_markers = [{"marker": label,
                        "total_hits": sum(f["hits"] for f in files),
                        "dex_files": sorted(files, key=lambda f: f["name"])}
                       for label, files in sorted(marker_totals.items())]

        # Rust markers in native libs: stream each .so for Rust runtime
        # strings, bounded by the total scan budget.
        rust_hints = []
        rust_scanned = 0
        rust_truncated = False
        for abi in sorted(native):
            if rust_truncated or rust_scanned >= RUST_SCAN_BUDGET_BYTES:
                rust_truncated = rust_truncated or rust_scanned >= RUST_SCAN_BUDGET_BYTES
                break
            for lib in sorted(native[abi], key=lambda l: l["name"]):
                if rust_scanned >= RUST_SCAN_BUDGET_BYTES:
                    rust_truncated = True
                    break
                try:
                    with zf.open(lib["path"]) as f:
                        counts, read, trunc = count_patterns_in_stream(
                            f, RUST_PATTERNS,
                            budget=RUST_SCAN_BUDGET_BYTES - rust_scanned)
                except (KeyError, OSError, zipfile.BadZipFile):
                    continue
                rust_scanned += read
                rust_truncated = trunc
                found = sorted(p.decode("ascii") for p in RUST_PATTERNS if counts[p] > 0)
                if found:
                    rust_hints.append({"lib": lib["path"], "markers": found})
                if rust_truncated:
                    break

        # Engine version hints from binary headers, where a header
        # carries one. Unity: IL2CPP metadata format version. Godot:
        # PCK pack format version plus the engine version it records.
        # Unreal has no cheap header version: its version comes from
        # strings in libUE4.so (see references/modern-analysis.md).
        engine_versions = {}
        for n in names:
            if n.lower().endswith("global-metadata.dat"):
                v = unity_metadata_version_of(zf, n)
                if v is not None:
                    engine_versions["unity_metadata_version"] = v
                    engine_versions["unity_metadata_era"] = UNITY_METADATA_ERAS.get(v)
                    engine_versions["unity_metadata_file"] = n
                break
        pck_infos = []
        for n in names:
            if n.lower().endswith(".pck"):
                info = godot_pck_info_of(zf, n)
                if info:
                    info["name"] = n
                    pck_infos.append(info)
        if pck_infos:
            engine_versions["godot_pck"] = sorted(pck_infos, key=lambda p: p["name"])
        # Unreal: no header version; the build string inside the engine
        # library carries it ("++UE4+Release-4.16+Compile...").
        for abi in sorted(native):
            for lib in sorted(native[abi], key=lambda l: l["name"]):
                if lib["name"].lower() in ("libue4.so", "libunreal.so"):
                    uv = unreal_version_of(zf, lib["path"])
                    if uv:
                        engine_versions["unreal_engine"] = uv["engine"]
                        engine_versions["unreal_version"] = uv["version"]
                        engine_versions["unreal_version_file"] = lib["path"]
                    break
            if "unreal_version" in engine_versions:
                break

        # Baseline profiles (ART profile-guided optimization inputs) and
        # .dm DEX metadata files.
        baseline_profiles = sorted(
            n for n in names
            if n.lower().endswith(".dm")
            or "/dexopt/baseline.prof" in n.lower()
            or n.lower().endswith("baseline.prof")
            or n.lower().endswith("baseline.profm"))

        # Contained APKs/OBBs: traversal names (absolute
        # or '..' escapes) are refused recording as
        # extractable contained files and are listed
        # separately with the reason (2.6.1).
        def _contained(suffix):
            safe, refused = [], []
            for n in names:
                if not n.lower().endswith(suffix):
                    continue
                if _traversal_name(n):
                    refused.append({
                        "name": n,
                        "reason": "entry name is absolute or "
                                  "traverses outside the "
                                  "extraction root"})
                else:
                    safe.append({"name": n,
                                 "size_bytes":
                                     infos[n].file_size})
            safe.sort(key=lambda a: a["name"])
            refused.sort(key=lambda a: a["name"])
            return safe, refused

        contained_apks, contained_apks_rejected = \
            _contained(".apk")
        contained_obbs, contained_obbs_rejected = \
            _contained(".obb")

        result.update({
            "zip_entries": len(names),
            "has_manifest": has_manifest,
            "has_resources_arsc": has_arsc,
            "aab_modules": modules if result["is_aab"] else [],
            "is_container": (result["is_xapk"] or result["is_apkm"]
                             or result["is_apks"]),
            "container_manifest": container_manifest_of(zf)
            if (result["is_xapk"] or result["is_apkm"]) else None,
            "contained_apks": contained_apks,
            "contained_apks_rejected": contained_apks_rejected,
            "contained_obbs": contained_obbs,
            "contained_obbs_rejected": contained_obbs_rejected,
            "dex_files": sorted(dex, key=lambda d: d["name"]),
            "dex_count": len(dex),
            "dex_total_bytes": sum(d["size_bytes"] for d in dex),
            "dex_versions": sorted({d["dex_version"] for d in dex if d["dex_version"]}),
            "dex_markers": dex_markers,
            "rust_hints": rust_hints,
            "rust_scan_bytes": rust_scanned,
            "rust_scan_truncated": rust_truncated,
            "engine_versions": engine_versions,
            "baseline_profiles": baseline_profiles,
            "native_libs_by_abi": {abi: sorted(libs, key=lambda l: l["name"])
                                   for abi, libs in sorted(native.items())},
            "native_lib_count": sum(len(v) for v in native.values()),
            "meta_inf_entries": sorted(meta_inf),
            "asset_count": len(assets),
            "resource_file_count": len(res),
            "other_file_count": len(other),
        })
        # Signing files are the META-INF cert/key entries (analysis only).
        result["signing_files"] = [n for n in result["meta_inf_entries"]
                                   if n.upper().endswith((".RSA", ".DSA", ".EC", ".SF", ".MF"))]

        # Library versions: Java/AndroidX libraries stamp a tiny
        # META-INF/<group>_<artifact>.version file with their version
        # string. Cheap, exact version evidence (Kotlin's own version
        # is NOT recoverable this way: kotlin-stdlib ships no .version
        # file and its version lives in the stripped Metadata).
        library_versions = {}
        for n in names:
            if n.startswith("META-INF/") and n.endswith(".version"):
                try:
                    with zf.open(n) as _fh:
                        raw = _fh.read(256).decode(
                            "utf-8", "replace").strip()
                except (KeyError, OSError, zipfile.BadZipFile):
                    continue
                ver = raw.splitlines()[0].strip() if raw else ""
                if ver and len(ver) <= 64:
                    library_versions[n[len("META-INF/"):-len(".version")]] = ver
        result["library_versions"] = dict(sorted(library_versions.items()))

        # Game-engine hints: simple case-insensitive path-substring matching.
        engine_hints = []
        for engine, markers in ENGINE_SIGNATURES:
            hits = sorted({n for n in names
                           for m in markers if m.lower() in n.lower()})
            if hits:
                engine_hints.append({"engine": engine, "markers": hits[:10],
                                     "marker_count": len(hits)})
        result["engine_hints"] = engine_hints

        # Game asset bundles: .pak / .bundle / .unity3d / embedded .obb etc.
        bundles = [{"name": n, "size_bytes": infos[n].file_size}
                   for n in names
                   if n.lower().endswith(BUNDLE_EXTS) and not n.endswith("/")]
        result["asset_bundles"] = sorted(bundles, key=lambda b: b["name"])
        result["asset_bundle_count"] = len(bundles)
        result["asset_bundle_bytes"] = sum(b["size_bytes"] for b in bundles)

        # Split-base tell: an engine that always ships native code
        # (Unity/Unreal/Godot/Flutter) is hinted, IL2CPP metadata may
        # even be present, yet this file holds no .so at all. The
        # native libs then live in a config split of the same bundle;
        # saying "pure DEX app" here would mislead the analyst. A
        # second, engine-independent tell: APKs generated from a
        # bundle carry a bundletool stamp (stamp-cert-sha256) and the
        # base carries a splits manifest (res/xml/splits*.xml).
        native_engines = {"Unity (IL2CPP)", "Unity (Mono)", "Unreal Engine",
                          "Godot", "Flutter"}
        bundle_split_evidence = sorted(
            n for n in names
            if n == "stamp-cert-sha256" or n.startswith("res/xml/splits"))
        result["bundle_split_evidence"] = bundle_split_evidence
        result["split_native_suspected"] = bool(
            result["native_lib_count"] == 0
            and not result["is_container"]
            and (any(h["engine"] in native_engines for h in engine_hints)
                 or bundle_split_evidence))

        # ---------------------------------------------------------
        # Protection systems. Static markers only: a finding means
        # protection artifacts or protection code ship in the
        # package, never that a runtime check passed. Organized by
        # category; named products only where a dedicated marker
        # attributes them.
        protections = []

        def add_protection(category, name, attributed, evidence,
                           note=None, details=None):
            finding = {"category": category,
                       "category_label":
                           PROTECTION_CATEGORY_LABELS[category],
                       "name": name,
                       "attributed": attributed,
                       "evidence": evidence}
            if note:
                finding["note"] = note
            if details:
                finding["details"] = details
            protections.append(finding)

        def dex_evidence(patterns):
            ev = []
            for p in patterns:
                per_dex = prot_hits.get(p)
                if per_dex:
                    where = ", ".join(f"{dn} x{h}"
                                      for dn, h in sorted(per_dex.items()))
                    ev.append(f"DEX string "
                              f"{p.decode('ascii', 'replace')} in {where}")
            return ev

        # 1. Commercial packers / VM protectors: dedicated runtime
        # libraries, stub classes, wrapper packages, payload files.
        for product, so_matchers, dex_pats, entry_subs in PACKER_MARKERS:
            ev = []
            for n in names:
                base = n.rsplit("/", 1)[-1].lower()
                if not base.endswith(".so"):
                    continue
                for kind, pat in so_matchers:
                    if ((kind == "exact" and base == pat)
                            or (kind == "prefix" and base.startswith(pat))
                            or (kind == "contains" and pat in base)):
                        ev.append(n)
                        break
            ev.extend(dex_evidence(dex_pats))
            for sub in entry_subs:
                ev.extend(n for n in names if sub in n)
            if ev:
                add_protection("commercial_packer", product, True,
                               sorted(set(ev)))

        # A StubApp-shaped application class that no named packer
        # claimed: report the shape, never a guessed vendor.
        claimed_strings = set()
        for _, _, pats, _ in PACKER_MARKERS:
            claimed_strings.update(p.decode("ascii", "replace")
                                   for p in pats)
        unattributed_stubs = sorted({
            desc for _, st in string_stats
            for desc in st["stub_descriptors"]
            if not any(cs in desc for cs in claimed_strings)})
        if unattributed_stubs:
            add_protection(
                "commercial_packer", "Unattributed packer stub", False,
                [f"DEX class {d}" for d in unattributed_stubs[:5]],
                note="A StubApp-shaped application class is the classic "
                     "packer shell shape, but no vendor marker attributes "
                     "it; reported unattributed rather than guessed.")

        # 2. Obfuscation: name-shortening statistics from the DEX
        # string tables, plus R8 annotation-stripping residue.
        total_desc = sum(st["class_descriptors"] for _, st in string_stats)
        short_desc = sum(st["short_class_names"] for _, st in string_stats)
        if total_desc >= 200 and short_desc * 100 >= 30 * total_desc:
            examples = []
            for _, st in string_stats:
                examples.extend(st["short_examples"])
                if len(examples) >= 3:
                    break
            add_protection(
                "obfuscation", "Name obfuscation (R8 / ProGuard style)",
                False,
                [f"{short_desc:,} of {total_desc:,} class descriptors "
                 f"({100.0 * short_desc / total_desc:.0f}%) have simple "
                 f"names of <= 2 chars, e.g. {', '.join(examples[:3])}"],
                note="Shortened names are the visible residue of "
                     "R8/ProGuard/DexGuard-class obfuscation; which tool "
                     "ran cannot be told from names alone.")
        if ("Kotlin" in marker_totals
                and not all_pattern_totals.get(b"kotlin/Metadata")):
            add_protection(
                "obfuscation", "Annotation stripping (R8 residue)", False,
                ["Kotlin classes are referenced (Lkotlin/) but the "
                 "kotlin/Metadata annotation string is absent"],
                note="R8 strips kotlin.Metadata from release builds; "
                     "absence beside live Kotlin references is shrinking "
                     "residue, not a separate protection product.")

        # 3. Anti-tamper / RASP markers in DEX.
        for finding_name, pats, note in RASP_DEX_MARKERS:
            ev = dex_evidence(pats)
            if ev:
                add_protection("anti_tamper_rasp", finding_name, False,
                               ev, note)
        if "Play Integrity API" in marker_totals:
            files = ", ".join(
                f"{f['name']} x{f['hits']}"
                for f in marker_totals["Play Integrity API"])
            add_protection(
                "anti_tamper_rasp", "Play Integrity API", False,
                [f"DEX marker com/google/android/play/core/integrity "
                 f"in {files}"],
                note="Client-side presence only: the integrity verdict "
                     "is made by Google's servers, never inside the APK.")

        # 4. Network protection: pin constants compiled into code,
        # and pin-sets in a network security config.
        pins = sorted({pin for _, st in string_stats
                       for pin in st["pin_constants"]})
        if pins:
            add_protection(
                "network_protection",
                "SSL pinning (pin constants in code)", False,
                [f"DEX pin constant {p}" for p in pins[:5]],
                note="Pins in the sha256/<base64 digest> form used by "
                     "OkHttp CertificatePinner, compiled into code.")
        nsc_entries = []
        for n in names:
            if (re.match(r"^(base/)?res/xml/[^/]+\.xml$", n)
                    and infos[n].file_size <= 512 * 1024):
                try:
                    raw = zf.read(n)
                except (KeyError, OSError, RuntimeError, zipfile.BadZipFile):
                    continue
                has_digest = (b"sha256/" in raw
                              or "sha256/".encode("utf-16-le") in raw)
                has_pinset = ((b"SHA-256" in raw
                               or "SHA-256".encode("utf-16-le") in raw)
                              and (b"pin-set" in raw
                                   or "pin-set".encode("utf-16-le") in raw))
                if has_digest or has_pinset:
                    nsc_entries.append(n)
        if nsc_entries:
            add_protection(
                "network_protection",
                "SSL pinning (network security config pin-set)", False,
                sorted(nsc_entries),
                note="A res/xml config carries a certificate pin-set; "
                     "the manifest's networkSecurityConfig attribute "
                     "points at the file that enforces it.")

        # 5. Licensing / DRM. The CHECK_LICENSE permission is folded
        # in after badging (see apply_check_license below).
        for finding_name, pats, note in LICENSING_DEX_MARKERS:
            ev = dex_evidence(pats)
            if ev:
                add_protection("licensing_drm", finding_name, False,
                               ev, note)

        # Widevine DRM: string form, raw-byte form, or both compiled
        # UUID halves in the same DEX (see WIDEVINE_DEX_PATTERNS).
        wv_ev = dex_evidence([WIDEVINE_UUID_STRING])
        raw_hits = prot_hits.get(WIDEVINE_UUID_RAW) or {}
        for dn in sorted(raw_hits):
            wv_ev.append(f"DEX Widevine UUID raw bytes in {dn}"
                         f" x{raw_hits[dn]}")
        msb_hits = prot_hits.get(WIDEVINE_UUID_MSB_LE) or {}
        lsb_hits = prot_hits.get(WIDEVINE_UUID_LSB_LE) or {}
        for dn in sorted(set(msb_hits) & set(lsb_hits)):
            wv_ev.append("DEX compiled Widevine UUID constants"
                         f" (both 64-bit halves) in {dn}")
        if wv_ev:
            add_protection("licensing_drm", "Widevine DRM", False,
                           wv_ev,
                           note="Identified by its MediaDrm scheme"
                                " UUID in string, raw-byte, or"
                                " compiled-constant form.")

        # 6. Code / asset encryption.
        bad_dex = [d["name"] for d in dex if d["dex_version"] is None]
        if bad_dex:
            add_protection(
                "code_asset_encryption",
                "DEX without a valid DEX header", False, bad_dex,
                note="A classes*.dex entry whose header magic is missing "
                     "is packed, encrypted, or corrupt; packers replace "
                     "the real DEX (or its header) and restore it at "
                     "runtime.")
        native_bytes = sum(lib["size_bytes"] for libs in native.values()
                           for lib in libs)
        if (dex and result["dex_total_bytes"] < STUB_DEX_MAX_BYTES
                and size >= STUB_APP_MIN_BYTES
                and (native_bytes >= STUB_PAYLOAD_MIN_BYTES
                     or result["asset_bundle_bytes"] >= STUB_PAYLOAD_MIN_BYTES)
                and not any(f["category"] == "commercial_packer"
                            and f["attributed"] for f in protections)):
            add_protection(
                "code_asset_encryption", "Shell / stub DEX pattern", False,
                [f"DEX total {result['dex_total_bytes']:,} bytes against "
                 f"{native_bytes:,} bytes of native libs and "
                 f"{result['asset_bundle_bytes']:,} bytes of asset "
                 f"bundles in a {size:,}-byte package"],
                note="The visible DEX is a loader; the real code is "
                     "delivered or decrypted at runtime (packer shell "
                     "or dynamic code delivery). Static DEX analysis "
                     "sees only the stub.")
        for n in names:
            if n.lower().endswith("global-metadata.dat"):
                if "unity_metadata_version" not in engine_versions:
                    add_protection(
                        "code_asset_encryption",
                        "IL2CPP metadata without a readable header", False,
                        [n],
                        note="global-metadata.dat is present but its "
                             "IL2CPP magic and version could not be read; "
                             "encrypted or obfuscated metadata is a "
                             "standard IL2CPP protection.")
                break
        for p in pck_infos:
            if p.get("encrypted"):
                add_protection(
                    "code_asset_encryption", "Encrypted Godot pack", False,
                    [f"{p['name']} (pack format "
                     f"{p['pack_format_version']}, engine "
                     f"{p['engine_version']})"],
                    note="The PCK header's encryption flag is set; the "
                         "pack contents need the pack key.")
        for bnd in bundles:
            if bnd["name"].lower().endswith(".pak"):
                if pak_index_encrypted_flag(zf, bnd["name"]):
                    add_protection(
                        "code_asset_encryption",
                        "Encrypted Unreal pak index", False, [bnd["name"]],
                        note="The pak footer's index-encryption flag is "
                             "set; nar-pak.py cannot list an encrypted "
                             "index without the key.")

        # 7. Native hardening posture from ELF headers.
        if native:
            libs_detail = []
            for abi in sorted(native):
                for lib in sorted(native[abi], key=lambda l: l["name"]):
                    eh = elf_hardening_of(zf, lib["path"],
                                          lib["size_bytes"])
                    if eh:
                        libs_detail.append({"path": lib["path"], **eh})
            if libs_detail:
                n_libs = len(libs_detail)
                pie = sum(1 for l in libs_detail if l["pie"])
                full = sum(1 for l in libs_detail
                           if l["relro"] and l["bind_now"])
                partial = sum(1 for l in libs_detail
                              if l["relro"] and not l["bind_now"])
                no_relro = sum(1 for l in libs_detail
                               if l["relro"] is False)
                known_stripped = [l for l in libs_detail
                                  if l["stripped"] is not None]
                stripped = sum(1 for l in known_stripped if l["stripped"])
                known_align = [l for l in libs_detail
                               if l.get("aligned_16k") is not None]
                aligned_16k = sum(1 for l in known_align
                                  if l["aligned_16k"])
                align_evidence = (
                    f"16 KB page alignment: {aligned_16k} of "
                    f"{len(known_align)} libs have every LOAD segment "
                    f"aligned to 16 KB or more" if known_align else
                    "16 KB page alignment: no LOAD segment alignment "
                    "could be read")
                add_protection(
                    "native_hardening",
                    "Native hardening posture (ELF headers)", False,
                    [f"{pie} of {n_libs} native libs are ET_DYN "
                     f"(position-independent)",
                     f"RELRO: {full} full (GNU_RELRO + BIND_NOW), "
                     f"{partial} partial (GNU_RELRO only), {no_relro} "
                     f"without GNU_RELRO",
                     f"symbol tables: {stripped} of "
                     f"{len(known_stripped)} libs stripped "
                     f"(no SHT_SYMTAB)",
                     align_evidence],
                    note="Read from ELF program, dynamic, and section "
                         "headers. Posture only: it describes build "
                         "flags, not exploit resistance.",
                    details={"libs": libs_detail})

        protections.sort(key=lambda f: (
            PROTECTION_CATEGORY_ORDER[f["category"]], f["name"]))
        result["protections"] = protections

    def apply_check_license(permissions):
        """Fold the CHECK_LICENSE permission into the licensing
        findings: it is extra evidence when the LVL classes are
        present, and a finding on its own when they are not (the
        permission alone declares a license check)."""
        if not permissions:
            return
        if "com.android.vending.CHECK_LICENSE" not in permissions:
            return
        prots = result.setdefault("protections", [])
        for f in prots:
            if f["name"] == "Play License Verification (LVL)":
                f["evidence"].append(
                    "permission com.android.vending.CHECK_LICENSE")
                return
        prots.append({
            "category": "licensing_drm",
            "category_label": PROTECTION_CATEGORY_LABELS["licensing_drm"],
            "name": "Play license check (CHECK_LICENSE permission)",
            "attributed": False,
            "evidence": ["permission com.android.vending.CHECK_LICENSE"],
            "note": "The permission declares a Play license check; no "
                    "LVL classes were found in the DEX, so the check "
                    "itself may live in native code or a split.",
        })
        prots.sort(key=lambda f: (
            PROTECTION_CATEGORY_ORDER[f["category"]], f["name"]))

    if result.get("is_container"):
        # Identity for a container comes from its manifest.json, not
        # from aapt2 (which cannot read a container at all).
        cm = result.get("container_manifest") or {}
        badging = {}
        for src, dst in (("package", "package"),
                         ("version_code", "version_code"),
                         ("version_name", "version_name"),
                         ("min_sdk", "min_sdk"),
                         ("target_sdk", "target_sdk"),
                         ("app_label", "app_label"),
                         ("permissions", "permissions")):
            if cm.get(src) is not None:
                badging[dst] = (str(cm[src]) if src in
                                ("version_code", "min_sdk", "target_sdk")
                                else cm[src])
        result["badging"] = badging
        result["badging_status"] = "ok" if badging else "unreadable"
        result["signature_schemes"] = {}
        result["signature_status"] = "not-applicable"
        apply_check_license(badging.get("permissions"))
        return result

    badging, badging_status = aapt2_badging(apk_path)
    result["badging"] = badging
    result["badging_status"] = badging_status
    apply_check_license(badging.get("permissions"))
    result["uses_sdk_count"] = (None if result["is_aab"]
                                else uses_sdk_count_of(apk_path))
    sig_info, sig_status = apksigner_verify(apk_path)
    result["signature_schemes"] = sig_info
    result["signature_status"] = sig_status
    return result


def human(report):
    title = f"NAR triage: {report['file']}"
    lines = [
        title,
        "=" * len(title),
        f"SHA-256: {report['sha256']}",
        f"Size:    {report['size_bytes']:,} bytes",
    ]
    if report.get("is_aab"):
        lines.append("NOTE: .aab bundle (ZIP container like an APK; needs bundletool to install).")
    if report.get("is_container"):
        kind = ("XAPK" if report.get("is_xapk")
                else "APKS" if report.get("is_apks") else "APKM")
        lines.append(f"NOTE: {kind} container (a ZIP of APKs)."
                     " Identity below is from the container manifest"
                     " when one is present; triage each contained APK"
                     " for code-level detail.")
        for a in report.get("contained_apks", []):
            lines.append(f"  - contains APK: {a['name']}  ({a['size_bytes']:,} bytes)")
        for o in report.get("contained_obbs", []):
            lines.append(f"  - contains OBB: {o['name']}  ({o['size_bytes']:,} bytes)")
    if report.get("is_obb"):
        lines.append("NOTE: OBB expansion file"
                     + (f" ({report['obb_kind']} for {report['obb_package']},"
                        f" version {report['obb_version_code']})"
                        if report.get("obb_package") else "")
                     + ". Asset container, not an installable app.")
    if report.get("looks_like_split"):
        lines.append("NOTE: filename looks like a SPLIT APK. Triage the base APK"
                     " plus every split together (see references/triage-and-inventory.md).")
    if report.get("error"):
        lines.append(f"ERROR: {report['error']}")
        return "\n".join(lines)
    b = report.get("badging") or {}
    if b:
        lines.append(f"Package: {b.get('package', '?')}  v{b.get('version_name', '?')} "
                     f"(code {b.get('version_code', '?')})")
        lines.append(f"SDK:     min {b.get('min_sdk', '?')} / target {b.get('target_sdk', '?')}"
                     + (f"  label: {b.get('app_label')}" if b.get("app_label") else ""))
        if b.get("form_factors"):
            lines.append(f"Form factors: {', '.join(b['form_factors'])}"
                         " (declared features/libraries)")
        if b.get("sdk_pairs"):
            pairs = "; ".join(f"min {p['min_sdk']} / target {p['target_sdk']}"
                              for p in b["sdk_pairs"])
            lines.append(f"WARNING: manifest declares <uses-sdk> {len(b['sdk_pairs'])}"
                         f" times ({pairs}). Using the FIRST, in agreement"
                         " with nar-perms.")
        elif report.get("uses_sdk_count") and report["uses_sdk_count"] > 1:
            lines.append(f"WARNING: manifest contains {report['uses_sdk_count']}"
                         " <uses-sdk> elements; the values above are from"
                         " the FIRST, in agreement with nar-perms.")
        if b.get("permissions"):
            lines.append(f"Permissions ({len(b['permissions'])}): {', '.join(b['permissions'])}")
        if b.get("implied_permissions"):
            impl = ", ".join(f"{i['name']} ({i['reason']})" if i.get("reason")
                             else i["name"] for i in b["implied_permissions"])
            lines.append("  of which implied by the platform, NOT declared"
                         f" in the manifest: {impl}")
    elif report.get("badging_status") == "not-found":
        lines.append("Package: unknown (aapt2 not found. See nar-doctor.sh)")
    elif report.get("is_aab"):
        lines.append("Package: unknown (bundletool could not read the .aab manifest;"
                     " see nar-doctor.sh)")
    else:
        lines.append("Package: unknown (aapt2 could not read badging for this file)")
    lines += [
        f"ZIP entries: {report['zip_entries']}  |  AndroidManifest.xml: "
        f"{'yes' if report['has_manifest'] else 'NO'}  |  resources.arsc: "
        f"{'yes' if report['has_resources_arsc'] else 'no'}",
        f"DEX: {report['dex_count']} file(s), {report['dex_total_bytes']:,} bytes total"
        + (f"  |  format version(s): {', '.join(report.get('dex_versions') or ['?'])}"
           if report['dex_count'] else ""),
    ]
    for d in report["dex_files"]:
        ver = d.get("dex_version") or "?"
        lines.append(f"  - {d['name']}  (DEX {ver}, {d['size_bytes']:,} bytes)")
    if report.get("dex_markers"):
        lines.append("DEX markers (string fingerprints inside DEX; a hit means the"
                     " framework's classes are referenced):")
        for m in report["dex_markers"]:
            files = ", ".join(f"{f['name']} x{f['hits']}" for f in m["dex_files"])
            lines.append(f"  - {m['marker']}: {m['total_hits']} hit(s) in {files}")
    lines.append(f"Native libs: {report['native_lib_count']} file(s)")
    for abi, libs in report["native_libs_by_abi"].items():
        for lib in libs:
            lines.append(f"  - [{abi}] {lib['name']}  ({lib['size_bytes']:,} bytes)")
    if not report["native_libs_by_abi"]:
        if report.get("is_container"):
            lines.append("  (none at container level: code lives in the contained APKs)")
        elif report.get("is_obb"):
            lines.append("  (none: OBBs carry assets, not code)")
        elif report.get("is_aab"):
            lines.append("  (none at bundle level. Check base/lib/ after bundletool extract)")
        elif report.get("split_native_suspected"):
            ev = report.get("bundle_split_evidence") or []
            native_engines = {"Unity (IL2CPP)", "Unity (Mono)",
                              "Unreal Engine", "Godot", "Flutter"}
            engine_based = any(h["engine"] in native_engines
                               for h in report.get("engine_hints", []))
            why = ("engine evidence above says native code exists"
                   if engine_based else
                   "this APK belongs to a split set")
            detail = f" (bundle evidence: {', '.join(ev)})" if ev else ""
            lines.append(f"  (none in this file, but {why}{detail}: the .so"
                         " files likely live in a config split of the same"
                         " bundle. Triage the splits too)")
        else:
            lines.append("  (none: pure DEX app)")
    lines.append(f"META-INF ({len(report['meta_inf_entries'])}): "
                 f"{', '.join(report['meta_inf_entries']) or '(none)'}")
    sig = report.get("signature_schemes") or {}
    sig_status = report.get("signature_status")
    if report["signing_files"]:
        lines.append(f"Signing files: {', '.join(report['signing_files'])}")
    elif sig_status == "ok" and (sig.get("v2") or sig.get("v3")):
        lines.append("Signing files: (none: v2/v3 signing uses the APK Signing"
                     " Block, which carries no META-INF files)")
    else:
        lines.append("Signing files: (none found)")
    if sig_status == "ok" and sig:
        if sig.get("verifies"):
            parts = [f"v1 {'yes' if sig.get('v1') else 'no'}",
                     f"v2 {'yes' if sig.get('v2') else 'no'}",
                     f"v3 {'yes' if sig.get('v3') else 'no'}",
                     f"v3.1 {'yes' if sig.get('v3_1') else 'no'}",
                     f"v4 {'yes' if sig.get('v4') else 'no'}"]
            lines.append("Signature schemes (apksigner): " + ", ".join(parts)
                         + f"  |  signers: {sig.get('signers', '?')}  |  verifies"
                         + (f"  |  source stamp: {'yes' if sig['source_stamp'] else 'no'}"
                            if "source_stamp" in sig else ""))
        else:
            err = "; ".join(sig.get("errors", [])) or "verification failed"
            lines.append(f"Signature schemes (apksigner): DOES NOT VERIFY ({err})")
        if sig.get("warnings"):
            lines.append(f"apksigner warnings ({len(sig['warnings'])}):")
            for w in sig["warnings"][:5]:
                lines.append(f"  - {w}")
            if len(sig["warnings"]) > 5:
                lines.append(f"  ... and {len(sig['warnings']) - 5} more (see --json)")
    elif sig_status == "not-found":
        lines.append("Signature schemes: unknown (apksigner not found. See nar-doctor.sh)")
    elif sig_status == "not-applicable":
        lines.append("Signature schemes: not applicable (apksigner verifies APKs only)")
    else:
        lines.append("Signature schemes: unknown (apksigner could not verify this file)")
    lines.append(f"Assets: {report['asset_count']} file(s)  |  res/: "
                 f"{report['resource_file_count']} file(s)  |  other: "
                 f"{report['other_file_count']} file(s)")
    if report.get("asset_bundles"):
        lines.append(f"Asset bundles ({report['asset_bundle_count']}, "
                     f"{report['asset_bundle_bytes']:,} bytes):")
        for b in report["asset_bundles"][:20]:
            lines.append(f"  - {b['name']}  ({b['size_bytes']:,} bytes)")
        if report["asset_bundle_count"] > 20:
            lines.append(f"  ... and {report['asset_bundle_count'] - 20} more (see --json)")
    if report.get("engine_hints"):
        lines.append("Engine hints (path signatures; confirm with the native guide):")
        for h in report["engine_hints"]:
            lines.append(f"  - {h['engine']}: {h['marker_count']} marker(s), e.g. {h['markers'][0]}")
    ev = report.get("engine_versions") or {}
    if ev.get("unity_metadata_version") is not None:
        era = ev.get("unity_metadata_era") or "unmapped version"
        lines.append(f"Unity metadata version: {ev['unity_metadata_version']} ({era})")
    if ev.get("godot_pck"):
        for p in ev["godot_pck"]:
            era = f", {p['pack_format_era']}" if p.get("pack_format_era") else ""
            lines.append(f"Godot PCK: {p['name']} (pack format {p['pack_format_version']}"
                         f"{era}, engine {p['engine_version']})")
    if ev.get("unreal_version"):
        lines.append(f"Unreal version: {ev.get('unreal_engine', 'UE')} "
                     f"{ev['unreal_version']} (build string in "
                     f"{ev.get('unreal_version_file', 'the engine library')})")
    if report.get("library_versions"):
        lv = report["library_versions"]
        lines.append(f"Library versions (META-INF/*.version, {len(lv)} entries):")
        for name in list(lv)[:20]:
            lines.append(f"  - {name}: {lv[name]}")
        if len(lv) > 20:
            lines.append(f"  ... and {len(lv) - 20} more (see --json)")
    if report.get("rust_hints"):
        lines.append("Rust markers in native libs (suggests Rust code linked in):")
        for h in report["rust_hints"]:
            lines.append(f"  - {h['lib']}: {', '.join(h['markers'])}")
    if report.get("rust_scan_truncated"):
        lines.append("  (Rust scan stopped at the 512 MB budget; later .so files unscanned)")
    if report.get("baseline_profiles"):
        lines.append(f"Baseline profiles: {', '.join(report['baseline_profiles'])}")
    prots = report.get("protections") or []
    if prots:
        lines.append("Protection systems (static markers only; a hit means"
                     " protection artifacts or protection code ship in the"
                     " package, not that a runtime check passed):")
        current = None
        for f in prots:
            if f["category"] != current:
                current = f["category"]
                lines.append(f"  [{f['category_label']}]")
            lines.append(f"  - {f['name']}: {'; '.join(f['evidence'])}")
            if f.get("note"):
                lines.append(f"    note: {f['note']}")
    else:
        lines.append("Protection systems: none detected by static markers"
                     " (absence proves nothing: several protection kinds"
                     " leave no static trace; see the triage guide)")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(description="NAR APK triage: first-5-minutes inventory.")
    p.add_argument("apk", help="path to the .apk, .aab, or .obb file")
    p.add_argument("--json", action="store_true", help="machine-readable JSON output")
    args = p.parse_args(argv)
    try:
        report = triage(args.apk)
    except FileNotFoundError as e:
        print(f"nar-triage: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"nar-triage: cannot read file: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(human(report))
    return 0 if "error" not in report else 1


if __name__ == "__main__":
    sys.exit(main())
