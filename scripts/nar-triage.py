#!/usr/bin/env python3
"""nar-triage.py: first-5-minutes APK triage for the NAR Skill.

Stdlib-only, no pip dependencies. Reads the APK as a ZIP (never executes it)
and reports identity, inventory, and structure.

Usage:
    python3 nar-triage.py app.apk [--json]
    python3 nar-triage.py app.aab [--json]     # AABs are ZIPs too; flagged as such
    python3 nar-triage.py main.123.com.game.obb [--json]  # OBB expansion files

Output: SHA-256, size, ZIP entry breakdown (DEX files, .so per ABI,
resources.arsc, AndroidManifest.xml, META-INF cert files, assets/res counts),
DEX list with sizes and DEX format versions (035/037/038/039/040/041, read
from each DEX header), native library list, signing files and signature
schemes (via `apksigner verify --verbose` when apksigner is available),
game-engine hints (Unity / Unreal / Godot / Cocos / Flutter / libGDX /
Adobe AIR / React Native old and new architecture, from path signatures
only), engine version hints from binary headers (Unity IL2CPP metadata
version, Godot PCK pack format and engine version), DEX content markers
(Kotlin, Jetpack Compose, Play Integrity, legacy Apache HttpClient, and
more, from string fingerprints inside the DEX files), Rust markers in
native libs (Rust runtime strings inside .so files), baseline profiles,
game asset-bundle inventory (.pak / .bundle / .unity3d / .obb / .pck),
and split-APK detection. When aapt2 is available, package name / version /
SDK levels from `aapt2 dump badging` are included; otherwise those fields
report why badging is unavailable.

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import glob
import hashlib
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
    # Adobe AIR: the descriptor is the strong marker; a bare .swf alone is
    # weak (any app can bundle one). Confirm with the descriptor path.
    ("Adobe AIR", ["META-INF/AIR/application.xml", ".swf"]),
]
# DEX content markers: byte fingerprints searched inside each DEX file.
# These are string occurrences in the DEX string/type tables, so a hit
# means the framework's classes are referenced, not that they run.
DEX_MARKERS = [
    ("Kotlin", [b"kotlin/Metadata"]),
    ("Jetpack Compose", [b"androidx/compose"]),
    ("Compose Multiplatform", [b"org/jetbrains/compose"]),
    ("Play Integrity API", [b"com/google/android/play/core/integrity"]),
    ("Apache HttpClient (legacy)", [b"org/apache/http"]),
    ("Adobe AIR", [b"com/adobe/air"]),
    ("libGDX", [b"com/badlogic/gdx"]),
    ("Flutter", [b"io/flutter/embedding"]),
    ("Unity player wrapper", [b"com/unity3d/player"]),
    ("Godot wrapper", [b"org/godotengine/godot"]),
    ("Cocos2d-x wrapper", [b"org/cocos2dx/lib"]),
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
    engine major/minor/patch. Returns None when the entry is missing,
    short, or has no GDPC magic.
    """
    try:
        with zf.open(name) as f:
            head = f.read(20)
    except (KeyError, OSError, zipfile.BadZipFile):
        return None
    if len(head) < 20 or head[:4] != b"GDPC":
        return None
    pack_version, major, minor, patch = struct.unpack("<IIII", head[4:20])
    return {"pack_format_version": pack_version,
            "pack_format_era": GODOT_PCK_ERAS.get(pack_version),
            "engine_version": f"{major}.{minor}.{patch}"}


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


def apksigner_verify(apk_path):
    """Signature schemes via `apksigner verify --verbose`.

    Returns (info_dict, status) where status is one of "ok",
    "not-found" (no apksigner binary), "unreadable" (apksigner ran but
    its output could not be parsed), or "not-applicable" (AAB/OBB:
    apksigner only verifies APKs; on an AAB it throws ApkFormatException).
    An unsigned APK is a normal "ok" result with verifies=False.
    """
    if apk_path.lower().endswith((".aab", ".obb")):
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
    if errors:
        info["errors"] = errors
    if not parsed:
        return {}, "unreadable"
    return info, "ok"


def aapt2_badging(apk_path):
    """Best-effort package identity via aapt2.

    Returns (info_dict, status) where status is one of "ok", "not-found",
    or "unreadable" (aapt2 ran but could not read badging. Expected for
    .aab bundles, which need bundletool instead).
    """
    aapt2 = shutil.which("aapt2")
    if not aapt2:
        # Look in common Android SDK locations.
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
                        aapt2 = cand
                        break
            if aapt2:
                break
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
    for line in out.stdout.splitlines():
        m = BADGING_PATTERNS["package"].match(line)
        if m:
            info["package"] = m.group(1)
            info["version_code"] = m.group(2)
            info["version_name"] = m.group(3)
            continue
        m = BADGING_PATTERNS["sdk"].match(line)
        if m:
            info["min_sdk"] = m.group(1)
            continue
        m = BADGING_PATTERNS["target_sdk"].match(line)
        if m:
            info["target_sdk"] = m.group(1)
            continue
        m = BADGING_PATTERNS["app_label"].match(line)
        if m:
            info["app_label"] = m.group(1)
            continue
        if line.startswith("uses-permission:"):
            pm = re.search(r"name='([^']+)'", line)
            if pm:
                permissions.append(pm.group(1))
    if permissions:
        info["permissions"] = sorted(set(permissions))
    return info, "ok"


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
        "obb_kind": obb_match.group(1) if obb_match else None,
        "obb_version_code": obb_match.group(2) if obb_match else None,
        "obb_package": obb_match.group(3) if obb_match else None,
        "looks_like_split": bool(SPLIT_RE.search(basename)),
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

        # DEX content markers: stream each DEX file once and count
        # framework fingerprints (Compose, Play Integrity, legacy
        # HttpClient, ...). One pass per DEX, all patterns together.
        all_dex_patterns = [p for _, pats in DEX_MARKERS for p in pats]
        marker_totals = {}
        for d in dex:
            try:
                with zf.open(d["name"]) as f:
                    counts, _, _ = count_patterns_in_stream(f, all_dex_patterns)
            except (KeyError, OSError, zipfile.BadZipFile):
                continue
            for label, pats in DEX_MARKERS:
                hits = sum(counts[p] for p in pats)
                if hits:
                    marker_totals.setdefault(label, []).append(
                        {"name": d["name"], "hits": hits})
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

        # Baseline profiles (ART profile-guided optimization inputs) and
        # .dm DEX metadata files.
        baseline_profiles = sorted(
            n for n in names
            if n.lower().endswith(".dm")
            or "/dexopt/baseline.prof" in n.lower()
            or n.lower().endswith("baseline.prof")
            or n.lower().endswith("baseline.profm"))

        result.update({
            "zip_entries": len(names),
            "has_manifest": has_manifest,
            "has_resources_arsc": has_arsc,
            "aab_modules": modules if result["is_aab"] else [],
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

    badging, badging_status = aapt2_badging(apk_path)
    result["badging"] = badging
    result["badging_status"] = badging_status
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
        if b.get("permissions"):
            lines.append(f"Permissions ({len(b['permissions'])}): {', '.join(b['permissions'])}")
    elif report.get("badging_status") == "not-found":
        lines.append("Package: unknown (aapt2 not found. See nar-doctor.sh)")
    elif report.get("is_aab"):
        lines.append("Package: unknown (aapt2 cannot read .aab badging;"
                     " use bundletool to inspect the manifest)")
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
        if report.get("is_obb"):
            lines.append("  (none: OBBs carry assets, not code)")
        elif report.get("is_aab"):
            lines.append("  (none at bundle level. Check base/lib/ after bundletool extract)")
        else:
            lines.append("  (none: pure DEX app)")
    lines.append(f"META-INF ({len(report['meta_inf_entries'])}): "
                 f"{', '.join(report['meta_inf_entries']) or '(none)'}")
    lines.append(f"Signing files: {', '.join(report['signing_files']) or '(none found)'}")
    sig = report.get("signature_schemes") or {}
    sig_status = report.get("signature_status")
    if sig_status == "ok" and sig:
        if sig.get("verifies"):
            parts = [f"v1 {'yes' if sig.get('v1') else 'no'}",
                     f"v2 {'yes' if sig.get('v2') else 'no'}",
                     f"v3 {'yes' if sig.get('v3') else 'no'}",
                     f"v3.1 {'yes' if sig.get('v3_1') else 'no'}",
                     f"v4 {'yes' if sig.get('v4') else 'no'}"]
            lines.append("Signature schemes (apksigner): " + ", ".join(parts)
                         + f"  |  signers: {sig.get('signers', '?')}  |  verifies")
        else:
            err = "; ".join(sig.get("errors", [])) or "verification failed"
            lines.append(f"Signature schemes (apksigner): DOES NOT VERIFY ({err})")
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
    if report.get("rust_hints"):
        lines.append("Rust markers in native libs (suggests Rust code linked in):")
        for h in report["rust_hints"]:
            lines.append(f"  - {h['lib']}: {', '.join(h['markers'])}")
    if report.get("rust_scan_truncated"):
        lines.append("  (Rust scan stopped at the 512 MB budget; later .so files unscanned)")
    if report.get("baseline_profiles"):
        lines.append(f"Baseline profiles: {', '.join(report['baseline_profiles'])}")
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
