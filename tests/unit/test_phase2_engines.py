"""Phase 2 fix-round regression tests: engines + native cluster.

Covers three measured findings from the Phase 2 accuracy
benchmark (generic descriptions; no target-identifying data):

- M2-13: native.json's per-library jni_exports list counted
  JNI_OnLoad as a JNI export, so every count ran +1 against a
  Java_*-only census. jni_exports is now Java_* only;
  JNI_OnLoad stays in the full exports list, which is where
  bridge classification reads it.
- M2-08: a weak JNI substring pattern matched inside mangled
  C++ names (a short pattern spanning identifier boundaries,
  e.g. the tail of one identifier plus the head of the next)
  produced a false engine family match. Weak substrings now
  require a whole-token match over demangle-aware tokens.
- M2-07: JNI evidence contributed solely by a known
  third-party SDK bridge namespace (an SDK built on an
  engine, shipped inside a native app) pushed that engine's
  verdict over the detection threshold on its own. Bridge-only
  JNI evidence is still recorded as an indicator but is
  weighed below the detection threshold; any non-bridge JNI
  evidence keeps the full weight.

Synthetic inputs only: ELF files are built byte-by-byte
below, no external fixtures, no app data.
"""
import importlib.util
import io
import json
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ENG = _load("nar_engines_p2", "nar-engines.py")
NAT = _load("nar_native_p2", "nar-native.py")
from narlib.elf import Elf  # noqa: E402


def _elf64_with_exports(names):
    """Minimal ELF64 (LE, ET_DYN) whose .dynsym exports
    exactly `names` as defined GLOBAL FUNC symbols."""
    dynstr = b"\x00"
    offsets = {}
    for name in names:
        offsets[name] = len(dynstr)
        dynstr += name.encode() + b"\x00"
    dynsym = b"\x00" * 24  # null symbol
    for name in names:
        dynsym += struct.pack(
            "<IBBHQQ", offsets[name], 0x12, 0, 1, 0, 0)
    shstrtab = b"\x00.dynsym\x00.dynstr\x00.shstrtab\x00"
    sh_name = {".dynsym": 1, ".dynstr": 9, ".shstrtab": 17}
    ehsize = 64
    off_dynsym = ehsize
    off_dynstr = off_dynsym + len(dynsym)
    off_shstr = off_dynstr + len(dynstr)
    shoff = off_shstr + len(shstrtab)

    def sh(name, shtype, offset, size, link, info, entsize):
        return struct.pack(
            "<IIQQQQIIQQ", sh_name.get(name, 0), shtype, 0, 0,
            offset, size, link, info, 8, entsize)

    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8,
        3, 0xB7, 1, 0, 0, shoff, 0, ehsize, 0, 0, 64, 4, 3)
    sections = b"\x00" * 64
    sections += sh(".dynsym", 11, off_dynsym, len(dynsym),
                   2, 1, 24)
    sections += sh(".dynstr", 3, off_dynstr, len(dynstr),
                   0, 0, 0)
    sections += sh(".shstrtab", 3, off_shstr, len(shstrtab),
                   0, 0, 0)
    return header + dynsym + dynstr + shstrtab + sections


def _apk(tmp_path, name, members):
    path = tmp_path / name
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for member, data in members:
            zf.writestr(member, data)
    path.write_bytes(buf.getvalue())
    return path


PLAIN_DEX = b"dex\n039\x00" + b"\x00" * 64


def _engines_report(apk):
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / "nar-engines.py"),
         str(apk), "--json"],
        capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


# ---------------------------------------------------------- M2-08

# Mangled C++ names whose lowered form contains the LÖVE
# weak pattern only across an identifier seam: the tail of
# one identifier plus the head of the next (Cell|Overlays,
# Seasonal|Overlay). None contains the pattern as a word.
BOUNDARY_ACCIDENT_SYMBOLS = [
    "_ZN9PanelMenu20animateCellOverlaysEPv",
    "_ZN15SeasonalOverlay4initEv",
    "_ZN7ShopPanel22setupCellOverlaysEPv",
    "_ZN19SeasonalOverlayNode9addToNodeEPv",
    "_ZN9SalonMenu22setupSalonCellOverlaysEPv",
]


def test_matcher_weak_substring_boundary_accident_is_not_love():
    out = ENG.match_jni_symbols(BOUNDARY_ACCIDENT_SYMBOLS)
    assert "LÖVE" not in out
    # Even with the stock Lua C API surface present (weak
    # prefix hits), the boundary accidents must not supply
    # the corroborating token the family requires.
    out = ENG.match_jni_symbols(
        BOUNDARY_ACCIDENT_SYMBOLS
        + ["luaL_newstate", "luaL_openlibs", "luaL_loadfile"])
    assert "LÖVE" not in out


def test_matcher_weak_substring_whole_token_still_matches():
    # The pattern as a whole mangled-name component (the
    # shape a genuine build of the family exports).
    mangled = ["_ZN4love12AudioDevice4initEv",
               "_ZN4love7physics4stepEf",
               "_ZN4love8graphics4drawEv"]
    out = ENG.match_jni_symbols(mangled)
    assert out["LÖVE"]["weak"] == 3
    # The pattern as a whole underscore-delimited token.
    plain = ["love_graphics_draw", "love_audio_play",
             "love_timer_step"]
    out = ENG.match_jni_symbols(plain)
    assert "LÖVE" in out


def test_engines_boundary_accident_symbols_no_love_verdict(tmp_path):
    cocos = [
        "Java_org_cocos2dx_lib_Cocos2dxActivity_nativeInit",
        "Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeRender",
        "Java_org_cocos2dx_lib_Cocos2dxHelper_nativeSetApkPath",
    ]
    apk = _apk(tmp_path, "accident.apk", [
        ("lib/arm64-v8a/libgame.so", _elf64_with_exports(
            cocos + BOUNDARY_ACCIDENT_SYMBOLS)),
        ("classes.dex", PLAIN_DEX),
    ])
    report = _engines_report(apk)
    verdicts = {v["engine"]: v for v in report["verdicts"]}
    assert verdicts["Cocos2d-x"]["detected"] is True
    assert "LÖVE" not in verdicts


# ---------------------------------------------------------- M2-07

# JNI exports of a known third-party SDK bridge hosted under
# an engine's Java package root (the registry's bridge
# namespace), and the engine's own player exports.
BRIDGE_SYMBOLS = [
    "Java_com_unity3d_coherence_Bridge_init",
    "Java_com_unity3d_coherence_Bridge_start",
    "Java_com_unity3d_coherence_Bridge_stop",
    "Java_com_unity3d_coherence_Bridge_send",
    "Java_com_unity3d_coherence_Bridge_recv",
]
OWN_SYMBOLS = [
    "Java_com_unity3d_player_UnityPlayer_nativeRender",
    "Java_com_unity3d_player_UnityPlayer_nativePause",
]


def test_bridge_prefixes_come_from_the_registry():
    assert ENG.JNI_BRIDGE_PREFIXES.get("Unity (IL2CPP)") == [
        "Java_com_unity3d_coherence_"]


def test_jni_evidence_marks_bridge_only(tmp_path):
    apk = _apk(tmp_path, "bridgeonly.apk", [
        ("lib/arm64-v8a/libsdkbridge.so",
         _elf64_with_exports(BRIDGE_SYMBOLS)),
        ("classes.dex", PLAIN_DEX),
    ])
    ev = ENG.jni_evidence(str(apk))
    match = ev["per_engine"]["Unity (IL2CPP)"]
    assert match["bridge_only"] is True
    assert match["bridge_symbols"] == len(BRIDGE_SYMBOLS)
    assert match["count"] == len(BRIDGE_SYMBOLS)


def test_jni_evidence_mixed_bridge_and_own_is_not_bridge_only(
        tmp_path):
    apk = _apk(tmp_path, "mixed.apk", [
        ("lib/arm64-v8a/libsdkbridge.so",
         _elf64_with_exports(BRIDGE_SYMBOLS)),
        ("lib/arm64-v8a/libengine.so",
         _elf64_with_exports(OWN_SYMBOLS)),
        ("classes.dex", PLAIN_DEX),
    ])
    ev = ENG.jni_evidence(str(apk))
    match = ev["per_engine"]["Unity (IL2CPP)"]
    assert match["bridge_only"] is False


def test_bridge_only_jni_recorded_but_not_detected(tmp_path):
    """The measured defect shape: a native app whose only
    engine-family JNI evidence is one SDK bridge library.
    The indicator stays recorded; the verdict must not
    cross the detection threshold on it."""
    apk = _apk(tmp_path, "sdkonly.apk", [
        ("lib/arm64-v8a/libsdkbridge.so",
         _elf64_with_exports(BRIDGE_SYMBOLS)),
        ("classes.dex", PLAIN_DEX),
    ])
    report = _engines_report(apk)
    verdicts = {v["engine"]: v for v in report["verdicts"]}
    v = verdicts["Unity (IL2CPP)"]
    assert v["detected"] is False
    assert v["confidence"] == "low"
    assert v["score"] == ENG.JNI_BRIDGE_ONLY_SCORE
    assert any(i["kind"] == "jni-symbols" for i in v["indicators"])
    assert v["jni_symbols"]["sdk_bridge_only"] is True
    assert v["jni_symbols"]["match_count"] == len(BRIDGE_SYMBOLS)


def test_bridge_plus_own_jni_still_detected(tmp_path):
    apk = _apk(tmp_path, "mixed2.apk", [
        ("lib/arm64-v8a/libsdkbridge.so",
         _elf64_with_exports(BRIDGE_SYMBOLS)),
        ("lib/arm64-v8a/libengine.so",
         _elf64_with_exports(OWN_SYMBOLS)),
        ("classes.dex", PLAIN_DEX),
    ])
    report = _engines_report(apk)
    verdicts = {v["engine"]: v for v in report["verdicts"]}
    v = verdicts["Unity (IL2CPP)"]
    assert v["detected"] is True
    assert v["confidence"] == "medium"
    assert "sdk_bridge_only" not in v["jni_symbols"]


def test_bridge_plus_engine_runtime_still_detected(tmp_path):
    """An app that really is built on the engine (its
    runtime library ships) stays detected even though its
    JNI evidence is bridge-only: the path/layout channels
    carry the verdict."""
    apk = _apk(tmp_path, "realengine.apk", [
        ("lib/arm64-v8a/libsdkbridge.so",
         _elf64_with_exports(BRIDGE_SYMBOLS)),
        ("lib/arm64-v8a/libil2cpp.so", b"placeholder"),
        ("assets/bin/Data/level0", b"data"),
        ("classes.dex", PLAIN_DEX),
    ])
    report = _engines_report(apk)
    verdicts = {v["engine"]: v for v in report["verdicts"]}
    v = verdicts["Unity (IL2CPP)"]
    assert v["detected"] is True
    assert v["jni_symbols"]["sdk_bridge_only"] is True


# ---------------------------------------------------------- M2-13

def test_jni_exports_exclude_jni_onload():
    facts = Elf(_elf64_with_exports(
        ["JNI_OnLoad", "Java_com_example_Native_run",
         "plain_helper"])).facts()
    assert facts["jni_exports"] == ["Java_com_example_Native_run"]
    # Bridge classification input is preserved: JNI_OnLoad is
    # still in the full exports list.
    assert "JNI_OnLoad" in facts["exports"]


def test_jni_exports_onload_only_library_is_empty():
    facts = Elf(_elf64_with_exports(["JNI_OnLoad"])).facts()
    assert facts["jni_exports"] == []
    assert facts["exports"] == ["JNI_OnLoad"]


def test_native_report_jni_counts_are_java_only(tmp_path):
    apk = _apk(tmp_path, "bridge.apk", [
        ("lib/arm64-v8a/libbridge.so", _elf64_with_exports(
            ["JNI_OnLoad", "Java_com_example_Native_run",
             "Java_com_example_Native_stop"])),
        ("lib/arm64-v8a/libonload.so", _elf64_with_exports(
            ["JNI_OnLoad"])),
    ])
    report = NAT.analyze(str(apk))
    libs = {lib["display_name"]: lib
            for lib in report["libraries"]}
    bridge = libs["arm64-v8a/libbridge.so"]
    assert bridge["jni_exports"] == [
        "Java_com_example_Native_run",
        "Java_com_example_Native_stop"]
    assert "JNI_OnLoad" in bridge["exports"]
    onload = libs["arm64-v8a/libonload.so"]
    assert onload["jni_exports"] == []
    assert onload["exports"] == ["JNI_OnLoad"]
    # jni_map mirrors jni_exports: the OnLoad-only library is
    # absent, the Java-export library carries Java_* only.
    assert report["jni_map"] == {
        "arm64-v8a/libbridge.so": [
            "Java_com_example_Native_run",
            "Java_com_example_Native_stop"]}
