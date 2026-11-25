"""Unit tests: nar-engines JNI / dynamic-symbol evidence (3.1).

Before Part 3.1 nar-engines never read ELF exports, so a
build whose game library carried a non-canonical name scored
only its DEX corroboration (+10) no matter how many family
JNI symbols it exported: a Cocos2d-x build exporting the
Java_org_cocos2dx_lib_* surface from libgame.so came back
detected=false / low. These tests pin the fix:

- JNI evidence extraction from lib/**/*.so dynsym exports,
  including corrupt-.so degradation to no-evidence;
- the matcher bars (one strong hit, or several weak hits;
  luaL_* alone is the stock Lua C API, not LÖVE evidence);
- scoring: JNI alone -> medium/detected, JNI + a matching
  DEX marker -> high, weak corroboration alone stays low;
- negative controls: a plain native app (own-package JNI
  only) and an ANativeActivity-only library are never
  attributed to an engine family.

Synthetic inputs only: the ELF files are built byte-by-byte
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


def _load_engines():
    spec = importlib.util.spec_from_file_location(
        "nar_engines", SCRIPTS / "nar-engines.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ENG = _load_engines()

COCOS_SYMBOLS = [
    "Java_org_cocos2dx_lib_Cocos2dxActivity_nativeInit",
    "Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeRender",
    "Java_org_cocos2dx_lib_Cocos2dxHelper_nativeSetApkPath",
]


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


def _report(apk):
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / "nar-engines.py"),
         str(apk), "--json"],
        capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


PLAIN_DEX = b"dex\n039\x00" + b"\x00" * 64
COCOS_DEX = (b"dex\n039\x00" + b"\x00" * 32
             + b"Lorg/cocos2dx/lib/Cocos2dxActivity;\x00"
             + b"\x00" * 32)


# ---------------------------------------------------------- matcher

def test_matcher_cocos_prefix():
    out = ENG.match_jni_symbols(COCOS_SYMBOLS + ["plain_helper"])
    assert out["Cocos2d-x"]["count"] == 3
    assert out["Cocos2d-x"]["strong"] == 3


def test_matcher_own_package_jni_matches_nothing():
    out = ENG.match_jni_symbols(
        ["Java_com_example_synctest_MainActivity_nativeStart",
         "ANativeActivity_onCreate", "JNI_OnLoad"])
    assert out == {}


def test_matcher_weak_surface_needs_several_hits():
    two = ENG.match_jni_symbols(["mono_jit_init", "mono_main"])
    assert "Xamarin / .NET" not in two
    many = ENG.match_jni_symbols(
        ["mono_jit_init", "mono_main", "mono_gc_init"])
    assert many["Xamarin / .NET"]["weak"] == 3


def test_matcher_lualone_is_not_love():
    lua_only = ENG.match_jni_symbols(
        ["luaL_newstate", "luaL_openlibs", "luaL_loadfile"])
    assert "LÖVE" not in lua_only
    with_love = ENG.match_jni_symbols(
        ["luaL_newstate", "luaL_openlibs", "luaopen_love"])
    assert "LÖVE" in with_love


# ------------------------------------------------------- extraction

def test_jni_evidence_extraction(tmp_path):
    apk = _apk(tmp_path, "jni.apk", [
        ("lib/arm64-v8a/libgame.so",
         _elf64_with_exports(COCOS_SYMBOLS + ["plain_helper"])),
        ("classes.dex", PLAIN_DEX),
    ])
    ev = ENG.jni_evidence(str(apk))
    assert ev["libraries_scanned"] == 1
    assert ev["libraries_with_exports"] == 1
    match = ev["per_engine"]["Cocos2d-x"]
    assert match["count"] == 3
    assert match["libraries"] == ["lib/arm64-v8a/libgame.so"]
    assert ev["anative_activity"] is False


def test_jni_evidence_corrupt_so_degrades(tmp_path):
    apk = _apk(tmp_path, "corrupt.apk", [
        ("lib/arm64-v8a/libbroken.so", b"\x7fELF" + b"\xff" * 40),
        ("lib/arm64-v8a/libtext.so", b"not an elf at all"),
        ("classes.dex", PLAIN_DEX),
    ])
    ev = ENG.jni_evidence(str(apk))
    assert ev["per_engine"] == {}
    assert ev["libraries_with_exports"] == 0


def test_jni_evidence_il2cpp_mono_is_not_xamarin(tmp_path):
    """libil2cpp.so exports the mono_* API as Unity internals
    (its runtime derives from the Mono codebase); that surface
    must not be attributed to Xamarin / .NET. The same symbols
    from a Mono runtime library name keep their match."""
    mono = ["mono_jit_init", "mono_main", "mono_gc_init",
            "mono_array_element_size"]
    apk = _apk(tmp_path, "il2cpp.apk", [
        ("lib/arm64-v8a/libil2cpp.so", _elf64_with_exports(mono)),
        ("classes.dex", PLAIN_DEX),
    ])
    ev = ENG.jni_evidence(str(apk))
    assert "Xamarin / .NET" not in ev["per_engine"]
    apk2 = _apk(tmp_path, "mono.apk", [
        ("lib/arm64-v8a/libmonosgen-2.0.so",
         _elf64_with_exports(mono)),
        ("classes.dex", PLAIN_DEX),
    ])
    ev2 = ENG.jni_evidence(str(apk2))
    assert ev2["per_engine"]["Xamarin / .NET"]["count"] == 4


def test_jni_evidence_anative_activity_flag(tmp_path):
    apk = _apk(tmp_path, "native.apk", [
        ("lib/arm64-v8a/libnative.so", _elf64_with_exports(
            ["ANativeActivity_onCreate",
             "Java_com_example_synctest_MainActivity_nativeStart"])),
        ("classes.dex", PLAIN_DEX),
    ])
    ev = ENG.jni_evidence(str(apk))
    assert ev["anative_activity"] is True
    assert ev["per_engine"] == {}


# ---------------------------------------------------------- scoring

def test_jni_alone_is_medium_detected(tmp_path):
    """The defect case: non-canonical library name, JNI
    symbols only — previously no verdict at all."""
    apk = _apk(tmp_path, "cocos.apk", [
        ("lib/arm64-v8a/libgame.so",
         _elf64_with_exports(COCOS_SYMBOLS)),
        ("classes.dex", PLAIN_DEX),
    ])
    report = _report(apk)
    verdicts = {v["engine"]: v for v in report["verdicts"]}
    v = verdicts["Cocos2d-x"]
    assert v["detected"] is True
    assert v["confidence"] == "medium"
    assert v["jni_symbols"]["match_count"] == 3
    assert v["jni_symbols"]["libraries"] == [
        "lib/arm64-v8a/libgame.so"]


def test_jni_plus_dex_marker_is_high(tmp_path):
    apk = _apk(tmp_path, "cocos2.apk", [
        ("lib/arm64-v8a/libgame.so",
         _elf64_with_exports(COCOS_SYMBOLS)),
        ("classes.dex", COCOS_DEX),
    ])
    verdicts = {v["engine"]: v
                for v in _report(apk)["verdicts"]}
    v = verdicts["Cocos2d-x"]
    assert v["detected"] is True
    assert v["confidence"] == "high"


def test_dex_marker_alone_stays_low(tmp_path):
    """Weak corroboration without JNI or path evidence must
    not inflate (pre-3.1 behaviour: score 10, low)."""
    apk = _apk(tmp_path, "cocos3.apk", [
        ("lib/arm64-v8a/libgame.so",
         _elf64_with_exports(["plain_helper"])),
        ("classes.dex", COCOS_DEX),
    ])
    verdicts = {v["engine"]: v
                for v in _report(apk)["verdicts"]}
    v = verdicts["Cocos2d-x"]
    assert v["detected"] is False
    assert v["confidence"] == "low"
    assert "jni_symbols" not in v


def test_native_only_is_not_an_engine(tmp_path):
    """Negative control: ANativeActivity + own-package JNI
    reaches no engine verdict at any confidence, and the
    scan identifies the target as native with no engine."""
    apk = _apk(tmp_path, "plain.apk", [
        ("lib/arm64-v8a/libnative.so", _elf64_with_exports(
            ["ANativeActivity_onCreate",
             "Java_com_example_synctest_MainActivity_nativeGo"])),
        ("classes.dex", PLAIN_DEX),
    ])
    report = _report(apk)
    assert report["verdicts"] == []
    assert report["jni_scan"]["anative_activity_oncreate"] is True
    assert report["jni_scan"]["native_no_engine"] is True


def test_corrupt_so_full_tool_still_reports(tmp_path):
    apk = _apk(tmp_path, "broken.apk", [
        ("lib/arm64-v8a/libbroken.so", b"\x7fELF" + b"\xff" * 40),
        ("classes.dex", PLAIN_DEX),
    ])
    report = _report(apk)
    assert report["verdicts"] == []
    assert report["jni_scan"]["libraries_with_exports"] == 0
