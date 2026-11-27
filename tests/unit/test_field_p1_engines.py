"""Field round P1 (Areas 4/6): native-strings engine evidence,
nar-cocos version-evidence verdict, and unknown-engine outcome.

Shapes reproduced from the field audit's synthetic matrix
(generic library name, statically-linked engine strings in the
library's raw bytes, custom content path, no canonical names):

- strings-only evidence in a generically-named library must
  detect Cocos2d-x at medium via a native-strings indicator;
- weak string tokens alone must stay a recorded candidate,
  never a detection;
- nar-cocos must count its own version_evidence toward its
  verdict, including 2.x-era version strings;
- a fat native target with no engine signals must get an
  explicit unknown/custom-engine record carrying its native
  evidence, instead of an affirmative plain-native label;
- a target with no native libraries at all is unchanged.

Synthetic inputs only: ELF files are built byte-by-byte below
(the builder approach of test_engines_jni_symbols.py, with
raw identifying strings appended as they would sit in a
statically-linked library's read-only data). No app data.
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


def _elf64_with_exports(names, extra_strings=b""):
    """Minimal ELF64 (LE, ET_DYN) whose .dynsym exports
    exactly `names`; `extra_strings` are appended raw after
    the sections (read-only-data shape)."""
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
    return header + dynsym + dynstr + shstrtab + sections \
        + extra_strings


def _apk(tmp_path, name, members):
    path = tmp_path / name
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for member, data in members:
            zf.writestr(member, data)
    path.write_bytes(buf.getvalue())
    return path


def _run(script, apk, *extra):
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / script), str(apk), *extra],
        capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stderr
    return proc


def _engines(apk):
    return json.loads(_run("nar-engines.py", apk, "--json").stdout)


def _cocos(apk):
    return json.loads(_run("nar-cocos.py", apk, "--json").stdout)


PLAIN_DEX = b"dex\n039\x00" + b"\x00" * 64

GENERIC_EXPORTS = [
    "ANativeActivity_onCreate",
    "Java_com_example_custom_MainActivity_nativeStart",
    "game_main_loop", "JNI_OnLoad",
]

CUSTOM_ASSETS = [
    ("assets/gamedata/level1.json",
     b'{"level":1,"pipeline":"custom"}'),
    ("assets/gamedata/pack0.bin", b"\x89CUSTOMPACK" + b"\x00" * 64),
]

# Strong version banner + exactly two distinct weak tokens:
# 40 + 12 + 12 = 64 -> medium, by the documented weighting.
STRINGS_DETECT = (
    b"\x00cocos2d-x 2.2.6\x00"
    b"cocos2d::Director::getInstance\x00"
    b"CCDirector\x00")

# Three distinct weak tokens, no version banner:
# weak-only contribution is capped below the detection bar.
STRINGS_WEAK_ONLY = (
    b"\x00cocos2d::Director::getInstance\x00"
    b"CCDirector\x00"
    b"CocosDenshion::SimpleAudioEngine\x00")


# ------------------------------------------------------- registry

def test_registry_exposes_string_signatures():
    from narlib import formats_registry
    table = formats_registry.engines_table()
    cocos = table["Cocos2d-x"]["string_signatures"]
    by_token = {s["token"]: s["strong"] for s in cocos}
    assert by_token["cocos2d-x "] is True
    assert by_token["cocos2d::"] is False
    assert by_token["CCDirector"] is False
    assert by_token["CocosDenshion"] is False
    unreal = {s["token"]: s["strong"]
              for s in table["Unreal Engine"]["string_signatures"]}
    assert unreal["++UE4+Release-"] is True
    assert unreal["++UE5+Release-"] is True


# ------------------------------------------- nar-engines strings

def test_strings_only_cocos_detected_medium(tmp_path):
    """The field shape: generic libgame.so, generic exports,
    Cocos strings only, custom assets path, plain DEX."""
    apk = _apk(tmp_path, "stringonly.apk", [
        ("lib/arm64-v8a/libgame.so",
         _elf64_with_exports(GENERIC_EXPORTS, STRINGS_DETECT)),
        ("classes.dex", PLAIN_DEX),
    ] + CUSTOM_ASSETS)
    report = _engines(apk)
    verdicts = {v["engine"]: v for v in report["verdicts"]}
    v = verdicts["Cocos2d-x"]
    assert v["detected"] is True
    assert v["confidence"] == "medium"
    strings_indicators = [i for i in v["indicators"]
                          if i["kind"] == "native-strings"]
    assert strings_indicators, v["indicators"]
    assert any("libgame.so" in i["detail"]
               and "cocos2d-x " in i["detail"]
               for i in strings_indicators)


def test_weak_strings_only_stays_candidate(tmp_path):
    apk = _apk(tmp_path, "weakonly.apk", [
        ("lib/arm64-v8a/libgame.so",
         _elf64_with_exports(GENERIC_EXPORTS, STRINGS_WEAK_ONLY)),
        ("classes.dex", PLAIN_DEX),
    ] + CUSTOM_ASSETS)
    report = _engines(apk)
    verdicts = {v["engine"]: v for v in report["verdicts"]}
    v = verdicts["Cocos2d-x"]
    assert v["detected"] is False
    assert v["confidence"] == "low"
    assert v["score"] < 40
    assert any(i["kind"] == "native-strings"
               for i in v["indicators"])


# ---------------------------------------------------- nar-cocos

def test_cocos_renamed_lib_version_strings_alone_present(tmp_path):
    apk = _apk(tmp_path, "cocos3x.apk", [
        ("lib/arm64-v8a/libgame.so",
         b"\x7fELF" + b"\x00" * 32 + b"cocos2d-x 3.17.2\x00"),
        ("classes.dex", PLAIN_DEX),
    ] + CUSTOM_ASSETS)
    report = _cocos(apk)
    assert report["version_evidence"], report
    assert report["verdict"] == "present"
    notes = " ".join(report.get("notes") or [])
    assert "version" in notes.lower()
    human = _run("nar-cocos.py", apk).stdout
    assert "Verdict: present" in human
    assert "cocos2d-x 3.17.2" in human


def test_cocos_2x_version_strings_present(tmp_path):
    apk = _apk(tmp_path, "cocos2x.apk", [
        ("lib/arm64-v8a/libgame.so",
         b"\x7fELF" + b"\x00" * 32 + b"cocos2d-x 2.2.6\x00"),
        ("classes.dex", PLAIN_DEX),
    ] + CUSTOM_ASSETS)
    report = _cocos(apk)
    assert report["version_evidence"], report
    assert any("2.2.6" in ev["match"]
               for ev in report["version_evidence"])
    assert report["verdict"] == "present"


# ------------------------------------------------ unknown engine

def test_unknown_engine_for_fat_native_target(tmp_path):
    apk = _apk(tmp_path, "fatnative.apk", [
        ("lib/arm64-v8a/libalpha.so", _elf64_with_exports(
            ["ANativeActivity_onCreate", "alpha_init",
             "alpha_update"])),
        ("lib/arm64-v8a/libbeta.so", _elf64_with_exports(
            ["beta_init", "beta_render", "JNI_OnLoad"])),
        ("lib/arm64-v8a/libgamma.so", _elf64_with_exports(
            ["gamma_start", "gamma_stop"])),
        ("classes.dex", PLAIN_DEX),
    ])
    report = _engines(apk)
    unknowns = [v for v in report["verdicts"]
                if v.get("unknown_engine")]
    assert len(unknowns) == 1, report["verdicts"]
    v = unknowns[0]
    assert v["engine"] == "Unknown / custom engine"
    assert v["detected"] is False
    assert v["confidence"] == "low"
    assert v["score"] == 0
    assert v["version"] is None
    assert v["recommended_next"] is None
    details = " ".join(i["detail"] for i in v["indicators"])
    assert "libalpha.so" in details
    assert "export" in details.lower()
    assert "ANativeActivity" in details
    assert report["jni_scan"]["native_no_engine"] is False
    assert report["jni_scan"]["unknown_engine"] is True
    human = _run("nar-engines.py", apk).stdout
    assert "Unknown / custom engine" in human
    assert "Native (no engine)" not in human


def test_no_native_target_unchanged(tmp_path):
    apk = _apk(tmp_path, "nonative.apk", [
        ("classes.dex", PLAIN_DEX),
        ("assets/data.json", b"{}"),
    ])
    report = _engines(apk)
    assert report["verdicts"] == []
    assert not any(v.get("unknown_engine")
                   for v in report["verdicts"])
    assert report["jni_scan"]["native_no_engine"] is False
    assert "unknown_engine" not in report["jni_scan"]
    human = _run("nar-engines.py", apk).stdout
    assert "No engine indicators found" in human
    assert "Unknown / custom engine" not in human
    assert "Native (no engine)" not in human
