"""Unit tests: field-findings round, P0 fixes.

Area 1 (F-01/F-02) — split APK orchestration: a loose
split set handed over as a bare base APK file (or as a
directory) is assembled and merged by default; triage's
split evidence is inherited by analyze; an incomplete set
carries the explicit "split set incomplete" limitation
instead of a bare detected:false / zero-library result.

Area 2 (F-04/F-05) — jadx identity validation: a candidate
counts only when its --version output identifies as jadx;
a wrapper jar or impostor binary is rejected with a named
tool_identity_mismatch record and resolution falls through
to the next candidate; NAR_JADX_JAR flows through the
registry like every other jar route.

Synthetic inputs only: tiny ZIP/APK fixtures with real
binary manifests built in-test, fake tool shims on a fake
PATH. No external fixtures, no app data.
"""
import importlib.util
import io
import json
import os
import re
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from narlib import container as C  # noqa: E402
from narlib import failures  # noqa: E402
from narlib import registry  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


nar_native = _load("nar_native_ff", "nar-native.py")
nar_engines = _load("nar_engines_ff", "nar-engines.py")
nar_dex = _load("nar_dex_ff", "nar-dex.py")
from narlib import chains as chains_mod  # noqa: E402


# ------------------------------------------------------------------
# fixture builders (shapes copied from test_app.py /
# test_container_splits.py, the repo's own builders)
# ------------------------------------------------------------------

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def build_axml(tag, attrs, children):
    """Minimal binary AXML for one element tree. attrs is a
    list of (name, value) where name may carry the
    'android:' prefix; values are str, bool or int."""
    strings = []
    index = {}

    def sidx(s):
        if s not in index:
            index[s] = len(strings)
            strings.append(s)
        return index[s]

    sidx(ANDROID_NS)

    def collect(node):
        t, at, kids = node
        sidx(t)
        for name, value in at:
            sidx(name.split(":", 1)[-1])
            if isinstance(value, str):
                sidx(value)
        for k in kids:
            collect(k)

    collect((tag, attrs, children))
    pool = bytearray()
    offsets = []
    body = bytearray()
    for s in strings:
        offsets.append(len(body))
        raw = s.encode("utf-16-le")
        body += struct.pack("<H", len(s)) + raw + b"\x00\x00"
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    pool += struct.pack("<HHIIIIII", 0x0001, header_size,
                        strings_start + len(body), len(strings),
                        0, 0, strings_start, 0)
    for off in offsets:
        pool += struct.pack("<I", off)
    pool += body

    def attr_bytes(at):
        out = bytearray()
        for name, value in at:
            prefixed = name.startswith("android:")
            ns = index[ANDROID_NS] if prefixed else 0xFFFFFFFF
            nm = index[name.split(":", 1)[-1]]
            if isinstance(value, bool):
                out += struct.pack("<IIIHBBI", ns, nm,
                                   0xFFFFFFFF, 8, 0, 0x12,
                                   0xFFFFFFFF if value else 0)
            elif isinstance(value, int):
                out += struct.pack("<IIIHBBI", ns, nm,
                                   0xFFFFFFFF, 8, 0, 0x10, value)
            else:
                vi = index[value]
                out += struct.pack("<IIIHBBI", ns, nm, vi, 8, 0,
                                   0x03, vi)
        return bytes(out)

    def elem_bytes(node):
        t, at, kids = node
        ab = attr_bytes(at)
        size = 36 + len(ab)
        out = bytearray()
        out += struct.pack("<HHI", 0x0102, 16, size)
        out += struct.pack("<II", 0, 0xFFFFFFFF)
        out += struct.pack("<II", 0xFFFFFFFF, index[t])
        out += struct.pack("<HHH", 20, 20, len(at))
        out += b"\x00" * 6
        out += ab
        for k in kids:
            out += elem_bytes(k)
        out += struct.pack("<HHI", 0x0103, 16, 24)
        out += struct.pack("<II", 0, 0xFFFFFFFF)
        out += struct.pack("<II", 0xFFFFFFFF, index[t])
        return bytes(out)

    root_bytes = elem_bytes((tag, attrs, children))
    total = 8 + len(pool) + len(root_bytes)
    return struct.pack("<HHI", 0x0003, 8, total) \
        + bytes(pool) + root_bytes


def _uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def build_dex():
    """Minimal DEX (same shape as test_container_splits')."""
    strings = [b"LFoo;", b"hello"]
    header_size = 0x70
    string_ids_off = header_size
    string_data_off = string_ids_off + 4 * len(strings)
    data = bytearray()
    offsets = []
    for s in strings:
        offsets.append(string_data_off + len(data))
        data += _uleb(len(s)) + s + b"\x00"
    type_ids_off = string_data_off + len(data)
    proto_ids_off = type_ids_off + 4
    method_ids_off = proto_ids_off + 12
    file_size = method_ids_off + 8
    out = bytearray(file_size)
    out[0:8] = b"dex\n039\x00"
    struct.pack_into("<I", out, 32, file_size)
    struct.pack_into("<I", out, 36, header_size)
    struct.pack_into("<I", out, 40, 0x12345678)
    struct.pack_into("<I", out, 56, len(strings))
    struct.pack_into("<I", out, 60, string_ids_off)
    struct.pack_into("<I", out, 64, 1)
    struct.pack_into("<I", out, 68, type_ids_off)
    struct.pack_into("<I", out, 72, 1)
    struct.pack_into("<I", out, 76, proto_ids_off)
    struct.pack_into("<I", out, 88, 1)
    struct.pack_into("<I", out, 92, method_ids_off)
    for i, off in enumerate(offsets):
        struct.pack_into("<I", out, string_ids_off + 4 * i, off)
    out[string_data_off:string_data_off + len(data)] = data
    struct.pack_into("<I", out, type_ids_off, 0)
    struct.pack_into("<III", out, proto_ids_off, 1, 0, 0)
    struct.pack_into("<HHI", out, method_ids_off, 0, 0, 1)
    return bytes(out)


def build_elf64(soname=b"libfoo.so", needed=b"libbar.so"):
    """Minimal ELF64 (same shape as test_container_splits')."""
    dynstr = b"\x00" + soname + b"\x00" + needed + b"\x00"
    ehdr_size, phdr_size = 64, 56
    phoff = ehdr_size
    dyn_off = phoff + 2 * phdr_size
    dynstr_off = dyn_off + 5 * 16
    file_size = dynstr_off + len(dynstr)
    base = 0x10000
    out = bytearray(file_size)
    out[0:4] = b"\x7fELF"
    out[4] = 2
    out[5] = 1
    struct.pack_into("<H", out, 16, 3)
    struct.pack_into("<H", out, 18, 183)
    struct.pack_into("<Q", out, 32, phoff)
    struct.pack_into("<H", out, 52, ehdr_size)
    struct.pack_into("<H", out, 54, phdr_size)
    struct.pack_into("<H", out, 56, 2)
    struct.pack_into("<IIQQQQQQ", out, phoff, 1, 5, 0, base,
                     base, file_size, file_size, 0x1000)
    struct.pack_into("<IIQQQQQQ", out, phoff + phdr_size, 2, 4,
                     dyn_off, base + dyn_off, base + dyn_off,
                     5 * 16, 5 * 16, 8)
    entries = [(14, 1), (1, 1 + len(soname) + 1),
               (5, base + dynstr_off), (10, len(dynstr)),
               (0, 0)]
    for i, (tag, val) in enumerate(entries):
        struct.pack_into("<qQ", out, dyn_off + i * 16, tag, val)
    out[dynstr_off:dynstr_off + len(dynstr)] = dynstr
    return bytes(out)


def _zip_bytes(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def _write(tmp_path, name, data):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return str(path)


def _manifest_axml(package, split=None):
    attrs = [("package", package), ("android:versionCode", 1)]
    if split:
        attrs.append(("split", split))
    return build_axml("manifest", attrs, [
        ("uses-sdk", [], []),
        ("application", [], []),
    ])


PKG = "com.example.game"


def _base_apk(package=PKG, evidence=True, extra=()):
    members = [("AndroidManifest.xml", _manifest_axml(package)),
               ("classes.dex", build_dex()),
               ("resources.arsc", b"\x02\x00\x0c\x00")]
    if evidence:
        members.append(("stamp-cert-sha256", b"stamp"))
    return _zip_bytes(members + list(extra))


def _abi_split(package=PKG, split="config.arm64_v8a",
               lib="lib/arm64-v8a/libgame.so", extra=()):
    return _zip_bytes([
        ("AndroidManifest.xml", _manifest_axml(package, split)),
        ("resources.arsc", b"\x02\x00\x0c\x00"),
        (lib, build_elf64()),
    ] + list(extra))


def _split_set(tmp_path, **base_kw):
    """The audit shape: a lone base APK whose only native
    library lives in the ABI split beside it."""
    base = _write(tmp_path, "base.apk", _base_apk(**base_kw))
    split = _write(tmp_path, "config.arm64_v8a.apk", _abi_split())
    return base, split


# ------------------------------------------------------------------
# Area 1 — resolution level
# ------------------------------------------------------------------

def test_sibling_discovery_merges_abi_split(tmp_path):
    base, _split = _split_set(tmp_path)
    with C.resolve_target(base) as r:
        assert [s["name"] for s in r.splits] == \
            ["config.arm64_v8a.apk"]
        assert r.splits[0]["kind"] == "config-abi"
        assert [m["name"] for m in r.splits_merged] == \
            ["config.arm64_v8a.apk"]
        assert len(r.native_roots) == 2
        assert r.native_roots[0] == base
        ss = r.split_set
        assert ss is not None and ss["detected"] is True
        assert ss["resolution"] == "sibling-files"
        assert ss["merged"] is True and ss["complete"] is True
        assert ss["members"][0]["source"] == "sibling-file"
        assert "stamp-cert-sha256" in ss["base_evidence"]


def test_sibling_discovery_rejects_other_package(tmp_path):
    base = _write(tmp_path, "base.apk", _base_apk())
    _write(tmp_path, "config.arm64_v8a.apk",
           _abi_split(package="com.example.other"))
    with C.resolve_target(base) as r:
        assert r.splits == []
        assert len(r.native_roots) == 1
        ss = r.split_set
        # The base carries split evidence, so the set is
        # detected — and named incomplete, with the rejected
        # candidate's reason recorded.
        assert ss is not None and ss["detected"] is True
        assert ss["complete"] is False
        assert ss["skipped"][0]["name"] == "config.arm64_v8a.apk"
        assert "package identity" in ss["skipped"][0]["reason"]


def test_sibling_discovery_declined_records_skipped(tmp_path):
    base, _split = _split_set(tmp_path)
    with C.resolve_target(base, merge_splits=False) as r:
        assert r.splits == []
        assert len(r.native_roots) == 1
        assert r.split_skipped[0]["name"] == \
            "config.arm64_v8a.apk"
        assert "merge disabled" in r.split_skipped[0]["reason"]
        assert r.split_set["merged"] is False
        assert r.split_set["complete"] is False


def test_sibling_discovery_ignores_unrelated_apks(tmp_path):
    # No base evidence, and the same-package neighbour is a
    # plain-named full APK with no split declaration: not a
    # set, no discovery, resolution untouched.
    base = _write(tmp_path, "base.apk",
                  _base_apk(evidence=False))
    _write(tmp_path, "other.apk", _base_apk(evidence=False))
    _write(tmp_path, "config.arm64_v8a.apk",
           _abi_split(package="com.example.other"))
    with C.resolve_target(base) as r:
        assert r.splits == []
        assert r.split_set is None
        assert len(r.native_roots) == 1


def test_sibling_discovery_via_split_declaration(tmp_path):
    # No bundle evidence in the base: the sibling's own
    # manifest split declaration proves membership.
    base = _write(tmp_path, "base.apk",
                  _base_apk(evidence=False))
    _write(tmp_path, "mymodule.apk", _abi_split(
        split="mymodule", lib="lib/arm64-v8a/libx.so"))
    with C.resolve_target(base) as r:
        assert [s["name"] for s in r.splits] == ["mymodule.apk"]
        assert r.split_set["complete"] is True


def test_directory_resolution_merges_set(tmp_path):
    _split_set(tmp_path)
    with C.resolve_directory(str(tmp_path)) as r:
        assert r.input_kind == "directory"
        assert r.base.endswith("base.apk")
        assert r.base_entry == "base.apk"
        assert [s["name"] for s in r.splits] == \
            ["config.arm64_v8a.apk"]
        assert len(r.native_roots) == 2
        assert r.split_set["resolution"] == "directory"
        assert r.split_set["complete"] is True


def test_directory_resolution_skips_foreign_package(tmp_path):
    _split_set(tmp_path)
    _write(tmp_path, "foreign.apk",
           _base_apk(package="com.example.other"))
    with C.resolve_directory(str(tmp_path)) as r:
        names = [s["name"] for s in r.splits]
        assert "foreign.apk" not in names
        assert any(s["name"] == "foreign.apk"
                   for s in r.split_skipped)


def test_directory_without_apks_returns_none(tmp_path):
    _write(tmp_path, "readme.txt", b"nothing here")
    assert C.resolve_directory(str(tmp_path)) is None


def test_directory_declined_records_skipped(tmp_path):
    _split_set(tmp_path)
    with C.resolve_directory(str(tmp_path),
                             merge_splits=False) as r:
        assert r.splits == []
        assert len(r.native_roots) == 1
        assert r.split_set["complete"] is False
        assert any("merge disabled" in s["reason"]
                   for s in r.split_skipped)


# ------------------------------------------------------------------
# Area 1 — stage level (the field failure numbers)
# ------------------------------------------------------------------

def test_native_counts_split_library(tmp_path):
    base, _split = _split_set(tmp_path)
    report = nar_native.analyze(base)
    assert report["native_library_count"] == 1
    lib = report["libraries"][0]
    assert lib["source_split"] == "config.arm64_v8a.apk"
    assert report["container"]["splits_merged"][0]["name"] == \
        "config.arm64_v8a.apk"
    assert report["container"]["split_set"]["resolution"] == \
        "sibling-files"


def test_engines_detects_engine_from_split_library(tmp_path):
    base = _write(tmp_path, "base.apk", _base_apk())
    _write(tmp_path, "config.arm64_v8a.apk", _abi_split(
        lib="lib/arm64-v8a/libcocos2dcpp.so"))
    report = nar_engines.fuse(base)
    verdicts = {v["engine"]: v for v in report["verdicts"]}
    assert verdicts["Cocos2d-x"]["detected"] is True


def test_engines_opt_out_via_env(tmp_path, monkeypatch):
    base = _write(tmp_path, "base.apk", _base_apk())
    _write(tmp_path, "config.arm64_v8a.apk", _abi_split(
        lib="lib/arm64-v8a/libcocos2dcpp.so"))
    monkeypatch.setenv(C.NO_MERGE_ENV_VAR, "1")
    report = nar_engines.fuse(base)
    verdicts = {v["engine"]: v for v in report["verdicts"]}
    assert verdicts.get("Cocos2d-x", {}).get(
        "detected") is not True


def test_dex_merges_split_dexes(tmp_path):
    base = _write(tmp_path, "base.apk", _base_apk())
    _write(tmp_path, "config.arm64_v8a.apk", _abi_split(
        extra=[("classes.dex", build_dex())]))
    report = nar_dex.analyze(base)
    names = [d["name"] for d in report["dex_files"]]
    assert "classes.dex" in names
    assert "config.arm64_v8a.apk:classes.dex" in names


# ------------------------------------------------------------------
# Area 1 — analyze level (CLI, the exact field shape)
# ------------------------------------------------------------------

def _run_analyze(tmp_path, target, *extra_args):
    out_dir = tmp_path / "case"
    env = dict(os.environ)
    env.setdefault("TMPDIR", str(tmp_path))
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / "nar-analyze.py"),
         str(target), "--out", str(out_dir), "--no-html",
         *extra_args],
        capture_output=True, text=True, timeout=1200, env=env)
    assert proc.returncode == 0, proc.stderr[-2000:]
    with open(out_dir / "report.json", encoding="utf-8") as fh:
        return json.load(fh), out_dir


def test_analyze_merges_loose_split_set(tmp_path):
    base, _split = _split_set(tmp_path)
    report, out_dir = _run_analyze(tmp_path, base)
    assert report["native_summary"]["libraries"] == 1
    assert report["split_set"]["resolution"] == \
        "sibling-files"
    assert report["split_set"]["complete"] is True
    assert report["container"]["splits_merged"][0][
        "name"] == "config.arm64_v8a.apk"
    assert any("sibling splits merged" in n
               for n in report["step_notes"])
    assert not any("split set incomplete" in lim
                   for lim in report["limitations"])
    with open(out_dir / "case.json", encoding="utf-8") as fh:
        case = json.load(fh)
    assert case["split_set"]["complete"] is True


def test_analyze_engine_verdict_from_split(tmp_path):
    base = _write(tmp_path, "base.apk", _base_apk())
    _write(tmp_path, "config.arm64_v8a.apk", _abi_split(
        lib="lib/arm64-v8a/libcocos2dcpp.so"))
    report, _out = _run_analyze(tmp_path, base)
    verdicts = {v["engine"]: v
                for v in report["engine_verdicts"]}
    assert verdicts["Cocos2d-x"]["detected"] is True
    assert report["native_summary"]["libraries"] == 1


def test_analyze_no_merge_splits_surfaces_limitation(tmp_path):
    base, _split = _split_set(tmp_path)
    report, _out = _run_analyze(tmp_path, base,
                                "--no-merge-splits")
    assert report["native_summary"]["libraries"] == 0
    assert report["split_set"]["complete"] is False
    assert any(
        "split set incomplete — native layer may be "
        "under-reported" in lim
        for lim in report["limitations"])


def test_analyze_missing_siblings_limitation(tmp_path):
    # Base carries bundle evidence; no siblings beside it.
    base = _write(tmp_path, "base.apk", _base_apk())
    report, _out = _run_analyze(tmp_path, base)
    assert report["split_set"]["detected"] is True
    assert report["split_set"]["complete"] is False
    assert any(
        "split set incomplete — native layer may be "
        "under-reported" in lim
        for lim in report["limitations"])


def test_analyze_directory_target(tmp_path):
    _split_set(tmp_path)
    report, _out = _run_analyze(tmp_path, tmp_path)
    assert report["split_set"]["resolution"] == "directory"
    assert report["split_set"]["complete"] is True
    assert report["native_summary"]["libraries"] == 1
    assert report["identity"]["kind"] == "split-set directory"


def test_analyze_empty_directory_rejected(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / "nar-analyze.py"),
         str(empty), "--out", str(tmp_path / "case"),
         "--no-html"],
        capture_output=True, text=True, timeout=300)
    assert proc.returncode == 2
    assert "directory holds no APK" in proc.stderr


# ------------------------------------------------------------------
# Area 2 — registry identity validation
# ------------------------------------------------------------------

def _shim(path, body):
    """Plant a fake tool whose --version prints one line.

    POSIX: an extensionless ``#!/bin/sh`` script, which is
    what PATH resolution finds there. Windows: CreateProcess
    cannot start a shell script and ``shutil.which`` resolves
    only PATHEXT suffixes, so the same fake is planted as
    ``<name>.bat`` printing the same line (run #63: the
    extensionless plant was invisible to the registry probe
    on the hosted Windows runner — "not found", never
    identity-rejected). Only single-echo bodies are
    translated; anything richer needs its own planter.
    Returns the planted file's path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if sys.platform == "win32":
        m = re.fullmatch(r"echo '([^']*)'\n", body)
        assert m, "win32 shim translation needs an echo body"
        bat = path.with_name(path.name + ".bat")
        bat.write_bytes(("@echo off\r\necho " + m.group(1)
                         + "\r\n").encode("utf-8"))
        return str(bat)
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def _java_shim(path):
    """Plant the per-jar dispatching fake ``java``: the
    wrapper jar reports another product, a jadx-shaped jar
    reports a jadx version, anything else fails. Batch on
    Windows (see _shim), a shell case dispatch elsewhere."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if sys.platform == "win32":
        bat = path.with_name(path.name + ".bat")
        bat.write_bytes((
            "@echo off\r\n"
            "echo %*| findstr /C:\"wrapper.jar\" >nul\r\n"
            "if %errorlevel%==0 goto wrapper\r\n"
            "echo %*| findstr /C:\"all.jar\" >nul\r\n"
            "if %errorlevel%==0 goto realjar\r\n"
            "exit /b 1\r\n"
            ":wrapper\r\n"
            "echo WRAPPER-JAR-NOT-JADX\r\n"
            "exit /b 0\r\n"
            ":realjar\r\n"
            "echo 1.5.3\r\n"
            "exit /b 0\r\n").encode("utf-8"))
        return str(bat)
    path.write_text("#!/bin/sh\n"
                    "for a in \"$@\"; do\n"
                    "  case \"$a\" in\n"
                    "    */wrapper.jar) echo "
                    "'WRAPPER-JAR-NOT-JADX'; exit 0 ;;\n"
                    "    */jadx-*-all.jar) echo '1.5.3'; "
                    "exit 0 ;;\n"
                    "  esac\n"
                    "done\n"
                    "exit 1\n", encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def _norm(path):
    """Separator-insensitive path comparison: a resolved
    Windows path may mix the separators of the pieces it
    was joined from (registry globs carry forward slashes,
    pathlib carries backslashes) while naming the same
    file."""
    return str(path).replace("\\", "/")


def _jadx_entry():
    reg = registry.load_registry()
    return next(t for t in reg["tools"] if t["name"] == "jadx")


@pytest.fixture()
def fake_env(tmp_path, monkeypatch):
    """Isolated HOME + PATH roots for registry probes."""
    home = tmp_path / "home"
    home.mkdir()
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    monkeypatch.setenv("HOME", str(home))
    # ntpath.expanduser("~") — which the registry's home
    # globs and workspace layout resolve through — ignores
    # HOME entirely and reads USERPROFILE, so the fake home
    # must be planted there too or the workspace candidates
    # resolve under the real profile on Windows (run #63).
    # Inert on POSIX, where expanduser reads HOME.
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv(
        "PATH", str(fakebin) + os.pathsep + "/usr/bin:/bin")
    monkeypatch.delenv("NAR_JADX_JAR", raising=False)
    monkeypatch.delenv("NAR_JADX_PATH", raising=False)
    return home, fakebin


def test_jadx_jar_route_registered():
    entry = _jadx_entry()
    assert entry.get("jar_env_var") == "NAR_JADX_JAR"
    assert entry.get("identity", {}).get("version_pattern")


def test_fake_jadx_binary_rejected(fake_env):
    _home, fakebin = fake_env
    _shim(fakebin / "jadx",
          "echo 'totally-not-jadx 9.9.9'\n")
    result = registry.probe(_jadx_entry())
    assert result["available"] is False
    assert result["note"].startswith("tool_identity_mismatch")
    rej = result["identity_rejections"]
    assert rej[0]["reported"] == "totally-not-jadx 9.9.9"
    assert rej[0]["reason"] == "tool_identity_mismatch"


def test_fake_jadx_falls_through_to_workspace(fake_env):
    home, fakebin = fake_env
    _shim(fakebin / "jadx",
          "echo 'totally-not-jadx 9.9.9'\n")
    good = _shim(home / "workspace" / "tools" / "jadx-cli"
                 / "bin" / "jadx", "echo '1.5.1'\n")
    result = registry.probe(_jadx_entry())
    assert result["available"] is True
    assert _norm(result["path"]) == _norm(good)
    assert result["version"] == "1.5.1"
    assert result["identity"] == "validated"
    assert len(result["identity_rejections"]) == 1


def test_wrapper_jar_rejected_and_falls_through(
        fake_env, monkeypatch, tmp_path):
    home, fakebin = fake_env
    # A fake java that answers per-jar: the wrapper reports
    # another product; the real-shaped jar reports a jadx
    # version.
    _java_shim(fakebin / "java")
    wrapper = tmp_path / "wrapper.jar"
    wrapper.write_bytes(b"not a real jar")
    monkeypatch.setenv("NAR_JADX_JAR", str(wrapper))
    real_jar = home / "workspace" / "tools" / "jadx-cli" \
        / "lib" / "jadx-1.5.3-all.jar"
    real_jar.parent.mkdir(parents=True)
    real_jar.write_bytes(b"jar bytes")
    result = registry.probe(_jadx_entry())
    assert result["available"] is True
    assert _norm(result["path"]) == _norm("jar:" + str(real_jar))
    assert result["version"] == "1.5.3"
    assert result["identity"] == "validated"
    rej = result["identity_rejections"]
    assert rej[0]["reported"] == "WRAPPER-JAR-NOT-JADX"
    assert registry.launch_prefix(result)[1] == "-jar"


def test_real_shape_jadx_binary_accepted(fake_env):
    _home, fakebin = fake_env
    _shim(fakebin / "jadx", "echo '1.5.1'\n")
    result = registry.probe(_jadx_entry())
    assert result["available"] is True
    assert result["version"] == "1.5.1"
    assert result["identity"] == "validated"
    assert not result.get("identity_rejections")


def test_identity_mismatch_classifies_wrong_version():
    kind = failures.classify_unavailable(
        "tool_identity_mismatch: no candidate identified "
        "as jadx (x reported 'WRAPPER-JAR-NOT-JADX')")
    assert kind is failures.FailureKind.WRONG_VERSION


def test_run_adapter_names_identity_mismatch(fake_env):
    _home, fakebin = fake_env
    _shim(fakebin / "jadx",
          "echo 'totally-not-jadx 9.9.9'\n")
    result = nar_dex.jadx_index(
        "/nonexistent.apk", str(fake_env[0] / "out"))
    assert "error" in result
    assert "tool_identity_mismatch" in result["error"]
    assert result["identity_rejections"][0][
        "reported"] == "totally-not-jadx 9.9.9"


# ------------------------------------------------------------------
# Area 2 — decompile outcome record
# ------------------------------------------------------------------

class _StubNarDex:
    def __init__(self, result):
        self._result = result

    def jadx_index(self, target, out_dir):
        return dict(self._result)


def test_rung_jadx_identity_validated_no_output(monkeypatch):
    stub = _StubNarDex({
        "class_files": 0, "decompile_errors": 0,
        "exit_code": 0, "tool_path": "jadx",
        "tool_version": "1.5.1", "tool_identity": "validated"})
    monkeypatch.setattr(chains_mod, "_nar_dex_mod", stub)
    run = chains_mod._rung_jadx("target.apk", "out")
    raw = run({})
    assert raw["status"] == "failed"
    assert "identity validated" in raw["detail"]
    assert "produced no Java sources" in raw["detail"]
    assert raw["tool_identity"] == "validated"
    # And the Fallback Record carries both, distinctly.
    spec = {"name": "jadx", "fidelity": "source-approximate",
            "budget_s": 60, "run": run}
    record = chains_mod.run_chain("java-decompile", [spec])
    attempt = record["attempts"][0]
    assert attempt["tool_identity"] == "validated"
    assert "identity validated" in attempt["reason"]


def test_rung_jadx_unvalidated_no_output_keeps_old_wording(
        monkeypatch):
    stub = _StubNarDex({
        "class_files": 0, "decompile_errors": 0,
        "exit_code": 0, "tool_path": "jadx",
        "tool_version": None})
    monkeypatch.setattr(chains_mod, "_nar_dex_mod", stub)
    raw = chains_mod._rung_jadx("target.apk", "out")({})
    assert raw["detail"] == "jadx produced no classes"
    assert "tool_identity" not in raw


# ------------------------------------------------------------------
# Area 2 — doctor identity checks (executed)
# ------------------------------------------------------------------

def _run_doctor(env):
    proc = subprocess.run(
        ["bash", str(SCRIPTS / "nar-doctor.sh"), "--json"],
        capture_output=True, text=True, timeout=600, env=env)
    doc = json.loads(proc.stdout)
    return next(c for c in doc["checks"] if c["name"] == "jadx")


@pytest.mark.skipif(not os.path.exists("/bin/bash"),
                    reason="doctor is a bash script")
def test_doctor_rejects_fake_binary_and_wrapper_jar(
        tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    fakebin = tmp_path / "fakebin"
    _shim(fakebin / "jadx",
          "echo 'totally-not-jadx 9.9.9'\n")
    wrapper = tmp_path / "wrapper.jar"
    wrapper.write_bytes(b"not a real jar")
    env = {"HOME": str(home),
           "PATH": str(fakebin) + os.pathsep + "/usr/bin:/bin",
           "NAR_JADX_JAR": str(wrapper)}
    check = _run_doctor(env)
    assert check["status"] == "warning"
    assert "tool_identity_mismatch" in check["detail"]
    assert "totally-not-jadx 9.9.9" in check["detail"]


@pytest.mark.skipif(not os.path.exists("/bin/bash"),
                    reason="doctor is a bash script")
def test_doctor_accepts_real_shape_jadx(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    fakebin = tmp_path / "fakebin"
    _shim(fakebin / "jadx", "echo '1.5.1'\n")
    env = {"HOME": str(home),
           "PATH": str(fakebin) + os.pathsep + "/usr/bin:/bin"}
    check = _run_doctor(env)
    assert check["status"] == "ok"
    assert "1.5.1" in check["detail"]
