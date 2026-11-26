"""Phase 2 fix-round regression tests: script domain.

Synthetic targets only (invented names, hand-built bytes):
binary containers and HTML content must never be claimed
as JavaScript, genuine JavaScript must keep being claimed,
IL2CPP metadata must be identified, split/container
targets must never produce a silently empty report, and
Python source members must be reported.
"""
import importlib.util
import json
import struct
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from narlib import evidence  # noqa: E402


def _load_tool(name, fname):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "scripts" / fname)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


nar_script = _load_tool("nar_script_p2", "nar-script.py")
nar_il2cpp = _load_tool("nar_il2cpp_p2", "nar-il2cpp.py")


def _schema(name):
    with open(ROOT / "schemas" / name, encoding="utf-8") as fh:
        return json.load(fh)


def _apk(path, members):
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return str(path)


def _by_file(report):
    return {r["file"]: r for r in report["files"]}


UNITY_BUNDLE = b"UnityFS\x00\x00\x00\x00\x085.x.x\x002022.3.0f1\x00" \
    + b"\x00\x01\x02binary bundle bytes" * 8
HTML_DOC = b"<!DOCTYPE html>\n<html>\n<head><title>x</title>" \
    b"</head>\n<body>not a script</body>\n</html>\n"
REAL_JS = b"function add(a, b) { return a + b; }\n" \
    b"console.log(add(1, 2));\n"


# ------------------------------------------------------------------
# M2-01: container / HTML / binary content is not JavaScript
# ------------------------------------------------------------------

def test_unity_bundle_is_not_javascript(tmp_path):
    target = _apk(tmp_path / "t.apk", {
        "assets/pack.bundle": UNITY_BUNDLE,
        "assets/app.js": REAL_JS})
    report = nar_script.scan_target(target)
    recs = _by_file(report)
    bundle = recs["assets/pack.bundle"]
    assert bundle["format"] != "javascript"
    assert bundle["format"] == "unknown"
    assert bundle["status"] == "identified_only"
    assert "UnityFS" in (bundle["reason"] or "")
    assert recs["assets/app.js"]["format"] == "javascript"
    assert evidence.validate(
        report, _schema("script.schema.json")) == []


def test_html_named_js_is_not_javascript(tmp_path):
    target = _apk(tmp_path / "t.apk", {
        "assets/help/page.js": HTML_DOC,
        "assets/real.js": REAL_JS})
    report = nar_script.scan_target(target)
    recs = _by_file(report)
    assert recs["assets/help/page.js"]["format"] != "javascript"
    assert "HTML" in (recs["assets/help/page.js"]["reason"] or "")
    assert recs["assets/real.js"]["format"] == "javascript"


def _zip_bytes(members):
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def _metadata_bytes(version=29):
    return struct.pack("<II", 0xFAB11BAF, version) + b"\x00" * 64


def _split_xapk(tmp_path, name="set.xapk"):
    base = _zip_bytes([
        ("AndroidManifest.xml", b"<manifest/>"),
        ("assets/bin/Data/Managed/Metadata/global-metadata.dat",
         _metadata_bytes()),
        ("assets/app.js", REAL_JS)])
    config = _zip_bytes([
        ("AndroidManifest.xml", b"<manifest/>"),
        ("lib/arm64-v8a/libil2cpp.so", b"\x7fELF" + b"\x00" * 60)])
    manifest = {"package_name": "com.example.game",
                "split_apks": [
                    {"file": "com.example.game.apk", "id": "base"},
                    {"file": "config.arm64_v8a.apk",
                     "id": "config.arm64_v8a"}]}
    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("manifest.json", json.dumps(manifest))
        zf.writestr("com.example.game.apk", base)
        zf.writestr("config.arm64_v8a.apk", config)
    return str(path)


# ------------------------------------------------------------------
# M2-02: IL2CPP metadata is identified; the il2cpp tool
# searches container targets across their merged members
# ------------------------------------------------------------------

def test_script_identifies_il2cpp_metadata(tmp_path):
    target = _apk(tmp_path / "t.apk", {
        "assets/bin/Data/Managed/Metadata/global-metadata.dat":
            _metadata_bytes(31),
        "lib/arm64-v8a/libil2cpp.so": b"\x7fELF" + b"\x00" * 60,
        "assets/app.js": REAL_JS})
    report = nar_script.scan_target(target)
    recs = _by_file(report)
    rec = recs["assets/bin/Data/Managed/Metadata/global-metadata.dat"]
    assert rec["format"] == "il2cpp-metadata"
    assert rec["status"] == "supported"
    assert rec["facts"]["metadata_magic_ok"] is True
    assert rec["facts"]["metadata_version"] == 31
    assert rec["facts"]["native_library_present"] is True
    assert evidence.validate(
        report, _schema("script.schema.json")) == []


def test_script_il2cpp_metadata_bad_magic_named(tmp_path):
    target = _apk(tmp_path / "t.apk", {
        "assets/bin/Data/Managed/Metadata/global-metadata.dat":
            b"\xde\xad\xbe\xef" + b"\x00" * 64})
    report = nar_script.scan_target(target)
    rec = report["files"][0]
    assert rec["format"] == "il2cpp-metadata"
    assert rec["status"] == "identified_only"
    assert rec["facts"]["metadata_magic_ok"] is False
    assert rec["facts"]["metadata_version"] is None
    assert rec["facts"]["native_library_present"] is False


def test_il2cpp_tool_finds_pair_split_across_container(tmp_path):
    target = _split_xapk(tmp_path)
    out = tmp_path / "out"
    report = nar_il2cpp.analyze(target, str(out))
    assert report["is_il2cpp"] is True
    assert report["metadata"]["version"] == 29
    assert report["metadata"]["magic_ok"] is True
    assert report["binary"]["abi"] == "arm64-v8a"


# ------------------------------------------------------------------
# M2-14: split targets are covered through the merged
# resolution, and an uncoverable target yields a named
# degraded record, never a silently empty "absent"
# ------------------------------------------------------------------

def test_script_covers_metadata_in_split_member(tmp_path):
    # The asset-pack shape in miniature: the metadata
    # lives in a split, the base carries no scripts.
    base = _zip_bytes([("AndroidManifest.xml", b"<manifest/>")])
    pack = _zip_bytes([
        ("assets/bin/Data/Managed/Metadata/global-metadata.dat",
         _metadata_bytes())])
    manifest = {"package_name": "com.example.game",
                "split_apks": [
                    {"file": "com.example.game.apk", "id": "base"},
                    {"file": "asset_pack.apk", "id": "asset_pack"}]}
    path = tmp_path / "set.xapk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("manifest.json", json.dumps(manifest))
        zf.writestr("com.example.game.apk", base)
        zf.writestr("asset_pack.apk", pack)
    report = nar_script.scan_target(str(path))
    formats = {r["format"] for r in report["files"]}
    assert "il2cpp-metadata" in formats
    assert report["verdict"] == "present"


def test_script_unresolvable_container_is_named_not_silent(tmp_path):
    path = tmp_path / "empty.xapk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("readme.txt", b"no archives here")
    report = nar_script.scan_target(str(path))
    assert len(report["files"]) == 1
    rec = report["files"][0]
    assert rec["format"] == "unknown"
    assert rec["status"] == "identified_only"
    assert "could not cover" in (rec["reason"] or "")
    assert evidence.validate(
        report, _schema("script.schema.json")) == []


def test_script_skipped_split_is_named_in_limitations(tmp_path):
    base = _zip_bytes([("AndroidManifest.xml", b"<manifest/>")])
    manifest = {"package_name": "com.example.game",
                "split_apks": [
                    {"file": "com.example.game.apk", "id": "base"},
                    {"file": "missing_split.apk",
                     "id": "missing_split"}]}
    path = tmp_path / "set.xapk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("manifest.json", json.dumps(manifest))
        zf.writestr("com.example.game.apk", base)
    report = nar_script.scan_target(str(path))
    named = [r for r in report["files"]
             if r["file"] == "(target resolution)"]
    assert len(named) == 1
    assert "missing_split.apk" in (named[0]["reason"] or "")
    assert any("missing_split.apk" in line
               for line in report["limitations"])


# ------------------------------------------------------------------
# Python source members are reported
# ------------------------------------------------------------------

def test_python_source_members_reported(tmp_path):
    target = _apk(tmp_path / "t.apk", {
        "assets/tool.py": b"import os\n\nprint('hello')\n",
        "assets/sub/counter.py": b"def count():\n    return 1\n",
        "assets/app.js": REAL_JS})
    report = nar_script.scan_target(target)
    recs = _by_file(report)
    for name in ("assets/tool.py", "assets/sub/counter.py"):
        assert recs[name]["format"] == "python"
        assert recs[name]["facts"]["variant"] == "source"
        assert recs[name]["facts"]["line_count"] >= 2
    assert evidence.validate(
        report, _schema("script.schema.json")) == []


def test_binary_bundle_is_not_javascript(tmp_path):
    target = _apk(tmp_path / "t.apk", {
        "assets/blob.bundle": b"\x7fELF\x00\x01\x02" + b"\x00" * 64,
        "assets/code.bundle": REAL_JS})
    report = nar_script.scan_target(target)
    recs = _by_file(report)
    assert recs["assets/blob.bundle"]["format"] != "javascript"
    # A text .bundle (the React Native shape) stays JavaScript.
    assert recs["assets/code.bundle"]["format"] == "javascript"
