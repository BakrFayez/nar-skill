"""Unit tests: the script & bytecode universe (Part 5).

Covers narlib.scriptparse + nar-script.py + the nar-ask
scripts intent. Fixtures are synthetic with invented names
only, except where a real toolchain exists on the box:

- a REAL .pyc compiled with the running python3
  (py_compile) — the census is asserted against the known
  source shape, and a second fixture proves the walker
  never executes the payload (a module that would write a
  sentinel file if it were ever imported/run);
- a REAL .wasm built with wat2wasm (wabt) when the tool
  is present — skipped otherwise; a hand-built empty
  module pins the parser without the toolchain;
- Lua chunks are HAND-CONSTRUCTED (no lua/luajit
  interpreter exists on this box): a minimal valid 5.1
  chunk and 5.3 chunk following the documented lundump
  layout, plus a LuaJIT BCDump framing fixture;
- a Hermes header fixture in the documented
  BytecodeFileHeader layout (the real-target wiring is
  asserted separately on the retained React Native
  fixture when present);
- hostile .pyc fixtures: a tuple-count marshal bomb and
  a nesting bomb, both refused with a named failure,
  fast, with no execution.

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import importlib.util
import io
import json
import os
import py_compile
import shutil
import struct
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from narlib import evidence  # noqa: E402
from narlib import scriptparse as sp  # noqa: E402


def _load_tool(name, fname):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "scripts" / fname)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


nar_script = _load_tool("nar_script_tool", "nar-script.py")


def _schema(name):
    with open(ROOT / "schemas" / name, encoding="utf-8") as fh:
        return json.load(fh)


# ------------------------------------------------------------------
# Fixture builders (invented names only)
# ------------------------------------------------------------------

def lua51_chunk():
    """Hand-constructed minimal valid Lua 5.1 chunk:
    top-level prototype with one nested prototype, three
    constants (nil, number, string) at the top and one
    string constant in the child. No lua interpreter
    exists on this box, so the chunk is built byte by
    byte from the documented 5.1 lundump layout."""
    out = bytearray(b"\x1bLua")
    out += bytes([0x51, 0, 1, 4, 4, 4, 8, 0])  # ver, fmt, endian,
    # sizeof(int)=4, sizeof(size_t)=4, sizeof(instr)=4,
    # sizeof(number)=8, integral=0

    def s(txt):
        if txt is None:
            return struct.pack("<I", 0)
        b = txt.encode()
        return struct.pack("<I", len(b) + 1) + b + b"\x00"

    def child():
        p = bytearray()
        p += s(None)
        p += struct.pack("<ii", 1, 3)
        p += bytes([0, 1, 0, 3])          # nups, params, vararg, stack
        p += struct.pack("<i", 1) + b"\x00" * 4      # code
        p += struct.pack("<i", 1) + bytes([4]) + s("world")
        p += struct.pack("<i", 0)                    # protos
        p += struct.pack("<i", 1) + struct.pack("<i", 1)  # lineinfo
        p += struct.pack("<i", 0)                    # locvars
        p += struct.pack("<i", 0)                    # upvalue names
        return bytes(p)

    p = bytearray()
    p += s("@main.lua")
    p += struct.pack("<ii", 0, 0)
    p += bytes([1, 0, 2, 2])
    p += struct.pack("<i", 2) + b"\x00" * 8          # code
    p += struct.pack("<i", 3) + bytes([0]) \
        + bytes([3]) + struct.pack("<d", 1.5) \
        + bytes([4]) + s("hello")                    # constants
    p += struct.pack("<i", 1) + child()              # protos
    p += struct.pack("<i", 2) + struct.pack("<ii", 0, 1)  # lineinfo
    p += struct.pack("<i", 1) + s("x") + struct.pack("<ii", 0, 2)
    p += struct.pack("<i", 1) + s("_ENV")            # upvalue names
    return bytes(out) + bytes(p)


def lua53_chunk():
    """Hand-constructed minimal valid Lua 5.3 chunk (same
    provenance note as the 5.1 fixture)."""
    out = bytearray(b"\x1bLua")
    out += bytes([0x53, 0]) + b"\x19\x93\r\n\x1a\n"
    out += bytes([4, 8, 4, 8, 8])         # int, size_t, instr,
    # integer, number sizes
    out += struct.pack("<q", 0x5678) + struct.pack("<d", 370.5)

    def s(txt):
        if txt is None:
            return struct.pack("<Q", 0)
        b = txt.encode()
        return struct.pack("<Q", len(b) + 1) + b

    p = bytearray()
    p += s("@main")
    p += struct.pack("<ii", 0, 0) + bytes([0, 2, 2])
    p += struct.pack("<i", 1) + b"\x00" * 4          # code
    p += struct.pack("<i", 2) + bytes([0x13]) \
        + struct.pack("<q", 42) + bytes([0x04]) + s("hello")
    p += struct.pack("<i", 1) + bytes([1, 0])        # upvalues
    p += struct.pack("<i", 0)                        # protos
    p += struct.pack("<i", 0)                        # lineinfo
    p += struct.pack("<i", 0)                        # locvars
    p += struct.pack("<i", 1) + s("_ENV")            # upvalue names
    return bytes(out) + bytes(p)


def luajit_dump():
    out = bytearray(b"\x1bLJ") + bytes([2, 0])  # version 2, flags 0
    out += bytes([8]) + b"main.lua"             # chunk name
    out += bytes([4]) + b"\x00" * 4             # prototype 1
    out += bytes([3]) + b"\x00" * 3             # prototype 2
    out += bytes([0])                           # end marker
    return bytes(out)


def gdsc3_stream():
    out = bytearray(b"GDSC")
    out += struct.pack("<IIIII", 13, 2, 3, 4, 99)
    for name in (b"name", b"player"):
        enc = bytes(b ^ 0xB6 for b in name + b"\x00")
        out += struct.pack("<I", len(name) + 1) + enc
    return bytes(out)


def gdsc4_stream():
    out = bytearray(b"GDSC")
    out += struct.pack("<IIIIII", 101, 0, 1, 2, 3, 42)
    # identifier "hi": 2 UTF-32 code units, bytes XOR 0xB6
    enc = bytearray()
    for ch in "hi":
        enc += bytes(b ^ 0xB6
                     for b in struct.pack("<I", ord(ch)))
    out += struct.pack("<I", 2) + enc
    return bytes(out)


def hermes_header():
    out = bytearray(128)
    out[0:8] = bytes.fromhex("c61fbc03c103191f")
    struct.pack_into("<I", out, 8, 96)          # bytecode version
    struct.pack_into("<10I", out, 32,
                     9000, 0, 7, 2, 11, 13, 0, 100, 0, 0)
    return bytes(out)


def amx_header():
    return struct.pack("<I H B B h h i i i i i i i i i i i",
                       56, 0xF1E0, 8, 10, 0, 8, 56, 100, 200,
                       4096, 0, 100, 116, 132, 140, 156, 164)


def _write_apk(path, members):
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)


# ------------------------------------------------------------------
# Lua / LuaJIT
# ------------------------------------------------------------------

def test_lua51_chunk_walk_counts_and_strings():
    rec = sp.parse_lua(lua51_chunk())
    assert rec["status"] == "supported"
    assert rec["facts"]["version"] == "5.1"
    assert rec["facts"]["function_count"] == 2
    assert rec["facts"]["string_constant_count"] == 2
    assert rec["facts"]["string_pool_sample"] == ["hello", "world"]


def test_lua53_chunk_walk():
    rec = sp.parse_lua(lua53_chunk())
    assert rec["status"] == "supported"
    assert rec["facts"]["version"] == "5.3"
    assert rec["facts"]["function_count"] == 1
    assert rec["facts"]["string_pool_sample"] == ["hello"]


def test_luajit_framing_walk():
    rec = sp.parse_lua(luajit_dump())
    assert rec["status"] == "supported"
    assert rec["facts"]["variant"] == "luajit"
    assert rec["facts"]["version"] == 2
    assert rec["facts"]["chunk_name"] == "main.lua"
    assert rec["facts"]["function_count"] == 2
    assert rec["facts"]["string_constant_count"] is None


def test_lua_encrypted_chunk_identified_not_decoded():
    data = bytearray(lua51_chunk())
    data[5] = 9  # non-official format byte: the obfuscated
    # / encrypted presentation
    rec = sp.parse_lua(bytes(data))
    assert rec["status"] == "identified_only"
    assert "encrypted or obfuscated" in rec["reason"]


def test_lua_truncated_chunk_identified():
    rec = sp.parse_lua(lua51_chunk()[:30])
    assert rec["status"] == "identified_only"
    assert "failed structural validation" in rec["reason"]


# ------------------------------------------------------------------
# GDScript
# ------------------------------------------------------------------

def test_gdscript_godot3_counts_and_identifiers():
    rec = sp.parse_gdscript(gdsc3_stream())
    assert rec["status"] == "supported"
    assert rec["facts"]["version"] == 13
    assert rec["facts"]["identifier_count"] == 2
    assert rec["facts"]["constant_count"] == 3
    assert rec["facts"]["token_count"] == 99
    assert rec["facts"]["identifiers_sample"] == ["name", "player"]


def test_gdscript_godot4_uncompressed():
    rec = sp.parse_gdscript(gdsc4_stream())
    assert rec["status"] == "supported"
    assert rec["facts"]["version"] == 101
    assert rec["facts"]["token_count"] == 42
    assert rec["facts"]["identifiers_sample"] == ["hi"]


def test_gdscript_godot4_zstd_identified_only():
    out = bytearray(b"GDSC") + struct.pack("<II", 101, 500)
    rec = sp.parse_gdscript(bytes(out) + b"\x00" * 16)
    assert rec["status"] == "identified_only"
    assert "Zstd" in rec["reason"]


def test_gdscript_encrypted_named_never_decoded():
    rec = sp.parse_gdscript(b"GDEC" + b"\x00" * 40)
    assert rec["status"] == "identified_only"
    assert rec["facts"]["encrypted"] is True
    assert "never decoded" in rec["reason"]


# ------------------------------------------------------------------
# WebAssembly
# ------------------------------------------------------------------

def _wat2wasm():
    cand = shutil.which("wat2wasm") or str(
        Path.home() / "workspace" / "tools" / "rea-engines"
        / "wabt" / "bin" / "wat2wasm")
    return cand if os.path.isfile(cand) else None


def test_wasm_empty_module_supported():
    rec = sp.parse_wasm(b"\x00asm\x01\x00\x00\x00")
    assert rec["status"] == "supported"
    assert rec["facts"]["function_count"] == 0
    assert rec["facts"]["sections"] == []


def test_wasm_bad_magic_identified():
    rec = sp.parse_wasm(b"NOPE" + b"\x00" * 20)
    assert rec["status"] == "identified_only"


@pytest.mark.skipif(_wat2wasm() is None,
                    reason="wat2wasm (wabt) not present on this box")
def test_wasm_real_module_from_wat(tmp_path):
    wat = tmp_path / "mod.wat"
    wat.write_text(
        "(module\n"
        "  (import \"env\" \"log\" (func $log (param i32)))\n"
        "  (memory (export \"mem\") 1 2)\n"
        "  (global $g (mut i32) (i32.const 7))\n"
        "  (func (export \"main\") (result i32) i32.const 42)\n"
        "  (func $helper (param i32) (result i32)"
        " local.get 0))\n")
    out = tmp_path / "mod.wasm"
    subprocess.run([_wat2wasm(), str(wat), "-o", str(out)],
                   check=True, capture_output=True, timeout=60)
    rec = sp.parse_wasm(out.read_bytes())
    assert rec["status"] == "supported"
    f = rec["facts"]
    assert f["type_count"] == 3
    assert f["import_count"] == 1
    assert f["imports_by_kind"] == {"function": 1}
    assert f["function_count"] == 2
    assert f["total_functions"] == 3
    assert f["memory_count"] == 1
    assert f["memories"] == [{"flags": 1, "initial_pages": 1,
                              "max_pages": 2}]
    assert f["global_count"] == 1
    assert f["export_count"] == 2
    assert f["exports_by_kind"] == {"memory": 1, "function": 1}
    assert f["export_names_sample"] == ["mem", "main"]
    assert f["code_count"] == 2


# ------------------------------------------------------------------
# Hermes (header layout fixture; wiring proven at scan level)
# ------------------------------------------------------------------

def test_hermes_header_via_wired_parser():
    rn = nar_script._rn()
    header = rn.parse_hermes_header(hermes_header())
    assert header["bytecode_version"] == 96
    assert header["function_count"] == 7
    assert header["string_count"] == 13
    assert header["identifier_count"] == 11


# ------------------------------------------------------------------
# Python .pyc — real compile, structural census, hostile refusal
# ------------------------------------------------------------------

_SAMPLE_SRC = ("def alpha(x):\n"
               "    def beta(y):\n"
               "        return y + 1\n"
               "    return beta(x)\n"
               "VALUE = alpha(1)\n")


def _compile(tmp_path, source, stem):
    src = tmp_path / (stem + ".py")
    src.write_text(source)
    pyc = tmp_path / (stem + ".pyc")
    py_compile.compile(str(src), cfile=str(pyc), doraise=True)
    return pyc.read_bytes()


def test_pyc_real_compile_census(tmp_path):
    data = _compile(tmp_path, _SAMPLE_SRC, "sample_mod")
    rec = sp.parse_pyc(data)
    assert rec["status"] == "supported"
    assert rec["facts"]["cpython_version"] == \
        "%d.%d" % sys.version_info[:2]
    assert rec["facts"]["code_object_count"] == 3
    assert rec["facts"]["function_count"] == 2
    assert set(rec["facts"]["code_names_sample"]) == \
        {"<module>", "alpha", "beta"}


def test_pyc_walker_never_executes(tmp_path):
    sentinel = tmp_path / "sentinel.txt"
    source = "open(%r, 'w').write('pwned')\n" % str(sentinel)
    data = _compile(tmp_path, source, "evil_mod")
    rec = sp.parse_pyc(data)
    assert rec["status"] == "supported"
    assert rec["facts"]["code_object_count"] == 1
    assert not sentinel.exists()


def test_pyc_unknown_magic_identified_only():
    rec = sp.parse_pyc(b"\x99\x99\r\n" + b"\x00" * 28)
    assert rec["status"] == "identified_only"
    assert rec["facts"]["cpython_version"] is None
    assert "unknown CPython magic" in rec["reason"]


def _hostile_pyc(payload):
    import importlib.util
    return (importlib.util.MAGIC_NUMBER
            + struct.pack("<III", 0, 0, 0) + payload)


def test_pyc_marshal_count_bomb_refused_fast():
    payload = b"\xa8" + struct.pack("<i", 0x7FFFFFFF)  # tuple
    start = time.time()
    rec = sp.parse_pyc(_hostile_pyc(payload))
    elapsed = time.time() - start
    assert rec["status"] == "identified_only"
    assert "marshal_bomb_refused" in rec["reason"]
    assert elapsed < 5


def test_pyc_marshal_depth_bomb_refused_fast():
    payload = (b"\xdb" + struct.pack("<i", 1)) * 500 + b"N"
    start = time.time()
    rec = sp.parse_pyc(_hostile_pyc(payload))
    elapsed = time.time() - start
    assert rec["status"] == "identified_only"
    assert "marshal_bomb_refused" in rec["reason"]
    assert elapsed < 5


def test_pyc_source_has_no_marshal_loads():
    text = (ROOT / "scripts" / "narlib" / "scriptparse.py") \
        .read_text(encoding="utf-8")
    assert "marshal.loads(" not in text
    assert "import marshal" not in text


# ------------------------------------------------------------------
# JavaScript bundles
# ------------------------------------------------------------------

def test_javascript_webpack_bundle_facts():
    body = ('/***/ "./src/a.js":\n/***/ (function() {})\n'
            '/***/ "./src/b.js":\n/***/ (function() {})\n'
            '//# sourceMappingURL=main.js.map\n')
    rec = sp.parse_javascript(
        body.encode(), sibling_names=["assets/main.js.map"])
    f = rec["facts"]
    assert rec["status"] == "supported"
    assert f["bundled"] is True
    assert f["module_count_estimate"] == 2
    assert "heuristic" in f["module_count_basis"]
    assert f["source_map_ref"] == "main.js.map"
    assert f["source_map_file_present"] is True
    assert f["minified"] is False


def test_javascript_minified_heuristic_labelled():
    rec = sp.parse_javascript(b"var x=" + b"1," * 300)
    assert rec["facts"]["minified"] is True
    assert "heuristic" in rec["facts"]["minified_basis"]


# ------------------------------------------------------------------
# .NET CIL (builder shared with test_dotnetmeta)
# ------------------------------------------------------------------

def test_dotnet_cil_via_dotnetmeta(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "test_dotnetmeta_helpers",
        ROOT / "tests" / "unit" / "test_dotnetmeta.py")
    helpers = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helpers)
    path = helpers.build_assembly(tmp_path)
    data = Path(path).read_bytes()
    rec = sp.parse_dotnet(data, str(tmp_path / "member.dll"))
    assert rec["status"] == "supported"
    assert rec["facts"]["typedef_count"] == 2
    assert rec["facts"]["methoddef_count"] == 5
    assert rec["facts"]["namespace_count"] == 2
    assert rec["facts"]["obfuscation_markers"]["suspected"] is False


def test_dotnet_non_cli_identified(tmp_path):
    rec = sp.parse_dotnet(b"not a PE at all",
                          str(tmp_path / "member.dll"))
    assert rec["status"] == "identified_only"
    assert "not a parseable CLI assembly" in rec["reason"]


# ------------------------------------------------------------------
# Dart / kernel, Squirrel, Pawn, AngelScript, custom VM
# ------------------------------------------------------------------

def test_kernel_blob_header_facts():
    data = b"\x90\xab\xcd\xef" + struct.pack("<I", 110) \
        + b"\x00" * 16
    rec = sp.parse_kernel_blob(data)
    assert rec["status"] == "identified_only"
    assert rec["facts"]["kernel_format_version"] == 110
    assert rec["facts"]["class_count"] is None
    assert "null rather than invented" in rec["reason"]


def test_dart_snapshot_facts_null_counts():
    rec = sp.dart_snapshot_facts(
        b"", dart_vm_version="3.5.0", flutter_version="3.24.0",
        markers=["_kDartVmSnapshotData"])
    assert rec["facts"]["dart_vm_version"] == "3.5.0"
    assert rec["facts"]["aot_snapshot"] is True
    assert rec["facts"]["class_count"] is None


def test_squirrel_compiled_stream_identified():
    data = b"\xfa\xfaRIQS" + b"TRAPTRAP" + b"\x00" * 8 + b"LIAT"
    rec = sp.parse_squirrel(data)
    assert rec["status"] == "identified_only"
    assert rec["facts"]["compiled"] is True
    assert rec["facts"]["part_marker_count"] == 2
    assert rec["facts"]["tail_marker_present"] is True


def test_squirrel_source_census():
    rec = sp.parse_squirrel(
        b"function main() { return 1; }\nfunction helper() {}\n")
    assert rec["facts"]["compiled"] is False
    assert rec["facts"]["function_like_count"] == 2


def test_pawn_amx_table_counts():
    rec = sp.parse_pawn_amx(amx_header())
    assert rec["status"] == "supported"
    f = rec["facts"]
    assert f["public_count"] == 2
    assert f["native_count"] == 2
    assert f["library_count"] == 1
    assert f["pubvar_count"] == 2
    assert f["tag_count"] == 1


def test_angelscript_source_identified_only():
    rec = sp.parse_angelscript_source(
        b"void main() { int x = 1; }\n")
    assert rec["status"] == "identified_only"
    assert "no standard compiled file format" in \
        rec["facts"]["function_count_basis"]


def test_custom_vm_named_never_decoded():
    rec = sp.custom_vm_record("SpiderMonkey bytecode (.jsc)",
                              "synthetic detail")
    assert rec["status"] == "identified_only"
    assert "never decoded" in rec["reason"]


# ------------------------------------------------------------------
# Scan level: one APK carrying every family + absent control
# ------------------------------------------------------------------

def _demo_apk(tmp_path, pyc_bytes):
    members = {
        "AndroidManifest.xml": b"\x03\x00\x08\x00",
        "assets/index.android.bundle": hermes_header(),
        "assets/main.js": b"/***/ \"./a.js\":\n" * 2
        + b"//# sourceMappingURL=main.js.map\n",
        "assets/main.js.map": b"{}",
        "assets/mod.wasm": b"\x00asm\x01\x00\x00\x00",
        "assets/game.luac": lua51_chunk(),
        "assets/script.gdc": gdsc3_stream(),
        "assets/mod.pyc": pyc_bytes,
        "assets/kernel_blob.bin": b"\x90\xab\xcd\xef"
        + struct.pack("<I", 110) + b"\x00" * 8,
        "assets/compiled.cnut": b"\xfa\xfaRIQS" + b"TRAP"
        + b"\x00" * 4,
        "assets/game.amx": amx_header(),
        "assets/plugin.jsc": b"\x00" * 32,
        "assets/notes.as": b"void main() {}\n",
        "lib/arm64-v8a/libapp.so": b"\x7fELF" + b"\x00" * 64
        + b"_kDartVmSnapshotData\x00_kDartIsolateSnapshotData"
        + b"\x003.24.0 (stable)\x00",
        "lib/arm64-v8a/libflutter.so": b"\x7fELF" + b"\x00" * 32
        + b"Dart VM version: 3.5.0\x00",
    }
    apk = tmp_path / "scriptdemo.apk"
    _write_apk(apk, members)
    return apk


def test_scan_target_all_families(tmp_path):
    pyc_bytes = _compile(tmp_path, _SAMPLE_SRC, "scan_mod")
    apk = _demo_apk(tmp_path, pyc_bytes)
    report = nar_script.scan_target(str(apk))
    assert report["verdict"] == "present"
    assert evidence.validate(report, _schema("script.schema.json")) == []
    by_format = {}
    for rec in report["files"]:
        by_format.setdefault(rec["format"], []).append(rec)
    assert by_format["hermes"][0]["facts"]["function_count"] == 7
    assert by_format["hermes"][0]["status"] == "supported"
    assert by_format["wasm"][0]["status"] == "supported"
    assert by_format["lua"][0]["facts"]["function_count"] == 2
    assert by_format["gdscript"][0]["facts"]["token_count"] == 99
    assert by_format["pyc"][0]["facts"]["code_object_count"] == 3
    js = by_format["javascript"][0]
    assert js["facts"]["source_map_file_present"] is True
    assert by_format["pawn"][0]["facts"]["public_count"] == 2
    assert by_format["squirrel"][0]["status"] == "identified_only"
    assert by_format["angelscript"][0]["status"] == "identified_only"
    assert by_format["custom-vm"][0]["status"] == "identified_only"
    dart = by_format["dart-snapshot"]
    snap = [r for r in dart if r["file"].endswith("libapp.so")][0]
    assert snap["facts"]["dart_vm_version"] == "3.5.0"
    assert snap["facts"]["flutter_version"] == "3.24.0"
    assert snap["facts"]["aot_snapshot"] is True
    assert snap["facts"]["kernel_blob_present"] is True
    assert snap["facts"]["class_count"] is None
    kernel = [r for r in dart
              if r["file"].endswith("kernel_blob.bin")][0]
    assert kernel["facts"]["kernel_format_version"] == 110
    assert report["totals"]["file_count"] == len(report["files"])


def test_scan_absent_target_verdict_and_exit(tmp_path):
    apk = tmp_path / "plain.apk"
    _write_apk(apk, {"AndroidManifest.xml": b"\x03\x00\x08\x00"})
    report = nar_script.scan_target(str(apk))
    assert report["verdict"] == "absent"
    assert report["files"] == []
    assert evidence.validate(report, _schema("script.schema.json")) == []
    assert nar_script.main([str(apk), "--json"]) == 0
    assert nar_script.main([str(tmp_path / "missing.apk")]) == 2


def test_scan_loose_wasm_file(tmp_path):
    wasm = tmp_path / "mod.wasm"
    wasm.write_bytes(b"\x00asm\x01\x00\x00\x00")
    report = nar_script.scan_target(str(wasm))
    assert report["verdict"] == "present"
    assert report["files"][0]["format"] == "wasm"


# ------------------------------------------------------------------
# Real-target wiring: the retained React Native + Flutter
# fixtures, when present (generic counts only)
# ------------------------------------------------------------------

_FIXTURES = Path(os.environ.get(
    "NAR_FIXTURES", Path.home() / "workspace"
    / "nar-e2e-fixtures"))


@pytest.mark.skipif(
    not (_FIXTURES / "engines" / "rn.apk").is_file(),
    reason="retained RN fixture not present")
def test_real_hermes_fixture_counts():
    report = nar_script.scan_target(
        str(_FIXTURES / "engines" / "rn.apk"))
    hermes = [r for r in report["files"]
              if r["format"] == "hermes"]
    assert len(hermes) == 1
    facts = hermes[0]["facts"]
    assert hermes[0]["status"] == "supported"
    assert facts["bytecode_version"] == 98
    assert facts["function_count"] == 20566
    assert facts["string_count"] == 164372
    assert facts["identifier_count"] == 25401


@pytest.mark.skipif(
    not (_FIXTURES / "engines" / "flutter.apk").is_file(),
    reason="retained Flutter fixture not present")
def test_real_dart_fixture_facts():
    report = nar_script.scan_target(
        str(_FIXTURES / "engines" / "flutter.apk"))
    dart = [r for r in report["files"]
            if r["format"] == "dart-snapshot"]
    assert dart, "expected a Dart snapshot record"
    snap = dart[0]
    assert snap["facts"]["dart_vm_version"] == "3.12.2"
    assert snap["facts"]["flutter_version"] == "3.44.8"
    assert snap["facts"]["aot_snapshot"] is True
    assert snap["facts"]["class_count"] is None


# ------------------------------------------------------------------
# nar-ask wiring (Part 5): the scripts intent deepens through
# nar-script's runtime detection, like nar-anim / nar-atlas
# ------------------------------------------------------------------

_spec = importlib.util.spec_from_file_location(
    "test_ask_helpers_script",
    ROOT / "tests" / "unit" / "test_ask.py")
_helpers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_helpers)
ask = _helpers.ask
make_mini_case = _helpers.make_mini_case


def test_ask_classifies_script_questions():
    assert ask.classify_intent("What scripts does it ship?") \
        == "scripts"
    assert ask.classify_intent(
        "Does it use Lua or Hermes bytecode?") == "scripts"
    assert ask.classify_intent(
        "Are there any WebAssembly modules or source maps?") \
        == "scripts"


def test_ask_scripts_deepens_via_nar_script(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    target = tmp_path / "target.apk"
    make_mini_case(str(case_dir), str(target))
    pyc_bytes = _compile(tmp_path, _SAMPLE_SRC, "ask_mod")
    _write_apk(target, {
        "AndroidManifest.xml": b"\x03\x00\x08\x00",
        "assets/game.luac": lua51_chunk(),
        "assets/mod.pyc": pyc_bytes})
    case = ask.Case(str(case_dir))
    doc = ask.build_scripts(
        "What scripts does it ship?", case,
        {"target": str(target), "subject": None,
         "second": None, "extra_targets": []})
    assert doc["intent"] == "scripts"
    assert doc["confidence"] == "strongly-indicated"
    assert "nar-script" in doc["answer"]
    joined = " ".join(doc["evidence"])
    assert "function_count=2" in joined
    assert "code_object_count=3" in joined
    assert "never as source" in doc["boundary"]


def test_ask_scripts_fallback_when_no_script_files(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    target = tmp_path / "target.bin"
    make_mini_case(str(case_dir), str(target))
    case = ask.Case(str(case_dir))
    doc = ask.build_scripts(
        "What scripts does it ship?", case,
        {"target": str(target), "subject": None,
         "second": None, "extra_targets": []})
    assert doc["intent"] == "scripts"
    assert doc["confidence"] == "inferred"
    assert any("coverage script_formats" in e
               for e in doc["evidence"])
    assert "no decodable script files" in doc["boundary"]
