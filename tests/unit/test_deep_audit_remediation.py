"""2.6.1 deep-audit remediation — regression tests.

Covers the six W0-S items from the owner's code-level
audit of 2.6.0:

1. ZIP path traversal in nar-analyze extraction
   (contained destinations, hostile containers end to
   end, triage rejection lists).
2. DEX LEB128 hardening (bounds + 5-byte caps; mutated
   class-data / interfaces / proto-parameter offsets
   raise DexError, never IndexError).
3. Unified archive resource budget (nar-rn bundle/DEX
   read caps, nar-il2cpp pair extraction cap,
   nar-analyze extraction caps).
4. Graph provenance (no evidence cited for absent
   documents; merge keeps accumulated evidence).
5. Investigation fact separation (UNVERIFIED findings
   never land in verified_facts; dashboard renders both
   the new shape and tolerates the old one).
6. (Doc freshness — covered by the docs consistency
   suite; nothing to execute here.)

Synthetic fixtures only, like the rest of the unit
suite.
"""
import importlib.util
import io
import json
import os
import struct
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_dex_elf  # noqa: E402
from narlib import evidence, graph, investigation  # noqa: E402
from narlib.dex import Dex, DexError, _sleb128, _uleb128  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, str(SCRIPTS / filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


az = _load("nar_analyze_remed", "nar-analyze.py")
triage = _load("nar_triage_remed", "nar-triage.py")
nar_rn = _load("nar_rn_remed", "nar-rn.py")
nar_il2cpp = _load("nar_il2cpp_remed", "nar-il2cpp.py")
REPORT = _load("nar_report_remed", "nar-report.py")


def _schema(name):
    with open(ROOT / "schemas" / name, encoding="utf-8") as fh:
        return json.load(fh)


def _zip_bytes(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


# ----------------------------------------------------------
# Item 1: ZIP path traversal
# ----------------------------------------------------------

def test_contained_join_rejects_escapes(tmp_path):
    root = str(tmp_path / "case")
    ok = az._contained_join(root, "container", "base.apk")
    assert ok.startswith(os.path.abspath(root) + os.sep)
    for bad in ("../../evil.apk", "/abs.apk",
                "a/../../../evil.apk"):
        with pytest.raises(ValueError):
            az._contained_join(root, "container", bad)
    # One level up from a subdir stays inside root and is
    # contained — only escapes of root itself are refused.
    inner = az._contained_join(root, "container", "../base.apk")
    assert inner == os.path.join(os.path.abspath(root), "base.apk")


def test_extract_entry_refuses_traversal(tmp_path):
    root = tmp_path / "case"
    root.mkdir()
    zpath = tmp_path / "in.zip"
    zpath.write_bytes(_zip_bytes([("base.apk", b"payload")]))
    with zipfile.ZipFile(zpath) as zf:
        with pytest.raises(ValueError):
            az.extract_entry(zf, "base.apk", str(root),
                             "container", "../../../evil.apk")
        dest = az.extract_entry(zf, "base.apk", str(root),
                                "container", "base.apk")
    assert Path(dest).read_bytes() == b"payload"
    assert not (tmp_path / "evil.apk").exists()


def test_triage_rejects_traversal_names(tmp_path):
    target = tmp_path / "container.xapk"
    target.write_bytes(_zip_bytes([
        ("../../outside.apk", b"x"),
        ("/abs.apk", b"x"),
        ("..\\win.apk", b"x"),
        ("base.apk", b"x"),
        ("../main.obb", b"x"),
        ("main.obb", b"x"),
    ]))
    report = triage.triage(str(target))
    assert [a["name"] for a in report["contained_apks"]] == [
        "base.apk"]
    rejected = report["contained_apks_rejected"]
    assert [r["name"] for r in rejected] == [
        "../../outside.apk", "..\\win.apk", "/abs.apk"]
    assert all("travers" in r["reason"] for r in rejected)
    assert [o["name"] for o in report["contained_obbs"]] == [
        "main.obb"]
    assert [r["name"] for r in
            report["contained_obbs_rejected"]] == ["../main.obb"]


def test_hostile_container_end_to_end(tmp_path):
    """A container whose only members carry traversal
    names: nothing is extracted, nothing lands outside
    the work dir, and the rejection is recorded."""
    case_root = tmp_path / "case"
    work = case_root / "work"
    outside = tmp_path / "outside"
    outside.mkdir()
    hostile = tmp_path / "hostile.xapk"
    inner = _zip_bytes([("x", b"y")])
    hostile.write_bytes(_zip_bytes([
        ("../../outside.apk", inner),
        ("/abs.apk", inner),
        ("../main.obb", inner),
    ]))
    report = az.analyze(str(hostile), str(work),
                        str(case_root))
    assert not (outside / "outside.apk").exists()
    assert not (tmp_path / "abs.apk").exists()
    assert not list(outside.iterdir())
    notes = " ".join(report["step_notes"])
    assert "no triageable base APK" in notes
    tri = report["triage"]
    assert tri["contained_apks"] == []
    rejected = {r["name"] for r in
                tri["contained_apks_rejected"]}
    assert rejected == {"../../outside.apk", "/abs.apk"}
    assert {r["name"] for r in
            tri["contained_obbs_rejected"]} == {"../main.obb"}
    # Nothing anywhere under the case tree escaped into
    # a sibling of the work dir either.
    assert not (case_root / "outside.apk").exists()


# ----------------------------------------------------------
# Item 2: DEX LEB128 hardening + offset mutations
# ----------------------------------------------------------

def test_leb128_bounds_and_caps():
    # A full 5-byte encoding decodes (the cap is on
    # length, not on the decoded width).
    assert _uleb128(b"\xff\xff\xff\xff\x7f", 0) == (0x7FFFFFFFF, 5)
    assert _uleb128(b"\xe5\x8e\x26", 0) == (624485, 3)
    assert _sleb128(b"\x7f", 0) == (-1, 1)
    for bad in (b"", b"\x80", b"\x80\x80\x80\x80\x80",
                b"\x80\x80\x80\x80\x80\x80",
                b"\xff\xff\xff\xff\xff\x7f"):
        with pytest.raises(DexError):
            _uleb128(bad, 0)
    for bad in (b"", b"\x80\x80\x80\x80\x80",
                b"\x80\x80\x80\x80\x80\x80"):
        with pytest.raises(DexError):
            _sleb128(bad, 0)


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


def build_dex_with_class():
    """Minimal DEX with one class def, one interface
    type_list, one proto with a parameter type_list and
    one direct method (code_off 0)."""
    strings = [b"LFoo;", b"hello", b"V"]
    header = 0x70
    string_ids_off = header
    sdata_off = string_ids_off + 4 * len(strings)
    data = bytearray()
    offs = []
    for s in strings:
        offs.append(sdata_off + len(data))
        data += _uleb(len(s)) + s + b"\x00"
    type_ids_off = sdata_off + len(data)
    proto_ids_off = type_ids_off + 4 * 3
    method_ids_off = proto_ids_off + 12
    class_defs_off = method_ids_off + 8
    ifaces_off = class_defs_off + 32
    params_off = ifaces_off + 4 + 2 * 2
    class_data_off = params_off + 4 + 2 * 1
    class_data = (_uleb(0) + _uleb(0) + _uleb(1) + _uleb(0)
                  + _uleb(0) + _uleb(1) + _uleb(0))
    file_size = class_data_off + len(class_data)

    out = bytearray(file_size)
    out[0:8] = b"dex\n039\x00"
    struct.pack_into("<I", out, 32, file_size)
    struct.pack_into("<I", out, 36, header)
    struct.pack_into("<I", out, 40, 0x12345678)
    struct.pack_into("<I", out, 56, len(strings))
    struct.pack_into("<I", out, 60, string_ids_off)
    struct.pack_into("<I", out, 64, 3)               # types
    struct.pack_into("<I", out, 68, type_ids_off)
    struct.pack_into("<I", out, 72, 1)               # protos
    struct.pack_into("<I", out, 76, proto_ids_off)
    struct.pack_into("<I", out, 88, 1)               # methods
    struct.pack_into("<I", out, 92, method_ids_off)
    struct.pack_into("<I", out, 96, 1)               # class defs
    struct.pack_into("<I", out, 100, class_defs_off)
    for i, off in enumerate(offs):
        struct.pack_into("<I", out, string_ids_off + 4 * i, off)
    out[sdata_off:sdata_off + len(data)] = data
    for i in range(3):
        struct.pack_into("<I", out, type_ids_off + 4 * i, i)
    # proto: shorty=2 ("V"), return=0, params_off
    struct.pack_into("<III", out, proto_ids_off, 2, 0, params_off)
    # method: class 0, proto 0, name 1
    struct.pack_into("<HHI", out, method_ids_off, 0, 0, 1)
    # class def: class 0, access 1, super -1,
    # interfaces_off, source -1, annotations 0,
    # class_data_off, static_values 0
    struct.pack_into("<IIIIIIII", out, class_defs_off,
                     0, 1, 0xFFFFFFFF, ifaces_off, 0xFFFFFFFF,
                     0, class_data_off, 0)
    struct.pack_into("<IH", out, ifaces_off, 1, 2)
    struct.pack_into("<IH", out, params_off, 1, 2)
    out[class_data_off:class_data_off + len(class_data)] = class_data
    return (bytes(out), class_defs_off, ifaces_off, params_off,
            proto_ids_off)


def test_dex_offset_mutations_raise_dexerror():
    (good, cd_off, if_off, pa_off,
     proto_off) = build_dex_with_class()
    dex = Dex(good)  # control: the unmutated input parses
    defs = dex.class_defs()
    assert defs[0]["interfaces"] == ["V"]
    assert dex.proto_info(0) == ("LFoo;", ["V"])
    assert len(list(dex.class_methods(defs[0]["class_data_off"]))) == 1

    past_eof = 0x00FFFFFF
    m = bytearray(good)
    struct.pack_into("<I", m, cd_off + 24, past_eof)  # class_data_off
    with pytest.raises(DexError):
        list(Dex(bytes(m)).class_methods(past_eof))

    m = bytearray(good)
    struct.pack_into("<I", m, cd_off + 12, past_eof)  # interfaces_off
    with pytest.raises(DexError):
        Dex(bytes(m)).class_defs()

    m = bytearray(good)
    struct.pack_into("<I", m, if_off, 0x00FFFFFF)     # iface size
    with pytest.raises(DexError):
        Dex(bytes(m)).class_defs()

    m = bytearray(good)
    struct.pack_into("<I", m, proto_off + 8, past_eof)  # params_off
    with pytest.raises(DexError):
        Dex(bytes(m)).proto_info(0)

    m = bytearray(good)
    struct.pack_into("<I", m, pa_off, 0x00FFFFFF)     # params size
    with pytest.raises(DexError):
        Dex(bytes(m)).proto_info(0)


def test_dex_overlong_string_leb_is_tolerated():
    good = test_dex_elf.build_dex()
    m = bytearray(good)
    # Point string 0's data at an overlong LEB run
    # appended at the end of the file.
    run_off = len(m)
    m += b"\x80\x80\x80\x80\x80\x80\x80\x00"
    struct.pack_into("<I", m, 0x70, run_off)
    strings = Dex(bytes(m)).strings()
    assert strings[0] == "" and strings[1] == "hello"


# ----------------------------------------------------------
# Item 3: unified archive resource budget
# ----------------------------------------------------------

def test_analyze_extraction_cap_refuses_and_cleans(tmp_path,
                                                   monkeypatch):
    monkeypatch.setattr(az, "MAX_EXTRACT_ENTRY_BYTES", 4)
    az._EXTRACT_BUDGET["used"] = 0
    root = tmp_path / "case"
    root.mkdir()
    zpath = tmp_path / "in.zip"
    zpath.write_bytes(_zip_bytes([("big.apk", b"0123456789")]))
    with zipfile.ZipFile(zpath) as zf:
        with pytest.raises(ValueError):
            az.extract_entry(zf, "big.apk", str(root),
                             "container", "big.apk")
    assert not (root / "container" / "big.apk").exists()


def _rn_apk(tmp_path, bundle=b"var m = require('react-native');\n" * 8,
            with_dex=False):
    entries = [("assets/index.android.bundle", bundle)]
    if with_dex:
        entries.append(("classes.dex", test_dex_elf.build_dex()))
    target = tmp_path / "app.apk"
    target.write_bytes(_zip_bytes(entries))
    return str(target)


def test_rn_bundle_read_cap(tmp_path, monkeypatch):
    target = _rn_apk(tmp_path)
    monkeypatch.setattr(nar_rn, "MAX_BUNDLE_READ_BYTES", 8)
    report = nar_rn.inspect(target, str(tmp_path / "w1"))
    assert report["is_react_native"] is False
    assert "read cap" in report["note"]
    monkeypatch.undo()
    report = nar_rn.inspect(target, str(tmp_path / "w2"))
    assert report["is_react_native"] is True
    assert report["bundle_size_bytes"] > 8


def test_rn_dex_read_cap(tmp_path, monkeypatch):
    target = _rn_apk(tmp_path, with_dex=True)
    monkeypatch.setattr(nar_rn, "MAX_DEX_READ_BYTES", 8)
    report = nar_rn.inspect(target, str(tmp_path / "w"))
    errors = report["bridge_mapping"]["dex_errors"]
    assert len(errors) == 1
    assert errors[0]["dex"] == "classes.dex"
    assert "read cap" in errors[0]["error"]


def test_il2cpp_pair_extraction_cap(tmp_path, monkeypatch):
    target = tmp_path / "game.apk"
    target.write_bytes(_zip_bytes([
        ("assets/bin/Data/Managed/Metadata/global-metadata.dat",
         b"M" * 100),
        ("lib/arm64-v8a/libil2cpp.so", b"S" * 100),
    ]))
    monkeypatch.setattr(nar_il2cpp, "MAX_PAIR_ENTRY_BYTES", 8)
    report = nar_il2cpp.analyze(str(target), str(tmp_path / "o1"))
    assert "extraction refused" in (report.get("error") or "")
    monkeypatch.undo()
    report = nar_il2cpp.analyze(str(target), str(tmp_path / "o2"))
    assert "extraction refused" not in (report.get("error") or "")
    assert report.get("is_il2cpp") is True


# ----------------------------------------------------------
# Item 4: graph provenance
# ----------------------------------------------------------

def _app_node(doc):
    apps = [n for n in doc["nodes"] if n["kind"] == "application"]
    assert len(apps) == 1
    return apps[0]


def test_graph_empty_build_cites_no_absent_document():
    doc = graph.build_graph()
    app = _app_node(doc)
    assert app["status"] == "unidentified"
    assert app["evidence"] == {"stage": "graph",
                               "document": "graph.json",
                               "field_path": "nodes"}
    for node in doc["nodes"]:
        assert node["evidence"]["document"] != "fingerprint.json"
    assert evidence.validate(doc, _schema("graph.schema.json")) == []


def test_graph_app_node_evidence_follows_the_source():
    doc = graph.build_graph(perms_data={
        "package": "com.example.perms",
        "permissions": [], "components": {}})
    app = _app_node(doc)
    assert app["id"] == "application:com.example.perms"
    assert app["evidence"]["document"] == "permissions.json"
    assert app["evidence"]["field_path"] == "package"

    doc = graph.build_graph(fingerprint_data={
        "properties": {"package": {"value": "com.example.fp"}}})
    app = _app_node(doc)
    assert app["evidence"]["document"] == "fingerprint.json"
    assert app["evidence"]["field_path"] == "properties.package"


def test_graph_merge_accumulates_evidence():
    dex = {"dex_files": [
        {"name": "classes.dex",
         "classes": [{"class": "LFoo;"}]},
        {"name": "classes2.dex",
         "classes": [{"class": "LFoo;"}]}]}
    doc = graph.build_graph(dex_data=dex)
    cls = next(n for n in doc["nodes"] if n["kind"] == "class")
    assert cls["evidence"]["field_path"] == \
        "dex_files[0].classes[0].class"
    also = cls.get("evidence_also") or []
    assert [e["field_path"] for e in also] == [
        "dex_files[1].classes[0].class"]
    assert evidence.validate(doc, _schema("graph.schema.json")) == []

    entry = {"url": "https://api.example.com/v1",
             "referencing_classes": ["Lcom/example/App;"],
             "status": "code-referenced",
             "verification_status": "CONFIRMED"}
    doc = graph.build_graph(
        correlations_data={"endpoints": [entry, dict(entry)]})
    edges = [e for e in doc["edges"]
             if e["kind"] == "references_endpoint"]
    assert len(edges) == 1
    also = edges[0].get("evidence_also") or []
    assert [e["field_path"] for e in also] == ["endpoints[1]"]
    assert evidence.validate(doc, _schema("graph.schema.json")) == []


# ----------------------------------------------------------
# Item 5: investigation fact separation
# ----------------------------------------------------------

_SECURITY = {"findings": [
    {"title": "Confirmed issue", "affected_component": "Lcom/a;",
     "evidence": "seen in code",
     "verification_status": "CONFIRMED"},
    {"title": "Unverified issue", "affected_component": "Lcom/b;",
     "evidence": "string only",
     "verification_status": "UNVERIFIED"},
    {"title": "Statusless issue", "affected_component": "Lcom/c;",
     "evidence": "no status recorded"},
]}


def test_investigation_separates_unverified_findings():
    doc = investigation.build_investigation(
        security_data=_SECURITY)
    assert [f["fact"] for f in doc["verified_facts"]] == [
        "Confirmed issue"]
    assert [f["fact"] for f in doc["unverified_findings"]] == [
        "Unverified issue", "Statusless issue"]
    assert doc["counts"]["verified_facts"] == 1
    assert doc["counts"]["unverified_findings"] == 2
    assert evidence.validate(
        doc, _schema("investigation.schema.json")) == []
    summary = investigation.summarize_investigation(doc)
    assert [f["fact"] for f in summary["unverified_findings"]] == [
        "Unverified issue", "Statusless issue"]


def _write_case(root, investigation_doc=None):
    case = root / "case"
    case.mkdir(parents=True)
    (case / "report.json").write_text(json.dumps({
        "identity": {"package": "com.example.x",
                     "version_name": "1.0", "version_code": 1,
                     "app_label": "X", "min_sdk": 24,
                     "target_sdk": 34, "kind": "apk"},
        "target_sha256": "a" * 64, "limitations": []}))
    if investigation_doc is not None:
        (case / "investigation.json").write_text(
            json.dumps(investigation_doc))
    return str(case)


def test_dashboard_renders_both_investigation_shapes(tmp_path):
    doc = investigation.build_investigation(
        security_data=_SECURITY)
    page = REPORT.render(_write_case(tmp_path / "new", doc))
    assert "Unverified findings (reported, not verified)" in page
    assert "Unverified issue" in page
    # The old shape (no unverified_findings key at all)
    # still renders, without the new section.
    old = {k: v for k, v in doc.items()
           if k != "unverified_findings"}
    page = REPORT.render(_write_case(tmp_path / "old", old))
    assert "Unverified findings" not in page
    assert "Confirmed issue" in page
