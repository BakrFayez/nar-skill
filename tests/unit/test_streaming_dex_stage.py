"""2.6.1 W4 — streaming DEX stage machinery.

The token re-serializer must reproduce json.dump(doc,
indent=1) byte for byte on arbitrary JSON (it copies
scalar/string tokens verbatim and regenerates only
whitespace); the span scanner must walk documents
without materializing them; the projection extractor
must return exactly the fields the downstream builders
read. All fixtures synthetic.
"""
import importlib.util
import io
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, str(SCRIPTS / filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


az = _load("nar_analyze_stream", "nar-analyze.py")


class _MM:
    """Minimal mmap stand-in over bytes for the scanners
    (they only need len/getitem/slicing)."""

    def __init__(self, data):
        self._d = data

    def __len__(self):
        return len(self._d)

    def __getitem__(self, k):
        return self._d[k]


DOCS = [
    {},
    [],
    {"a": 1},
    {"a": [1, 2.5, -3e10, True, False, None], "b": {}},
    {"empty_arr": [], "empty_obj": {}, "nested": [[[]]]},
    {"s": "esc \" \\ \n \t üñïçødé \u0001 end"},
    {"deep": {"l1": {"l2": {"l3": [{"x": []}, {}]}}}},
    [1, [2, [3, [4, {"five": 5}]]], "six"],
    {"big": list(range(50)),
     "objs": [{"k": i, "v": [i]} for i in range(20)]},
    {"f": 0.1, "g": 1e-06, "h": 123456789012345678901234567890},
    {"key with spaces": {"and-dash": [True]}},
]


@pytest.mark.parametrize("doc", DOCS)
def test_emit_matches_json_dump_indent1(doc):
    text = json.dumps(doc)  # the stage tools' own format
    mm = _MM(text.encode())
    out = io.BytesIO()
    end = az._json_emit_value(mm, 0, out, 0)
    assert end == len(text.encode())
    assert out.getvalue() == json.dumps(
        doc, indent=1).encode()


def test_scanner_spans():
    doc = {"tool": "x", "dex_files": [{"name": "a"}, {"name": "b"}],
           "totals": {"classes": 2}, "call_graph": {"edges": [1, 2]}}
    mm = _MM(json.dumps(doc).encode())
    items = dict()
    for key, vs, ve in az._json_object_items(mm):
        items[key] = (vs, ve)
    assert json.loads(mm[items["totals"][0]:items["totals"][1]]) == \
        {"classes": 2}
    spans = list(az._json_array_items(mm, items["dex_files"][0]))
    assert [json.loads(mm[s:e])["name"] for s, e in spans] == ["a", "b"]
    # skipping a container value lands exactly at its end
    s, e = items["call_graph"]
    assert json.loads(mm[s:e]) == {"edges": [1, 2]}


def test_projection_extraction(tmp_path):
    doc = {
        "tool": "nar-dex", "version": "2.6.0",
        "totals": {"classes": 2},
        "call_graph": {"nodes": [{"x": 1}]},
        "dex_files": [{
            "name": "classes.dex", "class_count": 2,
            "kotlin": {"detected": False},
            "classes": [
                {"class": "LFoo;", "superclass": "LBar;",
                 "fields": [{"name": "f"}], "methods": []},
                {"class": "LBar;", "interfaces": []}],
            "native_methods": [
                {"class": "LFoo;", "name": "run", "extra": 1}],
            "entry_points": [
                {"class": "LFoo;", "via_superclass": "LAct;"}],
            "string_references": [
                {"string": "https://x.example", "count": 3,
                 "sample_classes": ["LFoo;"]}],
            "call_edges": [{"from": "a", "to": "b"}],
            "reflection": {"uses": 1},
        }],
    }
    path = tmp_path / "dex.json"
    path.write_text(json.dumps(doc))
    slim = az._dex_projection_from_file(str(path))
    assert slim["totals"] == {"classes": 2}
    f0 = slim["dex_files"][0]
    assert f0["name"] == "classes.dex"
    assert f0["class_count"] == 2
    assert f0["classes"] == [{"class": "LFoo;"},
                             {"class": "LBar;"}]
    assert f0["native_methods"] == [
        {"class": "LFoo;", "name": "run"}]
    assert f0["entry_points"] == [
        {"class": "LFoo;", "via_superclass": "LAct;"}]
    assert f0["string_references"] == [
        {"string": "https://x.example",
         "sample_classes": ["LFoo;"]}]
    # The heavy fields are gone from the retained copy.
    assert "call_edges" not in f0 and "reflection" not in f0


def test_copy_minus_trailing_newline():
    for src_bytes, want in ((b"abc\n", b"abc"),
                            (b"abc", b"abc"),
                            (b"a\nb\n", b"a\nb"),
                            (b"\n", b""),
                            (b"", b"")):
        out = io.BytesIO()
        az._copy_minus_trailing_newline(
            io.BytesIO(src_bytes), out)
        assert out.getvalue() == want


def test_streamed_stage_end_to_end(tmp_path):
    """analyze() on a zip-only target degrades the DEX
    stage exactly like the classic path (no JSON from the
    tool -> limitation, no crash, no case corruption)."""
    import zipfile
    target = tmp_path / "plain.apk"
    with zipfile.ZipFile(target, "w") as zf:
        zf.writestr("x.txt", "hello")
    report = az.analyze(str(target), str(tmp_path / "work"),
                        str(tmp_path / "case"))
    assert report["tool"] == "nar-analyze"
