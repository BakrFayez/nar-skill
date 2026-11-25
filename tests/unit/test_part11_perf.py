"""3.0 Part 11 — performance & size.

Pins:
- nar-dex compact shape is the default; --full restores
  the 2.6.2 document shape (no dex_format marker, no
  method_table, per-method / per-edge objects), and the
  narlib expansion path reads both shapes identically
  (lossless: expanded compact == full).
- The graph / correlations builders produce identical
  documents over compact and full dex data.
- nar-ask / nar-blueprint class reads are shape-blind.
- The nar-analyze streaming writer emits bytes identical
  to json.dump(indent=N) without materializing the text.
- nar analyze --budget-mb aborts at the named
  memory-budget:<stage> boundary (no traceback), records
  resume_boundary in case.json, and a re-run of the same
  case directory resumes to a complete case that passes
  `nar case verify`; a --dex-full case verifies too
  (its cache key binds the shape, and verify derives the
  candidate keys from the case record).
"""
import importlib.util
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from narlib import dex as dexlib  # noqa: E402
from narlib import graph as graphlib  # noqa: E402
from narlib import correlations as corrlib  # noqa: E402

FIXTURES = os.environ.get(
    "NAR_FIXTURES",
    os.path.expanduser("~/workspace/nar-e2e-fixtures"))
DEMO = os.path.join(FIXTURES, "demo", "NarDemo.apk")


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, str(SCRIPTS / filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


nar_dex = _load("nar_dex_p11", "nar-dex.py")
az = _load("nar_analyze_p11", "nar-analyze.py")


def _run(script, args, timeout=900):
    return subprocess.run(
        [sys.executable, str(SCRIPTS / script)] + args,
        capture_output=True, text=True, timeout=timeout)


def _demo_dex_docs(tmp_path):
    if not os.path.isfile(DEMO):
        pytest.skip("demo fixture absent")
    full = nar_dex.analyze(DEMO, compact=False)
    compact = nar_dex.analyze(DEMO, compact=True)
    return full, compact


def test_compact_default_and_full_shape_restored(tmp_path):
    full, compact = _demo_dex_docs(tmp_path)
    assert "dex_format" not in full
    assert compact["dex_format"] == "compact"
    assert dexlib.dex_doc_format(full) == "full"
    assert dexlib.dex_doc_format(compact) == "compact"
    for f_full, f_comp in zip(full["dex_files"],
                              compact["dex_files"]):
        if "error" in f_full:
            continue
        assert "method_table" not in f_full
        assert "method_table" in f_comp
        assert "invoke_kinds" in f_comp
        # Compact rows really are index/array rows.
        for cls in f_comp["classes"]:
            for row in cls["methods"]:
                assert isinstance(row, list)
            for row in cls["fields"]:
                assert isinstance(row, list)
        for edge in f_comp["call_edges"]:
            assert isinstance(edge, list)
        # Lossless: expansion reproduces the full rows,
        # and every other field is identical.
        assert dexlib.expand_dex_classes(f_comp) == \
            f_full["classes"]
        assert dexlib.expand_call_edges(f_comp) == \
            f_full["call_edges"]
        for key in f_full:
            if key not in ("classes", "call_edges"):
                assert f_comp[key] == f_full[key]
        assert f_comp["method_count"] == f_full["method_count"]
    # Compact is smaller on the same input.
    assert len(json.dumps(compact)) < len(json.dumps(full))


def test_cli_full_flag_matches_pre_30_shape(tmp_path):
    if not os.path.isfile(DEMO):
        pytest.skip("demo fixture absent")
    proc = _run("nar-dex.py", [DEMO, "--json", "--full"])
    assert proc.returncode == 0, proc.stderr[-300:]
    doc = json.loads(proc.stdout)
    assert "dex_format" not in doc
    for f in doc["dex_files"]:
        assert "method_table" not in f
    proc = _run("nar-dex.py", [DEMO, "--json"])
    doc = json.loads(proc.stdout)
    assert doc["dex_format"] == "compact"


def _hand_docs():
    """One full-shape and one compact-shape dex document
    carrying the same facts, built by hand."""
    classes_full = [{
        "class": "Lcom/example/Main;", "superclass": "LAct;",
        "interfaces": [],
        "methods": [{"name": "run", "kind": "direct",
                     "native": True, "access_flags": 0x101},
                    {"name": "go", "kind": "virtual",
                     "native": False, "access_flags": 0x1}],
        "fields": [{"name": "x", "type": "I",
                    "kind": "instance"}]}]
    full = {"dex_files": [{
        "name": "classes.dex", "classes": classes_full,
        "native_methods": [
            {"class": "Lcom/example/Main;", "name": "run"}],
        "entry_points": [
            {"class": "Lcom/example/Main;",
             "via_superclass": "LAct;"}],
        "string_references": [
            {"string": "https://api.example.test",
             "referencing_classes": 1,
             "sample_classes": ["Lcom/example/Main;"]}]}]}
    compact = {"dex_files": [{
        "name": "classes.dex",
        "method_table": {
            "classes": ["Lcom/example/Main;"],
            "names": ["run", "go"],
            "ids": [[0, 0, "V"], [0, 1, "V"]]},
        "classes": [{
            "class": "Lcom/example/Main;",
            "superclass": "LAct;", "interfaces": [],
            "methods": [[0, 0x101, "direct"], [1, 0x1, "virtual"]],
            "fields": [["x", "I", "instance"]]}],
        "invoke_kinds": ["direct"],
        "call_edges": [[1, 0, 0]],
        "native_methods": [
            {"class": "Lcom/example/Main;", "name": "run"}],
        "entry_points": [
            {"class": "Lcom/example/Main;",
             "via_superclass": "LAct;"}],
        "string_references": [
            {"string": "https://api.example.test",
             "referencing_classes": 1,
             "sample_classes": ["Lcom/example/Main;"]}]}]}
    return full, compact


def test_builders_identical_over_both_shapes():
    full, compact = _hand_docs()
    assert dexlib.expand_dex_classes(
        compact["dex_files"][0]) == full["dex_files"][0]["classes"]
    assert dexlib.expand_call_edges(
        compact["dex_files"][0]) == [{
            "from_class": "Lcom/example/Main;",
            "from_method": "go",
            "to_class": "Lcom/example/Main;",
            "to_method": "run", "kind": "direct"}]
    corr_full = corrlib.build_correlations(
        full, None, None, None, "2.6.2")
    corr_comp = corrlib.build_correlations(
        compact, None, None, None, "2.6.2")
    assert corr_full == corr_comp
    g_full = graphlib.build_graph(dex_data=full)
    g_comp = graphlib.build_graph(dex_data=compact)
    assert g_full == g_comp


def test_ask_blueprint_read_both_shapes(tmp_path):
    full, compact = _hand_docs()
    ask = _load("nar_ask_p11", "nar-ask.py")
    blueprint = _load("nar_blueprint_p11", "nar-blueprint.py")
    rows = {}
    for label, doc in (("full", full), ("compact", compact)):
        case_dir = tmp_path / label
        case_dir.mkdir()
        (case_dir / "dex.json").write_text(
            json.dumps(doc), encoding="utf-8")
        rows[label] = (
            ask.Case(str(case_dir)).dex_classes(),
            blueprint.Case(str(case_dir)).dex_classes())
    assert rows["full"] == rows["compact"]
    classes = rows["compact"][0]
    assert classes[0][0] == "Lcom/example/Main;"
    assert classes[0][1] == ["run", "go"]
    assert classes[0][2] == ["x"]


def test_jsonstream_byte_identical():
    docs = [
        {}, [], {"a": 1},
        {"a": [1, 2.5, -3e10, True, False, None], "b": {}},
        {"empty_arr": [], "empty_obj": {}, "nested": [[[]]]},
        {"s": "esc \" \\ \n \t üñïçødé  end"},
        {"deep": {"l1": {"l2": {"l3": [{"x": []}, {}]}}}},
        [1, [2, [3, [4, {"five": 5}]]], "six"],
        {"big": list(range(50)),
         "objs": [{"k": i, "v": [i]} for i in range(20)]},
        {"f": 0.1, "g": 1e-06,
         "h": 123456789012345678901234567890},
        {5: "intkey", True: "boolkey", None: "nonekey"},
    ]
    for indent in (1, 2):
        for doc in docs:
            out = io.BytesIO()
            az.dump_json_streaming(doc, out, indent=indent)
            assert out.getvalue() == json.dumps(
                doc, indent=indent).encode()


def test_memory_budget_check_raises_named_boundary():
    az.EXEC_LOG.clear()
    az.set_budgets(budget_mb=0.001)
    try:
        with pytest.raises(az._MemoryBudgetExceeded) as ei:
            az._check_memory_budget("dex")
        assert ei.value.boundary == "memory-budget:dex"
        entry = az.EXEC_LOG[-1]
        assert entry["status"] == "budget-exceeded"
        assert entry["boundary"] == "memory-budget:dex"
    finally:
        az.set_budgets()
        az.EXEC_LOG.clear()


def test_memory_budget_win32_rss_source(monkeypatch):
    """Windows RSS source (win-fixes B7): the resource
    module does not exist on Windows, so _peak_rss_bytes
    must read PeakWorkingSetSize through ctypes
    GetProcessMemoryInfo there, and the named boundary
    must raise identically. Simulated on a POSIX host by
    patching sys.platform and injecting a fake psapi /
    kernel32 pair into ctypes.WinDLL; a failing DLL load
    must surface as an honest named budget-unavailable
    log entry, never a silent pass and never an
    AttributeError/OSError leak."""
    import ctypes

    class _FakeKernel32:
        def GetCurrentProcess(self):
            return -1  # the real pseudo-handle value

    class _FakePsapi:
        def GetProcessMemoryInfo(self, handle, ref, size):
            counters = ctypes.cast(
                ref, ctypes.POINTER(
                    az._ProcessMemoryCountersEx)).contents
            counters.PeakWorkingSetSize = 64 * 1024 * 1024
            return 1

    fakes = {"kernel32": _FakeKernel32(), "psapi": _FakePsapi()}
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(ctypes, "WinDLL",
                        lambda name, **kw: fakes[name],
                        raising=False)
    assert az._peak_rss_bytes() == 64 * 1024 * 1024
    az.EXEC_LOG.clear()
    az.set_budgets(budget_mb=0.001)
    try:
        with pytest.raises(az._MemoryBudgetExceeded) as ei:
            az._check_memory_budget("dex")
        assert ei.value.boundary == "memory-budget:dex"
        entry = az.EXEC_LOG[-1]
        assert entry["status"] == "budget-exceeded"
        assert entry["boundary"] == "memory-budget:dex"
        assert entry["peak_rss_bytes"] == 64 * 1024 * 1024
    finally:
        az.set_budgets()
        az.EXEC_LOG.clear()

    def _failing_windll(name, **kw):
        raise OSError("DLL load failed (simulated)")

    monkeypatch.setattr(ctypes, "WinDLL", _failing_windll,
                        raising=False)
    assert az._peak_rss_bytes() is None
    az.EXEC_LOG.clear()
    az.set_budgets(budget_mb=0.001)
    try:
        az._check_memory_budget("dex")  # must not raise
        entry = az.EXEC_LOG[-1]
        assert entry["status"] == "budget-unavailable"
        assert entry["boundary"] == "memory-budget:dex"
    finally:
        az.set_budgets()
        az.EXEC_LOG.clear()


@pytest.mark.skipif(not os.path.isfile(DEMO),
                    reason="demo fixture absent")
def test_budget_abort_then_resume_and_verify(tmp_path):
    case = str(tmp_path / "case")
    proc = _run("nar-analyze.py",
                [DEMO, "--out", case, "--budget-mb", "1",
                 "--no-html"])
    assert proc.returncode == 1, proc.stderr[-500:]
    assert "Traceback" not in proc.stderr
    assert "memory-budget:" in proc.stderr
    case_doc = json.loads(
        Path(case, "case.json").read_text(encoding="utf-8"))
    boundary = case_doc["resume_boundary"]["boundary"]
    assert boundary.startswith("memory-budget:")
    assert case_doc["resume_boundary"]["resumable"] is True
    # Resume: same case directory, no budget.
    proc = _run("nar-analyze.py",
                [DEMO, "--out", case, "--no-html"])
    assert proc.returncode == 0, proc.stderr[-500:]
    case_doc = json.loads(
        Path(case, "case.json").read_text(encoding="utf-8"))
    assert "resume_boundary" not in case_doc
    assert case_doc["config"]["dex_format"] == "compact"
    dex_doc = json.loads(
        Path(case, "dex.json").read_text(encoding="utf-8"))
    assert dex_doc["dex_format"] == "compact"
    proc = _run("nar-analyze.py", ["--verify", case])
    assert proc.returncode == 0, proc.stdout[-1000:]


@pytest.mark.skipif(not os.path.isfile(DEMO),
                    reason="demo fixture absent")
def test_dex_full_case_verifies(tmp_path):
    case = str(tmp_path / "case-full")
    proc = _run("nar-analyze.py",
                [DEMO, "--out", case, "--dex-full",
                 "--no-html"])
    assert proc.returncode == 0, proc.stderr[-500:]
    case_doc = json.loads(
        Path(case, "case.json").read_text(encoding="utf-8"))
    assert case_doc["config"]["dex_format"] == "full"
    dex_doc = json.loads(
        Path(case, "dex.json").read_text(encoding="utf-8"))
    assert "dex_format" not in dex_doc
    proc = _run("nar-analyze.py", ["--verify", case])
    assert proc.returncode == 0, proc.stdout[-1000:]
