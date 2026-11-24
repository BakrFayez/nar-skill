"""Unit tests: Phases 11-14 (Worker E).

- Phase 11: narlib.formats identifies the synthetic v11 pak
  (its footer magic sits ~204 bytes from EOF, outside the
  historical 64-byte tail window).
- Phase 12: the offline dashboard renders Unified graph and
  Investigation sections from graph.json / investigation.json
  companions, keeps facts / paths / hypotheses / unknowns in
  separate tables, escapes labels, stays at zero external
  references, and omits both sections gracefully when the
  companions are absent.
- Phase 13: CLI consistency — `nar case graph` /
  `nar case investigation` on a case whose companion is
  missing exit 2 (the bad-input code used across the CLI),
  and a malformed companion JSON is a structured error with
  no traceback.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                    "..", ".."))
SCRIPTS = os.path.join(ROOT, "scripts")
TESTS = os.path.join(ROOT, "tests")
sys.path.insert(0, SCRIPTS)
sys.path.insert(0, TESTS)


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(SCRIPTS, filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


REPORT = _load("nar_report_e", "nar-report.py")


def _run(*args):
    return subprocess.run(
        [sys.executable, os.path.join(SCRIPTS, "nar.py"), *args],
        capture_output=True, text=True, timeout=600)


def _write_case(root, extra=None, name="case"):
    case = os.path.join(root, name)
    os.makedirs(case)
    with open(os.path.join(case, "report.json"), "w") as fh:
        json.dump({"identity": {"package": "com.example.x",
                                "version_name": "1.0",
                                "version_code": 1,
                                "app_label": "X", "min_sdk": 24,
                                "target_sdk": 34, "kind": "apk"},
                   "target_sha256": "a" * 64,
                   "limitations": []}, fh)
    for fname, doc in (extra or {}).items():
        with open(os.path.join(case, fname), "w") as fh:
            json.dump(doc, fh)
    return case


GRAPH_DOC = {
    "tool": "nar-analyze", "kind": "graph",
    "nodes": [
        {"id": "application:com.example.x", "kind": "application",
         "label": "com.example.x"},
        {"id": "class:com.example.<A>", "kind": "class",
         "label": "com.example.<A>"},
        {"id": "permission:android.permission.INTERNET",
         "kind": "permission",
         "label": "android.permission.INTERNET"},
    ],
    "edges": [
        {"source": "application:com.example.x",
         "target": "permission:android.permission.INTERNET",
         "kind": "requests_permission", "confidence": "high"},
    ],
    "counts": {"nodes": 3, "edges": 1,
               "nodes_by_kind": {"application": 1, "class": 1,
                                 "permission": 1},
               "edges_by_kind": {"requests_permission": 1}},
    "contributing_stages": ["dex", "permissions"],
}

INVESTIGATION_DOC = {
    "tool": "nar-analyze", "kind": "investigation",
    "verified_facts": [
        {"fact": "JNI binding matched", "kind": "jni_binding",
         "subject": "Java_com_example_Native_run",
         "verification_status": "CONFIRMED"}],
    "paths": [
        {"rank": 1, "rule_id": "INV-EXPORTED-NO-PERMISSION",
         "priority": 1,
         "recommendation": "Confirm at runtime whether the "
                            "exported component can be invoked",
         "subject": "com.example.Main<Activity>",
         "confidence": "high"}],
    "hypotheses": [
        {"statement": "The method may be bound dynamically",
         "subject": "Java_com_example_Native_run",
         "confirm": "Runtime JNI observation",
         "refute": "Exhaustive split search"}],
    "unknowns": [
        {"question": "What does the app do at runtime?",
         "reason": "Static data cannot observe execution"}],
    "counts": {"verified_facts": 1, "paths": 1,
               "hypotheses": 1, "unknowns": 1},
}


class DashboardCompanionsTest(unittest.TestCase):
    def test_graph_and_investigation_sections_offline(self):
        with tempfile.TemporaryDirectory() as td:
            case = _write_case(td, {
                "graph.json": GRAPH_DOC,
                "investigation.json": INVESTIGATION_DOC})
            page = REPORT.render(case)
        self.assertIn("Unified graph", page)
        self.assertIn("3 nodes, 1 edges", page)
        self.assertIn("requests_permission", page)
        self.assertIn("Investigation", page)
        # The four investigation layers stay separated.
        for heading in ("Verified facts", "Ranked paths",
                        "Hypotheses (unverified)", "Unknowns"):
            self.assertIn(heading, page)
        self.assertIn("INV-EXPORTED-NO-PERMISSION", page)
        # Labels are escaped, never raw markup.
        self.assertIn("com.example.Main&lt;Activity&gt;", page)
        self.assertNotIn("com.example.Main<Activity>", page)
        # Zero external references of any kind.
        for bad in ("http://", "https://", "src=", "href=",
                    "<link", "@import"):
            self.assertNotIn(bad, page)

    def test_sections_absent_without_companions(self):
        with tempfile.TemporaryDirectory() as td:
            case = _write_case(td, None)
            page = REPORT.render(case)
        self.assertNotIn("Unified graph", page)
        self.assertNotIn("Investigation", page)

    def test_empty_companions_render_no_sections(self):
        with tempfile.TemporaryDirectory() as td:
            case = _write_case(td, {
                "graph.json": {"nodes": [], "edges": []},
                "investigation.json": {
                    "verified_facts": [], "paths": [],
                    "hypotheses": [], "unknowns": []}},
                name="case-empty")
            page = REPORT.render(case)
        self.assertNotIn("Unified graph", page)
        self.assertNotIn("Investigation", page)


class CaseViewExitCodesTest(unittest.TestCase):
    def test_missing_companion_exits_2_no_traceback(self):
        with tempfile.TemporaryDirectory() as td:
            for verb in ("graph", "investigation"):
                proc = _run("case", verb, td)
                self.assertEqual(proc.returncode, 2,
                                 (verb, proc.stdout, proc.stderr))
                self.assertNotIn("Traceback", proc.stderr)

    def test_malformed_companion_exits_2_no_traceback(self):
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "graph.json"),
                      "w") as fh:
                fh.write("{not json")
            proc = _run("case", "graph", td)
            self.assertEqual(proc.returncode, 2,
                             (proc.stdout, proc.stderr))
            self.assertNotIn("Traceback", proc.stderr)


class SyntheticPakIdentificationTest(unittest.TestCase):
    def test_v11_synthetic_pak_identified(self):
        import synthetic_fixtures as sf
        from narlib import formats
        with tempfile.TemporaryDirectory() as td:
            sf.generate(td)
            verdict = formats.identify(
                os.path.join(td, "synthetic.pak"))
        self.assertEqual(verdict["format"], "unreal-pak")


if __name__ == "__main__":
    unittest.main()
