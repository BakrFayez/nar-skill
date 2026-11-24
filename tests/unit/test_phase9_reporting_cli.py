"""Unit tests: reporting + CLI (Evolution Phase 9).

- The offline dashboard renders the native dependency
  graph from native.json as inline SVG: section present,
  labels escaped, cyclic graphs terminate, and the page
  still carries zero external references. An absent or
  empty graph renders no section.
- The unified CLI gains five verbs without touching the
  existing ones: tools (registry view), identify /
  validate (nar-input aliases), benchmark (the benchmark
  runner), case (export / import / verify routing).
"""
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SCRIPTS = os.path.join(ROOT, "scripts")
sys.path.insert(0, SCRIPTS)

from narlib import __version__ as NAR_VERSION  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(SCRIPTS, filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


REPORT = _load("nar_report_p9", "nar-report.py")


def _run_nar(*args):
    return subprocess.run(
        [sys.executable, os.path.join(SCRIPTS, "nar.py"), *args],
        capture_output=True, text=True, timeout=600)


def _write_case(root, native_doc=None, name="case"):
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
    if native_doc is not None:
        with open(os.path.join(case, "native.json"), "w") as fh:
            json.dump(native_doc, fh)
    return case


class DashboardGraphTest(unittest.TestCase):
    GRAPH = {"liba.so": ["libb.so", "libc.so"],
             "libb.so": ["libc.so"],
             "lib<x>&.so": ["liba.so"],
             "libp.so": ["libq.so"],
             "libq.so": ["libp.so"]}  # cyclic pair must render

    def test_graph_section_rendered_offline_and_escaped(self):
        with tempfile.TemporaryDirectory() as td:
            case = _write_case(td, {"dependency_graph": self.GRAPH})
            page = REPORT.render(case)
        self.assertIn("Native dependency graph", page)
        self.assertIn("<svg", page)
        self.assertIn("6 libraries, 6 bundled-to-bundled", page)
        # Labels are escaped, never raw markup.
        self.assertIn("lib&lt;x&gt;&amp;.so", page)
        self.assertNotIn("lib<x>", page)
        # Zero external references of any kind.
        for bad in ("http://", "https://", "src=", "href=",
                    "<link", "@import"):
            self.assertNotIn(bad, page)

    def test_absent_or_empty_graph_renders_no_section(self):
        with tempfile.TemporaryDirectory() as td:
            case = _write_case(td, None)
            self.assertNotIn("Native dependency graph",
                             REPORT.render(case))
            case = _write_case(td, {"dependency_graph": {}},
                               name="case-empty")
            self.assertNotIn("Native dependency graph",
                             REPORT.render(case))

    def test_oversized_graph_is_truncated_with_note(self):
        graph = {f"lib{i:03d}.so": [f"lib{i + 1:03d}.so"]
                 for i in range(REPORT.MAX_GRAPH_NODES + 40)}
        with tempfile.TemporaryDirectory() as td:
            case = _write_case(td, {"dependency_graph": graph})
            page = REPORT.render(case)
        self.assertIn("Native dependency graph", page)
        self.assertIn("full graph is in native.json", page)


class CliVerbsTest(unittest.TestCase):
    def test_help_lists_new_verbs_and_keeps_old(self):
        proc = _run_nar("--help")
        self.assertEqual(proc.returncode, 0)
        for verb in ("tools", "identify", "validate", "benchmark",
                     "case"):
            self.assertIn(f"nar {verb}", proc.stdout)
        for verb in ("doctor", "triage", "analyze", "runtime"):
            self.assertIn(f"nar {verb}", proc.stdout)

    def test_each_new_verb_help_exits_zero(self):
        for verb in ("tools", "identify", "validate", "benchmark",
                     "case"):
            proc = _run_nar(verb, "--help")
            self.assertEqual(proc.returncode, 0,
                             f"{verb} --help: {proc.stderr[:200]}")

    def test_tools_json_is_the_registry_view(self):
        proc = _run_nar("tools", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr[:200])
        doc = json.loads(proc.stdout)
        self.assertEqual(doc["tool"], "nar-tools")
        names = {t["name"] for t in doc["tools"]}
        self.assertIn("jadx", names)
        self.assertIn("apktool", names)
        self.assertEqual(doc["summary"]["declared"], len(doc["tools"]))
        for t in doc["tools"]:
            self.assertIn("available", t)

    def _synthetic_apk(self, root):
        path = os.path.join(root, "sample.apk")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
            zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)
        return path

    def test_identify_and_validate_aliases(self):
        with tempfile.TemporaryDirectory() as td:
            apk = self._synthetic_apk(td)
            proc = _run_nar("identify", apk, "--json")
            self.assertEqual(proc.returncode, 0, proc.stderr[:200])
            self.assertEqual(json.loads(proc.stdout)["format"],
                             "apk")
            proc = _run_nar("validate", apk)
            self.assertEqual(proc.returncode, 0, proc.stderr[:200])
            self.assertIn("valid=True", proc.stdout)

    def test_case_round_trip_through_the_cli(self):
        with tempfile.TemporaryDirectory() as td:
            case = os.path.join(td, "case")
            os.makedirs(os.path.join(case, "cache"))
            input_sha = "b" * 64
            with open(os.path.join(case, "case.json"), "w") as fh:
                json.dump({"case_id": "nar-p9",
                           "nar_version": NAR_VERSION,
                           "input": {"path": "/nonexistent/a.apk",
                                     "sha256": input_sha},
                           "stages": {}}, fh)
            with open(os.path.join(case, "report.json"), "w") as fh:
                json.dump({"ok": True}, fh)
            key = hashlib.sha256(
                f"{input_sha}|{NAR_VERSION}|fingerprint".encode()
            ).hexdigest()
            with open(os.path.join(case, "cache",
                                   "fingerprint.json"), "w") as fh:
                json.dump({"cached": True}, fh)
            with open(os.path.join(case, "cache",
                                   "fingerprint.json.key"),
                      "w") as fh:
                fh.write(key)
            bundle = os.path.join(td, "case.zip")
            proc = _run_nar("case", "export", case,
                            "--bundle", bundle)
            self.assertEqual(proc.returncode, 0, proc.stderr[:300])
            self.assertTrue(os.path.isfile(bundle))
            out = os.path.join(td, "imported")
            proc = _run_nar("case", "import", bundle,
                            "--out", out)
            self.assertEqual(proc.returncode, 0, proc.stderr[:300])
            proc = _run_nar("case", "verify", out)
            self.assertEqual(proc.returncode, 0, proc.stderr[:300])
            self.assertIn("OK", proc.stdout)

    def test_case_rejects_unknown_subcommand(self):
        proc = _run_nar("case", "frobnicate", "x")
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
