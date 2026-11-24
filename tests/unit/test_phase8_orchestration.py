"""Unit tests: evidence + orchestration (Evolution Phase 8).

- verification_for_fact_class maps fact classes to the
  strongest verification status they can honestly carry.
- narlib.correlations joins fabricated stage documents:
  the known JNI pair matches; a planted declaration with
  no export is declaration-only; an unclaimed export is
  export-only; components and endpoints join with
  deduplication.
- Orchestration budgets: a total budget already exhausted
  stops a stage with a recorded "budget-exceeded" entry
  (no run, no hang); a 1 ms stage timeout against a real
  tool records budget-exceeded instead of failed.
- Case export/import/verify round-trip on a synthetic
  case; a tampered file fails verify.
"""
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from narlib import correlations, evidence  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(ROOT, "scripts", filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _schema(name):
    with open(os.path.join(ROOT, "schemas", name),
              encoding="utf-8") as fh:
        return json.load(fh)


DEX = {"dex_files": [{
    "name": "classes.dex",
    "classes": [{"class": "Lcom/example/App;"},
                {"class": "Lokhttp3/OkHttpClient;"}],
    "native_methods": [
        {"class": "Lcom/example/App;", "name": "greet"},
        {"class": "Lcom/example/App;", "name": "planted"}],
    "entry_points": [
        {"class": "Lcom/example/App;",
         "via_superclass": "Landroid/app/Activity;"}],
    "string_references": [
        {"string": "https://api.example.com/v1",
         "sample_classes": ["Lcom/example/App;"],
         "referencing_classes": 1}],
}]}
NATIVE = {
    "jni_map": {"arm64-v8a/libapp.so":
                ["Java_com_example_App_greet"]},
    "libraries": [{"name": "libapp.so",
                   "exports": ["Java_com_example_App_greet",
                               "Java_com_example_App_orphan"],
                   "jni_exports": ["Java_com_example_App_greet",
                                   "Java_com_example_App_orphan"],
                   "register_natives_hint": False}]}
PERMS = {"components": {
    "activity": [{"name": "com.example.App"}],
    "service": [{"name": "com.example.SyncService"}]}}
NETWORK = {
    "endpoints": [
        {"url": "https://api.example.com/v1",
         "host": "api.example.com", "classification": "confirmed"},
        {"url": "https://cdn.example.com/x",
         "host": "cdn.example.com", "classification": "potential"}],
    "network_libraries": [{"library": "OkHttp",
                           "evidence": "test"}]}


class CorrelationsTest(unittest.TestCase):
    def test_full_join(self):
        doc = correlations.build_correlations(
            DEX, NATIVE, PERMS, NETWORK, "2.4.0")
        self.assertEqual(evidence.validate(
            doc, _schema("correlations.schema.json")), [])
        jni = {(e["class"], e["method"]): e
               for e in doc["jni_bindings"]
               if e["status"] != "export-only"}
        pair = jni[("com.example.App", "greet")]
        self.assertEqual(pair["status"], "matched")
        self.assertEqual(pair["verification_status"], "CONFIRMED")
        self.assertEqual(
            jni[("com.example.App", "planted")]["status"],
            "declaration-only")
        exports_only = [e for e in doc["jni_bindings"]
                        if e["status"] == "export-only"]
        self.assertEqual(len(exports_only), 1)
        self.assertEqual(exports_only[0]["symbol"],
                         "Java_com_example_App_orphan")
        comps = {e["component"]: e["status"]
                 for e in doc["components"]}
        self.assertEqual(comps["com.example.App"], "matched")
        self.assertEqual(comps["com.example.SyncService"],
                         "declaration-only")
        eps = {e["host"]: e for e in doc["endpoints"]}
        self.assertEqual(eps["api.example.com"]["status"],
                         "code-referenced")
        self.assertEqual(eps["api.example.com"]
                         ["referencing_classes"],
                         ["com.example.App"])
        self.assertEqual(eps["cdn.example.com"]["status"],
                         "no-code-reference")
        libs = doc["network_libraries"]
        self.assertEqual(libs[0]["status"], "matched")
        self.assertEqual(libs[0]["classes_found"], 1)
        self.assertEqual(doc["counts"]["jni_matched"], 1)
        self.assertIn("never", doc["deduplication"])

    def test_degraded_inputs_note_the_gap(self):
        doc = correlations.build_correlations(
            None, None, None, None, "2.4.0")
        self.assertEqual(doc["jni_bindings"], [])
        self.assertEqual(len(doc["notes"]), 4)
        self.assertEqual(evidence.validate(
            doc, _schema("correlations.schema.json")), [])


class VerificationMappingTest(unittest.TestCase):
    def test_mapping(self):
        self.assertEqual(
            evidence.verification_for_fact_class("observed"),
            "CONFIRMED")
        self.assertEqual(
            evidence.verification_for_fact_class("derived"),
            "STRONGLY_INDICATED")
        self.assertEqual(
            evidence.verification_for_fact_class("inferred"),
            "POTENTIAL")
        self.assertEqual(
            evidence.verification_for_fact_class("unknown"),
            "UNVERIFIED")


class BudgetsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.az = _load("nar_analyze_for_test", "nar-analyze.py")

    def tearDown(self):
        self.az.set_budgets(None, None)
        self.az.EXEC_LOG.clear()

    def test_total_budget_precheck_records_stop(self):
        self.az.set_budgets(None, 0.001)
        self.az.BUDGET["t0"] = time.time() - 10
        with tempfile.TemporaryDirectory() as td:
            data, err, cached = self.az.run_cached_stage(
                "fingerprint", "nar-fingerprint.py",
                ["/nonexistent.apk"], "key", td)
        self.assertIsNone(data)
        self.assertIn("budget", err)
        entry = self.az.EXEC_LOG[-1]
        self.assertEqual(entry["status"], "budget-exceeded")
        self.assertEqual(entry["stage"], "fingerprint")

    def test_stage_timeout_records_budget_exceeded(self):
        fixtures = os.environ.get(
            "NAR_FIXTURES",
            os.path.expanduser("~/workspace/nar-e2e-fixtures"))
        demo = os.path.join(fixtures, "demo", "NarDemo.apk")
        if not os.path.isfile(demo):
            self.skipTest("demo fixture absent")
        self.az.set_budgets(0.001, None)
        started = time.time()
        data, err = self.az.run_json_tool(
            "nar-fingerprint.py", [demo])
        elapsed = time.time() - started
        self.assertIsNone(data)
        self.assertLess(elapsed, 30)
        entry = self.az.EXEC_LOG[-1]
        self.assertEqual(entry["status"], "budget-exceeded")
        self.assertIn("budget", entry)


class CaseBundleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.az = _load("nar_analyze_for_bundle", "nar-analyze.py")

    def _make_case(self, root):
        case = os.path.join(root, "case")
        os.makedirs(os.path.join(case, "cache"))
        input_sha = "a" * 64
        with open(os.path.join(case, "case.json"), "w") as fh:
            json.dump({"case_id": "nar-test",
                       "nar_version": "2.4.0",
                       "input": {"path": "/nonexistent/app.apk",
                                 "sha256": input_sha},
                       "stages": {}}, fh)
        with open(os.path.join(case, "report.json"), "w") as fh:
            json.dump({"ok": True}, fh)
        key = hashlib.sha256(
            f"{input_sha}|2.4.0|fingerprint".encode()).hexdigest()
        with open(os.path.join(case, "cache",
                               "fingerprint.json"), "w") as fh:
            json.dump({"cached": True}, fh)
        with open(os.path.join(case, "cache",
                               "fingerprint.json.key"), "w") as fh:
            fh.write(key)
        return case

    def test_round_trip_and_tamper(self):
        with tempfile.TemporaryDirectory() as td:
            case = self._make_case(td)
            bundle = os.path.join(td, "case.zip")
            summary = self.az.export_case(case, bundle)
            self.assertEqual(summary["files"], 4)
            out = os.path.join(td, "imported")
            result = self.az.import_case(bundle, out)
            self.assertTrue(result["ok"], result["failures"])
            with open(os.path.join(out, "report.json"),
                      "a") as fh:
                fh.write('{"tampered": true}')
            again = self.az.verify_case(out)
            self.assertFalse(again["ok"])
            self.assertTrue(any("report.json" in f
                                for f in again["failures"]))

    def test_verify_rejects_missing_case(self):
        with tempfile.TemporaryDirectory() as td:
            result = self.az.verify_case(td)
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
