"""Unit tests: graph + investigation companions
(2.6.0 Phases 7/8, R-008 / R-009 / R-020 investigation half).

- graph.json is built from fabricated stage data +
  correlations, validates against its schema, keeps
  one-sided joins as explicit-status edges/nodes, and is
  queryable by kind / edge kind / confidence / text.
- investigation.json is deterministic and offline: facts
  are lifted from stage data, paths carry rule ids, and
  hypotheses are separated. A dedicated assertion checks
  that NO referenced entity is invented: every subject in
  the investigation (and every graph node label of an
  entity kind) exists in the fabricated / generated case
  data it was built from.
- The layer is optional (disable flag / env) and a builder
  failure degrades to a recorded stage error while the
  rest of the analysis continues.
- A generated case (demo fixture) carries both companions,
  validates them, and keeps correlations.json valid.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SCRIPTS = os.path.join(ROOT, "scripts")
sys.path.insert(0, SCRIPTS)

from narlib import correlations, evidence, graph, investigation  # noqa: E402


def _schema(name):
    with open(os.path.join(ROOT, "schemas", name),
              encoding="utf-8") as fh:
        return json.load(fh)


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(SCRIPTS, filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _prop(value):
    return {"value": value, "provenance": "test",
            "confidence": "high", "fact_class": "observed"}


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
    "dependency_graph": {"libapp.so": ["liblog.so"]},
    "libraries": [{"name": "libapp.so",
                   "display_name": "arm64-v8a/libapp.so",
                   "exports": ["Java_com_example_App_greet",
                               "Java_com_example_App_orphan"],
                   "jni_exports": ["Java_com_example_App_greet",
                                   "Java_com_example_App_orphan"],
                   "register_natives_hint": False}]}
PERMS = {
    "package": "com.example.demo",
    "permissions": [
        {"name": "android.permission.INTERNET"},
        {"name": "com.example.GUARD"}],
    "components": {
        "activity": [
            {"name": "com.example.App", "exported": True,
             "permission": None},
            {"name": "com.example.Guarded", "exported": True,
             "permission": "com.example.GUARD"}],
        "service": [{"name": "com.example.SyncService",
                     "exported": False, "permission": None}]},
}
NETWORK = {
    "endpoints": [
        {"url": "https://api.example.com/v1",
         "host": "api.example.com", "classification": "confirmed"},
        {"url": "https://cdn.example.com/x",
         "host": "cdn.example.com", "classification": "potential"}],
    "hosts": ["api.example.com", "cdn.example.com"],
    "api_hosts": [], "services": [],
    "network_security_config": {},
    "network_libraries": [{"library": "OkHttp",
                           "evidence": "test"}]}
FINGERPRINT = {"source_sha256": "a" * 64,
               "properties": {"package": _prop("com.example.demo")},
               "notes": []}
ENGINES = {"verdicts": [{"engine": "unity", "detected": True,
                         "confidence": "high", "score": 12,
                         "version": None}],
           "ambiguities": []}
SECURITY = {"findings": [{
    "id": "NAR-SEC-001", "title": "Example finding",
    "severity": "high", "confidence": "high",
    "verification_status": "CONFIRMED",
    "affected_component": "com.example.App",
    "file_path": "AndroidManifest.xml", "evidence": "test",
    "explanation": "x", "potential_impact": "x",
    "reproduction": "static", "remediation": "x",
    "false_positive_considerations": ""}],
    "severity_counts": {"high": 1}, "positive_observations": []}
ASSETS = {"assets": [{"path": "assets/data.bin", "type": "data",
                      "category": "data", "size_bytes": 3,
                      "sha256": "b" * 64}],
          "total_assets": 1, "total_bytes": 3}

CORR = correlations.build_correlations(DEX, NATIVE, PERMS,
                                       NETWORK, "2.5.2")

# Every entity the fabricated case actually contains.
ALLOWED_SUBJECTS = {
    "com.example.App", "okhttp3.OkHttpClient", "com.example.Guarded",
    "com.example.SyncService", "com.example.demo",
    "Java_com_example_App_greet", "Java_com_example_App_planted",
    "Java_com_example_App_orphan",
    "https://api.example.com/v1", "https://cdn.example.com/x",
    "OkHttp", "network_security_config",
    "android.permission.INTERNET", "com.example.GUARD",
}


def _build_graph():
    return graph.build_graph(
        dex_data=DEX, native_data=NATIVE, perms_data=PERMS,
        network_data=NETWORK, fingerprint_data=FINGERPRINT,
        engines_data=ENGINES, security_data=SECURITY,
        assets_data=ASSETS, correlations_data=CORR,
        version="2.5.2")


def _build_inv():
    return investigation.build_investigation(
        dex_data=DEX, native_data=NATIVE, perms_data=PERMS,
        network_data=NETWORK, security_data=SECURITY,
        correlations_data=CORR, engines_data=ENGINES,
        version="2.5.2")


class GraphTest(unittest.TestCase):
    def test_graph_validates_and_contains_expected_edges(self):
        doc = _build_graph()
        self.assertEqual(
            evidence.validate(doc, _schema("graph.schema.json")),
            [])
        kinds = {n["kind"] for n in doc["nodes"]}
        for kind in ("application", "dex_file", "class",
                     "native_library", "jni_function",
                     "network_endpoint", "component", "permission",
                     "engine", "security_finding", "asset"):
            self.assertIn(kind, kinds)
        edges = {(e["source"], e["target"], e["kind"], e["status"])
                 for e in doc["edges"]}
        self.assertIn(("class:com.example.App",
                       "jni_function:Java_com_example_App_greet",
                       "declares", "matched"), edges)
        self.assertIn(("native_library:arm64-v8a/libapp.so",
                       "jni_function:Java_com_example_App_greet",
                       "exports_jni", "matched"), edges)
        self.assertIn(("class:com.example.App",
                       "network_endpoint:https://api.example.com/v1",
                       "references_endpoint", "code-referenced"),
                      edges)
        # One-sided joins are kept, with explicit status.
        self.assertTrue(any(
            e["kind"] == "references_endpoint"
            and e["status"] == "no-code-reference"
            for e in doc["edges"]))
        jni_nodes = {n["label"]: n for n in doc["nodes"]
                     if n["kind"] == "jni_function"}
        self.assertEqual(
            jni_nodes["Java_com_example_App_planted"]["status"],
            "declaration-only")
        self.assertEqual(
            jni_nodes["Java_com_example_App_orphan"]["status"],
            "export-only")
        # Provenance + evidence on every node and edge.
        for n in doc["nodes"]:
            self.assertIn("stage", n["evidence"])
            self.assertIn("field_path", n["evidence"])
        for e in doc["edges"]:
            self.assertIn("stage", e["provenance"])
            self.assertIn("field_path", e["provenance"])
        self.assertIn("correlations", doc["contributing_stages"])
        self.assertIn("cached stage outputs", doc["rebuild_note"])
        self.assertEqual(doc["counts"]["nodes"],
                         len(doc["nodes"]))

    def test_graph_degraded_inputs_validate(self):
        doc = graph.build_graph(version="2.5.2")
        self.assertEqual(
            evidence.validate(doc, _schema("graph.schema.json")),
            [])
        self.assertTrue(doc["notes"])

    def test_query_graph_filters(self):
        doc = _build_graph()
        by_kind = graph.query_graph(doc, kind="class")
        self.assertTrue(by_kind["nodes"])
        self.assertTrue(all(n["kind"] == "class"
                            for n in by_kind["nodes"]))
        by_edge = graph.query_graph(doc, edge_kind="declares")
        self.assertTrue(by_edge["edges"])
        self.assertTrue(all(e["kind"] == "declares"
                            for e in by_edge["edges"]))
        high = graph.query_graph(doc, min_confidence="high")
        self.assertTrue(all(e["confidence"] == "high"
                            for e in high["edges"]))
        by_text = graph.query_graph(doc, text="okhttp")
        labels = " ".join(n["label"] for n in by_text["nodes"])
        self.assertIn("OkHttpClient", labels)


class InvestigationTest(unittest.TestCase):
    def test_investigation_validates_and_rules_fire(self):
        doc = _build_inv()
        self.assertEqual(
            evidence.validate(
                doc, _schema("investigation.schema.json")), [])
        self.assertEqual(doc["method"],
                         "deterministic-offline-rules")
        facts = {(f["kind"], f["subject"])
                 for f in doc["verified_facts"]}
        self.assertIn(("jni_binding",
                       "Java_com_example_App_greet"), facts)
        self.assertIn(("endpoint",
                       "https://api.example.com/v1"), facts)
        rules = {p["rule_id"] for p in doc["paths"]}
        for rule in ("INV-EXPORTED-NO-PERMISSION",
                     "INV-JNI-DECL-ONLY",
                     "INV-ENDPOINT-NO-CODE-REF",
                     "INV-FINDING-FOLLOWUP"):
            self.assertIn(rule, rules)
        exported = [p for p in doc["paths"]
                    if p["rule_id"] ==
                    "INV-EXPORTED-NO-PERMISSION"]
        self.assertEqual([p["subject"] for p in exported],
                         ["com.example.App"])
        self.assertEqual(exported[0]["priority"], 1)
        ranks = [p["rank"] for p in doc["paths"]]
        self.assertEqual(ranks, sorted(ranks))
        self.assertTrue(doc["hypotheses"])
        for h in doc["hypotheses"]:
            self.assertEqual(h["label"], "hypothesis")
            self.assertTrue(h["confirm"])
            self.assertTrue(h["refute"])
        self.assertTrue(doc["unknowns"])
        # Hypotheses never leak into verified facts.
        hyp_subjects = {h["subject"] for h in doc["hypotheses"]}
        fact_text = " ".join(f["fact"] or ""
                             for f in doc["verified_facts"])
        self.assertNotIn("may be bound dynamically", fact_text)
        self.assertTrue(hyp_subjects)

    def test_no_invented_entities(self):
        inv = _build_inv()
        for section in ("verified_facts", "paths", "hypotheses"):
            for item in inv[section]:
                subject = item.get("subject")
                if subject is not None:
                    self.assertIn(
                        subject, ALLOWED_SUBJECTS,
                        f"{section} references invented "
                        f"entity: {subject}")
        doc = _build_graph()
        for node in doc["nodes"]:
            if node["kind"] in ("class", "component",
                                "network_endpoint", "jni_function"):
                self.assertIn(node["label"], ALLOWED_SUBJECTS,
                              f"graph invented {node['label']}")

    def test_disable_env_helpers(self):
        self.assertTrue(investigation.investigation_disabled(
            {"NAR_NO_INVESTIGATION": "1"}))
        self.assertTrue(investigation.investigation_disabled(
            {"NAR_DISABLE_INVESTIGATION": "true"}))
        self.assertFalse(investigation.investigation_disabled({}))
        self.assertTrue(investigation.graph_disabled(
            {"NAR_NO_GRAPH": "yes"}))
        self.assertFalse(investigation.graph_disabled({}))


class OrchestrationDegradationTest(unittest.TestCase):
    """run_2_0_stages with stubbed stage runners: a failing
    graph builder is recorded and the run continues; the
    disable switches suppress the companions."""

    STAGE_DATA = {"fingerprint": FINGERPRINT, "engines": ENGINES,
                  "dex": DEX, "native": NATIVE,
                  "network": NETWORK, "security": SECURITY,
                  "assets": ASSETS}

    def _run(self, az, out, target):
        report = {"limitations": []}
        az.run_2_0_stages(report, target, out, out,
                          perms_data=PERMS)
        return report

    def test_builder_failure_degrades_and_disable_works(self):
        az = _load("nar_analyze_for_graph_test", "nar-analyze.py")
        orig_stage = az.run_cached_stage
        orig_graph = az._graph
        az.run_cached_stage = lambda stage, script, args, key, out: (  # noqa: E501
            self.STAGE_DATA[stage], None, False)
        try:
            with tempfile.TemporaryDirectory() as td:
                target = os.path.join(td, "target.apk")
                with open(target, "wb") as fh:
                    fh.write(b"dummy-target")
                # 1. graph builder raises -> stage error,
                #    investigation still emitted.
                az._graph = types.SimpleNamespace(
                    build_graph=lambda **kw: (_ for _ in ()).throw(
                        RuntimeError("planted builder failure")))
                az.EXEC_LOG.clear()
                report = self._run(az, os.path.join(td, "c1"), target)
                self.assertFalse(os.path.isfile(
                    os.path.join(td, "c1", "graph.json")))
                self.assertTrue(os.path.isfile(
                    os.path.join(td, "c1",
                                 "investigation.json")))
                self.assertTrue(any(
                    "graph.json not emitted" in lim
                    for lim in report["limitations"]))
                self.assertTrue(any(
                    e["stage"] == "graph"
                    and e["status"] == "failed"
                    for e in az.EXEC_LOG))
                # 2. investigation disabled via the layer
                #    switch -> no file, graph restored works.
                az._graph = orig_graph
                az.set_layers(graph=True, investigation=False)
                self._run(az, os.path.join(td, "c2"), target)
                self.assertTrue(os.path.isfile(
                    os.path.join(td, "c2", "graph.json")))
                self.assertFalse(os.path.isfile(
                    os.path.join(td, "c2",
                                 "investigation.json")))
                # 3. investigation disabled via env var.
                az.set_layers(graph=True, investigation=True)
                old = os.environ.get("NAR_NO_INVESTIGATION")
                os.environ["NAR_NO_INVESTIGATION"] = "1"
                try:
                    self._run(az, os.path.join(td, "c3"), target)
                finally:
                    if old is None:
                        os.environ.pop(
                            "NAR_NO_INVESTIGATION", None)
                    else:
                        os.environ["NAR_NO_INVESTIGATION"] = old
                self.assertFalse(os.path.isfile(
                    os.path.join(td, "c3",
                                 "investigation.json")))
        finally:
            az.run_cached_stage = orig_stage
            az._graph = orig_graph
            az.set_layers(graph=True, investigation=True)
            az.EXEC_LOG.clear()


class GeneratedCaseGraphInvestigationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures = os.environ.get(
            "NAR_FIXTURES",
            os.path.expanduser("~/workspace/nar-e2e-fixtures"))
        cls.demo = os.path.join(fixtures, "demo", "NarDemo.apk")
        if not os.path.isfile(cls.demo):
            raise unittest.SkipTest("demo fixture absent")
        cls._tmp = tempfile.TemporaryDirectory()
        cls.case = os.path.join(cls._tmp.name, "case")
        proc = subprocess.run(
            [sys.executable, os.path.join(SCRIPTS, "nar-analyze.py"),
             cls.demo, "--out", cls.case],
            capture_output=True, text=True, timeout=900)
        if proc.returncode != 0:
            cls._tmp.cleanup()
            raise AssertionError(
                f"nar-analyze failed: {proc.stderr[-500:]}")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _read(self, name):
        with open(os.path.join(self.case, name),
                  encoding="utf-8") as fh:
            return json.load(fh)

    def test_companions_exist_and_validate(self):
        for name, schema in (
                ("graph.json", "graph.schema.json"),
                ("investigation.json",
                 "investigation.schema.json"),
                ("correlations.json",
                 "correlations.schema.json")):
            self.assertEqual(
                evidence.validate(self._read(name),
                                  _schema(schema)), [], name)

    def test_generated_no_invented_entities(self):
        corpus = ""
        for name in ("dex.json", "native.json", "endpoints.json",
                     "correlations.json",
                     "security-findings.json", "engines.json",
                     "assets.json", "fingerprint.json"):
            path = os.path.join(self.case, name)
            if os.path.isfile(path):
                with open(path, encoding="utf-8") as fh:
                    corpus += fh.read()
        inv = self._read("investigation.json")
        for section in ("verified_facts", "paths", "hypotheses"):
            for item in inv[section]:
                subject = item.get("subject")
                if subject is not None:
                    self.assertTrue(
                        subject in corpus
                        or subject == "network_security_config",
                        f"{section} invented entity: {subject}")

    def test_cli_views(self):
        proc = subprocess.run(
            [sys.executable, os.path.join(SCRIPTS, "nar.py"),
             "case", "graph", self.case, "--kind", "class"],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr[-300:])
        doc = json.loads(proc.stdout)
        self.assertEqual(doc["kind"], "graph")
        self.assertTrue(all(n["kind"] == "class"
                            for n in doc["nodes"]))
        proc = subprocess.run(
            [sys.executable, os.path.join(SCRIPTS, "nar.py"),
             "case", "investigation", self.case],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr[-300:])
        doc = json.loads(proc.stdout)
        self.assertEqual(doc["kind"], "investigation")
        self.assertIn("counts", doc)


if __name__ == "__main__":
    unittest.main()
