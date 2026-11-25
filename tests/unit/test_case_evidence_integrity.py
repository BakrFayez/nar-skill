"""Unit tests: evidence & case integrity (2.6.2,
Workstream F).

- F1: `nar case verify` (nar-analyze verify_case) now
  enforces the checks the 2.6.1 round ran externally:
  evidence references (primary AND evidence_also)
  resolve to a present document and a resolvable field
  path; graph endpoints / duplicates / orphaned
  relationships; header counts reconcile (graph,
  investigation, correlations); hypotheses carry
  basis + confirm + refute; the result carries a
  structured evidence_integrity section and the exit
  code follows hard failures only.
- F2: companion presence vs the report's companion
  list, companion schema validity, companion version
  fields vs the case record, and the export -> import
  -> verify round trip under the new checks; tampered
  companions fail with the right reason.
- F3: narlib.investigation refuses at build time to
  emit a hypothesis that cannot state confirm/refute
  (or lacks a basis evidence reference).
- Backward compatibility: a 2.6.0-shaped case (no
  unverified_findings section; evidence citing the
  permissions document that pipeline never wrote)
  verifies with WARNINGS, not failures; the same
  defects in a 2.6.1-shaped case are hard failures.

All fixtures are synthetic role data built in-test
through the real graph / investigation / correlations
builders; no real target is named anywhere.
"""
import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SCRIPTS = os.path.join(ROOT, "scripts")
sys.path.insert(0, SCRIPTS)

from narlib import correlations, evidence, graph, investigation  # noqa: E402


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
    # Producer identity fields: nar-perms always emits
    # file / path / parser_requested (audit() header), and
    # schemas/permissions.schema.json requires them; the
    # stub carried none of the three until the schema was
    # registered in verify (stability campaign, E-09).
    "file": "role-target.apk",
    "path": "/nonexistent/role-target.apk",
    "parser_requested": "auto",
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
        # Manifest tag name verbatim: the hyphenated key
        # is the field-path grammar regression case from
        # the 2.6.1 checker lesson.
        "activity-alias": [
            {"name": "com.example.Alias", "exported": False,
             "permission": None}],
        "service": [{"name": "com.example.SyncService",
                     "exported": False, "permission": None}]},
}
NETWORK = {
    "endpoints": [
        # 'kind' added (stability campaign): the endpoints
        # schema requires url/kind/classification per entry
        # and real producer entries always carry kind; the
        # stub predates verify's schema check of this file.
        {"url": "https://api.example.com/v1",
         "host": "api.example.com", "kind": "api",
         "classification": "confirmed"},
        {"url": "https://cdn.example.com/x",
         "host": "cdn.example.com", "kind": "web",
         "classification": "potential"}],
    "hosts": ["api.example.com", "cdn.example.com"],
    "api_hosts": [], "services": [],
    "network_security_config": {},
    # Producer shape is a list of library label strings
    # (nar-network emits sorted labels); the object shape
    # here predates verify's schema check of this file
    # (stability campaign).
    "network_libraries": ["OkHttp"]}
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

VERSION = "2.6.1"


def _docs(version=VERSION):
    corr = correlations.build_correlations(
        DEX, NATIVE, PERMS, NETWORK, version)
    graph_doc = graph.build_graph(
        dex_data=DEX, native_data=NATIVE, perms_data=PERMS,
        network_data=NETWORK, fingerprint_data=FINGERPRINT,
        engines_data=ENGINES, security_data=SECURITY,
        assets_data=ASSETS, correlations_data=corr,
        version=version)
    inv_doc = investigation.build_investigation(
        dex_data=DEX, native_data=NATIVE, perms_data=PERMS,
        network_data=NETWORK, security_data=SECURITY,
        correlations_data=corr, engines_data=ENGINES,
        version=version)
    return corr, graph_doc, inv_doc


def _write(case, name, doc):
    with open(os.path.join(case, name), "w",
              encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)


def _read(case, name):
    with open(os.path.join(case, name), encoding="utf-8") as fh:
        return json.load(fh)


def make_case(root, version=VERSION):
    """A complete synthetic case whose graph /
    investigation / correlations companions are built by
    the real builders over fabricated stage documents, so
    every evidence reference genuinely resolves."""
    case = os.path.join(root, "case")
    os.makedirs(case)
    corr, graph_doc, inv_doc = _docs(version)
    _write(case, "case.json", {
        "case_id": "nar-synthetic", "nar_version": version,
        "created": "2026-01-01T00:00:00Z",
        "input": {"path": "/nonexistent/role-target.apk",
                  "sha256": "a" * 64, "size_bytes": 3},
        "config": {}, "tool_versions": {}, "stages": {}})
    _write(case, "report.json", {
        "tool": "nar-analyze", "version": version,
        "companions": {
            "graph": {"file": "graph.json", "projected": True},
            "investigation": {"file": "investigation.json",
                              "projected": True},
            "correlations": {"file": "correlations.json",
                             "projected": True},
            "permissions": {"file": "permissions.json",
                            "cached": False}}})
    _write(case, "dex.json", DEX)
    _write(case, "native.json", NATIVE)
    _write(case, "permissions.json", PERMS)
    _write(case, "endpoints.json", NETWORK)
    _write(case, "fingerprint.json", FINGERPRINT)
    _write(case, "engines.json", ENGINES)
    _write(case, "security-findings.json", SECURITY)
    _write(case, "assets.json", ASSETS)
    _write(case, "correlations.json", corr)
    _write(case, "graph.json", graph_doc)
    _write(case, "investigation.json", inv_doc)
    return case


def _failed_checks(result):
    section = result["evidence_integrity"]
    return {c["check"] for c in section["checks"]
            if c["status"] == "fail"}


def _warned_checks(result):
    section = result["evidence_integrity"]
    return {c["check"] for c in section["checks"]
            if c["status"] == "warning"}


class FieldPathGrammarTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.az = _load("nar_analyze_fp", "nar-analyze.py")

    def test_resolves_builder_grammar(self):
        resolve = self.az._resolve_evidence_path
        doc = {"components": {"activity-alias": [
            {"name": "x"}]},
            "dex_files": [{"classes": [{"class": "A"},
                                       {"class": "B"}]}],
            "properties": {"package": None},
            "dependency_graph": {"liba.so": []}}
        self.assertTrue(resolve(
            doc, "components.activity-alias[0].name"))
        self.assertTrue(resolve(
            doc, "dex_files[0].classes[1].class"))
        # A present key with a null value still resolves.
        self.assertTrue(resolve(doc, "properties.package"))
        self.assertTrue(resolve(doc, "dependency_graph"))

    def test_rejects_unresolvable_paths(self):
        resolve = self.az._resolve_evidence_path
        doc = {"a": [{"b": 1}]}
        self.assertFalse(resolve(doc, "a[1].b"))
        self.assertFalse(resolve(doc, "a[0].c"))
        self.assertFalse(resolve(doc, "a[x].b"))
        self.assertFalse(resolve(doc, "a..b"))
        self.assertFalse(resolve(doc, ""))
        self.assertFalse(resolve(doc, "a[0].b.c"))


class VerifyCleanCaseTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.az = _load("nar_analyze_clean", "nar-analyze.py")

    def test_fresh_synthetic_case_verifies_clean(self):
        with tempfile.TemporaryDirectory() as td:
            case = make_case(td)
            result = self.az.verify_case(case)
            self.assertTrue(result["ok"], result["failures"])
            self.assertEqual(result["warnings"], [])
            section = result["evidence_integrity"]
            self.assertTrue(section["ok"])
            self.assertTrue(section["checks"])
            # Hyphenated component keys resolve (the
            # fabricated case cites
            # components.activity-alias[0].name).
            graph_doc = _read(case, "graph.json")
            paths = {n["evidence"]["field_path"]
                     for n in graph_doc["nodes"]}
            self.assertIn("components.activity-alias[0].name",
                          paths)
            by_name = {c["check"]: c["status"]
                       for c in section["checks"]}
            self.assertEqual(
                by_name["evidence field paths resolve in "
                        "their documents"], "pass")

    def test_result_shape_is_backward_compatible(self):
        with tempfile.TemporaryDirectory() as td:
            case = make_case(td)
            result = self.az.verify_case(case)
            for key in ("ok", "checks", "failures", "notes"):
                self.assertIn(key, result)
            for entry in result["checks"]:
                self.assertIn("check", entry)
                self.assertIn("ok", entry)
                self.assertIn("detail", entry)


class VerifyNegativeTest(unittest.TestCase):
    """Each hand-corrupted case fails verify with the
    expected structured reason."""

    @classmethod
    def setUpClass(cls):
        cls.az = _load("nar_analyze_neg", "nar-analyze.py")

    def _verify_mutated(self, mutate):
        with tempfile.TemporaryDirectory() as td:
            case = make_case(td)
            mutate(case)
            return self.az.verify_case(case)

    def test_dangling_evidence_document(self):
        def mutate(case):
            doc = _read(case, "graph.json")
            doc["nodes"][0]["evidence"]["document"] = \
                "missing-doc.json"
            _write(case, "graph.json", doc)
        result = self._verify_mutated(mutate)
        self.assertFalse(result["ok"])
        self.assertIn(
            "evidence references name documents present "
            "in the case", _failed_checks(result))
        self.assertTrue(any(
            "missing-doc.json" in f
            for f in result["failures"]))

    def test_dangling_evidence_also_document(self):
        def mutate(case):
            doc = _read(case, "graph.json")
            doc["nodes"][0]["evidence_also"] = [{
                "stage": "dex", "document": "ghost.json",
                "field_path": "dex_files"}]
            _write(case, "graph.json", doc)
        result = self._verify_mutated(mutate)
        self.assertFalse(result["ok"])
        self.assertIn(
            "evidence references name documents present "
            "in the case", _failed_checks(result))
        self.assertTrue(any(
            "ghost.json" in f for f in result["failures"]))

    def test_dangling_evidence_field_path(self):
        def mutate(case):
            doc = _read(case, "graph.json")
            doc["nodes"][0]["evidence"]["field_path"] = \
                "properties.no_such_key"
            _write(case, "graph.json", doc)
        result = self._verify_mutated(mutate)
        self.assertFalse(result["ok"])
        self.assertIn(
            "evidence field paths resolve in their "
            "documents", _failed_checks(result))
        self.assertTrue(any(
            "properties.no_such_key" in f
            for f in result["failures"]))

    def test_missing_endpoint_node_orphans_edge(self):
        def mutate(case):
            doc = _read(case, "graph.json")
            target = doc["edges"][0]["target"]
            victim = next(n for n in doc["nodes"]
                          if n["id"] == target)
            doc["nodes"] = [n for n in doc["nodes"]
                            if n["id"] != target]
            doc["counts"]["nodes"] -= 1
            doc["counts"]["nodes_by_kind"][
                victim["kind"]] -= 1
            _write(case, "graph.json", doc)
        result = self._verify_mutated(mutate)
        self.assertFalse(result["ok"])
        failed = _failed_checks(result)
        self.assertIn("graph edge endpoints exist as nodes",
                      failed)
        self.assertIn("graph orphaned relationships", failed)

    def test_duplicate_node_id(self):
        def mutate(case):
            doc = _read(case, "graph.json")
            dupe = copy.deepcopy(doc["nodes"][0])
            doc["nodes"].append(dupe)
            doc["counts"]["nodes"] += 1
            doc["counts"]["nodes_by_kind"][dupe["kind"]] += 1
            _write(case, "graph.json", doc)
        result = self._verify_mutated(mutate)
        self.assertFalse(result["ok"])
        self.assertIn("graph node identifiers are unique",
                      _failed_checks(result))

    def test_duplicate_edge_identity(self):
        def mutate(case):
            doc = _read(case, "graph.json")
            dupe = copy.deepcopy(doc["edges"][0])
            doc["edges"].append(dupe)
            doc["counts"]["edges"] += 1
            doc["counts"]["edges_by_kind"][dupe["kind"]] += 1
            _write(case, "graph.json", doc)
        result = self._verify_mutated(mutate)
        self.assertFalse(result["ok"])
        self.assertIn("graph edge identifiers are unique",
                      _failed_checks(result))

    def test_graph_count_mismatch(self):
        def mutate(case):
            doc = _read(case, "graph.json")
            doc["counts"]["nodes"] += 5
            _write(case, "graph.json", doc)
        result = self._verify_mutated(mutate)
        self.assertFalse(result["ok"])
        self.assertIn(
            "graph counts reconcile with the arrays",
            _failed_checks(result))

    def test_investigation_count_mismatch(self):
        def mutate(case):
            doc = _read(case, "investigation.json")
            doc["counts"]["paths"] += 2
            _write(case, "investigation.json", doc)
        result = self._verify_mutated(mutate)
        self.assertFalse(result["ok"])
        self.assertIn("investigation counts reconcile",
                      _failed_checks(result))

    def test_correlations_count_mismatch(self):
        def mutate(case):
            doc = _read(case, "correlations.json")
            doc["counts"]["jni_matched"] += 1
            _write(case, "correlations.json", doc)
        result = self._verify_mutated(mutate)
        self.assertFalse(result["ok"])
        self.assertIn("correlations counts reconcile",
                      _failed_checks(result))

    def test_hypothesis_missing_refute(self):
        def mutate(case):
            doc = _read(case, "investigation.json")
            self.assertTrue(doc["hypotheses"])
            del doc["hypotheses"][0]["refute"]
            _write(case, "investigation.json", doc)
        result = self._verify_mutated(mutate)
        self.assertFalse(result["ok"])
        self.assertIn(
            "investigation hypotheses carry basis + "
            "confirm + refute", _failed_checks(result))
        self.assertTrue(any(
            "hypotheses[0]" in f and "refute" in f
            for f in result["failures"]))

    def test_hypothesis_missing_basis(self):
        def mutate(case):
            doc = _read(case, "investigation.json")
            doc["hypotheses"][0]["basis"] = {}
            _write(case, "investigation.json", doc)
        result = self._verify_mutated(mutate)
        self.assertFalse(result["ok"])
        self.assertIn(
            "investigation hypotheses carry basis + "
            "confirm + refute", _failed_checks(result))

    def test_listed_companion_missing(self):
        def mutate(case):
            os.unlink(os.path.join(case, "investigation.json"))
        result = self._verify_mutated(mutate)
        self.assertFalse(result["ok"])
        self.assertIn(
            "companion files listed in report.json present",
            _failed_checks(result))

    def test_tampered_companion_fails_schema(self):
        def mutate(case):
            _write(case, "graph.json", {"tool": "tampered"})
        result = self._verify_mutated(mutate)
        self.assertFalse(result["ok"])
        self.assertIn("companion schema validity",
                      _failed_checks(result))

    def test_stale_companion_version(self):
        def mutate(case):
            doc = _read(case, "graph.json")
            doc["version"] = "2.5.2"
            _write(case, "graph.json", doc)
        result = self._verify_mutated(mutate)
        self.assertFalse(result["ok"])
        self.assertIn(
            "companion version fields match the case record",
            _failed_checks(result))
        self.assertTrue(any(
            "2.5.2" in f for f in result["failures"]))


class RoundTripIntegrityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.az = _load("nar_analyze_rt", "nar-analyze.py")

    def test_imported_case_reverifies_fully(self):
        with tempfile.TemporaryDirectory() as td:
            case = make_case(td)
            bundle = os.path.join(td, "case.zip")
            self.az.export_case(case, bundle)
            out = os.path.join(td, "imported")
            result = self.az.import_case(bundle, out)
            self.assertTrue(result["ok"], result["failures"])
            section = result["evidence_integrity"]
            self.assertTrue(section["ok"],
                            section["failures"])
            # Tamper with a companion after import: the
            # bundle manifest check names the file.
            with open(os.path.join(out, "graph.json"),
                      "a") as fh:
                fh.write('{"tampered": true}')
            again = self.az.verify_case(out)
            self.assertFalse(again["ok"])
            self.assertTrue(any(
                "graph.json" in f for f in again["failures"]))

    def test_input_hash_tamper_still_fails(self):
        # Pre-existing F2 coverage, restated against the
        # extended result shape: a recorded input whose
        # file changed on disk fails the hash check.
        with tempfile.TemporaryDirectory() as td:
            case = make_case(td)
            target = os.path.join(td, "role-target.apk")
            with open(target, "wb") as fh:
                fh.write(b"original-bytes")
            import hashlib
            doc = _read(case, "case.json")
            doc["input"]["path"] = target
            doc["input"]["sha256"] = hashlib.sha256(
                b"original-bytes").hexdigest()
            _write(case, "case.json", doc)
            self.assertTrue(self.az.verify_case(case)["ok"])
            with open(target, "wb") as fh:
                fh.write(b"changed-bytes!")
            result = self.az.verify_case(case)
            self.assertFalse(result["ok"])
            self.assertTrue(any(
                "input file hash" in f
                for f in result["failures"]))


class LegacyCaseTest(unittest.TestCase):
    """Migration compatibility: a 2.6.0-shaped case
    verifies (with warnings); the same shape at 2.6.1 is
    strict (covered by VerifyNegativeTest)."""

    @classmethod
    def setUpClass(cls):
        cls.az = _load("nar_analyze_legacy", "nar-analyze.py")

    def _make_legacy(self, td):
        case = make_case(td, version="2.6.0")
        # Pre-separation investigation: no
        # unverified_findings section or count.
        inv = _read(case, "investigation.json")
        del inv["unverified_findings"]
        del inv["counts"]["unverified_findings"]
        _write(case, "investigation.json", inv)
        # The 2.6.0 pipeline never wrote the permissions
        # companion its graph cites (2.6.1 report section
        # 4): remove the file and its report registration.
        os.unlink(os.path.join(case, "permissions.json"))
        report = _read(case, "report.json")
        del report["companions"]["permissions"]
        _write(case, "report.json", report)
        return case

    def test_legacy_case_verifies_with_warnings(self):
        with tempfile.TemporaryDirectory() as td:
            case = self._make_legacy(td)
            result = self.az.verify_case(case)
            self.assertTrue(result["ok"], result["failures"])
            self.assertTrue(result["warnings"])
            warned = _warned_checks(result)
            self.assertIn(
                "evidence references name documents "
                "present in the case", warned)
            self.assertIn("investigation legacy sections",
                          warned)
            self.assertTrue(any(
                "permissions.json" in w
                for w in result["warnings"]))

    def test_legacy_hypothesis_gap_warns_not_fails(self):
        with tempfile.TemporaryDirectory() as td:
            case = self._make_legacy(td)
            inv = _read(case, "investigation.json")
            self.assertTrue(inv["hypotheses"])
            del inv["hypotheses"][0]["refute"]
            _write(case, "investigation.json", inv)
            result = self.az.verify_case(case)
            self.assertTrue(result["ok"], result["failures"])
            self.assertIn(
                "investigation hypotheses carry basis + "
                "confirm + refute", _warned_checks(result))

    def test_legacy_tamper_still_fails(self):
        # Legacy tolerance is not a blanket pass: count
        # tampering was never a legitimate legacy shape.
        with tempfile.TemporaryDirectory() as td:
            case = self._make_legacy(td)
            doc = _read(case, "graph.json")
            doc["counts"]["edges"] += 3
            _write(case, "graph.json", doc)
            result = self.az.verify_case(case)
            self.assertFalse(result["ok"])
            self.assertIn(
                "graph counts reconcile with the arrays",
                _failed_checks(result))


class BuildTimeHypothesisGateTest(unittest.TestCase):
    """F3: the builder gate in narlib.investigation."""

    def test_problems_detected(self):
        good = {
            "statement": "s", "subject": "x",
            "basis": {"stage": "correlations",
                      "document": "correlations.json",
                      "field_path": "jni_bindings[0]"},
            "confirm": "c", "refute": "r"}
        self.assertEqual(
            investigation._hypothesis_problems(good), [])
        for drop in ("confirm", "refute", "statement"):
            bad = {k: v for k, v in good.items() if k != drop}
            self.assertTrue(
                investigation._hypothesis_problems(bad), drop)
        bad = dict(good, basis={"stage": "correlations"})
        self.assertTrue(
            investigation._hypothesis_problems(bad))

    def test_incomplete_hypothesis_not_emitted(self):
        emitted, suppressed = [], []
        ok = investigation._emit_hypothesis(
            emitted, suppressed,
            {"statement": "s", "subject": "x",
             "basis": {"stage": "s", "document": "d.json",
                       "field_path": "p"},
             "confirm": "c"})  # no refute
        self.assertFalse(ok)
        self.assertEqual(emitted, [])
        self.assertEqual(len(suppressed), 1)
        self.assertIn("refute", suppressed[0])

    def test_builder_output_hypotheses_all_complete(self):
        _corr, _g, inv = _docs()
        self.assertTrue(inv["hypotheses"])
        for hyp in inv["hypotheses"]:
            self.assertEqual(
                investigation._hypothesis_problems(hyp), [])
            self.assertEqual(hyp["label"], "hypothesis")
        # Hypotheses are never promoted into facts.
        statements = {h["statement"] for h in inv["hypotheses"]}
        fact_texts = {f.get("fact")
                      for f in inv["verified_facts"]}
        self.assertFalse(statements & fact_texts)
        self.assertEqual(
            evidence.validate(
                inv, json.load(open(os.path.join(
                    ROOT, "schemas",
                    "investigation.schema.json"),
                    encoding="utf-8"))), [])


class CliVerifyJsonTest(unittest.TestCase):
    def test_json_mode_structure_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as td:
            case = make_case(td)
            script = os.path.join(SCRIPTS, "nar-analyze.py")
            proc = subprocess.run(
                [sys.executable, script, "--verify", case,
                 "--json"], capture_output=True, text=True,
                timeout=120)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            doc = json.loads(proc.stdout)
            self.assertIn("evidence_integrity", doc)
            self.assertTrue(
                doc["evidence_integrity"]["checks"])
            self.assertIn("warnings", doc)
            doc2 = _read(case, "graph.json")
            doc2["counts"]["nodes"] += 1
            _write(case, "graph.json", doc2)
            proc = subprocess.run(
                [sys.executable, script, "--verify", case,
                 "--json"], capture_output=True, text=True,
                timeout=120)
            self.assertEqual(proc.returncode, 1)
            doc = json.loads(proc.stdout)
            self.assertFalse(doc["ok"])
            self.assertTrue(any(
                "graph counts reconcile" in f
                for f in doc["failures"]))


class GeneratedCaseVerifyTest(unittest.TestCase):
    """A fresh case from the real pipeline (demo
    fixture) verifies clean under the new checks."""

    @classmethod
    def setUpClass(cls):
        fixtures = os.environ.get(
            "NAR_FIXTURES",
            os.path.expanduser("~/workspace/nar-e2e-fixtures"))
        cls.demo = os.path.join(fixtures, "demo", "NarDemo.apk")
        if not os.path.isfile(cls.demo):
            raise unittest.SkipTest("demo fixture absent")
        cls.az = _load("nar_analyze_gen", "nar-analyze.py")
        cls._tmp = tempfile.TemporaryDirectory()
        cls.case = os.path.join(cls._tmp.name, "case")
        proc = subprocess.run(
            [sys.executable,
             os.path.join(SCRIPTS, "nar-analyze.py"),
             cls.demo, "--out", cls.case],
            capture_output=True, text=True, timeout=900)
        if proc.returncode != 0:
            cls._tmp.cleanup()
            raise AssertionError(
                f"nar-analyze failed: {proc.stderr[-500:]}")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_generated_case_verifies_clean(self):
        result = self.az.verify_case(self.case)
        self.assertTrue(result["ok"], result["failures"])
        self.assertEqual(result["warnings"], [])
        self.assertTrue(result["evidence_integrity"]["ok"])


if __name__ == "__main__":
    unittest.main()
