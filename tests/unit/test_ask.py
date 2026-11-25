"""Unit tests: the Q&A layer (Part 7, nar-ask.py).

Pins: deterministic intent classification for every
mandatory question in the brief; Answer Contract completeness
on a synthetic mini case; the forbidden-phrasing rules;
unknown answers carrying REASON + PROBE + COST from the
closed taxonomy; question-library <-> classifier <-> module
consistency (JSON canonical, MD rendering in sync); and
--json output validating against schemas/ask.schema.json.
"""
import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from narlib import evidence  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "nar_ask", os.path.join(ROOT, "scripts", "nar-ask.py"))
ask = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ask)

KNOWN_MODULES = {
    "case", "manifest", "application", "fingerprint",
    "permissions", "engines", "frameworks", "dex", "decompile",
    "assets", "endpoints", "network-analysis",
    "security-findings", "investigation", "report", "native",
    "coverage", "compare", "blueprint",
}

MANDATORY = [
    ("What is this?", "identity"),
    ("What engine?", "build"),
    ("What language?", "build"),
    ("What toolchain?", "build"),
    ("What screens does it have?", "screens"),
    ("How do I get to screen X?", "screens"),
    ("How is X stored?", "storage"),
    ("Where are my coins?", "storage"),
    ("How is progress saved?", "storage"),
    ("How does X work?", "behaviour"),
    ("How is X animated?", "animation"),
    ("What does it talk to?", "network"),
    ("What is this endpoint for?", "network"),
    ("Is it protected?", "security"),
    ("Which packer?", "security"),
    ("Can static analysis see the logic?", "security"),
    ("How is it monetised?", "monetisation"),
    ("What does the ad flow do?", "monetisation"),
    ("Where is purchase verified?", "monetisation"),
    ("What changed between v1 and v2?", "compare"),
    ("How do I rebuild X?", "rebuild"),
    ("What can you NOT tell me, and why?", "gaps"),
    ("How is the car animated?", "animation"),
    ("How do I rebuild this app?", "rebuild"),
    ("What assets does it contain?", "assets"),
]


def _write(path, doc):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)


def _prop(value, status="CONFIRMED"):
    return {"value": value, "provenance": "synthetic test",
            "confidence": "high", "fact_class": "observed",
            "verification_status": status}


def make_mini_case(case_dir, target_path):
    """A synthetic case (generic names only) + target file."""
    with open(target_path, "wb") as fh:
        fh.write(b"synthetic ask test target")
    target_sha = ask.sha256_of(target_path)
    _write(os.path.join(case_dir, "case.json"), {
        "case_id": "synthetic", "nar_version": "2.6.2",
        "input": {"path": target_path, "sha256": target_sha,
                  "size_bytes": 25}})
    _write(os.path.join(case_dir, "application.json"), {
        "properties": {
            "package": _prop("com.example.synthetic"),
            "app_label": _prop("Synthetic"),
            "version_name": _prop("1.0"),
            "version_code": _prop("1"),
            "min_sdk": _prop("24"), "target_sdk": _prop("34")}})
    _write(os.path.join(case_dir, "fingerprint.json"),
           {"properties": {}})
    _write(os.path.join(case_dir, "manifest.json"), {
        "package": "com.example.synthetic",
        "component_counts": {"activity": 1, "service": 0,
                             "receiver": 0, "provider": 0,
                             "total": 1},
        "permission_count": 2})
    _write(os.path.join(case_dir, "permissions.json"), {
        "package": "com.example.synthetic",
        "launcher_activity": "com.example.MainActivity",
        "permissions": [
            {"name": "android.permission.INTERNET"},
            {"name": "com.android.vending.BILLING"}],
        "components": {
            "activity": [{
                "name": "com.example.MainActivity",
                "exported": True,
                "intent_filters": [{
                    "actions": ["android.intent.action.MAIN"],
                    "data": []}]}],
            "service": [], "receiver": [], "provider": []},
        "component_counts": {"activity": 1, "service": 0,
                             "receiver": 0, "provider": 0}})
    verdict = {"engine": "FakeEngine", "detected": True,
               "confidence": "high", "score": 90,
               "indicators": [{"kind": "path",
                               "detail": "libfake.so"}]}
    _write(os.path.join(case_dir, "engines.json"),
           {"verdicts": [verdict]})
    _write(os.path.join(case_dir, "frameworks.json"), {
        "verdicts": [verdict],
        "markers": {"framework_markers": ["Kotlin"],
                    "engine_versions": {}}})
    _write(os.path.join(case_dir, "dex.json"), {
        "dex_files": [{"name": "classes.dex", "classes": [
            {"class": "Lcom/example/CoinWallet;",
             "methods": [{"name": "getCoins"},
                         {"name": "saveCoins"}],
             "fields": [{"name": "balance",
                         "type": "I"}]},
            {"class": "Lcom/example/PrefsStore;",
             "methods": [{"name": "saveProgress"}],
             "fields": []},
            {"class": "Landroid/content/SharedPreferences;",
             "methods": [{"name": "edit"}], "fields": []},
            {"class": "Lcom/android/billingclient/api/"
                      "BillingClient;",
             "methods": [{"name": "launchBillingFlow"}],
             "fields": []},
            {"class": "Lcom/google/android/gms/ads/AdView;",
             "methods": [{"name": "loadAd"}], "fields": []},
            {"class": "Lcom/example/AppDbHelper;",
             "superclass": "Landroid/database/sqlite/"
                           "SQLiteOpenHelper;",
             "methods": [{"name": "onCreate"}], "fields": []},
        ]}],
        "totals": {"classes": 5, "methods": 6, "fields": 1}})
    _write(os.path.join(case_dir, "assets.json"), {
        "total_assets": 2, "total_bytes": 100,
        "by_category": {"texture": 1, "data": 1},
        "assets": [
            {"path": "assets/hero.png", "type": "png-image",
             "size_bytes": 60},
            {"path": "assets/anim/hero_spine.json",
             "type": "json", "size_bytes": 40}],
        "largest": [
            {"path": "assets/hero.png", "type": "png-image",
             "size_bytes": 60}]})
    _write(os.path.join(case_dir, "endpoints.json"), {
        "endpoints": [{
            "url": "https://api.example.com/v1/coins",
            "host": "api.example.com", "kind": "api",
            "classification": "third-party",
            "sources": ["classes.dex"]}],
        "hosts": ["api.example.com"],
        "network_libraries": ["OkHttp"],
        "classification_counts": {"third-party": 1}})
    _write(os.path.join(case_dir, "network-analysis.json"), {
        "endpoint_count": 1,
        "classification_counts": {"third-party": 1},
        "cleartext": {"base_cleartext_permitted": False,
                      "pin_set_present": True}})
    _write(os.path.join(case_dir, "security-findings.json"), {
        "findings": [{
            "id": "NAR-SEC-001", "title": "Debuggable build",
            "severity": "high",
            "verification_status": "CONFIRMED",
            "evidence": "android:debuggable=true"}],
        "severity_counts": {"high": 1},
        "positive_observations": []})
    _write(os.path.join(case_dir, "report.json"), {
        "protections": [],
        "limitations": ["Static analysis only."]})
    _write(os.path.join(case_dir, "decompile.json"), {
        "capability": "java-decompile",
        "chain": ["jadx", "nar-dex-disasm"],
        "attempts": [{"rung": "jadx", "status": "failed"},
                     {"rung": "nar-dex-disasm",
                      "status": "ok"}],
        "served_by": "nar-dex-disasm",
        "fidelity": "bytecode-listing", "caveats": []})
    _write(os.path.join(case_dir, "investigation.json"), {
        "verified_facts": [{
            "fact": "Coins are kept in the wallet",
            "kind": "behaviour", "subject": "wallet",
            "detail": "CoinWallet.saveCoins writes the "
                      "balance field",
            "verification_status": "CONFIRMED"}],
        "unknowns": [{
            "question": "What happens at runtime?",
            "reason": "Static data cannot observe "
                      "execution."}]})
    return target_sha


class IntentClassificationTest(unittest.TestCase):
    def test_mandatory_questions(self):
        for question, intent in MANDATORY:
            self.assertEqual(
                ask.classify_intent(question), intent,
                "%r -> %s, want %s"
                % (question, ask.classify_intent(question),
                   intent))

    def test_classifier_is_deterministic(self):
        for question, _intent in MANDATORY:
            self.assertEqual(ask.classify_intent(question),
                             ask.classify_intent(question))


class MiniCaseContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="nar-ask-test-")
        cls.case_dir = os.path.join(cls.tmp, "case")
        os.makedirs(cls.case_dir)
        cls.target = os.path.join(cls.tmp, "target.apk")
        make_mini_case(cls.case_dir, cls.target)

    def _ask(self, question, **kw):
        return ask.answer_question(question, self.target,
                                   self.case_dir, **kw)

    def _assert_contract(self, doc):
        for field in ("question", "answer", "evidence",
                      "confidence", "why", "chain", "boundary"):
            self.assertTrue(doc.get(field),
                            "missing/empty %s in %r"
                            % (field, doc))
        self.assertIn(doc["confidence"], ask.CONFIDENCES)
        self.assertTrue(doc["evidence"],
                        "evidence must never be empty")
        for phrase in ask.FORBIDDEN_ANSWER_PHRASES:
            self.assertNotIn(phrase, doc["answer"].lower())
        if doc["confidence"] == "unknown":
            self.assertIn(doc["reason"], ask.UNKNOWN_REASONS)
            self.assertTrue(doc["probe"])
            self.assertTrue(doc["cost"])

    def test_identity(self):
        doc = self._ask("What is this app?")
        self._assert_contract(doc)
        self.assertEqual(doc["confidence"], "confirmed")
        self.assertIn("com.example.synthetic", doc["answer"])

    def test_build(self):
        doc = self._ask("What engine does it use?")
        self._assert_contract(doc)
        self.assertEqual(doc["confidence"],
                         "strongly-indicated")
        self.assertIn("FakeEngine", doc["answer"])

    def test_screens_inventory_and_named(self):
        doc = self._ask("What screens does it have?")
        self._assert_contract(doc)
        self.assertEqual(doc["confidence"], "confirmed")
        doc = self._ask("How do I get to the main screen?")
        self._assert_contract(doc)
        self.assertIn("MainActivity", doc["answer"])

    def test_behaviour_trace(self):
        doc = self._ask("How does the wallet work?")
        self._assert_contract(doc)
        self.assertIn("CoinWallet", doc["answer"])
        self.assertIn("decompile", doc["chain"])

    def test_behaviour_unknown_subject(self):
        doc = self._ask("How does teleportation work?")
        self._assert_contract(doc)
        self.assertEqual(doc["confidence"], "unknown")
        self.assertEqual(doc["reason"], "absent")

    def test_storage(self):
        doc = self._ask("Where are my coins?")
        self._assert_contract(doc)
        self.assertIn("SharedPreferences", doc["answer"])
        doc = self._ask("How is progress saved?")
        self._assert_contract(doc)
        self.assertTrue(any("PrefsStore" in e
                            for e in doc["evidence"]))
        doc = self._ask("What database does it use?")
        self._assert_contract(doc)
        self.assertTrue(any("SQLiteOpenHelper" in e
                            for e in doc["evidence"]),
                        "superclass storage evidence missed: "
                        "%r" % (doc["evidence"],))

    def test_network(self):
        doc = self._ask("What does it talk to?")
        self._assert_contract(doc)
        self.assertTrue(any("api.example.com" in e
                            for e in doc["evidence"]))

    def test_security_and_visibility(self):
        doc = self._ask("Is it protected?")
        self._assert_contract(doc)
        doc = self._ask("Can static analysis see the logic?")
        self._assert_contract(doc)
        self.assertIn("bytecode-listing", doc["answer"])
        self.assertIn("nar-dex-disasm", doc["chain"])

    def test_monetisation(self):
        doc = self._ask("How is it monetised?")
        self._assert_contract(doc)
        self.assertTrue(any("BillingClient" in e
                            for e in doc["evidence"]))

    def test_assets(self):
        doc = self._ask("What assets does it contain?")
        self._assert_contract(doc)
        self.assertEqual(doc["confidence"], "confirmed")

    def test_animation_boundary_names_part4(self):
        doc = self._ask("How is the hero animated?")
        self._assert_contract(doc)
        self.assertIn("Part 4", doc["boundary"])
        # Part 4 has landed: the boundary must scope the
        # identification-level answer to THIS target's
        # evidence, never claim the machinery is unbuilt.
        self.assertNotIn("not built yet", doc["boundary"])
        self.assertEqual(doc["confidence"], "inferred")

    def test_rebuild_boundary_names_blueprint(self):
        if os.path.isfile(os.path.join(
                ROOT, "scripts", "nar-blueprint.py")):
            self.skipTest("blueprint present; fallback path "
                          "not exercised")
        doc = self._ask("How do I rebuild this app?")
        self._assert_contract(doc)
        self.assertIn("nar blueprint", doc["boundary"])

    def test_compare_single_target_is_unknown_absent(self):
        doc = self._ask("What changed between v1 and v2?")
        self._assert_contract(doc)
        self.assertEqual(doc["confidence"], "unknown")
        self.assertEqual(doc["reason"], "absent")
        self.assertIn("second artifact", doc["probe"])

    def test_gaps(self):
        doc = self._ask("What can you NOT tell me, and why?")
        self._assert_contract(doc)
        self.assertTrue(any("coverage gap" in e
                            for e in doc["evidence"]))

    def test_other_fallback_uses_verified_facts(self):
        doc = self._ask("Tell me about the wallet.")
        self._assert_contract(doc)
        self.assertIn("Coins are kept", doc["answer"])

    def test_human_render_has_all_labels(self):
        doc = self._ask("What is this app?")
        text = ask.render_human(doc)
        for label in ("QUESTION:", "ANSWER:", "EVIDENCE:",
                      "CONFIDENCE:", "WHY:", "CHAIN:",
                      "BOUNDARY:"):
            self.assertIn(label, text)
        doc = self._ask("What changed between v1 and v2?")
        text = ask.render_human(doc)
        for label in ("REASON:", "PROBE:", "COST:"):
            self.assertIn(label, text)

    def test_json_validates_against_ask_schema(self):
        schema = json.load(open(os.path.join(
            ROOT, "schemas", "ask.schema.json"),
            encoding="utf-8"))
        for question, _intent in MANDATORY:
            doc = self._ask(question)
            self.assertEqual(
                evidence.validate(doc, schema), [],
                "%r failed ask.schema.json" % question)
            self._assert_contract(doc)

    def test_scripts_answer_validates_against_ask_schema(self):
        # Regression: the scripts intent is a first-class
        # classifier intent (ask.INTENTS, question.schema.json)
        # but was missing from ask.schema.json's intent enum,
        # so every scripts answer document failed the schema.
        schema = json.load(open(os.path.join(
            ROOT, "schemas", "ask.schema.json"),
            encoding="utf-8"))
        doc = self._ask("What scripts does it ship?")
        self.assertEqual(doc["intent"], "scripts")
        self._assert_contract(doc)
        self.assertEqual(evidence.validate(doc, schema), [])

    def test_ask_schema_intents_match_classifier(self):
        schema = json.load(open(os.path.join(
            ROOT, "schemas", "ask.schema.json"),
            encoding="utf-8"))
        enum = schema["properties"]["intent"]["enum"]
        self.assertEqual(set(enum), set(ask.INTENTS))

    def test_case_reuse_via_main(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = ask.main(["What is this app?", self.target,
                           "--case", self.case_dir, "--json"])
        self.assertEqual(rc, 0)
        doc = json.loads(buf.getvalue())
        self.assertEqual(doc["confidence"], "confirmed")


class QuestionLibraryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lib = json.load(open(os.path.join(
            ROOT, "references", "question-library.json"),
            encoding="utf-8"))
        cls.md = open(os.path.join(
            ROOT, "references", "question-library.md"),
            encoding="utf-8").read()

    def test_library_size_and_schema(self):
        self.assertGreaterEqual(
            len(self.lib["questions"]), 250)
        schema = json.load(open(os.path.join(
            ROOT, "schemas", "question.schema.json"),
            encoding="utf-8"))
        self.assertEqual(evidence.validate(self.lib, schema),
                         [])

    def test_every_question_maps_to_modules_and_intent(self):
        for rec in self.lib["questions"]:
            self.assertTrue(rec["modules"],
                            "no serving module: %r" % rec)
            for module in rec["modules"]:
                self.assertIn(module, KNOWN_MODULES,
                              "unknown module %r" % module)
            self.assertEqual(
                ask.classify_intent(rec["question"]),
                rec["intent"],
                "classifier disagrees with library: %r"
                % rec["question"])
            self.assertTrue(rec["answer_shape"])

    def test_all_intents_covered(self):
        intents = {r["intent"] for r in self.lib["questions"]}
        self.assertEqual(intents, set(ask.INTENTS))

    def test_md_rendering_in_sync(self):
        md_questions = re.findall(r"^- Q: (.+)$", self.md,
                                  re.M)
        json_questions = [r["question"]
                          for r in self.lib["questions"]]
        self.assertEqual(md_questions, json_questions)
        self.assertGreaterEqual(len(md_questions), 250)

    def test_mandatory_questions_in_library(self):
        have = {r["question"] for r in self.lib["questions"]}
        for question, _intent in MANDATORY:
            if question in ("How is X stored?",
                            "How does X work?",
                            "How is X animated?",
                            "How do I rebuild X?",
                            "How do I get to screen X?"):
                continue  # template forms; concrete
                # instances are in the library
            self.assertIn(question, have)


class ForbiddenPhrasingTest(unittest.TestCase):
    def test_no_bare_unknown_anywhere_in_source_answers(self):
        # The builders must never emit a bare refusal as an
        # answer string; the unknown path always carries the
        # full explanation + REASON/PROBE/COST (asserted in
        # the contract tests above).
        src = open(os.path.join(ROOT, "scripts", "nar-ask.py"),
                   encoding="utf-8").read()
        for phrase in ("I don't know", "cannot determine"):
            # allowed only inside the FORBIDDEN list itself
            occurrences = src.lower().count(phrase)
            self.assertLessEqual(occurrences, 1,
                                 "%r appears %d times"
                                 % (phrase, occurrences))


if __name__ == "__main__":
    unittest.main()
