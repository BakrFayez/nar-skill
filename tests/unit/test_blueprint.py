"""Unit tests: the rebuild layer (Part 8, nar-blueprint.py).

Pins: all 9 spec files emitted on a synthetic mini case;
every features.md bullet cited-or-inferred (automated
check); the Part 0.3 boundary line appearing verbatim
exactly once per spec; an evidence-free section rendering
NOT RECOVERABLE instead of being skipped; unknowns.json
validating against schemas/blueprint.schema.json;
network.md never printing an unredacted secret-shaped
value (planted fixture); unrecoverable.md non-empty with
its fixed categories; no credit line in any output.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from narlib import evidence  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "nar_blueprint",
    os.path.join(ROOT, "scripts", "nar-blueprint.py"))
bp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bp)

PLANTED_SECRET = "PLANTEDSECRETVALUE123"
CREDIT_PHRASE = "Research by " + "Bakr Fayez"


def _write(path, doc):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)


def _prop(value):
    return {"value": value, "provenance": "synthetic test",
            "confidence": "high", "fact_class": "observed",
            "verification_status": "CONFIRMED"}


def make_mini_case(case_dir, target_path, omit=()):
    with open(target_path, "wb") as fh:
        fh.write(b"synthetic blueprint test target")
    target_sha = bp.sha256_of(target_path)
    docs = {
        "case.json": {
            "case_id": "synthetic", "nar_version": "2.6.2",
            "input": {"path": target_path,
                      "sha256": target_sha, "size_bytes": 29}},
        "application.json": {
            "properties": {
                "package": _prop("com.example.synthetic"),
                "app_label": _prop("Synthetic"),
                "version_name": _prop("1.0"),
                "min_sdk": _prop("24"),
                "target_sdk": _prop("34"),
                "abis": _prop(["arm64-v8a"])}},
        "fingerprint.json": {
            "properties": {"abis": _prop(["arm64-v8a"])}},
        "manifest.json": {
            "package": "com.example.synthetic",
            "component_counts": {"activity": 1, "service": 0,
                                 "receiver": 0, "provider": 0,
                                 "total": 1},
            "permission_count": 2},
        "permissions.json": {
            "package": "com.example.synthetic",
            "launcher_activity": "com.example.MainActivity",
            "permissions": [
                {"name": "android.permission.INTERNET"},
                {"name": "com.android.vending.CHECK_LICENSE"}],
            "components": {
                "activity": [{
                    "name": "com.example.MainActivity",
                    "exported": True,
                    "intent_filters": [{
                        "actions": ["android.intent.action.MAIN"],
                        "data": []}]}],
                "service": [], "receiver": [], "provider": []},
            "component_counts": {"activity": 1, "service": 0,
                                 "receiver": 0, "provider": 0}},
        "engines.json": {"verdicts": [{
            "engine": "FakeEngine", "detected": True,
            "confidence": "high", "score": 90,
            "version": "1.0"}]},
        "frameworks.json": {
            "verdicts": [],
            "markers": {"framework_markers": ["Kotlin"],
                        "engine_versions": {}}},
        "dex.json": {
            "dex_files": [{"name": "classes.dex", "classes": [
                {"class": "Lcom/example/CoinWallet;",
                 "methods": [{"name": "saveCoins"}],
                 "fields": [{"name": "balance"}]},
                {"class": "Landroid/content/"
                          "SharedPreferences;",
                 "methods": [{"name": "edit"}], "fields": []},
                {"class": "Lcom/example/AppDbHelper;",
                 "superclass": "Landroid/database/sqlite/"
                               "SQLiteOpenHelper;",
                 "methods": [{"name": "onCreate"}],
                 "fields": []}]}],
            "totals": {"classes": 3, "methods": 3,
                       "fields": 1}},
        "native.json": {"libraries": [{
            "name": "arm64-v8a/libgame.so",
            "elf_class": "ELF64", "arch": "AArch64",
            "needed": ["libc.so"], "has_symtab": False}]},
        "assets.json": {
            "total_assets": 2, "total_bytes": 100,
            "by_category": {"texture": 1, "data": 1},
            "assets": [
                {"path": "assets/hero.png",
                 "type": "png-image", "size_bytes": 60},
                {"path": "assets/save_game.sav",
                 "type": "data", "size_bytes": 40}],
            "duplicates": [],
            "largest": [
                {"path": "assets/hero.png",
                 "type": "png-image", "size_bytes": 60}]},
        "endpoints.json": {
            "endpoints": [{
                "url": "https://user:pw@api.example.com/v1/"
                       "coins?api_key=" + PLANTED_SECRET +
                       "&mode=full",
                "host": "api.example.com", "kind": "api",
                "classification": "third-party",
                "sources": ["classes.dex"]}],
            "hosts": ["api.example.com"],
            "api_hosts": ["api.example.com"],
            "network_libraries": ["OkHttp"],
            "classification_counts": {"third-party": 1}},
        "network-analysis.json": {
            "endpoint_count": 1,
            "classification_counts": {"third-party": 1},
            "cleartext": {"base_cleartext_permitted": False,
                          "pin_set_present": True}},
        "security-findings.json": {
            "findings": [], "severity_counts": {}},
        "report.json": {
            "protections": [{
                "category": "licensing_drm",
                "name": "Play License Verification (LVL)",
                "evidence": ["DEX string licensing x2"]}],
            "limitations": ["Static analysis only."]},
        "decompile.json": {
            "capability": "java-decompile",
            "chain": ["jadx", "baksmali", "nar-dex-disasm"],
            "attempts": [
                {"rung": "jadx", "status": "failed",
                 "classification": "NOT_INSTALLED",
                 "reason": "NOT_INSTALLED: jadx missing"},
                {"rung": "nar-dex-disasm", "status": "ok",
                 "classification": None, "reason": None}],
            "served_by": "nar-dex-disasm",
            "fidelity": "bytecode-listing",
            "caveats": ["bytecode listing, not source"]},
        "investigation.json": {
            "verified_facts": [{
                "fact": "Coins are kept in the wallet",
                "kind": "behaviour", "subject": "wallet",
                "detail": "CoinWallet.saveCoins writes the "
                          "balance",
                "verification_status": "CONFIRMED"}],
            "unknowns": [{
                "question": "What happens at runtime?",
                "reason": "Static data cannot observe "
                          "execution."}]},
        "graph.json": {"nodes": [], "edges": [],
                       "counts": {"nodes": 0, "edges": 0}},
    }
    for name, doc in docs.items():
        if name not in omit:
            _write(os.path.join(case_dir, name), doc)
    return target_sha


class BlueprintMiniCaseTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="nar-bp-test-")
        cls.case_dir = os.path.join(cls.tmp, "case")
        os.makedirs(cls.case_dir)
        cls.target = os.path.join(cls.tmp, "target.apk")
        make_mini_case(cls.case_dir, cls.target)
        cls.out = os.path.join(cls.tmp, "spec")
        rc = bp.main([cls.target, "--out", cls.out,
                      "--case", cls.case_dir])
        assert rc == 0

    def _read(self, name):
        with open(os.path.join(self.out, name),
                  encoding="utf-8") as fh:
            return fh.read()

    def test_all_nine_files_emitted(self):
        for name in bp.SPEC_FILES:
            path = os.path.join(self.out, name)
            self.assertTrue(os.path.isfile(path), name)
            self.assertGreater(os.path.getsize(path), 0, name)

    def test_features_every_bullet_cited_or_inferred(self):
        bullets = [ln.strip() for ln in
                   self._read("features.md").splitlines()
                   if ln.strip().startswith("- ")]
        self.assertGreater(len(bullets), 3)
        for b in bullets:
            self.assertTrue(
                "(evidence:" in b or "inferred" in b,
                "uncited feature bullet: %s" % b[:120])

    def test_features_bullets_carry_trigger_effect(self):
        text = self._read("features.md")
        self.assertIn("Trigger:", text)
        self.assertIn("Effect:", text)
        self.assertIn("Implementing components:", text)

    def test_boundary_line_verbatim_exactly_once(self):
        total = 0
        for name in bp.SPEC_FILES:
            total += self._read(name).count(bp.BOUNDARY_LINE)
        self.assertEqual(total, 1)
        self.assertIn(bp.BOUNDARY_LINE,
                      self._read("features.md"))

    def test_unknowns_validates_against_schema(self):
        doc = json.loads(self._read("unknowns.json"))
        schema = json.load(open(os.path.join(
            ROOT, "schemas", "blueprint.schema.json"),
            encoding="utf-8"))
        self.assertEqual(evidence.validate(doc, schema), [])
        self.assertTrue(doc["unknowns"])
        for u in doc["unknowns"]:
            self.assertIn(u["reason"], bp.UNKNOWN_REASONS)
            self.assertTrue(u["probe"])

    def test_network_redacts_planted_secret(self):
        text = self._read("network.md")
        self.assertNotIn(PLANTED_SECRET, text)
        self.assertNotIn("user:pw@", text)
        self.assertIn("REDACTED", text)
        self.assertIn("api.example.com", text)

    def test_no_output_contains_planted_secret(self):
        for name in bp.SPEC_FILES:
            self.assertNotIn(PLANTED_SECRET, self._read(name),
                             name)

    def test_unrecoverable_nonempty_with_categories(self):
        text = self._read("unrecoverable.md")
        for heading in ("## Server-side logic",
                        "## Encrypted payloads",
                        "## Stripped native code",
                        "## Licence checks",
                        "## Third-party internals",
                        "## Decompile chain outcome"):
            self.assertIn(heading, text)
        self.assertIn("libgame.so", text)
        self.assertIn("nar-dex-disasm", text)
        self.assertIn("bytecode-listing", text)
        self.assertIn("Probe:", text)

    def test_flows_launcher_first(self):
        text = self._read("flows.md")
        self.assertLess(
            text.index("MainActivity"),
            text.index("## Background"))
        self.assertIn("not statically knowable", text)

    def test_assets_identification_fidelity_labelled(self):
        text = self._read("assets.md")
        self.assertIn("Part 4", text)
        self.assertIn("identification", text)

    def test_build_order_steps_have_acceptance(self):
        text = self._read("build-order.md")
        steps = [ln for ln in text.splitlines()
                 if ln.strip().startswith("- **Step")]
        self.assertGreaterEqual(len(steps), 4)
        for s in steps:
            self.assertIn("Acceptance:", s)
            self.assertIn("(evidence:", s)

    def test_no_credit_line_in_outputs(self):
        for name in bp.SPEC_FILES:
            self.assertNotIn(CREDIT_PHRASE, self._read(name),
                             name)


class BlueprintNotRecoverableTest(unittest.TestCase):

    def _run(self, omit):
        tmp = tempfile.mkdtemp(prefix="nar-bp-nr-")
        case_dir = os.path.join(tmp, "case")
        os.makedirs(case_dir)
        target = os.path.join(tmp, "target.apk")
        make_mini_case(case_dir, target, omit=omit)
        out = os.path.join(tmp, "spec")
        rc = bp.main([target, "--out", out,
                      "--case", case_dir])
        assert rc == 0
        texts = {}
        for name in bp.SPEC_FILES:
            with open(os.path.join(out, name),
                      encoding="utf-8") as fh:
                texts[name] = fh.read()
        return texts

    def test_missing_network_companions_not_recoverable(self):
        texts = self._run(omit=("endpoints.json",
                                "network-analysis.json"))
        self.assertIn("## NOT RECOVERABLE",
                      texts["network.md"])
        for name in bp.SPEC_FILES:
            self.assertTrue(texts[name].strip(), name)

    def test_missing_assets_companion_not_recoverable(self):
        texts = self._run(omit=("assets.json",))
        self.assertIn("## NOT RECOVERABLE", texts["assets.md"])

    def test_missing_manifest_companions_not_recoverable(self):
        texts = self._run(omit=("permissions.json",
                                "manifest.json"))
        self.assertIn("## NOT RECOVERABLE", texts["flows.md"])


class BlueprintCliTest(unittest.TestCase):

    def test_missing_target_exit_2(self):
        out = os.path.join(tempfile.mkdtemp(), "spec")
        self.assertEqual(
            bp.main(["/nonexistent/target.apk",
                     "--out", out]), 2)

    def test_safe_url_malformed_port_does_not_crash(self):
        # A format-string URL harvested from native strings
        # (real-corpus find): its "port" is not numeric and
        # urlsplit's .port raises ValueError.
        safe = bp.safe_url("http://host.example:%d%s/x"
                           "?token=abc")
        self.assertNotIn("abc", safe)
        self.assertIn("REDACTED", safe)

    def test_safe_url_redacts_values(self):
        safe = bp.safe_url(
            "https://u:p@h.example.com/a?token=abc&x=1")
        self.assertNotIn("abc", safe)
        self.assertNotIn("u:p@", safe)
        self.assertIn("token=REDACTED", safe)
        self.assertIn("/a?", safe)


if __name__ == "__main__":
    unittest.main()
