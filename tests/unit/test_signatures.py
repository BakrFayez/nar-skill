"""Unit tests: the versioned protection-signature database
(Evolution Phase 5).

The signature set used to live as Python literals inside
nar-triage.py. It now ships as scripts/protection-signatures.json
and is loaded via narlib.signatures. These tests pin:

- the database loads and validates, with its version field;
- the loaded structures are behaviorally identical to the
  original code-embedded set — the canonical digest below
  was computed from the pre-extraction literals, so any
  drift in a pattern, matcher, note, or threshold fails;
- a malformed database is a hard error, never a fallback;
- nar-triage's module-level constants ARE the loaded
  database (no second copy can drift).
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from narlib import signatures  # noqa: E402

# Canonical digest of the signature set as it existed when
# embedded in nar-triage.py (computed 2026-11-24 from the
# literals, before extraction). A deliberate signature
# change updates the database AND this pin in one commit.
PINNED_DIGEST = ("634f2d2ece0e35fbc9a1f5d95b467bbd04948723b5cb97a"
                 "67de0b4fa429d9c8f")


def _load_triage():
    spec = importlib.util.spec_from_file_location(
        "nar_triage_for_test", os.path.join(ROOT, "scripts",
                                            "nar-triage.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SignatureDatabaseTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sig = signatures.load_signatures()

    def test_version_and_schema(self):
        self.assertEqual(self.sig["database_version"], "1.0.0")
        self.assertEqual(self.sig["schema"], 1)

    def test_counts(self):
        counts = self.sig["counts"]
        self.assertEqual(counts["categories"], 7)
        self.assertEqual(counts["packers"], 11)
        self.assertEqual(counts["rasp_markers"], 6)
        self.assertEqual(counts["licensing_markers"], 1)
        self.assertEqual(counts["widevine_dex_patterns"], 4)

    def test_digest_matches_pre_extraction_literals(self):
        self.assertEqual(signatures.canonical_digest(self.sig),
                         PINNED_DIGEST)

    def test_spot_values(self):
        packers = {name: (m, d, s) for name, m, d, s
                   in self.sig["packer_markers"]}
        matchers, dex, subs = packers["Pairip (Google)"]
        self.assertEqual(matchers, [("exact", "libpairipcore.so")])
        self.assertEqual(dex, [b"com/pairip/"])
        self.assertEqual(subs, [])
        wv = self.sig["widevine"]
        self.assertEqual(wv["uuid_string"],
                         b"edef8ba9-79d6-4ace-a3c8-27dcd51d21ed")
        self.assertEqual(len(wv["uuid_raw"]), 16)
        self.assertEqual(wv["dex_patterns"][0], wv["uuid_string"])
        self.assertEqual(self.sig["stub_dex_max_bytes"], 100_000)
        self.assertIn(b"StubApp;", self.sig["stub_descriptor_re"].pattern)

    def test_category_order(self):
        self.assertEqual(self.sig["categories"][0][0],
                         "commercial_packer")
        self.assertEqual(
            self.sig["category_order"]["licensing_drm"], 4)

    def _write_db(self, doc):
        fh = tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(doc, fh)
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        return fh.name

    def test_missing_file_is_hard_error(self):
        with self.assertRaises(signatures.SignaturesError):
            signatures.load_signatures("/nonexistent/db.json")

    def test_wrong_schema_is_hard_error(self):
        path = self._write_db({"schema": 99,
                               "database_version": "9.9.9"})
        with self.assertRaises(signatures.SignaturesError):
            signatures.load_signatures(path)

    def test_bad_matcher_kind_is_hard_error(self):
        doc = json.loads(open(signatures.default_db_path(),
                              encoding="utf-8").read())
        doc["packers"][0]["so_matchers"] = [
            {"kind": "glob", "value": "lib*"}]
        with self.assertRaises(signatures.SignaturesError):
            signatures.load_signatures(self._write_db(doc))

    def test_triage_constants_are_the_database(self):
        triage = _load_triage()
        self.assertEqual(triage.PACKER_MARKERS,
                         self.sig["packer_markers"])
        self.assertEqual(triage.RASP_DEX_MARKERS,
                         self.sig["rasp_dex_markers"])
        self.assertEqual(triage.WIDEVINE_DEX_PATTERNS,
                         self.sig["widevine"]["dex_patterns"])
        self.assertEqual(triage.PROTECTION_SIGNATURES_VERSION,
                         self.sig["database_version"])


if __name__ == "__main__":
    unittest.main()
