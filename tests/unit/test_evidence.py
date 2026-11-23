"""Unit tests: narlib.evidence schema validation + builders."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..",
                                "scripts"))
from narlib import evidence  # noqa: E402


class EvidenceTest(unittest.TestCase):
    def test_result_envelope(self):
        r = evidence.make_result("dex", "nar-dex", "2.0.0",
                                 "app.apk", {"classes": 3})
        self.assertEqual(r["fact_class"], "observed")
        self.assertEqual(r["status"], "ok")
        with self.assertRaises(ValueError):
            evidence.make_result("dex", "nar-dex", "2.0.0", "x", {},
                                 fact_class="proven")

    def test_finding_shape(self):
        f = evidence.make_finding(
            "NAR-SEC-001", "Example", "high", "medium",
            "com.example/.Main", "AndroidManifest.xml", "evidence",
            "explanation", "impact", "remediation")
        self.assertEqual(f["severity"], "high")
        with self.assertRaises(ValueError):
            evidence.make_finding("NAR-SEC-002", "X", "fatal",
                                  "high", "c", "p", "e", "x", "i",
                                  "r")

    def test_validator_accepts_and_rejects(self):
        schema = {
            "type": "object",
            "required": ["a"],
            "properties": {
                "a": {"type": "string", "pattern": "^x"},
                "b": {"type": "integer", "minimum": 2},
                "c": {"enum": ["p", "q"]},
            },
            "additionalProperties": False,
        }
        self.assertEqual(evidence.validate({"a": "xyz", "b": 3,
                                            "c": "p"}, schema), [])
        self.assertTrue(evidence.validate({"b": 3}, schema))
        self.assertTrue(evidence.validate({"a": "zz"}, schema))
        self.assertTrue(evidence.validate({"a": "x", "b": 1},
                                          schema))
        self.assertTrue(evidence.validate({"a": "x", "c": "z"},
                                          schema))
        self.assertTrue(evidence.validate({"a": "x", "zz": 1},
                                          schema))

    def test_validator_ref(self):
        schema = {
            "type": "object",
            "definitions": {
                "item": {"type": "object", "required": ["n"],
                         "properties": {"n": {"type": "string"}}},
            },
            "properties": {"items": {"type": "array",
                                     "items": {"$ref":
                                               "#/definitions/item"}}},
        }
        self.assertEqual(
            evidence.validate({"items": [{"n": "a"}]}, schema), [])
        self.assertTrue(
            evidence.validate({"items": [{"n": 1}]}, schema))


if __name__ == "__main__":
    unittest.main()
