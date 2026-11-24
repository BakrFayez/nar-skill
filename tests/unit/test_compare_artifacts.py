"""Unit tests: nar-compare named artifacts (Evolution
Phase 7).

feature_map() / version_diff_md() / write_artifacts()
project a compare() report into comparison.json +
feature-map.json + version-diff.md. Tested here as pure
functions over a fabricated report with known deltas
(added permission, method-count delta, endpoint change,
a signing-file change that must be separated from
content changes by the labeled build-noise heuristic);
the planted-pair e2e runs the real tools end to end.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from narlib import evidence  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(ROOT, "scripts", filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fake_report():
    return {
        "old": {"file": "app-v1.apk", "sha256": "a" * 64,
                "badging": {"package": "com.example.app",
                            "version_name": "1.0",
                            "version_code": "1"}},
        "new": {"file": "app-v2.apk", "sha256": "b" * 64,
                "badging": {"package": "com.example.app",
                            "version_name": "2.0",
                            "version_code": "2"}},
        "identical_files": False,
        "diff": {
            "size_delta_bytes": 120, "entry_count_delta": 1,
            "identity_changed": True, "manifest_changed": False,
            "permissions_added": ["android.permission.VIBRATE"],
            "permissions_removed": [],
            "dex": {"added": [], "removed": [], "changed": [],
                    "totals_delta": {"method_count": 2,
                                     "class_count": 0},
                    "total_bytes_delta": 40},
            "native_libs": {"added": [], "removed": [],
                            "changed": []},
            "resources_arsc": {"status": "changed", "old": {},
                               "new": {}},
            "counts_delta": {"assets": 1, "resources": 0,
                             "other": 0, "native_libs": 0},
            "signing_files": {
                "added": [], "removed": [],
                "changed": [{"name": "META-INF/CERT.RSA",
                             "old": {}, "new": {}}]},
            "entries": {
                "added": ["assets/new.png"], "removed": [],
                "changed": ["classes.dex", "META-INF/CERT.RSA"],
                "added_count": 1, "removed_count": 0,
                "changed_count": 2},
        },
        "extended": {
            "similarity": {"entry_jaccard_identical": 0.5,
                           "identical_entries": 2,
                           "total_entries_union": 4},
            "assets": {"added": ["assets/new.png"], "removed": [],
                       "changed": [], "added_count": 1,
                       "removed_count": 0, "changed_count": 0},
            "classes": {"added_count": 1, "removed_count": 0,
                        "added_sample": ["Lcom/example/B;"],
                        "removed_sample": []},
            "endpoints": {"added": ["https://api.example.com/v2"],
                          "removed": ["https://api.example.com/v1"],
                          "added_count": 1, "removed_count": 1},
            "engine_versions": {"old": {}, "new": {},
                                "changed": False},
            "severity": [{"level": "medium",
                          "change": "permission added: "
                                    "android.permission.VIBRATE",
                          "reason": "capability surface grew"}],
            "overall_severity": "medium",
            "notes": [],
        },
    }


class CompareArtifactsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cmp = _load("nar_compare_for_test", "nar-compare.py")

    def test_feature_map_validates_and_carries_deltas(self):
        fmap = self.cmp.feature_map(fake_report())
        with open(os.path.join(
                ROOT, "schemas",
                "compare-feature-map.schema.json"),
                encoding="utf-8") as fh:
            schema = json.load(fh)
        self.assertEqual(evidence.validate(fmap, schema), [])
        dims = fmap["dimensions"]
        self.assertEqual(dims["permissions"]["added"],
                         ["android.permission.VIBRATE"])
        self.assertEqual(dims["dex"]["totals_delta"]
                         ["method_count"], 2)
        self.assertEqual(dims["endpoints"]["added"],
                         ["https://api.example.com/v2"])
        self.assertEqual(dims["identity"]["fields"]
                         ["version_name"]["new"], "2.0")
        self.assertEqual(fmap["overall_severity"], "medium")

    def test_build_noise_separates_signing_churn(self):
        fmap = self.cmp.feature_map(fake_report())
        noise = fmap["build_noise"]
        self.assertIn("heuristic", noise["policy"])
        self.assertEqual(noise["signing_files_in_entry_diff"], 1)
        # classes.dex is content; CERT.RSA is signing churn.
        self.assertEqual(
            noise["content_changed_excluding_signing"], 1)
        self.assertEqual(
            fmap["dimensions"]["entries"]
            ["content_changed_excluding_signing"],
            ["classes.dex"])
        # Nothing is hidden: the signing dimension keeps it.
        self.assertEqual(fmap["dimensions"]["signing"]["changed"],
                         ["META-INF/CERT.RSA"])

    def test_version_diff_md_renders_same_deltas(self):
        fmap = self.cmp.feature_map(fake_report())
        md = self.cmp.version_diff_md(fmap)
        self.assertIn("# Version diff: app-v1.apk → app-v2.apk", md)
        self.assertIn("android.permission.VIBRATE", md)
        self.assertIn("https://api.example.com/v2", md)
        self.assertIn("heuristic", md)

    def test_write_artifacts_round_trip(self):
        report = fake_report()
        with tempfile.TemporaryDirectory() as td:
            paths = self.cmp.write_artifacts(report, td)
            self.assertEqual(sorted(os.listdir(td)),
                             ["comparison.json", "feature-map.json",
                              "version-diff.md"])
            with open(paths["comparison.json"],
                      encoding="utf-8") as fh:
                loaded = json.load(fh)
            self.assertEqual(loaded["old"]["file"], "app-v1.apk")
            with open(paths["feature-map.json"],
                      encoding="utf-8") as fh:
                fmap = json.load(fh)
        self.assertEqual(fmap["kind"], "version-feature-map")


if __name__ == "__main__":
    unittest.main()
