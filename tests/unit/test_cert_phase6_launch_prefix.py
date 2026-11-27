"""Unit tests: jar-resolved tools launch through java -jar
(Phase 6 certification finding P6-01).

registry.probe represents a jar-resolved tool's path as a
"jar:<path>" launch spec (jar_env_var / jar_globs / kind
"jar" resolution). nar-network's parse_nsc passed that
string to subprocess as the executable, so the apktool
decode — and with it the whole network-security-config
analysis — failed with Errno 2 for every install that
provides apktool as a jar, including the documented
NAR_APKTOOL_JAR route. registry.launch_prefix is the
translation every consumer must use; these tests pin it
and pin parse_nsc's use of it.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from narlib import registry  # noqa: E402


def _load_network():
    spec = importlib.util.spec_from_file_location(
        "nar_network_for_test_p6", os.path.join(ROOT, "scripts",
                                                "nar-network.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LaunchPrefixTest(unittest.TestCase):
    def test_executable_path_runs_directly(self):
        self.assertEqual(
            registry.launch_prefix({"path": "/usr/bin/apktool"}),
            ["/usr/bin/apktool"])

    def test_jar_path_launches_through_java(self):
        with mock.patch.object(registry, "_find_java",
                               return_value="/opt/jdk/bin/java"):
            self.assertEqual(
                registry.launch_prefix(
                    {"path": "jar:/tools/apktool.jar"}),
                ["/opt/jdk/bin/java", "-jar", "/tools/apktool.jar"])

    def test_jar_path_without_java_is_none(self):
        with mock.patch.object(registry, "_find_java",
                               return_value=None):
            self.assertIsNone(
                registry.launch_prefix(
                    {"path": "jar:/tools/apktool.jar"}))

    def test_missing_path_is_none(self):
        self.assertIsNone(registry.launch_prefix({"path": None}))
        self.assertIsNone(registry.launch_prefix({}))
        self.assertIsNone(registry.launch_prefix(None))


MANIFEST = (
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android"'
    ' package="com.example.app"><application'
    ' android:usesCleartextTraffic="false"'
    ' android:networkSecurityConfig="@xml/netsec"/></manifest>')
NSC = (
    '<network-security-config><base-config'
    ' cleartextTrafficPermitted="true">'
    '<trust-anchors><certificates src="system"/></trust-anchors>'
    '</base-config><domain-config>'
    '<domain includeSubdomains="true">example.com</domain>'
    '</domain-config></network-security-config>')


class _FakeCompleted:
    returncode = 0
    stdout = ""
    stderr = ""


class ParseNscLaunchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.net = _load_network()

    def _run_parse(self, probe_result, java="/opt/jdk/bin/java"):
        """parse_nsc with probe/subprocess stubbed; the fake
        decode writes the manifest + NSC the real apktool
        would have produced. Returns (result, note, argv)."""
        captured = {}

        def fake_run(argv, **kwargs):
            captured["argv"] = argv
            out_dir = argv[argv.index("-o") + 1]
            os.makedirs(os.path.join(out_dir, "res", "xml"),
                        exist_ok=True)
            with open(os.path.join(out_dir, "AndroidManifest.xml"),
                      "w", encoding="utf-8") as fh:
                fh.write(MANIFEST)
            with open(os.path.join(out_dir, "res", "xml",
                                   "netsec.xml"),
                      "w", encoding="utf-8") as fh:
                fh.write(NSC)
            return _FakeCompleted()

        net = self.net
        with tempfile.TemporaryDirectory() as work, \
                mock.patch.object(net.reg_mod, "probe",
                                  return_value=probe_result), \
                mock.patch.object(registry, "_find_java",
                                  return_value=java), \
                mock.patch.object(net.subprocess, "run",
                                  side_effect=fake_run):
            result, note = net.parse_nsc("/fake/app.apk", work)
        return result, note, captured.get("argv")

    def test_jar_resolved_apktool_decodes_via_java(self):
        result, note, argv = self._run_parse(
            {"available": True, "path": "jar:/fake/apktool.jar"})
        self.assertIsNone(note)
        # The launch spec must be translated: java -jar <jar>,
        # never the "jar:..." string as the executable (the
        # pre-fix behaviour, which died with Errno 2).
        self.assertEqual(argv[:3], ["/opt/jdk/bin/java", "-jar",
                                    "/fake/apktool.jar"])
        self.assertEqual(argv[3:7], ["d", "-f", "--no-src", "-o"])
        self.assertEqual(argv[-1], "/fake/app.apk")
        # And the decode output is actually parsed.
        self.assertIsNotNone(result)
        self.assertEqual(result["nsc_resource"], "netsec")
        self.assertTrue(result["base_cleartext_permitted"])
        self.assertEqual(result["domain_configs"], ["example.com"])
        self.assertEqual(result["trust_anchors"], ["system"])
        self.assertFalse(result["uses_cleartext_traffic"])

    def test_executable_apktool_runs_directly(self):
        result, note, argv = self._run_parse(
            {"available": True, "path": "/usr/bin/apktool"})
        self.assertIsNone(note)
        self.assertEqual(argv[0], "/usr/bin/apktool")
        self.assertNotIn("-jar", argv)
        self.assertIsNotNone(result)

    def test_jar_without_java_is_a_named_refusal(self):
        result, note, argv = self._run_parse(
            {"available": True, "path": "jar:/fake/apktool.jar"},
            java=None)
        self.assertIsNone(result)
        self.assertIsNone(argv)  # nothing was spawned
        self.assertIn("Java", note)


if __name__ == "__main__":
    unittest.main()
