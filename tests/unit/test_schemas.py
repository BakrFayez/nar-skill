"""Unit tests: schema layer integrity (2.5.1 regression guards).

The 2.5.0 release shipped two schemas that were not parseable
JSON at all (engine, timeline) and a report schema describing a
report shape the tool no longer writes — because no test parsed
every schema or validated a real generated report against its
schema. These tests close that hole:

- every file in schemas/ parses as JSON and is a schema object;
- a real case generated from the demo fixture validates
  against the schemas for report / engines / dex / native;
- the nar-dex sidecars (classes / methods) validate against
  their schemas;
- the runtime timeline template validates against the
  timeline schema.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SCRIPTS = os.path.join(ROOT, "scripts")
SCHEMAS = os.path.join(ROOT, "schemas")
sys.path.insert(0, SCRIPTS)

from narlib import evidence  # noqa: E402


def _schema(name):
    with open(os.path.join(SCHEMAS, name), encoding="utf-8") as fh:
        return json.load(fh)


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(SCRIPTS, filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _demo():
    fixtures = os.environ.get(
        "NAR_FIXTURES",
        os.path.expanduser("~/workspace/nar-e2e-fixtures"))
    return os.path.join(fixtures, "demo", "NarDemo.apk")


class SchemaParseTest(unittest.TestCase):
    def test_every_schema_file_parses(self):
        names = [n for n in sorted(os.listdir(SCHEMAS))
                 if n.endswith(".json")]
        self.assertGreater(len(names), 0)
        for name in names:
            with open(os.path.join(SCHEMAS, name),
                      encoding="utf-8") as fh:
                doc = json.load(fh)  # raises on the 2.5.0 defect
            self.assertIsInstance(doc, dict, name)
            self.assertIn("$schema", doc, name)
            self.assertEqual(doc.get("type"), "object", name)


class GeneratedCaseSchemaTest(unittest.TestCase):
    """Validate documents from a real nar-analyze run on the
    demo fixture against their shipped schemas."""

    @classmethod
    def setUpClass(cls):
        cls.demo = _demo()
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
                f"nar-analyze failed on demo fixture: {proc.stderr[-500:]}")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _validate(self, relpath, schema_name):
        with open(os.path.join(self.case, relpath),
                  encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertEqual(
            evidence.validate(doc, _schema(schema_name)), [],
            f"{relpath} does not validate against {schema_name}")

    def test_report_validates(self):
        self._validate("report.json", "report.schema.json")

    def test_engines_validates(self):
        self._validate("engines.json", "engine.schema.json")

    def test_dex_validates(self):
        self._validate("dex.json", "dex.schema.json")

    def test_native_validates(self):
        self._validate("native.json", "native.schema.json")


class DexSidecarSchemaTest(unittest.TestCase):
    def test_classes_and_methods_validate(self):
        demo = _demo()
        if not os.path.isfile(demo):
            self.skipTest("demo fixture absent")
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "dex")
            proc = subprocess.run(
                [sys.executable, os.path.join(SCRIPTS, "nar-dex.py"),
                 demo, "--out", out, "--json"],
                capture_output=True, text=True, timeout=600)
            self.assertEqual(proc.returncode, 0, proc.stderr[-500:])
            for relpath, schema_name in (
                    ("classes.json", "dex-classes.schema.json"),
                    ("methods.json", "dex-methods.schema.json")):
                with open(os.path.join(out, relpath),
                          encoding="utf-8") as fh:
                    doc = json.load(fh)
                self.assertEqual(
                    evidence.validate(doc, _schema(schema_name)), [],
                    f"{relpath} does not validate against {schema_name}")


class TimelineSchemaTest(unittest.TestCase):
    def test_template_validates_against_schema(self):
        runtime = _load("nar_runtime_for_schema_test", "nar-runtime.py")
        doc = runtime.timeline_template()
        self.assertEqual(
            evidence.validate(doc, _schema("timeline.schema.json")),
            [])


if __name__ == "__main__":
    unittest.main()
