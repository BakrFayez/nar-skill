"""Unit tests: runtime session records + finding
verification statuses (Evolution Phase 6).

Session records: the plan/status flows persist a
structured record (session/device identity, tool probes,
start/stop, events, evidence paths, errors) that validates
against schemas/runtime-session.schema.json. Offline: the
device snapshot is a recorded input, and the record must
carry its verification label unchanged — a record created
with no device attached still says
IMPLEMENTED_BUT_UNVERIFIED.

Findings: make_finding validates verification_status
against the Phase 8 vocabulary; nar-security's findings
all carry one, and findings written before the field
existed still validate against the schema (the field is
in properties, deliberately not in required).
"""
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from narlib import VERIFICATION_STATUSES, evidence  # noqa: E402


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


NO_DEVICE = {
    "adb": {"available": True, "version": "34.0.0",
            "path": "/sdk/adb"},
    "frida": {"available": True, "version": "17.27.4",
              "path": "/venv/frida"},
    "devices": [], "device_error": None,
    "verification_status": "IMPLEMENTED_BUT_UNVERIFIED",
}
ONE_DEVICE = dict(NO_DEVICE)
ONE_DEVICE["devices"] = [{"serial": "emulator-5554",
                          "model": "sdk_phone", "android": "8.0.0"}]
ONE_DEVICE["verification_status"] = "verified-live"


class SessionRecordTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rt = _load("nar_runtime_for_test", "nar-runtime.py")

    def test_status_session_validates(self):
        record = self.rt.new_session("status", NO_DEVICE)
        self.rt.close_session(record, [("status-probe", "test")])
        self.assertEqual(evidence.validate(
            record, _schema("runtime-session.schema.json")), [])
        self.assertTrue(record["session_id"].startswith("nar-rt-"))
        self.assertFalse(record["device"]["attached"])
        # The honest label survives recording.
        self.assertEqual(record["device"]["verification_status"],
                         "IMPLEMENTED_BUT_UNVERIFIED")
        self.assertLessEqual(record["started_at"],
                             record["stopped_at"])
        self.assertEqual(record["tools"]["frida"]["version"],
                         "17.27.4")

    def test_plan_session_events_and_target_hash(self):
        with tempfile.NamedTemporaryFile(
                suffix=".apk", delete=False) as fh:
            fh.write(b"PK\x03\x04 session target")
            target = fh.name
        self.addCleanup(os.unlink, target)
        record = self.rt.new_session("plan", ONE_DEVICE, target)
        steps = ["install", "baseline-logcat", "launch",
                 "frida-observe", "frida-fileio", "collect"]
        self.rt.close_session(record, [
            ("step-planned", s) for s in steps])
        self.assertEqual(evidence.validate(
            record, _schema("runtime-session.schema.json")), [])
        kinds = [e["kind"] for e in record["events"]]
        self.assertEqual(kinds[0], "session-started")
        self.assertEqual(kinds.count("step-planned"), 6)
        with open(target, "rb") as fh:
            want = hashlib.sha256(fh.read()).hexdigest()
        self.assertEqual(record["target"]["sha256"], want)
        self.assertTrue(record["device"]["attached"])

    def test_write_session_round_trip(self):
        record = self.rt.new_session("status", NO_DEVICE)
        self.rt.close_session(record)
        with tempfile.TemporaryDirectory() as td:
            path = self.rt.write_session(record, td)
            with open(path, encoding="utf-8") as fh:
                loaded = json.load(fh)
        self.assertEqual(loaded["session_id"],
                         record["session_id"])
        self.assertEqual(evidence.validate(
            loaded, _schema("runtime-session.schema.json")), [])

    def test_device_error_is_recorded(self):
        st = dict(NO_DEVICE)
        st["device_error"] = "adb devices failed: test"
        record = self.rt.new_session("status", st)
        self.assertEqual(record["errors"],
                         ["adb devices failed: test"])


class FindingVerificationTest(unittest.TestCase):
    def test_vocabulary(self):
        self.assertEqual(
            VERIFICATION_STATUSES,
            ("CONFIRMED", "STRONGLY_INDICATED", "POTENTIAL",
             "UNVERIFIED", "CONTRADICTED"))

    def test_make_finding_carries_status(self):
        f = evidence.make_finding(
            "NAR-SEC-001", "T", "high", "high", "c", "p", "e",
            "x", "i", "r", verification_status="CONFIRMED")
        self.assertEqual(f["verification_status"], "CONFIRMED")
        default = evidence.make_finding(
            "NAR-SEC-002", "T", "low", "low", "c", "p", "e",
            "x", "i", "r")
        self.assertEqual(default["verification_status"],
                         "UNVERIFIED")
        with self.assertRaises(ValueError):
            evidence.make_finding(
                "NAR-SEC-003", "T", "low", "low", "c", "p", "e",
                "x", "i", "r", verification_status="PROVEN")

    def test_schema_accepts_new_and_legacy_findings(self):
        schema = _schema("security-findings.schema.json")
        new = evidence.make_finding(
            "NAR-SEC-001", "T", "high", "high", "c", "p", "e",
            "x", "i", "r", verification_status="POTENTIAL")
        legacy = dict(new)
        del legacy["verification_status"]
        self.assertEqual(evidence.validate(
            {"findings": [new]}, schema), [])
        self.assertEqual(evidence.validate(
            {"findings": [legacy]}, schema), [])
        bad = dict(new)
        bad["verification_status"] = "PROVEN"
        self.assertTrue(evidence.validate(
            {"findings": [bad]}, schema))

    def test_nar_security_findings_carry_status(self):
        fixtures = os.environ.get(
            "NAR_FIXTURES",
            os.path.expanduser("~/workspace/nar-e2e-fixtures"))
        demo = os.path.join(fixtures, "demo", "NarDemo.apk")
        if not os.path.isfile(demo):
            self.skipTest("demo fixture absent")
        sec = _load("nar_security_for_test", "nar-security.py")
        report = sec.review(demo)
        self.assertTrue(report["findings"])
        for f in report["findings"]:
            self.assertIn(f["verification_status"],
                          VERIFICATION_STATUSES)
        self.assertEqual(evidence.validate(
            report, _schema("security-findings.schema.json")),
            [])


if __name__ == "__main__":
    unittest.main()
