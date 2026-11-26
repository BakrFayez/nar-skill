"""Unit tests: network redaction + network companions
(Evolution Phase 5).

Redaction: credential values inside endpoint URLs (sensitive
query parameters, URL userinfo) are replaced with REDACTED
before nar-network emits anything; the report counts the
redacted values and never carries a raw one. Classification
still runs on the original URL.

Companions: network-analysis.json and api-architecture.json
are projections of the endpoints document, validated
against their shipped schemas; the architecture projection
drops query strings entirely.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from narlib import companions, evidence  # noqa: E402


def _load_network():
    spec = importlib.util.spec_from_file_location(
        "nar_network_for_test", os.path.join(ROOT, "scripts",
                                             "nar-network.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _schema(name):
    with open(os.path.join(ROOT, "schemas", name),
              encoding="utf-8") as fh:
        return json.load(fh)


PLANTED = [
    ("https://api.example.com/v1/data?api_key=SECRETKEY1234&x=1", 1),
    ("https://user:passw0rd@example.com/login", 1),
    ("https://example.com/auth?access_token=tok_abcdef&other=ok", 1),
    ("https://example.com/plain?foo=bar", 0),
    ("wss://stream.example.com/socket?session=sess12345"
     "&token=tok12345", 2),
]
SECRETS = ["SECRETKEY1234", "passw0rd", "tok_abcdef", "sess12345",
           "tok12345"]


class RedactUrlTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.net = _load_network()

    def test_planted_counts(self):
        for url, want in PLANTED:
            _, count = self.net.redact_url(url)
            self.assertEqual(count, want, url)

    def test_values_replaced_shape_preserved(self):
        out, _ = self.net.redact_url(PLANTED[0][0])
        self.assertEqual(
            out, "https://api.example.com/v1/data"
                 "?api_key=REDACTED&x=1")
        out, _ = self.net.redact_url(PLANTED[1][0])
        self.assertEqual(out, "https://REDACTED@example.com/login")
        out, _ = self.net.redact_url(PLANTED[3][0])
        self.assertEqual(out, PLANTED[3][0])

    def test_no_secret_survives(self):
        for url, _ in PLANTED:
            out, _ = self.net.redact_url(url)
            for secret in SECRETS:
                self.assertNotIn(secret, out)


class AnalyzeRedactionTest(unittest.TestCase):
    """analyze() with the string/triage tools stubbed: the
    redaction pass must fire on the assembled report, with
    the planted count exact."""

    def test_analyze_redacts_and_counts(self):
        net = _load_network()
        strings_doc = {"groups": {
            "urls": {"hits": [
                {"value": url, "sources": ["classes.dex"]}
                for url, _ in PLANTED]},
            "api_endpoints": {"hits": []},
            "package_names": {"hits": []}}}
        triage_doc = {"library_versions": {}}
        real = net.run_json_tool

        def fake(script, args, timeout=1800):
            return strings_doc if "strings" in script else triage_doc

        net.run_json_tool = fake
        try:
            with tempfile.NamedTemporaryFile(
                    suffix=".apk", delete=False) as fh:
                fh.write(b"PK\x03\x04 planted")
                target = fh.name
            try:
                report = net.analyze(target)
            finally:
                os.unlink(target)
        finally:
            net.run_json_tool = real
        self.assertEqual(
            report["redaction"]["endpoint_values_redacted"], 5)
        blob = json.dumps(report)
        for secret in SECRETS:
            self.assertNotIn(secret, blob)
        by_url = {e["url"]: e for e in report["endpoints"]}
        sensitive = [e for e in report["endpoints"]
                     if e["classification"] == "sensitive"]
        # api_key + access_token + session/token URLs classify
        # sensitive from the ORIGINAL URLs, and are flagged
        # as redacted in the output. The userinfo URL also
        # classifies sensitive since the Phase 2 fix round
        # (M2-04): classify() now inspects URL userinfo, so
        # the planted user:password@ URL is the fourth.
        self.assertEqual(len(sensitive), 4)
        self.assertTrue(all(e.get("redacted") for e in sensitive))
        self.assertEqual(len(by_url), 5)
        errors = evidence.validate(
            report, _schema("endpoints.schema.json"))
        self.assertEqual(errors, [])


ENDPOINTS_DOC = {
    "endpoints": [
        {"url": "https://api.example.com/v1/data?api_key=REDACTED",
         "host": "api.example.com", "kind": "api",
         "classification": "sensitive", "sources": ["classes.dex"],
         "redacted": True},
        {"url": "wss://stream.example.com/socket?session=REDACTED",
         "host": "stream.example.com", "kind": "websocket",
         "classification": "confirmed", "sources": ["classes.dex"],
         "redacted": True},
        {"url": "https://example.com/about", "host": "example.com",
         "kind": "web", "classification": "third-party",
         "sources": ["assets/x"]},
    ],
    "hosts": ["api.example.com", "example.com",
              "stream.example.com"],
    "api_hosts": ["api.example.com"],
    "network_libraries": ["OkHttp"],
    "services": [{"service": "Firebase",
                  "evidence": {"project_id": "demo"}}],
    "network_security_config": {
        "uses_cleartext_traffic": False,
        "base_cleartext_permitted": False,
        "pin_set_present": True, "debug_overrides_present": False},
    "classification_counts": {"sensitive": 1, "confirmed": 1,
                              "third-party": 1},
    "redaction": {"endpoint_values_redacted": 2,
                  "policy": "test"},
    "notes": ["nsc note"],
}


class NetworkCompanionsTest(unittest.TestCase):
    def test_network_analysis_projection_validates(self):
        doc = companions.project_network_analysis(
            ENDPOINTS_DOC, "2.4.0")
        self.assertEqual(
            evidence.validate(
                doc, _schema("network-analysis.schema.json")), [])
        self.assertEqual(doc["endpoint_count"], 3)
        self.assertEqual(doc["cleartext"]["pin_set_present"], True)
        self.assertEqual(
            doc["redaction"]["endpoint_values_redacted"], 2)
        self.assertEqual(doc["services"], ["Firebase"])

    def test_api_architecture_projection_validates(self):
        doc = companions.project_api_architecture(
            ENDPOINTS_DOC, "2.4.0")
        self.assertEqual(
            evidence.validate(
                doc, _schema("api-architecture.schema.json")), [])
        self.assertEqual(doc["websocket_endpoint_count"], 1)
        profiles = {p["host"]: p for p in doc["host_profiles"]}
        self.assertEqual(
            profiles["api.example.com"]["endpoint_count"], 1)
        # Paths only: no query string survives the projection.
        for profile in doc["host_profiles"]:
            for path in profile["paths"]:
                self.assertNotIn("?", path)
                self.assertNotIn("REDACTED", path)

    def test_degraded_projections_are_explicit(self):
        for project, schema_name in (
                (companions.project_network_analysis,
                 "network-analysis.schema.json"),
                (companions.project_api_architecture,
                 "api-architecture.schema.json")):
            doc = project(None, "2.4.0")
            self.assertIn("unavailable", doc)
            self.assertEqual(
                evidence.validate(doc, _schema(schema_name)), [])


if __name__ == "__main__":
    unittest.main()
