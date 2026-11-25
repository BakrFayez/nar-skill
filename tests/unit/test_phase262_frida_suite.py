"""Unit tests: 2.6.2 WS-B Frida validation suite (B3).

The suite logic (tests/runtime_validation/frida_validation.py)
is exercised with recorded fake runners and canned session
outputs: syntax via node and via the documented fallback,
per-script evaluation for the pass / attach-failure /
no-device / server-down / no-target paths, serialization
round-trip, error-recovery verdicts, and report aggregation.
The live emulator run is recorded separately; these tests
never claim device results.
"""
import importlib.util
import json
import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SUITE_PATH = os.path.join(ROOT, "tests", "runtime_validation",
                          "frida_validation.py")
SCRIPTS_DIR = os.path.join(ROOT, "scripts", "frida")


def _load_suite():
    spec = importlib.util.spec_from_file_location(
        "frida_validation", SUITE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fv = _load_suite()
SPECS = {s["name"]: s for s in fv.SCRIPT_SPECS}

NETWORK_BANNER = (
    "[net] observing network connections. Query values, "
    "header values, and bodies are never logged.\n"
    "[net] hooked: java.net.URL.openConnection\n"
    "[net] hooked: java.net.Socket.connect\n")
FILEIO_BANNER = (
    "[file-io] observing file operations. Paths and byte "
    "counts only; contents are never logged.\n"
    "[file-io] hooked: java.io.FileInputStream constructor\n")
JNI_BANNER = "[jni-trace] hooked RegisterNatives at " \
             "0x76e610723690 (JNIEnv table)\n"
JAVAAPI_BANNER = (
    "[java-api-trace] tracing 1 target method(s). String "
    "values are never printed.\n"
    "[java-api-trace] hooked: java.net.URL.openConnection\n")
BANNERS = {"network-observe.js": NETWORK_BANNER,
           "file-io-observe.js": FILEIO_BANNER,
           "jni-trace.js": JNI_BANNER,
           "java-api-trace.js": JAVAAPI_BANNER}
SYNTAX_OK = {"status": fv.PASS, "method": "fake",
             "detail": "ok"}
CONN_OK = {"state": "ok", "detail": "enumerated"}


def _session(stdout, returncode=0, timed_out=False, stderr=""):
    return {"stdout": stdout, "stderr": stderr,
            "returncode": returncode, "timed_out": timed_out}


def _by_id(result):
    return {c["id"]: c for c in result["checks"]}


class SyntaxTest(unittest.TestCase):
    def test_all_bundled_scripts_pass_node_check(self):
        import shutil
        if not shutil.which("node"):
            self.skipTest("node not available on this host")
        for name in SPECS:
            out = fv.js_syntax_check(
                os.path.join(SCRIPTS_DIR, name))
            self.assertEqual(out["status"], fv.PASS, name)
            self.assertEqual(out["method"], "node --check")

    def test_missing_file_fails(self):
        out = fv.js_syntax_check("/nonexistent/script.js")
        self.assertEqual(out["status"], fv.FAIL)

    def test_fallback_scan_balanced(self):
        ok, _why = fv.fallback_js_scan(
            '"use strict";\nfunction f(x) { return [x, {a: 1}]; }\n'
            '// a comment with ( unbalanced\n'
            'var s = "string with } brace";\n')
        self.assertTrue(ok)

    def test_fallback_scan_unbalanced(self):
        ok, _why = fv.fallback_js_scan("function f( { return 1; ")
        self.assertFalse(ok)
        ok, _why = fv.fallback_js_scan('var s = "unterminated;')
        self.assertFalse(ok)
        ok, _why = fv.fallback_js_scan("/* unterminated")
        self.assertFalse(ok)

    def test_syntax_fallback_used_without_node(self):
        def no_node_runner(argv, timeout=30):
            raise AssertionError("node runner must not run")
        import unittest.mock as mock
        with mock.patch.object(fv.shutil, "which",
                               return_value=None):
            out = fv.js_syntax_check(
                os.path.join(SCRIPTS_DIR, "network-observe.js"),
                runner=no_node_runner)
        self.assertEqual(out["method"],
                         "fallback-delimiter-scan")
        self.assertEqual(out["status"], fv.PASS)
        self.assertIn("not a full", out["detail"])


class EvaluatePassTest(unittest.TestCase):
    def test_each_script_all_pass_with_recorded_banner(self):
        for name, banner in BANNERS.items():
            result = fv.evaluate_script(
                SPECS[name], SYNTAX_OK, CONN_OK,
                session=_session(banner),
                target_alive_after=True,
                recovery={"ok": True, "detail": "structured"})
            by_id = _by_id(result)
            self.assertEqual(
                [c["id"] for c in result["checks"]],
                list(fv.CHECK_IDS))
            for cid, check in by_id.items():
                self.assertEqual(check["status"], fv.PASS,
                                 f"{name}/{cid}: {check['detail']}")

    def test_banner_missing_is_fail(self):
        result = fv.evaluate_script(
            SPECS["network-observe.js"], SYNTAX_OK, CONN_OK,
            session=_session("[net] hooked: something\n"),
            target_alive_after=True,
            recovery={"ok": True, "detail": "x"})
        self.assertEqual(_by_id(result)["banner"]["status"],
                         fv.FAIL)

    def test_java_unavailable_banner_is_fail(self):
        result = fv.evaluate_script(
            SPECS["network-observe.js"], SYNTAX_OK, CONN_OK,
            session=_session(
                "[net] Java runtime is not available in this "
                "process.\n"),
            target_alive_after=True,
            recovery={"ok": True, "detail": "x"})
        self.assertEqual(_by_id(result)["banner"]["status"],
                         fv.FAIL)

    def test_dead_target_is_detach_fail(self):
        result = fv.evaluate_script(
            SPECS["file-io-observe.js"], SYNTAX_OK, CONN_OK,
            session=_session(FILEIO_BANNER),
            target_alive_after=False,
            recovery={"ok": True, "detail": "x"})
        self.assertEqual(_by_id(result)["detach"]["status"],
                         fv.FAIL)


class EvaluateNotRunTest(unittest.TestCase):
    def test_no_device_everything_device_side_not_run(self):
        conn = {"state": "no_device",
                "detail": "no device attached"}
        result = fv.evaluate_script(
            SPECS["jni-trace.js"], SYNTAX_OK, conn)
        by_id = _by_id(result)
        self.assertEqual(by_id["syntax"]["status"], fv.PASS)
        for cid in ("connectivity", "attach", "banner",
                    "serialization", "detach", "error_recovery"):
            self.assertEqual(by_id[cid]["status"], fv.NOT_RUN,
                             cid)

    def test_server_down_connectivity_fails_rest_not_run(self):
        conn = {"state": "server_down",
                "detail": "frida-server is not reachable"}
        result = fv.evaluate_script(
            SPECS["jni-trace.js"], SYNTAX_OK, conn)
        by_id = _by_id(result)
        self.assertEqual(by_id["connectivity"]["status"],
                         fv.FAIL)
        self.assertEqual(by_id["attach"]["status"], fv.NOT_RUN)

    def test_no_target_connectivity_passes_attach_not_run(self):
        conn = {"state": "no_target",
                "detail": "reachable, no test process"}
        result = fv.evaluate_script(
            SPECS["jni-trace.js"], SYNTAX_OK, conn)
        by_id = _by_id(result)
        self.assertEqual(by_id["connectivity"]["status"],
                         fv.PASS)
        self.assertEqual(by_id["attach"]["status"], fv.NOT_RUN)

    def test_attach_failure_dependents_not_run(self):
        result = fv.evaluate_script(
            SPECS["network-observe.js"], SYNTAX_OK, CONN_OK,
            session=_session(
                "", returncode=1,
                stderr="Failed to attach: unable to find "
                       "process with pid 4242"),
            target_alive_after=True,
            recovery={"ok": True, "detail": "x"})
        by_id = _by_id(result)
        self.assertEqual(by_id["attach"]["status"], fv.FAIL)
        for cid in ("banner", "serialization", "detach"):
            self.assertEqual(by_id[cid]["status"], fv.NOT_RUN,
                             cid)
        self.assertEqual(by_id["error_recovery"]["status"],
                         fv.PASS)


class SerializationRecoveryReportTest(unittest.TestCase):
    def test_serialization_round_trip(self):
        events = fv.event_lines(NETWORK_BANNER + "noise line\n")
        self.assertEqual(len(events), 3)
        out = fv.check_serialization(events)
        self.assertEqual(out["status"], fv.PASS)
        json.dumps(events)  # stays JSON-safe

    def test_recovery_verdicts(self):
        ok = fv.recovery_verdict(_session(
            "", returncode=1,
            stderr="Failed to attach: unable to find process "
                   "with pid 999999"))
        self.assertTrue(ok["ok"])
        bad = fv.recovery_verdict(_session("attached fine"))
        self.assertFalse(bad["ok"])

    def test_report_shape_and_summary(self):
        results = []
        for name, banner in BANNERS.items():
            results.append(fv.evaluate_script(
                SPECS[name], SYNTAX_OK, CONN_OK,
                session=_session(banner),
                target_alive_after=True,
                recovery={"ok": True, "detail": "x"}))
        report = fv.build_report(
            {"classification": {"kind": "emulator"},
             "statuses": {}},
            {"host": "17.27.4", "server": "17.27.4",
             "abi": "x86_64"},
            results)
        self.assertEqual(set(report),
                         {"device", "frida", "scripts", "summary"})
        s = report["summary"]
        self.assertEqual(s["checks_total"], 28)
        self.assertEqual(s["pass"], 28)
        self.assertEqual(s["fail"], 0)
        self.assertEqual(s["not_run"], 0)
        for result in report["scripts"]:
            for check in result["checks"]:
                self.assertIn(check["status"], fv.CHECK_STATUSES)
        json.dumps(report)  # the report itself is JSON-safe


if __name__ == "__main__":
    unittest.main()
