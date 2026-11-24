"""Unit tests: Phase 9 runtime hardening (R-007).

Device capability detection, emulator-vs-physical
identification, environment validation with named failure
reasons, Frida compatibility diagnostics, and bounded
connection recovery. All device interaction is faked with
recorded adb outputs (the live emulator verification is
recorded separately in the phase repair records); the
classifiers under test are the shipped code paths.
"""
import importlib.util
import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(ROOT, "scripts", filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rt = _load("nar_runtime_phase9", "nar-runtime.py")

EMU_PROPS = {
    "ro.product.model": "Android SDK built for x86_64",
    "ro.product.brand": "google",
    "ro.product.manufacturer": "Google",
    "ro.hardware": "ranchu",
    "ro.kernel.qemu": "1",
    "ro.build.fingerprint": "google/sdk_gphone_x86_64/generic:8.0.0",
    "ro.build.version.release": "8.0.0",
    "ro.build.version.sdk": "26",
    "ro.product.cpu.abi": "x86_64",
    "ro.product.cpu.abilist": "x86_64,x86",
    "ro.debuggable": "1",
    "sys.boot_completed": "1",
}
PHYS_PROPS = {
    "ro.product.model": "SM-G991B",
    "ro.product.brand": "samsung",
    "ro.product.manufacturer": "samsung",
    "ro.hardware": "exynos2100",
    "ro.build.fingerprint": "samsung/o1sxxx/o1s:13/TP1A:user/release-keys",
    "ro.build.version.release": "13",
    "ro.build.version.sdk": "33",
    "ro.product.cpu.abi": "arm64-v8a",
    "ro.product.cpu.abilist": "arm64-v8a,armeabi-v7a",
    "ro.debuggable": "0",
    "sys.boot_completed": "1",
}


def _dump(props):
    return "".join(f"[{k}]: [{v}]\n" for k, v in props.items())


class _Proc:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


class FakeAdb:
    """Runner with the _run(argv, timeout) shape, answering
    from recorded outputs for one emulator device."""

    def __init__(self, props=EMU_PROPS, frida_files=("frida-server",),
                 frida_version="17.27.4", states=None, pm=True):
        self.props = props
        self.frida_files = frida_files
        self.frida_version = frida_version
        self.states = states or {"emulator-5554": "device"}
        self.pm = pm
        self.calls = []

    def __call__(self, argv, timeout=30):
        self.calls.append(argv)
        if argv[1] == "devices":
            body = "".join(f"{s}\t{st}\n"
                           for s, st in self.states.items())
            return _Proc("List of devices attached\n" + body)
        if argv[1] == "reconnect":
            return _Proc("reconnecting emulator-5554\n")
        shell = argv[4:]
        if shell[:1] == ["getprop"] and len(shell) == 1:
            return _Proc(_dump(self.props))
        if shell[:1] == ["getprop"]:
            return _Proc(str(self.props.get(shell[1], "")) + "\n")
        if shell == ["id"]:
            return _Proc("uid=0(root) gid=0(root)\n")
        if shell == ["ls", "/data/local/tmp"]:
            return _Proc("\n".join(self.frida_files) + "\n")
        if shell and shell[0].endswith("frida-server") \
                and shell[1:] == ["--version"]:
            return _Proc(self.frida_version + "\n")
        if shell[:2] == ["pm", "path"]:
            return _Proc("package:/data/app/x/base.apk\n"
                         if self.pm else "")
        return _Proc("")


class ClassifyTest(unittest.TestCase):
    def test_emulator_strong_markers_with_evidence(self):
        out = rt.classify_device(EMU_PROPS, "emulator-5554")
        self.assertEqual(out["kind"], "emulator")
        props = {e["property"] for e in out["evidence"]}
        self.assertIn("ro.kernel.qemu", props)
        self.assertIn("ro.hardware", props)
        self.assertTrue(all("value" in e for e in out["evidence"]))

    def test_physical_no_markers(self):
        out = rt.classify_device(PHYS_PROPS, "R5CR30ABCDE")
        self.assertEqual(out["kind"], "physical")
        self.assertEqual(out["evidence"], [])

    def test_unknown_when_no_props(self):
        self.assertEqual(rt.classify_device({}, None)["kind"],
                         "unknown")
        self.assertEqual(rt.classify_device(None, None)["kind"],
                         "unknown")

    def test_single_weak_marker_not_decisive(self):
        props = dict(PHYS_PROPS)
        props["ro.build.fingerprint"] = "generic/o1s/o1s:13/x:user/keys"
        out = rt.classify_device(props, "R5CR30ABCDE")
        self.assertEqual(out["kind"], "unknown")


class FridaCompatTest(unittest.TestCase):
    def test_match_and_patch_tolerance(self):
        self.assertEqual(rt.frida_compatibility(
            "17.27.4", "17.27.4")["status"], "match")
        out = rt.frida_compatibility("17.27.4", "17.27.9")
        self.assertEqual(out["status"], "match")
        self.assertIn("patch", out["message"])

    def test_mismatch_message_is_actionable(self):
        out = rt.frida_compatibility("17.27.4", "16.5.9")
        self.assertEqual(out["status"], "mismatch")
        self.assertIn("17.27", out["message"])
        self.assertIn("16.5", out["message"])

    def test_unknown_when_version_missing(self):
        self.assertEqual(rt.frida_compatibility(
            "17.27.4", None)["status"], "unknown")
        self.assertEqual(rt.frida_compatibility(
            None, None)["status"], "unknown")


class CapabilitiesTest(unittest.TestCase):
    def test_capabilities_from_recorded_outputs(self):
        fake = FakeAdb()
        caps = rt.device_capabilities("/sdk/adb", "emulator-5554",
                                      runner=fake,
                                      frida_host_version="17.27.4")
        self.assertEqual(caps["abi"], "x86_64")
        self.assertEqual(caps["api_level"], 26)
        self.assertEqual(caps["android"], "8.0.0")
        self.assertTrue(caps["boot_completed"])
        self.assertEqual(caps["classification"]["kind"], "emulator")
        self.assertTrue(caps["root"]["adbd_uid0"])
        self.assertTrue(caps["frida_server"]["present"])
        self.assertEqual(caps["frida_server"]["version"], "17.27.4")
        self.assertEqual(
            caps["frida_server"]["compatibility"]["status"], "match")

    def test_frida_version_probed_despite_log_sidecar(self):
        # Regression (live find): a frida-server.log beside
        # the binary shares the name prefix; the version
        # probe must still run against the binary alone.
        fake = FakeAdb(frida_files=("frida-server",
                                    "frida-server.log"))
        caps = rt.device_capabilities("/sdk/adb", "emulator-5554",
                                      runner=fake,
                                      frida_host_version="17.27.4")
        self.assertTrue(caps["frida_server"]["present"])
        self.assertEqual(caps["frida_server"]["version"],
                         "17.27.4")
        self.assertEqual(
            caps["frida_server"]["compatibility"]["status"],
            "match")

    def test_capabilities_frida_absent(self):
        fake = FakeAdb(frida_files=("somefile",))
        caps = rt.device_capabilities("/sdk/adb", "emulator-5554",
                                      runner=fake,
                                      frida_host_version="17.27.4")
        self.assertFalse(caps["frida_server"]["present"])
        self.assertEqual(
            caps["frida_server"]["compatibility"]["status"],
            "unknown")

    def test_getprop_dump_parser(self):
        props = rt.parse_getprop_dump(
            "[ro.hardware]: [ranchu]\nnot a prop line\n"
            "[ro.build.version.sdk]: [26]\n")
        self.assertEqual(props, {"ro.hardware": "ranchu",
                                 "ro.build.version.sdk": "26"})

    def test_app_installed_states(self):
        self.assertTrue(rt.app_installed(
            "/sdk/adb", "emulator-5554", "com.example.x",
            runner=FakeAdb(pm=True)))
        self.assertFalse(rt.app_installed(
            "/sdk/adb", "emulator-5554", "com.example.x",
            runner=FakeAdb(pm=False)))


class DiagnosticsTest(unittest.TestCase):
    ADB_OK = {"available": True, "path": "/sdk/adb",
              "version": "34.0.0"}
    FRIDA_OK = {"available": True, "path": "/venv/frida",
                "version": "17.27.4"}

    def _caps(self, fake=None):
        return rt.device_capabilities(
            "/sdk/adb", "emulator-5554", runner=fake or FakeAdb(),
            frida_host_version="17.27.4")

    def test_all_pass(self):
        diag = rt.diagnostics_from(
            self.ADB_OK, self.FRIDA_OK, [self._caps()],
            states={"emulator-5554": "device"},
            package="com.example.x", installed=True)
        self.assertTrue(diag["ok"])
        self.assertEqual(diag["failure_reasons"], [])

    def test_no_device_named_reason(self):
        diag = rt.diagnostics_from(self.ADB_OK, self.FRIDA_OK, [],
                                   states={})
        self.assertFalse(diag["ok"])
        self.assertIn(rt.FAIL_NO_DEVICE, diag["failure_reasons"])

    def test_unauthorized_named_reason(self):
        diag = rt.diagnostics_from(
            self.ADB_OK, self.FRIDA_OK, [],
            states={"emulator-5554": "unauthorized"})
        self.assertIn(rt.FAIL_DEVICE_NOT_READY,
                      diag["failure_reasons"])

    def test_frida_mismatch_named_reason(self):
        fake = FakeAdb(frida_version="16.5.9")
        diag = rt.diagnostics_from(
            self.ADB_OK, self.FRIDA_OK, [self._caps(fake)],
            states={"emulator-5554": "device"})
        self.assertIn(rt.FAIL_FRIDA_MISMATCH,
                      diag["failure_reasons"])

    def test_app_missing_and_adb_missing(self):
        diag = rt.diagnostics_from(
            {"available": False}, self.FRIDA_OK, [self._caps()],
            states={"emulator-5554": "device"},
            package="com.example.x", installed=False)
        self.assertIn(rt.FAIL_ADB_MISSING, diag["failure_reasons"])
        self.assertIn(rt.FAIL_APP_MISSING, diag["failure_reasons"])
        for check in diag["checks"]:
            self.assertIn(check["status"],
                          ("pass", "fail", "warn", "skip"))


class RecoveryTest(unittest.TestCase):
    def test_recovers_after_reconnect(self):
        seq = [{"emulator-5554": "offline"},
               {"emulator-5554": "device"}]
        calls = {"n": 0}

        def runner(argv, timeout=30):
            if argv[1] == "devices":
                state = seq[min(calls["n"], len(seq) - 1)]
                calls["n"] += 1
                body = "".join(f"{s}\t{st}\n"
                               for s, st in state.items())
                return _Proc("List of devices attached\n" + body)
            return _Proc("reconnecting\n")

        out = rt.recover_connection("/sdk/adb", max_attempts=3,
                                    delay_s=0.01, runner=runner,
                                    sleep=lambda s: None)
        self.assertTrue(out["recovered"])
        self.assertEqual(out["attempts"], 2)

    def test_bounded_give_up(self):
        def runner(argv, timeout=30):
            if argv[1] == "devices":
                return _Proc("List of devices attached\n")
            return _Proc("")

        out = rt.recover_connection("/sdk/adb", max_attempts=99,
                                    delay_s=0.01, runner=runner,
                                    sleep=lambda s: None)
        self.assertFalse(out["recovered"])
        # 99 requested, clamped to the hard cap of 5.
        self.assertEqual(out["attempts"], 5)
        self.assertEqual(len(out["history"]), 5)


if __name__ == "__main__":
    unittest.main()
