"""Unit tests: 2.6.2 WS-B runtime validation.

Covers the capability status vocabulary (B1: every capability
reported as detected / verified / unsupported / unavailable /
not_tested) and the pure assessment behind the `validate`
surface (B2: named failure reasons with remedies for ADB,
device authorization, Frida host/server/version/ABI,
enumeration, attach, detach). All device interaction is faked
with recorded adb outputs, following the Phase 9 pattern; the
live emulator run is recorded separately and never claimed
from these tests.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(ROOT, "scripts", filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rt = _load("nar_runtime_262", "nar-runtime.py")

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
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class FakeAdb:
    def __init__(self, props=EMU_PROPS,
                 frida_files=("frida-server-17.27.4-android-x86_64",),
                 frida_version="17.27.4",
                 id_out="uid=0(root) gid=0(root)\n"):
        self.props = props
        self.frida_files = frida_files
        self.frida_version = frida_version
        self.id_out = id_out

    def __call__(self, argv, timeout=30):
        shell = argv[4:]
        if shell[:1] == ["getprop"] and len(shell) == 1:
            return _Proc(_dump(self.props))
        if shell == ["id"]:
            return _Proc(self.id_out)
        if shell == ["ls", "/data/local/tmp"]:
            return _Proc("\n".join(self.frida_files) + "\n")
        if shell and "frida-server" in shell[0] \
                and shell[1:] == ["--version"]:
            return _Proc(self.frida_version + "\n")
        return _Proc("")


def _caps(fake=None, host="17.27.4"):
    return rt.device_capabilities("/sdk/adb", "emulator-5554",
                                  runner=fake or FakeAdb(),
                                  frida_host_version=host)


class CapabilityStatusTest(unittest.TestCase):
    def test_vocabulary_is_exactly_the_five_statuses(self):
        self.assertEqual(set(rt.CAPABILITY_STATUSES),
                         {"detected", "verified", "unsupported",
                          "unavailable", "not_tested"})

    def test_emulator_statuses(self):
        st = _caps()["statuses"]
        self.assertEqual(st["api_level"]["status"], "detected")
        self.assertEqual(st["api_level"]["value"], 26)
        self.assertEqual(st["android_version"]["status"], "detected")
        self.assertEqual(st["build_fingerprint"]["status"], "detected")
        self.assertEqual(st["device_model"]["status"], "detected")
        self.assertEqual(st["abi_primary"]["status"], "detected")
        entries = {e["abi"]: e
                   for e in st["abi_list"]["entries"]}
        self.assertEqual(entries["x86_64"]["status"], "detected")
        self.assertEqual(entries["x86_64"]["frida_arch"], "x86_64")
        self.assertEqual(entries["x86"]["frida_arch"], "x86")
        # Root was actively probed via `id` -> verified.
        self.assertEqual(st["root_status"]["status"], "verified")
        self.assertIs(st["root_status"]["value"], True)
        # Server binary executed and versions agree -> verified.
        self.assertEqual(st["frida_compatibility"]["status"],
                         "verified")

    def test_adb_connectivity_verified_with_state(self):
        st = rt.capability_statuses(_caps(), adb_state="device")
        self.assertEqual(st["adb_connectivity"]["status"], "verified")
        st = rt.capability_statuses(_caps(),
                                    adb_state="unauthorized")
        self.assertEqual(st["adb_connectivity"]["status"],
                         "unavailable")

    def test_no_caps_everything_not_tested(self):
        st = rt.capability_statuses(None)
        self.assertTrue(st)
        for entry in st.values():
            self.assertEqual(entry["status"], "not_tested")

    def test_missing_property_is_unavailable(self):
        props = {k: v for k, v in EMU_PROPS.items()
                 if k != "ro.build.fingerprint"}
        st = _caps(FakeAdb(props=props))["statuses"]
        self.assertEqual(st["build_fingerprint"]["status"],
                         "unavailable")

    def test_frida_absent_is_unavailable_not_verified(self):
        st = _caps(FakeAdb(frida_files=("somefile",)))["statuses"]
        self.assertEqual(st["frida_compatibility"]["status"],
                         "unavailable")

    def test_frida_mismatch_is_unsupported(self):
        st = _caps(FakeAdb(frida_version="16.5.9"))["statuses"]
        self.assertEqual(st["frida_compatibility"]["status"],
                         "unsupported")

    def test_frida_present_unprobed_is_detected(self):
        # Two binary candidates -> version probe suppressed.
        fake = FakeAdb(frida_files=(
            "frida-server-17.27.4-android-x86_64",
            "frida-server-16.0.0-android-x86_64"))
        st = _caps(fake)["statuses"]
        self.assertEqual(st["frida_compatibility"]["status"],
                         "detected")

    def test_root_not_root_is_still_verified(self):
        fake = FakeAdb(props=PHYS_PROPS,
                       id_out="uid=1000(shell) gid=1000(shell)\n",
                       frida_files=("somefile",))
        st = _caps(fake)["statuses"]
        self.assertEqual(st["root_status"]["status"], "verified")
        self.assertIs(st["root_status"]["value"], False)

    def test_unsupported_abi_entry(self):
        props = dict(EMU_PROPS)
        props["ro.product.cpu.abi"] = "mips"
        props["ro.product.cpu.abilist"] = "mips"
        st = _caps(FakeAdb(props=props))["statuses"]
        entry = st["abi_list"]["entries"][0]
        self.assertEqual(entry["status"], "unsupported")
        self.assertIsNone(entry["frida_arch"])
        self.assertEqual(st["abi_list"]["status"], "unsupported")

    def test_arch_helpers(self):
        self.assertEqual(
            rt.frida_server_arch(
                "frida-server-17.27.4-android-x86_64"), "x86_64")
        self.assertIsNone(rt.frida_server_arch("frida-server"))
        self.assertEqual(rt.frida_arch_for_abi("arm64-v8a"),
                         "arm64")
        self.assertIsNone(rt.frida_arch_for_abi("mips"))


ADB_OK = {"available": True, "path": "/sdk/adb",
          "version": "34.0.0"}
FRIDA_OK = {"available": True, "path": "/venv/frida",
            "version": "17.27.4"}


def _validation(**kw):
    base = dict(states={"emulator-5554": "device"},
                enumeration={"ok": True,
                             "processes": [{"pid": 1, "name": "x"}],
                             "error": None},
                attach={"ok": True, "detail": "attached"},
                detach={"ok": True, "detail": "alive"})
    base.update(kw)
    return rt.validation_from(ADB_OK, FRIDA_OK, [_caps()],
                              **base)


class ValidationFromTest(unittest.TestCase):
    def test_all_pass(self):
        out = _validation()
        self.assertTrue(out["ok"], out["checks"])
        self.assertEqual(out["failure_reasons"], [])
        by_name = {c["check"]: c for c in out["checks"]}
        for name in ("adb_available", "device_authorized",
                     "frida_host_version", "frida_server_presence",
                     "frida_server_version", "frida_version_match",
                     "frida_abi_match", "process_enumeration",
                     "attach_capability", "clean_detach"):
            self.assertEqual(by_name[name]["status"], "pass", name)

    def test_unauthorized_named_reason_and_remedy(self):
        out = rt.validation_from(
            ADB_OK, FRIDA_OK, [],
            states={"emulator-5554": "unauthorized"},
            serial="emulator-5554")
        by_name = {c["check"]: c for c in out["checks"]}
        check = by_name["device_authorized"]
        self.assertEqual(check["status"], "fail")
        self.assertEqual(check["reason"],
                         rt.FAIL_DEVICE_UNAUTHORIZED)
        self.assertIn("authorization", check["action"])

    def test_offline_named_reason(self):
        out = rt.validation_from(
            ADB_OK, FRIDA_OK, [],
            states={"emulator-5554": "offline"},
            serial="emulator-5554")
        self.assertIn(rt.FAIL_DEVICE_OFFLINE,
                      out["failure_reasons"])

    def test_no_device(self):
        out = rt.validation_from(ADB_OK, FRIDA_OK, [], states={})
        self.assertIn(rt.FAIL_NO_DEVICE, out["failure_reasons"])
        by_name = {c["check"]: c for c in out["checks"]}
        self.assertEqual(by_name["frida_server_presence"]["status"],
                         "skip")
        self.assertEqual(by_name["attach_capability"]["status"],
                         "skip")

    def test_abi_mismatch_named_reason(self):
        fake = FakeAdb(frida_files=(
            "frida-server-17.27.4-android-arm64",))
        out = rt.validation_from(
            ADB_OK, FRIDA_OK, [_caps(fake)],
            states={"emulator-5554": "device"},
            enumeration={"ok": True, "processes": [], "error": None})
        self.assertIn(rt.FAIL_FRIDA_ABI_MISMATCH,
                      out["failure_reasons"])

    def test_abi_unknown_when_bare_server_name(self):
        fake = FakeAdb(frida_files=("frida-server",))
        out = rt.validation_from(
            ADB_OK, FRIDA_OK, [_caps(fake)],
            states={"emulator-5554": "device"},
            enumeration={"ok": True, "processes": [], "error": None})
        by_name = {c["check"]: c for c in out["checks"]}
        self.assertEqual(by_name["frida_abi_match"]["status"],
                         "warn")
        self.assertEqual(by_name["frida_abi_match"]["reason"],
                         rt.FAIL_FRIDA_ABI_UNKNOWN)

    def test_enumeration_failure_is_actionable(self):
        out = _validation(enumeration={
            "ok": False, "processes": [],
            "error": "unable to connect to remote server"})
        self.assertIn(rt.FAIL_ENUMERATION, out["failure_reasons"])
        by_name = {c["check"]: c for c in out["checks"]}
        self.assertIn("frida-server",
                      by_name["process_enumeration"]["action"])

    def test_attach_and_detach_failures(self):
        out = _validation(attach={"ok": False, "detail": "boom"},
                          detach=None)
        self.assertIn(rt.FAIL_ATTACH, out["failure_reasons"])
        out = _validation(detach={"ok": False,
                                  "detail": "target died"})
        self.assertIn(rt.FAIL_DETACH, out["failure_reasons"])

    def test_unrun_probes_are_skip_never_pass(self):
        out = _validation(enumeration=None, attach=None,
                          detach=None)
        by_name = {c["check"]: c for c in out["checks"]}
        for name in ("process_enumeration", "attach_capability",
                     "clean_detach"):
            self.assertEqual(by_name[name]["status"], "skip", name)

    def test_parse_frida_ps(self):
        text = ("    PID  Name\n"
                "  1234  com.example.test\n"
                "   987  system_server\n"
                "not a process row\n")
        procs = rt.parse_frida_ps(text)
        self.assertEqual(procs,
                         [{"pid": 1234, "name": "com.example.test"},
                          {"pid": 987, "name": "system_server"}])
        self.assertEqual(rt.parse_frida_ps(""), [])


class _ValidateRunner:
    """Full fake transport for validate(): adb + frida-ps +
    frida CLI. `pm_answers=False` simulates the live find
    where pm hangs (TimeoutExpired -> adb_shell None ->
    install state unknown) while pidof still answers."""

    def __init__(self, pm_answers=True, pid=4242):
        self.pm_answers = pm_answers
        self.pid = pid

    def __call__(self, argv, timeout=30):
        import subprocess as sp
        if argv[1] == "devices":
            return _Proc("List of devices attached\n"
                         "emulator-5554\tdevice\n")
        if argv[0].endswith("frida-ps"):
            return _Proc("    PID  Name\n"
                         "   4242  com.example.test\n"
                         "    987  system_server\n")
        if argv[0].endswith("frida"):
            return _Proc(rt.ATTACH_MARKER + "\n")
        shell = argv[4:]
        if shell[:1] == ["getprop"] and len(shell) == 1:
            return _Proc(_dump(EMU_PROPS))
        if shell == ["id"]:
            return _Proc("uid=0(root) gid=0(root)\n")
        if shell == ["ls", "/data/local/tmp"]:
            return _Proc(
                "frida-server-17.27.4-android-x86_64\n")
        if shell and "frida-server" in shell[0] \
                and shell[1:] == ["--version"]:
            return _Proc("17.27.4\n")
        if shell[:2] == ["pm", "path"]:
            if not self.pm_answers:
                raise sp.TimeoutExpired(argv, timeout)
            return _Proc("package:/data/app/x/base.apk\n")
        if shell[:1] == ["pidof"]:
            return _Proc(f"{self.pid}\n" if self.pid else "")
        if shell[:1] == ["monkey"]:
            return _Proc("Events injected: 1\n")
        return _Proc("")


class ValidateLiveAssemblyTest(unittest.TestCase):
    def _run_validate(self, runner):
        import types
        probes = {"adb": {"available": True, "path": "/sdk/adb",
                          "version": "34.0.0"},
                  "frida": {"available": True,
                            "path": "/venv/frida",
                            "version": "17.27.4"}}
        with mock.patch.object(
                rt, "probe_tool",
                side_effect=lambda name: probes[name]), \
                mock.patch.object(
                    rt, "time",
                    types.SimpleNamespace(
                        sleep=lambda s: None)):
            return rt.validate(package="com.example.test",
                               runner=runner)

    def test_validate_full_pass_with_fake_transport(self):
        out = self._run_validate(_ValidateRunner())
        self.assertTrue(out["ok"], out["checks"])
        by_name = {c["check"]: c for c in out["checks"]}
        self.assertEqual(by_name["attach_capability"]["status"],
                         "pass")
        self.assertEqual(by_name["clean_detach"]["status"],
                         "pass")
        self.assertEqual(by_name["frida_abi_match"]["status"],
                         "pass")

    def test_validate_pm_silent_still_attaches_on_pid(self):
        # Regression (live find): pm hanging must not skip
        # the attach probe when a pid is available.
        out = self._run_validate(_ValidateRunner(pm_answers=False))
        by_name = {c["check"]: c for c in out["checks"]}
        self.assertEqual(by_name["attach_capability"]["status"],
                         "pass", by_name["attach_capability"])

    def test_validate_pm_silent_and_no_process_fails_named(self):
        out = self._run_validate(
            _ValidateRunner(pm_answers=False, pid=None))
        by_name = {c["check"]: c for c in out["checks"]}
        check = by_name["attach_capability"]
        self.assertEqual(check["status"], "fail")
        self.assertEqual(check["reason"], rt.FAIL_ATTACH)
        self.assertIn("pm also did not answer", check["detail"])

    def test_validate_without_adb_reports_named_failure(self):
        with mock.patch.object(
                rt, "probe_tool",
                side_effect=lambda name: {"available": False,
                                          "note": "not found"}):
            with tempfile.TemporaryDirectory() as td:
                path = os.path.join(td, "report.json")
                out = rt.validate(json_path=path)
                self.assertFalse(out["ok"])
                self.assertIn(rt.FAIL_ADB_MISSING,
                              out["validation"]["failure_reasons"])
                with open(path, encoding="utf-8") as fh:
                    saved = json.load(fh)
                self.assertEqual(saved["tool"], "nar-runtime")


if __name__ == "__main__":
    unittest.main()
