"""Unit tests: Part 10.5 failure classification + fallback
chains + the decompile chain wired into nar-analyze.

- FailureKind is exactly the brief's closed set; the
  classifiers map common subprocess outcomes to it.
- The chain runner records every attempt with an enum
  classification (never a free-form reason), applies the
  bounded self-repair rules, and never upgrades fidelity.
- The chain registry declares every 10.5.2 capability with
  only the rungs that genuinely exist today.
- The decompile chain: a broken jadx (INSTALLED_WONT_START)
  is abandoned immediately and a lower rung serves; the
  built-in disassembler is the guaranteed floor; jadx
  PARTIAL output serves as a PARTIAL attempt.
- nar-analyze: kill-switch (tools stripped) still produces
  a complete case served by the floor; the decompile stage
  resumes from the stage cache on a second run.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", ".."))
SCRIPTS = os.path.join(ROOT, "scripts")
sys.path.insert(0, SCRIPTS)

from narlib import chains, failures, registry  # noqa: E402
from narlib.failures import FailureKind  # noqa: E402

EXPECTED_KINDS = {
    "NOT_INSTALLED", "INSTALLED_WONT_START", "WRONG_VERSION",
    "UNSUPPORTED_INPUT", "PROTECTED_INPUT", "CORRUPT_INPUT",
    "TIMEOUT", "OOM", "PARTIAL", "BUG", "BUDGET_EXCEEDED",
}


def _demo():
    fixtures = os.environ.get(
        "NAR_FIXTURES",
        os.path.expanduser("~/workspace/nar-e2e-fixtures"))
    return os.path.join(fixtures, "demo", "NarDemo.apk")


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(SCRIPTS, filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _spec(name, run, fidelity="structural-summary",
          budget_s=60):
    return {"name": name, "fidelity": fidelity,
            "budget_s": budget_s, "caveats": [], "run": run}


def _ok(artifacts=1):
    return lambda ctx: {"status": "ok", "artifacts": artifacts}


def _fail(kind, detail="boom"):
    return lambda ctx: {"status": "failed", "kind": kind,
                        "detail": detail}


def _assert_record_shape(case, record):
    case.assertEqual(
        set(record.keys()),
        {"capability", "chain", "attempts", "served_by",
         "fidelity", "caveats"})
    case.assertIn(record["fidelity"], chains.FIDELITY_LADDER)
    for attempt in record["attempts"]:
        case.assertIn("rung", attempt)
        case.assertIn("status", attempt)
        case.assertIn("duration_s", attempt)
        if attempt["status"] in ("failed", "partial"):
            # Every failure carries exactly one enum
            # classification, and the reason is prefixed
            # with it — no free-form failure strings.
            case.assertIn(attempt["classification"],
                          EXPECTED_KINDS)
            case.assertTrue(
                attempt["reason"].startswith(
                    attempt["classification"] + ":")
                or attempt["reason"] ==
                attempt["classification"],
                attempt["reason"])


class FailureEnumTest(unittest.TestCase):
    def test_exact_kind_names(self):
        self.assertEqual({k.value for k in FailureKind},
                         EXPECTED_KINDS)
        self.assertEqual({k.name for k in FailureKind},
                         EXPECTED_KINDS)

    def test_classify_missing_binary(self):
        self.assertIs(
            failures.classify_exception(
                FileNotFoundError("no such file")),
            FailureKind.NOT_INSTALLED)
        self.assertIs(
            failures.classify_subprocess(
                exception=FileNotFoundError("x")),
            FailureKind.NOT_INSTALLED)

    def test_classify_wont_start(self):
        self.assertIs(
            failures.classify_output(
                "ERROR: JAVA_HOME is not set and no "
                "'java' command could be found", 1),
            FailureKind.INSTALLED_WONT_START)

    def test_classify_timeout_and_oom(self):
        self.assertIs(
            failures.classify_subprocess(timed_out=True),
            FailureKind.TIMEOUT)
        self.assertIs(
            failures.classify_output(
                "java.lang.OutOfMemoryError: Java heap "
                "space", 1),
            FailureKind.OOM)

    def test_classify_own_exception_is_bug(self):
        self.assertIs(
            failures.classify_exception(ValueError("bad")),
            FailureKind.BUG)

    def test_classify_adapter_error_shapes(self):
        kind, _ = failures.classify_adapter_error(
            "jadx not available: not found")
        self.assertIs(kind, FailureKind.NOT_INSTALLED)
        kind, _ = failures.classify_adapter_error(
            "jadx not available: found but its version "
            "command did not run successfully; not counted "
            "as available")
        self.assertIs(kind, FailureKind.INSTALLED_WONT_START)
        kind, _ = failures.classify_adapter_error(
            "jadx run failed: Command timed out after 5s")
        self.assertIs(kind, FailureKind.TIMEOUT)

    def test_report_labels(self):
        self.assertEqual(
            failures.report_label_for(FailureKind.OOM),
            "oom-retry")
        self.assertEqual(
            failures.report_label_for(FailureKind.TIMEOUT),
            "timeout-retry")
        self.assertEqual(
            failures.report_label_for(
                FailureKind.INSTALLED_WONT_START),
            "needs-jdk")
        self.assertEqual(
            failures.report_label_for(
                FailureKind.NOT_INSTALLED),
            "needs-install")
        self.assertEqual(
            failures.report_label_for(
                FailureKind.CORRUPT_INPUT),
            "input-defect")
        self.assertEqual(
            failures.report_label_for(FailureKind.BUG),
            "internal-bug")


class ChainRunnerTest(unittest.TestCase):
    def test_first_ok_serves(self):
        record = chains.run_chain("cap", [
            _spec("a", _ok()), _spec("b", _ok())])
        _assert_record_shape(self, record)
        self.assertEqual(record["served_by"], "a")
        self.assertEqual(len(record["attempts"]), 1)

    def test_fallback_records_each_failure(self):
        record = chains.run_chain("cap", [
            _spec("a", _fail(FailureKind.NOT_INSTALLED)),
            _spec("b", _ok(), fidelity="bytecode-listing")])
        _assert_record_shape(self, record)
        self.assertEqual(record["served_by"], "b")
        self.assertEqual(record["fidelity"],
                         "bytecode-listing")
        self.assertEqual(record["attempts"][0]
                         ["classification"], "NOT_INSTALLED")
        self.assertEqual(record["attempts"][0]
                         ["report_label"], "needs-install")

    def test_oom_one_retry_recorded(self):
        calls = []

        def flaky(ctx):
            calls.append(ctx.get("repair"))
            if ctx.get("repair") == "oom-retry":
                return {"status": "ok", "artifacts": 2}
            return {"status": "failed",
                    "kind": FailureKind.OOM, "detail": "heap"}

        record = chains.run_chain("cap", [_spec("a", flaky)])
        self.assertEqual(record["served_by"], "a")
        self.assertEqual(calls, [None, "oom-retry"])
        self.assertEqual(record["attempts"][1]["repair"],
                         "oom-retry")
        _assert_record_shape(self, record)

    def test_timeout_one_retry_with_larger_budget(self):
        budgets = []

        def slow(ctx):
            budgets.append(ctx.get("budget_s"))
            if ctx.get("repair") == "timeout-retry":
                return {"status": "ok"}
            return {"status": "failed",
                    "kind": FailureKind.TIMEOUT,
                    "detail": "slow"}

        record = chains.run_chain(
            "cap", [_spec("a", slow, budget_s=10)],
            total_budget_s=1000)
        self.assertEqual(record["served_by"], "a")
        self.assertEqual(budgets, [10, 20])

    def test_wont_start_no_retry(self):
        calls = []

        def broken(ctx):
            calls.append(1)
            return {"status": "failed",
                    "kind": FailureKind.INSTALLED_WONT_START,
                    "detail": "JDK not found"}

        record = chains.run_chain("cap", [
            _spec("a", broken), _spec("b", _ok())])
        self.assertEqual(len(calls), 1)
        self.assertEqual(record["attempts"][0]
                         ["report_label"], "needs-jdk")
        self.assertEqual(record["served_by"], "b")

    def test_bug_records_traceback_and_continues(self):
        def buggy(ctx):
            raise RuntimeError("planted bug")

        record = chains.run_chain("cap", [
            _spec("a", buggy), _spec("b", _ok())])
        attempt = record["attempts"][0]
        self.assertEqual(attempt["classification"], "BUG")
        self.assertIn("RuntimeError", attempt["traceback"])
        self.assertEqual(record["served_by"], "b")

    def test_partial_serves(self):
        def partial(ctx):
            return {"status": "partial",
                    "detail": "finished with errors, "
                              "count: 3",
                    "artifacts": 5, "decompile_errors": 3}

        record = chains.run_chain("cap", [
            _spec("a", partial,
                  fidelity="source-approximate"),
            _spec("b", _ok())])
        _assert_record_shape(self, record)
        self.assertEqual(record["served_by"], "a")
        self.assertEqual(record["attempts"][0]["status"],
                         "partial")
        self.assertEqual(record["attempts"][0]
                         ["classification"], "PARTIAL")
        self.assertEqual(record["attempts"][0]
                         ["decompile_errors"], 3)

    def test_chain_budget_exceeded_named(self):
        record = chains.run_chain("cap", [
            _spec("a", _fail(FailureKind.BUG)),
            _spec("b", _ok())], total_budget_s=0)
        _assert_record_shape(self, record)
        self.assertEqual(record["attempts"][0]
                         ["classification"],
                         "BUDGET_EXCEEDED")
        self.assertIsNone(record["served_by"])
        self.assertEqual(record["fidelity"],
                         "identified-only")

    def test_no_rung_serves_identified_only(self):
        record = chains.run_chain("cap", [
            _spec("a", _fail(FailureKind.CORRUPT_INPUT))])
        self.assertIsNone(record["served_by"])
        self.assertEqual(record["fidelity"],
                         "identified-only")
        self.assertEqual(record["attempts"][0]
                         ["report_label"], "input-defect")


class ChainRegistryTest(unittest.TestCase):
    EXPECTED = {
        "java-decompile", "manifest-decode",
        "resource-table", "signature", "il2cpp-dump",
        "unity-assets", "unreal-packages", "unreal-pak",
        "godot", "flutter", "hermes", "native-decompile",
        "networking-runtime", "runtime-hooks",
        "xamarin-dotnet", "audio-banks",
    }

    def test_registry_covers_every_capability(self):
        data = chains.registry_as_dict()
        self.assertEqual(set(data.keys()), self.EXPECTED)
        json.dumps(data)  # machine-readable

    def test_decompile_chain_exact(self):
        entry = chains.CHAIN_REGISTRY["java-decompile"]
        self.assertEqual(
            entry["chain"],
            ["jadx", "baksmali", "dex2jar+cfr",
             "dex2jar+procyon", "nar-dex-disasm"])
        self.assertEqual(entry["floor_rung"],
                         "nar-dex-disasm")
        fid = entry["fidelity_by_rung"]
        self.assertEqual(fid["jadx"], "source-approximate")
        self.assertEqual(fid["baksmali"],
                         "bytecode-listing")
        self.assertEqual(fid["nar-dex-disasm"],
                         "bytecode-listing")

    def test_no_invented_rungs(self):
        rungs = {rung.lower() for entry in
                 chains.CHAIN_REGISTRY.values()
                 for rung in entry["chain"]}
        for invented in ("narlib-arsc", "narlib-apksig",
                         "narlib-hbc", "blutter",
                         "il2cppinspector", "assetripper",
                         "uassetapi", "fmodel", "unrealpak",
                         "ilspycmd", "monodis", "vgmstream"):
            self.assertNotIn(invented, rungs, invented)
        # dex2jar rungs exist only in the decompile chain.
        for cap, entry in chains.CHAIN_REGISTRY.items():
            if cap != "java-decompile":
                self.assertNotIn("dex2jar", " ".join(
                    entry["chain"]), cap)


class DecompileChainTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.demo = _demo()
        if not os.path.isfile(cls.demo):
            raise unittest.SkipTest("demo fixture absent")

    def test_broken_jadx_falls_to_lower_rung_fast(self):
        # A broken jadx override (NAR_JADX_PATH pointing
        # at a launcher that will not start) must not
        # degrade the chain by itself: since the field
        # round's identity validation, the registry tries
        # the next jadx candidate, and only when NO
        # candidate validates does the rung fail and the
        # chain fall to the lower rungs (the pre-fix
        # behaviour this test originally pinned).
        with tempfile.TemporaryDirectory() as td:
            fake = os.path.join(td, "jadx")
            with open(fake, "w", encoding="utf-8") as fh:
                fh.write("#!/bin/sh\n"
                         "echo 'ERROR: JAVA_HOME is not "
                         "set and no JDK was found' >&2\n"
                         "exit 1\n")
            os.chmod(fake, 0o755)
            old = os.environ.get("NAR_JADX_PATH")
            os.environ["NAR_JADX_PATH"] = fake
            try:
                reg = registry.load_registry()
                jadx_entry = next(t for t in reg["tools"]
                                  if t["name"] == "jadx")
                jadx_probe = registry.probe(jadx_entry)
                started = time.time()
                record = chains.run_decompile_chain(
                    self.demo, os.path.join(td, "work"))
                wall = time.time() - started
            finally:
                if old is None:
                    os.environ.pop("NAR_JADX_PATH", None)
                else:
                    os.environ["NAR_JADX_PATH"] = old
        self.assertLess(wall, 30)
        _assert_record_shape(self, record)
        jadx_attempt = record["attempts"][0]
        self.assertEqual(jadx_attempt["rung"], "jadx")
        if jadx_probe["available"]:
            # Another candidate validated: the broken
            # override was passed over (named in the
            # attempt's identity_rejections) and jadx
            # itself served the chain.
            self.assertEqual(record["served_by"], "jadx")
            self.assertEqual(record["fidelity"],
                             "source-approximate")
            self.assertEqual(
                jadx_attempt.get("tool_identity"),
                "validated")
            rejections = jadx_attempt.get(
                "identity_rejections", [])
            self.assertTrue(any(
                r["path"] == fake
                and "did not run" in r["reason"]
                for r in rejections), rejections)
            return
        self.assertEqual(jadx_attempt["classification"],
                         "INSTALLED_WONT_START")
        # baksmali is genuinely installed in this
        # environment (registry probe); where it is not,
        # the built-in floor is the honest expectation.
        reg = registry.load_registry()
        entry = next(t for t in reg["tools"]
                     if t["name"] == "baksmali")
        expected = "baksmali" if registry.probe(entry)[
            "available"] else "nar-dex-disasm"
        self.assertEqual(record["served_by"], expected)
        self.assertEqual(record["fidelity"],
                         "bytecode-listing")

    def test_floor_serves_when_no_external_tools(self):
        target = self.demo  # absolute, before HOME changes
        saved = {k: os.environ.get(k) for k in (
            "PATH", "HOME", "ANDROID_HOME",
            "ANDROID_SDK_ROOT", "NAR_JADX_PATH",
            "NAR_APKTOOL_JAR")}
        with tempfile.TemporaryDirectory() as td:
            shim = os.path.join(td, "shim")
            os.makedirs(shim)
            java = shutil.which("java")
            if java:
                os.symlink(java, os.path.join(shim, "java"))
            os.environ["PATH"] = shim
            os.environ["HOME"] = os.path.join(td, "home")
            for key in ("ANDROID_HOME", "ANDROID_SDK_ROOT",
                        "NAR_JADX_PATH", "NAR_APKTOOL_JAR"):
                os.environ.pop(key, None)
            try:
                record = chains.run_decompile_chain(
                    target, os.path.join(td, "work"))
            finally:
                for key, value in saved.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value
        _assert_record_shape(self, record)
        self.assertEqual(record["served_by"],
                         "nar-dex-disasm")
        # Fidelity honesty: the floor is a listing, never
        # source.
        self.assertEqual(record["fidelity"],
                         "bytecode-listing")
        self.assertFalse(record["fidelity"].startswith(
            "source"))

    def test_jadx_partial_attempt_serves(self):
        class FakeDex:
            @staticmethod
            def jadx_index(target, out_dir):
                return {"tool_path": "fake-jadx",
                        "tool_version": "0",
                        "exit_code": 1,
                        "output_tail": "finished with "
                                       "errors, count: 2",
                        "class_files": 4,
                        "decompile_errors": 2,
                        "classes_sample": []}

        old = chains._nar_dex_mod
        chains._nar_dex_mod = FakeDex
        try:
            specs = chains.decompile_rung_specs(
                self.demo, tempfile.mkdtemp())
            record = chains.run_chain(
                "java-decompile", specs[:1])
        finally:
            chains._nar_dex_mod = old
        _assert_record_shape(self, record)
        self.assertEqual(record["served_by"], "jadx")
        attempt = record["attempts"][0]
        self.assertEqual(attempt["status"], "partial")
        self.assertEqual(attempt["classification"],
                         "PARTIAL")
        self.assertEqual(attempt["decompile_errors"], 2)
        self.assertEqual(record["fidelity"],
                         "source-approximate")
        self.assertTrue(any("decompile errors: 2" in c
                            for c in record["caveats"]))


class AnalyzeDecompileStageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.demo = _demo()
        if not os.path.isfile(cls.demo):
            raise unittest.SkipTest("demo fixture absent")

    def _run_analyze(self, out, env_extra=None, timeout=600):
        env = dict(os.environ)
        if env_extra:
            env.update(env_extra)
        return subprocess.run(
            [sys.executable,
             os.path.join(SCRIPTS, "nar-analyze.py"),
             self.demo, "--out", out],
            capture_output=True, text=True, timeout=timeout,
            env=env)

    def test_kill_switch_case_completes_floor_serves(self):
        with tempfile.TemporaryDirectory() as td:
            shim = os.path.join(td, "shim")
            os.makedirs(shim)
            for name in ("bash", "sh", "env", "uname",
                         "dirname", "basename", "cat", "grep",
                         "sed", "awk", "head", "tail", "wc",
                         "tr", "cut", "sort", "uniq", "find",
                         "xargs", "mktemp", "rm", "mkdir", "cp",
                         "mv", "chmod", "touch", "date", "ls",
                         "readlink", "realpath", "stat"):
                src = shutil.which(name)
                if src:
                    os.symlink(src, os.path.join(shim, name))
            os.symlink(sys.executable,
                       os.path.join(shim, "python"))
            os.symlink(sys.executable,
                       os.path.join(shim, "python3"))
            java_home = os.environ.get("JAVA_HOME")
            if java_home:
                cand = os.path.join(java_home, "bin", "java")
                if os.path.isfile(cand):
                    os.symlink(cand,
                               os.path.join(shim, "java"))
            env = {"PATH": shim,
                   "HOME": os.path.join(td, "home"),
                   "TMPDIR": td}
            if java_home:
                env["JAVA_HOME"] = java_home
            out = os.path.join(td, "case")
            proc = subprocess.run(
                [sys.executable,
                 os.path.join(SCRIPTS, "nar-analyze.py"),
                 self.demo, "--out", out],
                capture_output=True, text=True, timeout=600,
                env=env)
            self.assertEqual(proc.returncode, 0,
                             proc.stderr[-500:])
            with open(os.path.join(out, "report.json"),
                      encoding="utf-8") as fh:
                report = json.load(fh)
            self.assertIn("decompile",
                          report.get("companions") or {})
            with open(os.path.join(out, "decompile.json"),
                      encoding="utf-8") as fh:
                record = json.load(fh)
            _assert_record_shape(self, record)
            # No jadx/apktool/aapt2/ghidra/UnityPy/
            # Il2CppDumper on PATH and no workspace tool
            # discovery (HOME is empty): the built-in
            # floor is the guaranteed server for a valid
            # DEX, at bytecode-listing fidelity.
            self.assertEqual(record["served_by"],
                             "nar-dex-disasm")
            self.assertEqual(record["fidelity"],
                             "bytecode-listing")
            summary = report.get("decompile_summary") or {}
            self.assertEqual(summary.get("served_by"),
                             "nar-dex-disasm")

    def test_decompile_stage_cache_resume(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "case")
            proc = self._run_analyze(out)
            self.assertEqual(proc.returncode, 0,
                             proc.stderr[-500:])
            with open(os.path.join(out, "decompile.json"),
                      encoding="utf-8") as fh:
                first = json.load(fh)
            proc = self._run_analyze(out)
            self.assertEqual(proc.returncode, 0,
                             proc.stderr[-500:])
            with open(os.path.join(out, "decompile.json"),
                      encoding="utf-8") as fh:
                second = json.load(fh)
            self.assertEqual(first, second)
            with open(os.path.join(out, "execution-log.json"),
                      encoding="utf-8") as fh:
                log = json.load(fh)
            entries = log["entries"] if isinstance(
                log, dict) else log
            decompile_entries = [
                e for e in entries
                if e.get("stage") == "decompile"]
            self.assertTrue(decompile_entries)
            self.assertEqual(decompile_entries[-1]
                             ["status"], "cached")
            with open(os.path.join(out, "report.json"),
                      encoding="utf-8") as fh:
                report = json.load(fh)
            self.assertTrue(report["companions"]
                            ["decompile"]["cached"])

    def test_no_dex_target_records_identified_only(self):
        az = _load("nar_analyze_for_part105", "nar-analyze.py")
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "nodex.apk")
            import zipfile
            with zipfile.ZipFile(target, "w") as zf:
                zf.writestr("resources.arsc", b"placeholder")
            out = os.path.join(td, "case")
            os.makedirs(out)
            report = {"limitations": []}
            companions = {}
            record = az._decompile_stage(
                report, companions, target, out,
                "0" * 64 + "|test")
            self.assertIsNotNone(record)
            self.assertEqual(record["fidelity"],
                             "identified-only")
            self.assertIsNone(record["served_by"])
            self.assertEqual(record["attempts"], [])
            self.assertTrue(os.path.isfile(
                os.path.join(out, "decompile.json")))
            self.assertEqual(companions["decompile"]
                             ["file"], "decompile.json")


if __name__ == "__main__":
    unittest.main()
