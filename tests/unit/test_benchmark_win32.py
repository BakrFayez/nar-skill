"""Windows regression coverage for the benchmark runner
(CI run #39, clusters B6/B8/C).

Root cause: tests/benchmarks/run_benchmarks.py imported
the POSIX-only ``resource`` module at module level, so on
Windows the import itself raised before argparse could
handle ``nar benchmark --help`` (exit 1 instead of 0). The
same module also called ``os.uname()`` (absent on Windows)
in main() and used ``resource`` unguarded in the peak-memory
measurement and in the benchmark-matrix driver subprocess.

There is no Windows host in the dev environment, so these
tests simulate one on any host: a ``sitecustomize`` blocker
on PYTHONPATH makes ``import resource`` raise ImportError
and deletes ``os.uname`` in every interpreter the test
spawns (including the child processes nar.py dispatches
to). Real Windows execution is NOT RUN; this simulation is
the regression mechanism.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
BENCH = ROOT / "tests" / "benchmarks" / "run_benchmarks.py"

BLOCKER = '''
import sys


class _Blocker:
    def find_module(self, name, path=None):
        if name == "resource":
            return self
        return None

    def find_spec(self, name, path=None, target=None):
        if name == "resource":
            raise ImportError(
                "No module named 'resource' (simulated win32)")
        return None

    def load_module(self, name):
        raise ImportError("No module named 'resource'")


sys.meta_path.insert(0, _Blocker())
sys.modules.pop("resource", None)
import os

if hasattr(os, "uname"):
    try:
        del os.uname
    except Exception:
        pass
'''


def _load_benchmarks():
    spec = importlib.util.spec_from_file_location(
        "run_benchmarks_under_test", BENCH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _win_env(blocker_dir):
    env = dict(os.environ)
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(blocker_dir) + (
        os.pathsep + existing if existing else "")
    return env


def _make_blocker(td):
    blocker = Path(td) / "winsim"
    blocker.mkdir()
    (blocker / "sitecustomize.py").write_text(BLOCKER)
    return blocker


def test_benchmark_help_exits_zero_without_resource_or_uname():
    with tempfile.TemporaryDirectory() as td:
        env = _win_env(_make_blocker(td))
        for argv in (
                [sys.executable, str(SCRIPTS / "nar.py"),
                 "benchmark", "--help"],
                [sys.executable, str(BENCH), "--help"]):
            proc = subprocess.run(
                argv, capture_output=True, text=True,
                timeout=120, env=env, cwd=str(ROOT))
            assert proc.returncode == 0, proc.stderr[-1000:]
            assert "usage:" in proc.stdout


def test_each_new_verb_help_exits_zero_without_resource_or_uname():
    # The full verb-help audit from
    # test_phase9_reporting_cli, replayed under the
    # simulated-Windows environment.
    with tempfile.TemporaryDirectory() as td:
        env = _win_env(_make_blocker(td))
        for verb in ("tools", "identify", "validate",
                     "benchmark", "case"):
            proc = subprocess.run(
                [sys.executable, str(SCRIPTS / "nar.py"),
                 verb, "--help"],
                capture_output=True, text=True, timeout=120,
                env=env, cwd=str(ROOT))
            assert proc.returncode == 0, (
                f"{verb} --help: {proc.stderr[-500:]}")


def test_module_imports_and_memory_degrades_without_resource():
    with tempfile.TemporaryDirectory() as td:
        env = _win_env(_make_blocker(td))
        stub = Path(td) / "stubscripts"
        stub.mkdir()
        (stub / "nar-analyze.py").write_text(
            "import sys; sys.exit(0)\n")
        target = Path(td) / "fixture.bin"
        target.write_bytes(b"x" * 16)
        code = (
            "import importlib.util, json, subprocess, sys\n"
            f"spec = importlib.util.spec_from_file_location("
            f"'rb', {str(BENCH)!r})\n"
            "rb = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(rb)\n"
            "assert rb.resource is None\n"
            "res = rb.measure_peak_memory("
            f"{{'FIX_X': {str(target)!r}}})\n"
            "assert res['status'] == 'not_run', res\n"
            "assert 'resource' in res['reason'], res\n"
            "proc = subprocess.run([sys.executable, '-c', "
            "rb._MATRIX_DRIVER, 't.apk', 'o', 'w', "
            f"{str(stub)!r}], capture_output=True, text=True)\n"
            "doc = json.loads("
            "proc.stdout.strip().splitlines()[-1])\n"
            "assert doc['exit_code'] == 0, proc.stderr\n"
            "assert doc['peak_rss_bytes'] is None, doc\n"
            "print('ok')\n")
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, timeout=120,
            env=env, cwd=str(ROOT))
        assert proc.returncode == 0, proc.stderr[-1500:]
        assert "ok" in proc.stdout


def test_peak_memory_degrades_to_not_run_when_resource_missing():
    rb = _load_benchmarks()
    saved = rb.resource
    rb.resource = None
    try:
        with tempfile.NamedTemporaryFile(
                delete=False) as fh:
            fh.write(b"x" * 16)
            path = fh.name
        try:
            res = rb.measure_peak_memory({"FIX_X": path})
        finally:
            os.unlink(path)
    finally:
        rb.resource = saved
    assert res["status"] == "not_run"
    assert "resource" in res["reason"]


def test_machine_label_matches_uname_where_available():
    rb = _load_benchmarks()
    if hasattr(os, "uname"):
        info = os.uname()
        assert rb._machine_label() == (
            info.sysname + " " + info.machine)
    else:
        assert rb._machine_label()
