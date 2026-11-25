"""2.6.1 W5 — the e2e harness's public mode.

CI runs the harness with NAR_E2E_PUBLIC=1 on a bare
clone: the private fixture tree and its manifest must
not be consulted, fixture-bound cases must SKIP (never
silently PASS), the fixture-independent subset must run
green, and the exit code must be 0. This test runs the
real harness in public mode with NAR_FIXTURES pointing
at a directory that does not exist — if the harness
touched the private tree or its manifest, the fixture
cases would find nothing to skip *from* and several
would fail instead.
"""
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"


def _load_nar():
    spec = importlib.util.spec_from_file_location(
        "nar_cli_e2e_public_mode", SCRIPTS / "nar.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _bash_or_skip():
    """Resolve bash via nar.py's resolve_bash() — the
    single source of truth for bash discovery (plain
    "bash" off win32, a real Git Bash on win32, never the
    System32 WSL stub). Skip, never silently pass, when
    no usable bash exists."""
    bash = _load_nar().resolve_bash()
    if bash is None:
        pytest.skip(
            "no usable bash found: Git Bash is required "
            "on Windows (the System32 WSL stub is not a "
            "usable bash)")
    return bash


def _script_arg(path):
    # Mirror nar.py run_entry: on win32 Git Bash takes
    # the script path with forward slashes.
    text = str(path)
    return text.replace("\\", "/") \
        if sys.platform == "win32" else text


def test_e2e_public_mode_skips_private_and_passes():
    env = dict(os.environ)
    env["NAR_E2E_PUBLIC"] = "1"
    env["NAR_FIXTURES"] = str(ROOT / "no-such-fixture-tree")
    proc = subprocess.run(
        [_bash_or_skip(),
         _script_arg(ROOT / "tests" / "run_e2e.sh")],
        capture_output=True, text=True, timeout=900, env=env,
        cwd=str(ROOT))
    out = proc.stdout + proc.stderr
    assert "PUBLIC MODE" in out
    assert proc.returncode == 0, out[-3000:]
    assert "\nFAIL " not in "\n" + out
    # Fixture-bound cases skipped; the independent subset
    # (doctor on this host, CLI smokes, synthetic-input
    # cases, dashboard, frida syntax) passed.
    assert "SKIP " in out
    assert "e2e matrix:" in out
    summary = [l for l in out.splitlines()
               if l.startswith("e2e matrix:")][0]
    assert " 0 failed" in summary
