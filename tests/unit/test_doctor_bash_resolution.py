"""Unit tests: nar.py doctor bash resolution on Windows.

Defect (hosted CI run #39, doctor job, windows-latest):
scripts/nar.py dispatched the doctor verb as a bare
["bash", path]. On native Windows that name resolves —
via the CreateProcess search order, System32 before
PATH — to the Windows Subsystem for Linux launcher stub
(C:\\Windows\\System32\\bash.exe), which prints "Windows
Subsystem for Linux has no installed distributions" and
never runs the doctor script. `python scripts/nar.py
doctor --help` therefore failed even though the doctor
itself, run under a real bash, was healthy.

Fix pinned here: on win32, nar.py resolves a REAL Git
Bash (git-relative layouts first, then the standard Git
for Windows install locations, then bash on PATH only
when it is not the System32 stub); with no usable bash
it exits 2 naming Git Bash as the missing prerequisite
and never invokes the stub. Non-win32 keeps the historic
plain-"bash" dispatch.

No Windows host is required: every test monkeypatches
sys.platform, shutil.which and os.path.isfile, and the
resolution logic is written in host-independent string
operations, so the suite passes identically on Linux.
"""
import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"

STUB = r"C:\Windows\System32\bash.exe"
STUB_FWD = "C:/Windows/System32/bash.exe"
GIT_BASH = "C:/Program Files/Git/bin/bash.exe"
GIT_CMD = r"C:\Program Files\Git\cmd\git.exe"
GIT_MINGW = r"C:\Program Files\Git\mingw64\bin\git.exe"


def _load_nar():
    spec = importlib.util.spec_from_file_location(
        "nar_cli_bash_resolution", SCRIPTS / "nar.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def nar():
    return _load_nar()


def _norm(path):
    return str(path).replace("\\", "/")


def _fake_which(mapping):
    def which(name, path=None):
        return mapping.get(name)
    return which


def _fake_isfile(existing):
    """isfile that is true exactly for *existing* paths
    (separator-insensitive) plus the real doctor script,
    whose existence run_entry checks before dispatch."""
    existing_norm = {_norm(p) for p in existing}

    def isfile(path):
        if _norm(path) in existing_norm:
            return True
        return _norm(path).endswith("scripts/nar-doctor.sh")
    return isfile


def _win32_env(monkeypatch, nar, which_map, existing):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(nar.shutil, "which",
                        _fake_which(which_map))
    monkeypatch.setattr(os.path, "isfile",
                        _fake_isfile(existing))
    for var in ("ProgramFiles", "ProgramFiles(x86)",
                "LOCALAPPDATA"):
        monkeypatch.delenv(var, raising=False)


# ----------------------------------------------------------
# The stub classifier itself.
# ----------------------------------------------------------

def test_stub_classifier(nar):
    assert nar._is_wsl_stub(STUB) is True
    assert nar._is_wsl_stub(STUB_FWD) is True
    assert nar._is_wsl_stub(r"c:\windows\system32\bash.exe") \
        is True
    assert nar._is_wsl_stub(GIT_BASH) is False
    assert nar._is_wsl_stub(
        "C:/Program Files/Git/usr/bin/bash.exe") is False
    assert nar._is_wsl_stub("") is False
    assert nar._is_wsl_stub(None) is False


# ----------------------------------------------------------
# (1) win32, only the System32 stub present: the stub is
# never selected and the dispatch fails honestly.
# ----------------------------------------------------------

def test_win32_only_stub_selects_nothing(nar, monkeypatch):
    _win32_env(monkeypatch, nar,
               {"git": None, "bash": STUB, "bash.exe": STUB},
               existing={STUB})
    assert nar._win_bash_candidates() == []
    assert nar.resolve_bash() is None


def test_win32_only_stub_run_entry_fails_honestly(
        nar, monkeypatch, capsys):
    _win32_env(monkeypatch, nar,
               {"git": None, "bash": STUB, "bash.exe": STUB},
               existing={STUB})
    calls = []

    def _boom_run(argv, **kwargs):
        calls.append(argv)
        raise AssertionError(
            "subprocess must never run with the stub")

    monkeypatch.setattr(nar.subprocess, "run", _boom_run)
    rc = nar.run_entry(("bash", "nar-doctor.sh", []),
                       ["--help"])
    assert rc == 2
    assert calls == []
    err = capsys.readouterr().err
    assert "Git Bash" in err


# ----------------------------------------------------------
# (2) win32 with a Git Bash candidate present: that
# candidate is selected, ahead of the stub on PATH.
# ----------------------------------------------------------

def test_win32_git_relative_bash_selected(nar, monkeypatch):
    _win32_env(monkeypatch, nar,
               {"git": GIT_CMD, "bash": STUB,
                "bash.exe": STUB},
               existing={GIT_BASH})
    assert nar.resolve_bash() == GIT_BASH


def test_win32_mingw64_git_layout_selected(nar, monkeypatch):
    # git.exe under mingw64/bin: only the ../../bin layout
    # lands on Git's real bin/bash.exe.
    _win32_env(monkeypatch, nar,
               {"git": GIT_MINGW, "bash": STUB,
                "bash.exe": STUB},
               existing={GIT_BASH})
    assert nar.resolve_bash() == GIT_BASH


def test_win32_standard_install_location_selected(
        nar, monkeypatch):
    _win32_env(monkeypatch, nar,
               {"git": None, "bash": STUB, "bash.exe": STUB},
               existing={GIT_BASH})
    monkeypatch.setenv("ProgramFiles", r"C:\Program Files")
    assert nar.resolve_bash() == GIT_BASH


def test_win32_real_bash_on_path_beats_stub_shape(
        nar, monkeypatch):
    # PATH bash that is NOT under System32 is usable.
    scoop = "C:/Users/test/scoop/apps/git/current/bin/bash.exe"
    _win32_env(monkeypatch, nar,
               {"git": None, "bash": scoop, "bash.exe": None},
               existing={scoop})
    assert nar.resolve_bash() == scoop


def test_win32_run_entry_dispatches_git_bash(
        nar, monkeypatch):
    _win32_env(monkeypatch, nar,
               {"git": GIT_CMD, "bash": STUB,
                "bash.exe": STUB},
               existing={GIT_BASH})
    captured = {}

    class _Proc:
        returncode = 0

    def _fake_run(argv, **kwargs):
        captured["argv"] = argv
        return _Proc()

    monkeypatch.setattr(nar.subprocess, "run", _fake_run)
    rc = nar.run_entry(("bash", "nar-doctor.sh", []),
                       ["--help"])
    assert rc == 0
    argv = captured["argv"]
    assert argv[0] == GIT_BASH
    assert _norm(argv[1]).endswith("scripts/nar-doctor.sh")
    assert argv[2:] == ["--help"]
    assert STUB not in argv and STUB_FWD not in argv


# ----------------------------------------------------------
# (3) non-win32: plain "bash", no Windows discovery at all.
# ----------------------------------------------------------

@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_non_win32_returns_plain_bash(nar, monkeypatch,
                                      platform):
    monkeypatch.setattr(sys, "platform", platform)

    def _boom_which(name, path=None):
        raise AssertionError(
            "Windows discovery must not run off win32")

    monkeypatch.setattr(nar.shutil, "which", _boom_which)
    assert nar.resolve_bash() == "bash"


def test_non_win32_run_entry_dispatch_is_unchanged(
        nar, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    captured = {}

    class _Proc:
        returncode = 0

    def _fake_run(argv, **kwargs):
        captured["argv"] = argv
        return _Proc()

    monkeypatch.setattr(nar.subprocess, "run", _fake_run)
    rc = nar.run_entry(("bash", "nar-doctor.sh", []),
                       ["--help"])
    assert rc == 0
    path = os.path.join(str(SCRIPTS), "nar-doctor.sh")
    assert captured["argv"] == ["bash", path, "--help"]
