"""Unit tests: field round P2 — the default Windows SDK
location (F-32) and the documentation guards that belong
with it.

The Android Studio default SDK location on Windows,
%LOCALAPPDATA%\\Android\\Sdk, was in NO candidate list:
not the registry's, not the doctor's, and not the inline
lists nar-triage / nar-compare / nar-perms carry for their
aapt2 / apksigner scans. A stock Windows install that
never set ANDROID_HOME was therefore undiscoverable on
every surface at once, compounding the .bat discovery
defect (F-07). These tests plant an SDK tree under a fake
LOCALAPPDATA and require every surface to find its tools
there — and to behave exactly as before when the variable
is absent.

Simulated, like the rest of the Windows estate: no
Windows host required.
"""
import importlib.util
import os
import re
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                    "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from narlib import registry  # noqa: E402


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(ROOT, "scripts", filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_tool(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _plant_localappdata_sdk(tmp_path, tools=("apksigner",)):
    """An SDK tree under a fake %LOCALAPPDATA% whose path
    contains a space, like the real one (C:\\Users\\<name>\\
    AppData\\Local). Returns (localappdata_dir, {tool: path})."""
    local = tmp_path / "Local AppData"
    sdk = local / "Android" / "Sdk"
    planted = {}
    for tool in tools:
        planted[tool] = _write_tool(
            sdk / "build-tools" / "35.0.0" / tool)
    return local, planted


def _isolate_sdk_env(monkeypatch, tmp_path):
    """Remove every other route to an SDK: no ANDROID_HOME /
    ANDROID_SDK_ROOT, an empty HOME (so the home-relative
    candidates point nowhere), and a PATH with no SDK tools."""
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir(exist_ok=True)
    monkeypatch.setenv("PATH", str(empty_bin))


# ----------------------------------------------------------
# (a) registry: _sdk_candidates / _find_sdk_tool
# ----------------------------------------------------------

def test_registry_candidates_include_localappdata(tmp_path,
                                                  monkeypatch):
    local, _ = _plant_localappdata_sdk(tmp_path)
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    expected = os.path.join(str(local), "Android", "Sdk")
    assert expected in registry._sdk_candidates()


def test_registry_candidates_omit_localappdata_when_unset(
        monkeypatch):
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    # No candidate may be derived from a variable that does
    # not exist; the rest of the list is untouched.
    assert registry._sdk_candidates()
    assert all("AppData" not in c
               for c in registry._sdk_candidates())


def test_registry_find_sdk_tool_under_localappdata(tmp_path,
                                                   monkeypatch):
    _isolate_sdk_env(monkeypatch, tmp_path)
    local, planted = _plant_localappdata_sdk(tmp_path)
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    assert registry._find_sdk_tool("apksigner") == \
        str(planted["apksigner"])


# ----------------------------------------------------------
# (b) doctor: find_sdk_tool with LOCALAPPDATA
# ----------------------------------------------------------

def _doctor_find_sdk_tool_source():
    text = _read(os.path.join("scripts", "nar-doctor.sh"))
    m = re.search(r"^find_sdk_tool\(\) \{.*?^\}", text, re.M | re.S)
    assert m, "find_sdk_tool not found in nar-doctor.sh"
    return m.group(0)


def _run_find_sdk_tool(sdk_candidates, tool, extra_env=None):
    driver = 'SDK_CANDIDATES="%s"\n%s\nfind_sdk_tool %s\n' % (
        sdk_candidates, _doctor_find_sdk_tool_source(), tool)
    env = dict(os.environ)
    env.pop("LOCALAPPDATA", None)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(["bash", "-c", driver],
                          capture_output=True, text=True, env=env)


def test_doctor_find_sdk_tool_under_localappdata(tmp_path):
    # The SDK exists ONLY under a %LOCALAPPDATA% whose path
    # contains a space; the apksigner there is the stock
    # Windows .bat form. SDK_CANDIDATES points nowhere.
    local = tmp_path / "Local AppData"
    bat = local / "Android" / "Sdk" / "build-tools" / "35.0.0" \
        / "apksigner.bat"
    bat.parent.mkdir(parents=True)
    bat.write_text("@echo off\n", encoding="utf-8")
    bat.chmod(0o644)
    proc = _run_find_sdk_tool(
        str(tmp_path / "no-such-sdk"), "apksigner",
        {"LOCALAPPDATA": str(local)})
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == \
        str(local) + "/Android/Sdk/build-tools/35.0.0/apksigner.bat"


def test_doctor_find_sdk_tool_localappdata_absent_unchanged(
        tmp_path):
    # No LOCALAPPDATA, no SDK anywhere: not found, no error.
    proc = _run_find_sdk_tool(str(tmp_path / "no-such-sdk"),
                              "apksigner")
    assert proc.returncode == 1
    assert proc.stdout.strip() == ""


def test_doctor_find_sdk_tool_falls_through_to_candidates(
        tmp_path):
    # LOCALAPPDATA set but holding no SDK: the classic
    # SDK_CANDIDATES route must still win.
    sdk = tmp_path / "sdk"
    tool = _write_tool(sdk / "build-tools" / "34.0.0" / "apksigner")
    empty_local = tmp_path / "Local AppData"
    empty_local.mkdir()
    proc = _run_find_sdk_tool(
        str(sdk), "apksigner", {"LOCALAPPDATA": str(empty_local)})
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == str(tool)


# ----------------------------------------------------------
# (c) nar-triage / nar-compare / nar-perms inline lists
# ----------------------------------------------------------

def test_triage_finders_under_localappdata(tmp_path, monkeypatch):
    _isolate_sdk_env(monkeypatch, tmp_path)
    local, planted = _plant_localappdata_sdk(
        tmp_path, tools=("apksigner", "aapt2"))
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    triage = _load("nar_triage_field_p2", "nar-triage.py")
    assert triage.find_sdk_tool("apksigner") == \
        str(planted["apksigner"])
    assert triage.find_aapt2() == str(planted["aapt2"])


def test_compare_find_aapt2_under_localappdata(tmp_path,
                                               monkeypatch):
    _isolate_sdk_env(monkeypatch, tmp_path)
    local, planted = _plant_localappdata_sdk(
        tmp_path, tools=("aapt2",))
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    compare = _load("nar_compare_field_p2", "nar-compare.py")
    assert compare.find_aapt2() == str(planted["aapt2"])


def test_perms_find_aapt2_under_localappdata(tmp_path,
                                             monkeypatch):
    _isolate_sdk_env(monkeypatch, tmp_path)
    local, planted = _plant_localappdata_sdk(
        tmp_path, tools=("aapt2",))
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    perms = _load("nar_perms_field_p2", "nar-perms.py")
    assert perms.find_aapt2() == str(planted["aapt2"])


# ----------------------------------------------------------
# (d) the setup guide documents what the code now does
# ----------------------------------------------------------

def test_setup_guide_documents_localappdata_and_overrides():
    guide = _read(os.path.join("references",
                               "setup-and-doctor.md"))
    # The Windows default SDK location is named, so a user
    # can find the one step that applies to their install.
    assert "%LOCALAPPDATA%" in guide
    # The override surface the code honours is documented:
    # the doctor's interpreter override, the generic
    # per-tool path override, and the split-merge opt-out.
    assert "NAR_PYTHON" in guide
    assert "NAR_<NAME>_PATH" in guide
    assert "NAR_NO_MERGE_SPLITS" in guide
