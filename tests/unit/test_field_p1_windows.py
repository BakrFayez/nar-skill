"""Unit tests: field round P1, Area 3 — Windows toolchain.

The registry layer already resolves PATHEXT / COMSPEC
correctly; the surfaces the field user actually hit did not:

- the doctor's bash ``find_sdk_tool`` tested only the
  extensionless name with ``[ -x ]``, so an SDK that ships
  ``apksigner.bat`` (the stock Windows build-tools form)
  reported apksigner MISSING;
- nar-triage's SDK scan did the same for apksigner, and
  ``apksigner_verify`` spawned a found ``.bat`` directly, so
  the launch OSError surfaced as a mislabelled "unreadable"
  (aapt2 in the same file already had the full treatment:
  variant file names, candidate check, cmd /c argv wrap);
- the registry ``python3`` entry declared only the
  ``python3`` candidate, so the tools view disagreed with
  the doctor's python3 -> python -> py chain on python-only
  Windows machines;
- no PyGhidra fallback existed anywhere (registry or docs)
  for when Ghidra's analyzeHeadless script execution fails.

Windows behaviour is simulated (sys.platform pinned, PATH /
SDK trees planted), following test_companions.py — no
Windows host required.
"""
import importlib.util
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                    "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from narlib import registry  # noqa: E402


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def _load_triage():
    spec = importlib.util.spec_from_file_location(
        "nar_triage_field_p1",
        os.path.join(ROOT, "scripts", "nar-triage.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_script(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


# ----------------------------------------------------------
# (a) Doctor: find_sdk_tool PATHEXT variants
# ----------------------------------------------------------

def _doctor_find_sdk_tool_source():
    text = _read(os.path.join("scripts", "nar-doctor.sh"))
    m = re.search(r"^find_sdk_tool\(\) \{.*?^\}", text, re.M | re.S)
    assert m, "find_sdk_tool not found in nar-doctor.sh"
    return m.group(0)


def _run_find_sdk_tool(sdk_root, tool):
    driver = 'SDK_CANDIDATES="%s"\n%s\nfind_sdk_tool %s\n' % (
        sdk_root, _doctor_find_sdk_tool_source(), tool)
    return subprocess.run(["bash", "-c", driver],
                          capture_output=True, text=True)


def test_doctor_find_sdk_tool_finds_bat_only(tmp_path):
    # Stock Windows build-tools shape: apksigner exists ONLY
    # as apksigner.bat (and not executable by POSIX bits).
    sdk = tmp_path / "sdk"
    bat = sdk / "build-tools" / "35.0.0" / "apksigner.bat"
    bat.parent.mkdir(parents=True)
    bat.write_text("@echo off\n", encoding="utf-8")
    bat.chmod(0o644)
    proc = _run_find_sdk_tool(sdk, "apksigner")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == str(bat)


def test_doctor_find_sdk_tool_finds_cmd_in_platform_tools(tmp_path):
    sdk = tmp_path / "sdk"
    cmd = sdk / "platform-tools" / "adb.cmd"
    cmd.parent.mkdir(parents=True)
    cmd.write_text("@echo off\n", encoding="utf-8")
    cmd.chmod(0o644)
    proc = _run_find_sdk_tool(sdk, "adb")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == str(cmd)


def test_doctor_find_sdk_tool_posix_extensionless_unchanged(tmp_path):
    # POSIX behaviour for the extensionless name stays
    # exactly as-is: an executable extensionless tool in
    # build-tools is found.
    sdk = tmp_path / "sdk"
    tool = _write_script(sdk / "build-tools" / "34.0.0" / "apksigner",
                         "#!/bin/sh\nexit 0\n")
    proc = _run_find_sdk_tool(sdk, "apksigner")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == str(tool)


# ----------------------------------------------------------
# (b) nar-triage: apksigner variants, scan, argv wrap
# ----------------------------------------------------------

def _plant_sdk_bat(tmp_path):
    sdk = tmp_path / "sdk"
    bat = sdk / "build-tools" / "35.0.0" / "apksigner.bat"
    bat.parent.mkdir(parents=True)
    bat.write_text("@echo off\n", encoding="utf-8")
    bat.chmod(0o644)  # not executable by POSIX semantics
    return sdk, bat


def test_triage_find_apksigner_bat_simulated_win32(tmp_path,
                                                   monkeypatch):
    sdk, bat = _plant_sdk_bat(tmp_path)
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("ANDROID_HOME", str(sdk))
    monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)
    monkeypatch.setenv("PATH", str(empty))
    monkeypatch.setattr(sys, "platform", "win32")
    # which() over an empty PATH finds nothing; the SDK scan
    # itself must test the .bat variant.
    monkeypatch.setattr(shutil, "which",
                        lambda name, path=None: None)
    mod = _load_triage()
    assert mod.find_apksigner() == str(bat)


def test_apksigner_argv_wraps_batch_via_cmd(monkeypatch):
    mod = _load_triage()
    bat = r"C:\sdk\build-tools\35.0.0\apksigner.bat"
    cmd = r"C:\sdk\build-tools\35.0.0\apksigner.cmd"
    exe = r"C:\sdk\build-tools\35.0.0\apksigner.exe"
    monkeypatch.setattr(sys, "platform", "win32")
    assert mod._apksigner_argv(bat, "verify") == \
        ["cmd", "/c", bat, "verify"]
    assert mod._apksigner_argv(cmd, "verify") == \
        ["cmd", "/c", cmd, "verify"]
    assert mod._apksigner_argv(exe, "verify") == [exe, "verify"]
    monkeypatch.setattr(sys, "platform", "linux")
    assert mod._apksigner_argv(bat, "verify") == [bat, "verify"]


def test_apksigner_verify_uses_wrapped_argv_for_bat(tmp_path,
                                                    monkeypatch):
    # A .bat found on PATH (PATHEXT resolution) must be
    # launched through cmd /c; spawning it directly raises
    # OSError on Windows, which the old code misreported as
    # "unreadable".
    bin_dir = tmp_path / "bin"
    bat = bin_dir / "apksigner.bat"
    bat.parent.mkdir(parents=True)
    bat.write_text("@echo off\n", encoding="utf-8")
    apk = str(tmp_path / "x.apk")
    monkeypatch.setattr(sys, "platform", "win32")

    def fake_which(name, path=None):
        return str(bat) if name == "apksigner" else None

    monkeypatch.setattr(shutil, "which", fake_which)
    captured = {}

    class _Proc:
        returncode = 0
        stdout = ("Verifies\n"
                  "Verified using v2 scheme "
                  "(APK Signature Scheme v2): true\n"
                  "Number of signers: 1\n")
        stderr = ""

    def fake_run(argv, **kwargs):
        captured["argv"] = list(argv)
        return _Proc()

    monkeypatch.setattr(subprocess, "run", fake_run)
    mod = _load_triage()
    info, status = mod.apksigner_verify(apk)
    assert status == "ok"
    assert info.get("verifies") is True
    assert captured["argv"] == ["cmd", "/c", str(bat),
                                "verify", "--verbose", apk]


# ----------------------------------------------------------
# (c) Registry: python3 entry falls through to python / py
# ----------------------------------------------------------

def _python3_entry():
    reg = registry.load_registry()
    return next(t for t in reg["tools"] if t["name"] == "python3")


def _probe_python3_with_only(tmp_path, monkeypatch, name):
    bin_dir = tmp_path / ("bin-" + name)
    _write_script(bin_dir / name,
                  "#!/bin/sh\necho 'Python 3.12.0'\n")
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.delenv("NAR_PYTHON3_PATH", raising=False)
    return registry.probe(_python3_entry())


def test_registry_python3_falls_through_to_python(tmp_path,
                                                  monkeypatch):
    result = _probe_python3_with_only(tmp_path, monkeypatch,
                                      "python")
    assert result["available"] is True
    assert result["path"].endswith(os.sep + "python")
    assert "3.12.0" in (result["version"] or "")


def test_registry_python3_falls_through_to_py(tmp_path,
                                              monkeypatch):
    result = _probe_python3_with_only(tmp_path, monkeypatch, "py")
    assert result["available"] is True
    assert result["path"].endswith(os.sep + "py")
    assert "3.12.0" in (result["version"] or "")


def test_registry_python3_broken_stub_falls_through(tmp_path,
                                                    monkeypatch):
    # The stock-Windows field case: python3 EXISTS on PATH
    # (the Microsoft Store stub) but its version run fails,
    # while python works. The stub must not shadow the
    # working candidate (coordinator addition: probe-level
    # fallthrough in narlib/registry.py).
    bin_dir = tmp_path / "bin-stub"
    _write_script(bin_dir / "python3",
                  "#!/bin/sh\nexit 1\n")
    _write_script(bin_dir / "python",
                  "#!/bin/sh\necho 'Python 3.12.0'\n")
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.delenv("NAR_PYTHON3_PATH", raising=False)
    result = registry.probe(_python3_entry())
    assert result["available"] is True
    assert result["path"].endswith(os.sep + "python")
    assert "3.12.0" in (result["version"] or "")


def test_registry_python3_all_broken_reports_first(tmp_path,
                                                   monkeypatch):
    # When no candidate runs, the report keeps the FIRST
    # candidate's historical failure note verbatim.
    bin_dir = tmp_path / "bin-allbroken"
    for name in ("python3", "python", "py"):
        _write_script(bin_dir / name, "#!/bin/sh\nexit 1\n")
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.delenv("NAR_PYTHON3_PATH", raising=False)
    result = registry.probe(_python3_entry())
    assert result["available"] is False
    assert result["path"].endswith(os.sep + "python3")
    assert "did not run successfully" in result["note"]


def test_registry_python3_hint_states_310_floor():
    entry = _python3_entry()
    assert entry["candidates"][0] == "python3"
    assert "python" in entry["candidates"]
    assert "py" in entry["candidates"]
    assert "3.10+" in entry["install_hint"]
    assert "3.9+" not in entry["install_hint"]


# ----------------------------------------------------------
# (d) PyGhidra: registry entry + probe
# ----------------------------------------------------------

def _entry(name):
    reg = registry.load_registry()
    return next((t for t in reg["tools"] if t["name"] == name),
                None)


def test_pyghidra_entry_mirrors_ghidra_shape():
    entry = _entry("pyghidra")
    assert entry is not None, "registry has no pyghidra entry"
    ghidra = _entry("ghidra")
    # Same field set as the ghidra entry, plus version_argv
    # (ghidra is presence-only; pyghidra's validation parses
    # version output, so it carries the probe argv ghidra
    # does not need).
    assert set(entry.keys()) == set(ghidra.keys()) | {"version_argv"}
    assert entry["required"] == "optional"
    assert entry["kind"] == "cli"
    assert entry["candidates"] == ["pyghidra"]
    assert entry["version_argv"] == ["--version"]
    assert entry["validation"] == "version output parsed"
    assert "PyGhidra" in entry["install_hint"]
    assert "fallback" in entry["limitations"].lower()


def test_pyghidra_probes_available_with_fake_on_path(tmp_path,
                                                     monkeypatch):
    bin_dir = tmp_path / "bin-pyghidra"
    _write_script(bin_dir / "pyghidra",
                  "#!/bin/sh\necho 'PyGhidra 12.2'\n")
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.delenv("NAR_PYGHIDRA_PATH", raising=False)
    monkeypatch.delenv("NAR_PYGHIDRA_DIR", raising=False)
    entry = _entry("pyghidra")
    assert entry is not None
    result = registry.probe(entry)
    assert result["available"] is True
    assert "12.2" in (result["version"] or "")


# ----------------------------------------------------------
# (d/e) Docs: PyGhidra fallback + interpreter guidance
# ----------------------------------------------------------

def test_docs_carry_pyghidra_fallback_and_interpreter_notes():
    native = _read(os.path.join("references",
                                "native-libs-and-jni.md"))
    assert "PyGhidra" in native
    assert "analyzeHeadless.bat" in native
    setup = _read(os.path.join("references",
                               "setup-and-doctor.md"))
    assert "PyGhidra" in setup
    assert "Microsoft Store" in setup
    assert "3.10+" in setup
    assert "3.9+" not in setup
    readme = _read("README.md")
    assert "py -3" in readme
    skill = _read("SKILL.md")
    assert "py -3" in skill
