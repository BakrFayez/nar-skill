"""Certification fallback-chain tests (Wave 3): C-01, C-04,
C-05, C-07, C-08, C-09.

Source of truth: ~/workspace/nar-cert-audit/
ANNEX_CD_INVENTORIES.md, Workstream C. Each item forces a
tool's absence (or failure) at the seam the audit cites and
asserts the DESIGNED degradation is recorded in the output
while the rest of the analysis completes. Tests only: no
product file is modified.

Forcing mechanisms follow the repo's existing
absence-forcing patterns (test_part105_chains.py):
monkeypatched probes / locators at the exact seam the code
consults, PATH shims with fake executables, and an emptied
HOME so the conventional ~/workspace/tools discovery finds
nothing. Where a real tool is installed on this box under
~/workspace/tools (bundletool jar, Il2CppDumper.dll,
hermes-dec, GodotPckTool), PATH/env control alone cannot
force absence, so the locator/probe the audit names is
monkeypatched instead — and each test asserts the forcing
actually took effect before asserting the degradation.

C-05 note (STOPPED sub-assertion, newly-classified finding
candidate, reported with this file): with bundletool
absent, nar-triage's human() prints
"Package: unknown (aapt2 not found. See nar-doctor.sh)"
for an .aab input, NOT the bundletool line the annex
describes (nar-triage.py human(): the
badging_status == "not-found" branch is checked before the
is_aab branch, and for .aab inputs aapt2 is never consulted
at all — aapt2_badging delegates to bundletool_manifest).
The status/identity degradation itself is proven by the
passing tests below; the human-line expectation is pinned
as a strict xfail so the defect cannot silently rot and
the marker must be removed once the line is fixed.
"""
import importlib.util
import os
import shutil
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from narlib import chains  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_test_helper(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "tests" / "unit" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


nar_network = _load("nar_network_cert_fb", "nar-network.py")
nar_il2cpp = _load("nar_il2cpp_cert_fb", "nar-il2cpp.py")
nar_triage = _load("nar_triage_cert_fb", "nar-triage.py")
nar_godot = _load("nar_godot_cert_fb", "nar-godot.py")
nar_rn = _load("nar_rn_cert_fb", "nar-rn.py")

# Pair-building helpers reused from test_il2cpp.py, the
# encrypted-pack builder from test_godot.py, the Hermes
# header fixture from test_script.py, and the minimal-DEX
# builder from test_container_splits.py.
il2cpp_helpers = _load_test_helper(
    "test_il2cpp_helpers_cert_fb", "test_il2cpp.py")
godot_helpers = _load_test_helper(
    "test_godot_helpers_cert_fb", "test_godot.py")
script_helpers = _load_test_helper(
    "test_script_helpers_cert_fb", "test_script.py")
container_helpers = _load_test_helper(
    "test_container_helpers_cert_fb", "test_container_splits.py")


def _write_zip(path, members):
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)
    return str(path)


# ------------------------------------------------------------------
# C-01 (P1, Missing Test): apktool absence at nar-network's
# probe seam (parse_nsc). Designed degradation: the report
# records the note "network security config: apktool not
# available", network_security_config stays null, and the
# rest of the analysis completes.
# ------------------------------------------------------------------

def _apktool_unavailable_probe(seen):
    def probe(entry):
        seen.append(entry["name"])
        return {"name": entry["name"], "kind": entry["kind"],
                "required": entry.get("required", "optional"),
                "available": False, "path": None,
                "version": None, "note": "not found"}
    return probe


def test_c01_parse_nsc_apktool_absent_direct(monkeypatch):
    seen = []
    # nar-network probes apktool through narlib.registry
    # (reg_mod.probe); that is the seam forced here.
    monkeypatch.setattr(nar_network.reg_mod, "probe",
                        _apktool_unavailable_probe(seen))
    result, err = nar_network.parse_nsc("unused.apk", "unused-work")
    assert seen == ["apktool"]  # the forcing hit the named seam
    assert result is None
    assert err == "apktool not available"


def test_c01_analyze_records_degradation_and_completes(
        monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(nar_network.reg_mod, "probe",
                        _apktool_unavailable_probe(seen))
    strings_doc = {"groups": {
        "urls": {"hits": [
            {"value": "https://example.com/about",
             "sources": ["classes.dex"]}]},
        "api_endpoints": {"hits": []},
        "package_names": {"hits": []}}}
    triage_doc = {"library_versions": {}}

    def fake_tool(script, args, timeout=1800):
        return strings_doc if "strings" in script else triage_doc

    monkeypatch.setattr(nar_network, "run_json_tool", fake_tool)
    # Smallest APK-shaped input carrying a network security
    # config resource (the shape parse_nsc would decode with
    # apktool present); no NSC fixture exists in
    # test_network_phase5.py.
    target = _write_zip(tmp_path / "mini.apk", [
        ("AndroidManifest.xml", b"\x03\x00\x08\x00"),
        ("res/xml/network_security_config.xml",
         b'<network-security-config>'
         b'<base-config cleartextTrafficPermitted="false"/>'
         b'</network-security-config>'),
    ])
    work = tmp_path / "work"
    work.mkdir()
    report = nar_network.analyze(target, str(work))
    # Degradation recorded, NSC field null.
    assert report["network_security_config"] is None
    assert "network security config: apktool not available" \
        in report["notes"]
    # The rest of the analysis completed.
    assert report["tool"] == "nar-network"
    assert report["target_sha256"]
    assert [e["url"] for e in report["endpoints"]] == \
        ["https://example.com/about"]
    assert report["hosts"] == ["example.com"]
    assert report["classification_counts"] == {"dex-string": 1}
    assert report["network_libraries"] == []
    assert report["services"] == []
    assert "redaction" in report


# ------------------------------------------------------------------
# C-04 (P1, Missing Test): Il2CppDumper / Cpp2IL absence.
# Designed degradation: the pair is recognised and the
# metadata facts are reported; the backend block records
# found=false with error text stating the metadata result
# is the full result without the dumper.
# ------------------------------------------------------------------

def _il2cpp_pair_apk(tmp_path):
    return _write_zip(tmp_path / "game.apk", [
        (il2cpp_helpers.META, il2cpp_helpers._metadata_blob()),
        (il2cpp_helpers.SO, b"\x7fELF" + b"\x00" * 60),
    ])


def test_c04_il2cppdumper_absent_metadata_only(
        monkeypatch, tmp_path):
    # find_dumper is the seam (env override, tools dir and
    # PATH all live behind it; the tools-dir DLL is really
    # installed on this box, so the locator is forced).
    monkeypatch.setattr(nar_il2cpp, "find_dumper",
                        lambda: (None, None))
    target = _il2cpp_pair_apk(tmp_path)
    report = nar_il2cpp.analyze(target, str(tmp_path / "out"))
    # Pair recognised, metadata facts present.
    assert report["is_il2cpp"] is True
    assert report["backend"] == "il2cppdumper"
    meta = report["metadata"]
    assert meta["magic_ok"] is True
    assert meta["version"] == 31
    assert meta["size_bytes"] == len(il2cpp_helpers._metadata_blob())
    assert report["binary"]["abi"] == "arm64-v8a"
    assert report["binary"]["size_bytes"] == 64
    # Dumper block: the recorded degradation.
    dumper = report["dumper"]
    assert dumper["found"] is False
    assert dumper["path"] is None
    assert dumper["via"] is None
    assert dumper["ran"] is False
    assert dumper["exit_code"] is None
    assert "Il2CppDumper not found" in dumper["error"]
    assert "$NAR_IL2CPPDUMPER_DLL" in dumper["error"]
    assert "The pair and metadata version above are the" \
        " full result without it." in dumper["error"]
    # Metadata-only result: no dump summary was invented.
    assert "summary" not in report
    assert "outputs" not in report


def test_c04_cpp2il_absent_metadata_only(monkeypatch, tmp_path):
    monkeypatch.setattr(nar_il2cpp, "find_cpp2il",
                        lambda: (None, None))
    target = _il2cpp_pair_apk(tmp_path)
    report = nar_il2cpp.analyze(
        target, str(tmp_path / "out"), backend="cpp2il")
    assert report["is_il2cpp"] is True
    assert report["metadata"]["version"] == 31
    assert report["metadata"]["magic_ok"] is True
    block = report["cpp2il"]
    assert block["found"] is False
    assert block["path"] is None
    assert block["ran"] is False
    assert block["exit_code"] is None
    assert "Cpp2IL not found" in block["error"]
    assert "$NAR_CPP2IL" in block["error"]
    assert "summary" not in report
    assert "outputs" not in report


# ------------------------------------------------------------------
# C-05 (P2, Missing Test): bundletool absence for a bundle
# (.aab) input. Designed degradation: identity status
# not-found, empty badging, package unknown in human output.
# (Human-line attribution defect: see the module docstring
# and the strict-xfail test below.)
# ------------------------------------------------------------------

def _aab_input(tmp_path):
    # AAB shape per test_container_splits.py: base module
    # manifest + dex + resources.pb inside a ZIP.
    return _write_zip(tmp_path / "app.aab", [
        ("base/manifest/AndroidManifest.xml", b"<manifest/>"),
        ("base/dex/classes.dex", b"dex\n039\x00" + b"\x00" * 100),
        ("base/resources.pb", b"\x00" * 10),
    ])


def test_c05_bundletool_manifest_absent_not_found(
        monkeypatch, tmp_path):
    # _find_bundletool is the seam (PATH binary, then
    # $BUNDLETOOL_JAR, then the tools-dir jar — the jar is
    # really installed on this box, so the locator itself
    # is forced to fail).
    monkeypatch.setattr(nar_triage, "_find_bundletool",
                        lambda: None)
    assert nar_triage._find_bundletool() is None
    target = _aab_input(tmp_path)
    info, status = nar_triage.bundletool_manifest(target)
    assert info == {}
    assert status == "not-found"
    # aapt2_badging delegates bundles to bundletool.
    info2, status2 = nar_triage.aapt2_badging(target)
    assert info2 == {}
    assert status2 == "not-found"


def test_c05_triage_aab_identity_degrades_not_found(
        monkeypatch, tmp_path):
    monkeypatch.setattr(nar_triage, "_find_bundletool",
                        lambda: None)
    target = _aab_input(tmp_path)
    report = nar_triage.triage(target)
    assert report["is_aab"] is True
    assert report["badging"] == {}
    assert report["badging_status"] == "not-found"
    # The rest of triage still completes.
    assert report["dex_count"] == 1
    assert report["signature_status"] == "not-applicable"
    text = nar_triage.human(report)
    assert "Package: unknown" in text
    assert ".aab bundle" in text


@pytest.mark.xfail(
    strict=True,
    reason="newly-classified defect candidate (Wave 3, "
           "C-05): human() checks badging_status == "
           "'not-found' before is_aab, so a bundletool-"
           "absent .aab prints the aapt2 line although "
           "aapt2 is never consulted for bundles; the "
           "designed bundletool line is unreachable on "
           "the absent path. Remove this marker when the "
           "branch order / attribution is fixed.")
def test_c05_triage_aab_human_line_names_bundletool(
        monkeypatch, tmp_path):
    monkeypatch.setattr(nar_triage, "_find_bundletool",
                        lambda: None)
    report = nar_triage.triage(_aab_input(tmp_path))
    text = nar_triage.human(report)
    assert "Package: unknown (bundletool could not read" \
        " the .aab manifest" in text


# ------------------------------------------------------------------
# C-07 (P2, Missing Test): GodotPckTool three branches.
# nar-godot locates the tool via shutil.which("godotpcktool")
# (PATH first), then ~/workspace/tools/godotpcktool/.
# Fixture: the encrypted format-2 pack from test_godot.py,
# whose own-parser listing is unavailable, which is exactly
# what triggers the tool-listing path.
# Windows note: a scripted fake executable is neither
# discoverable (PATHEXT requires a real extension) nor
# runnable there, so the two run-semantics tests are
# POSIX-only; Windows discovery of a real .exe through
# PATHEXT — the shape a shipped GodotPckTool takes — is
# covered by test_c07_godotpcktool_windows_discovery.
# ------------------------------------------------------------------

def _encrypted_pck(tmp_path):
    path = tmp_path / "enc.pck"
    path.write_bytes(godot_helpers.build_v2(encrypted=True))
    return str(path)


def _fake_tool(tmp_path, body):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    fake = bin_dir / "godotpcktool"
    fake.write_text(body, encoding="utf-8")
    fake.chmod(0o755)
    return fake


def test_c07_godotpcktool_absent(monkeypatch, tmp_path):
    # Absence forced the kill-switch way: PATH holds no
    # godotpcktool and HOME is emptied so the conventional
    # tools-dir fallback finds nothing either.
    empty_bin = tmp_path / "bin"
    empty_bin.mkdir()
    monkeypatch.setenv("PATH", str(empty_bin))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert nar_godot.find_godotpcktool() is None
    target = _encrypted_pck(tmp_path)
    files, err = nar_godot.tool_listing(target)
    assert files is None
    assert err == "GodotPckTool is not installed"
    report = nar_godot.inspect(target)
    pck = report["pck"]
    assert report["is_godot"] is True
    # Header facts kept, listing unavailable, error recorded.
    assert pck["format_version"] == 2
    assert pck["engine_version"] == "4.3.0"
    assert pck["encrypted"] is True
    assert pck["file_count"] is None
    assert "encrypted" in pck["listing_error"]
    assert pck["fallback_error"] == \
        "GodotPckTool is not installed"
    text = nar_godot.human(report, 50)
    assert "Listing unavailable" in text
    assert "fallback: GodotPckTool is not installed" in text


@pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows PATHEXT discovery shape")
def test_c07_godotpcktool_windows_discovery(
        monkeypatch, tmp_path):
    # On Windows a real GodotPckTool ships as an .exe and
    # shutil.which finds it through PATHEXT. An .exe-named
    # file on PATH is what find_godotpcktool must return.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "godotpcktool.exe"
    fake.write_bytes(b"")
    monkeypatch.setenv(
        "PATH", str(bin_dir) + os.pathsep
        + os.environ.get("PATH", ""))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert nar_godot.find_godotpcktool() == str(fake)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="a scripted fake executable is neither "
           "discoverable (PATHEXT) nor runnable on Windows; "
           "run semantics are covered on POSIX and Windows "
           "discovery by "
           "test_c07_godotpcktool_windows_discovery")
def test_c07_godotpcktool_failing_run_refused(
        monkeypatch, tmp_path):
    # A fake tool on PATH (which() wins over the tools-dir
    # copy) that prints a parseable-looking listing line
    # but exits non-zero: the run must be REFUSED as a
    # listing (stability audit B-10).
    fake = _fake_tool(
        tmp_path,
        "#!/bin/sh\n"
        "printf 'res://hello.txt size: 25\\n'\n"
        "echo 'boom' >&2\n"
        "exit 3\n")
    monkeypatch.setenv(
        "PATH", str(fake.parent) + os.pathsep
        + os.environ.get("PATH", ""))
    assert nar_godot.find_godotpcktool() == str(fake)
    target = _encrypted_pck(tmp_path)
    files, err = nar_godot.tool_listing(target)
    assert files is None
    assert err == "GodotPckTool exited 3: boom"
    report = nar_godot.inspect(target)
    pck = report["pck"]
    assert pck["file_count"] is None
    assert pck["listing_via"] == "stdlib"
    assert pck["fallback_error"] == \
        "GodotPckTool exited 3: boom"
    assert pck["format_version"] == 2
    assert pck["encrypted"] is True


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="a scripted fake executable is neither "
           "discoverable (PATHEXT) nor runnable on Windows; "
           "run semantics are covered on POSIX and Windows "
           "discovery by "
           "test_c07_godotpcktool_windows_discovery")
def test_c07_godotpcktool_serving_listing(monkeypatch, tmp_path):
    fake = _fake_tool(
        tmp_path,
        "#!/bin/sh\n"
        "printf 'res://hello.txt size: 25\\n"
        "res://project.godot size: 30\\n'\n"
        "exit 0\n")
    monkeypatch.setenv(
        "PATH", str(fake.parent) + os.pathsep
        + os.environ.get("PATH", ""))
    assert nar_godot.find_godotpcktool() == str(fake)
    target = _encrypted_pck(tmp_path)
    files, err = nar_godot.tool_listing(target)
    assert err is None
    assert files == [
        {"path": "res://hello.txt", "size_bytes": 25},
        {"path": "res://project.godot", "size_bytes": 30},
    ]
    report = nar_godot.inspect(target)
    pck = report["pck"]
    assert report["is_godot"] is True
    assert pck["listing_via"] == "godotpcktool"
    assert pck["file_count"] == 2
    assert [f["path"] for f in pck["files"]] == \
        ["res://hello.txt", "res://project.godot"]
    assert "fallback_error" not in pck


# ------------------------------------------------------------------
# C-08 (P2, Missing Test): hermes-dec absence. Designed
# degradation: the own Hermes header-parser result stands
# alone (detected verdict + header facts unchanged) and the
# report's hermes_dec block records ran=false + the
# not-installed error.
# ------------------------------------------------------------------

def test_c08_hermes_dec_absent_header_result_stands(
        monkeypatch, tmp_path):
    # find_hbc_parser is the seam (PATH binary, then the
    # tools-dir hermes-dec install — really present on this
    # box, so the locator is forced to not-installed).
    monkeypatch.setattr(nar_rn, "find_hbc_parser",
                        lambda: (None, None))
    info, err = nar_rn.hbc_cross_check("unused.bundle")
    assert info is None
    assert err == "hermes-dec (hbc-file-parser) is not installed"
    hermes = script_helpers.hermes_header()
    target = _write_zip(tmp_path / "rn.apk", [
        ("assets/index.android.bundle", hermes),
    ])
    report = nar_rn.inspect(target, str(tmp_path / "work"))
    # Detected verdict and header facts unchanged: exactly
    # the own parser's result on the same bytes.
    assert report["is_react_native"] is True
    assert report["engine"] == "Hermes"
    assert report["is_hermes"] is True
    assert report["hermes"] == nar_rn.parse_hermes_header(hermes)
    assert report["hermes"]["bytecode_version"] == 96
    assert report["hermes"]["function_count"] == 7
    assert report["hermes"]["string_count"] == 13
    assert report["hermes"]["identifier_count"] == 11
    # Cross-check degradation recorded.
    assert report["hermes_dec"] == {
        "ran": False,
        "error": "hermes-dec (hbc-file-parser) is not installed",
    }
    assert report.get("cross_check_agrees") is None
    text = nar_rn.human(report)
    assert "hermes-dec cross-check: unavailable" in text
    assert "hermes-dec (hbc-file-parser) is not installed" in text


# ------------------------------------------------------------------
# C-09 (P3, Known Limitation — pin the designed state; do
# NOT change behaviour): (a) the one wired chain emits a
# Fallback Record with explicit field VALUES on the
# floor-serves path; (b) the registry still declares 16
# chains with only java-decompile wired end-to-end.
# ------------------------------------------------------------------

def test_c09a_floor_serves_record_fields_explicit(
        monkeypatch, tmp_path):
    # Floor-serves path, forced the same kill-switch way as
    # test_part105_chains (stripped PATH, emptied HOME) but
    # on a self-contained synthetic DEX, asserting the
    # record's field VALUES that test_part105 only checks
    # for shape — including the per-rung NOT_INSTALLED
    # records of the two dex2jar rungs (annex CD
    # cross-cutting note).
    shim = tmp_path / "shim"
    shim.mkdir()
    java = shutil.which("java")
    if java:
        os.symlink(java, shim / "java")
    monkeypatch.setenv("PATH", str(shim))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    for key in ("ANDROID_HOME", "ANDROID_SDK_ROOT",
                "NAR_JADX_PATH", "NAR_APKTOOL_JAR"):
        monkeypatch.delenv(key, raising=False)
    target = _write_zip(tmp_path / "mini.apk", [
        ("classes.dex", container_helpers.build_dex()),
    ])
    record = chains.run_decompile_chain(
        target, str(tmp_path / "work"))
    # The Fallback Record fields, explicitly.
    assert set(record.keys()) == {
        "capability", "chain", "attempts", "served_by",
        "fidelity", "caveats"}
    assert record["capability"] == "java-decompile"
    assert record["chain"] == [
        "jadx", "baksmali", "dex2jar+cfr",
        "dex2jar+procyon", "nar-dex-disasm"]
    assert record["served_by"] == "nar-dex-disasm"
    assert record["served_by"] == \
        chains.CHAIN_REGISTRY["java-decompile"]["floor_rung"]
    # Fidelity is never upgraded: this synthetic DEX decodes
    # no method bytecode, so the floor honestly serves at
    # structural-summary, never at a source fidelity.
    assert record["fidelity"] in chains.FIDELITY_LADDER
    assert record["fidelity"] == "structural-summary"
    assert not record["fidelity"].startswith("source")
    # Attempts: every external rung failed NOT_INSTALLED
    # (the dex2jar rungs included), the floor served.
    assert [a["rung"] for a in record["attempts"]] == \
        record["chain"]
    for attempt in record["attempts"][:-1]:
        assert attempt["status"] == "failed"
        assert attempt["classification"] == "NOT_INSTALLED"
        assert attempt["reason"].startswith("NOT_INSTALLED:")
    assert record["attempts"][-1]["rung"] == "nar-dex-disasm"
    assert record["attempts"][-1]["status"] == "ok"
    # Caveats carry the floor's honesty labels.
    assert record["caveats"]
    assert all(isinstance(c, str) for c in record["caveats"])
    assert "built-in disassembly is a bytecode listing," \
        " not Java source" in record["caveats"]


def test_c09b_registry_pins_sixteen_declared_one_wired():
    data = chains.registry_as_dict()
    expected = {
        "java-decompile", "manifest-decode",
        "resource-table", "signature", "il2cpp-dump",
        "unity-assets", "unreal-packages", "unreal-pak",
        "godot", "flutter", "hermes", "native-decompile",
        "networking-runtime", "runtime-hooks",
        "xamarin-dotnet", "audio-banks",
    }
    # Sixteen declared chains, each with a real rung list.
    assert len(data) == 16
    assert set(data.keys()) == expected
    for cap, entry in data.items():
        assert entry["chain"], cap
    # Exactly one chain declares itself wired end-to-end.
    wired = [cap for cap, entry in chains.CHAIN_REGISTRY.items()
             if entry["notes"].startswith("Wired end-to-end")]
    assert wired == ["java-decompile"]
    # And exactly one production wiring exists in the tree:
    # no script calls the generic runner directly, and only
    # nar-analyze calls the decompile chain. If another
    # chain is ever wired, this test fails on purpose —
    # the disclosed limitation (chains.py module docstring:
    # the other capabilities are "declared, not re-wired")
    # must be updated in the same change.
    direct_runner_callers = []
    decompile_callers = []
    for path in sorted(SCRIPTS.rglob("*.py")):
        if path == SCRIPTS / "narlib" / "chains.py":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if "run_chain(" in text:
            direct_runner_callers.append(path.name)
        if "run_decompile_chain(" in text:
            decompile_callers.append(path.name)
    assert direct_runner_callers == []
    assert decompile_callers == ["nar-analyze.py"]
