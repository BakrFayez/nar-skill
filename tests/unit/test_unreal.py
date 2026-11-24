"""nar-unreal presentation tests on synthetic IoStore
containers (builders imported from test_iostore, the
same pattern the e2e harness uses).

Covered here: a UE5 IoStore-native (Zen) package chunk
— package magic as a trailer, Zen header first — is
identified as a Zen package in the container package
report instead of being fed to the classic
FPackageFileSummary parser, which would misreport it
as a corrupt package.
"""
import json
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parents[2] / "scripts"))

import importlib.util  # noqa: E402

import test_iostore  # noqa: E402
import test_uasset  # noqa: E402
from narlib import iostore as _iostore_mod  # noqa: E402
from narlib import uasset as _uasset_mod  # noqa: E402
from narlib import zen as _zen_mod  # noqa: E402


def _load_nar_unreal():
    spec = importlib.util.spec_from_file_location(
        "nar_unreal_w2", HERE.parents[2] / "scripts"
        / "nar-unreal.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

PACKAGE_MAGIC_LE = b"\xc1\x83\x2a\x9e"

# Minimal Zen-shaped chunk: header-size field at +4,
# filler where the rest of the Zen header and the
# package body would sit, package magic as the last
# four bytes (the trailer trait).
ZEN_CHUNK = (b"\x00\x00\x00\x00" + struct.pack("<I", 64)
             + b"zen synthetic payload " * 3
             + PACKAGE_MAGIC_LE)


def test_iostore_zen_package_identified(tmp_path):
    utoc, ucas = test_iostore.build_current(chunk_a=ZEN_CHUNK)
    (tmp_path / "case.utoc").write_bytes(utoc)
    (tmp_path / "case.ucas").write_bytes(ucas)
    script = HERE.parents[2] / "scripts" / "nar-unreal.py"
    proc = subprocess.run(
        [sys.executable, str(script),
         str(tmp_path / "case.utoc"), "--json"],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    packages = report["iostore_packages"]
    assert len(packages) == 1
    record = packages[0]
    assert record["entry"].endswith("Content/ChunkA.uasset")
    assert record["format"] == "zen-package"
    assert record["size"] == len(ZEN_CHUNK)
    assert record["zen_header_size"] == 64
    assert "error" not in record

# ------------------------------------------------ capability reporting (W2)

def test_capabilities_match_parser_constants():
    ua = _uasset_mod.capabilities()
    assert ua["unversioned"]["assumed_ue5_object_version"] == \
        _uasset_mod.ASSUMED_UE5_FOR_UNVERSIONED == 1010
    assert ua["unversioned"]["assumed_ue4_object_version"] == \
        _uasset_mod.FINAL_UE4
    assert ua["table_layouts"]["ue4_object_versions"][
        "oldest_loadable"] == _uasset_mod.OLDEST_LOADABLE_UE4
    assert ua["table_layouts"]["ue4_object_versions"][
        "final"] == _uasset_mod.FINAL_UE4
    assert ua["property_decoding"]["confidence"] == \
        _uasset_mod.PROPERTY_CONFIDENCE
    tag = {t["ue5_object_version"]: t
           for t in ua["tag_extension_layouts"]}
    assert tag[1011]["status"] == "implemented"
    assert tag[1011]["verification"] == "synthetic"
    assert tag[1011]["layout"] == "ue5-tag-extension"
    assert tag["1012+"]["status"] == "implemented"
    assert tag["1012+"]["verification"] == "synthetic"
    assert tag["1012+"]["min_ue5_object_version"] == 1012
    assert ua["requires_usmap"]["requirement"] == ".usmap"


def test_zen_and_iostore_capabilities_match_parsers():
    zn = _zen_mod.capabilities()
    layouts = {lay["layout"]: lay for lay in zn["layouts"]}
    assert layouts["ue5_3_plus"]["verification"] == "real"
    assert layouts["ue5_3_plus"][
        "real_packages_verified"] == 1209
    assert layouts["pre_ue5_3"]["verification"] == "synthetic"
    assert layouts["ea_legacy"]["verification"] == "synthetic"
    io = _iostore_mod.capabilities()
    assert io["toc_versions"] == _iostore_mod.TOC_VERSIONS
    assert io["toc_version_range"] == [0, 10]
    assert [lay["layout"] for lay in
            io["directory_index_layouts"]] == [
                "classic", "pooled"]
    assert io["compression_methods_decoded"] == ["None", "Zlib"]
    assert io["compression_methods_decoded"] == \
        _iostore_mod.COMPRESSION_METHODS_DECODED


def test_generated_limitations_never_call_1011_1012_unsupported():
    nu = _load_nar_unreal()
    for text in (nu._package_limitations()
                 + nu._iostore_limitations()):
        if "1011" in text or "1012" in text:
            assert "unsupported" not in text.lower(), text
    joined = " ".join(nu._package_limitations())
    assert "1011" in joined and "1012" in joined
    assert "implemented" in joined
    assert "synthetic" in joined


def test_each_capability_fact_appears_in_limitations():
    nu = _load_nar_unreal()
    pkg = " ".join(nu._package_limitations())
    # uasset facts
    assert "ue5-tag-extension" in pkg
    assert "ue5-complete-type-name" in pkg
    assert "1010" in pkg  # unversioned assumption
    assert "522" in pkg
    assert ".usmap" in pkg
    assert "primitive types" in pkg
    assert "class-specific" in pkg
    assert "Kismet/Blueprint" in pkg
    # zen facts
    for name in ("ue5_3_plus", "pre_ue5_3", "ea_legacy"):
        assert name in pkg
    assert "1,209" in pkg
    assert "dependency-bundle" in pkg
    assert "imported-package-name" in pkg
    assert "Zen export property" in pkg
    # iostore facts
    io_text = " ".join(nu._iostore_limitations())
    assert "0-10" in io_text
    assert "classic" in io_text and "pooled" in io_text
    assert "None" in io_text and "Zlib" in io_text
    assert "Oodle" in io_text
    assert "named, not decoded" in io_text
    assert "AES-sealed" in io_text
    assert "never" in io_text and "decrypted" in io_text
    # capabilities embedded in the report agree with modules
    caps = nu.unreal_capabilities()
    assert caps["uasset"] == _uasset_mod.capabilities()
    assert caps["zen"] == _zen_mod.capabilities()
    assert caps["iostore"]["toc_versions"] == {
        str(k): v for k, v in
        _iostore_mod.TOC_VERSIONS.items()} or \
        caps["iostore"] == _iostore_mod.capabilities()


def test_report_on_synthetic_1011_shows_implemented(tmp_path):
    data = test_uasset.build_ue5(
        1011, test_uasset._ue5_1011_export_data())
    target = tmp_path / "synth1011.uasset"
    target.write_bytes(data)
    script = HERE.parents[2] / "scripts" / "nar-unreal.py"
    proc = subprocess.run(
        [sys.executable, str(script), str(target), "--json"],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    pkg = report["packages"][0]
    props = pkg["exports"][0]["properties"]
    assert props["tag_layout"] == "ue5-tag-extension"
    assert props["status"] == "parsed"
    joined = " ".join(report["limitations"])
    assert "1011" in joined and "implemented" in joined
    assert "synthetic" in joined
    for text in report["limitations"]:
        if "1011" in text or "1012" in text:
            assert "unsupported" not in text.lower(), text
    assert report["capabilities"]["uasset"][
        "tag_extension_layouts"][0]["status"] == "implemented"

# ------------------------------------------------ configurable limits (W3)

import zipfile  # noqa: E402


def _run_unreal_cli(target, *extra):
    script = HERE.parents[2] / "scripts" / "nar-unreal.py"
    proc = subprocess.run(
        [sys.executable, str(script), str(target), "--json",
         *extra],
        capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def _build_multi_apk(path):
    """Synthetic APK: 30 loose packages, 7 IoStore
    containers (one named package chunk each), 30 config
    files. Built only from the existing synthetic
    builders; no real app data."""
    ue5 = test_uasset.build_ue5()
    utoc, ucas = test_iostore.build_current()
    with zipfile.ZipFile(path, "w") as zf:
        for i in range(30):
            zf.writestr(f"assets/Content/Pkg{i:02d}.uasset",
                        ue5)
        for i in range(7):
            zf.writestr(f"assets/Paks/c{i}.utoc", utoc)
            zf.writestr(f"assets/Paks/c{i}.ucas", ucas)
        for i in range(30):
            zf.writestr(f"assets/Config/cfg{i:02d}.ini",
                        "[section]\n")
    return path


def test_limits_defaults_equal_historical_caps():
    nu = _load_nar_unreal()
    limits = nu.UnrealLimits()
    assert limits.max_packages == nu.PACKAGE_CAP == 5
    assert limits.max_containers == nu.CONTAINER_CAP == 5
    assert limits.max_chunks == nu.ENTRY_CAP == 250
    assert limits.max_names == nu.NAME_CAP == 500
    assert limits.max_searchable == nu.SEARCHABLE_CAP == 100
    assert limits.max_display == nu.DISPLAY_CAP == 25
    assert limits.max_iostore_package_containers == \
        nu.IOSTORE_PACKAGE_CONTAINER_CAP == 2


def test_default_caps_on_multi_fixture(tmp_path):
    apk = _build_multi_apk(tmp_path / "multi.apk")
    report = _run_unreal_cli(apk)
    assert report["limits"]["max_packages"] == 5
    assert len(report["packages"]) == 5
    assert report["package_counts"] == {
        "total": 30, "processed": 5, "skipped": 25,
        "failed": 0}
    assert len(report["iostore_containers"]) == 5
    assert report["iostore_container_counts"] == {
        "total": 7, "processed": 5, "skipped": 2,
        "failed": 0}
    # IoStore package extraction considers 2 containers
    # by default; each names one package chunk whose
    # payload is not a real package (a failed record).
    io_counts = report["iostore_package_counts"]
    assert io_counts["total"] == 2
    assert io_counts["failed"] == 2
    assert io_counts["processed"] == 0
    assert io_counts["skipped"] == 0
    assert io_counts["containers_considered"] == 2
    assert io_counts["containers_total"] == 7
    assert len(report["config_files"]) == 25
    assert report["config_file_counts"] == {
        "total": 30, "processed": 25, "skipped": 5,
        "failed": 0}
    assert len(report["package_files"]) == 25
    assert report["package_file_counts"]["total"] == 30
    assert report["package_file_count"] == 30


def test_raised_limits_process_more_with_counts(tmp_path):
    apk = _build_multi_apk(tmp_path / "multi.apk")
    report = _run_unreal_cli(
        apk, "--max-packages", "10", "--max-containers", "6")
    assert len(report["packages"]) == 10
    assert report["package_counts"] == {
        "total": 30, "processed": 10, "skipped": 20,
        "failed": 0}
    assert len(report["iostore_containers"]) == 6
    assert report["iostore_container_counts"]["skipped"] == 1


def test_all_flags_process_everything(tmp_path):
    apk = _build_multi_apk(tmp_path / "multi.apk")
    report = _run_unreal_cli(
        apk, "--all-packages", "--all-containers",
        "--all-details")
    assert len(report["packages"]) == 30
    assert report["package_counts"]["skipped"] == 0
    assert len(report["iostore_containers"]) == 7
    assert report["iostore_container_counts"]["skipped"] == 0
    io_counts = report["iostore_package_counts"]
    assert io_counts["containers_considered"] == 7
    assert io_counts["total"] == 7
    assert io_counts["failed"] == 7
    assert len(report["config_files"]) == 30
    assert len(report["package_files"]) == 30
    assert report["limits"]["max_packages"] == "unlimited"
    assert report["limits"]["max_chunks"] == "unlimited"


def test_cap_hit_leaves_note_and_counts(tmp_path):
    utoc, ucas = test_iostore.build_current()
    (tmp_path / "case.utoc").write_bytes(utoc)
    (tmp_path / "case.ucas").write_bytes(ucas)
    report = _run_unreal_cli(
        tmp_path / "case.utoc", "--max-chunks", "2")
    container = report["iostore_containers"][0]
    assert len(container["entries"]) == 2
    assert container["entries_counts"] == {
        "total": 3, "processed": 2, "skipped": 1,
        "failed": 0}
    assert "limited to 2 of 3" in container["entries_capped"]
    assert "--all-details" in container["entries_capped"]
    # The one named package chunk fails to parse as a
    # package: it is accounted as failed, never hidden.
    assert report["iostore_package_counts"] == {
        "total": 1, "processed": 0, "skipped": 0,
        "failed": 1}
    # APK-mode cap hits surface as limitation notes too.
    apk = _build_multi_apk(tmp_path / "multi.apk")
    report = _run_unreal_cli(apk)
    joined = " ".join(report["limitations"])
    assert "limited to 5 of 30" in joined
    assert "--all-packages" in joined
    assert "limited to 5 of 7" in joined
    assert "--all-containers" in joined


def test_package_detail_caps_accounted():
    nu = _load_nar_unreal()
    data = test_uasset.build_ue5()
    limits = nu.UnrealLimits(max_names=5, max_chunks=1)
    record = nu.package_summary(data, "synth.uasset",
                                limits=limits)
    total_names = record["counts"]["names"]
    assert len(record["names"]) == 5
    assert record["names_counts"] == {
        "total": total_names, "processed": 5,
        "skipped": total_names - 5, "failed": 0}
    assert "limited to 5" in record["names_capped"]
    assert "--max-names" in record["names_capped"]
    # Default limits reproduce the historical detail:
    # nothing is capped on this small package.
    record = nu.package_summary(data, "synth.uasset")
    assert "names_capped" not in record
    assert record["names_counts"]["skipped"] == 0
    assert len(record["names"]) == total_names
