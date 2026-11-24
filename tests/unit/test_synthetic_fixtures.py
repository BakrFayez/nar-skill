"""Regression tests for the public synthetic fixtures (W5).

These tests need NO private files: the fixtures are built
in a pytest tmp dir by tests/synthetic_fixtures.py, parsed
with the real narlib parsers, and checked against the
builder intent recorded in tests/expected_outputs.json
(parser output == builder intent; see the design note in
tests/synthetic_fixtures.py). CLI smoke runs the parser
CLIs that accept a bare file against the synthetic files
and asserts exit 0 plus the key JSON fields.

If a parser's output changes, these tests fail until the
builder intent in tests/synthetic_fixtures.py (and the
regenerated manifest) is updated deliberately -- that is
the regression signal this file exists to provide.
"""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve()
TESTS_DIR = HERE.parents[1]
ROOT = HERE.parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(TESTS_DIR))
sys.path.insert(0, str(SCRIPTS))

import synthetic_fixtures as sf  # noqa: E402

from narlib.dex import Dex  # noqa: E402
from narlib.elf import Elf  # noqa: E402
from narlib.iostore import parse_utoc  # noqa: E402
from narlib.uasset import parse_package  # noqa: E402
from narlib.zen import parse_zen_package  # noqa: E402


def _load_script(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


nar_pak = _load_script("nar_pak_for_synfix", "nar-pak.py")
nar_godot = _load_script("nar_godot_for_synfix", "nar-godot.py")

COMMITTED_MANIFEST = json.loads(
    (TESTS_DIR / "expected_outputs.json").read_text(
        encoding="utf-8"))


@pytest.fixture(scope="module")
def gen_dir(tmp_path_factory):
    out = tmp_path_factory.mktemp("synthetic-fixtures")
    sf.generate(out)
    return out


def facts(fixture_id):
    return COMMITTED_MANIFEST["fixtures"][fixture_id]["facts"]


def read(gen_dir, fixture_id, index=0):
    name = COMMITTED_MANIFEST["fixtures"][fixture_id][
        "files"][index]
    return (gen_dir / name).read_bytes()


# ------------------------------------------------ manifest hygiene

def test_committed_manifest_matches_builder_intent():
    # The committed manifest must be exactly what the
    # generator produces today; regenerate it with
    # tests/generate_fixtures.py when builder intent
    # changes deliberately.
    assert sf.expected_outputs() == COMMITTED_MANIFEST


def test_generated_files_match_manifest(gen_dir):
    for fixture_id, entry in \
            COMMITTED_MANIFEST["fixtures"].items():
        for name, size in entry["file_sizes"].items():
            path = gen_dir / name
            assert path.is_file(), (fixture_id, name)
            assert path.stat().st_size == size, (
                fixture_id, name)


# ------------------------------------------------ parser assertions

def test_dex_facts(gen_dir):
    f = facts("dex")
    dex = Dex(read(gen_dir, "dex"))
    assert dex.version == f["dex_version"]
    assert dex.string_ids_size == f["string_count"]
    assert dex.strings() == f["strings"]
    assert dex.type_ids_size == f["type_count"]
    assert dex.types() == f["types"]
    assert dex.proto_ids_size == f["proto_count"]
    assert dex.field_ids_size == f["field_count"]
    assert dex.method_ids_size == f["method_id_count"]
    assert dex.class_defs_size == f["class_def_count"]
    ref = dex.method_ref(0)
    assert [ref[0], ref[1]] == f["method_ref"]


def test_elf_facts(gen_dir):
    f = facts("elf")
    elf = Elf(read(gen_dir, "elf"))
    got = elf.facts()
    assert got["elf_class"] == f["elf_class"]
    assert got["arch"] == f["arch"]
    assert elf.arch == f["arch"]
    assert got["type"] == f["type"]
    assert got["soname"] == f["soname"]
    assert got["needed"] == f["needed"]
    assert len(elf.program_headers()) == \
        f["program_header_count"]
    assert len(elf.sections()) == f["section_count"]
    assert got["section_names"] == f["section_names"]


def test_pak_facts(gen_dir):
    f = facts("pak")
    path = gen_dir / COMMITTED_MANIFEST["fixtures"]["pak"][
        "files"][0]
    report = nar_pak.list_pak(str(path))
    assert report["pak_version"] == f["pak_version"]
    assert report["supported"] is f["supported"]
    assert report["index_encrypted"] is f["index_encrypted"]
    assert report["mount_point"] == f["mount_point"]
    assert report["entry_count"] == f["entry_count"]
    assert [e["name"] for e in report["entries"]] == \
        f["entry_names"]
    assert {e["name"]: e["compression"]
            for e in report["entries"]} == \
        f["compression_by_entry"]


def test_iostore_facts(gen_dir):
    f = facts("iostore")
    parsed = parse_utoc(
        (gen_dir / "synthetic.utoc").read_bytes())
    header = parsed["header"]
    assert header["layout"] == f["layout"]
    assert header["version"] == f["toc_version"]
    assert header["version_name"] == f["toc_version_name"]
    assert parsed["entry_count"] == f["chunk_count"]
    assert header["toc_compressed_block_entry_count"] == \
        f["compressed_block_count"]
    assert parsed["compression_methods"] == \
        f["compression_methods"]
    assert parsed["entries_by_type"] == f["entries_by_type"]
    assert [e["chunk_type_name"]
            for e in parsed["entries"]] == \
        f["chunk_type_names"]
    assert parsed["total_chunk_bytes"] == \
        f["total_chunk_bytes"]
    di = parsed["directory_index"]
    want = f["directory_index"]
    assert di["layout"] == want["layout"]
    assert di["mount_point"] == want["mount_point"]
    assert di["directory_count"] == want["directory_count"]
    assert di["file_count"] == want["file_count"]
    # The flattened paths ride on the entries' file fields
    # (the directory-index summary itself carries counts).
    assert [e.get("file") for e in parsed["entries"]] == \
        want["file_paths"]


def test_zen_facts(gen_dir):
    f = facts("zen")
    rec = parse_zen_package(read(gen_dir, "zen"),
                            "Content/MyPackage")
    assert rec["format"] == f["format"]
    assert rec["summary"]["layout"] == f["layout"]
    assert rec["summary"]["package_name"] == \
        f["package_name"]
    assert rec["names"] == f["names"]
    assert rec["counts"] == f["counts"]
    assert rec["trailer_magic_ok"] is f["trailer_magic_ok"]


@pytest.mark.parametrize("fixture_id", [
    "uasset_ue4", "uasset_unversioned", "uasset_ue5_1010",
    "uasset_ue5_1011", "uasset_ue5_1012",
])
def test_uasset_facts(gen_dir, fixture_id):
    f = facts(fixture_id)
    report = parse_package(read(gen_dir, fixture_id),
                           fixture_id + ".uasset")
    summary = report["summary"]
    assert summary["legacy_file_version"] == \
        f["legacy_file_version"]
    assert summary["file_version_ue4"] == \
        f["file_version_ue4"]
    assert summary["file_version_ue5"] == \
        f["file_version_ue5"]
    assert summary["folder_name"] == f["folder_name"]
    assert bool(summary.get("unversioned")) is \
        f["unversioned"]
    assert report["counts"] == f["counts"]
    if "export_tag_layout" in f:
        props = report["exports"][0]["properties"]
        assert props["status"] == \
            f["export_properties_status"]
        assert props["tag_layout"] == f["export_tag_layout"]


def test_godot_facts(gen_dir):
    f = facts("godot_pck")
    report = nar_godot.parse_pck(read(gen_dir, "godot_pck"))
    assert report["format_version"] == f["format_version"]
    assert report["engine_version"] == f["engine_version"]
    assert report["encrypted"] is f["encrypted"]
    assert report["file_count"] == f["file_count"]
    assert [e["path"] for e in report["files"]] == \
        f["file_paths"]
    assert report["total_content_bytes"] == \
        f["total_content_bytes"]


# ------------------------------------------------ CLI smoke

def _run_cli(script, *args):
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / script), *args],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, (
        script, proc.returncode, proc.stderr[-500:])
    return json.loads(proc.stdout)


def test_cli_unreal_on_synthetic_utoc(gen_dir):
    f = facts("iostore")
    report = _run_cli("nar-unreal.py",
                      str(gen_dir / "synthetic.utoc"),
                      "--json")
    assert report["verdict"] == "iostore-container"
    (container,) = report["iostore_containers"]
    assert container["entry_count"] == f["chunk_count"]
    assert container["header"]["version"] == \
        f["toc_version"]
    assert container["directory_index"]["file_count"] == \
        f["directory_index"]["file_count"]


def test_cli_unreal_on_synthetic_uasset(gen_dir):
    f = facts("uasset_ue4")
    report = _run_cli("nar-unreal.py",
                      str(gen_dir / "synthetic_ue4.uasset"),
                      "--json")
    (pkg,) = report["packages"]
    assert pkg["format"] == "unreal-package"
    assert pkg["counts"] == f["counts"]


def test_cli_pak_on_synthetic_pak(gen_dir):
    f = facts("pak")
    report = _run_cli("nar-pak.py",
                      str(gen_dir / "synthetic.pak"),
                      "--json")
    assert report["pak_version"] == f["pak_version"]
    assert report["entry_count"] == f["entry_count"]
    assert report["supported"] is True


def test_cli_native_on_synthetic_elf(gen_dir):
    f = facts("elf")
    report = _run_cli("nar-native.py",
                      str(gen_dir / "libsynthetic.so"),
                      "--json")
    (lib,) = report["libraries"]
    assert lib["arch"] == f["arch"]
    assert lib["elf_class"] == f["elf_class"]
    assert lib["soname"] == f["soname"]
    assert lib["needed"] == f["needed"]


def test_cli_dex_on_synthetic_dex(gen_dir):
    # nar-dex accepts a bare .dex target (its argparse help
    # names .dex explicitly), so it is smoked here rather
    # than skipped.
    f = facts("dex")
    report = _run_cli("nar-dex.py",
                      str(gen_dir / "synthetic.dex"),
                      "--json")
    (dex_file,) = report["dex_files"]
    assert "error" not in dex_file
    counts = dex_file["header_counts"]
    assert counts["strings"] == f["string_count"]
    assert counts["types"] == f["type_count"]
    assert counts["protos"] == f["proto_count"]
    assert counts["fields"] == f["field_count"]
    assert counts["methods"] == f["method_id_count"]
    assert counts["class_defs"] == f["class_def_count"]
    assert dex_file["dex_version"] == f["dex_version"]
