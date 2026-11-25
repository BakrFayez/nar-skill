"""Part 3.2 gap-fill tests for nar-unreal: .bnk/.wem
audio-bank facts and the .locres census + decoder.

Fixtures are synthetic except the real-sample .locres
validation, which extracts the engine's own Engine.locres
from a retained real pak fixture (skipped when
NAR_FIXTURES does not provide it, per tree convention).

Covered:
- a synthetic v11 pak carrying one .bnk, one .wem and
  one .locres member: census counts + total sizes sit
  alongside the unchanged .uasset accounting, readable
  members carry mediainfo Wwise bank facts, and the
  .locres member is decoded (counts + sample keys);
- a standalone .bnk target reports bank facts;
- a standalone .locres target is decoded;
- an IoStore container whose .bnk chunk is stored
  carries bank facts, while the same chunk under an
  Oodle method name gets a named not-readable reason;
- narlib.locres validates end to end on a real sample
  (declared counts reconcile, offsets land inside the
  file, strings decode cleanly) and refuses bad magic.
"""
import hashlib
import importlib.util
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parents[2] / "scripts"))

import test_iostore  # noqa: E402
import test_pak  # noqa: E402
import test_textures_media  # noqa: E402
from narlib.locres import MAGIC, LocResError, parse_locres  # noqa: E402

INVALID = 0xFFFFFFFF
nar_pak = test_pak.nar_pak


def _run_unreal_cli(target, *extra):
    script = HERE.parents[2] / "scripts" / "nar-unreal.py"
    proc = subprocess.run(
        [sys.executable, str(script), str(target), "--json",
         *extra],
        capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


# ------------------------------------------------ synthetic .locres

def _fstr16(s):
    raw = s.encode("utf-16-le") + b"\x00\x00"
    return struct.pack("<i", -(len(raw) // 2)) + raw


def build_locres():
    """A minimal v1 (EntryMetaData) .locres: one
    namespace, two entries, two localized strings,
    laid out exactly per the public format."""
    entries = struct.pack("<I", 1)               # namespaces
    entries += _fstr16("TestNS")
    entries += struct.pack("<I", 2)              # entries
    entries += _fstr16("Hello") \
        + struct.pack("<Ii", 111, 0)             # hash, index
    entries += _fstr16("Dev") \
        + struct.pack("<Ii", 222, 1)
    string_array_offset = 25 + len(entries)
    array = struct.pack("<I", 2)
    array += _fstr16("World") + _fstr16("Development")
    return (MAGIC + bytes([1])
            + struct.pack("<q", string_array_offset)
            + entries + array)


def test_locres_synthetic_parse_and_refusals():
    parsed = parse_locres(build_locres(), "synth.locres")
    assert parsed["version"] == 1
    assert parsed["namespace_count"] == 1
    assert parsed["entry_count"] == 2
    assert parsed["string_count"] == 2
    assert parsed["entries"][0] == {
        "namespace": "TestNS", "key": "Hello",
        "source_string_hash": 111, "string_index": 0,
        "value": "World"}
    with pytest.raises(LocResError):
        parse_locres(b"\x00" * 40)
    with pytest.raises(LocResError):
        parse_locres(build_locres()[:-4])


# ------------------------------------------------ synthetic pak

def build_media_pak(members):
    """A complete synthetic v11 pak (the build_v11_encoded
    construction from test_pak) whose members are all
    stored: (name, payload) pairs."""
    data_region = b""
    blob = b""
    fdi_entries = []
    for name, payload in members:
        offset = len(data_region)
        data_region += test_pak._entry_header(
            len(payload), len(payload), 0, payload) + payload
        fdi_entries.append((name, len(blob)))
        blob += test_pak._encoded_record(
            offset, len(payload), len(payload), 0, ())

    mount = "../../../"
    ph_region = struct.pack("<Q", 0x1234) + struct.pack("<i", 0)
    fdi = struct.pack("<i", 1)
    fdi += test_pak._fstring("Game/Content/")
    fdi += struct.pack("<i", len(fdi_entries))
    for name, loc in fdi_entries:
        fdi += test_pak._fstring(name.rsplit("/", 1)[1])
        fdi += struct.pack("<i", loc)

    index_offset = len(data_region)
    idx_len = (len(test_pak._fstring(mount)) + 4 + 8 + 4 + 36
               + 4 + 36 + 4 + len(blob) + 4)
    ph_offset = index_offset + idx_len
    fdi_offset = ph_offset + len(ph_region)
    index = test_pak._fstring(mount)
    index += struct.pack("<i", len(members))
    index += struct.pack("<Q", 0x66AA1351)
    index += struct.pack("<i", 1)
    index += struct.pack("<q", ph_offset)
    index += struct.pack("<q", len(ph_region))
    index += hashlib.sha1(ph_region).digest()
    index += struct.pack("<i", 1)
    index += struct.pack("<q", fdi_offset)
    index += struct.pack("<q", len(fdi))
    index += hashlib.sha1(fdi).digest()
    index += struct.pack("<i", len(blob)) + blob
    index += struct.pack("<i", 0)
    assert len(index) == idx_len
    slots = (b"Zlib".ljust(32, b"\x00")
             + b"Oodle".ljust(32, b"\x00") + b"\x00" * 96)
    footer = (b"\x00" * 16 + b"\x00" + test_pak.MAGIC
              + struct.pack("<IQQ", 11, index_offset, len(index))
              + hashlib.sha1(index).digest() + slots)
    assert len(footer) == 221
    return data_region + index + ph_region + fdi + footer


def test_pak_media_census_bank_facts_and_locres(tmp_path):
    bnk = test_textures_media.make_bnk()
    wem = test_textures_media.make_wem()
    locres = build_locres()
    stored = b"STORED!" * 10
    pak = tmp_path / "media.pak"
    pak.write_bytes(build_media_pak([
        ("Game/Content/bank.bnk", bnk),
        ("Game/Content/voice.wem", wem),
        ("Game/Content/en.locres", locres),
        ("Game/Content/stored.uasset", stored),
    ]))
    report = _run_unreal_cli(pak)
    assert report["verdict"] == "pak-container"
    summary = report["paks"][0]
    # Existing accounting is unchanged.
    assert summary["uasset_count"] == 1
    assert summary["umap_count"] == 0
    assert summary["entry_count"] == 4
    # Additive census: counts + total sizes.
    assert summary["bnk_count"] == 1
    assert summary["bnk_total_bytes"] == len(bnk)
    assert summary["wem_count"] == 1
    assert summary["wem_total_bytes"] == len(wem)
    assert summary["locres_count"] == 1
    assert summary["locres_total_bytes"] == len(locres)
    # Bank facts for both readable audio members.
    facts = {r["file"]: r for r in summary["bank_facts"]}
    bank = facts["Game/Content/bank.bnk"]["bank"]
    assert bank["version"] == 140
    assert bank["bank_id"] == 0x11223344
    assert bank["section_ids"] == ["BKHD", "DIDX", "HIRC"]
    wem_facts = facts["Game/Content/voice.wem"]["bank"]
    assert wem_facts["is_wem"] is True
    assert wem_facts["channels"] == 2
    assert wem_facts["sample_rate_hz"] == 48000
    # The .locres member is decoded, counts + sample keys.
    loc = summary["locres_files"][0]
    assert loc["file"] == "Game/Content/en.locres"
    assert loc["locres"]["namespace_count"] == 1
    assert loc["locres"]["entry_count"] == 2
    assert loc["locres"]["string_count"] == 2
    assert loc["locres"]["sample_entries"][0] == {
        "namespace": "TestNS", "key": "Hello",
        "value": "World"}
    joined = " ".join(report["limitations"])
    assert ".locres" in joined and "decoded" in joined


# ------------------------------------------------ standalone targets

def test_standalone_bnk_and_wem_targets(tmp_path):
    bnk_path = tmp_path / "bank.bnk"
    bnk_path.write_bytes(test_textures_media.make_bnk())
    report = _run_unreal_cli(bnk_path)
    assert report["verdict"] == "audio-bank"
    record = report["bank_facts"][0]
    assert record["file"] == "bank.bnk"
    assert record["bank"]["version"] == 140
    assert record["bank"]["bank_id"] == 0x11223344

    wem_path = tmp_path / "voice.wem"
    wem_path.write_bytes(test_textures_media.make_wem())
    report = _run_unreal_cli(wem_path)
    assert report["verdict"] == "audio-bank"
    assert report["bank_facts"][0]["bank"]["is_wem"] is True
    assert report["bank_facts"][0]["bank"][
        "sample_rate_hz"] == 48000


def test_standalone_locres_target(tmp_path):
    target = tmp_path / "en.locres"
    target.write_bytes(build_locres())
    report = _run_unreal_cli(target)
    assert report["verdict"] == "locres"
    assert report["locres_count"] == 1
    assert report["locres_total_bytes"] == len(build_locres())
    loc = report["locres_files"][0]["locres"]
    assert loc["entry_count"] == 2
    assert loc["sample_entries"][1] == {
        "namespace": "TestNS", "key": "Dev",
        "value": "Development"}


# ------------------------------------------------ IoStore members

def _dir_index_named(names):
    """test_iostore's classic directory index with the
    three file names replaced."""
    return b"".join([
        test_iostore._fstring("../../../SyntheticGame/"),
        struct.pack("<I", 2),
        test_iostore._fstring(""),
        struct.pack("<III", 1, 2, INVALID),
        test_iostore._fstring("Content"),
        struct.pack("<III", INVALID, 0, INVALID),
        struct.pack("<I", 3),
        test_iostore._fstring(names[0]),
        struct.pack("<II", 1, 0),
        test_iostore._fstring(names[1]),
        struct.pack("<II", INVALID, 1),
        test_iostore._fstring(names[2]),
        struct.pack("<II", INVALID, 2),
    ])


def test_iostore_stored_bnk_bank_facts(tmp_path):
    bnk = test_textures_media.make_bnk()
    utoc, ucas = test_iostore.build_current(
        chunk_a=bnk,
        dir_index=_dir_index_named(
            ["bank.bnk", "ChunkB.ubulk", "global_names.bin"]))
    (tmp_path / "case.utoc").write_bytes(utoc)
    (tmp_path / "case.ucas").write_bytes(ucas)
    report = _run_unreal_cli(tmp_path / "case.utoc")
    container = report["iostore_containers"][0]
    assert container["bnk_count"] == 1
    assert container["bnk_total_bytes"] == len(bnk)
    assert container["wem_count"] == 0
    assert container["locres_count"] == 0
    facts = container["bank_facts"]
    assert len(facts) == 1
    assert facts[0]["file"].endswith("Content/bank.bnk")
    assert facts[0]["bank"]["bank_id"] == 0x11223344
    assert facts[0]["bank"]["version"] == 140


def test_iostore_oodle_bnk_not_readable(tmp_path):
    utoc, ucas = test_iostore.build_current(
        method_name=b"Oodle",
        dir_index=_dir_index_named(
            ["ChunkA.uasset", "bank.bnk", "global_names.bin"]))
    (tmp_path / "case.utoc").write_bytes(utoc)
    (tmp_path / "case.ucas").write_bytes(ucas)
    report = _run_unreal_cli(tmp_path / "case.utoc")
    container = report["iostore_containers"][0]
    assert container["bnk_count"] == 1
    facts = container["bank_facts"]
    assert len(facts) == 1
    assert facts[0]["file"].endswith("Content/bank.bnk")
    assert "bank" not in facts[0]
    assert "Oodle" in facts[0]["not_readable"]
    assert "not decoded" in facts[0]["not_readable"]


# ------------------------------------------------ real .locres sample

def test_locres_real_sample_validates(tmp_path):
    fixtures = os.environ.get("NAR_FIXTURES")
    if not fixtures:
        pytest.skip("NAR_FIXTURES not set")
    pak = Path(fixtures) / "games" / "unreal-pak-fixture.pak"
    if not pak.exists():
        pytest.skip(f"real pak fixture absent: {pak}")
    rep = nar_pak.extract_pak(
        str(pak),
        "Engine/Content/Localization/Engine/en/Engine.locres",
        str(tmp_path / "out"))
    assert len(rep["extracted"]) == 1, rep["extract_errors"]
    data = Path(rep["extracted"][0]["out_path"]).read_bytes()
    # parse_locres itself enforces the end-to-end rules:
    # the entry table ends exactly at the recorded string
    # array offset, the array ends exactly at EOF, every
    # string index lands inside the array, and every
    # string decodes strictly.
    parsed = parse_locres(data, "Engine.locres")
    assert parsed["version"] == 1
    assert parsed["namespace_count"] == 482
    assert parsed["entry_count"] == 4806
    assert parsed["string_count"] == 3791
    assert all(e["value"] == parsed["strings"][e["string_index"]]
               for e in parsed["entries"][:50])
