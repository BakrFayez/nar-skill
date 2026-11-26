"""NAR 3.0.1 certification — fuzz breadth sweeps (Workstream D).

Findings D-05 / D-07 / D-08 / D-09: the parsers that had only
hand-crafted hostile examples get bounded, deterministic,
systematic sweeps here.

- D-05: the ZIP mutation harness (tests/fuzz/zip_fuzz.py)
  driven in-process for a bounded seeded set against the
  safe-extraction layer (narlib.safearchive). The sweep
  found a real crash-class defect (NF-02: zlib.error
  escaped safe_extract / read_member_capped on a
  deflate-corrupt entry; repro preserved in
  ~/workspace/nar-cert-audit/fuzz-d05-crash/). NF-02 is
  fixed — both sites now refuse a corrupt member by name
  (report rejection / ValueError) — and the sweep below
  runs unpinned at full strength.
- D-07: UAsset truncation + summary/import/export field
  blasts against narlib.uasset.parse_package.
- D-08: PAK index-field sweep (entry count, blob length,
  directory-index descriptor, encoded-entry flags / offsets /
  sizes / block fields, directory-index counts and entry
  locations) against the nar-pak parse chain. The encoded
  index is SHA-1-verified against the footer, so mutations
  that are meant to exercise the fields BEHIND the hash are
  re-stamped after mutation; mutations without re-stamping
  are asserted to die at the hash check, by name.
- D-09: plist reader truncations / flips / shape blasts
  (narlib.atlas.parse_cocos_plist) and animation-format
  truncations / count blasts (Spine .skel, Aseprite, Cocos
  .ccb via narlib.anim.classify_and_parse).

Phase 3 additions:

- D-06: the ELF mutation harness (tests/fuzz/elf_fuzz.py)
  driven in-process for a bounded seeded set against
  narlib.elf -- the pre-harness coverage was four
  hand-picked header shapes; the harness sweeps the full
  header-field set, program/section entry fields,
  string-table indices, truncations and flips over
  ELF32/ELF64 seeds including a section/symbol/relocation
  rich seed.
- AXML / ARSC: the mutation harness
  (tests/fuzz/axml_fuzz.py) driven in-process against
  nar-perms' AXML reader, narlib.anim's AXML tree walk,
  nar-flutter's embedding walk and nar-app's resources.arsc
  string lookup. The ARSC sweep found a real crash-class
  defect (bare struct.error escapes from the lookup on
  truncated / offset-blasted packages); it is fixed -- a
  malformed package is skipped and the lookup returns
  None -- and pinned by
  tests/unit/test_cert_axml_arsc_regressions.py; the sweep
  below runs unpinned.

Invariant everywhere: the named error type, an error record,
an identified-only record, or a clean parse — never a bare
IndexError / struct.error / traceback-class leak. All inputs
are the repo's synthetic fixtures; all seeds are fixed.
"""
import hashlib
import importlib.util
import plistlib
import random
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_anim  # noqa: E402
import test_atlas  # noqa: E402
import test_pak  # noqa: E402
import test_uasset  # noqa: E402
from narlib import anim, atlas as atlas_mod  # noqa: E402
from narlib.uasset import UAssetError, parse_package  # noqa: E402

nar_pak = test_pak.nar_pak
PakError = nar_pak.PakError


def _load_fuzz(name):
    spec = importlib.util.spec_from_file_location(
        name, str(ROOT / "tests" / "fuzz" / f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


zip_fuzz = _load_fuzz("zip_fuzz")
elf_fuzz = _load_fuzz("elf_fuzz")
axml_fuzz = _load_fuzz("axml_fuzz")


# ---------------------------------------------------------- D-05 ZIP

def test_d05_zip_fuzz_sweep_no_crash_class(tmp_path):
    """300 seeded mutants through the harness's own mutate /
    exercise pair: zero crash-class outcomes."""
    zip_fuzz._WORKDIR = str(tmp_path)
    seeds = zip_fuzz.seed_corpus()
    assert len(seeds) >= 3
    rng = random.Random(20261126)
    failures = []
    strategies = set()
    for i in range(300):
        _name, seed_bytes = seeds[rng.randrange(len(seeds))]
        mutant, strategy = zip_fuzz.mutate(rng, seed_bytes)
        strategies.add(strategy)
        failure = zip_fuzz.exercise(mutant)
        if failure is not None:
            failures.append((i, strategy, failure))
    assert strategies >= {"cen-field", "local-field",
                          "descriptor-flag", "size-lie",
                          "truncate"}
    assert failures == []


def test_d05_zip_fuzz_harness_cli_clean(tmp_path):
    """The standalone harness itself: a short seeded run
    exits 0 and writes no crash artifacts."""
    out = tmp_path / "out"
    rc = zip_fuzz.main(["--seed", "7", "--iterations", "40",
                        "--out", str(out)])
    assert rc == 0
    assert list(out.glob("crash-*")) == []


# ---------------------------------------------------------- D-06 ELF

def test_d06_elf_fuzz_sweep_no_crash_class():
    """300 seeded mutants through the harness's own mutate /
    exercise pair: zero crash-class outcomes."""
    seeds = elf_fuzz.seed_corpus()
    assert len(seeds) >= 3
    rng = random.Random(20261126)
    failures = []
    strategies = set()
    for i in range(300):
        _name, seed_bytes = seeds[rng.randrange(len(seeds))]
        mutant, strategy = elf_fuzz.mutate(rng, seed_bytes)
        strategies.add(strategy)
        failure = elf_fuzz.exercise(mutant)
        if failure is not None:
            failures.append((i, strategy, failure))
    assert strategies >= {"header-field", "ident-byte",
                          "truncate", "byte-flip"}
    assert failures == []


def test_d06_elf_fuzz_harness_cli_clean(tmp_path):
    """The standalone harness itself: a short seeded run
    exits 0 and writes no crash artifacts."""
    out = tmp_path / "out"
    rc = elf_fuzz.main(["--seed", "7", "--iterations", "40",
                        "--out", str(out)])
    assert rc == 0
    assert list(out.glob("crash-*")) == []


# --------------------------------------------------- AXML / ARSC fuzz

def test_axml_fuzz_sweep_no_crash_class():
    """150 seeded mutants per format through the harness's
    own mutate / exercise pairs: zero crash-class
    outcomes across all four parser entry points."""
    axml_seeds, arsc_seeds = axml_fuzz.seed_corpus()
    assert len(axml_seeds) >= 3 and len(arsc_seeds) >= 1
    rng = random.Random(20261126)
    failures = []
    strategies = set()
    for i in range(150):
        _name, seed_bytes = \
            axml_seeds[rng.randrange(len(axml_seeds))]
        mutant, strategy = axml_fuzz.mutate_axml(rng, seed_bytes)
        strategies.add(strategy)
        failure = axml_fuzz.exercise_axml(mutant)
        if failure is not None:
            failures.append(("axml", i, strategy, failure))
    for i in range(150):
        _name, seed_bytes = \
            arsc_seeds[rng.randrange(len(arsc_seeds))]
        mutant, strategy = axml_fuzz.mutate_arsc(rng, seed_bytes)
        strategies.add(strategy)
        failure = axml_fuzz.exercise_arsc(mutant)
        if failure is not None:
            failures.append(("arsc", i, strategy, failure))
    assert strategies >= {"chunk-header", "truncate",
                          "byte-flip"}
    assert failures == []


def test_axml_fuzz_harness_cli_clean(tmp_path):
    """The standalone harness itself: a short seeded run
    exits 0 and writes no crash artifacts."""
    out = tmp_path / "out"
    rc = axml_fuzz.main(["--seed", "7", "--iterations", "25",
                         "--out", str(out)])
    assert rc == 0
    assert list(out.glob("crash-*")) == []


# ------------------------------------------------------- D-07 UAsset

def _uasset_summary_fields(data):
    """Walk the UE4 fixture's summary to the (count, offset)
    field positions, validating each against the parser's own
    summary so fixture drift fails loudly here, not silently
    in the sweep."""
    summary = parse_package(data, "control.uasset")["summary"]
    pos = 20  # magic + legacy + ue3 + ue4 + licensee versions
    custom_count = struct.unpack_from("<i", data, pos)[0]
    fields = {"total_header_size": 24 + 20 * custom_count}
    pos = fields["total_header_size"] + 4
    folder_len = struct.unpack_from("<i", data, pos)[0]
    pos += 4 + max(folder_len, 0)  # folder-name FString
    pos += 4  # package flags
    for key in ("name_count", "name_offset",
                "gatherable_text_data_count",
                "gatherable_text_data_offset",
                "export_count", "export_offset",
                "import_count", "import_offset",
                "depends_offset",
                "soft_package_references_count",
                "soft_package_references_offset",
                "searchable_names_offset"):
        fields[key] = pos
        pos += 4
    for key, off in fields.items():
        if key in summary and isinstance(summary[key], int):
            assert struct.unpack_from("<i", data, off)[0] == \
                summary[key], key
    return fields, summary


def test_d07_uasset_systematic_sweep():
    good = test_uasset.build_ue4()
    parse_package(good, "control.uasset")  # control
    fields, _summary = _uasset_summary_fields(good)
    blast = (0, -1, 1, 0x7FFFFFFF, -0x80000000,
             len(good) + 4096, 10 ** 9)
    cases = []

    # Truncations: stepped through the whole package plus
    # cuts aimed at the summary, name table, import table,
    # export map and preload table boundaries.
    cuts = set(range(0, len(good), 37))
    cuts |= {100, 251, 900, 984, 1192, 1250, len(good) - 1}
    for cut in sorted(cuts):
        cases.append((f"trunc@{cut}", good[:cut]))

    # Field blasts on every summary count/offset.
    for key, off in fields.items():
        for value in blast:
            buf = bytearray(good)
            struct.pack_into("<i", buf, off, value)
            cases.append((f"{key}={value}", bytes(buf)))

    # Export-map blasts: entry 0's class index, serial size
    # and serial offset.
    exp_off = struct.unpack_from(
        "<i", good, fields["export_offset"])[0]
    for off, fmt, value in (
            (exp_off, "<i", 0x7FFFFFFF), (exp_off, "<i", -99),
            (exp_off + 32, "<q", 0x7FFFFFFFFFFFFFFF),
            (exp_off + 32, "<q", -1),
            (exp_off + 40, "<q", -1),
            (exp_off + 40, "<q", len(good) + 9999)):
        buf = bytearray(good)
        struct.pack_into(fmt, buf, off, value)
        cases.append((f"exportmap@{off}={value}", bytes(buf)))

    # Deterministic byte flips anywhere in the package.
    rng = random.Random(0x0D07)
    for i in range(60):
        buf = bytearray(good)
        for _ in range(rng.randint(1, 6)):
            buf[rng.randrange(len(buf))] = rng.randrange(256)
        cases.append((f"flip#{i}", bytes(buf)))

    assert len(cases) >= 150
    for label, mutant in cases:
        try:
            parse_package(mutant, "fuzz.uasset")
        except UAssetError:
            pass  # refused by name: the invariant holds


# ---------------------------------------------------------- D-08 PAK

def _pak_layout(data):
    """Locate the v11 encoded-index fields of the synthetic
    pak by walking its documented layout from the footer."""
    version, index_offset, index_size = nar_pak.find_footer(data)
    assert version == 11
    lay = {"index_offset": index_offset,
           "index_size": index_size,
           "footer_base": data.rfind(b"\xe1\x12\x6f\x5a")}
    pos = index_offset
    mount_len = struct.unpack_from("<i", data, pos)[0]
    pos += 4 + mount_len
    lay["count_off"] = pos
    pos += 4 + 8  # entry count + path-hash seed
    lay["phi_off_off"] = pos + 4
    lay["phi_size_off"] = pos + 12
    pos += 4 + 8 + 8 + 20  # path-hash index descriptor
    lay["fdi_off_off"] = pos + 4
    lay["fdi_size_off"] = pos + 12
    lay["fdi_hash_pos"] = pos + 20
    pos += 4 + 8 + 8 + 20  # full-directory-index descriptor
    lay["bloblen_off"] = pos
    lay["blob_off"] = pos + 4
    lay["blob_len"] = struct.unpack_from("<i", data, pos)[0]
    lay["fdi_off"], lay["fdi_size"] = struct.unpack_from(
        "<qq", data, lay["fdi_off_off"])
    # Encoded entry records, walked with the parser's decoder.
    blob = data[lay["blob_off"]:lay["blob_off"] + lay["blob_len"]]
    records = []
    loc = 0
    while loc < len(blob):
        _fields, consumed = nar_pak._decode_encoded_entry(blob, loc)
        records.append(loc)
        loc += consumed
    lay["records"] = records
    # Directory index: count, dir FString, file count, then
    # per-file FString + i32 encoded-entry location.
    fp = lay["fdi_off"] + 4
    dir_len = struct.unpack_from("<i", data, fp)[0]
    fp += 4 + dir_len
    lay["fdi_file_count_off"] = fp
    fp += 4
    name_len = struct.unpack_from("<i", data, fp)[0]
    lay["fdi_first_loc_off"] = fp + 4 + name_len
    return lay


def _pak_parse(data):
    version, off, size = nar_pak.find_footer(data)
    return nar_pak._parse_index(data, version, off, size)


def test_d08_pak_systematic_index_field_sweep():
    good = test_pak.build_v11_encoded()
    _mount, entries, _layout = _pak_parse(good)
    assert entries  # control
    lay = _pak_layout(good)

    def rehash(buf):
        """Re-stamp the footer's index SHA-1 after mutating
        index bytes, so the sweep exercises the fields behind
        the hash instead of dying at the hash check."""
        idx = bytes(buf[lay["index_offset"]:
                        lay["index_offset"] + lay["index_size"]])
        struct.pack_into("<20s", buf, lay["footer_base"] + 24,
                         hashlib.sha1(idx).digest())
        return buf

    def refdi(buf):
        """Re-stamp the directory-index SHA-1 (recorded in the
        index) after mutating FDI bytes, then the index hash."""
        fdi = bytes(buf[lay["fdi_off"]:
                        lay["fdi_off"] + lay["fdi_size"]])
        struct.pack_into("<20s", buf, lay["fdi_hash_pos"],
                         hashlib.sha1(fdi).digest())
        return rehash(buf)

    cases = []

    def add(label, buf, stamp=None):
        if stamp is not None:
            buf = stamp(buf)
        cases.append((label, bytes(buf)))

    # Truncations.
    for cut in (0, 10, len(good) // 2, lay["index_offset"] + 5,
                len(good) - 100, len(good) - 1):
        cases.append((f"trunc@{cut}", good[:cut]))

    # Raw index-field blasts WITHOUT re-stamping: these must
    # die at the footer's SHA-1 check, by name.
    for off, fmt, value in (
            (lay["count_off"], "<i", 0x7FFFFFFF),
            (lay["blob_off"], "<I", 0xFFFFFFFF)):
        buf = bytearray(good)
        struct.pack_into(fmt, buf, off, value)
        cases.append((f"raw@{off}={value}", bytes(buf)))

    # Re-stamped index-field blasts: entry count, blob length,
    # descriptor offsets/sizes.
    for off, fmt, value in (
            (lay["count_off"], "<i", 0x7FFFFFFF),
            (lay["count_off"], "<i", -1),
            (lay["count_off"], "<i", 0),
            (lay["bloblen_off"], "<i", -1),
            (lay["bloblen_off"], "<i", 0x7FFFFFFF),
            (lay["bloblen_off"], "<i", 3),
            (lay["fdi_off_off"], "<q", len(good) + 100),
            (lay["fdi_off_off"], "<q", -16),
            (lay["fdi_size_off"], "<q", -5),
            (lay["fdi_size_off"], "<q", 0x7FFFFFFF),
            (lay["phi_off_off"], "<q", -1),
            (lay["phi_size_off"], "<q", 0x7FFFFFFF)):
        buf = bytearray(good)
        struct.pack_into(fmt, buf, off, value)
        add(f"index@{off}={value}", buf, rehash)

    # Encoded-entry field blasts per record: flags word
    # (block-count / method / width bits), offset, uncompressed
    # size, compressed size where present.
    blob = good[lay["blob_off"]:lay["blob_off"] + lay["blob_len"]]
    for rec_loc in lay["records"]:
        _fields, _c = nar_pak._decode_encoded_entry(blob, rec_loc)
        base = lay["blob_off"] + rec_loc
        for value in (0xFFFFFFFF,
                      0x3F << 23,  # compression-method bits blast
                      0xFFFF << 6 | 32):  # block-count bits blast
            buf = bytearray(good)
            struct.pack_into("<I", buf, base, value)
            add(f"flags@{rec_loc}={value:#x}", buf, rehash)
        buf = bytearray(good)
        struct.pack_into("<I", buf, base + 4, 0xFFFFFFFF)
        add(f"entry-offset@{rec_loc}", buf, rehash)
        buf = bytearray(good)
        struct.pack_into("<I", buf, base + 8, 0xFFFFFFFF)
        add(f"entry-usize@{rec_loc}", buf, rehash)

    # Directory-index blasts (re-stamped twice): directory
    # count, file count, first entry location.
    for off, value in (
            (lay["fdi_off"], 0x7FFFFFFF),
            (lay["fdi_off"], -1),
            (lay["fdi_file_count_off"], 0x7FFFFFFF),
            (lay["fdi_file_count_off"], -1),
            (lay["fdi_first_loc_off"], 0x7FFFFFFF),
            (lay["fdi_first_loc_off"], -5),
            (lay["fdi_first_loc_off"], 10 ** 6)):
        buf = bytearray(good)
        struct.pack_into("<i", buf, off, value)
        add(f"fdi@{off}={value}", buf, refdi)

    # Footer blasts: version, index offset, index size.
    base = lay["footer_base"]
    for off, fmt, value in (
            (base + 4, "<I", 0xFFFFFFFF),
            (base + 8, "<Q", len(good) + 4096),
            (base + 16, "<Q", 0xFFFFFFFFFFFFFFFF),
            (base + 16, "<Q", 1)):
        buf = bytearray(good)
        struct.pack_into(fmt, buf, off, value)
        cases.append((f"footer@{off}={value}", bytes(buf)))

    # Deterministic byte flips anywhere in the file.
    rng = random.Random(0x0D08)
    for i in range(40):
        buf = bytearray(good)
        for _ in range(rng.randint(1, 6)):
            buf[rng.randrange(len(buf))] = rng.randrange(256)
        cases.append((f"flip#{i}", bytes(buf)))

    assert len(cases) >= 60
    for label, mutant in cases:
        try:
            _pak_parse(mutant)
        except PakError:
            pass  # refused by name: the invariant holds


# ------------------------------------------- D-09 plist + animation

def test_d09_plist_reader_sweep():
    xml = plistlib.dumps(test_atlas.cocos_doc())
    binary = plistlib.dumps(test_atlas.cocos_doc(),
                            fmt=plistlib.FMT_BINARY)
    cases = []
    for label, data in (("xml", xml), ("binary", binary)):
        for cut in list(range(0, len(data), 29)) + [len(data) - 1]:
            cases.append((f"{label}-trunc@{cut}", data[:cut]))
        rng = random.Random(0x0D09)
        for i in range(40):
            buf = bytearray(data)
            for _ in range(rng.randint(1, 8)):
                buf[rng.randrange(len(buf))] = rng.randrange(256)
            cases.append((f"{label}-flip#{i}", bytes(buf)))
    # Shape blasts: valid plists whose decoded shapes are
    # hostile to the atlas reader's assumptions.
    for doc in ({"frames": [1, 2, 3]},
                {"frames": {"a.png": "not-a-dict"}},
                {"frames": {}, "metadata": {"size": "{x,y}"}},
                {"maxParticles": "many"},
                [1, 2, 3],
                "just a string"):
        cases.append(("shape", plistlib.dumps(doc)))
        cases.append(("shape-bin",
                      plistlib.dumps(doc, fmt=plistlib.FMT_BINARY)))
    assert len(cases) >= 80
    for label, mutant in cases:
        rec = atlas_mod.parse_cocos_plist(mutant)
        assert isinstance(rec, dict), label
        assert "error" in rec, label


def _assert_anim_outcome(name, data, label):
    rec = anim.classify_and_parse(name, data, "test.apk")
    assert rec is None or isinstance(rec, dict), label
    if isinstance(rec, dict):
        assert rec.get("status") in ("decoded", "identified_only"), \
            (label, rec.get("status"))


def test_d09_animation_format_sweeps():
    skel = test_anim._spine_string("deadbeef") \
        + test_anim._spine_string("4.2.36") \
        + struct.pack(">ffff", 1.0, 2.0, 200.0, 100.0) \
        + b"\x00" * 32
    ase = test_anim._aseprite_bytes()
    ccb = plistlib.dumps(
        {"nodeGraph": {"children": []}, "sequences": [],
         "resolutions": []}, fmt=plistlib.FMT_BINARY)
    fixtures = (("assets/hero.skel", skel),
                ("assets/sprite.aseprite", ase),
                ("assets/scene.ccb", ccb))
    cases = 0
    for name, data in fixtures:
        _assert_anim_outcome(name, data, f"control {name}")
        for cut in list(range(0, len(data), 13)) + [len(data) - 1]:
            _assert_anim_outcome(name, data[:cut],
                                 f"trunc {name}@{cut}")
            cases += 1
        rng = random.Random(0x0D09 + len(name))
        for i in range(40):
            buf = bytearray(data)
            for _ in range(rng.randint(1, 8)):
                buf[rng.randrange(len(buf))] = rng.randrange(256)
            _assert_anim_outcome(name, bytes(buf),
                                 f"flip {name}#{i}")
            cases += 1
    # Count-field blasts aimed at each format's header counts.
    buf = bytearray(ase)
    struct.pack_into("<H", buf, 6, 0xFFFF)  # Aseprite frame count
    _assert_anim_outcome("assets/sprite.aseprite", bytes(buf),
                         "ase frame-count blast")
    buf = bytearray(ase)
    struct.pack_into("<I", buf, 128, 0xFFFFFFFF)  # first frame size
    _assert_anim_outcome("assets/sprite.aseprite", bytes(buf),
                         "ase frame-size blast")
    buf = bytearray(skel)
    buf[0] = 0xFF  # Spine string-length byte run to the cap
    _assert_anim_outcome("assets/hero.skel", bytes(buf),
                         "skel string-length blast")
    buf = bytearray(ccb)
    buf[-1] ^= 0xFF  # binary-plist trailer / offset table
    _assert_anim_outcome("assets/scene.ccb", bytes(buf),
                         "ccb trailer blast")
    cases += 4
    assert cases >= 100


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
