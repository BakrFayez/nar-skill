"""W7 regression + security coverage (2.5.2).

Gap coverage only — the suites that already pin an area
(test_phase11_mutations, test_safearchive, test_schemas,
test_yaml_validation, test_phase8_orchestration,
test_unreal, the parser suites, test_synthetic_fixtures)
are not duplicated here. What this file adds:

- the nar-doctor ``nar-scripts`` check covering EVERY
  scripts/*.py (a W6-found defect: it compiled only a
  hand-listed 10 of 24 scripts while claiming "all");
- invalid offsets per parser (DEX / ELF / UAsset /
  IoStore / Zen) raising the module's named error, never
  a leaked IndexError / struct.error;
- oversized / hostile archive guards (safearchive
  declared sizes + entry count, a pak footer claiming an
  index larger than the file);
- memory-exhaustion guards on absurd header counts;
- invalid container metadata (pak magic / version,
  .utoc magic / TOC version, Zen trailer magic);
- partial pak extraction failures recorded per entry,
  at module level and at the CLI (exit code + JSON);
- orchestration / evidence / security surface:
  nar-analyze on garbage, evidence.validate on a
  malformed finding, nar-security redaction;
- path traversal on the extraction paths
  test_safearchive does not already cover (pak
  extraction, nar-input's extract command).

Three defects found by this workstream are fixed in the
tree and pinned here: narlib.elf leaking struct.error /
silently tolerating corrupt header offsets, nar-analyze
exiting 0 on a non-container target, and nar-pak
inflating a compressed entry fully before checking it
against its promised size.
"""
import copy
import hashlib
import importlib.util
import io
import json
import os
import struct
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_dex_elf  # noqa: E402
import test_iostore  # noqa: E402
import test_pak  # noqa: E402
import test_uasset  # noqa: E402
import test_zen  # noqa: E402
from narlib import evidence, safearchive  # noqa: E402
from narlib.dex import Dex, DexError  # noqa: E402
from narlib.elf import Elf, ElfError  # noqa: E402
from narlib.iostore import IoStoreError, extract_chunk, \
    parse_utoc  # noqa: E402
from narlib.uasset import UAssetError, parse_package  # noqa: E402
from narlib.zen import ZenError, is_zen_package, \
    parse_zen_package  # noqa: E402

nar_pak = test_pak.nar_pak
PakError = nar_pak.PakError


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _patch_i32(data, off, value):
    out = bytearray(data)
    struct.pack_into("<i", out, off, value)
    return bytes(out)


def _patch_u32(data, off, value):
    out = bytearray(data)
    struct.pack_into("<I", out, off, value)
    return bytes(out)


def _first_i32_variant(data, old, new, scan=256):
    """Patch the first header field whose i32 value is
    ``old`` (the UAsset builders return bare bytes, so the
    summary field is located by its parsed value; the
    tests assert on the resulting error text, which names
    the field, so a wrong candidate fails loudly)."""
    for off in range(0, min(scan, len(data) - 3)):
        if struct.unpack_from("<i", data, off)[0] == old:
            return _patch_i32(data, off, new)
    raise AssertionError(f"no i32 field with value {old}")


# ----------------------------------------------------- doctor

def test_doctor_nar_scripts_check_globs_every_script():
    """Static drift guard: the checked set must come from
    the scripts/*.py glob, never a hand-maintained list."""
    text = (SCRIPTS / "nar-doctor.sh").read_text()
    block = text.split("nar scripts (core", 1)[1].split(
        "# --- protection", 1)[0]
    assert '"$SCRIPT_DIR"/*.py' in block
    assert "nar-triage.py nar-strings.py" not in block


def test_doctor_reports_all_scripts_compile(tmp_path):
    """Behavioral: run the doctor; its nar-scripts detail
    must name the true scripts/*.py count, report ok, and
    leave no new __pycache__ in the tree."""
    scripts = sorted(SCRIPTS.glob("*.py"))
    assert len(scripts) >= 20
    cache_dir = SCRIPTS / "__pycache__"
    before = {p.name for p in cache_dir.glob("*")} \
        if cache_dir.is_dir() else set()
    env = dict(os.environ)
    jdk = Path.home() / "workspace" / "jdk-17.0.20.1+1"
    if jdk.is_dir():
        env.setdefault("JAVA_HOME", str(jdk))
    proc = subprocess.run(
        ["bash", str(SCRIPTS / "nar-doctor.sh"), "--json"],
        capture_output=True, text=True, timeout=300, env=env)
    doc = json.loads(proc.stdout)
    check = next(c for c in doc["checks"]
                 if c["name"] == "nar-scripts")
    assert check["status"] == "ok"
    assert check["detail"] == (
        f"all bundled scripts compile ({len(scripts)} scripts)")
    after = {p.name for p in cache_dir.glob("*")} \
        if cache_dir.is_dir() else set()
    assert after == before


# ------------------------------------------- invalid offsets

def test_dex_string_table_offset_beyond_eof():
    good = test_dex_elf.build_dex()
    # Header layout (builder-pinned): string_ids_size at
    # 56, string_ids_off at 60, type_ids_off at 68.
    assert Dex(good).string_ids_off == struct.unpack_from(
        "<I", good, 60)[0]
    with pytest.raises(DexError, match="string_ids"):
        Dex(_patch_u32(good, 60, 0x00FFFFF0))


def test_dex_type_table_offset_beyond_eof():
    good = test_dex_elf.build_dex()
    with pytest.raises(DexError, match="type_ids"):
        Dex(_patch_u32(good, 68, 0x00FFFFF0))


def test_elf_section_header_offset_beyond_eof():
    """Defect regression: sections() used to return []
    silently for a corrupt shoff, so facts() reported a
    section-less file instead of a corrupt one."""
    data = bytearray(test_dex_elf.build_elf64())
    struct.pack_into("<Q", data, 40, 0x00FFFFF0)   # shoff
    struct.pack_into("<H", data, 58, 64)           # shentsize
    struct.pack_into("<H", data, 60, 4)            # shnum
    with pytest.raises(ElfError, match="section header"):
        Elf(bytes(data)).sections()


def test_elf_program_header_offset_beyond_eof():
    """Defect regression: program_headers() leaked a bare
    struct.error for a corrupt phoff."""
    data = bytearray(test_dex_elf.build_elf64())
    struct.pack_into("<Q", data, 32, 0x00FFFFF0)   # phoff
    with pytest.raises(ElfError, match="program header"):
        Elf(bytes(data)).program_headers()


def test_elf_shstrndx_out_of_range():
    """Defect regression: an shstrndx outside the section
    table was silently treated as "no string table"."""
    data = bytearray(test_dex_elf.build_elf64())
    shoff = len(data)
    data += b"\x00" * 64                            # 1 section
    struct.pack_into("<Q", data, 40, shoff)
    struct.pack_into("<H", data, 58, 64)           # shentsize
    struct.pack_into("<H", data, 60, 1)            # shnum
    struct.pack_into("<H", data, 62, 99)           # shstrndx
    with pytest.raises(ElfError, match="out of range"):
        Elf(bytes(data)).sections()


def test_elf_truncated_elf64_header():
    """Defect regression: a 52-63 byte ELF64 header leaked
    struct.error from the header unpack."""
    with pytest.raises(ElfError, match="truncated ELF header"):
        Elf(test_dex_elf.build_elf64()[:56])


def test_uasset_name_offset_beyond_eof():
    good = test_uasset.build_ue4()
    summary = parse_package(good)["summary"]
    mutated = _first_i32_variant(
        good, summary["name_offset"], len(good) + 0x10000)
    with pytest.raises(UAssetError, match="name_offset"):
        parse_package(mutated)


def test_uasset_import_offset_beyond_eof():
    good = test_uasset.build_ue4()
    summary = parse_package(good)["summary"]
    mutated = _first_i32_variant(
        good, summary["import_offset"], len(good) + 0x10000)
    with pytest.raises(UAssetError, match="import_offset"):
        parse_package(mutated)


def test_iostore_extract_chunk_index_out_of_range():
    utoc, ucas = test_iostore.build_current()
    parsed = parse_utoc(utoc)
    with pytest.raises(IoStoreError, match="out of range"):
        extract_chunk(parsed, ucas, len(parsed["entries"]) + 100)


def test_iostore_extract_block_offset_outside_ucas():
    utoc, ucas = test_iostore.build_current()
    parsed = copy.deepcopy(parse_utoc(utoc))
    parsed["_blocks"][0]["offset"] = len(ucas) + 1000
    with pytest.raises(IoStoreError, match="past the .ucas"):
        extract_chunk(parsed, ucas, 0)


def test_zen_offset_table_entry_beyond_chunk():
    good = test_zen.current_fixture()
    parsed = parse_zen_package(good, "Content/Sec")
    # build_current's 52-byte summary: the imported
    # package names offset is the last i32, at byte 48.
    assert parsed["summary"][
        "imported_package_names_offset"] == struct.unpack_from(
            "<i", good, 48)[0]
    mutated = _patch_i32(good, 48, len(good) + 5000)
    with pytest.raises(ZenError):
        parse_zen_package(mutated, "Content/Sec")


# --------------------------------- memory-exhaustion guards

def test_absurd_header_counts_fail_fast_with_named_errors():
    """Headers claiming absurd counts must fail with the
    module's named error, without allocating the claimed
    amount (the whole group must return in seconds)."""
    started = time.monotonic()

    dex = _patch_u32(test_dex_elf.build_dex(), 56, 0x7FFFFFFF)
    with pytest.raises(DexError):
        Dex(dex)  # string_ids count (Phase 11 regression)

    zen = test_zen.current_fixture()
    name_map_off = parse_zen_package(
        zen, "Content/Sec")["summary"]["name_map_offset"]
    with pytest.raises(ZenError):
        parse_zen_package(
            _patch_i32(zen, name_map_off, 0x7FFFFFFF),
            "Content/Sec")  # name-batch count

    utoc, _ucas = test_iostore.build_current()
    # TOC header: entry count at byte 24 (after the magic,
    # version/reserved words and the TocHeaderSize field).
    assert parse_utoc(utoc)["header"]["toc_entry_count"] == \
        struct.unpack_from("<I", utoc, 24)[0]
    with pytest.raises(IoStoreError):
        parse_utoc(_patch_u32(utoc, 24, 0x7FFFFFFF))

    good = test_uasset.build_ue4()
    summary = parse_package(good)["summary"]
    mutated = _first_i32_variant(
        good, summary["name_count"], 0x7FFFFFFF)
    with pytest.raises(UAssetError, match="name_count"):
        parse_package(mutated)

    assert time.monotonic() - started < 10


# ------------------------------------- hostile archive sizes

def _zip_bytes(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


def test_safearchive_declared_huge_member_rejected(tmp_path):
    """A zip whose central directory declares a ~4 GiB
    member (16 real bytes) hits the per-file size guard
    on the DECLARED size, before any inflation."""
    raw = bytearray(_zip_bytes([("big.bin", b"x" * 16)]))
    central = raw.find(b"PK\x01\x02")
    assert central > 0
    # Central header: compressed size at +20, declared
    # uncompressed size at +24. A large declared compressed
    # size keeps the whole-archive ratio guard out of the
    # way so the per-file guard is the one that fires.
    struct.pack_into("<I", raw, central + 20, 100_000_000)
    struct.pack_into("<I", raw, central + 24, 0xFFFFFFFF)
    src = tmp_path / "declared.zip"
    src.write_bytes(bytes(raw))
    report = safearchive.safe_extract(str(src),
                                      str(tmp_path / "out"))
    assert report["extracted"] == []
    assert len(report["rejected"]) == 1
    assert "per-file size limit" in report["rejected"][0]["reason"]


def test_safearchive_member_count_guard(tmp_path):
    src = tmp_path / "many.zip"
    src.write_bytes(_zip_bytes(
        [(f"f{i}.txt", b"x") for i in range(6)]))
    report = safearchive.safe_extract(
        str(src), str(tmp_path / "out"),
        limits={"max_entries": 5})
    assert report["extracted"] == []
    assert report["rejected"][0]["entry"] == "(whole archive)"
    assert "entry count 6 exceeds limit 5" in \
        report["rejected"][0]["reason"]


def test_pak_footer_index_size_larger_than_file(tmp_path):
    data = bytearray(test_pak.build_v11_encoded())
    base = len(data) - 221  # v11 footer size (builder-pinned)
    # Footer: magic at base+17, version at base+21, index
    # offset at base+25, index size at base+33.
    struct.pack_into("<Q", data, base + 33, len(data) * 10)
    path = tmp_path / "huge-index.pak"
    path.write_bytes(bytes(data))
    report = nar_pak.list_pak(str(path))
    assert report["supported"] is False
    assert "outside the file" in report["error"]


# ---------------------------------- invalid container metadata

def test_pak_bad_magic_raises_pakerror(tmp_path):
    path = tmp_path / "zeros.pak"
    path.write_bytes(b"\x00" * 2048)
    with pytest.raises(PakError, match="footer magic"):
        nar_pak.list_pak(str(path))


def test_pak_unsupported_footer_version_reported(tmp_path):
    path = tmp_path / "v9.pak"
    path.write_bytes(_pak_with_version(9))
    report = nar_pak.list_pak(str(path))
    assert report["pak_version"] == 9
    assert report["supported"] is False
    assert "version 9" in report["error"]


def _pak_with_version(version):
    """A footer-only pak at an arbitrary version (the
    test_pak v11 builder's shape, version patched in the
    footer: magic at 16+1, version right after it)."""
    data = bytearray(test_pak.build_v11(0))
    struct.pack_into("<I", data, len(data) - 221 + 21, version)
    return bytes(data)


def test_utoc_bad_magic_and_unsupported_toc_version():
    utoc, _ucas = test_iostore.build_current()
    bad_magic = bytearray(utoc)
    bad_magic[0:4] = b"BAD!"
    with pytest.raises(IoStoreError, match="magic"):
        parse_utoc(bytes(bad_magic))
    # TOC version byte at 16, right after the magic.
    bad_version = bytearray(utoc)
    bad_version[16] = 99
    with pytest.raises(IoStoreError, match="TOC version"):
        parse_utoc(bytes(bad_version))


def test_zen_bad_trailer_magic_not_identified_or_parsed():
    good = test_zen.current_fixture()
    mutated = good[:-4] + b"BAD!"
    assert is_zen_package(good) is True
    assert is_zen_package(mutated) is False
    with pytest.raises(ZenError):
        parse_zen_package(mutated, "Content/Sec")


# -------------------------------- partial extraction failures

def _corrupted_v11_pak(tmp_path):
    """The test_pak v11 pak with the stored entry's payload
    flipped in place: its recorded SHA-1 no longer matches,
    while the zlib entries stay intact."""
    data = bytearray(test_pak.build_v11_encoded())
    at = data.find(b"STORED!")
    assert at > 0
    for i in range(at, at + 8):
        data[i] ^= 0xFF
    path = tmp_path / "corrupt.pak"
    path.write_bytes(bytes(data))
    return str(path)


def test_pak_partial_extraction_failure_is_per_entry(tmp_path):
    out = tmp_path / "out"
    report = nar_pak.extract_pak(
        _corrupted_v11_pak(tmp_path), "*.uasset", str(out))
    extracted = {e["name"] for e in report["extracted"]}
    assert extracted == {"Game/Content/zlib1.uasset",
                         "Game/Content/zlib2.uasset"}
    errors = {e["name"]: e["error"]
              for e in report["extract_errors"]}
    assert "SHA-1" in errors["Game/Content/stored.uasset"]
    assert "Oodle" in errors["Game/Content/oodle.uasset"]
    assert (out / "Game" / "Content" / "zlib1.uasset"
            ).read_bytes() == b"Z" * 1000


def test_pak_extract_cli_reports_errors_and_exits_nonzero(tmp_path):
    out = tmp_path / "out"
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / "nar-pak.py"),
         _corrupted_v11_pak(tmp_path), "--extract", "*.uasset",
         "--out", str(out), "--json"],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 1
    assert "Traceback" not in proc.stderr
    report = json.loads(proc.stdout)
    assert len(report["extracted"]) == 2
    assert len(report["extract_errors"]) == 2


def test_pak_stream_expanding_past_promised_size_refused():
    """Defect regression: extraction used to inflate a
    compressed entry fully and only then compare against
    the promised size. A stream expanding far past its
    promise is now refused at the promised bound."""
    import zlib as _zlib
    stream = _zlib.compress(b"\x00" * 100_000)
    header_len = 8 + 8 + 8 + 4 + 20 + 4 + 16 + 5
    header = b"".join([
        struct.pack("<Q", 0),
        struct.pack("<Q", len(stream)),
        struct.pack("<Q", 10),               # promised size
        struct.pack("<i", 1),                # method: zlib
        hashlib.sha1(b"\x00" * 10).digest(),
        struct.pack("<i", 1),                # one block
        struct.pack("<QQ", header_len, header_len + len(stream)),
        b"\x00" * 5,                         # trailer
    ])
    assert len(header) == header_len
    entry = {"offset": 0, "size_bytes": len(stream),
             "uncompressed_size_bytes": 10,
             "compression_method": 1, "compression": "Zlib",
             "encrypted": False}
    with pytest.raises(PakError, match="expands past"):
        nar_pak.extract_entry(header + stream, 5, (False, 5),
                              entry)


# ------------------------------------------------- traversal

def _fstring(s):
    raw = s.encode("utf-8") + b"\x00"
    return struct.pack("<i", len(raw)) + raw


def _build_classic_pak(entries):
    """A minimal classic (v5) pak of stored entries, for
    names the encoded-index builder cannot express."""
    data_region = b""
    records = b""
    for name, raw in entries:
        offset = len(data_region)
        header = b"".join([
            struct.pack("<Q", 0), struct.pack("<Q", len(raw)),
            struct.pack("<Q", len(raw)), struct.pack("<i", 0),
            hashlib.sha1(raw).digest(), b"\x00" * 5])
        data_region += header + raw
        records += b"".join([
            _fstring(name), struct.pack("<Q", offset),
            struct.pack("<Q", len(raw)),
            struct.pack("<Q", len(raw)), struct.pack("<i", 0),
            hashlib.sha1(raw).digest(), b"\x00" * 5])
    index = _fstring("../../../") + struct.pack("<i", len(entries)) \
        + records
    footer = test_pak.MAGIC + struct.pack(
        "<IQQ", 5, len(data_region), len(index)) + b"\x00" * 20
    return data_region + index + footer


def test_pak_traversal_entry_stays_inside_out_dir(tmp_path):
    pak = tmp_path / "trav.pak"
    pak.write_bytes(_build_classic_pak([
        ("../../evil.txt", b"evil"),
        ("ok/good.txt", b"good"),
    ]))
    out = tmp_path / "a" / "out"
    report = nar_pak.extract_pak(str(pak), "*", str(out))
    assert len(report["extracted"]) == 2
    # The traversal target a naive join would write to:
    assert not (tmp_path / "evil.txt").exists()
    # The entry lands inside the out dir under a sanitized
    # relative path instead.
    inside = [p for p in out.rglob("evil.txt")]
    assert len(inside) == 1
    assert inside[0].read_bytes() == b"evil"
    assert (out / "ok" / "good.txt").read_bytes() == b"good"


def test_nar_input_extract_rejects_traversal(tmp_path):
    src = tmp_path / "in.zip"
    src.write_bytes(_zip_bytes([("../evil.txt", b"x"),
                                ("ok.txt", b"y")]))
    out = tmp_path / "out"
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / "nar-input.py"),
         "extract", str(src), "--out", str(out), "--json"],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0
    report = json.loads(proc.stdout)
    reasons = [r["reason"] for r in report["rejected"]]
    assert any("traversal" in r for r in reasons)
    assert not (tmp_path / "evil.txt").exists()
    assert (out / "ok.txt").read_bytes() == b"y"


# --------------------------- orchestration / evidence / CLI

def test_nar_analyze_garbage_fails_cleanly(tmp_path):
    """Defect regression: nar-analyze used to exit 0 on a
    non-container target (triage's own error was ignored,
    and the report even claimed an "apk" identity). It now
    records a fatal and exits nonzero, with no traceback."""
    target = tmp_path / "garbage.bin"
    target.write_bytes(b"not an archive at all" * 4)
    out = tmp_path / "out"
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / "nar-analyze.py"),
         str(target), "--out", str(out), "--no-html", "--json"],
        capture_output=True, text=True, timeout=600)
    assert proc.returncode == 1
    assert "Traceback" not in proc.stderr
    report = json.loads(proc.stdout)
    assert "not a valid ZIP/APK container" in report["fatal"]
    written = json.loads((out / "report.json").read_text())
    assert written["fatal"] == report["fatal"]


def test_evidence_validate_rejects_malformed_finding():
    schema = json.loads(
        (ROOT / "schemas" / "security-findings.schema.json")
        .read_text())
    good = evidence.make_finding(
        "NAR-SEC-001", "Example", "high", "medium",
        "component", "AndroidManifest.xml", "evidence",
        "explanation", "impact", "remediation")
    assert evidence.validate({"findings": [good]}, schema) == []
    malformed = dict(good)
    del malformed["remediation"]
    del malformed["evidence"]
    errors = evidence.validate({"findings": [malformed]}, schema)
    assert any("missing required remediation" in e for e in errors)
    assert any("missing required evidence" in e for e in errors)
    bad_severity = dict(good, severity="fatal")
    errors = evidence.validate(
        {"findings": [bad_severity]}, schema)
    assert any("not in enum" in e for e in errors)


def test_nar_security_redacts_planted_cleartext_endpoint(tmp_path):
    """nar-security over a network report built by the real
    nar-network redaction pass (its tool calls stubbed, the
    phase-5 pattern): the planted credential value must
    never reach nar-security's JSON; findings carry counts
    and the REDACTED marker only."""
    secret = "PLANTEDSECRETVALUE42"
    net = _load("nar_network_for_w7", "nar-network.py")
    strings_doc = {"groups": {
        "urls": {"hits": [
            {"value": f"http://api.example.test/data"
                      f"?token={secret}",
             "sources": ["classes.dex"]},
            {"value": "http://plain.example.test/index.html",
             "sources": ["classes.dex"]},
        ]},
        "api_endpoints": {"hits": []},
        "package_names": {"hits": []}}}
    net.run_json_tool = lambda script, args, timeout=1800: \
        strings_doc if "strings" in script else \
        {"library_versions": {}}
    target = tmp_path / "target.apk"
    target.write_bytes(b"PK\x03\x04 planted")
    network_report = net.analyze(str(target))
    assert network_report["redaction"][
        "endpoint_values_redacted"] == 1

    sec = _load("nar_security_for_w7", "nar-security.py")
    docs = {"nar-perms.py": {"application": {},
                             "components": {},
                             "permissions": []},
            "nar-triage.py": {"signature_schemes": {},
                              "protections": {}},
            "nar-network.py": network_report}
    sec.run_json_tool = lambda script, args, timeout=1800: \
        docs[script]
    report = sec.review(str(target))
    blob = json.dumps(report)
    assert secret not in blob
    assert "REDACTED" in blob
    cleartext = [f for f in report["findings"]
                 if f["title"] == "Cleartext HTTP endpoints "
                                  "in code"]
    assert len(cleartext) == 1
    assert cleartext[0]["evidence"].startswith(
        "1 confirmed http:// endpoint(s)")
    assert report["severity_counts"]["medium"] >= 1
