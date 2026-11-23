"""Unit tests for narlib.iostore on synthetic containers.

Two builders construct small IoStore (.utoc + .ucas) pairs
byte-exactly per the public TOC layout, one per era:

- current (UE5-era, TOC v6): TocHeaderSize field, 10-byte
  big-endian offset/length records, perfect-hash seeds +
  without-hash indices, 33-byte chunk-hash meta records;
- legacy (UE4 experimental, TOC v4): no TocHeaderSize
  field, 8-byte packed little-endian offset/length
  records, seeds only, 21-byte SHA-1 meta records.

Each container holds three chunks (one stored, one
zlib-compressed, one stored spanning two compression
blocks) and a directory index naming all three. No
external fixtures, no app data.
"""
import hashlib
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]
                       / "scripts"))

from narlib.iostore import (IoStoreError, chunk_sha1_ok,  # noqa: E402
                            extract_chunk, parse_utoc)

BLOCK_SIZE = 4096
CHUNK_A = b"NAR synthetic chunk A payload. " * 6          # 186
CHUNK_B = b"bulk-data-pattern-" * 60                      # 1080
CHUNK_C = bytes(range(256)) * 20                          # 5120
INVALID = 0xFFFFFFFF


def _fstring(s):
    raw = s.encode("utf-8") + b"\x00"
    return struct.pack("<i", len(raw)) + raw


def _block_entry(offset, csize, usize, method):
    return (offset.to_bytes(5, "little") + csize.to_bytes(3, "little")
            + usize.to_bytes(3, "little") + bytes([method]))


def _chunk_id(cid, index, ctype):
    return (struct.pack("<Q", cid) + index.to_bytes(2, "big")
            + b"\x00" + bytes([ctype]))


def _dir_index():
    return b"".join([
        _fstring("../../../SyntheticGame/"),
        struct.pack("<I", 2),                      # directories
        _fstring(""), struct.pack("<III", 1, 2, INVALID),
        _fstring("Content"), struct.pack("<III", INVALID, 0, INVALID),
        struct.pack("<I", 3),                      # files
        _fstring("ChunkA.uasset"), struct.pack("<II", 1, 0),
        _fstring("ChunkB.ubulk"), struct.pack("<II", INVALID, 1),
        _fstring("global_names.bin"), struct.pack("<II", INVALID, 2),
    ])


def _blocks_and_ucas():
    z_b = zlib.compress(CHUNK_B)
    blocks = [
        _block_entry(0, len(CHUNK_A), len(CHUNK_A), 0),
        _block_entry(len(CHUNK_A), len(z_b), len(CHUNK_B), 1),
        _block_entry(len(CHUNK_A) + len(z_b), 4096, 4096, 0),
        _block_entry(len(CHUNK_A) + len(z_b) + 4096, 1024, 1024, 0),
    ]
    return blocks, CHUNK_A + z_b + CHUNK_C


def _chunk_ids():
    # UE5-era type bytes: 1 ExportBundleData, 2 BulkData,
    # 10 PackageStoreEntry.
    return b"".join([
        _chunk_id(0xAAAA000000000001, 0, 1),
        _chunk_id(0xBBBB000000000002, 1, 2),
        _chunk_id(0xCCCC000000000003, 2, 10),
    ])


def build_current(method_name=b"Zlib"):
    """TOC v6, current layout. Returns (utoc, ucas)."""
    blocks, ucas = _blocks_and_ucas()
    dir_index = _dir_index()
    header = b"".join([
        b"-==--==--==--==-",
        bytes([6, 0]), struct.pack("<H", 0),       # version, reserved
        struct.pack("<I", 144),                    # TocHeaderSize
        struct.pack("<I", 3),                      # toc entries
        struct.pack("<I", 4),                      # compressed blocks
        struct.pack("<I", 12),                     # block entry size
        struct.pack("<I", 1),                      # method names
        struct.pack("<I", 32),                     # method name length
        struct.pack("<I", BLOCK_SIZE),
        struct.pack("<I", len(dir_index)),
        struct.pack("<I", 1),                      # partitions
        struct.pack("<Q", 0x1122334455667788),     # container id
        b"\x00" * 16,                              # encryption guid
        bytes([0x09, 0]), struct.pack("<H", 0),    # flags, enc, res
        struct.pack("<I", 2),                      # perfect hash seeds
        struct.pack("<Q", len(ucas)),              # partition size
        struct.pack("<I", 1),                      # without perfect hash
        struct.pack("<I", 0),                      # reserved7
        b"\x00" * 40,                              # reserved8[5]
    ])
    assert len(header) == 144

    def offlen(offset, length):
        return (offset.to_bytes(5, "big")
                + length.to_bytes(5, "big"))

    sections = b"".join([
        _chunk_ids(),
        offlen(0, len(CHUNK_A)),
        offlen(BLOCK_SIZE, len(CHUNK_B)),
        offlen(2 * BLOCK_SIZE, len(CHUNK_C)),
        struct.pack("<ii", 111, -222),             # hash seeds
        struct.pack("<i", 2),                      # without-hash idx
        b"".join(blocks),
        method_name.ljust(32, b"\x00"),
        dir_index,
        b"".join(hashlib.sha256(c).digest() + b"\x00"
                 for c in (CHUNK_A, CHUNK_B, CHUNK_C)),
    ])
    return header + sections, ucas


def build_legacy():
    """TOC v4, legacy layout. Returns (utoc, ucas)."""
    blocks, ucas = _blocks_and_ucas()
    dir_index = _dir_index()
    header = b"".join([
        b"-==--==--==--==-",
        bytes([4, 0]), struct.pack("<H", 0),       # version, reserved
        struct.pack("<I", 3),                      # toc entries
        struct.pack("<I", 4),                      # compressed blocks
        struct.pack("<I", 12),                     # block entry size
        struct.pack("<I", 1),                      # method names
        struct.pack("<I", 32),                     # method name length
        struct.pack("<I", BLOCK_SIZE),
        struct.pack("<I", len(dir_index)),
        struct.pack("<I", 1),                      # partitions
        struct.pack("<Q", 0x1122334455667788),     # container id
        b"\x00" * 16,                              # encryption guid
        bytes([0x09, 0]), struct.pack("<H", 0),    # flags, res
        struct.pack("<I", 2),                      # perfect hash seeds
        struct.pack("<Q", len(ucas)),              # partition size
        struct.pack("<I", 0),                      # without (unused v4)
        struct.pack("<I", 0),                      # reserved7
        b"\x00" * 40,                              # reserved8[5]
    ])
    assert len(header) == 140

    def offlen(offset, length):
        return struct.pack("<Q", (length << 40) | offset)

    sections = b"".join([
        _chunk_ids(),
        offlen(0, len(CHUNK_A)),
        offlen(BLOCK_SIZE, len(CHUNK_B)),
        offlen(2 * BLOCK_SIZE, len(CHUNK_C)),
        struct.pack("<ii", 111, -222),             # hash seeds (v4: only)
        b"".join(blocks),
        b"Zlib".ljust(32, b"\x00"),
        dir_index,
        b"".join(hashlib.sha1(c).digest() + b"\x00"
                 for c in (CHUNK_A, CHUNK_B, CHUNK_C)),
    ])
    return header + sections, ucas


def _check_inventory(parsed):
    entries = parsed["entries"]
    assert [e["chunk_type_name"] for e in entries] == [
        "ExportBundleData", "BulkData", "PackageStoreEntry"]
    assert entries[0]["chunk_type_name_legacy"] == "InstallManifest"
    assert entries[0]["offset"] == 0
    assert entries[0]["length"] == len(CHUNK_A)
    assert entries[0]["compression_methods"] == ["None"]
    assert entries[0]["block_count"] == 1
    assert entries[1]["compression_methods"] == ["Zlib"]
    assert entries[1]["stored_size"] == len(zlib.compress(CHUNK_B))
    assert entries[2]["offset"] == 2 * BLOCK_SIZE
    assert entries[2]["length"] == len(CHUNK_C)
    assert entries[2]["block_count"] == 2
    assert parsed["entries_by_type"] == {
        "ExportBundleData": 1, "BulkData": 1,
        "PackageStoreEntry": 1}
    assert parsed["total_chunk_bytes"] == \
        len(CHUNK_A) + len(CHUNK_B) + len(CHUNK_C)


def _check_paths(parsed):
    di = parsed["directory_index"]
    assert di["mount_point"] == "../../../SyntheticGame/"
    assert di["directory_count"] == 2
    assert di["file_count"] == 3
    files = {e["index"]: e.get("file") for e in parsed["entries"]}
    assert files[0] == "../../../SyntheticGame/Content/ChunkA.uasset"
    assert files[1] == "../../../SyntheticGame/Content/ChunkB.ubulk"
    assert files[2] == "../../../SyntheticGame/global_names.bin"


def test_current_header_fields():
    utoc, _ = build_current()
    parsed = parse_utoc(utoc, "synthetic.utoc")
    h = parsed["header"]
    assert h["layout"] == "current"
    assert h["version"] == 6
    assert h["version_name"] == "OnDemandMetaData"
    assert h["toc_header_size"] == 144
    assert h["header_size"] == 144
    assert h["toc_entry_count"] == 3
    assert h["container_id"] == 0x1122334455667788
    assert h["container_flag_names"] == ["Compressed", "Indexed"]
    assert h["encryption_key_guid_zero"] is True
    assert parsed["compression_methods"] == ["None", "Zlib"]
    assert parsed["perfect_hash_seed_count"] == 2
    assert parsed["chunks_without_perfect_hash"] == 1
    assert parsed["meta_present"] is True
    assert parsed["meta_entry_size"] == 33
    assert parsed["trailing_bytes"] == 0


def test_current_inventory_and_paths():
    utoc, _ = build_current()
    parsed = parse_utoc(utoc)
    _check_inventory(parsed)
    _check_paths(parsed)
    assert parsed["entries"][0]["chunk_hash"] == \
        hashlib.sha256(CHUNK_A).hexdigest()


def test_current_extract_byte_exact():
    utoc, ucas = build_current()
    parsed = parse_utoc(utoc)
    assert extract_chunk(parsed, ucas, 0) == CHUNK_A
    assert extract_chunk(parsed, ucas, 1) == CHUNK_B
    assert extract_chunk(parsed, ucas, 2) == CHUNK_C
    # Current containers carry a 32-byte chunk hash, not a
    # plain SHA-1: verification reports None, never a fake pass.
    assert all(chunk_sha1_ok(parsed, ucas, i) is None
               for i in range(3))


def test_legacy_layout_and_sha1():
    utoc, ucas = build_legacy()
    parsed = parse_utoc(utoc)
    h = parsed["header"]
    assert h["layout"] == "legacy"
    assert h["version"] == 4
    assert h["version_name"] == "PerfectHash"
    assert h["header_size"] == 140
    assert parsed["meta_entry_size"] == 21
    assert parsed["chunks_without_perfect_hash"] == 0
    _check_inventory(parsed)
    _check_paths(parsed)
    assert extract_chunk(parsed, ucas, 0) == CHUNK_A
    assert extract_chunk(parsed, ucas, 1) == CHUNK_B
    assert extract_chunk(parsed, ucas, 2) == CHUNK_C
    assert all(chunk_sha1_ok(parsed, ucas, i) is True
               for i in range(3))


def test_bad_magic_and_truncation():
    utoc, _ = build_current()
    for bad in (b"NOPE" + utoc[4:], utoc[:100], utoc[:200]):
        try:
            parse_utoc(bad)
        except IoStoreError:
            continue
        raise AssertionError("expected IoStoreError")


def test_unsupported_method_named_not_decoded():
    utoc, ucas = build_current(method_name=b"Oodle")
    parsed = parse_utoc(utoc)
    assert parsed["entries"][1]["compression_methods"] == ["Oodle"]
    try:
        extract_chunk(parsed, ucas, 1)
    except IoStoreError as e:
        assert "Oodle" in str(e)
    else:
        raise AssertionError("expected IoStoreError for Oodle chunk")
    # The stored chunk still extracts fine.
    assert extract_chunk(parsed, ucas, 0) == CHUNK_A
