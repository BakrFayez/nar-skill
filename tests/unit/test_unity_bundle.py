"""First-party UnityFS bundle header inspection tests.

Synthetic bundles are built byte-exactly per the public
UnityFS layout (signature, format version, player/engine
version strings, size fields, archive flags; blocks info =
16-byte hash + block table + node table; data blocks are
the concatenated decompressed stream the node offsets
address). LZMA blocks use Unity's stream shape: a 5-byte
properties header (props byte + dictionary size) followed
by a raw LZMA1 stream, produced here with the stdlib.

The real-fixture cases resolve their targets through the
fixture manifest's role bindings (FIX_UNITY /
FIX_UNITY_BUNDLES) and skip when the corpus is absent;
they assert role-level facts only (header parses, the
LZ4HC blocks-info boundary is named).
"""
import importlib.util
import json
import lzma
import os
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"

_spec = importlib.util.spec_from_file_location(
    "nar_unity", SCRIPTS / "nar-unity.py")
nar_unity = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nar_unity)


def _fixture_path(role):
    env = os.environ.get("NAR_FIXTURES")
    if not env:
        return None
    manifest = Path(env) / "manifest.env"
    if not manifest.is_file():
        return None
    for line in manifest.read_text().splitlines():
        if line.startswith(role + "="):
            raw = line.split("=", 1)[1].strip().strip('"')
            raw = raw.replace("${NAR_FIXTURES}", env)
            path = Path(raw)
            return path if path.is_file() else None
    return None


# ------------------------------------------------------------ builders

def _cstr(text):
    return text.encode() + b"\x00"


def _lzma_unity_block(raw):
    """Compress raw as a Unity LZMA block: 5-byte
    properties header + raw LZMA1 stream (stdlib)."""
    filters = [{"id": lzma.FILTER_LZMA1,
                "dict_size": 1 << 23, "lc": 3, "lp": 0,
                "pb": 2}]
    comp = lzma.compress(raw, format=lzma.FORMAT_RAW,
                         filters=filters)
    props_byte = (2 * 5 + 0) * 9 + 3  # pb=2, lp=0, lc=3
    return bytes([props_byte]) + struct.pack("<I", 1 << 23) \
        + comp


def build_serialized_v22(metadata_size=100, trailing=7):
    """Serialized file, format 22: zeroed classic fields,
    endianness + reserved, then the extended header
    (metadata size u32, file size i64, data offset i64,
    one trailing i64)."""
    header_len = 48
    data_offset = header_len + metadata_size
    payload = b"OBJECTDATA"
    file_size = data_offset + len(payload)
    out = struct.pack(">IIII", 0, 0, 22, 0)
    out += b"\x00" + b"\x00\x00\x00"          # LE + reserved
    out += struct.pack(">Iqqq", metadata_size, file_size,
                       data_offset, trailing)
    assert len(out) == header_len
    return out + b"\x00" * metadata_size + payload


def build_serialized_v17():
    """Serialized file, format 17 (pre-22): classic u32
    fields, big-endian byte, distinctive reserved bytes."""
    metadata_size = 40
    header_len = 20
    data_offset = header_len + metadata_size
    payload = b"DATA"
    file_size = data_offset + len(payload)
    out = struct.pack(">IIII", metadata_size, file_size,
                      17, data_offset)
    out += b"\x01" + b"\x01\x02\x03"         # BE + reserved
    return out + b"\x00" * metadata_size + payload


def build_bundle(serialized_blobs, info_comp="none",
                 block_comp="none", version=8):
    """UnityFS bundle carrying the given serialized files
    as its nodes. blocks: one per serialized blob."""
    stream = b""
    blocks = []
    nodes = []
    for blob in serialized_blobs:
        offset = len(stream)
        if block_comp == "lzma":
            stored = _lzma_unity_block(blob)
            bflags = 1
        else:
            stored = blob
            bflags = 0
        blocks.append((len(blob), len(stored), bflags, stored))
        stream += stored
        nodes.append((offset, len(blob), 0x04,
                      f"file{len(nodes)}.assets"))
    info = b"\x00" * 16
    info += struct.pack(">i", len(blocks))
    for usize, csize, bflags, _stored in blocks:
        info += struct.pack(">IIH", usize, csize, bflags)
    info += struct.pack(">i", len(nodes))
    for offset, size, nflags, path in nodes:
        info += struct.pack(">QQI", offset, size, nflags)
        info += _cstr(path)
    if info_comp == "lzma":
        info_stored = _lzma_unity_block(info)
        info_type = 1
    else:
        info_stored = info
        info_type = 0
    flags = info_type | 0x40  # combined blocks+directory info
    header = _cstr("UnityFS") + struct.pack(">I", version)
    header += _cstr("5.x.x") + _cstr("2022.3.0f1")
    header_len = len(header) + 20
    if version >= 7:
        header_len = (header_len + 15) & ~15
    total = header_len + len(info_stored) + len(stream)
    header += struct.pack(">QIII", total, len(info_stored),
                          len(info), flags)
    header += b"\x00" * (header_len - len(header))
    return header + info_stored + stream


# ------------------------------------------------------------ tests

def test_bundle_uncompressed_round_trip():
    blob = build_serialized_v22()
    rec = nar_unity.parse_unityfs_bundle(
        build_bundle([blob]), "synthetic.bundle")
    assert rec["parsed"] is True
    assert rec["signature"] == "UnityFS"
    assert rec["bundle_format_version"] == 8
    assert rec["unity_version_player"] == "5.x.x"
    assert rec["unity_version_engine"] == "2022.3.0f1"
    assert rec["bundle_size_matches_data_length"] is True
    assert rec["blocks_info"]["compression"] == "none"
    assert rec["blocks"][0]["uncompressed_size"] == len(blob)
    assert rec["nodes"][0]["is_serialized_file"] is True
    sf = rec["serialized_file"]
    assert sf["status"] == "parsed"
    assert sf["format_version"] == 22
    assert sf["metadata_size"] == 100
    assert sf["file_size"] == len(blob)
    assert sf["data_offset"] == 148
    assert sf["endianness"] == "little"
    assert sf["reserved"] == [0, 0, 0]
    assert sf["header_size"] == 48
    assert sf["extended_trailing_i64"] == 7
    assert sf["file_size_matches_data_length"] is True


def test_bundle_lzma_round_trip_v17():
    blob = build_serialized_v17()
    rec = nar_unity.parse_unityfs_bundle(
        build_bundle([blob], info_comp="lzma",
                     block_comp="lzma"), "synthetic.bundle")
    assert rec["parsed"] is True
    assert rec["blocks_info"]["compression"] == "lzma"
    assert rec["blocks"][0]["compression"] == "lzma"
    sf = rec["serialized_file"]
    assert sf["status"] == "parsed"
    assert sf["format_version"] == 17
    assert sf["endianness"] == "big"
    assert sf["reserved"] == [1, 2, 3]
    assert sf["header_size"] == 20
    assert sf["file_size_matches_data_length"] is True


def test_bundle_lz4_blocks_info_boundary():
    # Blocks info declared LZ4HC with undecodable bytes:
    # the header parses, the boundary is named, no block
    # or node tables are claimed.
    header = _cstr("UnityFS") + struct.pack(">I", 8)
    header += _cstr("5.x.x") + _cstr("2022.3.0f1")
    header_len = (len(header) + 20 + 15) & ~15
    info = b"\xff" * 40
    total = header_len + len(info)
    header += struct.pack(">QIII", total, len(info), 183,
                          3 | 0x40 | 0x200)
    header += b"\x00" * (header_len - len(header))
    rec = nar_unity.parse_unityfs_bundle(header + info,
                                         "synthetic.bundle")
    assert rec["parsed"] is True
    assert rec["blocks_info"]["compression"] == "lz4hc"
    assert "blocks" not in rec and "nodes" not in rec
    assert any("lz4hc" in lim and "standard library" in lim
               for lim in rec["limitations"])


def test_bundle_lz4_data_block_boundary():
    # Blocks info stored plain, the data block is LZ4:
    # tables parse, the serialized-file header is
    # recorded unavailable with the boundary named.
    blob = build_serialized_v22()
    info = b"\x00" * 16 + struct.pack(">i", 1)
    info += struct.pack(">IIH", len(blob), 10, 3)
    info += struct.pack(">i", 1)
    info += struct.pack(">QQI", 0, len(blob), 0x04)
    info += _cstr("file0.assets")
    header = _cstr("UnityFS") + struct.pack(">I", 8)
    header += _cstr("5.x.x") + _cstr("2022.3.0f1")
    header_len = (len(header) + 20 + 15) & ~15
    total = header_len + len(info) + 10
    header += struct.pack(">QIII", total, len(info),
                          len(info), 0x40)
    header += b"\x00" * (header_len - len(header))
    rec = nar_unity.parse_unityfs_bundle(
        header + info + b"\xff" * 10, "synthetic.bundle")
    assert rec["nodes"][0]["is_serialized_file"] is True
    sf = rec["serialized_file"]
    assert sf["status"] == "unavailable"
    assert "lz4hc" in sf["reason"]


def test_bundle_bad_signature_rejected():
    with pytest.raises(nar_unity.BundleError):
        nar_unity.parse_unityfs_bundle(b"NotABundle\x00"
                                       + b"\x00" * 64)


def test_bundle_truncated_header_rejected():
    with pytest.raises(nar_unity.BundleError):
        nar_unity.parse_unityfs_bundle(b"UnityFS\x00\x00")


def test_serialized_header_errors():
    with pytest.raises(nar_unity.BundleError):
        nar_unity.parse_serialized_file_header(b"\x00" * 8)
    with pytest.raises(nar_unity.BundleError):
        # format version 0
        nar_unity.parse_serialized_file_header(
            struct.pack(">IIII", 0, 0, 0, 0) + b"\x00" * 8)
    with pytest.raises(nar_unity.BundleError):
        # invalid endianness byte (must be 0 or 1)
        nar_unity.parse_serialized_file_header(
            struct.pack(">IIII", 0, 24, 17, 20)
            + b"\x07\x00\x00\x00")


def test_serialized_header_pre9_note():
    blob = struct.pack(">IIII", 10, 26, 8, 16) + b"\x00" * 10
    rec = nar_unity.parse_serialized_file_header(blob)
    assert rec["format_version"] == 8
    assert rec["endianness"] is None
    assert any("format < 9" in n for n in rec["notes"])


# ------------------------------------------------- real fixtures

def _run_cli(apk):
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / "nar-unity.py"),
         str(apk), "--json"],
        capture_output=True, text=True, timeout=900)
    assert proc.returncode == 0, proc.stderr[-500:]
    return json.loads(proc.stdout)


@pytest.mark.parametrize("role", ["FIX_UNITY_BUNDLES",
                                  "FIX_UNITY"])
def test_real_bundle_headers_by_role(role):
    fixture = _fixture_path(role)
    if fixture is None:
        pytest.skip(f"{role} fixture absent")
    report = _run_cli(fixture)
    inspections = report["bundle_inspections"]
    assert inspections, "fixture carries bundles"
    first = inspections[0]
    assert first["parsed"] is True
    assert first["signature"] == "UnityFS"
    assert first["bundle_size_matches_data_length"] is True
    # The corpus bundles compress their blocks info with
    # LZ4HC: the header facts land and the stdlib boundary
    # is named rather than decoded.
    assert first["blocks_info"]["compression"] == "lz4hc"
    assert any("lz4hc" in lim
               for lim in first["limitations"])
    counts = report["bundle_inspection_counts"]
    assert counts["processed"] == len(inspections)
    assert counts["failed"] == 0


def test_cli_synthetic_apk(tmp_path):
    blob = build_serialized_v22()
    bundle = build_bundle([blob])
    apk = tmp_path / "synthetic.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("assets/aa/test.bundle", bundle)
    report = _run_cli(apk)
    assert report["unityfs_bundle_count"] == 1
    insp = report["bundle_inspections"][0]
    assert insp["serialized_file"]["format_version"] == 22
