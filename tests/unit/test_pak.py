"""Unit tests for nar-pak on synthetic paks.

The footer builders construct only the FPakInfo footer region
(plus a dummy index area) byte-exactly per the documented
footer layout:

- v11 (modern): 16-byte encryption-key GUID, 1-byte
  bEncryptedIndex flag, magic, version, index offset/size,
  20-byte index hash, then five 32-byte compression-method name
  slots (221-byte footer total);
- v5 (legacy): magic, version, index offset/size, index hash,
  with no GUID/flag prefix and no name slots.

A third builder constructs a complete v11 pak -- entry data
region with classic serialized entry headers, the encoded
primary index, an (empty) path-hash index, the full directory
index, and the footer -- byte-exactly per the documented v10+
layout, so listing and extraction are tested end to end.

No external fixtures, no app data. The tests pin the reporting
contract exposed by real modern titles' containers: v8/v9 paks
stay unsupported; a v10/v11 pak whose footer flags the index
as AES-encrypted is surfaced explicitly, because no index
parser could read its entries without the encryption key; an
unencrypted v10/v11 encoded index is listed in full, stdlib
compression methods extract, and methods with no stdlib
decoder are refused by name.
"""
import hashlib
import importlib.util
import struct
import zlib
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
_spec = importlib.util.spec_from_file_location(
    "nar_pak", SCRIPTS / "nar-pak.py")
nar_pak = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nar_pak)

MAGIC = struct.pack("<I", 0x5A6F12E1)


def build_v11(enc_flag):
    index = b"\xAA" * 64
    slots = b"Oodle".ljust(32, b"\x00") + b"\x00" * (32 * 4)
    footer = (
        b"\x00" * 16
        + bytes([enc_flag])
        + MAGIC
        + struct.pack("<IQQ", 11, 0, len(index))
        + b"\x00" * 20
        + slots
    )
    assert len(footer) == 221
    return index + footer


def build_v5():
    index = b"\xBB" * 32
    footer = MAGIC + struct.pack("<IQQ", 5, 0, len(index)) + b"\x00" * 20
    return index + footer


def write(tmp_path, name, blob):
    path = tmp_path / name
    path.write_bytes(blob)
    return str(path)


def test_v11_encrypted_index_is_surfaced(tmp_path):
    report = nar_pak.list_pak(write(tmp_path, "a.pak", build_v11(1)))
    assert report["pak_version"] == 11
    assert report["supported"] is False
    assert report["index_encrypted"] is True
    assert "flagged encrypted (AES)" in report["error"]


def test_v11_plain_index_is_not_called_encrypted(tmp_path):
    report = nar_pak.list_pak(write(tmp_path, "b.pak", build_v11(0)))
    assert report["pak_version"] == 11
    assert report["supported"] is False
    assert report["index_encrypted"] is False
    assert "flagged encrypted" not in report["error"]


def test_v5_footer_has_no_index_encrypted_field(tmp_path):
    report = nar_pak.list_pak(write(tmp_path, "c.pak", build_v5()))
    assert report["pak_version"] == 5
    assert "index_encrypted" not in report


def test_index_encrypted_helper_version_gate():
    blob = build_v11(1)
    assert nar_pak.index_encrypted(blob, 11) is True
    assert nar_pak.index_encrypted(blob, 7) is True
    assert nar_pak.index_encrypted(blob, 6) is None
    assert nar_pak.index_encrypted(build_v11(0), 11) is False


# ------------------------------------------------------- v11 encoded pak

def _fstring(s):
    if s == "":
        return struct.pack("<i", 0)
    raw = s.encode("utf-8") + b"\x00"
    return struct.pack("<i", len(raw)) + raw


def _entry_header(size, usize, method_value, raw, block_sizes=()):
    """The classic serialized header preceding an entry's data
    in the file: zero offset field (patched from the index at
    load), packed size, uncompressed size, method index value,
    SHA-1 of the uncompressed data, the compression block
    table when compressed, and a 5-byte trailer (encryption
    flag + compression block size)."""
    h = struct.pack("<Q", 0)
    h += struct.pack("<Q", size)
    h += struct.pack("<Q", usize)
    h += struct.pack("<i", method_value)
    h += hashlib.sha1(raw).digest()
    if method_value:
        h += struct.pack("<i", len(block_sizes))
        pos = 53 + 4 + 16 * len(block_sizes)
        for bs in block_sizes:
            h += struct.pack("<QQ", pos, pos + bs)
            pos += bs
    h += b"\x00" + struct.pack("<I", 65536 if method_value else 0)
    return h


def _encoded_record(offset, usize, size, method_value, block_sizes=()):
    """One encoded index record (flags word first)."""
    flags = 0 if method_value == 0 else 32  # block size >> 11
    flags |= (len(block_sizes) & 0xFFFF) << 6
    flags |= (method_value & 0x3F) << 23
    flags |= (1 << 29) | (1 << 30) | (1 << 31)  # u32 fields
    out = struct.pack("<I", flags)
    out += struct.pack("<I", offset)
    out += struct.pack("<I", usize)
    if method_value:
        out += struct.pack("<I", size)
        if len(block_sizes) > 1:
            for bs in block_sizes:
                out += struct.pack("<I", bs)
    return out


def build_v11_encoded():
    """A complete synthetic v11 pak with an unencrypted
    encoded index: one stored entry, one single-block zlib
    entry, one two-block zlib entry, and one entry using a
    compression method with no stdlib decoder."""
    raw_stored = b"STORED!" * 10
    raw_z1 = b"Z" * 1000
    comp_z1 = zlib.compress(raw_z1)
    raw_z2 = b"AB" * 40000
    comp_z2a = zlib.compress(raw_z2[:65536])
    comp_z2b = zlib.compress(raw_z2[65536:])
    raw_oo = b"FAKEOODLE" * 5
    # name, payload in file, uncompressed data, method value
    # (footer slot + 1), per-block compressed sizes
    specs = [
        ("Game/Content/stored.uasset", raw_stored, raw_stored,
         0, ()),
        ("Game/Content/zlib1.uasset", comp_z1, raw_z1,
         1, (len(comp_z1),)),
        ("Game/Content/zlib2.uasset", comp_z2a + comp_z2b, raw_z2,
         1, (len(comp_z2a), len(comp_z2b))),
        ("Game/Content/oodle.uasset", raw_oo, raw_oo,
         2, (len(raw_oo),)),
    ]
    data_region = b""
    blob = b""
    fdi_entries = []
    for name, payload, raw, method_value, blocks in specs:
        offset = len(data_region)
        data_region += _entry_header(
            len(payload), len(raw), method_value, raw,
            blocks if method_value else ()) + payload
        fdi_entries.append((name, len(blob)))
        blob += _encoded_record(offset, len(raw), len(payload),
                                method_value, blocks)

    mount = "../../../"
    ph_region = struct.pack("<Q", 0x1234) + struct.pack("<i", 0)
    # Full directory index: a directory -> files map.
    fdi = struct.pack("<i", 1)
    fdi += _fstring("Game/Content/")
    fdi += struct.pack("<i", len(fdi_entries))
    for name, loc in fdi_entries:
        fdi += _fstring(name.rsplit("/", 1)[1])
        fdi += struct.pack("<i", loc)

    index_offset = len(data_region)
    idx_len = (len(_fstring(mount)) + 4 + 8 + 4 + 36 + 4 + 36
               + 4 + len(blob) + 4)
    ph_offset = index_offset + idx_len
    fdi_offset = ph_offset + len(ph_region)
    index = _fstring(mount)
    index += struct.pack("<i", len(specs))
    index += struct.pack("<Q", 0x66AA1351)      # path-hash seed
    index += struct.pack("<i", 1)               # has path-hash idx
    index += struct.pack("<q", ph_offset)
    index += struct.pack("<q", len(ph_region))
    index += hashlib.sha1(ph_region).digest()
    index += struct.pack("<i", 1)               # has directory idx
    index += struct.pack("<q", fdi_offset)
    index += struct.pack("<q", len(fdi))
    index += hashlib.sha1(fdi).digest()
    index += struct.pack("<i", len(blob)) + blob
    index += struct.pack("<i", 0)               # trailing array
    assert len(index) == idx_len
    slots = (b"Zlib".ljust(32, b"\x00")
             + b"Oodle".ljust(32, b"\x00") + b"\x00" * 96)
    footer = (b"\x00" * 16 + b"\x00" + MAGIC
              + struct.pack("<IQQ", 11, index_offset, len(index))
              + hashlib.sha1(index).digest() + slots)
    assert len(footer) == 221
    return data_region + index + ph_region + fdi + footer


def test_v11_encoded_index_lists_entries(tmp_path):
    report = nar_pak.list_pak(
        write(tmp_path, "enc.pak", build_v11_encoded()))
    assert report["pak_version"] == 11
    assert report["supported"] is True
    assert report["index_encrypted"] is False
    assert report["mount_point"] == "../../../"
    assert report["entry_count"] == 4
    by_name = {e["name"]: e for e in report["entries"]}
    assert by_name["Game/Content/stored.uasset"]["compression"] \
        == "None"
    assert by_name["Game/Content/zlib1.uasset"]["compression"] \
        == "Zlib"
    assert by_name["Game/Content/zlib2.uasset"]["compression"] \
        == "Zlib"
    assert by_name["Game/Content/oodle.uasset"]["compression"] \
        == "Oodle"
    z2 = by_name["Game/Content/zlib2.uasset"]
    assert z2["compression_blocks"] == 2
    assert z2["compression_block_size"] == 65536
    assert len(z2["compression_block_sizes"]) == 2
    assert sum(z2["compression_block_sizes"]) == z2["size_bytes"]
    assert z2["uncompressed_size_bytes"] == 80000


def test_v11_encoded_extracts_stdlib_entries(tmp_path):
    path = write(tmp_path, "enc.pak", build_v11_encoded())
    out = tmp_path / "out"
    report = nar_pak.extract_pak(path, "*.uasset", str(out))
    files = {p.name: p.read_bytes() for p in out.rglob("*.uasset")}
    assert files["stored.uasset"] == b"STORED!" * 10
    assert files["zlib1.uasset"] == b"Z" * 1000
    assert files["zlib2.uasset"] == b"AB" * 40000
    assert "oodle.uasset" not in files
    errors = report["extract_errors"]
    assert len(errors) == 1 and "Oodle" in str(errors[0])


def test_encoded_entry_u64_fields_and_block_size_escape():
    # The paths a real small pak never exercises: 64-bit
    # offset/sizes (flag bits 29-31 clear) and the 0x3F
    # block-size escape (a full uint32 follows the sizes).
    # Built per the documented encoded-record layout.
    flags = 0x3F | (1 << 6) | (1 << 23)
    blob = struct.pack("<I", flags)
    blob += struct.pack("<Q", 0x1_0000_0001)   # offset > 4 GiB
    blob += struct.pack("<Q", 0x2_0000_0002)   # uncompressed
    blob += struct.pack("<Q", 12345)           # compressed size
    blob += struct.pack("<I", 131072)          # escaped block size
    fields, consumed = nar_pak._decode_encoded_entry(blob, 0)
    assert consumed == len(blob)
    assert fields["offset"] == 0x1_0000_0001
    assert fields["uncompressed"] == 0x2_0000_0002
    assert fields["size"] == 12345
    assert fields["method"] == 1
    assert fields["block_count"] == 1
    assert fields["block_size"] == 131072
    assert fields["encrypted"] is False
