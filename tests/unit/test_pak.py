"""Unit tests for nar-pak's footer reporting on synthetic paks.

The builders construct only the FPakInfo footer region (plus a
dummy index area) byte-exactly per the documented footer layout:

- v11 (modern): 16-byte encryption-key GUID, 1-byte
  bEncryptedIndex flag, magic, version, index offset/size,
  20-byte index hash, then five 32-byte compression-method name
  slots (221-byte footer total);
- v5 (legacy): magic, version, index offset/size, index hash,
  with no GUID/flag prefix and no name slots.

No external fixtures, no app data. The tests pin the reporting
contract exposed by a real modern title's containers: a v8+ pak
is unsupported, and when its footer flags the index as
AES-encrypted the report says so explicitly, because no index
parser could read its entries without the encryption key.
"""
import importlib.util
import struct
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
    assert "additionally flagged encrypted" in report["error"]


def test_v11_plain_index_is_not_called_encrypted(tmp_path):
    report = nar_pak.list_pak(write(tmp_path, "b.pak", build_v11(0)))
    assert report["pak_version"] == 11
    assert report["supported"] is False
    assert report["index_encrypted"] is False
    assert "additionally flagged encrypted" not in report["error"]


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
