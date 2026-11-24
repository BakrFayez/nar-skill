"""Unit tests for nar-godot on synthetic packs.

The builders construct packs byte-exactly per the documented
PCK layouts:

- format 2 (Godot 4.0-4.4): 96-byte header (magic, format,
  engine version, pack flags, file base, 16 reserved uint32);
  bit 0 of the pack flags is the encryption flag, bit 1 marks
  entry offsets as relative to the file base; the directory
  follows the header; each entry is path length, zero-padded
  path, offset, size, 16-byte MD5, entry flags (bit 0 =
  encrypted);
- format 3 (Godot 4.5+): 104-byte header that adds a directory
  offset field; the directory sits at that offset (the end of
  the pack) and entry offsets are always relative to the file
  base;
- format 4: same header field positions as format 3 per the
  format documentation, but a directory layout this reader does
  not parse; only the header facts (including the encryption
  flag) may be reported.

In an encrypted pack the directory bytes after the file count
are ciphertext. The encrypted builders mirror that shape with
deterministic stand-in bytes: the parser must key only on the
header encryption flag, name the pack encrypted, and never
present a listing. The format 2 encrypted shape and the format
3 directory-at-end shape were both cross-checked against a
real engine pack writer/reader during development; the tests
themselves need no external fixtures and no app data.
"""
import hashlib
import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
_spec = importlib.util.spec_from_file_location(
    "nar_godot", SCRIPTS / "nar-godot.py")
nar_godot = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nar_godot)

FILES = [(b"res://hello.txt", b"hello godot pack fixture\n"),
         (b"res://project.godot", b"; minimal\nconfig_version=5\n")]


def _ciphertext(n):
    """Deterministic non-plaintext bytes standing in for an
    encrypted directory region."""
    out = bytearray()
    block = hashlib.sha256(b"nar-godot-fixture").digest()
    while len(out) < n:
        out += block
        block = hashlib.sha256(block).digest()
    return bytes(out[:n])


def _entries(files, entry_flags=None):
    out = bytearray()
    off = 0
    for i, (path, blob) in enumerate(files):
        flags = (entry_flags or {}).get(i, 0)
        out += struct.pack("<I", len(path)) + path
        out += b"\x00" * ((4 - len(path) % 4) % 4)
        out += struct.pack("<QQ", off, len(blob))
        out += hashlib.md5(blob).digest()
        out += struct.pack("<I", flags)
        off += len(blob)
    return bytes(out)


def build_v2(files=FILES, encrypted=False, relative=False,
             entry_flags=None):
    if encrypted:
        flags = 0x1
        header = (b"GDPC" + struct.pack("<IIII", 2, 4, 3, 0)
                  + struct.pack("<IQ", flags, 288) + b"\x00" * 64)
        # Plaintext file count, then ciphertext, as a real
        # encrypted pack lays out its directory.
        return header + struct.pack("<I", len(files)) + _ciphertext(160)
    directory = struct.pack("<I", len(files)) + _entries(
        files, entry_flags)
    data = b"".join(blob for _, blob in files)
    if relative:
        file_base = 96 + len(directory)
        flags = 0x2
    else:
        file_base = 0
        flags = 0x0
    header = (b"GDPC" + struct.pack("<IIII", 2, 4, 3, 0)
              + struct.pack("<IQ", flags, file_base) + b"\x00" * 64)
    assert len(header) == 96
    return header + directory + data


def build_v3(files=FILES, encrypted=False):
    data = b"".join(blob for _, blob in files)
    file_base = 104
    dir_offset = file_base + len(data)
    if encrypted:
        header = (b"GDPC" + struct.pack("<IIII", 3, 4, 5, 0)
                  + struct.pack("<IQ", 0x1, file_base)
                  + struct.pack("<Q", dir_offset) + b"\x00" * 64)
        assert len(header) == 104
        return header + _ciphertext(len(data)) + _ciphertext(160)
    directory = struct.pack("<I", len(files)) + _entries(files)
    header = (b"GDPC" + struct.pack("<IIII", 3, 4, 5, 0)
              + struct.pack("<IQ", 0x0, file_base)
              + struct.pack("<Q", dir_offset) + b"\x00" * 64)
    assert len(header) == 104
    return header + data + directory


def build_v4(encrypted):
    header = (b"GDPC" + struct.pack("<IIII", 4, 4, 6, 0)
              + struct.pack("<IQ", 0x1 if encrypted else 0x0, 104)
              + struct.pack("<Q", 200) + b"\x00" * 64)
    return header + _ciphertext(200)


def human_for(data):
    with tempfile.NamedTemporaryFile(
            suffix=".pck", delete=False) as fh:
        fh.write(data)
        path = fh.name
    return nar_godot.human(nar_godot.inspect(path), 50)


class TestEncryptedDetection(unittest.TestCase):
    def test_v2_encrypted_flag_detected(self):
        report = nar_godot.parse_pck(build_v2(encrypted=True))
        self.assertTrue(report["encrypted"])
        self.assertEqual(report["pack_flags"], 1)
        self.assertIsNone(report["file_count"])
        self.assertEqual(report["files"], [])
        self.assertIn("encrypted", report["listing_error"])

    def test_v2_encrypted_human_output(self):
        text = human_for(build_v2(encrypted=True))
        self.assertIn("Encryption: YES (pack flag)", text)
        self.assertIn("Listing unavailable", text)
        self.assertNotIn("Files:", text)

    def test_v3_encrypted_flag_detected(self):
        report = nar_godot.parse_pck(build_v3(encrypted=True))
        self.assertTrue(report["encrypted"])
        self.assertIsNone(report["file_count"])
        self.assertIn("encrypted", report["listing_error"])

    def test_v4_encrypted_flag_detected(self):
        report = nar_godot.parse_pck(build_v4(encrypted=True))
        self.assertTrue(report["encrypted"])
        self.assertIsNone(report["file_count"])
        self.assertIn("encrypted", report["listing_error"])


class TestPlainListing(unittest.TestCase):
    def test_v2_plain_listing(self):
        report = nar_godot.parse_pck(build_v2())
        self.assertFalse(report["encrypted"])
        self.assertEqual(report["file_count"], 2)
        self.assertEqual([f["path"] for f in report["files"]],
                         ["res://hello.txt", "res://project.godot"])
        self.assertEqual(report["total_content_bytes"],
                         sum(len(b) for _, b in FILES))

    def test_v2_relative_base_offsets(self):
        report = nar_godot.parse_pck(build_v2(relative=True))
        self.assertEqual(report["file_count"], 2)
        first, second = report["files"]
        self.assertEqual(first["offset"], report["file_base"])
        self.assertEqual(second["offset"],
                         report["file_base"] + len(FILES[0][1]))

    def test_v3_plain_directory_at_end(self):
        # Regression: format 3 keeps its directory at the recorded
        # offset, not after the header; reading offset 96 (inside
        # the reserved header area) used to report "Files: 0".
        report = nar_godot.parse_pck(build_v3())
        self.assertFalse(report["encrypted"])
        self.assertEqual(report["directory_offset"],
                         104 + sum(len(b) for _, b in FILES))
        self.assertEqual(report["file_count"], 2)
        self.assertEqual([f["path"] for f in report["files"]],
                         ["res://hello.txt", "res://project.godot"])
        self.assertEqual(report["files"][0]["offset"], 104)

    def test_v3_bad_directory_offset_raises(self):
        data = bytearray(build_v3())
        struct.pack_into("<Q", data, 32, len(data) + 500)
        with self.assertRaises(nar_godot.PckError):
            nar_godot.parse_pck(bytes(data))


class TestNewerFormatHonesty(unittest.TestCase):
    def test_v4_plain_listing_marked_unsupported(self):
        report = nar_godot.parse_pck(build_v4(encrypted=False))
        self.assertFalse(report["encrypted"])
        self.assertIsNone(report["file_count"])
        self.assertEqual(report["files"], [])
        self.assertIn("not supported", report["listing_error"])


class TestPerFileEncryption(unittest.TestCase):
    def test_encrypted_entry_marked(self):
        data = build_v2(entry_flags={1: 0x1})
        report = nar_godot.parse_pck(data)
        self.assertFalse(report["encrypted"])
        self.assertFalse(report["files"][0]["encrypted"])
        self.assertTrue(report["files"][1]["encrypted"])
        text = human_for(data)
        self.assertIn("res://project.godot", text)
        self.assertIn("[encrypted]", text)


TSCN_V4 = (
    b'[gd_scene load_steps=3 format=3 uid="uid://scene1"]\n'
    b"\n"
    b'[ext_resource type="PackedScene" uid="uid://enemy1" '
    b'path="res://enemy.tscn" id="1_xyz"]\n'
    b'[ext_resource type="Texture2D" '
    b'path="res://icon.png" id="2_abc"]\n'
    b"\n"
    b'[sub_resource type="CircleShape2D" '
    b'id="CircleShape2D_1"]\n'
    b"radius = 4.0\n"
    b"\n"
    b'[node name="Main" type="Node2D"]\n'
    b"\n"
    b'[node name="Enemy" parent="." '
    b'instance=ExtResource("1_xyz")]\n'
    b"\n"
    b'[node name="Sprite" parent="." type="Sprite2D"]\n'
    b'texture = ExtResource("2_abc")\n'
)

TSCN_V3 = (
    b"[gd_scene load_steps=2 format=2]\n"
    b"\n"
    b'[ext_resource path="res://other.tscn" type="PackedScene"'
    b" id=1]\n"
    b"\n"
    b'[node name="Root" type="Node"]\n'
    b"\n"
    b'[node name="Other" parent="." instance=ExtResource( 1 )]\n'
)


class TestSceneRelationships(unittest.TestCase):
    def test_pack_scene_relationships_exact(self):
        files = [(b"res://main.tscn", TSCN_V4),
                 (b"res://icon.png", b"\x89PNG\r\n\x1a\n....")]
        report = nar_godot.parse_pck(
            build_v2(files=files, relative=True))
        self.assertEqual(report["scene_relationship_counts"],
                         {"total": 1, "processed": 1,
                          "skipped": 0, "failed": 0})
        rel = report["scene_relationships"][0]
        self.assertEqual(rel["path"], "res://main.tscn")
        self.assertEqual(rel["kind"], "scene")
        self.assertEqual(rel["node_count"], 3)
        self.assertEqual(rel["external_resource_count"], 2)
        ext = {e["id"]: e for e in rel["external_resources"]}
        self.assertEqual(ext["1_xyz"]["path"],
                         "res://enemy.tscn")
        self.assertEqual(ext["1_xyz"]["type"], "PackedScene")
        self.assertEqual(ext["2_abc"]["path"], "res://icon.png")
        self.assertEqual(rel["sub_resource_ids"],
                         ["CircleShape2D_1"])
        self.assertEqual(rel["sub_resource_count"], 1)
        self.assertEqual(rel["instanced_scenes"], [
            {"node": "Enemy", "ext_resource_id": "1_xyz",
             "path": "res://enemy.tscn"}])

    def test_godot3_integer_ids_join(self):
        files = [(b"res://main.tscn", TSCN_V3)]
        report = nar_godot.parse_pck(
            build_v2(files=files, relative=True))
        rel = report["scene_relationships"][0]
        self.assertEqual(rel["external_resources"][0]["id"],
                         "1")
        self.assertEqual(rel["instanced_scenes"], [
            {"node": "Other", "ext_resource_id": "1",
             "path": "res://other.tscn"}])
        self.assertEqual(rel["node_count"], 2)

    def test_encrypted_scene_named_not_decoded(self):
        files = [(b"res://main.tscn", TSCN_V4),
                 (b"res://secret.tscn", TSCN_V3)]
        report = nar_godot.parse_pck(
            build_v2(files=files, relative=True,
                     entry_flags={1: 0x1}))
        self.assertEqual(report["scene_relationship_counts"],
                         {"total": 2, "processed": 1,
                          "skipped": 1, "failed": 0})
        paths = [r["path"]
                 for r in report["scene_relationships"]]
        self.assertEqual(paths, ["res://main.tscn"])

    def test_bare_scene_file_target(self):
        with tempfile.NamedTemporaryFile(
                suffix=".tscn", delete=False) as fh:
            fh.write(TSCN_V4)
            path = fh.name
        report = nar_godot.inspect(path)
        self.assertTrue(report["is_godot"])
        rel = report["scene_relationships"][0]
        self.assertEqual(rel["node_count"], 3)
        self.assertEqual(rel["external_resource_count"], 2)
        text = nar_godot.human(report, 50)
        self.assertIn("Scene relationships:", text)
        self.assertIn("Enemy -> res://enemy.tscn", text)

    def test_bare_binary_scene_rejected_honestly(self):
        with tempfile.NamedTemporaryFile(
                suffix=".tscn", delete=False) as fh:
            fh.write(b"RSRC" + b"\x00" * 32)
            path = fh.name
        report = nar_godot.inspect(path)
        self.assertFalse(report["is_godot"])
        self.assertIn("binary", report["error"])


if __name__ == "__main__":
    unittest.main()
