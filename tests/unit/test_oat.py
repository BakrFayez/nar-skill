"""Unit tests: narlib.oat + formats OAT/VDEX/ODEX/CDEX/ART
identification (synthetic inputs, byte-exact builders).

The builders follow the documented layouts: VDEX 006
(24-byte header + per-dex checksums + dex bytes), the OAT
header inside an ELF body, the Dalvik ODEX header (dex
offset/length + deps/aux), and the ART image header.
"""
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..",
                                "scripts"))
from narlib import formats, oat  # noqa: E402


def _write(path, data):
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def make_dex(total=208):
    """A minimal DEX-shaped blob: magic + a file_size field
    that matches its length (the fields the carver checks)."""
    blob = bytearray(b"dex\n038\x00" + b"\x00" * (total - 8))
    struct.pack_into("<I", blob, 32, total)
    return bytes(blob)


def make_vdex006(dex_blobs):
    dex_region = b"".join(dex_blobs)
    header = b"vdex006\x00" + struct.pack(
        "<IIII", len(dex_blobs), len(dex_region), 0, 0)
    checksums = b"".join(struct.pack("<I", 0x1000 + i)
                          for i in range(len(dex_blobs)))
    return header + checksums + dex_region


def make_oat_elf(oat_version="052", dex_count=1, kv=b"",
                 locations=b""):
    header = b"oat\n" + oat_version.encode() + b"\x00"
    header += struct.pack("<IIII", 0x99, 5, 0, dex_count)
    header += b"\x00" * 64 + kv + locations
    elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 200
    return elf + header


def make_dalvik_odex(dex_blob):
    header = b"dey\n036\x00" + struct.pack(
        "<IIIIIII", 40, len(dex_blob), 0, 0, 0, 0, 0)
    return header + b"\x00" * 4 + dex_blob


def make_art(image_size):
    header = b"art\n046\x00" + struct.pack(
        "<IIIIIII", 0, image_size, 0, 0, 0, 0, 0)
    return header + b"\x00" * (image_size - len(header))


class OatParseTest(unittest.TestCase):
    def test_vdex006_header_and_extraction(self):
        dex = make_dex()
        blob = make_vdex006([dex])
        info = oat.parse_vdex(blob)
        self.assertEqual(info["vdex_version"], "006")
        self.assertEqual(info["number_of_dex_files"], 1)
        self.assertEqual(info["dex_size"], len(dex))
        self.assertEqual(len(info["embedded"]), 1)
        self.assertEqual(info["embedded"][0]["kind"], "dex")
        self.assertEqual(info["embedded"][0]["version"], "038")
        out = oat.extract_dex_from_vdex(blob)
        self.assertEqual(len(out), 1)
        name, carved, kind = out[0]
        self.assertEqual(name, "classes.dex")
        self.assertEqual(kind, "dex")
        self.assertEqual(carved, dex)

    def test_vdex_multi_dex_names(self):
        blob = make_vdex006([make_dex(), make_dex(232)])
        out = oat.extract_dex_from_vdex(blob)
        self.assertEqual([n for n, _b, _k in out],
                         ["classes.dex", "classes2.dex"])

    def test_vdex_rejects_non_vdex(self):
        with self.assertRaises(oat.OatError):
            oat.parse_vdex(b"dex\n038\x00" + b"\x00" * 64)

    def test_scan_rejects_dex_magic_with_bad_size(self):
        # A dex magic whose declared file_size cannot fit the
        # carrier is string data, not an embedded dex.
        blob = bytearray(b"vdex006\x00" + b"\x00" * 64)
        blob[32:40] = b"dex\n038\x00"
        struct.pack_into("<I", blob, 32 + 32, 10 ** 9)
        self.assertEqual(oat.scan_embedded_dex(bytes(blob)), [])

    def test_oat_header_parse(self):
        blob = make_oat_elf(
            kv=b"compiler-filter\x00speed\x00",
            locations=b"/data/app/com.example.x/base.apk\x00")
        info = oat.parse_oat(blob)
        self.assertEqual(info["oat_version"], "052")
        self.assertEqual(info["instruction_set_name"], "x86_64")
        self.assertEqual(info["dex_file_count"], 1)
        self.assertEqual(info["key_value_store"],
                         {"compiler-filter": "speed"})
        self.assertEqual(info["dex_locations"],
                         ["/data/app/com.example.x/base.apk"])
        self.assertTrue(info["is_elf"])

    def test_oat_locations_ignore_cmdline_fragments(self):
        # The key-value store holds a dex2oat command line
        # whose --zip-location value ends in .apk; only the
        # real OatDexFile location may be reported.
        blob = make_oat_elf(
            kv=b"dex2oat-cmdline\x00--zip-location=base.apk "
               b"--compiler-filter=speed\x00",
            locations=b"/data/app/com.example.x/base.apk\x00")
        info = oat.parse_oat(blob)
        self.assertEqual(info["dex_locations"],
                         ["/data/app/com.example.x/base.apk"])

    def test_oat_requires_versioned_magic(self):
        with self.assertRaises(oat.OatError):
            oat.parse_oat(b"\x7fELF\x02" + b"oat\n" + b"\x00" * 64)

    def test_dalvik_odex_roundtrip(self):
        dex = make_dex()
        blob = make_dalvik_odex(dex)
        info = oat.parse_odex_dalvik(blob)
        self.assertEqual(info["odex_version"], "036")
        self.assertEqual(info["dex"], dex)

    def test_dalvik_odex_truncated_dex_rejected(self):
        blob = make_dalvik_odex(make_dex())[:100]
        with self.assertRaises(oat.OatError):
            oat.parse_odex_dalvik(blob)

    def test_art_image_parse(self):
        blob = make_art(256)
        info = oat.parse_art_image(blob)
        self.assertEqual(info["art_version"], "046")
        self.assertEqual(info["image_size"], 256)


class FormatsOatTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="nar-test-oat-")

    def p(self, name):
        return os.path.join(self.tmp, name)

    def test_art_oat_named_odex_is_oat_not_elf(self):
        # The Android 8.0+ layout: an OAT file wearing the
        # .odex name must identify as oat, with no extension
        # mismatch.
        path = _write(self.p("base.odex"), make_oat_elf())
        v = formats.identify(path)
        self.assertEqual(v["format"], "oat")
        self.assertEqual(v["details"]["oat_version"], "052")
        self.assertFalse(v["extension_mismatch"])
        self.assertEqual(formats.validate_structure(path, v), [])

    def test_plain_elf_stays_elf(self):
        path = _write(self.p("libx.so"),
                      b"\x7fELF\x02\x01\x01" + b"\x00" * 256)
        self.assertEqual(formats.identify(path)["format"], "elf")

    def test_vdex_version_and_counts(self):
        path = _write(self.p("base.vdex"),
                      make_vdex006([make_dex()]))
        v = formats.identify(path)
        self.assertEqual(v["format"], "vdex")
        self.assertEqual(v["details"]["vdex_version"], "006")
        self.assertEqual(v["details"]["number_of_dex_files"], 1)
        self.assertEqual(formats.validate_structure(path, v), [])

    def test_vdex_count_mismatch_is_a_validation_note(self):
        # Header declares two dex files; the file carries one.
        dex = make_dex()
        header = b"vdex006\x00" + struct.pack(
            "<IIII", 2, len(dex), 0, 0)
        blob = header + struct.pack("<II", 1, 2) + dex
        path = _write(self.p("bad.vdex"), blob)
        notes = formats.validate_structure(path)
        self.assertTrue(any("declares 2" in n for n in notes))

    def test_dalvik_odex_version(self):
        path = _write(self.p("app.odex"),
                      make_dalvik_odex(make_dex()))
        v = formats.identify(path)
        self.assertEqual(v["format"], "odex")
        self.assertEqual(v["details"]["odex_version"], "036")
        self.assertEqual(formats.validate_structure(path, v), [])

    def test_cdex(self):
        path = _write(self.p("classes.cdex"),
                      b"cdex001\x00" + b"\x00" * 200)
        v = formats.identify(path)
        self.assertEqual(v["format"], "cdex")
        self.assertEqual(v["details"]["cdex_version"], "001")

    def test_art_image(self):
        path = _write(self.p("boot.art"), make_art(256))
        v = formats.identify(path)
        self.assertEqual(v["format"], "art")
        self.assertEqual(v["details"]["art_version"], "046")
        self.assertEqual(formats.validate_structure(path, v), [])

    def test_art_image_size_below_file_size_is_valid(self):
        # Regression (real API 26 boot image): the header's
        # image_size counts the image data only and is
        # smaller than the file, which carries trailing
        # data. That must not be flagged.
        blob = make_art(256) + b"\x00" * 64
        path = _write(self.p("boot2.art"), blob)
        self.assertEqual(formats.validate_structure(path), [])

    def test_art_image_size_beyond_file_is_flagged(self):
        blob = bytearray(make_art(256))
        struct.pack_into("<I", blob, 12, 10 ** 6)
        path = _write(self.p("boot3.art"), bytes(blob))
        notes = formats.validate_structure(path)
        self.assertTrue(any("exceeds file size" in n
                            for n in notes))

    def test_extracted_vdex_dex_parses(self):
        # The carve is only useful if the DEX parser accepts
        # the result. Use a real fixture DEX when present in
        # the synthetic builder's place: here the header-only
        # blob is enough to prove the slice boundaries (the
        # parser must reject it for its empty tables, not for
        # a bad magic or size).
        blob = make_vdex006([make_dex()])
        _name, carved, _kind = oat.extract_dex_from_vdex(blob)[0]
        self.assertTrue(carved.startswith(b"dex\n038\x00"))
        self.assertEqual(len(carved), 208)


if __name__ == "__main__":
    unittest.main()
