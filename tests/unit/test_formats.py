"""Unit tests: narlib.formats identification (synthetic inputs)."""
import os
import struct
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..",
                                "scripts"))
from narlib import formats  # noqa: E402


def _write(path, data):
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def _zip(path, entries):
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


class FormatsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="nar-test-formats-")

    def p(self, name):
        return os.path.join(self.tmp, name)

    def test_apk_structure(self):
        apk = _zip(self.p("a.apk"), {
            "AndroidManifest.xml": b"\x03\x00\x08\x00",
            "classes.dex": b"dex\n035\x00" + b"\x00" * 100,
            "resources.arsc": b"\x02\x00"})
        v = formats.identify(apk)
        self.assertEqual(v["format"], "apk")
        self.assertEqual(v["confidence"], "high")
        self.assertFalse(v["extension_mismatch"])

    def test_apk_masquerading_as_zip(self):
        apk = _zip(self.p("a.zip"), {
            "AndroidManifest.xml": b"\x03\x00\x08\x00",
            "classes.dex": b"dex\n035\x00" + b"\x00" * 100})
        v = formats.identify(apk)
        self.assertEqual(v["format"], "apk")
        self.assertTrue(v["extension_mismatch"])

    def test_aab_structure(self):
        aab = _zip(self.p("a.aab"), {
            "base/manifest/AndroidManifest.xml": b"\x03\x00",
            "base/resources.pb": b"\x00",
            "base/dex/classes.dex": b"dex\n039\x00" + b"\x00" * 100})
        self.assertEqual(formats.identify(aab)["format"], "aab")

    def test_xapk_structure(self):
        x = _zip(self.p("a.xapk"), {
            "manifest.json": b"{}",
            "com.example.app.apk": b"PK\x03\x04"})
        self.assertEqual(formats.identify(x)["format"], "xapk")

    def test_aar_structure(self):
        aar = _zip(self.p("a.aar"), {
            "AndroidManifest.xml": b"\x03\x00",
            "classes.jar": b"PK\x03\x04"})
        self.assertEqual(formats.identify(aar)["format"], "aar")

    def test_bare_dex(self):
        dex = _write(self.p("classes.dex"),
                     b"dex\n039\x00" + b"\x00" * 200)
        v = formats.identify(dex)
        self.assertEqual(v["format"], "dex")
        self.assertEqual(v["details"]["dex_version"], "039")

    def test_odex_vdex_magics(self):
        odex = _write(self.p("a.odex"), b"dey\n036\x00" + b"\x00" * 64)
        vdex = _write(self.p("a.vdex"), b"vdex019\x00" + b"\x00" * 64)
        self.assertEqual(formats.identify(odex)["format"], "odex")
        self.assertEqual(formats.identify(vdex)["format"], "vdex")

    def test_elf(self):
        elf = _write(self.p("libx.so"),
                     b"\x7fELF\x02\x01\x01" + b"\x00" * 64)
        v = formats.identify(elf)
        self.assertEqual(v["format"], "elf")
        self.assertEqual(v["details"]["elf_class"], "ELF64")

    def test_godot_pck(self):
        pck = _write(self.p("a.pck"), b"GDPC" + b"\x00" * 64)
        self.assertEqual(formats.identify(pck)["format"], "godot-pck")

    def test_unity_bundle(self):
        bundle = _write(self.p("a.bundle"),
                        b"UnityFS\x00" + b"\x00" * 64)
        self.assertEqual(formats.identify(bundle)["format"],
                         "unity-assetbundle")

    def test_pak_footer_magic(self):
        data = bytearray(b"\x00" * 200)
        struct.pack_into("<I", data, 150, formats.PAK_MAGIC)
        pak = _write(self.p("a.pak"), bytes(data))
        self.assertEqual(formats.identify(pak)["format"], "unreal-pak")

    def test_unknown(self):
        f = _write(self.p("a.bin"), b"just some text, no signature")
        self.assertEqual(formats.identify(f)["format"], "unknown")

    def test_corrupt_zip_flagged(self):
        f = _write(self.p("bad.apk"), b"PK\x03\x04" + b"\xff" * 32)
        notes = formats.validate_structure(f)
        self.assertTrue(notes)


if __name__ == "__main__":
    unittest.main()
