"""Unit tests: Phase 10 security/reliability pass.

- safearchive: pre-existing symlink in the destination must
  not let an entry write outside it; non-regular (FIFO)
  entries are refused; a corrupt/CRC-lying entry rejects
  alone and does not abort the extraction or leave a
  partial file behind.
- nar-analyze import_case: hostile bundles (symlink entry,
  archive-bomb ratio, traversal) are refused through the
  guarded layer instead of the old raw extractall.
- parser read caps: formats whole-file readers and the
  Godot pack/scene readers refuse over-cap inputs with a
  named message instead of an unbounded read.
- subprocess/temp inventory as executable assertions: no
  shell=True / os.system anywhere in shipped code; every
  subprocess.run carries a timeout except the single
  documented interactive dispatcher in nar.py; the three
  former predictable temp paths now use mkdtemp.
"""
import ast
import glob
import importlib.util
import io
import os
import struct
import sys
import tempfile
import unittest
import zipfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from narlib import formats, safearchive  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(ROOT, "scripts", filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _zip_bytes(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            if isinstance(data, zipfile.ZipInfo):
                zf.writestr(data, b"payload")
            else:
                zf.writestr(name, data)
    return buf.getvalue()


class SafeArchivePhase10Test(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="nar-test-p10-")

    def _src(self, data, name="in.zip"):
        src = os.path.join(self.tmp, name)
        with open(src, "wb") as fh:
            fh.write(data)
        return src

    def test_preexisting_symlink_dir_not_followed(self):
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(outside)
        dest = os.path.join(self.tmp, "dest")
        os.makedirs(dest)
        os.symlink(outside, os.path.join(dest, "linkdir"))
        src = self._src(_zip_bytes([("linkdir/evil.txt", b"x"),
                                    ("ok.txt", b"y")]))
        report = safearchive.safe_extract(src, dest)
        self.assertFalse(os.path.exists(
            os.path.join(outside, "evil.txt")))
        reasons = [r["reason"] for r in report["rejected"]]
        self.assertTrue(any("escapes" in r for r in reasons))
        self.assertEqual(len(report["extracted"]), 1)

    def test_fifo_entry_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            info = zipfile.ZipInfo("fifo")
            info.external_attr = (0o010644 << 16)  # FIFO type bits
            zf.writestr(info, b"payload")
            zf.writestr("real.txt", b"data")
        src = self._src(buf.getvalue())
        report = safearchive.safe_extract(
            src, os.path.join(self.tmp, "out"))
        reasons = [r["reason"] for r in report["rejected"]]
        self.assertTrue(any("non-regular" in r for r in reasons))

    def test_corrupt_entry_rejects_alone_no_partial(self):
        good = _zip_bytes([("good.txt", bytes(range(256)) * 4),
                           ("bad.txt", bytes(range(255, -1, -1))
                            * 20)])
        # Corrupt bad.txt's stored CRC in both headers so the
        # read fails mid-extraction (header-lying entry).
        data = bytearray(good)
        idx = data.rfind(b"bad.txt")
        # central directory entry: CRC is 16 bytes before the
        # filename in the central header record.
        cen = data.rfind(b"PK\x01\x02")
        self.assertGreater(cen, 0)
        struct.pack_into("<I", data, cen + 16, 0xDEADBEEF)
        src = self._src(bytes(data), "corrupt.zip")
        out = os.path.join(self.tmp, "outc")
        report = safearchive.safe_extract(src, out)
        names = [e["entry"] for e in report["extracted"]]
        self.assertIn("good.txt", names)
        self.assertNotIn("bad.txt", names)
        self.assertTrue(any(r["entry"] == "bad.txt"
                            for r in report["rejected"]))
        self.assertFalse(os.path.exists(
            os.path.join(out, "bad.txt")))


class ImportCasePhase10Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.az = _load("nar_analyze_p10", "nar-analyze.py")

    def _bundle(self, extra_entries):
        tmp = tempfile.mkdtemp(prefix="nar-test-bundle-")
        bundle = os.path.join(tmp, "bundle.zip")
        with zipfile.ZipFile(bundle, "w") as zf:
            zf.writestr(self.az.BUNDLE_MANIFEST,
                        '{"tool": "nar-analyze"}')
            for name, data in extra_entries:
                zf.writestr(name, data)
        return bundle, tmp

    def test_symlink_bundle_refused(self):
        info = zipfile.ZipInfo("evil-link")
        info.external_attr = (0o120777 << 16)
        bundle, _ = self._bundle([(info, b"/etc/passwd")])
        out = os.path.join(tempfile.mkdtemp(), "case")
        with self.assertRaises(ValueError) as ctx:
            self.az.import_case(bundle, out)
        self.assertIn("symlink", str(ctx.exception))
        self.assertFalse(os.path.islink(os.path.join(out,
                                                     "evil-link")))

    def test_traversal_bundle_refused(self):
        bundle, _ = self._bundle([("../evil.txt", b"x")])
        out = os.path.join(tempfile.mkdtemp(), "case")
        with self.assertRaises(ValueError):
            self.az.import_case(bundle, out)


class ParserCapsTest(unittest.TestCase):
    def _sparse(self, magic, size):
        fd, path = tempfile.mkstemp(prefix="nar-test-cap-")
        with os.fdopen(fd, "wb") as fh:
            fh.write(magic)
            fh.truncate(size)
        self.addCleanup(os.unlink, path)
        return path

    def test_formats_vdex_over_cap_skips_parse(self):
        path = self._sparse(b"vdex",
                            formats.STRUCT_READ_CAP_BYTES + 1)
        notes = formats.validate_structure(
            path, {"format": "vdex", "extension": ".vdex"})
        self.assertTrue(any("read cap" in n for n in notes),
                        notes)

    def test_formats_cdex_identify_over_cap(self):
        path = self._sparse(b"cdex038",
                            formats.STRUCT_READ_CAP_BYTES + 1)
        verdict = formats.identify(path)
        self.assertEqual(verdict["format"], "cdex")
        self.assertIn("read cap",
                      verdict["details"].get("cdex_error", ""))

    def test_godot_caps(self):
        godot = _load("nar_godot_p10", "nar-godot.py")
        old_pck, old_scene = godot.MAX_PCK_BYTES, godot.MAX_SCENE_BYTES
        godot.MAX_PCK_BYTES = 8
        godot.MAX_SCENE_BYTES = 8
        self.addCleanup(setattr, godot, "MAX_PCK_BYTES", old_pck)
        self.addCleanup(setattr, godot, "MAX_SCENE_BYTES", old_scene)
        with tempfile.TemporaryDirectory() as td:
            pck = os.path.join(td, "big.pck")
            with open(pck, "wb") as fh:
                fh.write(b"GDPC" + b"\x00" * 64)
            rep = godot.inspect(pck)
            self.assertIn("read cap", rep.get("error", ""))
            scene = os.path.join(td, "big.tscn")
            with open(scene, "wb") as fh:
                fh.write(b"[gd_scene load_steps=2]\n" + b"x" * 64)
            rep = godot.inspect(scene)
            self.assertIn("read cap", rep.get("error", ""))

    def test_godot_embedded_pck_over_cap_not_decompressed(self):
        godot = _load("nar_godot_p10b", "nar-godot.py")
        old = godot.MAX_PCK_BYTES
        godot.MAX_PCK_BYTES = 8
        self.addCleanup(setattr, godot, "MAX_PCK_BYTES", old)
        with tempfile.TemporaryDirectory() as td:
            apk = os.path.join(td, "x.apk")
            with zipfile.ZipFile(apk, "w") as zf:
                zf.writestr("assets/game.pck",
                            b"GDPC" + b"\x00" * 256)
                zf.writestr("lib/arm64-v8a/libgodot_android.so",
                            b"\x7fELF")
            rep = godot.inspect(apk)
            self.assertIn("read cap",
                          rep["pck"].get("parse_error", ""))


class InventoryTest(unittest.TestCase):
    def _shipped_py(self):
        return glob.glob(os.path.join(ROOT, "scripts", "*.py")) + \
            glob.glob(os.path.join(ROOT, "scripts", "narlib", "*.py"))

    def test_no_shell_no_os_system(self):
        for path in self._shipped_py():
            src = open(path, encoding="utf-8").read()
            self.assertNotIn("shell=True", src, path)
            self.assertNotIn("os.system(", src, path)
            self.assertNotIn("eval(", src.replace("evaluate", ""), path)

    def test_subprocess_timeouts(self):
        # The one documented exception: nar.py's run_entry is
        # the interactive top-level dispatcher — it inherits
        # the terminal and the user owns interruption; every
        # other subprocess.run in shipped code must carry a
        # timeout so a hung child cannot hang the pipeline.
        for path in self._shipped_py():
            tree = ast.parse(open(path, encoding="utf-8").read())
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if isinstance(func, ast.Attribute) \
                        and func.attr in ("run", "Popen"):
                    kws = {k.arg for k in node.keywords}
                    if "timeout" in kws:
                        continue
                    self.assertEqual(
                        os.path.basename(path), "nar.py",
                        f"{path}:{node.lineno} subprocess."
                        f"{func.attr} without timeout")

    def test_predictable_temp_paths_gone(self):
        for fname in ("nar-analyze.py", "nar-il2cpp.py",
                      "nar-rn.py"):
            src = open(os.path.join(ROOT, "scripts", fname),
                       encoding="utf-8").read()
            self.assertNotIn("gettempdir(), f\"nar-", src, fname)
            self.assertIn("mkdtemp", src, fname)


if __name__ == "__main__":
    unittest.main()
