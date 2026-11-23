"""Unit tests: narlib.safearchive guard behavior (planted cases)."""
import io
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..",
                                "scripts"))
from narlib import safearchive  # noqa: E402


def _zip_bytes(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


class SafeArchiveTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="nar-test-safe-")

    def _run(self, entries, limits=None):
        src = os.path.join(self.tmp, "in.zip")
        with open(src, "wb") as fh:
            fh.write(_zip_bytes(entries))
        out = os.path.join(self.tmp, "out")
        return safearchive.safe_extract(src, out, limits), out

    def test_normal_extract(self):
        report, out = self._run([("a/b.txt", b"hello"),
                                 ("c.bin", b"\x00" * 10)])
        self.assertEqual(len(report["extracted"]), 2)
        self.assertEqual(report["rejected"], [])
        with open(os.path.join(out, "a", "b.txt"), "rb") as fh:
            self.assertEqual(fh.read(), b"hello")

    def test_traversal_rejected(self):
        report, out = self._run([("../evil.txt", b"x"),
                                 ("ok.txt", b"y")])
        reasons = [r["reason"] for r in report["rejected"]]
        self.assertTrue(any("traversal" in r for r in reasons))
        self.assertFalse(os.path.exists(
            os.path.join(self.tmp, "evil.txt")))
        self.assertEqual(len(report["extracted"]), 1)

    def test_absolute_rejected(self):
        report, _ = self._run([("/abs.txt", b"x")])
        self.assertEqual(len(report["rejected"]), 1)
        self.assertIn("absolute", report["rejected"][0]["reason"])

    def test_symlink_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            info = zipfile.ZipInfo("link")
            info.external_attr = (0o120777 << 16)  # symlink mode
            zf.writestr(info, b"/etc/passwd")
            zf.writestr("real.txt", b"data")
        src = os.path.join(self.tmp, "links.zip")
        with open(src, "wb") as fh:
            fh.write(buf.getvalue())
        out = os.path.join(self.tmp, "out2")
        report = safearchive.safe_extract(src, out)
        reasons = [r["reason"] for r in report["rejected"]]
        self.assertTrue(any("symlink" in r for r in reasons))
        self.assertFalse(os.path.islink(os.path.join(out, "link")))

    def test_ratio_bomb_rejected(self):
        big = b"\x00" * (2 * 1024 * 1024)  # compresses to ~2 KB
        report, _ = self._run([("bomb.bin", big)],
                              limits={"max_ratio": 50.0})
        reasons = [r["reason"] for r in report["rejected"]]
        self.assertTrue(any("ratio" in r for r in reasons))

    def test_total_size_limit_rejected(self):
        report, _ = self._run([("a.bin", b"x" * 100),
                               ("b.bin", b"y" * 100)],
                              limits={"max_total_bytes": 150})
        self.assertEqual(len(report["extracted"]), 1)
        self.assertEqual(len(report["rejected"]), 1)

    def test_nested_archive_listed_not_opened(self):
        inner = _zip_bytes([("inner.txt", b"deep")])
        report, out = self._run([("inner.zip", inner)])
        self.assertEqual(report["nested_archives"], ["inner.zip"])
        self.assertFalse(os.path.exists(
            os.path.join(out, "inner.txt")))


if __name__ == "__main__":
    unittest.main()
