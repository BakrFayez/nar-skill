"""Certification fix A1-01 (Accuracy Defect, P2): nar-native
headline count must not count failed parses.

Audit evidence (ANNEX_A1 A1-01): ``native_library_count`` was
``len(report["libraries"])`` with no exclusion of error
entries, so a truncated ELF whose libraries list contains
only an error record still yielded
``native_library_count = 1``.

Contract after the fix:
- ``native_library_count`` equals the number of SUCCESSFULLY
  parsed libraries (entries without an ``error`` key);
- failed parses are counted separately in the additive
  companion field ``native_library_failed_count``;
- the ``libraries`` list itself is unchanged (error entries
  are retained, so no consumer loses information), and
  ``native_library_count + native_library_failed_count``
  equals ``len(libraries)``.

Synthetic inputs only: the valid ELF is the shared builder
from test_dex_elf (same pattern as test_elf_robustness);
the corrupt library is that ELF truncated to 60 bytes,
which narlib.elf rejects with a named ElfError
("truncated ELF header").
"""
import importlib.util
import io
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_dex_elf  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "nar_native_a101", SCRIPTS / "nar-native.py")
nar_native = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nar_native)


def _valid_so():
    return test_dex_elf.build_elf64()


def _truncated_so():
    # Valid ELF64 header prefix cut at 60 bytes: narlib.elf
    # raises ElfError("truncated ELF header (60 bytes)").
    return test_dex_elf.build_elf64()[:60]


def _apk_bytes(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def test_bare_corrupt_library_counts_zero_successes(tmp_path):
    target = tmp_path / "libtruncated.so"
    target.write_bytes(_truncated_so())
    report = nar_native.analyze(str(target))
    # The failed parse is retained as an error entry.
    assert len(report["libraries"]) == 1
    assert "error" in report["libraries"][0]
    # Headline count is successes only; failure counted apart.
    assert report["native_library_count"] == 0
    assert report["native_library_failed_count"] == 1
    assert (report["native_library_count"]
            + report["native_library_failed_count"]
            == len(report["libraries"]))


def test_mixed_archive_counts_only_successful_parses(tmp_path):
    apk = tmp_path / "mixed.apk"
    apk.write_bytes(_apk_bytes([
        ("lib/arm64-v8a/libfoo.so", _valid_so()),
        ("lib/arm64-v8a/libtruncated.so", _truncated_so()),
    ]))
    report = nar_native.analyze(str(apk))
    assert len(report["libraries"]) == 2
    errors = [lib for lib in report["libraries"]
              if "error" in lib]
    assert len(errors) == 1
    assert report["native_library_count"] == 1
    assert report["native_library_failed_count"] == 1
    assert (report["native_library_count"]
            + report["native_library_failed_count"]
            == len(report["libraries"]))


def test_all_valid_archive_counts_every_library(tmp_path):
    apk = tmp_path / "valid.apk"
    apk.write_bytes(_apk_bytes([
        ("lib/arm64-v8a/libfoo.so", _valid_so()),
        ("lib/arm64-v8a/libbar.so", _valid_so()),
    ]))
    report = nar_native.analyze(str(apk))
    assert len(report["libraries"]) == 2
    assert all("error" not in lib for lib in report["libraries"])
    assert report["native_library_count"] == 2
    assert report["native_library_failed_count"] == 0
