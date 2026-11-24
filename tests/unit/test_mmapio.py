"""Unit tests for narlib.mmapio and for the narlib parsers
fed with a real mmap instead of bytes (W4).

The parsers slice and struct.unpack_from their input, so
an mmap must behave exactly like the bytes it replaces:
every test here parses the same synthetic input twice —
once as bytes, once as an mmap obtained through
mapped_file with the tiny-file threshold forced to zero —
and asserts the results are identical. Synthetic inputs
only (builders borrowed from the sibling test modules);
no external fixtures, no app data.
"""
import importlib.util
import mmap
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

from narlib import elf as elf_mod  # noqa: E402
from narlib import iostore, uasset, zen  # noqa: E402
from narlib.mmapio import mapped_file  # noqa: E402
import narlib.mmapio as mmapio  # noqa: E402


def _load_sibling(name):
    spec = importlib.util.spec_from_file_location(
        name, HERE / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _forced_mmap(tmp_path, name, blob, monkeypatch):
    """Write blob and map it, with the tiny-file bytes
    fallback disabled so even a small file is mapped."""
    monkeypatch.setattr(mmapio, "_TINY_BYTES", -1)
    path = tmp_path / name
    path.write_bytes(blob)
    return mapped_file(str(path))


def test_tiny_file_yields_bytes(tmp_path):
    path = tmp_path / "tiny.bin"
    path.write_bytes(b"hello\x00world")
    with mapped_file(str(path)) as data:
        assert isinstance(data, bytes)
        assert data == b"hello\x00world"


def test_large_file_yields_mmap_closed_on_exit(tmp_path):
    blob = bytes(range(256)) * 1000  # 256,000 bytes
    path = tmp_path / "large.bin"
    path.write_bytes(blob)
    with mapped_file(str(path)) as data:
        assert isinstance(data, mmap.mmap)
        assert len(data) == len(blob)
        assert data[:4] == blob[:4]
        assert data[-4:] == blob[-4:]
    assert data.closed


def test_empty_file_yields_empty_bytes(tmp_path):
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")
    with mapped_file(str(path)) as data:
        assert data == b""


def test_missing_file_raises(tmp_path):
    with pytest.raises(OSError):
        with mapped_file(str(tmp_path / "nope.bin")):
            pass


def test_iostore_and_extract_over_mmap(tmp_path, monkeypatch):
    builders = _load_sibling("test_iostore")
    utoc, ucas = builders.build_current()
    want = iostore.parse_utoc(utoc, "synthetic")
    want.pop("_blocks", None)
    want_chunks = [iostore.extract_chunk(
        iostore.parse_utoc(utoc, "synthetic"), ucas, i)
        for i in range(3)]
    with _forced_mmap(tmp_path, "c.utoc", utoc,
                      monkeypatch) as mm_utoc, \
            _forced_mmap(tmp_path, "c.ucas", ucas,
                         monkeypatch) as mm_ucas:
        assert isinstance(mm_utoc, mmap.mmap)
        got_parsed = iostore.parse_utoc(mm_utoc, "synthetic")
        got = dict(got_parsed)
        got.pop("_blocks", None)
        assert got == want
        for i in range(3):
            assert iostore.extract_chunk(
                got_parsed, mm_ucas, i) == want_chunks[i]


def test_zen_over_mmap(tmp_path, monkeypatch):
    builders = _load_sibling("test_zen")
    chunk = builders.current_fixture()
    want = zen.parse_zen_package(chunk, "synthetic")
    with _forced_mmap(tmp_path, "pkg.chunk", chunk,
                      monkeypatch) as mm:
        assert isinstance(mm, mmap.mmap)
        assert zen.parse_zen_package(mm, "synthetic") == want


def test_uasset_over_mmap(tmp_path, monkeypatch):
    builders = _load_sibling("test_uasset")
    pkg = builders.build_ue4()
    want = uasset.parse_package(pkg, "synthetic")
    with _forced_mmap(tmp_path, "pkg.uasset", pkg,
                      monkeypatch) as mm:
        assert isinstance(mm, mmap.mmap)
        assert uasset.parse_package(mm, "synthetic") == want


def test_elf_over_mmap(tmp_path, monkeypatch):
    builders = _load_sibling("test_native")
    blob = builders.build_elf64()
    want = elf_mod.Elf(blob, "libfoo.so").facts()
    path = tmp_path / "libfoo.so"
    path.write_bytes(blob)
    monkeypatch.setattr(mmapio, "_TINY_BYTES", -1)
    with mapped_file(str(path)) as mm:
        assert isinstance(mm, mmap.mmap)
        assert elf_mod.Elf(mm, "libfoo.so").facts() == want
