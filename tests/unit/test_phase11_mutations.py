"""Evolution Phase 11 — parser mutation corpus.

Truncated / corrupted inputs must fail cleanly with each
parser's named error type — never with a leaked
struct.error, IndexError, or any other traceback-class
exception. The valid inputs are the synthetic builders
from the existing parser test modules (no real app bytes);
each mutation is applied to a copy.

Covered parsers: DEX (narlib.dex), ELF (narlib.elf),
Unreal .pak (scripts/nar-pak.py), IoStore TOC
(narlib.iostore), Zen package (narlib.zen).
"""
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]
                       / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_dex_elf  # noqa: E402
import test_iostore  # noqa: E402
import test_pak  # noqa: E402
import test_zen  # noqa: E402
from narlib.dex import Dex, DexError  # noqa: E402
from narlib.elf import Elf, ElfError  # noqa: E402
from narlib.iostore import IoStoreError, parse_utoc  # noqa: E402
from narlib.zen import ZenError, parse_zen_package  # noqa: E402

nar_pak = test_pak.nar_pak
PakError = nar_pak.PakError


def _pak_parse(data):
    """The nar-pak CLI's parse chain: footer, then the index."""
    version, off, size = nar_pak.find_footer(data)
    return nar_pak._parse_index(data, version, off, size)


def _dex_parse(data):
    """Construct + materialize the lazy tables."""
    dex = Dex(data)
    dex.strings()
    dex.types()
    return dex


def _elf_parse(data):
    """Construct + materialize the lazy section table."""
    elf = Elf(data)
    elf.sections()
    return elf


# ---------------------------------------------------------- DEX

def test_dex_mutations_fail_with_dexerror():
    good = test_dex_elf.build_dex()
    _dex_parse(good)  # control: the unmutated input parses
    bad_magic = bytearray(good)
    bad_magic[0:4] = b"BAD!"
    inflated = bytearray(good)
    struct.pack_into("<I", inflated, 56, 0x00FFFFFF)
    for mutated in (bytes(bad_magic), good[:len(good) // 2],
                    bytes(inflated), b""):
        with pytest.raises(DexError):
            _dex_parse(mutated)


# ---------------------------------------------------------- ELF

def test_elf_mutations_fail_with_elferror():
    good = test_dex_elf.build_elf64()
    _elf_parse(good)  # control
    bad_magic = bytearray(good)
    bad_magic[0:4] = b"BAD!"
    bad_class = bytearray(good)
    bad_class[4] = 9  # EI_CLASS neither 32 nor 64
    for mutated in (bytes(bad_magic), good[:16], bytes(bad_class),
                    b""):
        with pytest.raises(ElfError):
            _elf_parse(mutated)


# ---------------------------------------------------------- PAK

def test_pak_mutations_fail_with_pakerror():
    # build_v11_encoded is the fully parseable pak fixture
    # (test_pak's build_v5 is a footer-only fixture).
    good = test_pak.build_v11_encoded()
    mount, entries, _layout = _pak_parse(good)
    assert entries  # control: entries listed
    truncated = good[:len(good) // 2]
    for mutated in (b"\x00" * 2048, truncated, b""):
        with pytest.raises(PakError):
            _pak_parse(mutated)


# ------------------------------------------------------- IoStore

def test_iostore_mutations_fail_with_iostoreerror():
    utoc, _ucas = test_iostore.build_current()
    parse_utoc(utoc)  # control
    bad_magic = bytearray(utoc)
    bad_magic[0:4] = b"BAD!"
    for mutated in (bytes(bad_magic), utoc[:len(utoc) // 2],
                    utoc[:40], b""):
        with pytest.raises(IoStoreError):
            parse_utoc(mutated)


# ----------------------------------------------------------- Zen

def test_zen_mutations_fail_with_zenerror():
    good = test_zen.current_fixture()
    parse_zen_package(good, "Content/Mut")  # control
    bad_magic = bytearray(good)
    bad_magic[0] ^= 0xFF
    for mutated in (bytes(bad_magic), good[:len(good) // 2],
                    good[:24], b""):
        with pytest.raises(ZenError):
            parse_zen_package(mutated, "Content/Mut")
