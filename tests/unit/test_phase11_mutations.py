"""Evolution Phase 11 — parser mutation corpus.

Truncated / corrupted inputs must fail cleanly with each
parser's named error type — never with a leaked
struct.error, IndexError, or any other traceback-class
exception. The valid inputs are the synthetic builders
from the existing parser test modules (no real app bytes);
each mutation is applied to a copy.

Covered parsers: DEX (narlib.dex), ELF (narlib.elf),
Unreal .pak (scripts/nar-pak.py), IoStore TOC
(narlib.iostore), Zen package (narlib.zen), UAsset
package (narlib.uasset).
"""
import hashlib
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
import test_uasset  # noqa: E402
import test_zen  # noqa: E402
from narlib.dex import Dex, DexError  # noqa: E402
from narlib.elf import Elf, ElfError  # noqa: E402
from narlib.iostore import IoStoreError, parse_utoc  # noqa: E402
from narlib.uasset import UAssetError, parse_package  # noqa: E402
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


def test_pak_index_field_mutations_fail_with_pakerror():
    """Index-field shapes beyond the three above (3.0.1
    certification D-08): the encoded index is SHA-1-verified
    against the footer, so each mutant is re-stamped after
    mutation — otherwise every shape would die at the hash
    check and the fields behind it would never be exercised.
    Field offsets are located by walking the documented
    layout of the synthetic fixture."""
    good = test_pak.build_v11_encoded()
    _pak_parse(good)  # control
    _version, index_offset, index_size = nar_pak.find_footer(good)
    footer_base = good.rfind(b"\xe1\x12\x6f\x5a")
    pos = index_offset
    mount_len = struct.unpack_from("<i", good, pos)[0]
    pos += 4 + mount_len
    count_off = pos
    pos += 4 + 8 + 4 + 8 + 8 + 20  # count, seed, path-hash desc
    fdi_off_off = pos + 4
    pos += 4 + 8 + 8 + 20  # directory-index descriptor
    bloblen_off = pos
    blob_off = pos + 4

    def rehash(buf):
        idx = bytes(buf[index_offset:index_offset + index_size])
        struct.pack_into("<20s", buf, footer_base + 24,
                         hashlib.sha1(idx).digest())
        return bytes(buf)

    mutants = []
    entry_count = bytearray(good)
    struct.pack_into("<i", entry_count, count_off, 0x7FFFFFFF)
    mutants.append(rehash(entry_count))
    blob_len = bytearray(good)
    struct.pack_into("<i", blob_len, bloblen_off, -1)
    mutants.append(rehash(blob_len))
    fdi_off = bytearray(good)
    struct.pack_into("<q", fdi_off, fdi_off_off, len(good) + 100)
    mutants.append(rehash(fdi_off))
    entry_offset = bytearray(good)
    struct.pack_into("<I", entry_offset, blob_off + 12, 0xFFFFFFFF)
    mutants.append(rehash(entry_offset))
    block_count = bytearray(good)
    flags = struct.unpack_from("<I", good, blob_off + 28)[0]
    struct.pack_into("<I", block_count, blob_off + 28,
                     flags | (0xFFFF << 6))
    mutants.append(rehash(block_count))
    for mutated in mutants:
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


# -------------------------------------------------------- UAsset

def test_uasset_mutations_fail_with_uasseterror():
    """UAsset enters the mutation corpus (3.0.1 certification
    D-07). Summary field offsets in the synthetic UE4 fixture:
    name count at 72, name offset at 76, import count at 96,
    import offset at 100, export offset at 92 — the layout
    test_uasset.build_ue4 writes and parse_package's summary
    reports (name_offset 251, import_offset 900,
    export_offset 984 for this fixture)."""
    good = test_uasset.build_ue4()
    parse_package(good, "mut.uasset")  # control
    bad_magic = bytearray(good)
    bad_magic[0:4] = b"BAD!"
    name_count = bytearray(good)
    struct.pack_into("<i", name_count, 72, 0x7FFFFFFF)
    name_off = bytearray(good)
    struct.pack_into("<i", name_off, 76, len(good) + 4096)
    import_count = bytearray(good)
    struct.pack_into("<i", import_count, 96, 0x7FFFFFFF)
    import_off = bytearray(good)
    struct.pack_into("<i", import_off, 100, -1)
    export_off = bytearray(good)
    struct.pack_into("<i", export_off, 92, 0x7FFFFFFF)
    for mutated in (bytes(bad_magic), good[:len(good) // 2],
                    good[:100], bytes(name_count),
                    bytes(name_off), bytes(import_count),
                    bytes(import_off), bytes(export_off), b""):
        with pytest.raises(UAssetError):
            parse_package(mutated, "mut.uasset")


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
