"""2.6.2 Workstream A3: ELF robustness.

Every malformed ELF must fail as a named ElfError attributable
to the file and the structure at fault -- never a leaked
struct.error / IndexError, never a silent empty result where
the file claims structure exists. Areas: invalid headers,
unsupported architecture, truncated program headers, invalid
section tables, invalid string tables, dynamic symbol
inconsistencies, relocation boundaries, GNU hash sections
(which narlib.elf deliberately treats as opaque -- it has no
GNU-hash parser, so a malformed one must simply not disturb
the rest of the parse), JNI symbol names, and oversized
section counts.

Synthetic inputs only.
"""
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_dex_elf  # noqa: E402
from narlib.elf import Elf, ElfError  # noqa: E402


def _patch(data, off, fmt, value):
    out = bytearray(data)
    struct.pack_into(fmt, out, off, value)
    return bytes(out)


# ----------------------------------------------------------
# Headers / architecture
# ----------------------------------------------------------

def test_invalid_magic_and_short_files():
    for bad in (b"", b"\x7fEL", b"\x7fELX" + b"\x00" * 60,
                b"dex\n039\x00" + b"\x00" * 60):
        with pytest.raises(ElfError, match="not an ELF"):
            Elf(bad)


def test_invalid_ei_class_and_ei_data():
    good = test_dex_elf.build_elf64()
    with pytest.raises(ElfError, match="EI_CLASS"):
        Elf(_patch(good, 4, "<B", 9))
    with pytest.raises(ElfError, match="EI_DATA"):
        Elf(_patch(good, 5, "<B", 9))
    with pytest.raises(ElfError, match="EI_DATA"):
        Elf(_patch(good, 5, "<B", 0))


def test_truncated_headers_both_classes():
    with pytest.raises(ElfError, match="truncated ELF header"):
        Elf(test_dex_elf.build_elf64()[:60])
    # ELF32: 40 bytes passes the 52-byte floor check only for
    # 64-bit; a 32-bit file needs 52 -- build the ident by hand.
    data = bytearray(52)
    data[0:4] = b"\x7fELF"
    data[4] = 1
    data[5] = 1
    Elf(bytes(data))  # exactly 52: parses
    with pytest.raises(ElfError):  # below the 52-byte floor
        Elf(bytes(data[:51]))


def test_unsupported_arch_reports_numerically_no_crash():
    """An unknown e_machine is not an error in this parser:
    like unmapped relocation types it is reported numerically
    (machine-0x...) and the rest of the parse proceeds."""
    data = _patch(test_dex_elf.build_elf64(), 18, "<H", 0x1234)
    elf = Elf(data)
    assert elf.arch == "machine-0x1234"
    facts = elf.facts()
    assert facts["arch"] == "machine-0x1234"
    assert facts["soname"] == "libfoo.so"


# ----------------------------------------------------------
# Program / section header tables
# ----------------------------------------------------------

def test_truncated_program_headers():
    data = _patch(test_dex_elf.build_elf64(), 32, "<Q",
                  0x00FFFFF0)  # phoff
    with pytest.raises(ElfError, match="program header"):
        Elf(data).program_headers()
    # phnum claiming far more entries than the file holds.
    data = _patch(test_dex_elf.build_elf64(), 56, "<H", 0xFFFF)
    with pytest.raises(ElfError, match="program header"):
        Elf(data).program_headers()


def test_program_header_entsize_too_small():
    data = _patch(test_dex_elf.build_elf64(), 54, "<H", 8)
    with pytest.raises(ElfError, match="program header entry size"):
        Elf(data).program_headers()


def test_section_header_entsize_too_small():
    good = bytearray(_elf_with_sections())
    shoff = struct.unpack_from("<Q", good, 40)[0]
    struct.pack_into("<H", good, 58, 8)  # shentsize
    assert shoff > 0
    with pytest.raises(ElfError, match="section header entry size"):
        Elf(bytes(good)).sections()


def test_oversized_section_count_fails_named():
    good = bytearray(_elf_with_sections())
    struct.pack_into("<H", good, 60, 0xFFFF)  # shnum
    with pytest.raises(ElfError, match="section header"):
        Elf(bytes(good)).sections()


def test_invalid_section_string_table_index():
    good = bytearray(_elf_with_sections())
    struct.pack_into("<H", good, 62, 99)  # shstrndx
    with pytest.raises(ElfError, match="out of range"):
        Elf(bytes(good)).sections()


# ----------------------------------------------------------
# Sectioned ELF builder (dynsym / dynstr / rela / gnu.hash)
# ----------------------------------------------------------

DYNSYM_NAMES = b"\x00libfoo.so\x00" \
    b"Java_com_example_Native_run\x00" \
    b"\xff\xfe invalid utf8\x00"


def _elf_with_sections(dynsym_entsize=24, rela_entsize=24,
                       dynsym_link=2, extra_dynsym=b"",
                       rela_entries=None, gnu_hash=b"\x01\x00\x00\x00"
                       b"\xff\xff\xff\xff"):
    """ELF64 LE with sections: null, .dynsym, .dynstr,
    .rela.dyn, .gnu.hash, .shstrtab. Two dynsym entries:
    the null symbol and one defined Java_* export."""
    dynstr = DYNSYM_NAMES
    jni_off = dynstr.index(b"Java_")
    dynsym = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
    dynsym += struct.pack("<IBBHQQ", jni_off, 0x12, 0, 1,
                           0x1000, 16)
    dynsym += extra_dynsym
    if rela_entries is None:
        # sym index 1 (the JNI export), type 1027 (RELATIVE
        # on AArch64), plus one entry whose symbol index is
        # far beyond the table.
        rela_entries = [
            (0x2000, (1 << 32) | 1027, 0),
            (0x3000, (999 << 32) | 1025, 0),
        ]
    rela = b"".join(struct.pack("<QQq", off, info, add)
                    for off, info, add in rela_entries)
    shstr = b"\x00.dynsym\x00.dynstr\x00.rela.dyn\x00" \
            b".gnu.hash\x00.shstrtab\x00"
    name_off = {".dynsym": 1, ".dynstr": 9, ".rela.dyn": 17,
                ".gnu.hash": 27, ".shstrtab": 37}

    ehsize = 64
    dynsym_off = ehsize
    dynstr_off = dynsym_off + len(dynsym)
    rela_off = dynstr_off + len(dynstr)
    gnu_off = rela_off + len(rela)
    shstr_off = gnu_off + len(gnu_hash)
    shoff = shstr_off + len(shstr)

    def sh(name, typ, off, size, link, entsize):
        return struct.pack("<IIQQQQIIQQ", name_off[name], typ,
                           0, 0, off, size, link, 0, 1, entsize)

    sections = b"".join([
        b"\x00" * 64,
        sh(".dynsym", 11, dynsym_off, len(dynsym), dynsym_link,
           dynsym_entsize),
        sh(".dynstr", 3, dynstr_off, len(dynstr), 0, 0),
        sh(".rela.dyn", 4, rela_off, len(rela), 1, rela_entsize),
        sh(".gnu.hash", 0x6FFFFFF6, gnu_off, len(gnu_hash), 1, 0),
        sh(".shstrtab", 3, shstr_off, len(shstr), 0, 0),
    ])
    out = bytearray(shoff + len(sections))
    out[0:4] = b"\x7fELF"
    out[4] = 2
    out[5] = 1
    struct.pack_into("<H", out, 16, 3)      # ET_DYN
    struct.pack_into("<H", out, 18, 183)    # AArch64
    struct.pack_into("<Q", out, 40, shoff)
    struct.pack_into("<H", out, 52, ehsize)
    struct.pack_into("<H", out, 58, 64)     # shentsize
    struct.pack_into("<H", out, 60, 6)      # shnum
    struct.pack_into("<H", out, 62, 5)      # shstrndx
    out[dynsym_off:dynsym_off + len(dynsym)] = dynsym
    out[dynstr_off:dynstr_off + len(dynstr)] = dynstr
    out[rela_off:rela_off + len(rela)] = rela
    out[gnu_off:gnu_off + len(gnu_hash)] = gnu_hash
    out[shstr_off:shstr_off + len(shstr)] = shstr
    out[shoff:shoff + len(sections)] = sections
    return bytes(out)


def test_sectioned_elf_symbols_and_jni():
    elf = Elf(_elf_with_sections())
    facts = elf.facts()
    assert facts["jni_exports"] == ["Java_com_example_Native_run"]
    assert "libfoo.so" not in facts["exports"]  # name only, undef
    names = [s["name"] for s in elf.sections()]
    assert ".gnu.hash" in names and ".rela.dyn" in names


def test_malformed_gnu_hash_section_is_opaque():
    """narlib.elf has no GNU-hash parser by design: a garbage
    .gnu.hash section is carried as a named section and must
    not disturb symbols, relocations, or facts."""
    elf = Elf(_elf_with_sections(
        gnu_hash=b"\xff" * 64 + b"\x00\x01"))
    facts = elf.facts()
    assert facts["jni_exports"] == ["Java_com_example_Native_run"]
    assert elf.relocation_summary()["total"] == 2


def test_dynsym_link_out_of_range_yields_empty_names():
    """A dynsym whose linked string table index is outside
    the section table: names resolve to empty strings, the
    parse completes, nothing crashes."""
    elf = Elf(_elf_with_sections(dynsym_link=99))
    syms = elf.symbols(11)
    assert len(syms) == 2
    assert all(s["name"] == "" for s in syms)


def test_dynsym_entsize_too_small_is_named_error():
    elf = Elf(_elf_with_sections(dynsym_entsize=8))
    with pytest.raises(ElfError, match="symbol entry size"):
        elf.symbols(11)
    with pytest.raises(ElfError, match="symbol entry size"):
        elf.relocations()  # resolves names via the dynsym


def test_dynsym_partial_trailing_entry_ignored():
    """Section size not a multiple of the entry size: the
    trailing partial entry is not read (no struct.error)."""
    elf = Elf(_elf_with_sections(extra_dynsym=b"\x01\x02\x03"))
    assert len(elf.symbols(11)) == 2


def test_invalid_utf8_symbol_name_does_not_crash():
    bad_off = DYNSYM_NAMES.index(b"\xff\xfe")
    extra = struct.pack("<IBBHQQ", bad_off, 0x12, 0, 1, 0, 0)
    elf = Elf(_elf_with_sections(extra_dynsym=extra))
    names = [s["name"] for s in elf.symbols(11)]
    assert len(names) == 3
    assert "�" in names[2]  # replacement-char decoding


def test_relocation_symbol_beyond_table_is_none():
    elf = Elf(_elf_with_sections())
    relocs = elf.relocations()
    by_off = {r["offset"]: r for r in relocs}
    assert by_off[0x2000]["symbol"] == \
        "Java_com_example_Native_run"
    assert by_off[0x2000]["type_name"] == "RELATIVE"
    assert by_off[0x3000]["symbol"] is None
    assert by_off[0x3000]["symbol_index"] == 999


def test_relocation_entsize_too_small_is_named_error():
    elf = Elf(_elf_with_sections(rela_entsize=8))
    with pytest.raises(ElfError, match="relocation entry size"):
        elf.relocations()


def test_relocation_section_truncated_mid_entry():
    """Cut the file so the last relocation entry is partial:
    the failure must be the named ElfError, never a leaked
    struct.error and never entries fabricated from bytes
    that are not there."""
    good = _elf_with_sections()
    elf = Elf(good[:-10])
    # Section headers are at the end, so truncating breaks
    # them first -- that failure must be the named ElfError.
    with pytest.raises(ElfError):
        elf.sections()
    # With the section table intact but the rela section
    # size overstated past EOF, the section's declared
    # extent is invalid: _section_data raises the named
    # ElfError (stability audit A-04). The pre-fix behavior
    # silently sliced to EOF and decoded the FOLLOWING
    # sections' bytes as further relocation entries --
    # fabricated evidence of exactly the class A-04
    # eliminated for symbol tables, and contrary to this
    # module's contract (malformed structure fails by
    # name, never silently).
    data = bytearray(good)
    shoff = struct.unpack_from("<Q", data, 40)[0]
    rela_sh = shoff + 3 * 64
    size = struct.unpack_from("<Q", data, rela_sh + 32)[0]
    struct.pack_into("<Q", data, rela_sh + 32, size + 4096)
    elf = Elf(bytes(data))
    with pytest.raises(ElfError, match="past the end"):
        elf.relocations()
