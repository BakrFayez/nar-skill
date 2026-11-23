"""Unit tests for narlib.dex and narlib.elf on synthetic inputs.

Both builders construct the smallest spec-shaped binaries that
exercise the parsers: no external fixtures, no app data.
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]
                       / "scripts"))

from narlib.dex import Dex, DexError  # noqa: E402
from narlib.elf import Elf, ElfError  # noqa: E402


def _uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def build_dex():
    """Minimal DEX: strings [LFoo;, hello], 1 type, 1 proto,
    1 method (LFoo;->hello), 0 class defs."""
    strings = [b"LFoo;", b"hello"]
    header_size = 0x70
    string_ids_off = header_size
    string_data_off = string_ids_off + 4 * len(strings)
    data = bytearray()
    offsets = []
    for s in strings:
        offsets.append(string_data_off + len(data))
        data += _uleb(len(s)) + s + b"\x00"
    type_ids_off = string_data_off + len(data)
    proto_ids_off = type_ids_off + 4
    method_ids_off = proto_ids_off + 12
    file_size = method_ids_off + 8

    out = bytearray(file_size)
    out[0:8] = b"dex\n039\x00"
    struct.pack_into("<I", out, 32, file_size)       # file_size
    struct.pack_into("<I", out, 36, header_size)     # header_size
    struct.pack_into("<I", out, 40, 0x12345678)      # endian LE
    struct.pack_into("<I", out, 56, len(strings))    # string_ids_size
    struct.pack_into("<I", out, 60, string_ids_off)
    struct.pack_into("<I", out, 64, 1)               # type_ids_size
    struct.pack_into("<I", out, 68, type_ids_off)
    struct.pack_into("<I", out, 72, 1)               # proto_ids_size
    struct.pack_into("<I", out, 76, proto_ids_off)
    struct.pack_into("<I", out, 88, 1)               # method_ids_size
    struct.pack_into("<I", out, 92, method_ids_off)
    for i, off in enumerate(offsets):
        struct.pack_into("<I", out, string_ids_off + 4 * i, off)
    out[string_data_off:string_data_off + len(data)] = data
    struct.pack_into("<I", out, type_ids_off, 0)     # type 0 -> str 0
    # proto: shorty_idx=1, return_type_idx=0, params_off=0
    struct.pack_into("<III", out, proto_ids_off, 1, 0, 0)
    # method: class_idx=0, proto_idx=0, name_idx=1
    struct.pack_into("<HHI", out, method_ids_off, 0, 0, 1)
    return bytes(out)


def build_elf64():
    """Minimal ELF64 LE AArch64: one PT_LOAD + one PT_DYNAMIC
    with SONAME libfoo.so and NEEDED libbar.so."""
    dynstr = b"\x00libfoo.so\x00libbar.so\x00"
    ehdr_size, phdr_size = 64, 56
    phoff = ehdr_size
    dyn_off = phoff + 2 * phdr_size
    dynstr_off = dyn_off + 5 * 16
    file_size = dynstr_off + len(dynstr)
    base = 0x10000

    out = bytearray(file_size)
    out[0:4] = b"\x7fELF"
    out[4] = 2      # ELFCLASS64
    out[5] = 1      # little endian
    struct.pack_into("<H", out, 16, 3)      # ET_DYN
    struct.pack_into("<H", out, 18, 183)    # AArch64
    struct.pack_into("<Q", out, 32, phoff)
    struct.pack_into("<H", out, 52, ehdr_size)
    struct.pack_into("<H", out, 54, phdr_size)
    struct.pack_into("<H", out, 56, 2)      # phnum
    # PT_LOAD: whole file at base
    struct.pack_into("<IIQQQQQQ", out, phoff, 1, 5, 0, base, base,
                     file_size, file_size, 0x1000)
    # PT_DYNAMIC
    struct.pack_into("<IIQQQQQQ", out, phoff + phdr_size, 2, 4,
                     dyn_off, base + dyn_off, base + dyn_off,
                     5 * 16, 5 * 16, 8)
    entries = [(14, 1),                # DT_SONAME -> "libfoo.so"
               (1, 11),                # DT_NEEDED -> "libbar.so"
               (5, base + dynstr_off),  # DT_STRTAB
               (10, len(dynstr)),      # DT_STRSZ
               (0, 0)]                 # DT_NULL
    for i, (tag, val) in enumerate(entries):
        struct.pack_into("<qQ", out, dyn_off + i * 16, tag, val)
    out[dynstr_off:dynstr_off + len(dynstr)] = dynstr
    return bytes(out)


def test_dex_strings_and_types():
    dex = Dex(build_dex())
    assert dex.strings() == ["LFoo;", "hello"]
    assert dex.types() == ["LFoo;"]
    assert dex.version == "039"


def test_dex_method_ref():
    dex = Dex(build_dex())
    ref = dex.method_ref(0)
    assert ref[0] == "LFoo;" and ref[1] == "hello"
    full = dex.method_full(0)
    assert full[0] == "LFoo;" and full[1] == "hello"
    assert full[2] == "LFoo;" and full[3] == []


def test_dex_rejects_garbage():
    try:
        Dex(b"not a dex at all")
    except DexError:
        return
    raise AssertionError("DexError not raised")


def test_elf_identity():
    elf = Elf(build_elf64())
    assert elf.is_64
    assert elf.arch == "AArch64"
    assert elf.endian == "<"
    facts = elf.facts()
    assert facts["elf_class"] == "ELF64"


def test_elf_dynamic_facts():
    facts = Elf(build_elf64()).facts()
    assert facts["soname"] == "libfoo.so"
    assert facts["needed"] == ["libbar.so"]
    assert facts["jni_exports"] == []


def test_elf_rejects_garbage():
    try:
        Elf(b"\x7fELX" + b"\x00" * 60)
    except ElfError:
        return
    raise AssertionError("ElfError not raised")
