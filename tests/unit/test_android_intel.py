"""Unit tests: Evolution Phase 3 Android intelligence —
DEX try/catch tables + debug presence, dexdis block
summary, ELF relocations + .comment fingerprints, and
Kotlin @Metadata annotation parsing.

All fixtures are synthetic and built in this file; the
encoded-value regression case (string index >= 256 in an
annotation array) reproduces the stream desync found on
real @Metadata payloads during this phase.
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]
                       / "scripts"))

from narlib.dex import Dex  # noqa: E402
from narlib import dexdis  # noqa: E402
from narlib.elf import Elf  # noqa: E402


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


def _dex_with_tables(strings, types, extra=b"", class_defs=()):
    """Minimal DEX: given string list and type->string-index
    list, plus raw trailing bytes (code items, annotation
    directories) appended after the tables. class_defs is a
    list of (class_type_idx, annotations_off)."""
    header_size = 0x70
    string_ids_off = header_size
    string_data_off = string_ids_off + 4 * len(strings)
    data = bytearray()
    offsets = []
    for s in strings:
        offsets.append(string_data_off + len(data))
        raw = s.encode()
        data += _uleb(len(raw)) + raw + b"\x00"
    type_ids_off = string_data_off + len(data)
    class_defs_off = type_ids_off + 4 * len(types)
    tail_off = class_defs_off + 32 * len(class_defs)
    file_size = tail_off + len(extra)
    out = bytearray(file_size)
    out[0:8] = b"dex\n038\x00"
    struct.pack_into("<I", out, 32, file_size)
    struct.pack_into("<I", out, 36, header_size)
    struct.pack_into("<I", out, 40, 0x12345678)
    struct.pack_into("<I", out, 56, len(strings))
    struct.pack_into("<I", out, 60, string_ids_off)
    struct.pack_into("<I", out, 64, len(types))
    struct.pack_into("<I", out, 68, type_ids_off)
    struct.pack_into("<I", out, 96, len(class_defs))
    struct.pack_into("<I", out, 100, class_defs_off)
    for i, off in enumerate(offsets):
        struct.pack_into("<I", out, string_ids_off + 4 * i, off)
    out[string_data_off:string_data_off + len(data)] = data
    for i, sidx in enumerate(types):
        struct.pack_into("<I", out, type_ids_off + 4 * i, sidx)
    for i, (class_idx, ann_off) in enumerate(class_defs):
        base = class_defs_off + 32 * i
        struct.pack_into("<IIIIIIII", out, base,
                         class_idx, 0, 0xFFFFFFFF, 0, 0,
                         ann_off, 0, 0)
    out[tail_off:tail_off + len(extra)] = extra
    return bytes(out), tail_off


def _code_item(insns, tries=(), debug_off=0):
    """Code item bytes: header, insns, padding, try items,
    then the encoded catch handler list (one handler per
    try, in order). tries: [(start, count, handler)] with
    handler = ([(type_idx, addr)], catch_all_or_None)."""
    out = bytearray()
    out += struct.pack("<HHHHII", 2, 1, 1, len(tries),
                       debug_off, len(insns))
    for u in insns:
        out += struct.pack("<H", u)
    if len(insns) % 2 and tries:
        out += struct.pack("<H", 0)
    handler_list = bytearray()
    handler_list += _uleb(len(tries))
    handler_offsets = []
    for _start, _count, (typed, catch_all) in tries:
        handler_offsets.append(len(handler_list))
        size = len(typed) if catch_all is None else -len(typed)
        # sleb128 of size
        val = size
        while True:
            b = val & 0x7F
            val >>= 7
            if (val == 0 and not (b & 0x40)) or \
                    (val == -1 and (b & 0x40)):
                handler_list.append(b)
                break
            handler_list.append(b | 0x80)
        for type_idx, addr in typed:
            handler_list += _uleb(type_idx)
            handler_list += _uleb(addr)
        if catch_all is not None:
            handler_list += _uleb(catch_all)
    for (start, count, _h), hoff in zip(tries, handler_offsets):
        out += struct.pack("<IHH", start, count, hoff)
    out += handler_list
    return bytes(out)


# ---------------------------------------------------------------
# DEX try/catch + debug presence

def test_code_item_try_catch_and_debug():
    strings = ["Ljava/lang/Exception;", "LFoo;"]
    code = _code_item(
        [0x0000, 0x0000, 0x0000, 0x000E],
        tries=[(0, 3, ([(0, 3)], 2))], debug_off=0x40)
    blob, tail = _dex_with_tables(strings, [0, 1], extra=code)
    dex = Dex(blob)
    info = dex.code_item_info(tail)
    assert info["tries_size"] == 1
    assert info["has_debug_info"] is True
    assert info["handler_list_count"] == 1
    entry = info["tries"][0]
    assert entry["start_addr"] == 0 and entry["end_addr"] == 3
    assert entry["handlers"] == [
        {"type": "Ljava/lang/Exception;", "addr": 3}]
    assert entry["catch_all_addr"] == 2


def test_code_item_no_tries_no_debug():
    code = _code_item([0x000E], tries=(), debug_off=0)
    blob, tail = _dex_with_tables(["LFoo;"], [0], extra=code)
    info = Dex(blob).code_item_info(tail)
    assert info["tries"] == []
    assert info["has_debug_info"] is False
    assert Dex(blob).code_item_info(0) is None


# ---------------------------------------------------------------
# dexdis block summary

def test_block_summary_known_branches():
    # goto +2 ; nop ; return-void, with a try over [0,2)
    # whose catch-all handler sits at 2.
    code = _code_item(
        [0x0228, 0x0000, 0x000E],
        tries=[(0, 2, ([], 2))], debug_off=0)
    blob, tail = _dex_with_tables(["LFoo;"], [0], extra=code)
    summary = dexdis.block_summary(Dex(blob), tail)
    assert summary["status"] == "ok"
    assert summary["blocks"] == [
        {"start": 0, "end": 2, "instructions": 2},
        {"start": 2, "end": 3, "instructions": 1}]
    assert summary["branch_edges"] == [[0, 2]]
    assert len(summary["tries"]) == 1
    assert summary["tries"][0]["catch_all_addr"] == 2


# ---------------------------------------------------------------
# Kotlin @Metadata

def _int_value(v):
    return bytes([0x04]) + bytes([v])


def _array_value(items):
    return bytes([0x1C]) + _uleb(len(items)) + b"".join(items)


def _string_value(idx):
    # Fixed-width little-endian index, arg+1 bytes (the DEX
    # encoded_value rule for index-carrying values).
    if idx < 256:
        return bytes([0x17, idx])
    return bytes([0x37]) + struct.pack("<H", idx)


def _metadata_dex():
    """One class Lcom/example/Foo; carrying @Metadata with
    elements in the order that desynced the pre-fix decoder:
    d2 (holding a string at index 300) BEFORE mv and k."""
    strings = ["filler"] * 300
    strings.append("target-string")          # index 300
    strings += ["Lkotlin/Metadata;", "mv", "k", "d2",
                "Lcom/example/Foo;"]
    idx_target = 300
    idx_meta_type_str = 301
    types = [idx_meta_type_str, 305]         # Metadata, Foo
    elements = (
        _uleb(304) + _array_value([_string_value(idx_target)])
        + _uleb(302) + _array_value(
            [_int_value(1), _int_value(9), _int_value(0)])
        + _uleb(303) + _int_value(1))
    annotation = _uleb(0) + _uleb(3) + elements
    item = bytes([1]) + annotation           # visibility + body
    # Layout inside `extra`: directory (16 B), set (8 B),
    # item. All offsets in these structures are ABSOLUTE
    # file offsets, patched once the tail position is known.
    directory = struct.pack("<IIII", 0, 0, 0, 0)
    ann_set = struct.pack("<II", 1, 0)
    extra = directory + ann_set + item
    blob, tail = _dex_with_tables(
        strings, types, extra=extra,
        class_defs=[(1, 0)])                 # patched below
    blob = bytearray(blob)
    class_defs_off = struct.unpack_from("<I", blob, 100)[0]
    # class_def.annotations_off -> directory at tail
    struct.pack_into("<I", blob, class_defs_off + 20, tail)
    # directory.class_annotations_off -> set at tail + 16
    struct.pack_into("<I", blob, tail, tail + 16)
    # set entry -> item at tail + 24
    struct.pack_into("<I", blob, tail + 16 + 4, tail + 24)
    return bytes(blob)


def test_kotlin_metadata_parsed():
    dex = Dex(_metadata_dex())
    cdef = dex.class_defs()[0]
    annotations = dex.class_annotations(cdef)
    assert len(annotations) == 1
    ann = annotations[0]
    assert ann["type"] == "Lkotlin/Metadata;"
    assert ann["elements"]["mv"] == [1, 9, 0]
    assert ann["elements"]["k"] == 1
    # The regression: a string index >= 256 inside an array
    # element that precedes mv/k must not desync the stream.
    assert ann["elements"]["d2"] == ["target-string"]


# ---------------------------------------------------------------
# ELF relocations + .comment

def _elf_with_reloc_and_comment():
    """ELF64 LE AArch64 with .dynsym/.dynstr/.rela.plt/
    .comment/.shstrtab sections (no program headers)."""
    dynstr = b"\x00__cxa_finalize\x00"
    dynsym = bytearray(48)
    struct.pack_into("<IBBHQQ", dynsym, 24, 1, 0x12, 0, 0, 0, 0)
    rela = struct.pack("<QQq", 0x2000, (1 << 32) | 1026, 0)
    comment = (b"clang version 18.0.3 (synthetic test)\x00"
               b"GCC: (GNU) 13.2.0\x00")
    shstr = (b"\x00.dynsym\x00.dynstr\x00.rela.plt\x00"
             b".comment\x00.shstrtab\x00")
    names = {".dynsym": 1, ".dynstr": 9, ".rela.plt": 17,
             ".comment": 27, ".shstrtab": 36}
    ehdr = 64
    dynsym_off = ehdr
    dynstr_off = dynsym_off + len(dynsym)
    rela_off = dynstr_off + len(dynstr)
    comment_off = rela_off + len(rela)
    shstr_off = comment_off + len(comment)
    shoff = shstr_off + len(shstr)
    out = bytearray(shoff + 6 * 64)
    out[0:4] = b"\x7fELF"
    out[4] = 2
    out[5] = 1
    struct.pack_into("<H", out, 16, 3)       # ET_DYN
    struct.pack_into("<H", out, 18, 183)     # AArch64
    struct.pack_into("<Q", out, 40, shoff)
    struct.pack_into("<H", out, 52, ehdr)
    struct.pack_into("<H", out, 58, 64)      # shentsize
    struct.pack_into("<H", out, 60, 6)       # shnum
    struct.pack_into("<H", out, 62, 5)       # shstrndx
    out[dynsym_off:dynsym_off + len(dynsym)] = dynsym
    out[dynstr_off:dynstr_off + len(dynstr)] = dynstr
    out[rela_off:rela_off + len(rela)] = rela
    out[comment_off:comment_off + len(comment)] = comment
    out[shstr_off:shstr_off + len(shstr)] = shstr

    def shdr(idx, name, stype, off, size, link, entsize):
        struct.pack_into("<IIQQQQIIQQ", out, shoff + idx * 64,
                         names[name], stype, 0, 0, off, size,
                         link, 0, 1, entsize)
    shdr(1, ".dynsym", 11, dynsym_off, len(dynsym), 2, 24)
    shdr(2, ".dynstr", 3, dynstr_off, len(dynstr), 0, 0)
    shdr(3, ".rela.plt", 4, rela_off, len(rela), 1, 24)
    shdr(4, ".comment", 1, comment_off, len(comment), 0, 0)
    shdr(5, ".shstrtab", 3, shstr_off, len(shstr), 0, 0)
    return bytes(out)


def test_elf_relocations_and_comment():
    elf = Elf(_elf_with_reloc_and_comment())
    entries = elf.relocations()
    assert len(entries) == 1
    entry = entries[0]
    assert entry["section"] == ".rela.plt"
    assert entry["type"] == 1026
    assert entry["type_name"] == "JUMP_SLOT"
    assert entry["symbol"] == "__cxa_finalize"
    summary = elf.relocation_summary()
    assert summary["total"] == 1
    assert summary["plt_got"] == 1
    assert summary["by_type"] == {"JUMP_SLOT": 1}
    facts = elf.facts()
    assert facts["relocations"]["total"] == 1
    fps = facts["compiler_fingerprints"]
    assert [f["tool"] for f in fps] == ["clang", "gcc"]
    assert all(f["fact_class"] == "observed" for f in fps)
    assert "clang version 18.0.3" in fps[0]["banner"]


def test_elf_no_comment_no_relocations_claimed():
    # A section-less ELF: nothing is claimed.
    import test_dex_elf as base  # noqa: E402
    facts = Elf(base.build_elf64()).facts()
    assert facts["relocations"]["total"] == 0
    assert facts["comment_strings"] == []
    assert facts["compiler_fingerprints"] == []
