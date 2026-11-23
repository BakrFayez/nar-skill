"""Unit tests for narlib.dotnetmeta on a synthetic assembly.

The builder constructs the smallest ECMA-335-shaped PE/CLI
image that exercises the reader: one section, a CLI header,
a metadata root with #~ and #Strings streams, and Module /
TypeRef / TypeDef / MethodDef tables (3 TypeDef rows
including <Module>, 5 MethodDef rows). No external
fixtures, no app data.
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]
                       / "scripts"))

from narlib.dotnetmeta import (DotNetMetaError,  # noqa: E402
                               count_assembly)

STRINGS = [b"Test.dll", b"Object", b"System", b"<Module>",
           b"Foo", b"NS.One", b"Bar", b"NS.Two"]


def _strings_heap():
    heap = bytearray(b"\x00")
    offsets = {}
    for s in STRINGS:
        offsets[s] = len(heap)
        heap += s + b"\x00"
    return bytes(heap), offsets


def build_assembly(tmp_path):
    strings, idx = _strings_heap()

    # #~ tables stream.
    valid = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 6)
    tables = bytearray()
    tables += struct.pack("<IBBBB", 0, 2, 0, 0, 0)   # hdr part 1
    tables += struct.pack("<QQ", valid, 0)           # valid, sorted
    tables += struct.pack("<IIII", 1, 1, 3, 5)       # row counts
    # Module row (10 B): gen, name, mvid, encid, encbaseid
    tables += struct.pack("<HHHHH", 0, idx[b"Test.dll"], 0, 0, 0)
    # TypeRef row (6 B): scope(coded), name, namespace
    tables += struct.pack("<HHH", 0, idx[b"Object"], idx[b"System"])
    # TypeDef rows (14 B): flags, name, ns, extends, fields, methods
    for name, ns in ((b"<Module>", None), (b"Foo", b"NS.One"),
                     (b"Bar", b"NS.Two")):
        tables += struct.pack(
            "<IHHHHH", 0, idx[name], idx[ns] if ns else 0, 0, 1, 1)
    # MethodDef rows are never walked; only their count is read.

    # Metadata root.
    version = b"v4.0.30319\x00\x00"                  # 12 bytes, padded
    root = bytearray()
    root += struct.pack("<IHHI", 0x424A5342, 1, 1, 0)
    root += struct.pack("<I", len(version)) + version
    root += struct.pack("<HH", 0, 2)                 # flags, streams
    tables_off = 0  # filled below (relative to root start)
    strings_off = 0
    header_len = len(root) + 2 * 8 + len(b"#~\x00\x00") \
        + len(b"#Strings\x00\x00\x00")
    tables_off = header_len
    strings_off = tables_off + len(tables)
    root += struct.pack("<II", tables_off, len(tables)) + b"#~\x00\x00"
    root += struct.pack("<II", strings_off, len(strings)) \
        + b"#Strings\x00\x00\x00"
    root += tables + strings

    # CLI header (72 bytes) + metadata in one section.
    section_rva = 0x2000
    cli = bytearray(72)
    struct.pack_into("<I", cli, 0, 72)
    struct.pack_into("<II", cli, 8, section_rva + 72, len(root))
    section = bytes(cli) + bytes(root)

    # PE scaffolding: headers in page 1, section raw at 0x200.
    pe = bytearray(0x200)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\x00\x00"
    coff = 0x84
    struct.pack_into("<H", pe, coff + 2, 1)          # 1 section
    struct.pack_into("<H", pe, coff + 16, 0xE0)      # optional hdr size
    opt = coff + 20
    struct.pack_into("<H", pe, opt, 0x10B)           # PE32
    struct.pack_into("<II", pe, opt + 96 + 14 * 8,
                     section_rva, 72)                # CLI directory
    sec = opt + 0xE0
    pe[sec:sec + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", pe, sec + 8, len(section),
                     section_rva, len(section), 0x200)
    path = tmp_path / "Synthetic.dll"
    path.write_bytes(bytes(pe) + section)
    return str(path)


def test_counts_and_namespaces(tmp_path):
    result = count_assembly(build_assembly(tmp_path))
    assert result["types"] == 2          # <Module> excluded
    assert result["methods"] == 5
    assert result["namespaces"] == {"NS.One": 1, "NS.Two": 1}


def test_rejects_non_pe(tmp_path):
    bad = tmp_path / "bad.dll"
    bad.write_bytes(b"not a PE at all")
    try:
        count_assembly(str(bad))
    except DotNetMetaError:
        return
    raise AssertionError("expected DotNetMetaError")
