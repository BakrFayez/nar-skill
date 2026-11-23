"""Minimal ECMA-335 CLI metadata reader (pure Python).

Counts TypeDef and MethodDef rows and reads TypeDef
namespaces from a .NET assembly's #~ tables stream —
enough to summarize dummy assemblies produced by IL2CPP
recovery tools (Cpp2IL's dll output formats) in the same
shape nar-il2cpp uses for Il2CppDumper's dump.cs, without
depending on a .NET runtime just to count.

Only the structures on that path are parsed: PE headers,
the CLI header, the metadata root and stream directory,
the tables header (row counts), and the Module / TypeRef
/ TypeDef rows (the tables preceding and including
TypeDef). Anything malformed raises DotNetMetaError.
"""
import struct

# ECMA-335 table ids on the path this reader walks.
T_MODULE = 0
T_TYPEREF = 1
T_TYPEDEF = 2
T_FIELD = 4
T_METHODDEF = 6
T_MODULEREF = 26
T_TYPESPEC = 27
T_ASSEMBLYREF = 35


class DotNetMetaError(Exception):
    pass


def _u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def _u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def _coded_size(tables, tag_bits, rows):
    """Byte size of a coded index over `tables` given the
    row-count map."""
    max_rows = max((rows.get(t, 0) for t in tables), default=0)
    return 2 if max_rows < (1 << (16 - tag_bits)) else 4


def _simple_size(table, rows):
    return 2 if rows.get(table, 0) < 65536 else 4


class _Tables:
    """Parsed #~ stream: row counts plus the offsets the
    TypeDef walk needs."""

    def __init__(self, data, base, strings):
        self.data = data
        self.strings = strings
        (self.major, self.minor, self.heap_sizes) = (
            data[base + 4], data[base + 5], data[base + 6])
        self.valid = struct.unpack_from("<Q", data, base + 8)[0]
        pos = base + 24
        self.rows = {}
        for t in range(64):
            if self.valid >> t & 1:
                self.rows[t] = _u32(data, pos)
                pos += 4
        self.rows_base = pos
        self.str_size = 4 if self.heap_sizes & 0x01 else 2
        self.guid_size = 4 if self.heap_sizes & 0x02 else 2
        self.blob_size = 4 if self.heap_sizes & 0x04 else 2

    def row_size(self, table):
        rows = self.rows
        s, g, b = self.str_size, self.guid_size, self.blob_size
        if table == T_MODULE:
            return 2 + s + g + g + g
        if table == T_TYPEREF:
            scope = _coded_size(
                [T_MODULE, T_MODULEREF, T_ASSEMBLYREF, T_TYPEREF],
                2, rows)
            return scope + s + s
        if table == T_TYPEDEF:
            extends = _coded_size(
                [T_TYPEREF, T_TYPEDEF, T_TYPESPEC], 2, rows)
            return (4 + s + s + extends
                    + _simple_size(T_FIELD, rows)
                    + _simple_size(T_METHODDEF, rows))
        raise DotNetMetaError(
            f"row size for table {table} not implemented")

    def table_offset(self, table):
        pos = self.rows_base
        for t in range(table):
            if t in self.rows:
                pos += self.rows[t] * self.row_size(t)
        return pos

    def string(self, index):
        if index == 0 or index >= len(self.strings):
            return ""
        end = self.strings.find(b"\x00", index)
        if end < 0:
            end = len(self.strings)
        return self.strings[index:end].decode(
            "utf-8", "replace")


def count_assembly(path):
    """Return {"types", "methods", "namespaces"} for one
    CLI assembly file. `types` excludes the <Module>
    pseudo-type row every assembly carries."""
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:2] != b"MZ":
        raise DotNetMetaError("not a PE file (no MZ header)")
    pe_off = _u32(data, 0x3C)
    if data[pe_off:pe_off + 4] != b"PE\x00\x00":
        raise DotNetMetaError("no PE signature")
    coff = pe_off + 4
    section_count = _u16(data, coff + 2)
    opt_size = _u16(data, coff + 16)
    opt = coff + 20
    magic = _u16(data, opt)
    if magic == 0x10B:
        dd_base = opt + 96
    elif magic == 0x20B:
        dd_base = opt + 112
    else:
        raise DotNetMetaError(f"unknown optional-header magic "
                              f"{magic:#x}")
    cli_rva = _u32(data, dd_base + 14 * 8)
    if cli_rva == 0:
        raise DotNetMetaError("no CLI header (not a .NET assembly)")
    sections = []
    sec_base = opt + opt_size
    for i in range(section_count):
        off = sec_base + i * 40
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from(
            "<IIII", data, off + 8)
        sections.append((vaddr, max(vsize, raw_size), raw_ptr))

    def rva_to_off(rva):
        for vaddr, span, raw_ptr in sections:
            if vaddr <= rva < vaddr + span:
                return raw_ptr + (rva - vaddr)
        raise DotNetMetaError(f"RVA {rva:#x} not in any section")

    cli_off = rva_to_off(cli_rva)
    meta_rva = _u32(data, cli_off + 8)
    meta_off = rva_to_off(meta_rva)
    if _u32(data, meta_off) != 0x424A5342:
        raise DotNetMetaError("bad metadata root signature")
    ver_len = _u32(data, meta_off + 12)
    pos = meta_off + 16 + ((ver_len + 3) & ~3)
    stream_count = _u16(data, pos + 2)
    pos += 4
    streams = {}
    for _ in range(stream_count):
        s_off, s_size = struct.unpack_from("<II", data, pos)
        pos += 8
        end = data.index(b"\x00", pos)
        name = data[pos:end].decode("ascii", "replace")
        pos += ((end - pos + 1) + 3) & ~3
        streams[name] = (meta_off + s_off, s_size)
    if "#~" not in streams:
        raise DotNetMetaError("no #~ tables stream")
    tables_off, _ = streams["#~"]
    strings = b""
    if "#Strings" in streams:
        s_off, s_size = streams["#Strings"]
        strings = data[s_off:s_off + s_size]
    tables = _Tables(data, tables_off, strings)

    type_rows = tables.rows.get(T_TYPEDEF, 0)
    methods = tables.rows.get(T_METHODDEF, 0)
    namespaces = {}
    types = type_rows
    if type_rows:
        base = tables.table_offset(T_TYPEDEF)
        row_size = tables.row_size(T_TYPEDEF)
        s = tables.str_size
        for i in range(type_rows):
            row = base + i * row_size
            name_idx = struct.unpack_from(
                "<I" if s == 4 else "<H", data, row + 4)[0]
            ns_idx = struct.unpack_from(
                "<I" if s == 4 else "<H", data, row + 4 + s)[0]
            name = tables.string(name_idx)
            if i == 0 and name == "<Module>":
                types -= 1
                continue
            ns = tables.string(ns_idx) or "(global)"
            namespaces[ns] = namespaces.get(ns, 0) + 1
    return {"types": types, "methods": methods,
            "namespaces": namespaces}


def summarize_dlls(dll_paths):
    """Aggregate count_assembly over generated DLLs into
    the nar-il2cpp summary shape."""
    import collections
    total_types = 0
    total_methods = 0
    ns_counts = collections.Counter()
    counted = 0
    for path in dll_paths:
        result = count_assembly(path)
        total_types += result["types"]
        total_methods += result["methods"]
        ns_counts.update(result["namespaces"])
        counted += 1
    return {
        "types": total_types,
        "methods": total_methods,
        "top_namespaces": [
            {"namespace": ns, "types": n}
            for ns, n in ns_counts.most_common(10)],
        "assemblies": counted,
    }
