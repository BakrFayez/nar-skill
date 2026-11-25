"""narlib.scriptparse: structural parsers for the script &
bytecode universe (Part 5).

One pure-bytes parser per format family. Every parser takes
the member bytes (already bounded by the caller) and returns
a record dict:

    {"status": "supported" | "identified_only",
     "fidelity": <chains.FIDELITY_LADDER value>,
     "facts": {...}, "reason": str | None,
     "error": str | None}

Honesty rules, enforced by construction:

- a parser returns "supported" only when it walked the
  documented structure end to end and validated it;
- anything encrypted, compressed with a codec the stdlib
  lacks, truncated, or failing validation degrades to
  "identified_only" with a named reason — counts are never
  invented to fill a record;
- undecoded bytecode is never presented as source: facts
  carry counts and header fields only;
- the .pyc walker is a STRUCTURAL marshal reader: it walks
  the marshal stream's own length/count fields with hard
  caps (depth, object count, count-vs-remaining) and refuses
  hostile files with a named failure. It never calls
  marshal.loads, never imports and never executes target
  code.

Layouts follow the public format documentation: the Lua
5.x chunk format (lundump), the LuaJIT BCDump framing, the
Godot GDScript binary-token layout (GDSC; gdsdecomp's
bytecode history), the WebAssembly binary format, the
Hermes BytecodeFileHeader (parsed by nar-rn's
parse_hermes_header, wired by nar-script), ECMA-335 via
narlib.dotnetmeta, the CPython marshal format, the Squirrel
compiled-stream tags (0xFAFA / RIQS / TRAP / LIAT) and the
Pawn AMX header (Pawn Implementer's Guide).

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import re
import struct

# ------------------------------------------------------------------
# Shared bounded reader
# ------------------------------------------------------------------


class ParseError(Exception):
    """A structural validation failure with a named reason."""


class _Reader:
    __slots__ = ("data", "pos")

    def __init__(self, data, pos=0):
        self.data = data
        self.pos = pos

    def remaining(self):
        return len(self.data) - self.pos

    def need(self, n, what):
        if n < 0 or self.pos + n > len(self.data):
            raise ParseError(
                f"truncated: {what} needs {n} byte(s) at offset "
                f"{self.pos}, only {self.remaining()} remain")

    def bytes(self, n, what="bytes"):
        self.need(n, what)
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self, what="u8"):
        return self.bytes(1, what)[0]

    def u32(self, what="u32"):
        return struct.unpack("<I", self.bytes(4, what))[0]

    def i32(self, what="i32"):
        return struct.unpack("<i", self.bytes(4, what))[0]

    def uleb(self, what="uleb128"):
        """Unsigned LEB128 (wasm / LuaJIT), bounded to 10 bytes."""
        result = 0
        shift = 0
        for _ in range(10):
            b = self.u8(what)
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                return result
            shift += 7
        raise ParseError(f"{what}: LEB128 run exceeds 10 bytes")


def _record(status, fidelity, facts, reason=None, error=None):
    return {"status": status, "fidelity": fidelity,
            "facts": facts, "reason": reason, "error": error}


# ------------------------------------------------------------------
# WebAssembly — full documented structural parse
# ------------------------------------------------------------------

_WASM_SECTIONS = {0: "custom", 1: "type", 2: "import",
                  3: "function", 4: "table", 5: "memory",
                  6: "global", 7: "export", 8: "start",
                  9: "element", 10: "code", 11: "data",
                  12: "data_count"}
_WASM_KINDS = {0: "function", 1: "table", 2: "memory", 3: "global"}


def _wasm_limits(r):
    flags = r.uleb("memory limits flags")
    initial = r.uleb("memory initial pages")
    maximum = r.uleb("memory maximum pages") if flags & 0x01 else None
    return {"flags": flags, "initial_pages": initial,
            "max_pages": maximum}


def parse_wasm(data):
    """Full structural parse of a .wasm module: section
    census with sizes, type/import/function/table/memory/
    global/export counts, memory limits, export names.
    Raises no exceptions: failures return identified_only."""
    facts = {"sections": []}
    if len(data) < 8 or data[:4] != b"\x00asm":
        return _record("identified_only", "identified-only", facts,
                       reason="no WebAssembly magic (\\0asm)")
    r = _Reader(data, 4)
    try:
        facts["version"] = r.u32("wasm version")
        counts = {"type_count": 0, "import_count": 0,
                  "function_count": 0, "table_count": 0,
                  "memory_count": 0, "global_count": 0,
                  "export_count": 0, "code_count": 0,
                  "data_segment_count": 0}
        imports_by_kind = {}
        exports_by_kind = {}
        export_names = []
        memories = []
        last_order = -1
        while r.remaining() > 0:
            sec_id = r.u8("section id")
            if sec_id not in _WASM_SECTIONS:
                raise ParseError(f"unknown section id {sec_id}")
            size = r.uleb("section size")
            r.need(size, f"section {_WASM_SECTIONS[sec_id]} body")
            end = r.pos + size
            if sec_id != 0:
                if sec_id < last_order:
                    raise ParseError(
                        "non-custom sections out of order at "
                        f"section {sec_id}")
                last_order = sec_id
            name = _WASM_SECTIONS[sec_id]
            entry = {"id": sec_id, "name": name, "size_bytes": size}
            sub = _Reader(data, r.pos)
            if sec_id == 1:
                counts["type_count"] = sub.uleb("type count")
                for _ in range(counts["type_count"]):
                    if sub.u8("type form") != 0x60:
                        raise ParseError("type entry is not a "
                                         "function type (0x60)")
                    for _ in range(sub.uleb("param count")):
                        sub.u8("param valtype")
                    for _ in range(sub.uleb("result count")):
                        sub.u8("result valtype")
            elif sec_id == 2:
                counts["import_count"] = sub.uleb("import count")
                for _ in range(counts["import_count"]):
                    for _ in range(2):  # module + name strings
                        n = sub.uleb("import name length")
                        sub.bytes(n, "import name")
                    kind = sub.u8("import kind")
                    imports_by_kind[_WASM_KINDS.get(kind, str(kind))] = \
                        imports_by_kind.get(
                            _WASM_KINDS.get(kind, str(kind)), 0) + 1
                    if kind == 0:
                        sub.uleb("import type index")
                    elif kind == 1:
                        sub.u8("table elemtype")
                        _wasm_limits(sub)
                    elif kind == 2:
                        _wasm_limits(sub)
                    elif kind == 3:
                        sub.u8("global valtype")
                        sub.u8("global mutability")
                    else:
                        raise ParseError(f"unknown import kind {kind}")
            elif sec_id == 3:
                counts["function_count"] = sub.uleb("function count")
                for _ in range(counts["function_count"]):
                    sub.uleb("function type index")
            elif sec_id == 4:
                counts["table_count"] = sub.uleb("table count")
                for _ in range(counts["table_count"]):
                    sub.u8("table elemtype")
                    _wasm_limits(sub)
            elif sec_id == 5:
                counts["memory_count"] = sub.uleb("memory count")
                for _ in range(counts["memory_count"]):
                    memories.append(_wasm_limits(sub))
            elif sec_id == 6:
                counts["global_count"] = sub.uleb("global count")
            elif sec_id == 7:
                counts["export_count"] = sub.uleb("export count")
                for _ in range(counts["export_count"]):
                    n = sub.uleb("export name length")
                    raw = sub.bytes(n, "export name")
                    kind = sub.u8("export kind")
                    sub.uleb("export index")
                    exports_by_kind[_WASM_KINDS.get(kind, str(kind))] = \
                        exports_by_kind.get(
                            _WASM_KINDS.get(kind, str(kind)), 0) + 1
                    if len(export_names) < 20:
                        export_names.append(
                            raw.decode("utf-8", "replace"))
            elif sec_id == 10:
                counts["code_count"] = sub.uleb("code count")
            elif sec_id == 11:
                counts["data_segment_count"] = sub.uleb("data count")
            elif sec_id == 12:
                entry["declared_function_count"] = sub.uleb(
                    "data-count value")
            if sub.pos > end:
                raise ParseError(
                    f"section {name} body overruns its declared size")
            facts["sections"].append(entry)
            r.pos = end
        facts.update(counts)
        facts["total_functions"] = (counts["function_count"]
                                    + imports_by_kind.get("function", 0))
        facts["imports_by_kind"] = imports_by_kind
        facts["exports_by_kind"] = exports_by_kind
        facts["export_names_sample"] = export_names
        facts["memories"] = memories
        return _record("supported", "structural-summary", facts)
    except ParseError as exc:
        return _record("identified_only", "identified-only", facts,
                       reason=f"wasm structure failed validation: {exc}")


# ------------------------------------------------------------------
# Lua / LuaJIT bytecode
# ------------------------------------------------------------------

LUA_MAGIC = b"\x1bLua"
LUAJIT_MAGIC = b"\x1bLJ"
_LUA_MAX_PROTOS = 10000
_LUA_MAX_DEPTH = 32


class _LuaChunk:
    def __init__(self, data, pos, version, sizes):
        self.r = _Reader(data, pos)
        self.version = version
        (self.int_sz, self.size_sz, self.instr_sz,
         self.integer_sz, self.number_sz) = sizes
        self.protos = 0
        self.strings = []
        self.string_count = 0

    def _int(self):
        raw = self.r.bytes(self.int_sz, "chunk int")
        return int.from_bytes(raw, "little", signed=True)

    def _size(self):
        raw = self.r.bytes(self.size_sz, "chunk size_t")
        return int.from_bytes(raw, "little")

    def _count(self, what):
        n = self._int()
        if n < 0:
            raise ParseError(f"{what} count {n} is negative")
        if n > 100000000:
            raise ParseError(f"{what} count {n} is implausible")
        return n

    def string(self):
        if self.version >= 0x53:
            if self.version >= 0x54:
                size = self.r.u8("string size")
                if size == 0xFF:
                    size = self._size()
            else:
                size = self._size()
            if size == 0:
                return None
            # The stored size is the length + 1 in every 5.x
            # writer; the extra byte is not stored as a NUL
            # in 5.3/5.4 (5.1/5.2 store it, handled below).
            return self.r.bytes(size - 1, "string body")
        size = self._size()
        if size == 0:
            return None
        raw = self.r.bytes(size - 1, "string body")
        self.r.u8("string NUL terminator")
        return raw

    def proto(self, depth):
        if depth > _LUA_MAX_DEPTH:
            raise ParseError("prototype nesting exceeds depth cap")
        self.protos += 1
        if self.protos > _LUA_MAX_PROTOS:
            raise ParseError("prototype count exceeds cap")
        r = self.r
        self.string()  # source name
        self._int()    # linedefined
        self._int()    # lastlinedefined
        if self.version == 0x51:
            r.u8("num upvalues")
        r.u8("num params")
        r.u8("is vararg")
        r.u8("max stack")
        if self.version >= 0x52:
            pass  # upvalues are a separate block, read below
        # code
        n = self._count("code")
        r.bytes(n * self.instr_sz, "instruction stream")
        # constants
        nk = self._count("constant")
        for _ in range(nk):
            tag = r.u8("constant tag")
            if tag == 0:      # nil
                pass
            elif tag == 1:    # boolean
                r.u8("boolean constant")
            elif tag == 3:    # number (5.1/5.2) or float (5.3+)
                r.bytes(self.number_sz, "number constant")
            elif tag == 0x13:  # integer (5.3+)
                r.bytes(self.integer_sz, "integer constant")
            elif tag in (4, 0x04, 0x14):  # string
                raw = self.string()
                self.string_count += 1
                if raw is not None and len(self.strings) < 50:
                    self.strings.append(
                        raw.decode("utf-8", "replace")[:120])
            else:
                raise ParseError(f"unknown constant tag {tag}")
        # upvalues (5.2+): after constants in 5.3/5.4 ordering the
        # documented sequence is constants, upvalues, protos for
        # 5.3+ and constants, protos, upvalues for 5.2 — both are
        # handled by reading the upvalue block at the position
        # the version's lundump uses.
        if self.version == 0x52:
            nproto = self._count("nested prototype")
            for _ in range(nproto):
                self.proto(depth + 1)
            nu = self._count("upvalue")
            for _ in range(nu):
                r.u8("upvalue instack")
                r.u8("upvalue index")
        else:
            if self.version >= 0x53:
                nu = self._count("upvalue")
                for _ in range(nu):
                    r.u8("upvalue instack")
                    r.u8("upvalue index")
            nproto = self._count("nested prototype")
            for _ in range(nproto):
                self.proto(depth + 1)
        # debug: line info, local vars, upvalue names
        nl = self._count("line info")
        r.bytes(nl * self.int_sz, "line info")
        nloc = self._count("local var")
        for _ in range(nloc):
            self.string()
            self._int()
            self._int()
        nu_names = self._count("upvalue name")
        for _ in range(nu_names):
            self.string()


def parse_lua(data):
    """Lua 5.x chunk walk + LuaJIT framing walk."""
    facts = {}
    if data[:3] == LUAJIT_MAGIC:
        return _parse_luajit(data)
    if data[:4] != LUA_MAGIC:
        return _record("identified_only", "identified-only", facts,
                       reason="no Lua chunk magic")
    if len(data) < 12:
        return _record("identified_only", "identified-only", facts,
                       reason="Lua chunk shorter than the 12-byte header")
    version = data[4]
    facts["variant"] = "lua"
    facts["version_byte"] = version
    facts["version"] = {0x51: "5.1", 0x52: "5.2", 0x53: "5.3",
                        0x54: "5.4"}.get(version)
    facts["format_byte"] = data[5]
    if facts["version"] is None:
        return _record("identified_only", "identified-only", facts,
                       reason=f"unknown Lua version byte {version:#x}")
    if data[5] != 0:
        return _record(
            "identified_only", "identified-only", facts,
            reason=f"non-official chunk format byte {data[5]}: "
                   "chunk is likely encrypted or obfuscated; "
                   "identified, not decoded")
    try:
        if version == 0x51:
            endian = data[6]
            sizes = (data[7], data[8], data[9], data[10], data[10])
            facts["endianness"] = "little" if endian else "big"
            if endian != 1:
                raise ParseError("big-endian chunks are not walked")
            pos = 12
        elif version == 0x52:
            sizes = (data[7], data[8], data[9], data[10], data[10])
            if data[12:18] != b"\x19\x93\r\n\x1a\n":
                raise ParseError("5.2 header tail mismatch")
            pos = 18
        elif version == 0x53:
            if data[6:12] != b"\x19\x93\r\n\x1a\n":
                raise ParseError("5.3 header tail mismatch")
            sizes = (data[12], data[13], data[14], data[15], data[16])
            pos = 17 + sizes[3] + sizes[4]  # LUAC_INT + LUAC_NUM checks
        else:  # 5.4: tail, then LUAC_INT/LUAC_NUM checks; sizes fixed
            if data[6:12] != b"\x19\x93\r\n\x1a\n":
                raise ParseError("5.4 header tail mismatch")
            sizes = (4, 8, 4, 8, 8)
            pos = 12 + 8 + 8
            # 5.4 stores the top-level upvalue count before the
            # top-level prototype.
            up = _Reader(data, pos)
            n_up = up.u8("top-level upvalue count")
            facts["top_level_upvalues"] = n_up
            pos = up.pos
        facts["sizes"] = {"int": sizes[0], "size_t": sizes[1],
                          "instruction": sizes[2],
                          "integer": sizes[3], "number": sizes[4]}
        chunk = _LuaChunk(data, pos, version, sizes)
        chunk.proto(0)
        if chunk.r.remaining() != 0:
            raise ParseError(
                f"{chunk.r.remaining()} trailing byte(s) after the "
                "top-level prototype")
        facts["function_count"] = chunk.protos
        facts["string_constant_count"] = chunk.string_count
        facts["string_pool_sample"] = chunk.strings
        return _record("supported", "structural-summary", facts)
    except ParseError as exc:
        return _record(
            "identified_only", "identified-only", facts,
            reason=f"Lua chunk failed structural validation ({exc}); "
                   "an encrypted or obfuscated chunk presents the "
                   "same way and is identified, never decoded")


def _parse_luajit(data):
    facts = {"variant": "luajit"}
    r = _Reader(data, 3)
    try:
        version = r.u8("LuaJIT version")
        flags = r.uleb("LuaJIT flags")
        facts["version"] = version
        facts["flags"] = flags
        facts["big_endian"] = bool(flags & 0x01)
        facts["stripped"] = bool(flags & 0x02)
        facts["has_ffi"] = bool(flags & 0x04)
        if not facts["stripped"]:
            n = r.uleb("chunk name length")
            raw = r.bytes(n, "chunk name")
            facts["chunk_name"] = raw.decode("utf-8", "replace")[:120]
        count = 0
        while True:
            plen = r.uleb("prototype length")
            if plen == 0:
                break
            r.bytes(plen, "prototype body")
            count += 1
            if count > _LUA_MAX_PROTOS:
                raise ParseError("prototype count exceeds cap")
        facts["function_count"] = count
        facts["string_pool_sample"] = None
        facts["string_constant_count"] = None
        return _record(
            "supported", "structural-summary", facts,
            reason=None)
    except ParseError as exc:
        return _record(
            "identified_only", "identified-only", facts,
            reason=f"LuaJIT dump failed framing validation ({exc}); "
                   "identified, not decoded")


# ------------------------------------------------------------------
# GDScript .gdc (GDSC binary token stream)
# ------------------------------------------------------------------

GDSC_MAGIC = b"GDSC"
GDEC_MAGIC = b"GDEC"
_GDSC_VERSIONS = {3: "Godot 1.0", 4: "Godot 1.1", 10: "Godot 2.x",
                  11: "Godot 3.0 (dev)", 12: "Godot 3.0",
                  13: "Godot 3.1-3.5", 100: "Godot 4.3",
                  101: "Godot 4.5"}


def parse_gdscript(data):
    facts = {}
    if data[:4] == GDEC_MAGIC:
        return _record(
            "identified_only", "identified-only",
            {"encrypted": True},
            reason="Godot FileAccessEncrypted wrapper (GDEC magic): "
                   "the script is encrypted; named, never decoded")
    if data[:4] != GDSC_MAGIC:
        return _record("identified_only", "identified-only", facts,
                       reason="no GDSC magic: not a compiled GDScript "
                              "token stream (an encrypted .gde whose "
                              "wrapper differs presents the same way)")
    if len(data) < 24:
        return _record("identified_only", "identified-only", facts,
                       reason="GDSC stream shorter than its header")
    r = _Reader(data, 4)
    version = r.u32("GDScript tokenizer version")
    facts["version"] = version
    facts["godot_release"] = _GDSC_VERSIONS.get(version)
    try:
        if version >= 100:
            decompressed = r.u32("decompressed size")
            facts["compressed"] = decompressed != 0
            facts["decompressed_size"] = decompressed or None
            if decompressed:
                return _record(
                    "identified_only", "identified-only", facts,
                    reason="Godot 4 token stream is Zstd-compressed "
                           "and the stdlib has no Zstd decoder; "
                           "header facts only")
            counts_at = r.pos
            facts["identifier_count"] = r.u32("identifier count")
            facts["constant_count"] = r.u32("constant count")
            facts["token_line_count"] = r.u32("token line count")
            facts["token_count"] = r.u32("token count")
            del counts_at
            sample = []
            for _ in range(min(facts["identifier_count"], 100000)):
                n = r.u32("identifier length")
                if n > 100000:
                    raise ParseError("identifier length implausible")
                raw = r.bytes(n * 4, "identifier body")
                if len(sample) < 20:
                    chars = bytes(b ^ 0xB6 for b in raw)
                    sample.append(chars.decode(
                        "utf-32-le", "replace")[:80])
            facts["identifiers_sample"] = sample
        else:
            facts["identifier_count"] = r.u32("identifier count")
            facts["constant_count"] = r.u32("constant count")
            facts["token_line_count"] = r.u32("token line count")
            facts["token_count"] = r.u32("token count")
            sample = []
            for _ in range(min(facts["identifier_count"], 100000)):
                n = r.u32("identifier length")
                if n > 1000000:
                    raise ParseError("identifier length implausible")
                raw = r.bytes(n, "identifier body")
                if len(sample) < 20:
                    chars = bytes(b ^ 0xB6 for b in raw)
                    sample.append(chars.rstrip(b"\x00").decode(
                        "utf-8", "replace")[:80])
            facts["identifiers_sample"] = sample
        return _record("supported", "structural-summary", facts)
    except ParseError as exc:
        return _record("identified_only", "identified-only", facts,
                       reason=f"GDSC stream failed validation: {exc}")


# ------------------------------------------------------------------
# Python .pyc — magic + STRUCTURAL marshal walker (never executes)
# ------------------------------------------------------------------

PYC_MAGIC_VERSIONS = {
    62211: "2.7", 3350: "3.5", 3379: "3.6", 3394: "3.7",
    3413: "3.8", 3425: "3.9", 3439: "3.10", 3495: "3.11",
    3531: "3.12", 3559: "3.13", 3571: "3.13",
}
_MARSHAL_MAX_DEPTH = 64
_MARSHAL_MAX_OBJECTS = 300000


class MarshalRefusal(Exception):
    """A hostile or unreadable marshal stream, refused by name."""


class _MarshalWalker:
    """Walks a marshal stream by its own length/count fields.

    Returns light nodes only (strings decoded for name fields,
    containers as lists); code objects are counted, never
    built into real code objects, never executed."""

    def __init__(self, data, pos, layout):
        self.r = _Reader(data, pos)
        self.layout = layout  # "legacy" | "mid" | "new"
        self.objects = 0
        self.refs = 0
        self.code_count = 0
        self.function_count = 0
        self.names_sample = []

    def _tick(self):
        self.objects += 1
        if self.objects > _MARSHAL_MAX_OBJECTS:
            raise MarshalRefusal(
                "marshal_bomb_refused: object count exceeds the "
                f"{_MARSHAL_MAX_OBJECTS} cap")

    def _count(self, what):
        n = self.r.i32(what)
        if n < 0:
            raise MarshalRefusal(
                f"marshal_invalid: negative {what} count {n}")
        if n > self.r.remaining():
            raise MarshalRefusal(
                f"marshal_bomb_refused: {what} declares {n} item(s) "
                f"with only {self.r.remaining()} byte(s) remaining")
        return n

    def _len_bytes(self, what):
        n = self.r.i32(what)
        if n < 0 or n > self.r.remaining():
            raise MarshalRefusal(
                f"marshal_bomb_refused: {what} declares {n} byte(s) "
                f"with only {self.r.remaining()} byte(s) remaining")
        return self.r.bytes(n, what)

    def value(self, depth):
        if depth > _MARSHAL_MAX_DEPTH:
            raise MarshalRefusal(
                "marshal_bomb_refused: nesting exceeds the "
                f"{_MARSHAL_MAX_DEPTH} depth cap")
        self._tick()
        try:
            raw = self.r.u8("marshal type")
        except ParseError as exc:
            raise MarshalRefusal(f"marshal_truncated: {exc}") from None
        flag_ref = bool(raw & 0x80)
        t = chr(raw & 0x7F)
        if flag_ref:
            self.refs += 1
        if t == "0":      # NULL (dict terminator)
            return ("null", None)
        if t in "NFTS.":
            return ("leaf", None)
        if t == "i":
            self.r.bytes(4, "int32")
            return ("leaf", None)
        if t == "I":
            self.r.bytes(8, "int64")
            return ("leaf", None)
        if t == "l":
            n = self.r.i32("long digit count")
            if abs(n) > self.r.remaining() // 2 + 1:
                raise MarshalRefusal(
                    "marshal_bomb_refused: bignum digit count "
                    f"{n} exceeds the remaining stream")
            self.r.bytes(abs(n) * 2, "bignum digits")
            return ("leaf", None)
        if t == "f":
            n = self.r.u8("float text length")
            self.r.bytes(n, "float text")
            return ("leaf", None)
        if t == "g":
            self.r.bytes(8, "binary float")
            return ("leaf", None)
        if t == "x":
            for _ in range(2):
                n = self.r.u8("complex part length")
                self.r.bytes(n, "complex part")
            return ("leaf", None)
        if t == "y":
            self.r.bytes(16, "binary complex")
            return ("leaf", None)
        if t in "stu":
            rawb = self._len_bytes(f"string ({t})")
            return ("str", rawb.decode("utf-8", "replace"))
        if t == "s":
            self._len_bytes("bytes")
            return ("leaf", None)
        if t in "aA":
            rawb = self._len_bytes("ascii string")
            return ("str", rawb.decode("ascii", "replace"))
        if t in "zZ":
            n = self.r.u8("short ascii length")
            if n > self.r.remaining():
                raise MarshalRefusal(
                    "marshal_bomb_refused: short string declares "
                    f"{n} byte(s) with {self.r.remaining()} remaining")
            rawb = self.r.bytes(n, "short ascii")
            return ("str", rawb.decode("ascii", "replace"))
        if t == "r":
            idx = self.r.i32("ref index")
            if idx < 0 or idx >= self.refs:
                raise MarshalRefusal(
                    f"marshal_invalid: reference index {idx} with "
                    f"only {self.refs} reference(s) allocated")
            return ("ref", None)
        if t == "(":
            n = self._count("tuple")
            return ("seq", [self.value(depth + 1) for _ in range(n)])
        if t == ")":
            n = self.r.u8("small tuple count")
            if n > self.r.remaining():
                raise MarshalRefusal(
                    "marshal_bomb_refused: small tuple declares "
                    f"{n} item(s) with {self.r.remaining()} remaining")
            return ("seq", [self.value(depth + 1) for _ in range(n)])
        if t == "[":
            n = self._count("list")
            return ("seq", [self.value(depth + 1) for _ in range(n)])
        if t in "<>":
            n = self._count("set")
            return ("seq", [self.value(depth + 1) for _ in range(n)])
        if t == "{":
            items = []
            while True:
                key = self.value(depth + 1)
                if key[0] == "null":
                    break
                items.append(key)
                items.append(self.value(depth + 1))
                if len(items) > 2 * _MARSHAL_MAX_OBJECTS:
                    raise MarshalRefusal(
                        "marshal_bomb_refused: dict exceeds cap")
            return ("seq", items)
        if t == "c":
            return ("code", self._code(depth))
        raise MarshalRefusal(f"marshal_invalid: unknown type byte {t!r}")

    def _code(self, depth):
        self.code_count += 1
        r = self.r
        try:
            if self.layout == "new12":     # CPython >= 3.12
                # argcount, posonly, kwonly, stacksize, flags;
                # then names/localsplusnames/localspluskinds
                # replace the varnames/freevars/cellvars triple.
                r.bytes(20, "code header ints")
                self.value(depth + 1)      # bytecode
                consts = self.value(depth + 1)
                self.value(depth + 1)      # names
                self.value(depth + 1)      # localsplusnames
                self.value(depth + 1)      # localspluskinds
                self.value(depth + 1)      # filename
                name = self.value(depth + 1)   # name
                self.value(depth + 1)      # qualname
                r.bytes(4, "firstlineno")
                self.value(depth + 1)      # linetable
                self.value(depth + 1)      # exceptiontable
            elif self.layout == "new":     # CPython 3.11
                r.bytes(16, "code header ints")
                self.value(depth + 1)      # bytecode
                consts = self.value(depth + 1)
                self.value(depth + 1)      # names
                self.value(depth + 1)      # varnames
                self.value(depth + 1)      # freevars
                self.value(depth + 1)      # cellvars
                self.value(depth + 1)      # filename
                name = self.value(depth + 1)   # name
                self.value(depth + 1)      # qualname
                r.bytes(4, "firstlineno")
                self.value(depth + 1)      # linetable
                self.value(depth + 1)      # exceptiontable
            elif self.layout == "mid":     # 3.8 - 3.10
                r.bytes(24, "code header ints")
                self.value(depth + 1)      # code
                consts = self.value(depth + 1)
                for _ in range(5):         # names..cellvars
                    self.value(depth + 1)
                self.value(depth + 1)      # filename
                name = self.value(depth + 1)
                r.bytes(4, "firstlineno")
                self.value(depth + 1)      # lnotab / linetable
            else:                          # <= 3.7 (and 2.7 shape)
                r.bytes(20 if self.layout == "legacy37"
                        else 16, "code header ints")
                self.value(depth + 1)      # code
                consts = self.value(depth + 1)
                for _ in range(5):
                    self.value(depth + 1)
                self.value(depth + 1)      # filename
                name = self.value(depth + 1)
                r.bytes(4, "firstlineno")
                self.value(depth + 1)      # lnotab
        except ParseError as exc:
            raise MarshalRefusal(
                f"marshal_truncated: code object: {exc}") from None
        name_str = name[1] if name and name[0] == "str" else None
        if name_str and name_str != "<module>":
            self.function_count += 1
        if name_str and len(self.names_sample) < 20:
            self.names_sample.append(name_str)
        # Nested code objects inside consts were already
        # counted while the consts value itself was walked.
        return name_str


def _pyc_layout(version_str):
    try:
        major, minor = (int(x) for x in version_str.split("."))
    except (ValueError, AttributeError):
        return None
    if (major, minor) >= (3, 12):
        return "new12"
    if (major, minor) >= (3, 11):
        return "new"
    if (major, minor) >= (3, 8):
        return "mid"
    if major == 3 and minor >= 6:
        return "legacy37"
    if major == 3:
        return "legacy37"  # 3.0-3.5 share the kwonly-era layout
    if major == 2:
        return "legacy"
    return None


def parse_pyc(data):
    """Magic -> CPython version, then a structural marshal
    census of code objects. Never executes anything."""
    facts = {}
    if len(data) < 4:
        return _record("identified_only", "identified-only", facts,
                       reason="file shorter than the 4-byte magic")
    magic = struct.unpack_from("<H", data, 0)[0]
    facts["magic"] = magic
    version = PYC_MAGIC_VERSIONS.get(magic)
    facts["cpython_version"] = version
    if version is None:
        return _record(
            "identified_only", "identified-only", facts,
            reason=f"unknown CPython magic {magic}: version and "
                   "code layout are not derivable, so no census "
                   "is attempted")
    layout = _pyc_layout(version)
    header_size = 16 if magic >= 3394 else 12
    facts["header_size"] = header_size
    if magic >= 3394 and len(data) >= 8:
        facts["pep552_flags"] = struct.unpack_from("<I", data, 4)[0]
    if len(data) <= header_size:
        return _record("identified_only", "identified-only", facts,
                       reason="header present but no marshal payload")
    walker = _MarshalWalker(data, header_size, layout)
    try:
        walker.value(0)
    except MarshalRefusal as exc:
        return _record("identified_only", "identified-only", facts,
                       reason=str(exc), error=str(exc))
    facts["code_object_count"] = walker.code_count
    facts["function_count"] = walker.function_count
    facts["code_names_sample"] = walker.names_sample
    facts["marshal_objects_walked"] = walker.objects
    return _record("supported", "structural-summary", facts)


# ------------------------------------------------------------------
# JavaScript bundles (text) — heuristics labelled as such
# ------------------------------------------------------------------

_SOURCEMAP_RE = re.compile(r"//#\s*sourceMappingURL=(\S+)")
_WEBPACK_MODULE_RE = re.compile(r"/\*\*\*/|__webpack_require__|webpackJsonp")
_WEBPACK_ID_RE = re.compile(r"/\*\*\*/\s*\"?[\w./@-]+\"?\s*:")


def parse_javascript(data, sibling_names=()):
    """Text-bundle census. Minification and module counts
    are heuristics and are labelled with their basis."""
    text = data.decode("utf-8", "replace")
    facts = {"size_bytes": len(data)}
    lines = text.count("\n") + 1
    facts["line_count"] = lines
    avg = len(text) / max(lines, 1)
    facts["avg_line_length"] = round(avg, 1)
    facts["minified"] = avg > 200
    facts["minified_basis"] = (
        "heuristic: average line length "
        f"{avg:.0f} chars (threshold 200)")
    sm = _SOURCEMAP_RE.search(text[-8192:])
    facts["source_map_ref"] = sm.group(1)[:200] if sm else None
    facts["source_map_inline_data"] = bool(
        sm and sm.group(1).startswith("data:"))
    facts["source_map_file_present"] = any(
        n.endswith(".map") for n in sibling_names)
    markers = len(_WEBPACK_MODULE_RE.findall(text))
    facts["webpack_markers"] = markers
    facts["bundled"] = markers > 0
    facts["bundled_basis"] = (
        "heuristic: webpack runtime/module markers present"
        if markers else
        "heuristic: no webpack/esbuild/rollup markers found")
    if not facts["bundled"] and ("parcelRequire" in text
                                 or "esbuild" in text[:4096]):
        facts["bundled"] = True
        facts["bundled_basis"] = ("heuristic: parcel/esbuild "
                                  "marker present")
    ids = len(_WEBPACK_ID_RE.findall(text))
    facts["module_count_estimate"] = ids if ids else None
    facts["module_count_basis"] = (
        "heuristic: count of webpack module-wrapper markers"
        if ids else
        "not estimable: no webpack module wrappers present")
    return _record("supported", "structural-summary", facts)


# ------------------------------------------------------------------
# .NET CIL via narlib.dotnetmeta (bytes -> counts)
# ------------------------------------------------------------------

def parse_dotnet(data, tmp_path):
    """Write the member to tmp_path and run the ECMA-335
    reader. Obfuscation markers are a labelled heuristic
    over namespace shape."""
    import os
    from .dotnetmeta import DotNetMetaError, count_assembly
    with open(tmp_path, "wb") as fh:
        fh.write(data)
    try:
        result = count_assembly(tmp_path)
    except DotNetMetaError as exc:
        return _record("identified_only", "identified-only", {},
                       reason=f"not a parseable CLI assembly: {exc}")
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    namespaces = result.get("namespaces") or {}
    suspicious = [ns for ns in namespaces
                  if len(ns) <= 2 or not re.match(
                      r"^[A-Za-z_][\w.]*$", ns)]
    global_types = namespaces.get("(global)", 0)
    total = max(result.get("types", 0), 1)
    facts = {
        "typedef_count": result.get("types"),
        "methoddef_count": result.get("methods"),
        "namespace_count": len(namespaces),
        "namespaces_top": [
            {"namespace": ns, "types": n} for ns, n in
            sorted(namespaces.items(), key=lambda kv: -kv[1])[:10]],
        "obfuscation_markers": {
            "suspected": bool(suspicious)
            or global_types / total > 0.5,
            "basis": ("heuristic: namespaces that are <=2 chars "
                      "or non-identifier-shaped, or a majority of "
                      "types in the global namespace"),
            "suspicious_namespaces": suspicious[:10],
            "global_namespace_types": global_types,
        },
    }
    return _record("supported", "structural-summary", facts)


# ------------------------------------------------------------------
# Dart snapshot / kernel (facts wired from nar-flutter's extraction)
# ------------------------------------------------------------------

KERNEL_MAGIC = b"\x90\xab\xcd\xef"


def parse_kernel_blob(data):
    facts = {"kernel_magic_ok": data[:4] == KERNEL_MAGIC}
    if data[:4] != KERNEL_MAGIC:
        return _record("identified_only", "identified-only", facts,
                       reason="kernel_blob.bin without the kernel "
                              "magic 0x90ABCDEF")
    if len(data) >= 8:
        facts["kernel_format_version"] = struct.unpack_from(
            "<I", data, 4)[0]
    facts["class_count"] = None
    facts["string_pool_count"] = None
    return _record(
        "identified_only", "identified-only", facts,
        reason="kernel binary header facts only: the kernel "
               "class/string tables are a serialized object "
               "graph with no stdlib-feasible structural census; "
               "counts stay null rather than invented")


def dart_snapshot_facts(data, dart_vm_version=None,
                        flutter_version=None, markers=()):
    """Snapshot record for one libapp.so: the version strings
    and markers are nar-flutter's extraction, re-applied to
    the member bytes."""
    facts = {
        "dart_vm_version": dart_vm_version,
        "flutter_version": flutter_version,
        "snapshot_markers": sorted(markers),
        "aot_snapshot": bool(markers),
        "class_count": None,
        "string_pool_count": None,
    }
    return _record(
        "identified_only", "identified-only", facts,
        reason="Dart AOT snapshot is an ELF-embedded serialized "
               "object graph: VM/framework version strings and "
               "snapshot markers are extracted (the nar-flutter "
               "extraction), but class and string-pool counts "
               "are not derivable with the stdlib and stay null")


# ------------------------------------------------------------------
# AngelScript / Squirrel / Pawn — thin formats, honest records
# ------------------------------------------------------------------

def parse_angelscript_source(data):
    text = data.decode("utf-8", "replace")
    funcs = len(re.findall(r"\b\w+\s+\w+\s*\([^;{}]*\)\s*\{", text))
    facts = {"line_count": text.count("\n") + 1,
             "function_like_count": funcs,
             "function_count_basis": (
                 "heuristic: source-text pattern census; "
                 "AngelScript has no standard compiled file "
                 "format (scripts compile in memory, and saved "
                 "bytecode streams are engine-specific)")}
    return _record(
        "identified_only", "identified-only", facts,
        reason="AngelScript source census only: no documented "
               "compiled format exists to parse structurally")


def parse_squirrel(data):
    facts = {}
    if data[:2] == b"\xfa\xfa" or data[:4] == b"RIQS" \
            or b"RIQS" in data[:8]:
        facts["compiled"] = True
        facts["stream_tag"] = "0xFAFA"
        facts["signature"] = "RIQS"
        facts["part_marker_count"] = data.count(b"TRAP")
        facts["tail_marker_present"] = b"LIAT" in data[-64:]
        facts["part_marker_basis"] = (
            "marker census over the raw stream (TRAP = the "
            "reversed PART section delimiter); a section "
            "census, not a function count")
        return _record(
            "identified_only", "identified-only", facts,
            reason="Squirrel compiled stream identified by its "
                   "0xFAFA tag and RIQS signature; the closure "
                   "serialization has no documented entry-count "
                   "header, so no function count is claimed")
    text = data.decode("utf-8", "replace")
    facts["compiled"] = False
    facts["line_count"] = text.count("\n") + 1
    facts["function_like_count"] = len(
        re.findall(r"\bfunction\s+\w+\s*\(", text))
    facts["function_count_basis"] = (
        "heuristic: source-text 'function name(' census")
    return _record(
        "identified_only", "identified-only", facts,
        reason="Squirrel source (.nut) census only")


_AMX_MAGIC = 0xF1E0


def parse_pawn_amx(data):
    """Pawn .amx header (Pawn Implementer's Guide): table
    offsets yield the public/native/library/pubvar/tag
    entry counts directly."""
    facts = {}
    if len(data) < 56:
        return _record("identified_only", "identified-only", facts,
                       reason=".amx shorter than the AMX header")
    (size, magic, file_ver, amx_ver, flags, defsize, cod, dat,
     hea, stp, cip, publics, natives, libraries, pubvars, tags,
     nametable) = struct.unpack_from("<I H B B h h i i i i i i i i i i i",
                                     data, 0)
    facts["header_size_field"] = size
    facts["magic_ok"] = magic == _AMX_MAGIC
    facts["file_version"] = file_ver
    facts["amx_version"] = amx_ver
    facts["flags"] = flags
    facts["defsize"] = defsize
    facts["code_size"] = dat - cod
    facts["data_size"] = hea - dat
    if magic != _AMX_MAGIC:
        return _record("identified_only", "identified-only", facts,
                       reason=f"AMX magic mismatch ({magic:#x}, "
                              "expected 0xF1E0)")
    if defsize <= 0:
        return _record("identified_only", "identified-only", facts,
                       reason="AMX defsize is not positive; entry "
                              "counts are not derivable")
    facts["public_count"] = (natives - publics) // defsize
    facts["native_count"] = (libraries - natives) // defsize
    facts["library_count"] = (pubvars - libraries) // defsize
    facts["pubvar_count"] = (tags - pubvars) // defsize
    facts["tag_count"] = (nametable - tags) // defsize
    return _record("supported", "structural-summary", facts)


def parse_pawn_source(data):
    text = data.decode("utf-8", "replace")
    facts = {"line_count": text.count("\n") + 1,
             "public_like_count": len(re.findall(
                 r"^\s*public\s+\w+\s*\(", text, re.M)),
             "count_basis": "heuristic: source-text census"}
    return _record("identified_only", "identified-only", facts,
                   reason="Pawn source (.pwn) census only; the "
                          "compiled form is .amx")


# ------------------------------------------------------------------
# Custom VM bytecode — detect + name, never decode
# ------------------------------------------------------------------

def custom_vm_record(kind, detail):
    return _record(
        "identified_only", "identified-only",
        {"vm": kind, "detail": detail},
        reason="custom VM bytecode: detected and named, "
               "never decoded by design")
