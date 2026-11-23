"""DEX bytecode disassembler for narlib.

Decodes a method's code item into an instruction listing —
code-unit address, opcode mnemonic, and operands with every
reference resolved through the DEX's own tables (string
contents, type names, field and method signatures,
prototypes, call sites, method handles). Written from the
publicly documented DEX bytecode format; consumes the table
primitives in narlib.dex rather than re-parsing them.

Why this exists: nar-dex's structural pass reads what a
method *references* without decoding its instruction stream,
and jadx — the decompiler NAR orchestrates — fails on some
obfuscated or protected methods and leaves them empty. An
instruction listing never "fails to decompile": it is the
ground truth the decompiler approximations are checked
against, and it is available exactly where jadx gives up.

Discipline (the core risk is operand widths — one wrong
width desynchronizes everything after it):

- Widths come from the format table below, which the unit
  tests cross-check against narlib.dex.OP_WIDTH (itself
  proven by the 2.1.0 equivalence work).
- An unknown opcode, an out-of-range reference index, a
  stream that runs past its declared end, or a version-gated
  opcode in an older file marks THAT method's listing as
  failed with the precise reason and code-unit offset. No
  instruction is ever guessed, and one bad method never
  poisons the rest of the file.
- Payload pseudo-instructions (packed-switch, sparse-switch,
  fill-array-data) are consumed in-stream and listed as
  payloads, never mistaken for opcodes; switch and
  fill-array-data targets are cross-checked against the
  payloads actually decoded, with mismatches reported as
  warnings on the listing (the instruction stream itself
  still decoded byte-exactly).

Observed vs inferred: a listing is observed — it is what the
bytes say. What the code *means* remains the reader's work.

Part of NAR (Nirous Android Reversing). Research by
Bakr Fayez. MIT License. See LICENSE in the repo root.
"""
import json
import struct

from .dex import _uleb128

# ------------------------------------------------------------------
# Opcode table: opcode -> (mnemonic, format, reference kind).
# Reference kinds: string, type, field, method, call_site,
# proto, method_handle. Formats follow the documented DEX
# instruction-format naming (10x, 12x, 35c, ...).
OPS = {}


def _def(op, name, fmt, ref=None):
    OPS[op] = (name, fmt, ref)


_def(0x00, "nop", "10x")
_def(0x01, "move", "12x")
_def(0x02, "move/from16", "22x")
_def(0x03, "move/16", "32x")
_def(0x04, "move-wide", "12x")
_def(0x05, "move-wide/from16", "22x")
_def(0x06, "move-wide/16", "32x")
_def(0x07, "move-object", "12x")
_def(0x08, "move-object/from16", "22x")
_def(0x09, "move-object/16", "32x")
_def(0x0A, "move-result", "11x")
_def(0x0B, "move-result-wide", "11x")
_def(0x0C, "move-result-object", "11x")
_def(0x0D, "move-exception", "11x")
_def(0x0E, "return-void", "10x")
_def(0x0F, "return", "11x")
_def(0x10, "return-wide", "11x")
_def(0x11, "return-object", "11x")
_def(0x12, "const/4", "11n")
_def(0x13, "const/16", "21s")
_def(0x14, "const", "31i")
_def(0x15, "const/high16", "21h")
_def(0x16, "const-wide/16", "21s")
_def(0x17, "const-wide/32", "31i")
_def(0x18, "const-wide", "51l")
_def(0x19, "const-wide/high16", "21h")
_def(0x1A, "const-string", "21c", "string")
_def(0x1B, "const-string/jumbo", "31c", "string")
_def(0x1C, "const-class", "21c", "type")
_def(0x1D, "monitor-enter", "11x")
_def(0x1E, "monitor-exit", "11x")
_def(0x1F, "check-cast", "21c", "type")
_def(0x20, "instance-of", "22c", "type")
_def(0x21, "array-length", "12x")
_def(0x22, "new-instance", "21c", "type")
_def(0x23, "new-array", "22c", "type")
_def(0x24, "filled-new-array", "35c", "type")
_def(0x25, "filled-new-array/range", "3rc", "type")
_def(0x26, "fill-array-data", "31t")
_def(0x27, "throw", "11x")
_def(0x28, "goto", "10t")
_def(0x29, "goto/16", "20t")
_def(0x2A, "goto/32", "30t")
_def(0x2B, "packed-switch", "31t")
_def(0x2C, "sparse-switch", "31t")
for _i, _n in enumerate(("cmpl-float", "cmpg-float", "cmpl-double",
                         "cmpg-double", "cmp-long")):
    _def(0x2D + _i, _n, "23x")
for _i, _n in enumerate(("if-eq", "if-ne", "if-lt", "if-ge",
                         "if-gt", "if-le")):
    _def(0x32 + _i, _n, "22t")
for _i, _n in enumerate(("if-eqz", "if-nez", "if-ltz", "if-gez",
                         "if-gtz", "if-lez")):
    _def(0x38 + _i, _n, "21t")
# 0x3E-0x43 are unassigned in the DEX opcode map.
for _i, _n in enumerate((
        "aget", "aget-wide", "aget-object", "aget-boolean",
        "aget-byte", "aget-char", "aget-short",
        "aput", "aput-wide", "aput-object", "aput-boolean",
        "aput-byte", "aput-char", "aput-short")):
    _def(0x44 + _i, _n, "23x")
for _i, _n in enumerate((
        "iget", "iget-wide", "iget-object", "iget-boolean",
        "iget-byte", "iget-char", "iget-short",
        "iput", "iput-wide", "iput-object", "iput-boolean",
        "iput-byte", "iput-char", "iput-short")):
    _def(0x52 + _i, _n, "22c", "field")
for _i, _n in enumerate((
        "sget", "sget-wide", "sget-object", "sget-boolean",
        "sget-byte", "sget-char", "sget-short",
        "sput", "sput-wide", "sput-object", "sput-boolean",
        "sput-byte", "sput-char", "sput-short")):
    _def(0x60 + _i, _n, "21c", "field")
for _i, _n in enumerate(("invoke-virtual", "invoke-super",
                         "invoke-direct", "invoke-static",
                         "invoke-interface")):
    _def(0x6E + _i, _n, "35c", "method")
# 0x73 is unassigned.
for _i, _n in enumerate(("invoke-virtual/range", "invoke-super/range",
                         "invoke-direct/range", "invoke-static/range",
                         "invoke-interface/range")):
    _def(0x74 + _i, _n, "3rc", "method")
# 0x79-0x7A are unassigned.
for _i, _n in enumerate((
        "neg-int", "not-int", "neg-long", "not-long", "neg-float",
        "neg-double", "int-to-long", "int-to-float", "int-to-double",
        "long-to-int", "long-to-float", "long-to-double",
        "float-to-int", "float-to-long", "float-to-double",
        "double-to-int", "double-to-long", "double-to-float",
        "int-to-byte", "int-to-char", "int-to-short")):
    _def(0x7B + _i, _n, "12x")
_BINOP_BASE = []
for _t in ("int", "long"):
    for _v in ("add", "sub", "mul", "div", "rem", "and", "or",
               "xor", "shl", "shr", "ushr"):
        _BINOP_BASE.append(f"{_v}-{_t}")
for _t in ("float", "double"):
    for _v in ("add", "sub", "mul", "div", "rem"):
        _BINOP_BASE.append(f"{_v}-{_t}")
for _i, _n in enumerate(_BINOP_BASE):
    _def(0x90 + _i, _n, "23x")
    _def(0xB0 + _i, _n + "/2addr", "12x")
for _i, _n in enumerate(("add-int/lit16", "rsub-int", "mul-int/lit16",
                         "div-int/lit16", "rem-int/lit16",
                         "and-int/lit16", "or-int/lit16",
                         "xor-int/lit16")):
    _def(0xD0 + _i, _n, "22s")
for _i, _n in enumerate(("add-int/lit8", "rsub-int/lit8",
                         "mul-int/lit8", "div-int/lit8",
                         "rem-int/lit8", "and-int/lit8",
                         "or-int/lit8", "xor-int/lit8",
                         "shl-int/lit8", "shr-int/lit8",
                         "ushr-int/lit8")):
    _def(0xD8 + _i, _n, "22b")
# 0xE3-0xF9 are unassigned in DEX files (the range carries the
# odex "quickened" variants, which never appear in a .dex).
_def(0xFA, "invoke-polymorphic", "45cc", "method")
_def(0xFB, "invoke-polymorphic/range", "4rcc", "method")
_def(0xFC, "invoke-custom", "35c", "call_site")
_def(0xFD, "invoke-custom/range", "3rc", "call_site")
_def(0xFE, "const-method-handle", "21c", "method_handle")
_def(0xFF, "const-method-type", "21c", "proto")

FMT_WIDTH = {
    "10x": 1, "12x": 1, "11n": 1, "11x": 1, "10t": 1,
    "22x": 2, "21t": 2, "22t": 2, "21s": 2, "21h": 2, "21c": 2,
    "23x": 2, "22b": 2, "22s": 2, "22c": 2, "20t": 2,
    "32x": 3, "30t": 3, "31t": 3, "31i": 3, "31c": 3,
    "35c": 3, "3rc": 3,
    "45cc": 4, "4rcc": 4,
    "51l": 5,
}

# Opcodes introduced with DEX 038 (method handles and call
# sites). In an older file they are unassigned, and a stream
# containing one is corrupt, not modern.
VERSION_038_OPS = frozenset((0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF))

HANDLE_TYPES = {
    0x00: "static-put", 0x01: "static-get",
    0x02: "instance-put", 0x03: "instance-get",
    0x04: "invoke-static", 0x05: "invoke-instance",
    0x06: "invoke-constructor", 0x07: "invoke-direct",
    0x08: "invoke-interface",
}
HANDLE_FIELD_KINDS = frozenset((0x00, 0x01, 0x02, 0x03))

# map_list item types for the two tables the DEX header does
# not carry (they are located through the map, per the format).
MAP_TYPE_CALL_SITE_IDS = 0x0007
MAP_TYPE_METHOD_HANDLE_IDS = 0x0008


class _Fail(Exception):
    """One method's stream cannot be decoded faithfully."""

    def __init__(self, reason, offset_units):
        super().__init__(reason)
        self.reason = reason
        self.offset_units = offset_units


def _s8(v):
    return v - 0x100 if v >= 0x80 else v


def _s16(v):
    return v - 0x10000 if v >= 0x8000 else v


def _s32(v):
    return v - 0x100000000 if v >= 0x80000000 else v


def _s64(v):
    return v - 0x10000000000000000 if v >= 0x8000000000000000 else v


def _quote(s):
    return json.dumps(s, ensure_ascii=True)

class _Resolver:
    """Reference resolution through one Dex's tables.

    Every resolution bounds-checks its index against the
    table size and raises _Fail (out-of-range reference)
    instead of returning a placeholder.
    """

    def __init__(self, dex):
        self.dex = dex
        self._strings = dex.strings()
        self._types = dex.types()
        self._map = None
        self._handles = None
        self._call_sites = None

    # -- plain tables -------------------------------------------
    def string(self, idx, addr):
        if idx >= self.dex.string_ids_size:
            raise _Fail(
                f"string index {idx} out of range "
                f"(string_ids_size={self.dex.string_ids_size})",
                addr)
        return self._strings[idx]

    def type(self, idx, addr):
        if idx >= self.dex.type_ids_size:
            raise _Fail(
                f"type index {idx} out of range "
                f"(type_ids_size={self.dex.type_ids_size})",
                addr)
        return self._types[idx]

    def field(self, idx, addr):
        if idx >= self.dex.field_ids_size:
            raise _Fail(
                f"field index {idx} out of range "
                f"(field_ids_size={self.dex.field_ids_size})",
                addr)
        cls, typ, name = self.dex.field_ref(idx)
        return f"{cls}->{name}:{typ}"

    def method(self, idx, addr):
        if idx >= self.dex.method_ids_size:
            raise _Fail(
                f"method index {idx} out of range "
                f"(method_ids_size={self.dex.method_ids_size})",
                addr)
        cls, name, ret, params = self.dex.method_full(idx)
        return f"{cls}->{name}({''.join(params)}){ret}"

    def proto(self, idx, addr):
        if idx >= self.dex.proto_ids_size:
            raise _Fail(
                f"proto index {idx} out of range "
                f"(proto_ids_size={self.dex.proto_ids_size})",
                addr)
        ret, params = self.dex.proto_info(idx)
        return f"({''.join(params)}){ret}"

    # -- map-located tables -------------------------------------
    def _map_items(self):
        """{map type: (size, offset)} from the map_list."""
        if self._map is None:
            self._map = {}
            data = self.dex.data
            if len(data) >= 0x38:
                map_off = struct.unpack_from("<I", data, 0x34)[0]
                if 4 <= map_off and map_off + 4 <= len(data):
                    count = struct.unpack_from(
                        "<I", data, map_off)[0]
                    for i in range(count):
                        base = map_off + 4 + i * 12
                        if base + 12 > len(data):
                            break
                        typ, _u, size, off = struct.unpack_from(
                            "<HHII", data, base)
                        self._map[typ] = (size, off)
        return self._map

    def _handles_table(self):
        if self._handles is None:
            self._handles = []
            items = self._map_items()
            if MAP_TYPE_METHOD_HANDLE_IDS in items:
                size, off = items[MAP_TYPE_METHOD_HANDLE_IDS]
                data = self.dex.data
                for i in range(size):
                    base = off + i * 8
                    if base + 8 > len(data):
                        break
                    htype, _u, ref = struct.unpack_from(
                        "<HHI", data, base)
                    self._handles.append((htype, ref))
        return self._handles

    def method_handle_parts(self, idx, addr):
        handles = self._handles_table()
        if idx >= len(handles):
            raise _Fail(
                f"method-handle index {idx} out of range "
                f"(method_handle_ids_size={len(handles)})",
                addr)
        htype, ref = handles[idx]
        kind = HANDLE_TYPES.get(htype, f"handle-{htype:#04x}")
        if htype in HANDLE_FIELD_KINDS:
            target = self.field(ref, addr)
        else:
            target = self.method(ref, addr)
        return kind, target

    def method_handle(self, idx, addr):
        kind, target = self.method_handle_parts(idx, addr)
        return f"{kind}@{target}"

    # -- encoded values (call sites) ----------------------------
    def _enc_value(self, data, off):
        """Decode one encoded_value. Returns (summary, off)."""
        if off >= len(data):
            raise _Fail("call-site encoded value runs past "
                        "end of file", 0)
        head = data[off]
        off += 1
        vtype, varg = head & 0x1F, head >> 5
        if vtype == 0x1E:  # null
            return "null", off
        if vtype == 0x1F:  # boolean
            return "true" if varg else "false", off
        if vtype == 0x1C:  # array
            size, off = _uleb128(data, off)
            parts = []
            for _ in range(size):
                part, off = self._enc_value(data, off)
                parts.append(part)
            return "[" + ", ".join(parts) + "]", off
        width = varg + 1
        if vtype in (0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B):
            raw = int.from_bytes(data[off:off + width], "little")
            off += width
            if vtype == 0x15:
                return f"proto@{raw}", off
            if vtype == 0x16:
                return f"handle@{raw}", off
            if vtype == 0x17:
                s = self._strings[raw] if raw < len(
                    self._strings) else "?"
                return _quote(s), off
            if vtype == 0x18:
                t = self._types[raw] if raw < len(
                    self._types) else "?"
                return t, off
            if vtype == 0x19:
                if raw < self.dex.field_ids_size:
                    return self.field(raw, 0), off
                return f"field@{raw}", off
            if vtype == 0x1A:
                if raw < self.dex.method_ids_size:
                    return self.method(raw, 0), off
                return f"method@{raw}", off
            if vtype == 0x1B:  # enum: field id
                if raw < self.dex.field_ids_size:
                    return self.field(raw, 0), off
                return f"enum@{raw}", off
        if vtype in (0x00, 0x02, 0x03, 0x04, 0x06,
                     0x10, 0x11):
            raw = data[off:off + width]
            off += width
            val = int.from_bytes(raw, "little", signed=True)
            if vtype == 0x03:
                return f"'{chr(val)}'" if 0 <= val < 128 else \
                    f"char#{val}", off
            return str(val), off
        return f"value-type#{vtype:#04x}", off

    def call_site(self, idx, addr):
        """Resolve a call-site id to its bootstrap data.

        Returns (text, detail) where text renders the
        whole site in smali form —
        call_site_N("name", proto, link args...)@bootstrap
        target — and detail carries the bootstrap method
        handle and the resolved link arguments."""
        items = self._map_items()
        if MAP_TYPE_CALL_SITE_IDS not in items:
            raise _Fail("call-site table absent (no map entry) "
                        f"for call site {idx}", addr)
        size, off = items[MAP_TYPE_CALL_SITE_IDS]
        if idx >= size:
            raise _Fail(
                f"call-site index {idx} out of range "
                f"(call_site_ids_size={size})", addr)
        data = self.dex.data
        item_off = struct.unpack_from(
            "<I", data, off + idx * 4)[0]
        if item_off >= len(data):
            raise _Fail(
                f"call-site {idx} offset {item_off:#x} past "
                "end of file", addr)
        try:
            count, pos = _uleb128(data, item_off)
            if count < 3:
                raise _Fail(
                    f"call-site {idx} has {count} values "
                    "(bootstrap + name + type required)", addr)
            values = []
            for _ in range(count):
                val, pos = self._enc_value(data, pos)
                values.append(val)
        except _Fail:
            raise
        except (IndexError, struct.error, ValueError) as e:
            raise _Fail(f"call-site {idx} malformed: {e}", addr)
        bootstrap, name, proto = values[0], values[1], values[2]
        if name.startswith('"'):
            try:
                name = json.loads(name)
            except ValueError:
                pass

        def resolve(v):
            if v.startswith("handle@"):
                return self.method_handle(int(v[7:]), addr)
            if v.startswith("proto@"):
                return self.proto(int(v[6:]), addr)
            return v

        bootstrap_target = bootstrap
        if bootstrap.startswith("handle@"):
            hidx = int(bootstrap[len("handle@"):])
            _kind, bootstrap_target = \
                self.method_handle_parts(hidx, addr)
            bootstrap = self.method_handle(hidx, addr)
        if proto.startswith("proto@"):
            pidx = int(proto[len("proto@"):])
            proto = self.proto(pidx, addr)
        link_args = [resolve(v) for v in values[3:]]
        text = (f"call_site_{idx}({_quote(name)}, {proto}"
                + "".join(f", {a}" for a in link_args)
                + f")@{bootstrap_target}")
        return text, {"bootstrap": bootstrap,
                      "link_args": link_args}


# ------------------------------------------------------------------
# Decoder
# ------------------------------------------------------------------

def _sign(v, bits):
    if bits == 8:
        return _s8(v)
    if bits == 16:
        return _s16(v)
    if bits == 32:
        return _s32(v)
    return _s64(v)


def disassemble_method(dex, code_off):
    """Decode one code item. Returns a result dict:

    ok:    status "ok", register counts, the instruction
           list (real instructions plus payload entries),
           instruction_count / payload_count, warnings.
    failed: status "failed", error {reason, offset_units}
           (code-unit offset of the offending instruction),
           decoded_before_failure.

    code_off is the file offset of the code item, as carried
    by class_data. A code_off of 0 means the method is
    abstract or native and has no code; the caller should
    not pass it.
    """
    res = _Resolver(dex)
    data = dex.data
    base = {"status": "failed", "code_off": code_off,
            "instructions": []}
    if code_off <= 0 or code_off + 16 > len(data):
        base["error"] = {
            "reason": f"code offset {code_off:#x} out of bounds "
                      f"(file size {len(data)})",
            "offset_units": 0}
        return base
    regs, ins, outs, tries = struct.unpack_from(
        "<HHHH", data, code_off)
    _dbg, insns_size = struct.unpack_from("<II", data, code_off + 8)
    base.update({"registers_size": regs, "ins_size": ins,
                 "outs_size": outs, "tries_size": tries,
                 "insns_size": insns_size})
    start = code_off + 16
    if start + insns_size * 2 > len(data):
        base["error"] = {
            "reason": "instruction stream truncated by end of "
                      f"file (insns_size={insns_size}, "
                      f"{len(data) - start} bytes available)",
            "offset_units": 0}
        return base
    try:
        version = int(dex.version)
    except (TypeError, ValueError):
        version = 0
    version38 = version >= 38
    units = struct.unpack_from(f"<{insns_size}H", data, start) \
        if insns_size else ()
    instructions = []
    warnings = []
    payloads = {}
    try:
        return _walk(base, dex, res, units, insns_size,
                     instructions, warnings, payloads, version38)
    except _Fail as f:
        base["error"] = {"reason": f.reason,
                         "offset_units": f.offset_units}
        base["decoded_before_failure"] = len(instructions)
        return base


def _walk(base, dex, res, units, insns_size, instructions,
          warnings, payloads, version38):
    """The instruction walk, raising _Fail on any stream
    defect. Split from disassemble_method so the failure
    envelope is built in exactly one place."""
    i = 0

    def need(n, addr):
        if i + n > insns_size:
            raise _Fail(
                f"instruction at {addr:#06x} truncated: "
                f"needs {n} code units, "
                f"{insns_size - i} remain",
                addr)

    while i < insns_size:
        unit = units[i]
        op = unit & 0xFF
        addr = i
        if op == 0x00:
            ident = unit
            if ident == 0x0000:
                instructions.append(_ins(addr, 0, "nop", "", None))
                i += 1
                continue
            if ident == 0x0100:  # packed-switch payload
                need(2, addr)
                size = units[i + 1]
                total = 4 + size * 2
                need(total, addr)
                first_key = _s32(units[i + 2] |
                                 (units[i + 3] << 16))
                raw = [_s32(units[i + 4 + 2 * k] |
                            (units[i + 5 + 2 * k] << 16))
                       for k in range(size)]
                entry = _payload(addr, "packed-switch-payload",
                                 {"kind": "packed-switch",
                                  "size": size,
                                  "first_key": first_key,
                                  "target_offsets": raw})
                instructions.append(entry)
                payloads[addr] = entry
                i += total
                continue
            if ident == 0x0200:  # sparse-switch payload
                need(2, addr)
                size = units[i + 1]
                total = 2 + size * 4
                need(total, addr)
                keys = [_s32(units[i + 2 + 2 * k] |
                             (units[i + 3 + 2 * k] << 16))
                        for k in range(size)]
                base_k = i + 2 + size * 2
                raw = [_s32(units[base_k + 2 * k] |
                            (units[base_k + 1 + 2 * k] << 16))
                       for k in range(size)]
                entry = _payload(addr, "sparse-switch-payload",
                                 {"kind": "sparse-switch",
                                  "size": size, "keys": keys,
                                  "target_offsets": raw})
                instructions.append(entry)
                payloads[addr] = entry
                i += total
                continue
            if ident == 0x0300:  # fill-array-data payload
                need(4, addr)
                width = units[i + 1]
                count = units[i + 2] | (units[i + 3] << 16)
                data_units = (width * count + 1) // 2
                total = 4 + data_units
                need(total, addr)
                entry = _payload(addr, "fill-array-data-payload",
                                 {"kind": "fill-array-data",
                                  "element_width": width,
                                  "element_count": count,
                                  "data_units": data_units})
                instructions.append(entry)
                payloads[addr] = entry
                i += total
                continue
            raise _Fail(
                f"unit {ident:#06x} at {addr:#06x} is not a "
                "nop or a known payload identifier", addr)
        entry_def = OPS.get(op)
        if entry_def is None:
            raise _Fail(f"unknown opcode 0x{op:02x}", addr)
        mnemonic, fmt, refkind = entry_def
        if op in VERSION_038_OPS and not version38:
            raise _Fail(
                f"opcode 0x{op:02x} ({mnemonic}) requires "
                f"DEX 038+; file is DEX {dex.version}", addr)
        width = FMT_WIDTH[fmt]
        need(width, addr)
        insn = _decode_one(dex, res, units, i, op, mnemonic,
                           fmt, refkind, version38)
        instructions.append(insn)
        i += width
    # Cross-check switch/fill targets against decoded payloads.
    for insn in instructions:
        if insn.get("mnemonic") in (
                "packed-switch", "sparse-switch",
                "fill-array-data"):
            tgt = insn.get("target")
            want = {"packed-switch": "packed-switch",
                    "sparse-switch": "sparse-switch",
                    "fill-array-data": "fill-array-data"}[
                        insn["mnemonic"]]
            pay = payloads.get(tgt) if tgt is not None else None
            if pay is None:
                warnings.append(
                    f"instruction at {insn['addr']:#06x} "
                    f"({insn['mnemonic']}) targets "
                    f"{tgt:#06x}, which is not a decoded "
                    f"{want} payload")
            elif pay["payload"]["kind"] != want:
                warnings.append(
                    f"instruction at {insn['addr']:#06x} "
                    f"({insn['mnemonic']}) targets "
                    f"{tgt:#06x}, a "
                    f"{pay['payload']['kind']} payload")
            else:
                raw = pay["payload"].get("target_offsets", [])
                src = insn["addr"]
                insn["targets"] = [src + t for t in raw]
    real = [e for e in instructions
            if not e.get("is_payload")]
    result = dict(base)
    result.update({
        "status": "ok",
        "instructions": instructions,
        "instruction_count": len(real),
        "payload_count": len(instructions) - len(real),
        "decoded_before_failure": len(instructions)})
    if warnings:
        result["warnings"] = warnings
    return result


def _ins(addr, op, mnemonic, operands, ref):
    entry = {"addr": addr, "opcode": op, "mnemonic": mnemonic,
             "operands": operands,
             "text": (mnemonic + " " + operands).rstrip()}
    if ref is not None:
        entry["ref"] = ref
    return entry


def _payload(addr, mnemonic, payload):
    summary = _payload_summary(payload)
    return {"addr": addr, "opcode": 0, "mnemonic": mnemonic,
            "operands": summary,
            "text": mnemonic + " " + summary,
            "is_payload": True, "payload": payload}


def _payload_summary(payload):
    kind = payload["kind"]
    if kind == "packed-switch":
        return (f"size {payload['size']}, "
                f"first_key {payload['first_key']}")
    if kind == "sparse-switch":
        return f"size {payload['size']}"
    return (f"element_width {payload['element_width']}, "
            f"elements {payload['element_count']}")


def _decode_one(dex, res, units, i, op, mnemonic, fmt, refkind,
                version38):
    """Decode the instruction at code-unit offset i."""
    u0 = units[i]
    u1 = units[i + 1] if i + 1 < len(units) else 0
    u2 = units[i + 2] if i + 2 < len(units) else 0
    u3 = units[i + 3] if i + 3 < len(units) else 0

    def ref_text(kind, idx, addr):
        if kind == "string":
            return res.string(idx, addr), {
                "kind": "string", "index": idx,
                "value": res.string(idx, addr)}
        if kind == "type":
            return res.type(idx, addr), {
                "kind": "type", "index": idx,
                "value": res.type(idx, addr)}
        if kind == "field":
            return res.field(idx, addr), {
                "kind": "field", "index": idx,
                "value": res.field(idx, addr)}
        if kind == "method":
            return res.method(idx, addr), {
                "kind": "method", "index": idx,
                "value": res.method(idx, addr)}
        if kind == "proto":
            return res.proto(idx, addr), {
                "kind": "proto", "index": idx,
                "value": res.proto(idx, addr)}
        if kind == "method_handle":
            return res.method_handle(idx, addr), {
                "kind": "method_handle", "index": idx,
                "value": res.method_handle(idx, addr)}
        if kind == "call_site":
            text, detail = res.call_site(idx, addr)
            return text, {"kind": "call_site", "index": idx,
                          "value": text, **detail}
        return f"@{idx}", {"kind": kind, "index": idx}

    def regs_brace(regs):
        return "{" + ", ".join(f"v{r}" for r in regs) + "}"

    def regs_range(first, count):
        if count == 0:
            return "{}"
        return f"{{v{first} .. v{first + count - 1}}}"

    if fmt == "10x":
        return _ins(i, op, mnemonic, "", None)
    if fmt == "11x":
        return _ins(i, op, mnemonic, f"v{u0 >> 8}", None)
    if fmt == "12x":
        a, b = (u0 >> 8) & 0xF, (u0 >> 12) & 0xF
        return _ins(i, op, mnemonic, f"v{a}, v{b}", None)
    if fmt == "11n":
        a = (u0 >> 8) & 0xF
        nib = (u0 >> 12) & 0xF
        lit = nib - 16 if nib >= 8 else nib
        entry = _ins(i, op, mnemonic, f"v{a}, #{lit}", None)
        entry["literal"] = lit
        return entry
    if fmt == "10t":
        off = _s8(u0 >> 8)
        entry = _ins(i, op, mnemonic, f"{i + off:04x}", None)
        entry["target"] = i + off
        entry["offset"] = off
        return entry
    if fmt == "20t":
        off = _s16(u1)
        entry = _ins(i, op, mnemonic, f"{i + off:04x}", None)
        entry["target"] = i + off
        entry["offset"] = off
        return entry
    if fmt == "30t":
        off = _s32(u1 | (u2 << 16))
        entry = _ins(i, op, mnemonic, f"{i + off:04x}", None)
        entry["target"] = i + off
        entry["offset"] = off
        return entry
    if fmt == "22x":
        return _ins(i, op, mnemonic,
                    f"v{u0 >> 8}, v{u1}", None)
    if fmt == "32x":
        return _ins(i, op, mnemonic, f"v{u1}, v{u2}", None)
    if fmt == "23x":
        return _ins(i, op, mnemonic,
                    f"v{u0 >> 8}, v{u1 & 0xFF}, v{u1 >> 8}", None)
    if fmt == "21t":
        off = _s16(u1)
        entry = _ins(i, op, mnemonic,
                     f"v{u0 >> 8}, {i + off:04x}", None)
        entry["target"] = i + off
        entry["offset"] = off
        return entry
    if fmt == "22t":
        off = _s16(u1)
        entry = _ins(i, op, mnemonic,
                     f"v{(u0 >> 8) & 0xF}, "
                     f"v{(u0 >> 12) & 0xF}, {i + off:04x}", None)
        entry["target"] = i + off
        entry["offset"] = off
        return entry
    if fmt == "21s":
        lit = _s16(u1)
        entry = _ins(i, op, mnemonic,
                     f"v{u0 >> 8}, #{lit}", None)
        entry["literal"] = lit
        return entry
    if fmt == "21h":
        if mnemonic == "const-wide/high16":
            lit = _s64(u1 << 48)
        else:
            lit = _s32(u1 << 16)
        entry = _ins(i, op, mnemonic,
                     f"v{u0 >> 8}, #{lit}", None)
        entry["literal"] = lit
        return entry
    if fmt == "31i":
        lit = _s32(u1 | (u2 << 16))
        entry = _ins(i, op, mnemonic,
                     f"v{u0 >> 8}, #{lit}", None)
        entry["literal"] = lit
        return entry
    if fmt == "51l":
        lit = _s64(u1 | (u2 << 16) | (u3 << 32) |
                   (units[i + 4] << 48))
        entry = _ins(i, op, mnemonic,
                     f"v{u0 >> 8}, #{lit}", None)
        entry["literal"] = lit
        return entry
    if fmt == "21c":
        text, ref = ref_text(refkind, u1, i)
        if refkind == "string":
            operands = f"v{u0 >> 8}, {_quote(text)}"
        else:
            operands = f"v{u0 >> 8}, {text}"
        return _ins(i, op, mnemonic, operands, ref)
    if fmt == "31c":
        idx = u1 | (u2 << 16)
        text, ref = ref_text(refkind, idx, i)
        operands = f"v{u0 >> 8}, {_quote(text)}"
        return _ins(i, op, mnemonic, operands, ref)
    if fmt == "22c":
        text, ref = ref_text(refkind, u1, i)
        return _ins(i, op, mnemonic,
                    f"v{(u0 >> 8) & 0xF}, "
                    f"v{(u0 >> 12) & 0xF}, {text}", ref)
    if fmt == "22s":
        lit = _s16(u1)
        entry = _ins(i, op, mnemonic,
                     f"v{(u0 >> 8) & 0xF}, "
                     f"v{(u0 >> 12) & 0xF}, #{lit}", None)
        entry["literal"] = lit
        return entry
    if fmt == "22b":
        lit = _s8(u1 >> 8)
        entry = _ins(i, op, mnemonic,
                     f"v{u0 >> 8}, v{u1 & 0xFF}, #{lit}", None)
        entry["literal"] = lit
        return entry
    if fmt == "31t":
        off = _s32(u1 | (u2 << 16))
        entry = _ins(i, op, mnemonic,
                     f"v{u0 >> 8}, {i + off:04x}", None)
        entry["target"] = i + off
        entry["offset"] = off
        return entry
    if fmt == "35c":
        count = (u0 >> 12) & 0xF
        g = (u0 >> 8) & 0xF
        nibbles = (u2 & 0xF, (u2 >> 4) & 0xF,
                   (u2 >> 8) & 0xF, (u2 >> 12) & 0xF)
        pool = list(nibbles) + [g]
        regs = pool[:count]
        text, ref = ref_text(refkind, u1, i)
        entry = _ins(i, op, mnemonic,
                     f"{regs_brace(regs)}, {text}", ref)
        entry["registers"] = regs
        return entry
    if fmt == "3rc":
        count = u0 >> 8
        first = u2
        text, ref = ref_text(refkind, u1, i)
        entry = _ins(i, op, mnemonic,
                     f"{regs_range(first, count)}, {text}", ref)
        entry["registers"] = {"first": first, "count": count}
        return entry
    if fmt == "45cc":
        count = (u0 >> 12) & 0xF
        g = (u0 >> 8) & 0xF
        nibbles = (u2 & 0xF, (u2 >> 4) & 0xF,
                   (u2 >> 8) & 0xF, (u2 >> 12) & 0xF)
        pool = list(nibbles) + [g]
        regs = pool[:count]
        text, ref = ref_text(refkind, u1, i)
        proto = res.proto(u3, i)
        entry = _ins(i, op, mnemonic,
                     f"{regs_brace(regs)}, {text}, {proto}", ref)
        entry["registers"] = regs
        entry["proto_ref"] = {"kind": "proto", "index": u3,
                              "value": proto}
        return entry
    if fmt == "4rcc":
        count = u0 >> 8
        first = u2
        text, ref = ref_text(refkind, u1, i)
        proto = res.proto(u3, i)
        entry = _ins(i, op, mnemonic,
                     f"{regs_range(first, count)}, {text}, "
                     f"{proto}", ref)
        entry["registers"] = {"first": first, "count": count}
        entry["proto_ref"] = {"kind": "proto", "index": u3,
                              "value": proto}
        return entry
    raise _Fail(f"unhandled format {fmt} for opcode 0x{op:02x}",
                i)


# ------------------------------------------------------------------
# Batch API (used by nar-dex)
# ------------------------------------------------------------------

def methods_with_code(dex):
    """Yield (class, method_idx, name, signature, flags, kind,
    code_off) for every class-defined method that has code."""
    for cdef in dex.class_defs():
        cls = cdef["class"]
        for midx, name, flags, code_off, kind in \
                dex.class_methods_indexed(cdef["class_data_off"]):
            if not code_off:
                continue
            full = dex.method_full(midx)
            if full:
                sig = (f"{full[1]}({''.join(full[3])})"
                       f"{full[2]}")
            else:
                sig = name
            yield (cls, midx, name, sig, flags, kind, code_off)


def disassemble(dex, class_pattern=None, method_pattern=None,
                want_all=False, limit=500):
    """Disassemble selected methods of one DEX.

    Selection is by substring on the class descriptor and/or
    the method name; want_all selects every method that has
    code. Without a pattern and without want_all nothing is
    selected (the caller must ask for full disassembly
    explicitly — it is the expensive mode).
    Returns the evidence-style summary; listings are capped
    at `limit` methods (selection counts stay complete).
    """
    selected = []
    total_with_code = 0
    for cls, midx, name, sig, flags, kind, code_off in \
            methods_with_code(dex):
        total_with_code += 1
        if class_pattern and class_pattern not in cls:
            continue
        if method_pattern and method_pattern not in name:
            continue
        if not (class_pattern or method_pattern or want_all):
            continue
        selected.append((cls, midx, name, sig, flags, kind,
                         code_off))
    decoded = failed = 0
    listings = []
    failures = []
    for cls, midx, name, sig, flags, kind, code_off in selected:
        result = disassemble_method(dex, code_off)
        if result["status"] == "ok":
            decoded += 1
            if len(listings) < limit:
                listings.append({
                    "class": cls, "method": name,
                    "signature": sig, "kind": kind,
                    "method_idx": midx, "code_off": code_off,
                    "registers_size": result["registers_size"],
                    "ins_size": result["ins_size"],
                    "outs_size": result["outs_size"],
                    "tries_size": result["tries_size"],
                    "insns_size": result["insns_size"],
                    "instruction_count":
                        result["instruction_count"],
                    "payload_count": result["payload_count"],
                    "warnings": result.get("warnings", []),
                    "instructions": result["instructions"]})
        else:
            failed += 1
            if len(failures) < 100:
                failures.append({
                    "class": cls, "method": name,
                    "signature": sig, "kind": kind,
                    "reason": result["error"]["reason"],
                    "offset_units":
                        result["error"]["offset_units"]})
    return {
        "mode": "all" if want_all else "targeted",
        "class_pattern": class_pattern,
        "method_pattern": method_pattern,
        "methods_with_code": total_with_code,
        "methods_selected": len(selected),
        "methods_decoded": decoded,
        "methods_failed": failed,
        "failures": failures,
        "failures_truncated": failed > len(failures),
        "listings_truncated": len(selected) > len(listings),
        "methods": listings,
    }
