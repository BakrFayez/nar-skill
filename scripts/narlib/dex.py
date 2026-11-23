"""DEX parser primitives for the 2.0 modules.

Parses the DEX tables directly (header, string/type/proto/
field/method ids, class defs, class data, and a bounded
code-item scan) — the same evidence the guides teach, as
code. Everything is bounded: per-class string-reference
maps are capped, and instruction walking uses the DEX
opcode-width table so invoke/const-string evidence is read
from real instruction boundaries, not byte guessing.

Observed vs inferred discipline: enumeration and reference
facts are observed; anything built on top of them by callers
must be labeled by the caller.
"""
import struct

ACC_NATIVE = 0x0100

# Instruction widths in 16-bit code units, by opcode. 0x00 is
# handled specially (payload pseudo-instructions).
OP_WIDTH = [1] * 256
for _op in (0x02, 0x05, 0x08, 0x13, 0x15, 0x16, 0x19, 0x1A, 0x1C,
            0x1F, 0x20, 0x22, 0x23, 0x29, 0x2D, 0x2E, 0x2F, 0x30,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
            0x3A, 0x3B, 0x3C, 0x3D, 0x44, 0x45, 0x46, 0x47, 0x48,
            0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51,
            0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A,
            0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63,
            0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C,
            0x6D, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0,
            0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9,
            0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xD0, 0xD1, 0xD2,
            0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB,
            0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xFE, 0xFF):
    OP_WIDTH[_op] = 2
for _op in (0x03, 0x06, 0x09, 0x14, 0x17, 0x1B, 0x24, 0x25, 0x26,
            0x2A, 0x2B, 0x2C, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x74,
            0x75, 0x76, 0x77, 0x78, 0xFC, 0xFD):
    OP_WIDTH[_op] = 3
for _op in (0xFA, 0xFB):
    OP_WIDTH[_op] = 4
OP_WIDTH[0x18] = 5  # const-wide

INVOKE_OPS = {0x6E: "virtual", 0x6F: "super", 0x70: "direct",
              0x71: "static", 0x72: "interface",
              0x74: "virtual/range", 0x75: "super/range",
              0x76: "direct/range", 0x77: "static/range",
              0x78: "interface/range",
              0xFA: "polymorphic", 0xFB: "polymorphic/range"}
DYNAMIC_OPS = {0xFC: "invoke-custom", 0xFD: "invoke-custom/range"}


def _uleb128(data, off):
    result = 0
    shift = 0
    while True:
        byte = data[off]
        off += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, off
        shift += 7


class DexError(Exception):
    pass


class Dex:
    """One parsed DEX file (tables + lazily scanned code)."""

    def __init__(self, data, name="classes.dex"):
        if len(data) < 112 or not data.startswith(b"dex\n"):
            raise DexError(f"{name}: not a DEX file")
        self.name = name
        self.data = data
        self.version = data[4:7].decode("ascii", "replace")
        (self.string_ids_size, self.string_ids_off) = \
            struct.unpack_from("<II", data, 0x38)
        (self.type_ids_size, self.type_ids_off) = \
            struct.unpack_from("<II", data, 0x40)
        (self.proto_ids_size, self.proto_ids_off) = \
            struct.unpack_from("<II", data, 0x48)
        (self.field_ids_size, self.field_ids_off) = \
            struct.unpack_from("<II", data, 0x50)
        (self.method_ids_size, self.method_ids_off) = \
            struct.unpack_from("<II", data, 0x58)
        (self.class_defs_size, self.class_defs_off) = \
            struct.unpack_from("<II", data, 0x60)
        self._strings = None
        self._types = None

    # -- tables -------------------------------------------------
    def strings(self):
        if self._strings is None:
            out = []
            data = self.data
            for i in range(self.string_ids_size):
                off = struct.unpack_from(
                    "<I", data, self.string_ids_off + i * 4)[0]
                try:
                    _len, pos = _uleb128(data, off)
                    end = data.index(b"\x00", pos)
                    out.append(data[pos:end].decode("utf-8", "replace"))
                except (ValueError, IndexError, struct.error):
                    out.append("")
            self._strings = out
        return self._strings

    def types(self):
        if self._types is None:
            strings = self.strings()
            out = []
            for i in range(self.type_ids_size):
                idx = struct.unpack_from(
                    "<I", self.data, self.type_ids_off + i * 4)[0]
                out.append(strings[idx] if idx < len(strings) else "?")
            self._types = out
        return self._types

    def method_ref(self, idx):
        """(class_descriptor, name, proto_shorty) for a method id."""
        if idx >= self.method_ids_size:
            return None
        class_idx, proto_idx, name_idx = struct.unpack_from(
            "<HHI", self.data, self.method_ids_off + idx * 8)
        types, strings = self.types(), self.strings()
        shorty = ""
        if proto_idx < self.proto_ids_size:
            shorty_idx = struct.unpack_from(
                "<I", self.data, self.proto_ids_off + proto_idx * 12)[0]
            if shorty_idx < len(strings):
                shorty = strings[shorty_idx]
        return (types[class_idx] if class_idx < len(types) else "?",
                strings[name_idx] if name_idx < len(strings) else "?",
                shorty)

    def field_ref(self, idx):
        if idx >= self.field_ids_size:
            return None
        class_idx, type_idx, name_idx = struct.unpack_from(
            "<HHI", self.data, self.field_ids_off + idx * 8)
        types, strings = self.types(), self.strings()
        return (types[class_idx] if class_idx < len(types) else "?",
                types[type_idx] if type_idx < len(types) else "?",
                strings[name_idx] if name_idx < len(strings) else "?")

    # -- class defs ----------------------------------------------
    def class_defs(self):
        out = []
        types = self.types()
        for i in range(self.class_defs_size):
            vals = struct.unpack_from(
                "<IIIIIIII", self.data, self.class_defs_off + i * 32)
            (class_idx, _access, super_idx, interfaces_off,
             _source, _annotations, class_data_off,
             _static_values) = vals
            interfaces = []
            if interfaces_off:
                size = struct.unpack_from(
                    "<I", self.data, interfaces_off)[0]
                for j in range(size):
                    tidx = struct.unpack_from(
                        "<H", self.data, interfaces_off + 4 + j * 2)[0]
                    if tidx < len(types):
                        interfaces.append(types[tidx])
            out.append({
                "class": types[class_idx] if class_idx < len(types)
                else "?",
                "superclass": types[super_idx]
                if super_idx != 0xFFFFFFFF and super_idx < len(types)
                else None,
                "interfaces": interfaces,
                "class_data_off": class_data_off,
            })
        return out

    def class_fields(self, class_data_off):
        """Yield (name, type_descriptor, access_flags, kind)
        for a class's static + instance fields."""
        if not class_data_off:
            return
        data = self.data
        off = class_data_off
        static_n, off = _uleb128(data, off)
        instance_n, off = _uleb128(data, off)
        types, strings = self.types(), self.strings()
        for kind, count in (("static", static_n),
                            ("instance", instance_n)):
            field_idx = 0
            for _ in range(count):
                delta, off = _uleb128(data, off)
                flags, off = _uleb128(data, off)
                field_idx += delta
                ref = self.field_ref(field_idx)
                if ref:
                    yield (ref[2], ref[1], flags, kind)

    def proto_info(self, proto_idx):
        """(return_type, [param_types]) for a proto id."""
        types = self.types()
        if proto_idx >= self.proto_ids_size:
            return (None, [])
        _shorty, return_idx, params_off = struct.unpack_from(
            "<III", self.data, self.proto_ids_off + proto_idx * 12)
        params = []
        if params_off:
            size = struct.unpack_from("<I", self.data, params_off)[0]
            for j in range(size):
                tidx = struct.unpack_from(
                    "<H", self.data, params_off + 4 + j * 2)[0]
                if tidx < len(types):
                    params.append(types[tidx])
        return (types[return_idx] if return_idx < len(types)
                else None, params)

    def method_full(self, idx):
        """(class, name, return_type, [params]) for a method id."""
        if idx >= self.method_ids_size:
            return None
        class_idx, proto_idx, name_idx = struct.unpack_from(
            "<HHI", self.data, self.method_ids_off + idx * 8)
        types, strings = self.types(), self.strings()
        ret, params = self.proto_info(proto_idx)
        return (types[class_idx] if class_idx < len(types) else "?",
                strings[name_idx] if name_idx < len(strings) else "?",
                ret, params)

    def class_methods(self, class_data_off):
        """Yield (name, access_flags, code_off, kind) for a class."""
        if not class_data_off:
            return
        data = self.data
        off = class_data_off
        static_n, off = _uleb128(data, off)
        instance_n, off = _uleb128(data, off)
        direct_n, off = _uleb128(data, off)
        virtual_n, off = _uleb128(data, off)
        for _ in range(static_n + instance_n):
            _delta, off = _uleb128(data, off)
            _flags, off = _uleb128(data, off)
        for kind, count in (("direct", direct_n),
                            ("virtual", virtual_n)):
            method_idx = 0
            for _ in range(count):
                delta, off = _uleb128(data, off)
                flags, off = _uleb128(data, off)
                code_off, off = _uleb128(data, off)
                method_idx += delta
                ref = self.method_ref(method_idx)
                yield (ref[1] if ref else "?", flags, code_off, kind)

    # -- code scan -------------------------------------------------
    def scan_code(self, code_off):
        """Scan one code item. Returns {invokes: [(method_idx,
        kind)], string_refs: [string_idx], dynamic: [kinds]}."""
        data = self.data
        if code_off + 16 > len(data):
            return {"invokes": [], "string_refs": [], "dynamic": []}
        insns_size = struct.unpack_from("<I", data, code_off + 12)[0]
        start = code_off + 16
        end = min(len(data), start + insns_size * 2)
        invokes, string_refs, dynamic = [], [], []
        pos = start
        while pos + 2 <= end:
            unit = struct.unpack_from("<H", data, pos)[0]
            op = unit & 0xFF
            if op == 0x00:
                # Payload pseudo-instructions carry their own size.
                if unit == 0x0100 and pos + 4 <= end:  # packed-switch
                    sz = struct.unpack_from("<H", data, pos + 2)[0]
                    pos += (4 + sz * 2) * 2
                    continue
                if unit == 0x0200 and pos + 4 <= end:  # sparse-switch
                    sz = struct.unpack_from("<H", data, pos + 2)[0]
                    pos += (2 + sz * 4) * 2
                    continue
                if unit == 0x0300 and pos + 8 <= end:  # fill-array-data
                    width = struct.unpack_from("<H", data, pos + 2)[0]
                    sz = struct.unpack_from("<I", data, pos + 4)[0]
                    pos += (4 + (width * sz + 1) // 2) * 2
                    continue
                pos += 2
                continue
            if op in INVOKE_OPS:
                if pos + 4 <= end:
                    midx = struct.unpack_from("<H", data, pos + 2)[0]
                    invokes.append((midx, INVOKE_OPS[op]))
            elif op in DYNAMIC_OPS:
                dynamic.append(DYNAMIC_OPS[op])
            elif op == 0x1A:  # const-string
                if pos + 4 <= end:
                    string_refs.append(
                        struct.unpack_from("<H", data, pos + 2)[0])
            elif op == 0x1B:  # const-string/jumbo
                if pos + 6 <= end:
                    string_refs.append(
                        struct.unpack_from("<I", data, pos + 2)[0])
            pos += OP_WIDTH[op] * 2
        return {"invokes": invokes, "string_refs": string_refs,
                "dynamic": dynamic}
