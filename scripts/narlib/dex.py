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


def _sleb128(data, off):
    result = 0
    shift = 0
    while True:
        byte = data[off]
        off += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            if byte & 0x40:
                result |= -(1 << shift)
            return result, off


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
        # A header table whose declared extent runs past the
        # end of the buffer is corrupt by definition; reject
        # it here so the lazy table readers below can never
        # leak a bare struct.error on an inflated count
        # (mutation corpus, evolution Phase 11).
        for label, size, off, item in (
                ("string_ids", self.string_ids_size,
                 self.string_ids_off, 4),
                ("type_ids", self.type_ids_size,
                 self.type_ids_off, 4),
                ("proto_ids", self.proto_ids_size,
                 self.proto_ids_off, 12),
                ("field_ids", self.field_ids_size,
                 self.field_ids_off, 8),
                ("method_ids", self.method_ids_size,
                 self.method_ids_off, 8),
                ("class_defs", self.class_defs_size,
                 self.class_defs_off, 32)):
            if size and off + size * item > len(data):
                raise DexError(
                    f"{name}: {label} table ({size} entries at "
                    f"{off:#x}) extends past end of file")
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
                "annotations_off": _annotations,
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
        # The class_data header carries four counts; the
        # encoded fields start only after the two method
        # counts. (Fixed in 2.1.0: this walk previously
        # started two ULEB128s early, so field lists were
        # shifted onto the wrong field ids.)
        _direct_n, off = _uleb128(data, off)
        _virtual_n, off = _uleb128(data, off)
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

    def class_methods_indexed(self, class_data_off):
        """Yield (method_idx, name, access_flags, code_off, kind)
        for a class. The class_methods walk with the method-table
        index kept, for callers that need full signatures
        (narlib.dexdis). class_methods itself is unchanged."""
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
                yield (method_idx, ref[1] if ref else "?",
                       flags, code_off, kind)

    # -- code items: try/catch + debug presence ------------------
    def code_item_info(self, code_off):
        """Try/catch handler table and debug-info presence for
        one code item (Evolution Phase 3). Returns None when
        code_off is 0 or out of bounds. Handler type names are
        resolved through the DEX's own type table; a handler
        whose bytes are truncated is reported with a truncated
        flag instead of raising."""
        data = self.data
        if not code_off or code_off + 16 > len(data):
            return None
        (regs, ins, outs, tries_size, debug_off,
         insns_size) = struct.unpack_from("<HHHHII", data, code_off)
        info = {"registers_size": regs, "ins_size": ins,
                "outs_size": outs, "tries_size": tries_size,
                "debug_info_off": debug_off,
                "has_debug_info": bool(debug_off),
                "insns_size": insns_size, "tries": []}
        if not tries_size:
            return info
        types = self.types()
        tries_off = code_off + 16 + insns_size * 2
        if insns_size % 2:
            tries_off += 2  # uint alignment padding
        list_off = tries_off + tries_size * 8
        if list_off > len(data):
            info["tries_truncated"] = True
            return info
        try:
            handler_count, _ = _uleb128(data, list_off)
        except IndexError:
            info["tries_truncated"] = True
            return info
        info["handler_list_count"] = handler_count
        for i in range(tries_size):
            start_addr, insn_count, handler_off = \
                struct.unpack_from("<IHH", data, tries_off + i * 8)
            entry = {"start_addr": start_addr,
                     "insn_count": insn_count,
                     "end_addr": start_addr + insn_count,
                     "handlers": [], "catch_all_addr": None}
            try:
                pos = list_off + handler_off
                size, pos = _sleb128(data, pos)
                typed = abs(size)
                for _ in range(typed):
                    type_idx, pos = _uleb128(data, pos)
                    addr, pos = _uleb128(data, pos)
                    entry["handlers"].append({
                        "type": types[type_idx]
                        if type_idx < len(types) else "?",
                        "addr": addr})
                if size <= 0:
                    catch_all, pos = _uleb128(data, pos)
                    entry["catch_all_addr"] = catch_all
            except IndexError:
                entry["truncated"] = True
            info["tries"].append(entry)
        return info

    # -- annotations (encoded values, @Metadata) ------------------
    def _encoded_value(self, off):
        """Decode one encoded_value. Returns (value, new_off).
        References resolve through the DEX's own tables:
        strings and types to their text, fields/methods/enums
        to (kind, owner, name) tuples."""
        data = self.data
        header = data[off]
        off += 1
        vtype, arg = header & 0x1F, header >> 5
        if vtype in (0x00, 0x02, 0x03, 0x04, 0x06, 0x10, 0x11):
            nbytes = arg + 1
            raw = data[off:off + nbytes]
            if len(raw) < nbytes:
                raise DexError("encoded_value truncated")
            off += nbytes
            if vtype == 0x10:  # float, right-extended
                raw = raw.rjust(4, b"\x00")
                return struct.unpack("<f", raw)[0], off
            if vtype == 0x11:  # double
                raw = raw.rjust(8, b"\x00")
                return struct.unpack("<d", raw)[0], off
            value = int.from_bytes(raw, "little")
            if vtype in (0x00, 0x02, 0x04, 0x06) and nbytes and \
                    raw[-1] & 0x80:
                value -= 1 << (nbytes * 8)
            return value, off
        # Index-carrying values (string / type / field /
        # method / enum / method type / method handle) encode
        # the index as an unsigned little-endian integer of
        # value_arg+1 bytes — NOT as a ULEB128. The two agree
        # only for indices < 256 with arg 0; reading them as
        # ULEB128 desynchronizes the stream on larger indices
        # (found on real @Metadata payloads, Phase 3).
        if vtype in (0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B):
            nbytes = arg + 1
            raw = data[off:off + nbytes]
            if len(raw) < nbytes:
                raise DexError("encoded_value truncated")
            idx = int.from_bytes(raw, "little")
            off += nbytes
            if vtype == 0x17:  # string
                strings = self.strings()
                return (strings[idx] if idx < len(strings)
                        else "?"), off
            if vtype == 0x18:  # type
                types = self.types()
                return (types[idx] if idx < len(types)
                        else "?"), off
            if vtype in (0x19, 0x1B):  # field / enum (field ref)
                return (("field" if vtype == 0x19 else "enum"),
                        self.field_ref(idx)), off
            if vtype == 0x1A:  # method
                return ("method", self.method_ref(idx)), off
            return (("method_type" if vtype == 0x15
                     else "method_handle"), idx), off
        if vtype == 0x1C:  # array
            size, off = _uleb128(data, off)
            values = []
            for _ in range(size):
                value, off = self._encoded_value(off)
                values.append(value)
            return values, off
        if vtype == 0x1D:  # nested annotation
            return self._encoded_annotation(off)
        if vtype == 0x1E:
            return None, off
        if vtype == 0x1F:
            return bool(arg), off
        raise DexError(f"unknown encoded_value type {vtype:#x}")

    def _encoded_annotation(self, off):
        """Decode one encoded_annotation at off. Returns
        ({type, elements}, new_off)."""
        data = self.data
        type_idx, off = _uleb128(data, off)
        size, off = _uleb128(data, off)
        types, strings = self.types(), self.strings()
        elements = {}
        for _ in range(size):
            name_idx, off = _uleb128(data, off)
            value, off = self._encoded_value(off)
            name = strings[name_idx] if name_idx < len(strings) \
                else "?"
            elements[name] = value
        return ({"type": types[type_idx]
                 if type_idx < len(types) else "?",
                 "elements": elements}, off)

    def class_annotations(self, class_def):
        """Class-level annotations for one class_def entry:
        [{type, visibility, elements}]. Empty when the class
        carries no annotations directory or no class-level
        set. Malformed directories yield what parsed cleanly
        plus a truncated marker entry."""
        annotations_off = class_def.get("annotations_off") or 0
        data = self.data
        if not annotations_off or \
                annotations_off + 16 > len(data):
            return []
        class_set_off = struct.unpack_from(
            "<I", data, annotations_off)[0]
        if not class_set_off or class_set_off + 4 > len(data):
            return []
        size = struct.unpack_from("<I", data, class_set_off)[0]
        out = []
        for i in range(min(size, 4096)):
            item_off = struct.unpack_from(
                "<I", data, class_set_off + 4 + i * 4)[0]
            if not item_off or item_off + 1 > len(data):
                continue
            visibility = data[item_off]
            try:
                annotation, _ = self._encoded_annotation(
                    item_off + 1)
            except (DexError, IndexError, struct.error):
                out.append({"type": "?", "visibility": visibility,
                            "elements": {}, "truncated": True})
                continue
            annotation["visibility"] = visibility
            out.append(annotation)
        return out

    # -- code scan -------------------------------------------------
    def scan_code(self, code_off):
        """Scan one code item. Returns {invokes: [(method_idx,
        kind)], string_refs: [string_idx], dynamic: [kinds]}.
        The instruction stream is unpacked in one C pass and
        walked by index — per-unit struct calls were the
        second-hottest path in the DEX profile."""
        data = self.data
        if code_off + 16 > len(data):
            return {"invokes": [], "string_refs": [], "dynamic": []}
        insns_size = struct.unpack_from("<I", data, code_off + 12)[0]
        start = code_off + 16
        end = min(len(data), start + insns_size * 2)
        n_units = (end - start) // 2
        units = struct.unpack_from(f"<{n_units}H", data, start) \
            if n_units else ()
        invokes, string_refs, dynamic = [], [], []
        i = 0
        while i < n_units:
            unit = units[i]
            op = unit & 0xFF
            if op == 0x00:
                # Payload pseudo-instructions carry their own size.
                if unit == 0x0100 and i + 1 < n_units:  # packed-switch
                    sz = units[i + 1]
                    i += 4 + sz * 2
                    continue
                if unit == 0x0200 and i + 1 < n_units:  # sparse-switch
                    sz = units[i + 1]
                    i += 2 + sz * 4
                    continue
                if unit == 0x0300 and i + 3 < n_units:  # fill-array-data
                    width = units[i + 1]
                    sz = units[i + 2] | (units[i + 3] << 16)
                    i += 4 + (width * sz + 1) // 2
                    continue
                i += 1
                continue
            if op in INVOKE_OPS:
                if i + 1 < n_units:
                    invokes.append((units[i + 1], INVOKE_OPS[op]))
            elif op in DYNAMIC_OPS:
                dynamic.append(DYNAMIC_OPS[op])
            elif op == 0x1A:  # const-string
                if i + 1 < n_units:
                    string_refs.append(units[i + 1])
            elif op == 0x1B:  # const-string/jumbo
                if i + 2 < n_units:
                    string_refs.append(
                        units[i + 1] | (units[i + 2] << 16))
            i += OP_WIDTH[op]
        return {"invokes": invokes, "string_refs": string_refs,
                "dynamic": dynamic}
