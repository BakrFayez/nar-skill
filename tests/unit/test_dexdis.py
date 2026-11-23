"""Unit tests for narlib.dexdis on synthetic DEX inputs.

The builder constructs spec-shaped DEX files with hand-packed
instruction streams: no external fixtures, no app data. Every
format family, the payload pseudo-instructions, the DEX 038
version gates, and the clean-failure discipline (unknown
opcode, truncated stream, out-of-range reference) are
exercised against exact expected listings.
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]
                       / "scripts"))

from narlib.dex import Dex, OP_WIDTH  # noqa: E402
from narlib import dexdis  # noqa: E402


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


def _enc_value(vtype, value, width=None):
    """One encoded_value for a call-site item."""
    if width is None:
        width = max(1, (value.bit_length() + 7) // 8)
    return bytes([(vtype & 0x1F) | ((width - 1) << 5)]) + \
        value.to_bytes(width, "little")


class DexBuilder:
    """Assemble a minimal but spec-shaped DEX.

    classes: list of {"class": type_idx, "super": type_idx,
    "direct": [(method_idx, code_units | None)],
    "virtual": [...]}. code_units is a list of uint16.
    """

    def __init__(self, version="039"):
        self.version = version
        self.strings = []
        self.types = []       # string idx per type
        self.protos = []      # (shorty_str_idx, ret_type_idx,
        #                      [param_type_idx])
        self.fields = []      # (class_idx, type_idx, name_idx)
        self.methods = []     # (class_idx, proto_idx, name_idx)
        self.classes = []
        self.handles = []     # (handle_type, ref_idx)
        self.call_sites = []  # encoded-array bytes per site

    def s(self, text):
        if text not in self.strings:
            self.strings.append(text)
        return self.strings.index(text)

    def t(self, desc):
        sidx = self.s(desc)
        if sidx not in self.types:
            self.types.append(sidx)
        return self.types.index(sidx)

    def proto(self, shorty, ret, params=()):
        key = (self.s(shorty), ret, tuple(params))
        for i, p in enumerate(self.protos):
            if p == key:
                return i
        self.protos.append(key)
        return len(self.protos) - 1

    def field(self, cls, typ, name):
        key = (cls, typ, self.s(name))
        if key not in self.fields:
            self.fields.append(key)
        return self.fields.index(key)

    def method(self, cls, proto, name):
        key = (cls, proto, self.s(name))
        if key not in self.methods:
            self.methods.append(key)
        return self.methods.index(key)

    def build(self):
        header_size = 0x70
        n_str, n_type = len(self.strings), len(self.types)
        n_proto, n_field = len(self.protos), len(self.fields)
        n_method, n_class = len(self.methods), len(self.classes)
        string_ids_off = header_size
        type_ids_off = string_ids_off + 4 * n_str
        proto_ids_off = type_ids_off + 4 * n_type
        field_ids_off = proto_ids_off + 12 * n_proto
        method_ids_off = field_ids_off + 8 * n_field
        class_defs_off = method_ids_off + 8 * n_method
        data_off = class_defs_off + 32 * n_class

        data = bytearray()

        def align4():
            while (data_off + len(data)) % 4:
                data.append(0)

        # string data
        string_offsets = []
        for s in self.strings:
            string_offsets.append(data_off + len(data))
            raw = s.encode("utf-8")
            data += _uleb(len(raw)) + raw + b"\x00"
        # proto type lists
        proto_params_off = []
        for _shorty, _ret, params in self.protos:
            if not params:
                proto_params_off.append(0)
                continue
            align4()
            proto_params_off.append(data_off + len(data))
            data += struct.pack("<I", len(params))
            for p in params:
                data += struct.pack("<H", p)
        # code items + class data
        class_data_offs = []
        for cdef in self.classes:
            code_offs = {}
            for kind in ("direct", "virtual"):
                for midx, units in cdef.get(kind, []):
                    if units is None:
                        code_offs[midx] = 0
                        continue
                    align4()
                    code_offs[midx] = data_off + len(data)
                    data += struct.pack(
                        "<HHHHII", 8, 2, 2, 0, 0, len(units))
                    for u in units:
                        data += struct.pack("<H", u)
            class_data_offs.append(data_off + len(data))
            direct = cdef.get("direct", [])
            virtual = cdef.get("virtual", [])
            blob = _uleb(0) + _uleb(0) + _uleb(len(direct)) \
                + _uleb(len(virtual))
            for kind, group in (("direct", direct),
                                ("virtual", virtual)):
                prev = 0
                for midx, _units in group:
                    blob += _uleb(midx - prev)
                    blob += _uleb(0x1)          # access flags
                    blob += _uleb(code_offs[midx])
                    prev = midx
            data += blob
        # call-site ids + items
        call_site_ids_off = 0
        if self.call_sites:
            align4()
            item_offs = []
            items = bytearray()
            base = data_off + len(data) + 4 * len(self.call_sites)
            for site in self.call_sites:
                item_offs.append(base + len(items))
                items += site
            call_site_ids_off = data_off + len(data)
            for off in item_offs:
                data += struct.pack("<I", off)
            data += items
        # method-handle ids
        handle_ids_off = 0
        if self.handles:
            align4()
            handle_ids_off = data_off + len(data)
            for htype, ref in self.handles:
                data += struct.pack("<HHI", htype, 0, ref)
        # map list
        align4()
        map_off = data_off + len(data)
        map_items = []
        if self.call_sites:
            map_items.append((0x0007, len(self.call_sites),
                              call_site_ids_off))
        if self.handles:
            map_items.append((0x0008, len(self.handles),
                              handle_ids_off))
        data += struct.pack("<I", len(map_items))
        for typ, size, off in map_items:
            data += struct.pack("<HHII", typ, 0, size, off)

        file_size = data_off + len(data)
        out = bytearray(file_size)
        out[0:8] = b"dex\n" + self.version.encode() + b"\x00"
        struct.pack_into("<I", out, 32, file_size)
        struct.pack_into("<I", out, 36, header_size)
        struct.pack_into("<I", out, 40, 0x12345678)
        struct.pack_into("<I", out, 52, map_off)      # map_off
        struct.pack_into("<II", out, 56, n_str, string_ids_off)
        struct.pack_into("<II", out, 64, n_type, type_ids_off)
        struct.pack_into("<II", out, 72, n_proto, proto_ids_off)
        struct.pack_into("<II", out, 88 - 8, n_field,
                         field_ids_off)
        struct.pack_into("<II", out, 88, n_method,
                         method_ids_off)
        struct.pack_into("<II", out, 96, n_class, class_defs_off)
        for i, off in enumerate(string_offsets):
            struct.pack_into("<I", out, string_ids_off + 4 * i,
                             off)
        for i, sidx in enumerate(self.types):
            struct.pack_into("<I", out, type_ids_off + 4 * i,
                             sidx)
        for i, (shorty, ret, _p) in enumerate(self.protos):
            struct.pack_into("<III", out, proto_ids_off + 12 * i,
                             shorty, ret, proto_params_off[i])
        for i, (cls, typ, name) in enumerate(self.fields):
            struct.pack_into("<HHI", out, field_ids_off + 8 * i,
                             cls, typ, name)
        for i, (cls, proto, name) in enumerate(self.methods):
            struct.pack_into("<HHI", out, method_ids_off + 8 * i,
                             cls, proto, name)
        for i, cdef in enumerate(self.classes):
            struct.pack_into(
                "<IIIIIIII", out, class_defs_off + 32 * i,
                cdef["class"], 0x1, cdef.get("super", 0xFFFFFFFF),
                0, 0, 0, class_data_offs[i], 0)
        out[data_off:data_off + len(data)] = data
        return bytes(out)


def U(op, hi=0):
    """One code unit: opcode in the low byte, hi in the high."""
    return (hi << 8) | op


def listing(dex, code_off):
    r = dexdis.disassemble_method(dex, code_off)
    assert r["status"] == "ok", r.get("error")
    return [(e["addr"], e["mnemonic"], e["operands"])
            for e in r["instructions"]]


def first_code_off(dex):
    for _c, _m, _n, _s, _f, _k, code_off in \
            dexdis.methods_with_code(dex):
        return code_off
    raise AssertionError("no method with code")


def make_dex(version, method_units_list, extra=None):
    """One class LFoo; with one method per unit list."""
    b = DexBuilder(version)
    foo = b.t("LFoo;")
    obj = b.t("Ljava/lang/Object;")
    void = b.t("V")
    proto = b.proto("V", void)
    methods = []
    for i, units in enumerate(method_units_list):
        midx = b.method(foo, proto, f"m{i}")
        methods.append((midx, units))
    b.classes.append({"class": foo, "super": obj,
                      "direct": methods})
    if extra:
        extra(b, foo, void, proto)
    return Dex(b.build())


# ------------------------------------------------------------------
# Table discipline
# ------------------------------------------------------------------

def test_width_table_matches_proven_op_width():
    for op, (_name, fmt, _ref) in dexdis.OPS.items():
        assert dexdis.FMT_WIDTH[fmt] == OP_WIDTH[op], hex(op)


def test_defined_opcode_count():
    # 224 assigned opcodes in the DEX map; the rest are
    # unassigned or payloads.
    assert len(dexdis.OPS) == 224


# ------------------------------------------------------------------
# Format families
# ------------------------------------------------------------------

def test_register_and_const_formats():
    units = [
        U(0x01, 0x21),          # 0: move v1, v2
        U(0x02, 3), 7,          # 1: move/from16 v3, v7
        U(0x03, 0), 9, 11,      # 3: move/16 v9, v11
        U(0x12, 0xF5),          # 6: const/4 v5, #-1
        U(0x13, 2), 0xFFFE,     # 7: const/16 v2, #-2
        U(0x14, 1), 0x5678, 0x1234,   # 9: const v1, #305419896
        U(0x15, 4), 0x3F80,     # 12: const/high16 v4
        U(0x16, 5), 0xFFFF,     # 14: const-wide/16 v5, #-1
        U(0x17, 6), 0x0000, 0x8000,   # 16: const-wide/32 v6
        U(0x18, 7), 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
        # 19: const-wide v7, #-1 (op + 4 units)
        U(0x19, 8), 0x4000,     # 24: const-wide/high16 v8
        U(0x0E),                # 26: return-void
    ]
    dex = make_dex("039", [units])
    got = listing(dex, first_code_off(dex))
    assert got == [
        (0, "move", "v1, v2"),
        (1, "move/from16", "v3, v7"),
        (3, "move/16", "v9, v11"),
        (6, "const/4", "v5, #-1"),
        (7, "const/16", "v2, #-2"),
        (9, "const", "v1, #305419896"),
        (12, "const/high16", "v4, #1065353216"),
        (14, "const-wide/16", "v5, #-1"),
        (16, "const-wide/32", "v6, #-2147483648"),
        (19, "const-wide", "v7, #-1"),
        (24, "const-wide/high16", "v8, "
         "#4611686018427387904"),
        (26, "return-void", ""),
    ], got


def test_refs_invokes_and_fields():
    b = DexBuilder("039")
    foo = b.t("LFoo;")
    obj = b.t("Ljava/lang/Object;")
    sbuilder = b.t("Ljava/lang/StringBuilder;")
    integer = b.t("I")
    void = b.t("V")
    hello = b.s("hello")
    p_v = b.proto("V", void)
    p_iv = b.proto("IV", void, (integer,))
    p_sb = b.proto("VLjava/lang/StringBuilder;", sbuilder)
    fld = b.field(foo, integer, "count")
    sfld = b.field(foo, integer, "total")
    m_append = b.method(sbuilder, p_iv, "append")
    m_make = b.method(foo, p_sb, "make")
    m_main = b.method(foo, p_v, "main")
    units = [
        U(0x1A, 0), hello,                 # const-string v0
        U(0x1B, 1), hello, 0,              # const-string/jumbo v1
        U(0x1C, 2), foo,                   # const-class v2
        U(0x1F, 0), foo,                   # check-cast v0
        U(0x22, 3), sbuilder,              # new-instance v3
        U(0x20, 0x21), foo,                # instance-of v1, v2
        U(0x23, 0x21), foo,                # new-array v1, v2
        U(0x52, 0x10), fld,                # iget v0, v1
        U(0x60, 4), sfld,                  # sget v4
        U(0x6E, 0x20), m_append, 0x10,     # invoke-virtual {v0,v1}
        U(0x77, 3), m_make, 5,             # invoke-static/range
        U(0x24, 0x20), foo, 0x10,          # filled-new-array
        U(0x25, 2), foo, 7,                # filled-new-array/range
        U(0x0E),
    ]
    b.classes.append({"class": foo, "super": obj,
                      "direct": [(m_main, units)]})
    dex = Dex(b.build())
    got = listing(dex, first_code_off(dex))
    assert got == [
        (0, "const-string", 'v0, "hello"'),
        (2, "const-string/jumbo", 'v1, "hello"'),
        (5, "const-class", "v2, LFoo;"),
        (7, "check-cast", "v0, LFoo;"),
        (9, "new-instance", "v3, Ljava/lang/StringBuilder;"),
        (11, "instance-of", "v1, v2, LFoo;"),
        (13, "new-array", "v1, v2, LFoo;"),
        (15, "iget", "v0, v1, LFoo;->count:I"),
        (17, "sget", "v4, LFoo;->total:I"),
        (19, "invoke-virtual",
         "{v0, v1}, Ljava/lang/StringBuilder;->append(I)V"),
        (22, "invoke-static/range",
         "{v5 .. v7}, LFoo;->make()Ljava/lang/StringBuilder;"),
        (25, "filled-new-array", "{v0, v1}, LFoo;"),
        (28, "filled-new-array/range", "{v7 .. v8}, LFoo;"),
        (31, "return-void", ""),
    ], got


def test_binops_literals_and_misc():
    units = [
        U(0x90, 0), 0x0201,      # add-int v0, v1, v2
        U(0xB0, 0x21),           # add-int/2addr v1, v2
        U(0x7B, 0x10),           # neg-int v0, v1
        U(0x21, 0x10),           # array-length v0, v1
        U(0x44, 0), 0x0201,      # aget v0, v1, v2
        U(0xD0, 0x10), 0xFFF9,   # add-int/lit16 v0, v1, #-7
        U(0xD1, 0x10), 100,      # rsub-int v0, v1, #100
        U(0xD8, 0), 0xFB01,      # add-int/lit8 v0, v1, #-5
        U(0x2D, 3), 0x0504,      # cmpl-float v3, v4, v5
        U(0x1D, 6),              # monitor-enter v6
        U(0x27, 6),              # throw v6
        U(0x0A, 7),              # move-result v7
        U(0x0E),
    ]
    dex = make_dex("039", [units])
    got = listing(dex, first_code_off(dex))
    assert got == [
        (0, "add-int", "v0, v1, v2"),
        (2, "add-int/2addr", "v1, v2"),
        (3, "neg-int", "v0, v1"),
        (4, "array-length", "v0, v1"),
        (5, "aget", "v0, v1, v2"),
        (7, "add-int/lit16", "v0, v1, #-7"),
        (9, "rsub-int", "v0, v1, #100"),
        (11, "add-int/lit8", "v0, v1, #-5"),
        (13, "cmpl-float", "v3, v4, v5"),
        (15, "monitor-enter", "v6"),
        (16, "throw", "v6"),
        (17, "move-result", "v7"),
        (18, "return-void", ""),
    ], got


def test_branches_and_payloads():
    # Instruction starts: 0 goto, 1 nop, 2 goto/16, 4 goto/32,
    # 7 if-eqz, 9 if-eq, 11 packed-switch, 14 sparse-switch,
    # 17 fill-array-data, 20 return-void, 21 packed payload
    # (8 units), 29 sparse payload (6 units), 35 fill payload
    # (7 units). Switch targets are relative to the SWITCH
    # instruction address, per the format.
    units = [
        U(0x28, 0x02),                       # 0: goto +2 -> 2
        U(0x00),                             # 1: nop
        U(0x29, 0), 2,                       # 2: goto/16 +2 -> 4
        U(0x2A, 0), 3, 0,                    # 4: goto/32 +3 -> 7
        U(0x38, 1), 2,                       # 7: if-eqz v1 -> 9
        U(0x32, 0x10), 0xFFFE,               # 9: if-eq v0, v1 -> 7
        U(0x2B, 1), 10, 0,                   # 11: packed-switch -> 21
        U(0x2C, 2), 15, 0,                   # 14: sparse-switch -> 29
        U(0x26, 3), 18, 0,                   # 17: fill-array-data -> 35
        U(0x0E),                             # 20: return-void
        U(0x0100), 2, 10, 0,                 # 21: packed payload
        0xFFFE, 0xFFFF, 9, 0,                #   first_key 10; targets -2, +9
        U(0x0200), 1, 7, 0,                  # 29: sparse payload
        0xFFF9, 0xFFFF,                      #   key 7; target -7
        U(0x0300), 2, 3, 0,                  # 35: fill payload
        0x0102, 0x0304, 0x0005,              #   width 2, 3 elements
    ]
    dex = make_dex("039", [units])
    r = dexdis.disassemble_method(dex, first_code_off(dex))
    assert r["status"] == "ok", r.get("error")
    by_addr = {e["addr"]: e for e in r["instructions"]}
    assert by_addr[0]["target"] == 2
    assert by_addr[2]["target"] == 4
    assert by_addr[4]["target"] == 7
    assert by_addr[7]["target"] == 9
    assert by_addr[9]["target"] == 7
    assert by_addr[11]["mnemonic"] == "packed-switch"
    assert by_addr[11]["targets"] == [9, 20], by_addr[11]
    assert by_addr[14]["targets"] == [7], by_addr[14]
    assert by_addr[21]["is_payload"] is True
    assert by_addr[21]["payload"]["first_key"] == 10
    assert by_addr[29]["payload"]["keys"] == [7]
    assert by_addr[35]["payload"]["element_width"] == 2
    assert by_addr[35]["payload"]["element_count"] == 3
    assert r["payload_count"] == 3
    assert r["instruction_count"] == 10
    assert "warnings" not in r, r.get("warnings")



# ------------------------------------------------------------------
# DEX 038 version gates: invoke-custom / polymorphic / handles
# ------------------------------------------------------------------

def _gated_builder(version):
    """A DEX whose single method uses every 038-gated form.

    Returns (builder, units). Call-site 0 links through
    method handle 0 (invoke-static@LFoo;->boot()V), is named
    "dyn" with proto ()V and one string link argument.
    """
    b = DexBuilder(version)
    foo = b.t("LFoo;")
    obj = b.t("Ljava/lang/Object;")
    void = b.t("V")
    integer = b.t("I")
    p_v = b.proto("V", void)
    p_iv = b.proto("IV", void, (integer,))
    m_boot = b.method(foo, p_v, "boot")
    m_poly = b.method(foo, p_iv, "poly")
    m_main = b.method(foo, p_v, "main")
    fld = b.field(foo, integer, "count")
    b.handles.append((0x04, m_boot))       # invoke-static
    b.handles.append((0x01, fld))          # static-get (field)
    site = _uleb(4)
    site += _enc_value(0x16, 0)            # bootstrap handle 0
    site += _enc_value(0x17, b.s("dyn"))   # name
    site += _enc_value(0x15, p_v)          # method type ()V
    site += _enc_value(0x17, b.s("x"))     # one link arg
    b.call_sites.append(site)
    units = [
        U(0xFA, 0x10), m_poly, 0x0000, p_iv,   # invoke-polymorphic {v0}, poly(I)V, (I)V
        U(0xFB, 1), m_poly, 3, p_iv,           # invoke-polymorphic/range {v3}, ...
        U(0xFC, 0x10), 0, 0x0000,              # invoke-custom {v0}, site 0
        U(0xFD, 1), 0, 4,                      # invoke-custom/range {v4}, site 0
        U(0xFE, 2), 0,                         # const-method-handle v2, handle 0
        U(0xFE, 3), 1,                         # const-method-handle v3, handle 1
        U(0xFF, 4), p_iv,                      # const-method-type v4, (I)V
        U(0x0E),
    ]
    b.classes.append({"class": foo, "super": obj,
                      "direct": [(m_main, units)]})
    return b


def test_version_gated_ops_039():
    dex = Dex(_gated_builder("039").build())
    r = dexdis.disassemble_method(dex, first_code_off(dex))
    assert r["status"] == "ok", r.get("error")
    got = [(e["addr"], e["mnemonic"], e["operands"])
           for e in r["instructions"]]
    assert got == [
        (0, "invoke-polymorphic",
         "{v0}, LFoo;->poly(I)V, (I)V"),
        (4, "invoke-polymorphic/range",
         "{v3 .. v3}, LFoo;->poly(I)V, (I)V"),
        (8, "invoke-custom",
         '{v0}, call_site_0("dyn", ()V, "x")@LFoo;->boot()V'),
        (11, "invoke-custom/range",
         '{v4 .. v4}, call_site_0("dyn", ()V, "x")'
         "@LFoo;->boot()V"),
        (14, "const-method-handle",
         "v2, invoke-static@LFoo;->boot()V"),
        (16, "const-method-handle",
         "v3, static-get@LFoo;->count:I"),
        (18, "const-method-type", "v4, (I)V"),
        (20, "return-void", ""),
    ], got
    custom = r["instructions"][2]
    assert custom["ref"]["kind"] == "call_site"
    assert custom["ref"]["bootstrap"] == \
        "invoke-static@LFoo;->boot()V"
    assert custom["ref"]["link_args"] == ['"x"']
    handle = r["instructions"][4]
    assert handle["ref"]["kind"] == "method_handle"


def test_version_gate_failure_035():
    dex = Dex(_gated_builder("035").build())
    r = dexdis.disassemble_method(dex, first_code_off(dex))
    assert r["status"] == "failed"
    assert "DEX 038" in r["error"]["reason"], r["error"]
    assert r["error"]["offset_units"] == 0
    assert r["instructions"] == []


# ------------------------------------------------------------------
# Failure discipline
# ------------------------------------------------------------------

def test_unknown_opcode_fails_cleanly():
    units = [U(0x12, 0x10), U(0xE3, 0), U(0x0E)]
    dex = make_dex("039", [units])
    r = dexdis.disassemble_method(dex, first_code_off(dex))
    assert r["status"] == "failed"
    assert "unknown opcode 0xe3" in r["error"]["reason"]
    assert r["error"]["offset_units"] == 1
    assert r["decoded_before_failure"] == 1
    assert r["instructions"] == []


def test_bad_payload_ident_fails():
    dex = make_dex("039", [[U(0x0400), U(0x0E)]])
    r = dexdis.disassemble_method(dex, first_code_off(dex))
    assert r["status"] == "failed"
    assert "payload identifier" in r["error"]["reason"]


def test_truncated_stream_fails():
    # const (31i) needs 3 units; only 2 remain.
    dex = make_dex("039", [[U(0x14, 1), 0x1234]])
    r = dexdis.disassemble_method(dex, first_code_off(dex))
    assert r["status"] == "failed"
    assert "truncated" in r["error"]["reason"]
    assert r["error"]["offset_units"] == 0


def test_truncated_payload_fails():
    # packed-switch payload declares 3 targets but the
    # stream ends after the header.
    units = [U(0x0100), 3, 0, 0]
    dex = make_dex("039", [units])
    r = dexdis.disassemble_method(dex, first_code_off(dex))
    assert r["status"] == "failed"
    assert "truncated" in r["error"]["reason"]


def test_out_of_range_refs_fail():
    b = DexBuilder("039")
    foo = b.t("LFoo;")
    obj = b.t("Ljava/lang/Object;")
    void = b.t("V")
    p_v = b.proto("V", void)
    m = b.method(foo, p_v, "main")
    # const-string with a plainly out-of-range index (only a
    # "Ljava/lang/Object;", "V", "main", "V" shorty strings
    # exist; use a plainly out-of-range index).
    units = [U(0x1A, 0), 999, U(0x0E)]
    b.classes.append({"class": foo, "super": obj,
                      "direct": [(m, units)]})
    dex = Dex(b.build())
    r = dexdis.disassemble_method(dex, first_code_off(dex))
    assert r["status"] == "failed"
    assert "string index 999 out of range" in \
        r["error"]["reason"], r["error"]
    assert r["error"]["offset_units"] == 0


def test_one_bad_method_does_not_poison_others():
    good = [U(0x12, 0x10), U(0x0E)]
    bad = [U(0xE3, 0)]
    dex = make_dex("039", [bad, good])
    summary = dexdis.disassemble(dex, want_all=True)
    assert summary["methods_selected"] == 2
    assert summary["methods_decoded"] == 1
    assert summary["methods_failed"] == 1
    assert summary["failures"][0]["method"] == "m0"
    assert summary["methods"][0]["method"] == "m1"


# ------------------------------------------------------------------
# Batch selection discipline
# ------------------------------------------------------------------

def test_selection_requires_explicit_scope():
    dex = make_dex("039", [[U(0x0E)]])
    summary = dexdis.disassemble(dex)
    assert summary["methods_selected"] == 0
    assert summary["methods_with_code"] == 1


def test_selection_by_class_and_method():
    dex = make_dex("039", [[U(0x0E)], [U(0x0E)]])
    by_class = dexdis.disassemble(dex, class_pattern="LFoo;")
    assert by_class["methods_selected"] == 2
    by_method = dexdis.disassemble(dex, method_pattern="m1")
    assert by_method["methods_selected"] == 1
    none = dexdis.disassemble(dex, class_pattern="LBar;")
    assert none["methods_selected"] == 0


def test_selection_limit_marks_truncation():
    dex = make_dex("039", [[U(0x0E)], [U(0x0E)], [U(0x0E)]])
    summary = dexdis.disassemble(dex, want_all=True, limit=2)
    assert summary["methods_decoded"] == 3
    assert len(summary["methods"]) == 2
    assert summary["listings_truncated"] is True
