"""Unit tests for the 2.6.0 Phase 3 + Phase 4 worker-A
deliverables: CFG edges, resolved call graph + xref, CDEX
header parsing, the Kotlin d2 cross-check subset,
identifier-shape obfuscation indicators, the native
dependency graph detail, and native behavior indicators.

All inputs are synthetic and built in this file (or reused
from the sibling synthetic builders); no app data, no
fixture names.
"""
import importlib.util
import io
import struct
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]
                       / "scripts"))

from narlib import cdex, dexdis, formats, oat  # noqa: E402
from narlib.dex import Dex, assemble_call_graph, \
    identifier_shape_stats, kotlin_d2_stats  # noqa: E402
import test_dexdis as td  # noqa: E402
import test_android_intel as tai  # noqa: E402
import test_native as tn  # noqa: E402

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"


def _load_script(mod_name, filename):
    spec = importlib.util.spec_from_file_location(
        mod_name, SCRIPTS / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


nar_dex = _load_script("nar_dex_260", "nar-dex.py")
nar_native = _load_script("nar_native_260", "nar-native.py")

U = td.U


# ---------------------------------------------------------------
# CFG edges (R-003)

def _branch_dex():
    # 0: if-eqz v0 -> 3 ; 2: goto -> 4 ; 3: const/4 ; 4: return
    units = [U(0x38, 0), 3,
             U(0x28, 2),
             U(0x12, 0x10),
             U(0x0E)]
    return td.make_dex("039", [units])


def test_cfg_branch_edges_hand_computed():
    dex = _branch_dex()
    graph = dexdis.control_flow_graph(dex, td.first_code_off(dex))
    assert graph["status"] == "ok"
    assert [(b["start"], b["end"]) for b in graph["blocks"]] == [
        (0, 2), (2, 3), (3, 4), (4, 5)]
    assert graph["blocks"][0]["instruction_index_start"] == 0
    assert graph["blocks"][0]["instruction_index_end"] == 1
    edges = {(e["from_block"], e["to_block"], e["type"])
             for e in graph["edges"]}
    assert edges == {
        (0, 2, "branch"), (0, 1, "fallthrough"),
        (1, 3, "goto"),
        (2, 3, "fallthrough"),
        (3, None, "return-exit"),
    }, edges


def test_cfg_switch_edges():
    # 0: packed-switch v1 -> payload at 4 ; 3: return-void ;
    # payload: one case, target offset +3 (case -> addr 3)
    units = [U(0x2B, 1), 4, 0,
             U(0x0E),
             U(0x0100), 1, 0, 0, 3, 0]
    dex = td.make_dex("039", [units])
    graph = dexdis.control_flow_graph(dex, td.first_code_off(dex))
    assert graph["status"] == "ok"
    edges = {(e["from_block"], e["to_block"], e["type"])
             for e in graph["edges"]}
    assert (0, 1, "switch") in edges, edges
    assert (0, 1, "fallthrough") in edges, edges
    assert (1, None, "return-exit") in edges, edges


def test_cfg_try_handler_edges():
    # goto +2 ; nop ; return-void, try over [0,2) with a
    # catch-all handler at 2 (builder from the Phase 3 tests).
    code = tai._code_item(
        [0x0228, 0x0000, 0x000E],
        tries=[(0, 2, ([], 2))], debug_off=0)
    blob, tail = tai._dex_with_tables(["LFoo;"], [0], extra=code)
    graph = dexdis.control_flow_graph(Dex(blob), tail)
    assert graph["status"] == "ok"
    try_edges = [e for e in graph["edges"]
                 if e["type"] == "try-handler"]
    assert len(try_edges) == 1, graph["edges"]
    assert try_edges[0]["from_block"] == 0
    assert try_edges[0]["to"] == 2
    assert try_edges[0]["handler_type"] is None  # catch-all


def test_cfg_batch_requires_scope_and_listings_unchanged():
    dex = _branch_dex()
    unscoped = dexdis.cfg_batch(dex)
    assert unscoped["methods_selected"] == 0
    scoped = dexdis.cfg_batch(dex, method_pattern="m0")
    assert scoped["methods_selected"] == 1
    assert scoped["methods"][0]["edge_count"] == 5
    # The disassembly listing itself is unchanged by the CFG.
    listing = td.listing(dex, td.first_code_off(dex))
    assert listing[0][1] == "if-eqz"
    assert listing[-1][1] == "return-void"


# ---------------------------------------------------------------
# Call graph + xref (R-004)

def _two_class_dex(split=False):
    """LFoo;->main invokes a target. With split=False the
    target class LBar; is defined in the same DEX; with
    split=True the caller DEX references a class defined
    only in the second DEX returned."""
    def build(with_bar_def, with_foo=True):
        b = td.DexBuilder("039")
        foo = b.t("LFoo;")
        bar = b.t("LBar;")
        obj = b.t("Ljava/lang/Object;")
        lst = b.t("Ljava/util/List;")
        void = b.t("V")
        integer = b.t("I")
        p_v = b.proto("V", void)
        p_i = b.proto("I", integer)
        m_target = b.method(bar, p_v, "target")
        m_size = b.method(lst, p_i, "size")
        m_main = b.method(foo, p_v, "main")
        units = [
            U(0x6E, 0x10), m_target, 0x0000,   # invoke-virtual
            U(0x6E, 0x10), m_size, 0x0000,     # invoke-virtual
            U(0x0E),
        ]
        classes = []
        if with_foo:
            classes.append({"class": foo, "super": obj,
                            "direct": [(m_main, units)]})
        if with_bar_def:
            classes.append({"class": bar, "super": obj,
                            "direct": [(m_target, [U(0x0E)])]})
        b.classes = classes
        return Dex(b.build())
    if split:
        return build(False), build(True, with_foo=False)
    return build(True)


def test_call_graph_single_dex_resolution():
    dex = _two_class_dex()
    graph = assemble_call_graph([("classes.dex", dex)])
    assert graph["scope"] == "single-dex"
    assert graph["node_count"] == 2
    assert graph["edge_count"] == 2
    assert graph["resolved_edge_count"] == 1
    assert graph["unresolved_edge_count"] == 1
    assert graph["external_targets"]["distinct_count"] == 1
    sample = graph["external_targets"]["sample"]
    assert sample[0]["class"] == "Ljava/util/List;"
    assert sample[0]["method"] == "size"
    callers = {n["method"]: n for n in graph["top_callers"]}
    assert any("LFoo;->main" in m for m in callers)


def test_call_graph_xref():
    dex = _two_class_dex()
    graph = assemble_call_graph([("classes.dex", dex)],
                                xref_pattern="target")
    assert graph["xref_match_count"] == 1
    entry = graph["xref"][0]
    assert "LBar;->target" in entry["method"]
    assert entry["caller_count"] == 1
    assert any("LFoo;->main" in c for c in entry["callers"])
    assert entry["callee_count"] == 0


def test_call_graph_multi_dex_cross_resolution():
    caller_dex, def_dex = _two_class_dex(split=True)
    single = assemble_call_graph([("classes.dex", caller_dex)])
    assert single["resolved_edge_count"] == 0
    multi = assemble_call_graph(
        [("classes.dex", caller_dex),
         ("classes2.dex", def_dex)])
    assert multi["scope"] == "multi-dex"
    assert multi["resolved_edge_count"] == 1
    assert multi["resolved_cross_dex_edge_count"] == 1
    assert multi["unresolved_edge_count"] == 1


def test_nar_dex_report_has_call_graph():
    dex = _two_class_dex()
    report = nar_dex.analyze_dex("classes.dex", dex.data)
    assert report["call_graph"]["resolved_edge_count"] == 1
    assert "obfuscation_indicators" in report


# ---------------------------------------------------------------
# CDEX (R-002)

def build_cdex(feature_flags=0, owned=(0, 0)):
    """A synthetic compact DEX laid out per the public
    format: 136-byte header, then string/type/method/
    class-def sections back to back."""
    header = 136
    string_ids = (2, header)
    type_ids = (1, header + 8)
    proto_ids = (0, 0)
    field_ids = (0, 0)
    method_ids = (1, header + 12)
    class_defs = (1, header + 20)
    file_size = header + 20 + 32
    out = bytearray(file_size)
    out[0:8] = b"cdex001\x00"
    struct.pack_into("<I", out, 8, 0x11223344)      # checksum
    struct.pack_into("<I", out, 32, file_size)
    struct.pack_into("<I", out, 36, header)
    struct.pack_into("<I", out, 40, 0x12345678)     # endian
    struct.pack_into("<II", out, 56, *string_ids)
    struct.pack_into("<II", out, 64, *type_ids)
    struct.pack_into("<II", out, 72, *proto_ids)
    struct.pack_into("<II", out, 80, *field_ids)
    struct.pack_into("<II", out, 88, *method_ids)
    struct.pack_into("<II", out, 96, *class_defs)
    struct.pack_into("<II", out, 104,
                     file_size - header, header)  # data
    struct.pack_into("<IIIIII", out, 112, feature_flags,
                     0, 0, 0, owned[0], owned[1])
    return bytes(out)


def test_cdex_round_trip():
    info = cdex.parse_cdex(build_cdex(feature_flags=3,
                                      owned=(136, 188)))
    assert info["version"] == "001"
    assert info["file_size"] == 188
    assert info["header_size"] == 136
    assert info["sections"]["string_ids"] == \
        {"size": 2, "offset": 136}
    assert info["sections"]["class_defs"]["size"] == 1
    assert info["feature_flags"] == 3
    assert info["owned_data_begin"] == 136
    assert info["owned_data_end"] == 188
    assert info["payload_decoded"] is False


def test_cdex_named_errors():
    try:
        cdex.parse_cdex(b"dex\n039\x00" + b"\x00" * 200)
        raise AssertionError("no error")
    except cdex.CdexError as e:
        assert "not a compact DEX" in str(e)
    bad_version = bytearray(build_cdex())
    bad_version[4:7] = b"002"
    try:
        cdex.parse_cdex(bytes(bad_version))
        raise AssertionError("no error")
    except cdex.CdexError as e:
        assert "unsupported compact DEX version" in str(e)
    try:
        cdex.parse_cdex(build_cdex()[:100])
        raise AssertionError("no error")
    except cdex.CdexError as e:
        assert "truncated_header" in str(e)
    bad_section = bytearray(build_cdex())
    struct.pack_into("<I", bad_section, 56, 99999)
    try:
        cdex.parse_cdex(bytes(bad_section))
        raise AssertionError("no error")
    except cdex.CdexError as e:
        assert "section_out_of_bounds" in str(e)
        assert "string_ids" in str(e)


def test_cdex_formats_details(tmp_path):
    path = tmp_path / "classes.cdex"
    path.write_bytes(build_cdex())
    verdict = formats.identify(str(path))
    assert verdict["format"] == "cdex"
    header = verdict["details"]["cdex_header"]
    assert header["sections"]["method_ids"]["size"] == 1
    assert formats.validate_structure(str(path), verdict) == []


def test_cdex_oat_carving_gains_header():
    # Carrier: padding + cdex + a standard dex-shaped blob.
    import test_oat as to
    carrier = b"\x00" * 16 + build_cdex() + to.make_dex()
    hits = oat.scan_embedded_dex(carrier)
    cdex_hits = [h for h in hits if h["kind"] == "cdex"]
    assert len(cdex_hits) == 1
    hit = cdex_hits[0]
    assert hit["offset"] == 16
    assert hit["file_size"] == 188
    assert hit["cdex_header"]["feature_flags"] == 0
    carved = oat.extract_dex_from_vdex(carrier)
    cdex_entries = [c for c in carved if c[2] == "cdex"]
    assert cdex_entries[0][1] == build_cdex()


# ---------------------------------------------------------------
# Kotlin d2 cross-check subset (R-005)

def test_kotlin_d2_stats_pure():
    stats = kotlin_d2_stats(
        ["LFoo;", "bar", "()LBar;", "LExternal;", "[LFoo;"],
        "LFoo;", {"LFoo;", "LBar;"})
    assert stats["strings"] == 5
    assert stats["first_checked"] == 1
    assert stats["first_matched"] == 1
    assert stats["descriptors"] == 3
    assert stats["descriptors_in_table"] == 2
    assert stats["signature_types"] == 1
    assert stats["signature_types_in_table"] == 1


def test_kotlin_d2_in_nar_dex_report():
    dex = Dex(tai._metadata_dex())
    report = nar_dex.analyze_dex("classes.dex", dex.data)
    check = report["kotlin"]["metadata"]["d2_cross_check"]
    assert check["annotations_with_d2"] == 1
    assert check["strings"] == 1
    assert "not interpreted" in check["note"]


# ---------------------------------------------------------------
# Obfuscation indicators

def _many_class_dex(class_names, method_name):
    b = td.DexBuilder("039")
    obj = b.t("Ljava/lang/Object;")
    void = b.t("V")
    proto = b.proto("V", void)
    for cname in class_names:
        t = b.t(cname)
        midx = b.method(t, proto, method_name)
        b.classes.append({"class": t, "super": obj,
                          "direct": [(midx, [U(0x0E)])]})
    return Dex(b.build())


def test_identifier_shape_stats_small():
    dex = _many_class_dex(["La;", "Ldemo/LongName;"], "a")
    stats = identifier_shape_stats(dex)
    assert stats["classes"]["total"] == 2
    assert stats["classes"]["short_le2"] == 1
    assert stats["methods"]["single_char"] == 2


def test_obfuscation_indicators_high_and_low():
    short = [f"L{chr(97 + i % 26)}{chr(97 + (i // 26) % 26)};"
             for i in range(210)]
    obf = _many_class_dex(short, "a")
    rep = nar_dex.obfuscation_indicators(obf)
    kinds = {i["indicator"]: i for i in rep["indicators"]}
    assert "short_class_names" in kinds
    assert kinds["short_class_names"]["confidence"] in (
        "medium", "high")
    assert "verdict" not in str(rep).lower() or \
        "not an obfuscated" in rep["note"]
    long_names = [f"Ldemo/Feature{i}Screen;" for i in range(210)]
    clean = _many_class_dex(long_names, "doWork")
    rep2 = nar_dex.obfuscation_indicators(clean)
    assert all(i["confidence"] == "low"
               for i in rep2["indicators"])


# ---------------------------------------------------------------
# Native: dependency graph detail + behavior indicators

def _elf_with_imports(names):
    """ELF64 with a .dynsym of undefined symbols `names`."""
    dynstr = b"\x00" + b"".join(
        n.encode() + b"\x00" for n in names)
    offsets = {}
    pos = 1
    for n in names:
        offsets[n] = pos
        pos += len(n) + 1
    dynsym = bytearray(24 * (len(names) + 1))
    for i, n in enumerate(names):
        struct.pack_into("<IBBHQQ", dynsym, 24 * (i + 1),
                         offsets[n], 0x12, 0, 0, 0, 0)
    shstr = (b"\x00.dynsym\x00.dynstr\x00.shstrtab\x00")
    names_off = {".dynsym": 1, ".dynstr": 9, ".shstrtab": 17}
    ehdr = 64
    dynsym_off = ehdr
    dynstr_off = dynsym_off + len(dynsym)
    shstr_off = dynstr_off + len(dynstr)
    shoff = shstr_off + len(shstr)
    out = bytearray(shoff + 4 * 64)
    out[0:4] = b"\x7fELF"
    out[4] = 2
    out[5] = 1
    struct.pack_into("<H", out, 16, 3)
    struct.pack_into("<H", out, 18, 183)
    struct.pack_into("<Q", out, 40, shoff)
    struct.pack_into("<H", out, 52, ehdr)
    struct.pack_into("<H", out, 58, 64)
    struct.pack_into("<H", out, 60, 4)
    struct.pack_into("<H", out, 62, 3)
    out[dynsym_off:dynsym_off + len(dynsym)] = dynsym
    out[dynstr_off:dynstr_off + len(dynstr)] = dynstr
    out[shstr_off:shstr_off + len(shstr)] = shstr

    def shdr(idx, name, stype, off, size, link, entsize):
        struct.pack_into("<IIQQQQIIQQ", out, shoff + idx * 64,
                         names_off[name], stype, 0, 0, off,
                         size, link, 0, 1, entsize)
    shdr(1, ".dynsym", 11, dynsym_off, len(dynsym), 2, 24)
    shdr(2, ".dynstr", 3, dynstr_off, len(dynstr), 0, 0)
    shdr(3, ".shstrtab", 3, shstr_off, len(shstr), 0, 0)
    return bytes(out)


def test_behavior_indicators_planted_and_clean():
    facts = nar_native.analyze_elf(
        "libplanted.so",
        _elf_with_imports(["ptrace", "socket", "connect",
                           "fork", "dlopen", "dlsym", "memcpy"]))
    kinds = {r["indicator"]: r
             for r in facts["behavior_indicators"]}
    assert kinds["process_manipulation"]["confidence"] == "high"
    assert "ptrace" in kinds["process_manipulation"]["evidence"]
    assert "network_and_process_combination" in kinds
    assert "dynamic_code_loading" in kinds
    assert all("not a behavior verdict" in r["note"]
               for r in kinds.values())
    clean = nar_native.analyze_elf(
        "libclean.so", _elf_with_imports(["memcpy", "strlen"]))
    assert clean["behavior_indicators"] == []


def test_library_dependency_graph_detail(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lib/arm64-v8a/libfoo.so",
                    tn.build_elf64(b"libfoo.so", b"libbar.so"))
        zf.writestr("lib/arm64-v8a/libbar.so",
                    tn.build_elf64(b"libbar.so", b"libc.so"))
    apk = tmp_path / "graph.apk"
    apk.write_bytes(buf.getvalue())
    report = nar_native.analyze(str(apk))
    # Existing bundled-only graph keeps its shape.
    assert report["dependency_graph"] == {
        "arm64-v8a/libfoo.so": ["arm64-v8a/libbar.so"]}
    detail = report["library_dependency_graph"]
    assert detail["bundled_node_count"] == 2
    assert detail["external_node_count"] == 1
    assert detail["external_dependencies"] == ["libc.so"]
    ext_edges = [e for e in detail["edges"]
                 if e["to_kind"] == "external"]
    assert ext_edges == [{"from": "arm64-v8a/libbar.so",
                          "to": "libc.so",
                          "dependency": "libc.so",
                          "to_kind": "external"}]
    kinds = {n["name"]: n["kind"] for n in detail["nodes"]}
    assert kinds["libc.so"] == "external"
