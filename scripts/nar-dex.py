#!/usr/bin/env python3
"""nar-dex.py: deep DEX intelligence (brief section 4).

Parses every DEX in an APK (or a bare .dex) with the narlib
DEX parser. Compiled artifacts are valid targets too: a
.vdex yields the DEX files it carries, a Dalvik .odex yields
its embedded DEX (quickened opcodes, labeled in the report),
an ART .oat/.odex yields any DEX still embedded in it (the
Android 8.0+ layout keeps the DEX in the companion .vdex
instead, and the report says so), and a bare .cdex is
reported as unparseable by the DEX parser rather than
misread. The parsed artifact header rides in the report as
compiled_artifact. The module reports:

- header truth: string/type/proto/field/method/class counts,
- class enumeration with hierarchy (superclass, interfaces),
- method + field enumeration, native-method inventory,
- invoke-based call edges (bounded, counted, sampled),
- const-string reference mapping (string -> referencing
  classes, capped),
- reflection and dynamic-loading evidence (Class.forName,
  DexClassLoader family, invoke-custom / method handles),
- Android entry-point classes (Activity/Service/Receiver/
  Provider/Application subclasses),
- a Kotlin feature inventory from DEX evidence (metadata,
  coroutines, Flow, serialization, suspend candidates),
  with reconstructed features labeled as inferred,
- optional adapters: jadx decompile index and baksmali
  disassembly index, each version-checked through the
  registry before it runs (--jadx / --baksmali).
- targeted bytecode disassembly with NAR's own disassembler
  (narlib.dexdis): --disassemble decodes the instruction
  stream of the methods selected by --disasm-class and/or
  --disasm-method (substring match), with every reference
  resolved. --disasm-all selects every method that has code
  and must be requested explicitly — it is the expensive
  mode. A method whose stream cannot be decoded faithfully
  is reported as failed with the precise reason and offset,
  never guessed. This is the fallback for methods jadx
  fails on: the listing is ground truth, not an
  approximation.

Performance note (2.1.0): --json output is emitted with
the compact C encoder. An indent argument forces
CPython's pure-Python encoder, which profiling on a very
large multi-DEX target showed costing more than the
analysis itself; the parsed document is field-identical
either way, and every consumer of this output parses it
as JSON. Human-readable output remains the default.

Compact shape (3.0 Part 11, DEFAULT): the document is
emitted in the compact shape — each DEX's method-id
table is stored once (parallel class/name string tables
plus [class_idx, name_idx, shorty] index rows), each
class's defined methods are [method_idx, access_flags,
kind] index rows into that table, fields are [name,
type, kind] rows, and call edges are [from_method_idx,
to_method_idx, kind_idx] rows over a per-DEX invoke-kind
legend. The document carries "dex_format": "compact".
--full restores the 2.6.2 document shape EXACTLY (every
fact as per-method / per-edge objects, no dex_format
marker); narlib.dex.expand_dex_classes /
expand_call_edges read both shapes identically, and
every in-repo consumer goes through them or through
fields both shapes share.

Usage:
    python3 nar-dex.py app.apk [--json] [--out DIR]
                       [--compact | --full]
                       [--jadx] [--baksmali]
                       [--disassemble --disasm-class TEXT
                        [--disasm-method TEXT] | --disasm-all]

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import container as container_mod  # noqa: E402
from narlib import registry as reg_mod  # noqa: E402
from narlib import dexdis  # noqa: E402
from narlib import oat as oat_mod  # noqa: E402
from narlib import dex as dex_mod  # noqa: E402
from narlib import cdex as cdex_mod  # noqa: E402
from narlib.dex import Dex, DexError  # noqa: E402
from narlib.hashing import sha256_of  # noqa: E402
from narlib.safearchive import (  # noqa: E402
    MEMBER_READ_CAP_BYTES, read_member_capped)

DEX_NAME_RE = re.compile(r"^(base/dex/)?classes\d*\.dex$")
ENTRY_SUPERS = (
    "Landroid/app/Activity;", "Landroid/app/Service;",
    "Landroid/content/BroadcastReceiver;",
    "Landroid/content/ContentProvider;",
    "Landroid/app/Application;", "Landroidx/core/app/",
)
REFLECTION_TYPES = (
    "Ljava/lang/Class;", "Ljava/lang/reflect/Method;",
    "Ljava/lang/reflect/Field;", "Ljava/lang/reflect/Constructor;",
)
LOADER_TYPES = (
    "Ldalvik/system/DexClassLoader;",
    "Ldalvik/system/PathClassLoader;",
    "Ldalvik/system/InMemoryDexClassLoader;",
    "Ldalvik/system/BaseDexClassLoader;",
    "Ljava/lang/ClassLoader;",
)
REFLECTION_METHOD_NAMES = {"forName", "loadClass", "defineClass",
                           "getMethod", "getDeclaredMethod",
                           "getField", "getDeclaredField",
                           "newInstance", "invoke"}
MAX_CALL_EDGES = 200000
MAX_STRING_CLASSES = 5000
# @Metadata "k" element values, per the public Kotlin
# metadata format: the kind of declaration the annotated
# class represents.
KOTLIN_METADATA_KINDS = {
    1: "class", 2: "file facade", 3: "synthetic class",
    4: "multi-file class facade", 5: "multi-file class part",
}


def _read_file_capped(path):
    """Whole-file read under the member cap; None when
    the file is over it (the caller records the refusal
    instead of materializing an unbounded blob, D-05)."""
    if os.path.getsize(path) > MEMBER_READ_CAP_BYTES:
        return None
    with open(path, "rb") as fh:
        return fh.read()


def load_dexes(target):
    """Yield (name, bytes) for every DEX in the target.

    A member or file over the read cap yields (name,
    None): the refusal is recorded by the consumer as a
    labeled error entry, never silently skipped and
    never materialized (stability audit D-05)."""
    lower = target.lower()
    if lower.endswith(".dex"):
        yield os.path.basename(target), _read_file_capped(
            target)
        return
    if lower.endswith(".vdex"):
        with open(target, "rb") as fh:
            data = fh.read()
        for entry_name, blob, _kind in \
                oat_mod.extract_dex_from_vdex(data):
            yield entry_name, blob
        return
    if lower.endswith(".odex") or lower.endswith(".oat"):
        with open(target, "rb") as fh:
            data = fh.read()
        if data.startswith(oat_mod.ODEX_MAGIC):
            info = oat_mod.parse_odex_dalvik(
                data, os.path.basename(target))
            yield os.path.basename(target) + ":embedded.dex", \
                info["dex"]
            return
        # ART OAT (including the Android 8.0+ *.odex form):
        # carve any DEX still embedded in the file. From
        # Android 8.0 the DEX lives in the companion .vdex
        # instead, so an empty yield here is the honest
        # result; analyze() labels it via compiled_artifact.
        for hit in oat_mod.scan_embedded_dex(data):
            if hit["kind"] == "dex":
                yield (f"embedded@{hit['offset']}.dex",
                       data[hit["offset"]:
                            hit["offset"] + hit["file_size"]])
        return
    if lower.endswith(".cdex"):
        yield os.path.basename(target), _read_file_capped(
            target)
        return
    with zipfile.ZipFile(target) as zf:
        for name in sorted(zf.namelist()):
            if DEX_NAME_RE.match(name):
                try:
                    yield name, read_member_capped(zf, name)
                except ValueError:
                    yield name, None


def compiled_artifact_info(target):
    """Parsed header of a compiled-artifact target, or None.

    For .vdex/.odex/.oat/.art targets the header facts are
    themselves report evidence (versions, dex counts, where
    the DEX lives), independent of whether any DEX could be
    carved out of the file."""
    lower = target.lower()
    if not lower.endswith((".vdex", ".odex", ".oat", ".art")):
        return None
    with open(target, "rb") as fh:
        data = fh.read()
    name = os.path.basename(target)
    try:
        if lower.endswith(".vdex"):
            return {"kind": "vdex",
                    **oat_mod.parse_vdex(data, name)}
        if lower.endswith(".art"):
            return {"kind": "art",
                    **oat_mod.parse_art_image(data, name)}
        if data.startswith(oat_mod.ODEX_MAGIC):
            info = oat_mod.parse_odex_dalvik(data, name)
            info.pop("dex", None)
            return {"kind": "odex-dalvik", **info}
        info = oat_mod.parse_oat(data, name)
        companion = None
        vdex_path = os.path.splitext(target)[0] + ".vdex"
        if os.path.isfile(vdex_path):
            companion = vdex_path
        return {"kind": "oat", **info,
                "companion_vdex": companion,
                "note": ("DEX bytes live in the companion .vdex "
                         "on Android 8.0+" if companion else
                         "no companion .vdex found beside this "
                         "file; on Android 8.0+ the DEX lives "
                         "in the companion .vdex, not in the "
                         "OAT file itself")}
    except oat_mod.OatError as e:
        return {"kind": "unparseable", "error": str(e)}


def obfuscation_indicators(dex):
    """Evidence-based obfuscation pattern indicators for one
    DEX: identifier-shape statistics with confidence-labeled
    indicator records. Indicators only — a short-name ratio
    is a pattern signal (minified/shrunk builds produce it,
    but so do some hand-written codebases), never an
    obfuscated/not verdict."""
    stats = dex_mod.identifier_shape_stats(dex)
    indicators = []
    classes = stats["classes"]
    methods = stats["methods"]
    if classes["total"] >= 200 and classes["short_ratio"] >= 0.3:
        indicators.append({
            "indicator": "short_class_names",
            "value": classes["short_ratio"],
            "confidence": "high" if classes["short_ratio"] >= 0.5
                          else "medium",
            "evidence": f"{classes['short_le2']} of "
                        f"{classes['total']} defined classes "
                        "have simple names of <= 2 characters"})
    if methods["total"] >= 200 and methods["short_ratio"] >= 0.3:
        indicators.append({
            "indicator": "short_method_names",
            "value": methods["short_ratio"],
            "confidence": "high" if methods["short_ratio"] >= 0.5
                          else "medium",
            "evidence": f"{methods['short_le2']} of "
                        f"{methods['total']} defined methods "
                        "have names of <= 2 characters"})
    if not indicators:
        indicators.append({
            "indicator": "short_identifier_names",
            "value": max(classes["short_ratio"],
                         methods["short_ratio"]),
            "confidence": "low",
            "evidence": "class/method counts and short-name "
                        "ratios do not meet the reporting "
                        "thresholds (classes "
                        f"{classes['total']} at "
                        f"{classes['short_ratio']}, methods "
                        f"{methods['total']} at "
                        f"{methods['short_ratio']}) — no "
                        "short-name pattern indicator"})
    return {"identifier_shapes": stats,
            "indicators": indicators,
            "note": "Indicators with confidence only, from "
                    "identifier shapes the parser observes; "
                    "not an obfuscated / not-obfuscated verdict."}


def analyze_dex(name, data, disasm=None, cfg=None, dex_obj=None,
                compact=True):
    dex = dex_obj if dex_obj is not None else Dex(data, name)
    strings = dex.strings()
    types = dex.types()
    type_set = set(types)
    report = {
        "name": name,
        "dex_version": dex.version,
        "header_counts": {
            "strings": dex.string_ids_size,
            "types": dex.type_ids_size,
            "protos": dex.proto_ids_size,
            "fields": dex.field_ids_size,
            "methods": dex.method_ids_size,
            "class_defs": dex.class_defs_size,
        },
    }
    classes = []
    call_edges = []
    invoke_kinds = []
    invoke_kind_idx = {}
    edge_count = 0
    string_ref_classes = {}
    native_methods = []
    entry_points = []
    dynamic_ops = 0
    reflection_method_refs = set()
    suspend_candidates = 0
    methods_with_code = 0
    methods_with_tries = 0
    try_items_total = 0
    handler_entries_total = 0
    methods_with_debug = 0
    metadata_count = 0
    metadata_samples = []
    d2_agg = {"annotations_with_d2": 0, "strings": 0,
              "first_checked": 0, "first_matched": 0,
              "descriptors": 0, "descriptors_in_table": 0,
              "signature_types": 0, "signature_types_in_table": 0}
    # The @Metadata annotation type lives in the TYPE table
    # (descriptor Lkotlin/Metadata;); the bare string
    # "kotlin/Metadata" appears in the string table only when
    # something references it as a literal, which release
    # builds usually do not — gating on it under-reports.
    has_metadata_type = "Lkotlin/Metadata;" in type_set
    super_map = {}
    defs = dex.class_defs()
    for cdef in defs:
        if cdef["superclass"]:
            super_map[cdef["class"]] = cdef["superclass"]
    for cdef in defs:
        cls = cdef["class"]
        methods = []
        for caller_idx, mname, flags, code_off, kind in \
                dex.class_methods_indexed(cdef["class_data_off"]):
            is_native = bool(flags & 0x0100)
            if compact:
                methods.append([caller_idx, flags, kind])
            else:
                methods.append({"name": mname, "kind": kind,
                                "native": is_native,
                                "access_flags": flags})
            if is_native:
                native_methods.append({"class": cls, "name": mname})
            if code_off:
                methods_with_code += 1
                try:
                    cinfo = dex.code_item_info(code_off)
                except Exception:
                    cinfo = None
                if cinfo:
                    if cinfo["has_debug_info"]:
                        methods_with_debug += 1
                    if cinfo["tries"]:
                        methods_with_tries += 1
                        try_items_total += len(cinfo["tries"])
                        handler_entries_total += sum(
                            len(t["handlers"])
                            + (1 if t["catch_all_addr"] is not None
                               else 0)
                            for t in cinfo["tries"])
                scan = dex.scan_code(code_off)
                dynamic_ops += len(scan["dynamic"])
                for midx, ikind in scan["invokes"]:
                    edge_count += 1
                    if len(call_edges) < MAX_CALL_EDGES:
                        if compact:
                            if midx < dex.method_ids_size:
                                kidx = invoke_kind_idx.get(ikind)
                                if kidx is None:
                                    kidx = len(invoke_kinds)
                                    invoke_kind_idx[ikind] = kidx
                                    invoke_kinds.append(ikind)
                                call_edges.append(
                                    [caller_idx, midx, kidx])
                        else:
                            ref = dex.method_full(midx)
                            if ref:
                                call_edges.append({
                                    "from_class": cls,
                                    "from_method": mname,
                                    "to_class": ref[0],
                                    "to_method": ref[1],
                                    "kind": ikind})
                for sidx in scan["string_refs"]:
                    if sidx < len(strings):
                        key = strings[sidx]
                        bucket = string_ref_classes.setdefault(
                            key, set())
                        if len(bucket) < 50:
                            bucket.add(cls)
        if compact:
            fields = [[fname, ftype, fkind]
                      for fname, ftype, _fl, fkind
                      in dex.class_fields(cdef["class_data_off"])]
        else:
            fields = [{"name": fname, "type": ftype, "kind": fkind}
                      for fname, ftype, _fl, fkind
                      in dex.class_fields(cdef["class_data_off"])]
        if has_metadata_type:
            for annotation in dex.class_annotations(cdef):
                if annotation["type"] != "Lkotlin/Metadata;":
                    continue
                metadata_count += 1
                elements_all = annotation.get("elements") or {}
                if isinstance(elements_all.get("d2"), list):
                    d2_agg["annotations_with_d2"] += 1
                    per = dex_mod.kotlin_d2_stats(
                        elements_all["d2"], cls, type_set)
                    for key in per:
                        d2_agg[key] += per[key]
                if len(metadata_samples) < 50:
                    elements = annotation.get("elements") or {}
                    mv = elements.get("mv")
                    kind = elements.get("k")
                    metadata_samples.append({
                        "class": cls,
                        "metadata_version": (
                            ".".join(str(x) for x in mv)
                            if isinstance(mv, list) else mv),
                        "kind": kind,
                        "kind_name": KOTLIN_METADATA_KINDS.get(kind)
                        if isinstance(kind, int) else None})
        classes.append({
            "class": cls, "superclass": cdef["superclass"],
            "interfaces": cdef["interfaces"],
            "methods": methods, "fields": fields})
        sup = cdef["superclass"] or ""
        if any(sup.startswith(prefix) for prefix in ENTRY_SUPERS):
            entry_points.append({"class": cls, "via_superclass": sup})
    # Suspend candidates: methods whose last parameter is a
    # Continuation (the compiler shape of a suspend function).
    for idx in range(dex.method_ids_size):
        full = dex.method_full(idx)
        if full and full[3] and full[3][-1] == \
                "Lkotlin/coroutines/Continuation;":
            suspend_candidates += 1
    for idx in range(dex.method_ids_size):
        ref = dex.method_ref(idx)
        if ref and ref[1] in REFLECTION_METHOD_NAMES and (
                ref[0] in REFLECTION_TYPES or ref[0] in LOADER_TYPES
                or ref[0].startswith("Ljava/lang/reflect/")):
            reflection_method_refs.add(f"{ref[0]}->{ref[1]}")
    if compact:
        # The method-id table, stored once: parallel
        # class/name string tables (first-use order over
        # the method-id index space) plus one
        # [class_idx, name_idx, shorty] row per method id.
        # Class method rows and call edges above reference
        # it by index instead of repeating the strings.
        tbl_classes, tbl_names, tbl_ids = [], [], []
        tbl_class_idx, tbl_name_idx = {}, {}
        for idx in range(dex.method_ids_size):
            ref = dex.method_ref(idx)
            mcls, mname, mshorty = ref if ref else ("?", "?", "")
            ci = tbl_class_idx.get(mcls)
            if ci is None:
                ci = len(tbl_classes)
                tbl_class_idx[mcls] = ci
                tbl_classes.append(mcls)
            ni = tbl_name_idx.get(mname)
            if ni is None:
                ni = len(tbl_names)
                tbl_name_idx[mname] = ni
                tbl_names.append(mname)
            tbl_ids.append([ci, ni, mshorty])
        report["method_table"] = {
            "classes": tbl_classes, "names": tbl_names,
            "ids": tbl_ids}
    report["classes"] = classes
    report["class_count"] = len(classes)
    report["method_count"] = sum(len(c["methods"]) for c in classes)
    report["field_count"] = sum(len(c["fields"]) for c in classes)
    if compact:
        report["invoke_kinds"] = invoke_kinds
    report["call_edges"] = call_edges
    report["call_edge_count"] = edge_count
    report["call_edges_truncated"] = edge_count > len(call_edges)
    report["native_methods"] = native_methods
    report["entry_points"] = entry_points
    top_strings = sorted(string_ref_classes.items(),
                         key=lambda kv: -len(kv[1]))
    report["string_references"] = [
        {"string": s[:200], "referencing_classes": len(cs),
         "sample_classes": sorted(cs)[:5]}
        for s, cs in top_strings[:MAX_STRING_CLASSES]]
    report["reflection"] = {
        "reflection_types_present": [t for t in REFLECTION_TYPES
                                     if t in type_set],
        "loader_types_present": [t for t in LOADER_TYPES
                                 if t in type_set],
        "reflection_method_refs": sorted(reflection_method_refs),
        "invoke_custom_ops": dynamic_ops,
    }
    kotlin_types = [t for t in type_set if t.startswith("Lkotlin")]
    if disasm is not None:
        report["disassembly"] = dexdis.disassemble(
            dex,
            class_pattern=disasm.get("class_pattern"),
            method_pattern=disasm.get("method_pattern"),
            want_all=disasm.get("all", False),
            limit=disasm.get("limit", 500))
    if cfg is not None:
        report["cfg"] = dexdis.cfg_batch(
            dex,
            class_pattern=cfg.get("class_pattern"),
            method_pattern=cfg.get("method_pattern"),
            want_all=cfg.get("all", False),
            limit=cfg.get("limit", 100))
    report["call_graph"] = dex_mod.assemble_call_graph(
        [(name, dex)])
    report["obfuscation_indicators"] = obfuscation_indicators(dex)
    report["kotlin"] = {
        "metadata_annotation_present": has_metadata_type,
        "kotlin_type_count": len(kotlin_types),
        "coroutines_types": len([t for t in kotlin_types
                                 if t.startswith(
                                     "Lkotlinx/coroutines/")]),
        "flow_types": len([t for t in type_set
                           if "kotlinx/coroutines/flow" in t]),
        "serialization_types": len([t for t in type_set
                                    if t.startswith(
                                        "Lkotlinx/serialization/")]),
        "suspend_candidates": suspend_candidates,
        "metadata": {
            "classes_with_metadata": metadata_count,
            "d2_cross_check": {
                **d2_agg,
                "first_entry_agreement": round(
                    d2_agg["first_matched"]
                    / d2_agg["first_checked"], 4)
                if d2_agg["first_checked"] else None,
                "descriptor_agreement": round(
                    d2_agg["descriptors_in_table"]
                    / d2_agg["descriptors"], 4)
                if d2_agg["descriptors"] else None,
                "signature_type_agreement": round(
                    d2_agg["signature_types_in_table"]
                    / d2_agg["signature_types"], 4)
                if d2_agg["signature_types"] else None,
                "note": "Verified subset only: descriptor-"
                        "shaped d2 strings cross-checked "
                        "against this DEX's type table. The "
                        "d1 protobuf payload is not "
                        "interpreted, and non-descriptor d2 "
                        "strings are counted, not decoded.",
            },
            "samples": metadata_samples,
            "note": "metadata version (mv) and declaration "
                    "kind (k) are parsed from the @Metadata "
                    "annotation payload; kind names follow "
                    "the public Kotlin metadata format. "
                    "Data/sealed/companion classification of "
                    "individual classes is not claimed.",
        },
        "note": "Feature presence is observed from type/method "
                "tables and @Metadata payloads where present.",
    }
    report["try_catch"] = {
        "methods_with_code": methods_with_code,
        "methods_with_tries": methods_with_tries,
        "try_items": try_items_total,
        "handler_entries": handler_entries_total,
        "methods_with_debug_info": methods_with_debug,
    }
    return report


def run_adapter(tool_name, argv_builder, out_dir, timeout=1800):
    """Version-checked external adapter run (jadx/baksmali).

    The argv is built from the registry's launch prefix,
    never from the raw probe path: a tool resolved through
    a jar route carries a "jar:"-prefixed path that must be
    launched as [java, -jar, <jar>] (the P6-01 defect class
    — nar-network's NSC seam — existed here too: the raw
    path was spawned literally). The probe's identity
    verdict rides along (tool_identity /
    identity_rejections) so the decompile Fallback Record
    can state whether the tool that ran was validated as
    the tool it claims to be (field round F-04)."""
    registry = reg_mod.load_registry()
    entry = next((t for t in registry["tools"]
                  if t["name"] == tool_name), None)
    if entry is None:
        return {"error": f"{tool_name} not in registry"}
    probe = reg_mod.probe(entry)
    if not probe["available"]:
        result = {"error": f"{tool_name} not available: "
                           f"{probe['note']}",
                  "install_hint": entry.get("install_hint")}
        if probe.get("identity_rejections"):
            result["identity_rejections"] = \
                probe["identity_rejections"]
        return result
    prefix = reg_mod.launch_prefix(probe)
    if prefix is None:
        return {"error": f"{tool_name} resolved to "
                         f"{probe['path']} but no launch "
                         "prefix could be built (a jar tool "
                         "needs a Java runtime)",
                "tool_path": probe["path"],
                "install_hint": entry.get("install_hint")}
    argv = argv_builder(prefix, out_dir)
    identity = {}
    if probe.get("identity"):
        identity["tool_identity"] = probe["identity"]
    if probe.get("identity_rejections"):
        identity["identity_rejections"] = \
            probe["identity_rejections"]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"error": f"{tool_name} run failed: {e}",
                "tool_path": probe["path"],
                "tool_version": probe.get("version"),
                **identity}
    return {"tool_path": probe["path"],
            "tool_version": probe.get("version"),
            "exit_code": proc.returncode,
            "output_tail": (proc.stdout + proc.stderr)[-500:],
            **identity}


def jadx_index(apk_path, out_dir):
    result = run_adapter(
        "jadx",
        lambda prefix, out: prefix + ["-d", out, "--no-res",
                                      apk_path],
        out_dir)
    if "error" in result:
        return result
    classes = []
    errors = 0
    for root, _dirs, files in os.walk(out_dir):
        for name in files:
            if name.endswith(".java"):
                rel = os.path.relpath(os.path.join(root, name),
                                      out_dir)
                classes.append(rel)
    m = re.search(r"finished with errors, count: (\d+)",
                  result.get("output_tail", ""))
    if m:
        errors = int(m.group(1))
    if result.get("exit_code") not in (0, None) \
            and not classes and not m:
        # A hard jadx failure (bad input, broken runtime)
        # previously walked the empty output directory
        # and reported class_files 0 / decompile_errors 0
        # — a failed run dressed as a clean empty index
        # (stability audit D-03). jadx's legitimate
        # partial success (exit 1 WITH the errors marker
        # and classes on disk) still indexes normally.
        return {"error": f"jadx run failed "
                         f"(exit {result.get('exit_code')})",
                "tool_path": result.get("tool_path"),
                "tool_version": result.get("tool_version"),
                "tool_identity": result.get("tool_identity"),
                "identity_rejections":
                    result.get("identity_rejections"),
                "exit_code": result.get("exit_code"),
                "output_tail": result.get("output_tail")}
    result.update({"class_files": len(classes),
                   "decompile_errors": errors,
                   "classes_sample": sorted(classes)[:50]})
    return result


def baksmali_index(dex_bytes_path, out_dir):
    result = run_adapter(
        "baksmali",
        lambda prefix, out: prefix + ["disassemble",
                                      dex_bytes_path,
                                      "-o", out],
        out_dir)
    if "error" in result:
        return result
    count = 0
    for _root, _dirs, files in os.walk(out_dir):
        count += sum(1 for f in files if f.endswith(".smali"))
    result.update({"smali_files": count})
    return result


def analyze(target, out_dir=None, use_jadx=False,
            use_baksmali=False, disasm=None, cfg=None,
            xref=None, merge_splits=True, compact=True):
    report = {"tool": "nar-dex", "version": "3.0.3",
              "target": os.path.abspath(target),
              "target_sha256": sha256_of(target), "dex_files": []}
    if compact:
        report["dex_format"] = "compact"
    artifact = compiled_artifact_info(target)
    if artifact is not None:
        report["compiled_artifact"] = artifact
    totals = {"classes": 0, "methods": 0, "fields": 0,
              "call_edges": 0, "native_methods": 0}
    first_dex_path = None
    dex_entries = []
    # Container inputs resolve through narlib.container:
    # the DEX set is the base APK's DEXes plus every merged
    # split's DEXes (split DEXes are named
    # "<archive>:<member>" so their provenance is explicit
    # and the cross-DEX call graph spans the whole set).
    resolved = None
    dex_iter = load_dexes(target)
    if merge_splits and os.path.isfile(target) and \
            container_mod.detect_container(target) in \
            container_mod.CONTAINER_KINDS + ("apk",):
        # A plain APK resolves too, but the resolution is
        # adopted only when it actually assembled a set (a
        # container, or a loose split set merged by sibling
        # discovery — field round F-01); an ordinary lone
        # APK keeps the single-archive path unchanged.
        _candidate = container_mod.resolve_target(target)
        if _candidate.is_container or _candidate.splits:
            resolved = _candidate
        else:
            _candidate.cleanup()
    if resolved is not None:
        def _merged_dexes(_resolved=resolved):
            for _name, _data in load_dexes(_resolved.base):
                yield _name, _data
            for _split in _resolved.splits:
                _prefix = os.path.basename(_split["path"]) + ":"
                for _name, _data in load_dexes(_split["path"]):
                    yield _prefix + _name, _data

        dex_iter = _merged_dexes()
    for name, data in dex_iter:
        if data is None:
            report["dex_files"].append({
                "name": name,
                "error": "DEX exceeds the "
                         f"{MEMBER_READ_CAP_BYTES}-byte "
                         "read cap; not loaded"})
            continue
        if data[:4] == b"cdex":
            # Compact DEX is identified and its header
            # parsed by the cdex reader; it is NOT fed to
            # the standard DEX parser to fail with a
            # misleading magic error (stability audit
            # A-16). Payload decoding remains out of
            # scope, as the cdex module states.
            record = {"name": name, "format": "compact-dex",
                      "size_bytes": len(data),
                      "note": "compact DEX (cdex) payload "
                              "identified; header facts "
                              "follow, payload not decoded"}
            try:
                record["cdex_header"] = cdex_mod.parse_cdex(
                    data, name)
            except cdex_mod.CdexError as e:
                record["error"] = f"cdex header: {e}"
            report["dex_files"].append(record)
            continue
        try:
            dex_obj = Dex(data, name)
            dex_report = analyze_dex(name, data, disasm, cfg,
                                     dex_obj=dex_obj,
                                     compact=compact)
        except DexError as e:
            report["dex_files"].append({"name": name,
                                        "error": str(e)})
            continue
        dex_entries.append((name, dex_obj))
        report["dex_files"].append(dex_report)
        totals["classes"] += dex_report["class_count"]
        totals["methods"] += dex_report["method_count"]
        totals["fields"] += dex_report["field_count"]
        totals["call_edges"] += dex_report["call_edge_count"]
        totals["native_methods"] += len(
            dex_report["native_methods"])
        if out_dir and first_dex_path is None:
            os.makedirs(out_dir, exist_ok=True)
            first_dex_path = os.path.join(out_dir, "first.dex")
            with open(first_dex_path, "wb") as fh:
                fh.write(data)
    report["totals"] = totals
    if dex_entries:
        # Cross-DEX call graph over the whole set: resolution
        # is attempted across every DEX of the target and
        # labeled by scope (single-dex / multi-dex).
        report["call_graph"] = dex_mod.assemble_call_graph(
            dex_entries, xref_pattern=xref)
    if resolved is not None:
        report["container"] = resolved.container_block()
    jadx_target = resolved.base if resolved is not None \
        else target
    if use_jadx:
        report["jadx"] = jadx_index(
            jadx_target,
            os.path.join(out_dir or "nar-dex-jadx", "jadx"))
    if use_baksmali and first_dex_path:
        report["baksmali"] = baksmali_index(
            first_dex_path,
            os.path.join(out_dir or "nar-dex-smali", "smali"))
    if resolved is not None:
        resolved.cleanup()
    return report


def human(report):
    print(f"NAR DEX intelligence: "
          f"{os.path.basename(report['target'])}")
    print("=" * 60)
    artifact = report.get("compiled_artifact")
    if artifact:
        kind = artifact.get("kind")
        if kind == "vdex":
            print(f"Compiled artifact: VDEX "
                  f"{artifact.get('vdex_version')}, "
                  f"{artifact.get('number_of_dex_files')} "
                  "dex file(s) declared")
        elif kind == "oat":
            print(f"Compiled artifact: OAT "
                  f"{artifact.get('oat_version')} "
                  f"({artifact.get('instruction_set_name')}), "
                  f"{artifact.get('dex_file_count')} dex "
                  "file(s) declared")
            if artifact.get("note"):
                print(f"    {artifact['note']}")
        elif kind == "odex-dalvik":
            print(f"Compiled artifact: Dalvik ODEX "
                  f"{artifact.get('odex_version')} (embedded "
                  "DEX carries quickened opcodes)")
        elif kind == "art":
            print(f"Compiled artifact: ART image "
                  f"{artifact.get('art_version')}")
        elif kind == "unparseable":
            print(f"Compiled artifact: unparseable "
                  f"({artifact.get('error')})")
    for d in report["dex_files"]:
        if d.get("error"):
            print(f"- {d['name']}: ERROR {d['error']}")
            continue
        hc = d["header_counts"]
        print(f"- {d['name']} (DEX {d['dex_version']}): "
              f"{d['class_count']} classes, "
              f"{d['method_count']} methods, "
              f"{d['field_count']} fields "
              f"(header: {hc['methods']} method ids)")
        print(f"    call edges: {d['call_edge_count']:,}; "
              f"native methods: {len(d['native_methods'])}; "
              f"entry points: {len(d['entry_points'])}")
        tc = d.get("try_catch") or {}
        if tc:
            print(f"    try/catch: {tc['methods_with_tries']} of "
                  f"{tc['methods_with_code']} coded methods, "
                  f"{tc['try_items']} try items, "
                  f"{tc['handler_entries']} handler entries; "
                  f"debug info on {tc['methods_with_debug_info']} "
                  f"methods")
        r = d["reflection"]
        print(f"    reflection types: "
              f"{len(r['reflection_types_present'])}, loaders: "
              f"{len(r['loader_types_present'])}, invoke-custom: "
              f"{r['invoke_custom_ops']}")
        k = d["kotlin"]
        if k["kotlin_type_count"]:
            print(f"    Kotlin: {k['kotlin_type_count']} types, "
                  f"coroutines {k['coroutines_types']}, flow "
                  f"{k['flow_types']}, serialization "
                  f"{k['serialization_types']}, suspend candidates "
                  f"{k['suspend_candidates']}")
    t = report["totals"]
    print(f"Totals: {t['classes']} classes, {t['methods']} "
          f"methods, {t['fields']} fields, {t['call_edges']:,} "
          f"call edges, {t['native_methods']} native methods")
    cg = report.get("call_graph")
    if cg:
        ext_distinct = cg["external_targets"]["distinct_count"]
        print(f"Call graph ({cg['scope']}): {cg['node_count']} "
              f"defined methods, {cg['edge_count']:,} invoke "
              f"edges, {cg['resolved_edge_count']:,} resolved, "
              f"{cg['unresolved_edge_count']:,} unresolved/"
              f"external ({ext_distinct} distinct external "
              "targets)")
    for d in report["dex_files"]:
        cfg_rep = d.get("cfg")
        if cfg_rep:
            print(f"CFG ({d['name']}, {cfg_rep['mode']}): "
                  f"{len(cfg_rep['methods'])} graph(s), "
                  f"{cfg_rep['methods_selected']} selected, "
                  f"{cfg_rep['methods_failed']} failed")
    for d in report["dex_files"]:
        dis = d.get("disassembly")
        if not dis:
            continue
        print(f"Disassembly ({d['name']}, {dis['mode']}): "
              f"{dis['methods_decoded']} decoded, "
              f"{dis['methods_failed']} failed, "
              f"{dis['methods_selected']} selected of "
              f"{dis['methods_with_code']} methods with code")
        for f in dis["failures"][:10]:
            print(f"  FAILED {f['class']}->{f['signature']}: "
                  f"{f['reason']} (at {f['offset_units']:#06x})")
        if dis["mode"] == "targeted":
            for m in dis["methods"]:
                print(f"  {m['class']}->{m['signature']}")
                for e in m["instructions"]:
                    print(f"    {e['addr']:04x}: {e['text']}")
    for key in ("jadx", "baksmali"):
        if key in report:
            print(f"{key}: {json.dumps(report[key])[:300]}")


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Deep DEX intelligence: enumeration, call "
                    "edges, reflection/dynamic evidence, Kotlin "
                    "inventory, targeted bytecode disassembly, "
                    "optional jadx/baksmali adapters.")
    p.add_argument("target", help="path to an .apk, .dex, "
                                  ".vdex, .odex, .oat, or "
                                  ".cdex file")
    p.add_argument("--json", action="store_true")
    p.add_argument("--compact", action="store_true",
                   help="emit the compact dex shape (3.0 "
                        "Part 11; this is the default)")
    p.add_argument("--full", action="store_true",
                   help="emit the full 2.6.2 dex shape "
                        "exactly (per-method / per-edge "
                        "objects; larger)")
    p.add_argument("--out", metavar="DIR",
                   help="write classes/methods companion JSON here")
    p.add_argument("--jadx", action="store_true",
                   help="also run the jadx adapter (version-checked)")
    p.add_argument("--baksmali", action="store_true",
                   help="also run the baksmali adapter on the "
                        "first DEX")
    p.add_argument("--disassemble", action="store_true",
                   help="decode method bytecode with the "
                        "narlib disassembler; needs a scope: "
                        "--disasm-class and/or --disasm-method, "
                        "or --disasm-all")
    p.add_argument("--disasm-class", metavar="TEXT",
                   help="only disassemble methods of classes "
                        "whose descriptor contains TEXT")
    p.add_argument("--disasm-method", metavar="TEXT",
                   help="only disassemble methods whose name "
                        "contains TEXT")
    p.add_argument("--disasm-all", action="store_true",
                   help="disassemble every method that has "
                        "code (expensive; explicit opt-in)")
    p.add_argument("--disasm-limit", type=int, default=500,
                   metavar="N",
                   help="cap on method listings emitted "
                        "(counts stay complete; default 500)")
    p.add_argument("--cfg", action="store_true",
                   help="also build control-flow graphs for "
                        "the methods selected by the "
                        "--disasm-class / --disasm-method / "
                        "--disasm-all scope")
    p.add_argument("--xref", metavar="TEXT",
                   help="include caller/callee xrefs for "
                        "defined methods whose label contains "
                        "TEXT in the call-graph section")
    args = p.parse_args(argv)
    if os.path.isdir(args.target):
        # Directory targets are an input error (exit 2) on
        # every platform. This cannot be left to the open()
        # below: POSIX raises IsADirectoryError for a
        # directory open (caught under the try), but Windows
        # raises PermissionError instead, which would escape
        # as a traceback and the wrong exit code.
        print(f"nar-dex: is a directory: {args.target}",
              file=sys.stderr)
        return 2
    disasm = None
    if args.disassemble:
        if not (args.disasm_class or args.disasm_method
                or args.disasm_all):
            p.error("--disassemble needs a scope: "
                    "--disasm-class, --disasm-method, or "
                    "--disasm-all")
        disasm = {"class_pattern": args.disasm_class,
                  "method_pattern": args.disasm_method,
                  "all": args.disasm_all,
                  "limit": args.disasm_limit}
    cfg = None
    if args.cfg:
        if not (args.disasm_class or args.disasm_method
                or args.disasm_all):
            p.error("--cfg needs a scope: --disasm-class, "
                    "--disasm-method, or --disasm-all")
        cfg = {"class_pattern": args.disasm_class,
               "method_pattern": args.disasm_method,
               "all": args.disasm_all,
               "limit": args.disasm_limit}
    try:
        report = analyze(args.target, args.out, args.jadx,
                         args.baksmali, disasm, cfg, args.xref,
                         compact=not args.full)
    except (FileNotFoundError, IsADirectoryError,
            zipfile.BadZipFile) as e:
        print(f"nar-dex: {e}", file=sys.stderr)
        return 2
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        classes = []
        methods = []
        for d in report["dex_files"]:
            # The sidecars keep their 2.6.2 shape in both
            # modes: compact class rows are expanded through
            # the method table (narlib.dex), full rows pass
            # through unchanged.
            for c in dex_mod.expand_dex_classes(d):
                classes.append({"dex": d["name"], **{
                    k: c[k] for k in ("class", "superclass",
                                      "interfaces")}})
                for m in c["methods"]:
                    methods.append({"dex": d["name"],
                                    "class": c["class"], **m})
        with open(os.path.join(args.out, "classes.json"),
                  "w", encoding="utf-8") as fh:
            json.dump({"classes": classes}, fh, indent=1)
        with open(os.path.join(args.out, "methods.json"),
                  "w", encoding="utf-8") as fh:
            json.dump({"methods": methods}, fh, indent=1)
    if args.json:
        print(json.dumps(report))
    else:
        human(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
