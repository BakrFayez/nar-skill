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

Usage:
    python3 nar-dex.py app.apk [--json] [--out DIR]
                       [--jadx] [--baksmali]
                       [--disassemble --disasm-class TEXT
                        [--disasm-method TEXT] | --disasm-all]

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
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
from narlib import registry as reg_mod  # noqa: E402
from narlib import dexdis  # noqa: E402
from narlib import oat as oat_mod  # noqa: E402
from narlib.dex import Dex, DexError  # noqa: E402
from narlib.hashing import sha256_of  # noqa: E402

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


def load_dexes(target):
    """Yield (name, bytes) for every DEX in the target."""
    lower = target.lower()
    if lower.endswith(".dex"):
        with open(target, "rb") as fh:
            yield os.path.basename(target), fh.read()
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
        with open(target, "rb") as fh:
            yield os.path.basename(target), fh.read()
        return
    with zipfile.ZipFile(target) as zf:
        for name in sorted(zf.namelist()):
            if DEX_NAME_RE.match(name):
                yield name, zf.read(name)


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


def analyze_dex(name, data, disasm=None):
    dex = Dex(data, name)
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
        for mname, flags, code_off, kind in dex.class_methods(
                cdef["class_data_off"]):
            is_native = bool(flags & 0x0100)
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
        fields = [{"name": fname, "type": ftype, "kind": fkind}
                  for fname, ftype, _fl, fkind
                  in dex.class_fields(cdef["class_data_off"])]
        if has_metadata_type:
            for annotation in dex.class_annotations(cdef):
                if annotation["type"] != "Lkotlin/Metadata;":
                    continue
                metadata_count += 1
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
    report["classes"] = classes
    report["class_count"] = len(classes)
    report["method_count"] = sum(len(c["methods"]) for c in classes)
    report["field_count"] = sum(len(c["fields"]) for c in classes)
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
    """Version-checked external adapter run (jadx/baksmali)."""
    registry = reg_mod.load_registry()
    entry = next((t for t in registry["tools"]
                  if t["name"] == tool_name), None)
    if entry is None:
        return {"error": f"{tool_name} not in registry"}
    probe = reg_mod.probe(entry)
    if not probe["available"]:
        return {"error": f"{tool_name} not available: "
                         f"{probe['note']}",
                "install_hint": entry.get("install_hint")}
    argv = argv_builder(probe["path"], out_dir)
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"error": f"{tool_name} run failed: {e}",
                "tool_path": probe["path"],
                "tool_version": probe.get("version")}
    return {"tool_path": probe["path"],
            "tool_version": probe.get("version"),
            "exit_code": proc.returncode,
            "output_tail": (proc.stdout + proc.stderr)[-500:]}


def jadx_index(apk_path, out_dir):
    result = run_adapter(
        "jadx",
        lambda path, out: [path, "-d", out, "--no-res", apk_path],
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
    result.update({"class_files": len(classes),
                   "decompile_errors": errors,
                   "classes_sample": sorted(classes)[:50]})
    return result


def baksmali_index(dex_bytes_path, out_dir):
    result = run_adapter(
        "baksmali",
        lambda path, out: [path, "disassemble", dex_bytes_path,
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
            use_baksmali=False, disasm=None):
    report = {"tool": "nar-dex", "version": "2.5.1",
              "target": os.path.abspath(target),
              "target_sha256": sha256_of(target), "dex_files": []}
    artifact = compiled_artifact_info(target)
    if artifact is not None:
        report["compiled_artifact"] = artifact
    totals = {"classes": 0, "methods": 0, "fields": 0,
              "call_edges": 0, "native_methods": 0}
    first_dex_path = None
    for name, data in load_dexes(target):
        try:
            dex_report = analyze_dex(name, data, disasm)
        except DexError as e:
            report["dex_files"].append({"name": name,
                                        "error": str(e)})
            continue
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
    if use_jadx:
        report["jadx"] = jadx_index(
            target, os.path.join(out_dir or "nar-dex-jadx", "jadx"))
    if use_baksmali and first_dex_path:
        report["baksmali"] = baksmali_index(
            first_dex_path,
            os.path.join(out_dir or "nar-dex-smali", "smali"))
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
    args = p.parse_args(argv)
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
    try:
        report = analyze(args.target, args.out, args.jadx,
                         args.baksmali, disasm)
    except (FileNotFoundError, zipfile.BadZipFile) as e:
        print(f"nar-dex: {e}", file=sys.stderr)
        return 2
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        classes = []
        methods = []
        for d in report["dex_files"]:
            for c in d.get("classes", []):
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
