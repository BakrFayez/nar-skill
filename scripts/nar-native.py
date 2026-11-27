#!/usr/bin/env python3
"""nar-native.py: deep native library / ELF intelligence
(brief section 6).

For every .so in an APK (or a bare .so), parses the ELF with
the narlib parser and reports: class/architecture, SONAME,
DT_NEEDED dependencies, Build ID, symbol imports/exports,
JNI exports (Java_* only; JNI_OnLoad is reported in the full
exports list, not counted as a JNI export), RegisterNatives hints,
hardening facts (RELRO, BIND_NOW, symbol-table presence,
16 KB alignment), plus the native dependency graph (which
bundled libraries depend on which). When readelf is
available, its DT_NEEDED list is cross-checked against the
parser's and any disagreement is reported, never hidden.

Usage:
    python3 nar-native.py app.apk [--json] [--lib NAME]
    python3 nar-native.py libfoo.so [--json]

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
from narlib import anim as anim_mod  # noqa: E402
from narlib import container as container_mod  # noqa: E402
from narlib import registry as reg_mod  # noqa: E402
from narlib.elf import Elf, ElfError, SHT_SYMTAB  # noqa: E402
from narlib.hashing import sha256_of  # noqa: E402
from narlib.mmapio import mapped_file  # noqa: E402
from narlib.safearchive import read_member_capped  # noqa: E402

SO_RE = re.compile(r"^(base/)?lib/([^/]+)/(.+\.so)$")

# Capability clusters for the behavior indicators: sets of
# imported dynamic symbols whose co-presence is a pattern
# signal. Indicators only — the same imports appear in
# plenty of benign libraries, so no verdict is ever derived
# from them; each record carries its evidence (the matched
# symbols) and a confidence.
BEHAVIOR_CLUSTERS = {
    "process_manipulation": {
        "symbols": ("ptrace", "process_vm_readv",
                    "process_vm_writev", "kill", "fork",
                    "vfork", "execve", "posix_spawn"),
        "min_alone_high": ("ptrace", "process_vm_writev"),
    },
    "dynamic_code_loading": {
        "symbols": ("dlopen", "dlsym", "android_dlopen_ext",
                    "mprotect"),
        "min_alone_high": (),
    },
    "network_access": {
        "symbols": ("socket", "connect", "send", "sendto",
                    "recv", "recvfrom", "getaddrinfo"),
        "min_alone_high": (),
    },
}


def behavior_indicators(facts):
    """Suspicious-behavior pattern indicators for one library,
    from its imported dynamic symbols (observed data).

    Records: single-cluster hits (process manipulation,
    dynamic code loading, network access) plus the combined
    network+process cluster, which is the combination that
    warrants a second look. Confidence: high when a
    cluster's strongest symbol is present or >= 3 of its
    symbols match, medium for >= 2, low for 1 (only the
    combined record suppresses single-symbol noise)."""
    imports = set(facts.get("imports") or [])
    if not imports:
        return []
    matched = {}
    records = []
    for cluster, spec in BEHAVIOR_CLUSTERS.items():
        hits = sorted(imports & set(spec["symbols"]))
        matched[cluster] = hits
        if not hits:
            continue
        strong = [s for s in hits
                  if s in spec["min_alone_high"]]
        if strong or len(hits) >= 3:
            confidence = "high"
        elif len(hits) == 2:
            confidence = "medium"
        else:
            continue  # one weak symbol alone is not a signal
        records.append({
            "indicator": cluster, "confidence": confidence,
            "evidence": hits,
            "note": "pattern indicator from imported symbols "
                    "only; not a behavior verdict"})
    if matched.get("network_access") and \
            matched.get("process_manipulation"):
        records.append({
            "indicator": "network_and_process_combination",
            "confidence": "high"
            if len(matched["process_manipulation"]) >= 2
            else "medium",
            "evidence": sorted(
                matched["network_access"]
                + matched["process_manipulation"]),
            "note": "pattern indicator from imported symbols "
                    "only; not a behavior verdict"})
    return records


def readelf_needed(path):
    """DT_NEEDED list via readelf -d, or None if unavailable."""
    registry = reg_mod.load_registry()
    entry = next((t for t in registry["tools"]
                  if t["name"] == "readelf"), None)
    if entry is None:
        return None
    probe = reg_mod.probe(entry)
    if not probe["available"]:
        return None
    try:
        proc = subprocess.run(
            [probe["path"], "-d", path], capture_output=True,
            text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return sorted(set(re.findall(r"\[([^\]]+)\]", proc.stdout)))


#: Bounded raw-string scan window for the physics string
#: channel: only the first bytes of a library are scanned
#: for physics family tokens (the symbol channels are not
#: bounded this way — they read the symbol tables proper).
_PHYSICS_STRING_SCAN_BYTES = 16 * 1024 * 1024


def _physics_hits_for_facts(facts, data):
    """Physics family hits for one parsed library: the
    dynsym channel from its facts (defined exports), the
    symtab channel from a fresh SHT_SYMTAB read, and a
    bounded raw-string scan of its bytes — delegated to
    narlib.anim.physics_hits_for_library."""
    try:
        elf = Elf(data, facts.get("name") or "lib.so")
        symtab = sorted({s["name"] for s in
                         elf.symbols(SHT_SYMTAB)
                         if s.get("defined") and s.get("name")})
    except Exception:
        symtab = []
    return anim_mod.physics_hits_for_library(
        facts.get("exports") or [],
        bytes(data[:_PHYSICS_STRING_SCAN_BYTES]),
        symtab_names=symtab)


def _accumulate_physics(report, display, facts, data):
    """Fold one library's physics hits into the report-level
    accumulator (per-family sets only — library bytes are
    never retained) and label the library entry with the
    families it contributed hits to."""
    hits = _physics_hits_for_facts(facts, data)
    if not hits:
        return
    facts["physics_families"] = sorted(hits)
    accum = report.setdefault("_physics_accum", {})
    for family, fh in hits.items():
        slot = accum.setdefault(family, {
            "engine_guess": fh["engine_guess"],
            "symbols": set(), "string_tokens": set(),
            "evidence_sources": set(), "libraries": set()})
        slot["symbols"] |= fh["symbols"]
        slot["string_tokens"] |= fh["string_tokens"]
        slot["evidence_sources"] |= fh["evidence_sources"]
        slot["libraries"].add(display)


def analyze_elf(name, data, cross_check_path=None):
    elf = Elf(data, name)
    facts = elf.facts()
    facts["size_bytes"] = len(data)
    facts["behavior_indicators"] = behavior_indicators(facts)
    if cross_check_path:
        needed = readelf_needed(cross_check_path)
        if needed is not None:
            facts["readelf_needed"] = needed
            facts["readelf_agrees"] = (
                sorted(facts["needed"]) == needed)
    return facts


def analyze(target, only_lib=None, work_dir=None,
            merge_splits=True):
    if not merge_splits:
        return _analyze_single(target, only_lib, work_dir)
    report = {"tool": "nar-native", "version": "3.0.3",
              "target": os.path.abspath(target),
              "target_sha256": sha256_of(target), "libraries": []}
    resolved = None
    try:
        if target.lower().endswith(".so"):
            roots = [target]
        else:
            resolved = container_mod.resolve_target(target)
            roots = resolved.native_roots or [target]
        for root in roots:
            _scan_archive(report, root, only_lib, work_dir,
                          source_split=os.path.basename(root))
        if resolved is not None and (resolved.is_container
                                     or resolved.split_set
                                     is not None):
            report["container"] = resolved.container_block()
    finally:
        if resolved is not None:
            resolved.cleanup()
    # Headline count is SUCCESSFULLY parsed libraries only
    # (certification A1-01): entries that failed ELF parsing
    # carry {"name", "error"} instead of the facts dict and
    # must not inflate the count. Failures are not hidden --
    # they stay in "libraries" and are counted separately in
    # the additive native_library_failed_count field, so
    # count + failed_count == len(libraries).
    failed = sum(1 for lib in report["libraries"]
                 if "error" in lib)
    report["native_library_count"] = \
        len(report["libraries"]) - failed
    report["native_library_failed_count"] = failed
    _finish_report(report)
    return report


def _scan_archive(report, archive_path, only_lib, work_dir,
                  source_split=None):
    """Scan one archive's lib/**/*.so members into report.

    Libraries are processed ONE AT A TIME (parse, record,
    release) — never accumulated. Zip members materialize
    via the capped reader (decompression requires it) but
    each member's bytes are released before the next."""
    def process(display, data, temp_path):
        try:
            facts = analyze_elf(display, data, temp_path)
        except ElfError as e:
            entry = {"name": display, "error": str(e)}
            if source_split is not None:
                entry["source_split"] = source_split
            report["libraries"].append(entry)
            return
        facts["display_name"] = display
        if source_split is not None:
            facts["source_split"] = source_split
        _accumulate_physics(report, display, facts, data)
        report["libraries"].append(facts)

    if archive_path.lower().endswith(".so"):
        with mapped_file(archive_path) as data:
            process(os.path.basename(archive_path), data,
                    archive_path)
        return
    with zipfile.ZipFile(archive_path) as zf:
        for name in sorted(zf.namelist()):
            m = SO_RE.match(name)
            if not m:
                continue
            if only_lib and m.group(3) != only_lib:
                continue
            try:
                data = read_member_capped(zf, name)
            except ValueError as e:
                entry = {"name": f"{m.group(2)}/{m.group(3)}",
                         "error": str(e)}
                if source_split is not None:
                    entry["source_split"] = source_split
                report["libraries"].append(entry)
                continue
            temp_path = None
            if work_dir:
                os.makedirs(work_dir, exist_ok=True)
                if source_split is None:
                    fname = f"{m.group(2)}-{m.group(3)}"
                else:
                    fname = (f"{source_split}-"
                             f"{m.group(2)}-{m.group(3)}")
                temp_path = os.path.join(work_dir, fname)
                with open(temp_path, "wb") as fh:
                    fh.write(data)
            process(f"{m.group(2)}/{m.group(3)}", data,
                    temp_path)
            data = None


def _analyze_single(target, only_lib=None, work_dir=None):
    """The pre-3.0 single-archive behaviour: the
    --no-merge-splits path (single archive only; the shared
    scan / finish path, including physics detections, is
    identical to the merged path)."""
    report = {"tool": "nar-native", "version": "3.0.3",
              "target": os.path.abspath(target),
              "target_sha256": sha256_of(target), "libraries": []}
    _scan_archive(report, target, only_lib, work_dir,
                  source_split=None)
    _finish_report(report)
    return report


def _finish_report(report):
    # Native dependency graph among bundled libraries. Entries
    # that failed ELF parsing carry {"name", "error"} instead of
    # the facts dict (no display_name/soname/needed): they take
    # no part in the graph and must not crash its construction
    # (regression: an app bundling ZIP payloads named *.zip.so
    # crashed the whole stage with KeyError: 'display_name').
    def lib_name(lib):
        return lib.get("display_name") or lib.get("name")

    by_soname = {}
    for lib in report["libraries"]:
        name = lib_name(lib)
        if not name:
            continue
        if lib.get("soname"):
            by_soname[lib["soname"]] = name
        by_soname.setdefault(os.path.basename(name), name)
    graph = {}
    for lib in report["libraries"]:
        name = lib_name(lib)
        if not name:
            continue
        edges = [by_soname[n] for n in lib.get("needed", [])
                 if n in by_soname]
        if edges:
            graph[name] = sorted(edges)
    report["dependency_graph"] = graph
    # Detailed dependency graph (Phase 4): every DT_NEEDED
    # relationship as an edge, with dependencies that are
    # not bundled in the target labeled as external nodes
    # (system libraries and other outside providers). The
    # bundled-only dependency_graph above keeps its shape
    # for existing consumers. Bounded: node/edge lists are
    # capped with complete counts + truncation flags.
    nodes = []
    edges = []
    external_names = set()
    for lib in report["libraries"]:
        name = lib_name(lib)
        if not name or lib.get("error"):
            continue
        nodes.append({"name": name, "kind": "bundled",
                      "soname": lib.get("soname")})
        for needed in lib.get("needed", []):
            target_name = by_soname.get(needed)
            if target_name:
                edges.append({"from": name, "to": target_name,
                              "dependency": needed,
                              "to_kind": "bundled"})
            else:
                external_names.add(needed)
                edges.append({"from": name, "to": needed,
                              "dependency": needed,
                              "to_kind": "external"})
    for ext in sorted(external_names):
        nodes.append({"name": ext, "kind": "external"})
    node_cap, edge_cap = 500, 5000
    report["library_dependency_graph"] = {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "bundled_node_count": sum(
            1 for n in nodes if n["kind"] == "bundled"),
        "external_node_count": len(external_names),
        "external_dependencies": sorted(external_names),
        "nodes": nodes[:node_cap],
        "nodes_truncated": len(nodes) > node_cap,
        "edges": edges[:edge_cap],
        "edges_truncated": len(edges) > edge_cap,
    }
    report["behavior_indicator_count"] = sum(
        len(lib.get("behavior_indicators") or [])
        for lib in report["libraries"])
    # jni_map mirrors the per-library jni_exports lists
    # (Java_* exports only, M2-13): a library whose only JNI
    # surface is JNI_OnLoad no longer appears here. Bridge
    # classification is unaffected — it reads JNI_OnLoad from
    # each library's full "exports" list. Counts derived from
    # jni_map downstream (e.g. a "jni libraries" headline)
    # therefore count libraries WITH Java_* exports.
    report["jni_map"] = {
        lib_name(lib): lib["jni_exports"]
        for lib in report["libraries"] if lib.get("jni_exports")}
    # Physics detections (Area 5 wiring): the per-family
    # evidence accumulated during the scan (dynsym + symtab
    # + bounded string channels; see _accumulate_physics),
    # emitted as rig-shaped records at the same >= 3
    # distinct-evidence bar as narlib.anim.detect_physics.
    accum = report.pop("_physics_accum", {})
    family_tokens = {family: tokens for family, _guess,
                     tokens in anim_mod._PHYSICS_FAMILIES}
    detections = []
    for family, slot in sorted(accum.items()):
        count = anim_mod.physics_distinct_count(
            slot["symbols"], slot["string_tokens"],
            family_tokens.get(family, ()))
        if count < 3:
            continue
        symbols = sorted(slot["symbols"])
        det = {
            "family": family,
            "engine_guess": slot["engine_guess"],
            "symbol_count": count,
            "sample": symbols[:8] if symbols else
                      sorted(slot["string_tokens"])[:8],
            "libraries": sorted(slot["libraries"]),
            "confidence": "inferred",
            "evidence_sources": sorted(
                slot["evidence_sources"]),
        }
        if slot["string_tokens"]:
            det["string_tokens"] = sorted(slot["string_tokens"])
        detections.append(det)
    report["physics_detections"] = detections
    return report


def human(report):
    print(f"NAR native intelligence: "
          f"{os.path.basename(report['target'])}")
    print("=" * 60)
    cont = report.get("container")
    if cont:
        print(f"Container: {cont['input_kind']} — base "
              f"{cont['base']}; splits merged: "
              f"{[s['name'] for s in cont['splits_merged']]}; "
              f"skipped: {cont['split_skipped']}")
    for lib in report["libraries"]:
        if lib.get("error"):
            print(f"- {lib['name']}: ERROR {lib['error']}")
            continue
        print(f"- {lib['display_name']} ({lib['elf_class']}/"
              f"{lib['arch']}, {lib['size_bytes']:,} bytes)"
              + (f" [from {lib['source_split']}]"
                 if lib.get("source_split") else ""))
        print(f"    needed: {', '.join(lib['needed'][:8])}"
              f"{' …' if len(lib['needed']) > 8 else ''}")
        print(f"    imports {len(lib['imports'])}, exports "
              f"{len(lib['exports'])}, JNI exports "
              f"{len(lib['jni_exports'])}; symtab: "
              f"{lib['has_symtab']}; RELRO: {lib['has_gnu_relro']};"
              f" BIND_NOW: {lib['bind_now']}; 16K aligned: "
              f"{lib['aligned_16k']}")
        if lib.get("readelf_agrees") is False:
            print("    WARNING: readelf DT_NEEDED disagrees with "
                  "the built-in parser")
    if report["dependency_graph"]:
        print("Dependency graph (bundled -> bundled):")
        for src, dsts in report["dependency_graph"].items():
            print(f"  {src} -> {', '.join(dsts)}")
    detail = report.get("library_dependency_graph") or {}
    if detail:
        print(f"Dependency graph detail: {detail['node_count']} "
              f"nodes ({detail['bundled_node_count']} bundled, "
              f"{detail['external_node_count']} external), "
              f"{detail['edge_count']} edges")
    if report.get("physics_detections"):
        print("Physics detections (inferred, symbol/string "
              "evidence):")
        for det in report["physics_detections"]:
            print(f"  {det['engine_guess']} ({det['family']}): "
                  f"{det['symbol_count']} symbols/tokens in "
                  f"{', '.join(det['libraries'])} "
                  f"[evidence: "
                  f"{', '.join(det['evidence_sources'])}]")
    if report.get("behavior_indicator_count"):
        print(f"Behavior indicators: "
              f"{report['behavior_indicator_count']} "
              "(pattern indicators only, no verdicts)")
        for lib in report["libraries"]:
            for rec in lib.get("behavior_indicators") or []:
                print(f"  {lib.get('display_name')}: "
                      f"{rec['indicator']} "
                      f"({rec['confidence']}) — "
                      f"{', '.join(rec['evidence'])}")


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Deep ELF intelligence for the native "
                    "libraries of an APK (or one bare .so).")
    p.add_argument("target", help="path to an .apk or .so file")
    p.add_argument("--json", action="store_true")
    p.add_argument("--lib", metavar="NAME",
                   help="only analyze this library file name")
    p.add_argument("--work", metavar="DIR",
                   help="extraction dir enabling the readelf "
                        "cross-check")
    p.add_argument("--no-merge-splits", action="store_true",
                   help="analyse only the base APK of a "
                        "container (pre-3.0 behaviour, "
                        "byte-identical output)")
    args = p.parse_args(argv)
    if os.path.isdir(args.target):
        # Directory targets are an input error (exit 2) on
        # every platform. This cannot be left to the open()
        # below: POSIX raises IsADirectoryError for a
        # directory open (caught under the try), but Windows
        # raises PermissionError instead, which would escape
        # as a traceback and the wrong exit code.
        print(f"nar-native: is a directory: {args.target}",
              file=sys.stderr)
        return 2
    try:
        report = analyze(args.target, args.lib, args.work,
                         merge_splits=not args.no_merge_splits)
    except (FileNotFoundError, IsADirectoryError,
            zipfile.BadZipFile) as e:
        print(f"nar-native: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        human(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
