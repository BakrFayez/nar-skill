#!/usr/bin/env python3
"""nar-native.py: deep native library / ELF intelligence
(brief section 6).

For every .so in an APK (or a bare .so), parses the ELF with
the narlib parser and reports: class/architecture, SONAME,
DT_NEEDED dependencies, Build ID, symbol imports/exports,
JNI exports (Java_* and JNI_OnLoad), RegisterNatives hints,
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
from narlib import registry as reg_mod  # noqa: E402
from narlib.elf import Elf, ElfError  # noqa: E402
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


def analyze(target, only_lib=None, work_dir=None):
    report = {"tool": "nar-native", "version": "2.6.2",
              "target": os.path.abspath(target),
              "target_sha256": sha256_of(target), "libraries": []}
    # Libraries are processed ONE AT A TIME (parse, record,
    # release) — never accumulated. A bare .so is parsed
    # over a read-only mapping instead of a whole-file
    # read; zip members still materialize via zf.read()
    # (decompression requires it) but each member's bytes
    # are released before the next member is read.
    def process(display, data, temp_path):
        try:
            facts = analyze_elf(display, data, temp_path)
        except ElfError as e:
            report["libraries"].append({"name": display,
                                        "error": str(e)})
            return
        facts["display_name"] = display
        report["libraries"].append(facts)

    if target.lower().endswith(".so"):
        with mapped_file(target) as data:
            process(os.path.basename(target), data, target)
    else:
        with zipfile.ZipFile(target) as zf:
            for name in sorted(zf.namelist()):
                m = SO_RE.match(name)
                if not m:
                    continue
                if only_lib and m.group(3) != only_lib:
                    continue
                try:
                    data = read_member_capped(zf, name)
                except ValueError as e:
                    report["libraries"].append({
                        "name": f"{m.group(2)}/{m.group(3)}",
                        "error": str(e)})
                    continue
                temp_path = None
                if work_dir:
                    os.makedirs(work_dir, exist_ok=True)
                    temp_path = os.path.join(
                        work_dir, f"{m.group(2)}-{m.group(3)}")
                    with open(temp_path, "wb") as fh:
                        fh.write(data)
                process(f"{m.group(2)}/{m.group(3)}", data,
                        temp_path)
                data = None
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
    report["jni_map"] = {
        lib_name(lib): lib["jni_exports"]
        for lib in report["libraries"] if lib.get("jni_exports")}
    return report


def human(report):
    print(f"NAR native intelligence: "
          f"{os.path.basename(report['target'])}")
    print("=" * 60)
    for lib in report["libraries"]:
        if lib.get("error"):
            print(f"- {lib['name']}: ERROR {lib['error']}")
            continue
        print(f"- {lib['display_name']} ({lib['elf_class']}/"
              f"{lib['arch']}, {lib['size_bytes']:,} bytes)")
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
    args = p.parse_args(argv)
    try:
        report = analyze(args.target, args.lib, args.work)
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
