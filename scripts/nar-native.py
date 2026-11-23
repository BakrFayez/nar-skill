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
from narlib.elf import Elf, ElfError  # noqa: E402
from narlib.hashing import sha256_of  # noqa: E402

SO_RE = re.compile(r"^(base/)?lib/([^/]+)/(.+\.so)$")


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
    if cross_check_path:
        needed = readelf_needed(cross_check_path)
        if needed is not None:
            facts["readelf_needed"] = needed
            facts["readelf_agrees"] = (
                sorted(facts["needed"]) == needed)
    return facts


def analyze(target, only_lib=None, work_dir=None):
    report = {"tool": "nar-native", "version": "2.2.0",
              "target": os.path.abspath(target),
              "target_sha256": sha256_of(target), "libraries": []}
    libs = []  # (display_name, data, temp_path_for_crosscheck)
    if target.lower().endswith(".so"):
        with open(target, "rb") as fh:
            libs.append((os.path.basename(target), fh.read(),
                         target))
    else:
        with zipfile.ZipFile(target) as zf:
            for name in sorted(zf.namelist()):
                m = SO_RE.match(name)
                if not m:
                    continue
                if only_lib and m.group(3) != only_lib:
                    continue
                data = zf.read(name)
                temp_path = None
                if work_dir:
                    os.makedirs(work_dir, exist_ok=True)
                    temp_path = os.path.join(
                        work_dir, f"{m.group(2)}-{m.group(3)}")
                    with open(temp_path, "wb") as fh:
                        fh.write(data)
                libs.append((f"{m.group(2)}/{m.group(3)}", data,
                             temp_path))
    for display, data, temp_path in libs:
        try:
            facts = analyze_elf(display, data, temp_path)
        except ElfError as e:
            report["libraries"].append({"name": display,
                                        "error": str(e)})
            continue
        facts["display_name"] = display
        report["libraries"].append(facts)
    # Native dependency graph among bundled libraries.
    by_soname = {}
    for lib in report["libraries"]:
        if lib.get("soname"):
            by_soname[lib["soname"]] = lib["display_name"]
        by_soname.setdefault(
            os.path.basename(lib["display_name"]),
            lib["display_name"])
    graph = {}
    for lib in report["libraries"]:
        edges = [by_soname[n] for n in lib.get("needed", [])
                 if n in by_soname]
        if edges:
            graph[lib["display_name"]] = sorted(edges)
    report["dependency_graph"] = graph
    report["jni_map"] = {
        lib["display_name"]: lib["jni_exports"]
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
    except (FileNotFoundError, zipfile.BadZipFile) as e:
        print(f"nar-native: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        human(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
