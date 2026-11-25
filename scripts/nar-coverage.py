#!/usr/bin/env python3
"""nar-coverage.py: the coverage matrix (Part 1 + Part 16).

Reports, from scripts/formats.json alone (the single source
of truth — scripts/coverage.json is generated from it and
this tool reads the same projection), what NAR supports,
partially supports, only identifies, does not support, or
cannot decide client-side, per input type / engine / asset
format / script format / animation system / app framework /
protection kind. Every non-supported entry names its reason
and the cheapest probe that would raise its coverage.

Usage:
    python3 nar-coverage.py [--json]
    python3 nar-coverage.py --gap [--json] [--case DIR]
    python3 nar-coverage.py --write   (regenerate
                                       scripts/coverage.json)

--gap --json additionally aggregates recorded failure
classifications (Part 10.5.3): with --case DIR the counts
come from the Fallback Records (decompile.json companions)
actually recorded in that case; without a case it reports
the classification enum with zero counts and says so. No
count is ever invented.

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import formats_registry as registry  # noqa: E402
from narlib.failures import FAILURE_KIND_NAMES  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
COVERAGE_PATH = os.path.join(HERE, "coverage.json")

SECTION_TITLES = {
    "input_types": "Input types",
    "engines": "Engines",
    "asset_formats": "Asset formats",
    "script_formats": "Script formats",
    "animation_systems": "Animation systems",
    "app_frameworks": "App frameworks",
    "protection_kinds": "Protection kinds",
}


def failure_classifications(case_dir=None):
    """Aggregate FailureKind counts from real records.

    With a case directory: every decompile.json Fallback
    Record under it contributes its attempts' classifications.
    Without one: the enum with zero counts and an explicit
    note — never invented numbers."""
    counts = {name: 0 for name in sorted(FAILURE_KIND_NAMES)}
    if not case_dir:
        return {"counts": counts, "records_scanned": 0,
                "note": "no case supplied; counts are zero by "
                        "construction, not measured"}
    scanned = 0
    for dirpath, _dirs, files in os.walk(case_dir):
        for name in files:
            if name != "decompile.json":
                continue
            try:
                with open(os.path.join(dirpath, name),
                          encoding="utf-8") as fh:
                    record = json.load(fh)
            except (OSError, ValueError):
                continue
            scanned += 1
            for attempt in record.get("attempts") or []:
                kind = attempt.get("classification")
                if kind in counts:
                    counts[kind] += 1
    return {"counts": counts, "records_scanned": scanned,
            "note": f"aggregated from {scanned} Fallback "
                    "Record(s) in the supplied case directory"}


def gap_entries(coverage):
    """Every non-supported entry, grouped by section."""
    out = {}
    for section in registry.SECTIONS:
        rows = [e for e in coverage.get(section) or []
                if e["status"] != "supported"]
        if rows:
            out[section] = rows
    return out


def human(coverage, gap_only=False):
    print("NAR coverage matrix (from formats.json)")
    print("=" * 60)
    for section in registry.SECTIONS:
        entries = coverage.get(section) or []
        if gap_only:
            entries = [e for e in entries
                       if e["status"] != "supported"]
            if not entries:
                continue
        counts = {}
        for e in coverage.get(section) or []:
            counts[e["status"]] = counts.get(e["status"], 0) + 1
        summary = ", ".join(f"{k}: {counts[k]}"
                            for k in sorted(counts))
        print(f"\n## {SECTION_TITLES[section]} ({summary})")
        for e in entries:
            line = f"- {e['name']}: {e['status']}"
            if e.get("fidelity"):
                line += f" (fidelity {e['fidelity']})"
            print(line)
            if e["status"] != "supported":
                if e.get("reason"):
                    print(f"    reason: {e['reason']}")
                if e.get("probe"):
                    print(f"    probe: {e['probe']}")


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Coverage matrix generated from "
                    "formats.json (single source of truth).")
    p.add_argument("--json", action="store_true")
    p.add_argument("--gap", action="store_true",
                   help="only non-supported entries, each "
                        "with its reason and cheapest probe")
    p.add_argument("--case", metavar="DIR",
                   help="case directory whose recorded "
                        "Fallback Records feed the --gap "
                        "--json failure classification counts")
    p.add_argument("--write", action="store_true",
                   help="regenerate scripts/coverage.json "
                        "from formats.json and exit")
    args = p.parse_args(argv)
    coverage = registry.build_coverage()
    if args.write:
        with open(COVERAGE_PATH, "w", encoding="utf-8") as fh:
            json.dump(coverage, fh, indent=1)
            fh.write("\n")
        print(f"nar-coverage: wrote {COVERAGE_PATH}")
        return 0
    if args.json:
        if args.gap:
            doc = {"gap": gap_entries(coverage),
                   "failure_classifications":
                       failure_classifications(args.case)}
            print(json.dumps(doc, indent=2))
        else:
            print(json.dumps(coverage, indent=2))
        return 0
    human(coverage, gap_only=args.gap)
    if args.gap and args.case:
        fc = failure_classifications(args.case)
        print("\n## Failure classifications (recorded)")
        for kind, count in fc["counts"].items():
            print(f"- {kind}: {count}")
        print(f"({fc['note']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
