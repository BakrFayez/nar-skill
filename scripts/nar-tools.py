#!/usr/bin/env python3
"""nar-tools.py: the NAR tool-registry view.

Lists every tool declared in scripts/registry.json with its
live probe result (available / path / version) on this
machine, using the same discovery rules as the doctor
(narlib.registry). This is a view, not a gate: readiness
verdicts live in nar-doctor.sh. Tools registered as
unavailable are listed as such, never faked.

    python3 nar-tools.py [--json] [--available]

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import registry as reg  # noqa: E402


def build_report(only_available=False):
    data = reg.load_registry()
    results = reg.probe_all(data)
    shown = [r for r in results if r["available"]] \
        if only_available else results
    core_missing = [r["name"] for r in results
                    if r["required"] == "core" and not r["available"]]
    return {
        "tool": "nar-tools",
        "registry_version": data.get("registry_version"),
        "tools": shown,
        "summary": {
            "declared": len(results),
            "available": sum(1 for r in results if r["available"]),
            "core_missing": core_missing,
        },
    }


def human(report):
    print(f"NAR tool registry (registry "
          f"{report['registry_version']}): "
          f"{report['summary']['available']}/"
          f"{report['summary']['declared']} available")
    for r in report["tools"]:
        state = "OK  " if r["available"] else "MISS"
        version = reg.version_of(r) or "-"
        where = r["path"] or r["note"] or "-"
        print(f"{state} {r['name']:<16} {r['kind']:<14} "
              f"{r['required']:<9} {version:<12} {where}")
    missing = report["summary"]["core_missing"]
    if missing:
        print(f"core tools missing: {', '.join(missing)} "
              f"(run nar doctor for the readiness verdict)")
    else:
        print("core tools: all available (nar doctor gives "
              "the full readiness verdict)")


def main(argv=None):
    p = argparse.ArgumentParser(
        description="List the NAR tool registry with live "
                    "availability probes for this machine.")
    p.add_argument("--json", action="store_true",
                   help="print the registry view as JSON")
    p.add_argument("--available", action="store_true",
                   help="only show tools that probed available")
    args = p.parse_args(argv)
    try:
        report = build_report(args.available)
    except (OSError, ValueError) as e:
        print(f"nar-tools: registry unusable: {e}",
              file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        human(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
