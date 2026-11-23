#!/usr/bin/env python3
"""run_benchmarks.py: measured module timings on local
fixtures.

Runs a fixed module set against the local fixture roles
(demo / app / game / engine samples bound through
$NAR_FIXTURES + manifest.env, the same pattern as the e2e
harness) and records wall-clock seconds per run. Numbers
are measured on the machine that runs this script and are
reported as-is; nothing is estimated or extrapolated.

Usage:
    python3 tests/benchmarks/run_benchmarks.py [--out FILE]

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
SCRIPTS = os.path.join(ROOT, "scripts")
FIXTURES = os.environ.get("NAR_FIXTURES",
                          os.path.expanduser(
                              "~/workspace/nar-e2e-fixtures"))

MODULES = ["nar-triage.py", "nar-fingerprint.py",
           "nar-engines.py", "nar-dex.py", "nar-native.py",
           "nar-network.py", "nar-assets.py"]


def fixture_roles():
    roles = {}
    demo = os.path.join(FIXTURES, "demo", "NarDemo.apk")
    if os.path.isfile(demo):
        roles["demo (synthetic, ~29 KB)"] = demo
    manifest = os.path.join(FIXTURES, "manifest.env")
    env = {}
    if os.path.isfile(manifest):
        for line in open(manifest, encoding="utf-8"):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    for role, key in (("app (manifest FIX_APP)", "FIX_APP"),
                      ("game (manifest FIX_GAME)", "FIX_GAME"),
                      ("unity (manifest FIX_UNITY)", "FIX_UNITY")):
        path = env.get(key)
        if path:
            path = path.replace("${NAR_FIXTURES}", FIXTURES) \
                       .replace("$NAR_FIXTURES", FIXTURES)
        if path and os.path.isfile(path):
            roles[role] = path
    return roles


def timed(script, target):
    started = time.time()
    proc = subprocess.run(
        [sys.executable, os.path.join(SCRIPTS, script), target],
        capture_output=True, text=True, timeout=3600)
    return round(time.time() - started, 2), proc.returncode


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", metavar="FILE")
    args = p.parse_args(argv)
    roles = fixture_roles()
    results = {"machine": os.uname().sysname + " " +
               os.uname().machine,
               "python": sys.version.split()[0], "runs": []}
    for role, path in roles.items():
        size = os.path.getsize(path)
        for module in MODULES:
            seconds, rc = timed(module, path)
            results["runs"].append({
                "fixture_role": role, "size_bytes": size,
                "module": module, "seconds": seconds,
                "exit_code": rc})
            print(f"{role:28s} {module:22s} {seconds:8.2f}s "
                  f"(exit {rc})")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
