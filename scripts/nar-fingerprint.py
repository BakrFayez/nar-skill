#!/usr/bin/env python3
"""nar-fingerprint.py: normalized application fingerprint.

Runs the 1.x triage and permission audit and normalizes their
output into one fingerprint document (brief section 3.2) in
which EVERY property carries its provenance (which tool and
evidence produced it), a confidence, and a fact class
(observed / derived / inferred). Emits the fingerprint
schema shape:

    {source_sha256, properties: {name: {value, provenance,
     confidence, fact_class}}, notes[]}

Usage:
    python3 nar-fingerprint.py app.apk [--json] [--out FILE]

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import evidence as ev_mod  # noqa: E402
from narlib.hashing import sha256_of  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def run_json_tool(script, args, timeout=1200):
    cmd = [sys.executable, os.path.join(HERE, script)] + args + ["--json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
        return json.loads(proc.stdout), None
    except (OSError, ValueError, subprocess.TimeoutExpired) as e:
        return None, f"{script}: {e}"


def prop(value, provenance, confidence="high", fact_class="observed"):
    # verification_status (Phase 8): derived from the fact
    # class by the shared mapping — a property never claims
    # more verification than its fact class supports.
    return {"value": value, "provenance": provenance,
            "confidence": confidence, "fact_class": fact_class,
            "verification_status":
                ev_mod.verification_for_fact_class(fact_class)}


def fingerprint(apk_path):
    notes = []
    triage, err = run_json_tool("nar-triage.py", [apk_path])
    if triage is None:
        raise RuntimeError(f"triage failed: {err}")
    perms, perr = run_json_tool("nar-perms.py", [apk_path])
    if perms is None:
        notes.append(f"permission audit unavailable: {perr}")
        perms = {}
    badging = triage.get("badging") or {}
    container = triage.get("container_manifest") or {}
    props = {}

    def from_badging(name, key):
        if badging.get(key) is not None:
            props[name] = prop(badging[key], "aapt2 dump badging "
                                            "(via nar-triage)")
        elif container.get(key) is not None:
            props[name] = prop(container[key], "container "
                                               "manifest.json")

    from_badging("package", "package")
    from_badging("version_name", "version_name")
    from_badging("version_code", "version_code")
    from_badging("app_label", "app_label")
    from_badging("min_sdk", "min_sdk")
    from_badging("target_sdk", "target_sdk")
    from_badging("compile_sdk", "compile_sdk")
    if "compile_sdk" not in props:
        notes.append("compile SDK was not exposed by the badging "
                     "reader for this target (no compileSdkVersion "
                     "in the aapt2 badging output); absence is "
                     "recorded, not guessed")
    props["sha256"] = prop(triage["sha256"], "nar-triage file hash")
    props["size_bytes"] = prop(triage["size_bytes"],
                               "filesystem")
    props["abis"] = prop(sorted((triage.get("native_libs_by_abi")
                                 or {}).keys()),
                         "ZIP lib/<abi>/ layout (nar-triage)",
                         fact_class="derived")
    props["dex_count"] = prop(triage.get("dex_count"),
                              "ZIP DEX inventory (nar-triage)")
    props["dex_versions"] = prop(triage.get("dex_versions"),
                                 "DEX header magics (nar-triage)")
    props["native_library_count"] = prop(
        triage.get("native_lib_count"), "ZIP lib/ inventory")
    sig = triage.get("signature_schemes") or {}
    if sig:
        props["signing_schemes"] = prop(
            sig, "apksigner verify --verbose (via nar-triage)")
    if perms:
        props["permissions"] = prop(
            [p.get("name") for p in perms.get("permissions", [])
             if isinstance(p, dict)],
            "nar-perms manifest audit")
        props["component_counts"] = prop(
            perms.get("component_counts"), "nar-perms manifest audit")
        props["exported_component_count"] = prop(
            perms.get("exported_count"), "nar-perms manifest audit")
        app = perms.get("application") or {}
        for key in ("debuggable", "allow_backup"):
            if app.get(key) is not None:
                props[key] = prop(app[key],
                                  "nar-perms manifest audit")
    engines = [h.get("engine") for h in triage.get("engine_hints")
               or []]
    if engines:
        props["engine_hints"] = prop(
            engines, "nar-triage path signatures",
            confidence="medium", fact_class="derived")
    markers = [m.get("marker") for m in triage.get("dex_markers")
               or [] if m.get("total_hits", 0) > 0]
    if markers:
        props["framework_markers"] = prop(
            markers, "nar-triage DEX string fingerprints")
    if triage.get("engine_versions"):
        props["engine_versions"] = prop(
            triage["engine_versions"],
            "binary header / build-string evidence (nar-triage)")
    if triage.get("library_versions"):
        props["library_versions"] = prop(
            triage["library_versions"],
            "META-INF/*.version files (nar-triage)")
    form_factors = badging.get("form_factors")
    if form_factors:
        props["form_factors"] = prop(form_factors,
                                     "manifest features (nar-triage)",
                                     fact_class="derived")
    return {"source_sha256": sha256_of(apk_path),
            "properties": props, "notes": notes}


def human(fp):
    print("NAR fingerprint")
    print("=================")
    for name, p in fp["properties"].items():
        value = p["value"]
        if isinstance(value, (list, dict)):
            value = json.dumps(value)
        print(f"- {name}: {value}")
        print(f"    [{p['provenance']}; confidence "
              f"{p['confidence']}; {p['fact_class']}; "
              f"verification "
              f"{p.get('verification_status', 'UNVERIFIED')}]")
    for note in fp["notes"]:
        print(f"note: {note}")


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Normalized application fingerprint with "
                    "per-property provenance and confidence.")
    p.add_argument("apk", help="path to the .apk file")
    p.add_argument("--json", action="store_true")
    p.add_argument("--out", metavar="FILE",
                   help="also write the fingerprint JSON to FILE")
    args = p.parse_args(argv)
    try:
        fp = fingerprint(args.apk)
    except (FileNotFoundError, RuntimeError) as e:
        print(f"nar-fingerprint: {e}", file=sys.stderr)
        return 2
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(fp, fh, indent=2)
    if args.json:
        print(json.dumps(fp, indent=2))
    else:
        human(fp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
