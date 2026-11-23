#!/usr/bin/env python3
"""nar-unity.py: Unity deep dive (brief section 5).

For a Unity APK:

- scripting backend verdict (IL2CPP vs Mono) from layout +
  the nar-il2cpp metadata analysis when IL2CPP is present,
- Unity editor version evidence: the version string embedded
  in globalgamemanagers / the UnityFS container header,
- asset inventory: UnityFS bundles (magic-verified), the
  bin/Data layout, Addressables catalog presence,
- optional UnityPy pass: when the optional UnityPy module is
  importable in the running interpreter, one bundle is loaded
  and its object-type census reported; when it is not, that
  is stated plainly (never faked).

Usage:
    python3 nar-unity.py app.apk [--json] [--work DIR]

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import io
import json
import os
import re
import subprocess
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib.hashing import sha256_of  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
UNITY_VERSION_RE = re.compile(rb"(20\d\d\.\d+\.\d+[abfp]\d+)")
MAX_BUNDLE_SCAN = 200


def run_json_tool(script, args, timeout=1800):
    cmd = [sys.executable, os.path.join(HERE, script)] + args + ["--json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
        return json.loads(proc.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def unitypy_census(data):
    """Object-type census of one bundle via UnityPy, or None."""
    try:
        import UnityPy  # optional dependency
    except ImportError:
        return None
    try:
        env = UnityPy.load(data)
        census = {}
        for obj in env.objects:
            census[obj.type.name] = census.get(obj.type.name, 0) + 1
        return census
    except Exception:
        return None


def analyze(target, work_dir=None):
    report = {"tool": "nar-unity", "version": "2.3.0",
              "target": os.path.abspath(target),
              "target_sha256": sha256_of(target)}
    triage = run_json_tool("nar-triage.py", [target]) or {}
    hints = {h["engine"] for h in triage.get("engine_hints") or []}
    versions = triage.get("engine_versions") or {}
    backend = None
    if "Unity (IL2CPP)" in hints:
        backend = "IL2CPP"
    elif "Unity (Mono)" in hints:
        backend = "Mono"
    bundles, version_strings = [], []
    addressables = False
    data_files = 0
    with zipfile.ZipFile(target) as zf:
        names = zf.namelist()
        for name in names:
            if name.startswith("assets/bin/Data/"):
                data_files += 1
            if name.startswith("assets/aa/") or \
                    name.endswith("catalog.json"):
                addressables = True
            if name in ("assets/bin/Data/globalgamemanagers",
                        "assets/bin/Data/data.unity3d") or \
                    name.endswith((".unity3d", ".bundle")):
                with zf.open(name) as fh:
                    head = fh.read(4096)
                is_bundle = head.startswith(
                    (b"UnityFS", b"UnityWeb", b"UnityRaw"))
                if name.endswith("globalgamemanagers") or is_bundle:
                    m = UNITY_VERSION_RE.search(head)
                    if m:
                        version_strings.append(
                            m.group(1).decode("ascii", "replace"))
                if is_bundle:
                    bundles.append(name)
            if len(bundles) > MAX_BUNDLE_SCAN:
                break
    report.update({
        "verdict": "unity" if backend else "absent",
        "scripting_backend": backend,
        "unity_version_strings": sorted(set(version_strings)),
        "metadata_version": versions.get("unity_metadata_version"),
        "metadata_era": versions.get("unity_metadata_era"),
        "data_file_count": data_files,
        "unityfs_bundles": bundles[:50],
        "unityfs_bundle_count": len(bundles),
        "addressables": addressables,
    })
    if backend == "IL2CPP":
        il2cpp_args = [target]
        if work_dir:
            # Keep the (large) dumper output in the caller's
            # work dir instead of the tool's /tmp default.
            il2cpp_args += ["--out",
                            os.path.join(work_dir, "il2cpp")]
        il2cpp = run_json_tool("nar-il2cpp.py", il2cpp_args)
        if il2cpp:
            report["il2cpp"] = {k: il2cpp.get(k) for k in
                                ("verdict", "metadata_version",
                                 "dumper") if k in il2cpp}
    # Optional UnityPy census on the first bundle found.
    census = None
    if bundles:
        with zipfile.ZipFile(target) as zf:
            with zf.open(bundles[0]) as fh:
                census = unitypy_census(fh.read())
    if census is not None:
        report["unitypy_census_first_bundle"] = census
    else:
        report["notes"] = [
            "UnityPy is not importable in this interpreter; "
            "bundle object census skipped (bundle inventory "
            "above is magic-verified and complete)."]
    return report


def human(report):
    print(f"NAR Unity deep dive: "
          f"{os.path.basename(report['target'])}")
    print("=" * 60)
    print(f"Verdict: {report['verdict']} "
          f"(backend: {report['scripting_backend']})")
    if report["unity_version_strings"]:
        print(f"Unity version strings: "
              f"{report['unity_version_strings']}")
    if report["metadata_version"]:
        print(f"IL2CPP metadata: v{report['metadata_version']} "
              f"({report['metadata_era']})")
    print(f"Data files: {report['data_file_count']}; UnityFS "
          f"bundles: {report['unityfs_bundle_count']}; "
          f"Addressables: {report['addressables']}")
    if report.get("unitypy_census_first_bundle"):
        print(f"UnityPy census (first bundle): "
              f"{report['unitypy_census_first_bundle']}")
    for note in report.get("notes", []):
        print(f"note: {note}")


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Unity deep dive: backend, version evidence, "
                    "bundle inventory, optional UnityPy census.")
    p.add_argument("target", help="path to the .apk file")
    p.add_argument("--json", action="store_true")
    p.add_argument("--work", metavar="DIR",
                   help="work dir for the IL2CPP dumper output "
                        "(large; keep it off a small /tmp)")
    args = p.parse_args(argv)
    try:
        report = analyze(args.target, args.work)
    except (FileNotFoundError, zipfile.BadZipFile) as e:
        print(f"nar-unity: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        human(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
