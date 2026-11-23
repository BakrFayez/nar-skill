#!/usr/bin/env python3
"""nar-unreal.py: Unreal Engine deep dive (brief section 5).

For an APK (or a bare .pak / IoStore container):

- engine generation evidence: libUE4/libUnreal naming, triage
  build-string version evidence (e.g. UE 4.16), IoStore
  (.utoc/.ucas) presence as the UE5-era packaging indicator,
- every bundled .pak parsed with nar-pak: version, entry
  count, encryption flags, mount point, content statistics,
- IoStore containers inventoried honestly: the .utoc index
  format is parsed for its header facts only where the layout
  is verifiable; entry-level IoStore parsing is NOT claimed
  (no FModel/UAssetAPI-class tool is integrated — see the
  capability registry),
- config and content signals: .uasset/.umap counts from pak
  listings, Engine/Game config file presence.

Usage:
    python3 nar-unreal.py app.apk [--json]
    python3 nar-unreal.py content.pak [--json]

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import subprocess
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib.hashing import sha256_of  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def run_json_tool(script, args, timeout=1200):
    cmd = [sys.executable, os.path.join(HERE, script)] + args + ["--json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
        return json.loads(proc.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def pak_summary(data_path):
    out = run_json_tool("nar-pak.py", [data_path])
    if out is None:
        return {"error": "nar-pak failed"}
    entries = out.get("entries") or []
    return {
        "pak_version": out.get("pak_version"),
        "supported": out.get("supported"),
        "mount_point": out.get("mount_point"),
        "entry_count": out.get("entry_count"),
        "encrypted_entries": sum(1 for e in entries
                                 if e.get("encrypted")),
        "uasset_count": sum(1 for e in entries
                            if e["name"].endswith(".uasset")),
        "umap_count": sum(1 for e in entries
                          if e["name"].endswith(".umap")),
        "stats": out.get("stats"),
    }


def analyze(target, work_dir=None):
    report = {"tool": "nar-unreal", "version": "2.0.0",
              "target": os.path.abspath(target),
              "target_sha256": sha256_of(target)}
    lower = target.lower()
    if lower.endswith(".pak"):
        report["verdict"] = "pak-container"
        report["paks"] = [pak_summary(target)]
        return report
    triage = run_json_tool("nar-triage.py", [target])
    versions = (triage or {}).get("engine_versions") or {}
    hints = (triage or {}).get("engine_hints") or []
    unreal_hint = any(h["engine"] == "Unreal Engine" for h in hints)
    paks, iostore, configs = [], [], []
    with zipfile.ZipFile(target) as zf:
        names = zf.namelist()
        for name in names:
            ln = name.lower()
            if ln.endswith(".pak"):
                if work_dir:
                    os.makedirs(work_dir, exist_ok=True)
                    tmp = os.path.join(
                        work_dir, os.path.basename(name))
                    with open(tmp, "wb") as fh:
                        fh.write(zf.read(name))
                    summary = pak_summary(tmp)
                else:
                    summary = {"entry": name,
                               "note": "pass --work DIR to parse "
                                       "bundled paks"}
                summary["entry"] = name
                paks.append(summary)
            elif ln.endswith((".utoc", ".ucas")):
                iostore.append(name)
            elif "/config/" in ln and ln.endswith(".ini"):
                configs.append(name)
    generation = None
    if iostore:
        generation = "UE5-era (IoStore packaging)"
    elif versions.get("unreal_engine"):
        generation = versions["unreal_engine"]
    report.update({
        "verdict": "unreal" if (unreal_hint or paks or iostore)
                   else "absent",
        "generation": generation,
        "version_evidence": {k: v for k, v in versions.items()
                             if k.startswith("unreal")},
        "paks": paks,
        "iostore_files": iostore,
        "config_files": configs[:25],
        "limitations": [
            "IoStore entry-level parsing is not integrated (no "
            "FModel/UAssetAPI-class tool available); containers "
            "are inventoried, not unpacked.",
            "Encrypted pak entries are counted, never decrypted "
            "(key extraction is out of scope).",
        ],
    })
    return report


def human(report):
    print(f"NAR Unreal deep dive: "
          f"{os.path.basename(report['target'])}")
    print("=" * 60)
    print(f"Verdict: {report.get('verdict')}")
    if report.get("generation"):
        print(f"Generation: {report['generation']}")
    if report.get("version_evidence"):
        print(f"Version evidence: {report['version_evidence']}")
    for pak in report.get("paks", []):
        print(f"- pak {pak.get('entry', '')}: version "
              f"{pak.get('pak_version')}, entries "
              f"{pak.get('entry_count')}, encrypted "
              f"{pak.get('encrypted_entries')}, uassets "
              f"{pak.get('uasset_count')}, maps "
              f"{pak.get('umap_count')}")
        if pak.get("note"):
            print(f"    {pak['note']}")
        if pak.get("error"):
            print(f"    ERROR: {pak['error']}")
    if report.get("iostore_files"):
        print(f"IoStore files: {report['iostore_files']}")
    for lim in report.get("limitations", []):
        print(f"limitation: {lim}")


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Unreal deep dive: generation evidence, pak "
                    "inventory/encryption, IoStore inventory.")
    p.add_argument("target", help="path to an .apk or .pak file")
    p.add_argument("--json", action="store_true")
    p.add_argument("--work", metavar="DIR",
                   help="extraction dir for parsing bundled paks")
    args = p.parse_args(argv)
    try:
        report = analyze(args.target, args.work)
    except (FileNotFoundError, zipfile.BadZipFile) as e:
        print(f"nar-unreal: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        human(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
