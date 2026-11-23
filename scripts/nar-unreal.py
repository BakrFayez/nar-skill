#!/usr/bin/env python3
"""nar-unreal.py: Unreal Engine deep dive (brief section 5).

For an APK (or a bare .pak / IoStore container):

- engine generation evidence: libUE4/libUnreal naming, triage
  build-string version evidence (e.g. UE 4.16), IoStore
  (.utoc/.ucas) presence as the UE5-era packaging indicator,
- every bundled .pak parsed with nar-pak: version, entry
  count, encryption flags, mount point, content statistics,
- IoStore containers parsed at entry level by narlib.iostore
  (pure Python, public TOC layout): header, chunk IDs /
  offsets / lengths, compression block table, compression
  method names, directory index (chunk -> file path), and
  per-chunk SHA-1 meta. Compression methods other than
  None/Zlib (e.g. Oodle) are named, not decoded; encrypted
  containers are inventoried, never decrypted,
- config and content signals: .uasset/.umap counts from pak
  listings, Engine/Game config file presence.

Usage:
    python3 nar-unreal.py app.apk [--json]
    python3 nar-unreal.py content.pak [--json]
    python3 nar-unreal.py content.utoc [--json]

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
from narlib.iostore import IoStoreError, parse_utoc  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))

# Per-container chunk detail kept in JSON output; counts and
# totals always cover every chunk.
ENTRY_CAP = 250
CONTAINER_CAP = 5


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


def iostore_summary(utoc_bytes, name, ucas_name=None,
                    ucas_size=None):
    """Parse one .utoc into a presentation-ready container
    record (chunk detail capped; counts/totals complete)."""
    try:
        parsed = parse_utoc(utoc_bytes, name)
    except IoStoreError as e:
        return {"entry": name, "error": f"IoStore parse failed: {e}"}
    parsed.pop("_blocks", None)
    entries = parsed.pop("entries")
    total = len(entries)
    parsed["entries"] = entries[:ENTRY_CAP]
    if total > ENTRY_CAP:
        parsed["entries_capped"] = (
            f"chunk detail capped at {ENTRY_CAP} of {total}; "
            "counts and totals cover every chunk")
    parsed["entry"] = name
    if ucas_name:
        parsed["ucas_entry"] = ucas_name
        parsed["ucas_size"] = ucas_size
    return parsed


def analyze(target, work_dir=None):
    report = {"tool": "nar-unreal", "version": "2.1.0",
              "target": os.path.abspath(target),
              "target_sha256": sha256_of(target)}
    lower = target.lower()
    if lower.endswith(".pak"):
        report["verdict"] = "pak-container"
        report["paks"] = [pak_summary(target)]
        return report
    if lower.endswith(".utoc"):
        sibling = target[:-5] + ".ucas"
        ucas_name = ucas_size = None
        if os.path.exists(sibling):
            ucas_name = os.path.basename(sibling)
            ucas_size = os.path.getsize(sibling)
        with open(target, "rb") as fh:
            container = iostore_summary(
                fh.read(), os.path.basename(target),
                ucas_name, ucas_size)
        report["verdict"] = "iostore-container"
        report["generation"] = "UE5-era (IoStore packaging)"
        report["iostore_files"] = [os.path.basename(target)]
        report["iostore_containers"] = [container]
        report["limitations"] = _iostore_limitations()
        return report
    if lower.endswith(".ucas"):
        report["verdict"] = "iostore-data"
        report["limitations"] = [
            "A .ucas data file carries no index; parse its "
            "sibling .utoc instead.",
        ]
        return report
    triage = run_json_tool("nar-triage.py", [target])
    versions = (triage or {}).get("engine_versions") or {}
    hints = (triage or {}).get("engine_hints") or []
    unreal_hint = any(h["engine"] == "Unreal Engine" for h in hints)
    paks, iostore, configs = [], [], []
    containers = []
    with zipfile.ZipFile(target) as zf:
        names = zf.namelist()
        infos = {i.filename: i for i in zf.infolist()}
        ucas_by_prefix = {}
        for name in names:
            if name.lower().endswith(".ucas"):
                ucas_by_prefix[name[:-5].lower()] = name
        utoc_names = [n for n in names
                      if n.lower().endswith(".utoc")]
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
        for name in utoc_names[:CONTAINER_CAP]:
            ucas_name = ucas_by_prefix.get(name[:-5].lower())
            ucas_size = (infos[ucas_name].file_size
                         if ucas_name else None)
            containers.append(iostore_summary(
                zf.read(name), name, ucas_name, ucas_size))
        if len(utoc_names) > CONTAINER_CAP:
            containers.append({
                "note": f"{len(utoc_names)} .utoc containers "
                        f"found; only the first {CONTAINER_CAP} "
                        "were parsed"})
    generation = None
    if iostore:
        generation = "UE5-era (IoStore packaging)"
    elif versions.get("unreal_engine"):
        generation = versions["unreal_engine"]
    limitations = [
        "Encrypted pak entries are counted, never decrypted "
        "(key extraction is out of scope).",
    ]
    if containers:
        limitations = _iostore_limitations() + limitations
    report.update({
        "verdict": "unreal" if (unreal_hint or paks or iostore)
                   else "absent",
        "generation": generation,
        "version_evidence": {k: v for k, v in versions.items()
                             if k.startswith("unreal")},
        "paks": paks,
        "iostore_files": iostore,
        "iostore_containers": containers,
        "config_files": configs[:25],
        "limitations": limitations,
    })
    return report


def _iostore_limitations():
    return [
        "IoStore chunk payloads are inventoried, not "
        "extracted, in APK mode; extraction is a narlib "
        "capability exercised by the unit suite.",
        "IoStore compression methods other than None/Zlib "
        "(e.g. Oodle) are named, not decoded; containers "
        "flagged Encrypted are inventoried, never decrypted.",
    ]


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
    for c in report.get("iostore_containers", []):
        if c.get("error"):
            print(f"- utoc {c.get('entry', '')}: {c['error']}")
            continue
        if c.get("note"):
            print(f"- utoc: {c['note']}")
            continue
        h = c.get("header", {})
        di = c.get("directory_index") or {}
        print(f"- utoc {c.get('entry', '')}: TOC "
              f"v{h.get('version')} ({h.get('version_name')}), "
              f"{c.get('entry_count')} chunks, "
              f"{c.get('total_chunk_bytes')} bytes in "
              f"{c.get('total_stored_bytes')} stored, methods "
              f"{c.get('compression_methods')}, types "
              f"{c.get('entries_by_type')}")
        if di:
            print(f"    directory index: mount "
                  f"{di.get('mount_point')!r}, "
                  f"{di.get('files_named')} files named")
        if c.get("entries_capped"):
            print(f"    {c['entries_capped']}")
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
