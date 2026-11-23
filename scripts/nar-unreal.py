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
  listings, Engine/Game config file presence,
- UAsset-level inspection by narlib.uasset (pure Python,
  public package layout): FPackageFileSummary with UE4/UE5
  version gating, name/import/export/depends tables with
  references resolved to readable names, soft package
  references and searchable names, cooked .uexp/.ubulk
  awareness, and a best-effort FPropertyTag stream parse
  whose every result carries a confidence note. Packages
  are parsed loose in an APK, inside IoStore containers
  (directory-indexed ExportBundleData chunks), and inside
  .pak files when --work extraction is enabled; a bare
  .uasset/.umap file is a target of its own.
- Zen package inspection by narlib.zen (pure Python,
  public Zen layout): the IoStore-native packages UE5
  cooking writes carry a Zen header instead of an
  FPackageFileSummary — header, versioning info when the
  writer recorded it, per-package name map, bulk data
  map, imported public export hashes, import/export
  maps and export bundle entries are parsed; sections
  no public reader decodes are located and measured.

Usage:
    python3 nar-unreal.py app.apk [--json] [--work DIR]
    python3 nar-unreal.py content.pak [--json]
    python3 nar-unreal.py content.utoc [--json]
    python3 nar-unreal.py asset.uasset [--json]

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
from narlib.iostore import (IoStoreError, extract_chunk,  # noqa: E402
                            parse_utoc)
from narlib.uasset import UAssetError, parse_package  # noqa: E402
from narlib.zen import ZenError, parse_zen_package  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))

# Per-container chunk detail kept in JSON output; counts and
# totals always cover every chunk.
ENTRY_CAP = 250
CONTAINER_CAP = 5
# Packages fully parsed per source (loose / IoStore / pak);
# counts always cover every package found.
PACKAGE_CAP = 5
NAME_CAP = 500


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
        "index_encrypted": out.get("index_encrypted"),
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


def zen_package_summary(data, name):
    """Parse one Zen package into a presentation-ready
    record (detail capped the same way as classic
    packages; counts complete). A chunk whose header
    does not validate for a full parse — a newer Zen
    layout than this build reads, or a damaged chunk —
    keeps its identification record with the parse
    reason in the note; it is never reported as a
    corrupt classic package."""
    try:
        parsed = parse_zen_package(data, name)
    except ZenError as e:
        record = _zen_package_record(data, name)
        record["note"] += (
            f" A full Zen parse was attempted and "
            f"stopped: {e}")
        return record
    total_names = len(parsed["names"])
    if total_names > NAME_CAP:
        parsed["names"] = parsed["names"][:NAME_CAP]
        parsed["names_capped"] = (
            f"name detail capped at {NAME_CAP} of {total_names}; "
            "counts cover every name")
    for key in ("imports", "exports"):
        total = len(parsed[key])
        if total > ENTRY_CAP:
            parsed[key] = parsed[key][:ENTRY_CAP]
            parsed[key + "_capped"] = (
                f"{key} detail capped at {ENTRY_CAP} of {total}; "
                "counts cover every entry")
    parsed["entry"] = name
    parsed["zen_header_size"] = parsed["summary"]["header_size"]
    return parsed


def package_summary(data, name, uexp_data=None):
    """Parse one package into a presentation-ready record
    (name/import/export detail capped; counts complete).
    Zen (IoStore-native) chunks dispatch to the Zen
    parser; everything else to the classic one."""
    if _is_zen_package(data):
        return zen_package_summary(data, name)
    try:
        parsed = parse_package(data, name, uexp_data)
    except UAssetError as e:
        return {"entry": name, "error": f"package parse failed: {e}"}
    total_names = len(parsed["names"])
    if total_names > NAME_CAP:
        parsed["names"] = parsed["names"][:NAME_CAP]
        parsed["names_capped"] = (
            f"name detail capped at {NAME_CAP} of {total_names}; "
            "counts cover every name")
    for key in ("imports", "exports", "depends"):
        total = len(parsed[key])
        if total > ENTRY_CAP:
            parsed[key] = parsed[key][:ENTRY_CAP]
            parsed[key + "_capped"] = (
                f"{key} detail capped at {ENTRY_CAP} of {total}; "
                "counts cover every entry")
    searchable = parsed["searchable_names"]
    if len(searchable) > 100:
        parsed["searchable_names"] = dict(
            list(searchable.items())[:100])
        parsed["searchable_names_capped"] = (
            f"searchable-names detail capped at 100 of "
            f"{len(searchable)}; counts cover every entry")
    parsed["entry"] = name
    return parsed


def _package_generation(pkg):
    if not pkg or pkg.get("error"):
        return None
    if pkg.get("format") == "zen-package":
        s = pkg.get("summary") or {}
        if s.get("file_version_ue5"):
            return (f"UE5-era (Zen package; recorded UE5 "
                    f"object version {s['file_version_ue5']})")
        return ("UE5-era (IoStore/Zen packaging; header "
                "records no per-package object version)")
    s = pkg.get("summary") or {}
    if s.get("file_version_ue5"):
        return (f"UE5-era (UE5 object version "
                f"{s['file_version_ue5']})")
    if s.get("unversioned"):
        return "unversioned package (engine version not recorded)"
    if s.get("file_version_ue4"):
        return (f"UE4-era (UE4 object version "
                f"{s['file_version_ue4']})")
    return None


def _package_limitations():
    return [
        "Package property streams are parsed best-effort: "
        "values are decoded only for primitive types whose "
        "encoding is version-stable, and class-specific data "
        "after the tag stream is reported by size, not "
        "decoded.",
        "Packages flagged PKG_UnversionedProperties need a "
        ".usmap mapping file to read properties; their "
        "property streams are reported as unparsed, with "
        "the reason.",
        "UE5 property tag extensions (UE5 object version "
        ">= 1011) are reported as unsupported rather than "
        "guessed at.",
        "Zen (IoStore-native) packages are parsed from "
        "their Zen header: name map, import/export maps "
        "and bundle entries are decoded, while the "
        "dependency-bundle and imported-package-name "
        "sections are located and measured, not decoded, "
        "and versioned Zen property tag streams inside "
        "exports are located and measured, not decoded.",
    ]


PACKAGE_MAGIC_LE = b"\xc1\x83\x2a\x9e"


def _is_zen_package(blob):
    """UE5 IoStore-native (Zen) package chunks carry the
    package magic as a trailer, not a header: the chunk
    opens with the Zen package header instead of an
    FPackageFileSummary. (On a real UE 5.3 container set,
    every stored package chunk in it — 684 of 684 — has
    exactly this shape, and its recorded header size is
    in range in every case.)"""
    return len(blob) >= 8 \
        and blob[:4] != PACKAGE_MAGIC_LE \
        and blob[-4:] == PACKAGE_MAGIC_LE


def _zen_package_record(blob, path):
    """Presentation record for a Zen-format package
    chunk: identified and inventoried, never fed to the
    classic summary parser under a misleading corruption
    error, and no classic summary facts are claimed."""
    return {
        "entry": path,
        "format": "zen-package",
        "size": len(blob),
        "zen_header_size": int.from_bytes(blob[4:8],
                                          "little"),
        "note": ("UE5 IoStore-native (Zen) package: the "
                 "chunk carries a Zen package header, not "
                 "an FPackageFileSummary, so the classic "
                 "package parser does not apply. Zen "
                 "headers record no UE4/UE5 object "
                 "version — packages are versioned by "
                 "the engine build, not per package."),
    }


def iostore_packages(utoc_bytes, ucas_bytes, container_name):
    """Extract and parse the packages a container's
    directory index names (.uasset/.umap chunks)."""
    out = []
    if ucas_bytes is None:
        return out
    try:
        container = parse_utoc(utoc_bytes, container_name)
    except IoStoreError:
        return out
    for entry in container["entries"]:
        path = entry.get("file") or ""
        if not path.lower().endswith((".uasset", ".umap")):
            continue
        if len(out) >= PACKAGE_CAP:
            break
        try:
            blob = extract_chunk(container, ucas_bytes,
                                 entry["index"])
        except IoStoreError as e:
            out.append({"entry": path, "container": container_name,
                        "error": f"IoStore extraction failed: {e}"})
            continue
        record = package_summary(blob, path)
        record["container"] = container_name
        out.append(record)
    return out


def pak_packages(pak_path, out_dir):
    """Extract and parse a pak's .uasset/.umap entries.

    Uses nar-pak's own extractor entry by entry (exact-name
    matches, .uexp siblings included); extraction failures
    (encrypted, unsupported compression) are recorded per
    package, never fatal.
    """
    listing = run_json_tool("nar-pak.py", [pak_path])
    if not listing or not listing.get("supported"):
        return [], 0
    entries = listing.get("entries") or []
    asset_names = [e["name"] for e in entries
                   if e["name"].lower().endswith(
                       (".uasset", ".umap"))]
    by_lower = {e["name"].lower(): e["name"] for e in entries}
    out = []
    for name in asset_names[:PACKAGE_CAP]:
        stem = name.rsplit(".", 1)[0]
        wanted = [name]
        uexp_name = by_lower.get((stem + ".uexp").lower())
        if uexp_name:
            wanted.append(uexp_name)
        blobs = {}
        failure = None
        for want in wanted:
            rep = run_json_tool(
                "nar-pak.py",
                [pak_path, "--extract", want, "--out", out_dir])
            extracted = (rep or {}).get("extracted") or []
            errors = (rep or {}).get("extract_errors") or []
            if extracted:
                with open(extracted[0]["out_path"], "rb") as fh:
                    blobs[want] = fh.read()
            elif errors:
                failure = errors[0].get("error")
        if name not in blobs:
            out.append({"entry": name,
                        "error": "pak extraction failed: "
                                 f"{failure or 'entry not extracted'}"})
            continue
        record = package_summary(
            blobs[name], name,
            blobs.get(uexp_name) if uexp_name else None)
        out.append(record)
    return out, len(asset_names)


def analyze(target, work_dir=None):
    report = {"tool": "nar-unreal", "version": "2.4.0",
              "target": os.path.abspath(target),
              "target_sha256": sha256_of(target)}
    lower = target.lower()
    if lower.endswith((".uasset", ".umap")):
        stem = target.rsplit(".", 1)[0]
        uexp_data = None
        if os.path.exists(stem + ".uexp"):
            with open(stem + ".uexp", "rb") as fh:
                uexp_data = fh.read()
        with open(target, "rb") as fh:
            pkg = package_summary(
                fh.read(), os.path.basename(target), uexp_data)
        report["verdict"] = "package"
        report["generation"] = _package_generation(pkg)
        report["packages"] = [pkg]
        report["limitations"] = _package_limitations()
        return report
    if lower.endswith(".pak"):
        report["verdict"] = "pak-container"
        report["paks"] = [pak_summary(target)]
        if work_dir:
            pkgs, total = pak_packages(
                target, os.path.join(work_dir, "pak-assets"))
            report["pak_packages"] = pkgs
            report["pak_package_file_count"] = total
            report["limitations"] = _package_limitations()
        else:
            report["limitations"] = [
                "Asset-level parsing inside a .pak needs "
                "--work DIR (entries are extracted there "
                "first).",
            ]
        return report
    if lower.endswith(".utoc"):
        sibling = target[:-5] + ".ucas"
        ucas_name = ucas_size = None
        ucas_bytes = None
        if os.path.exists(sibling):
            ucas_name = os.path.basename(sibling)
            ucas_size = os.path.getsize(sibling)
            with open(sibling, "rb") as fh:
                ucas_bytes = fh.read()
        with open(target, "rb") as fh:
            utoc_bytes = fh.read()
        container = iostore_summary(
            utoc_bytes, os.path.basename(target),
            ucas_name, ucas_size)
        report["verdict"] = "iostore-container"
        report["generation"] = "UE5-era (IoStore packaging)"
        report["iostore_files"] = [os.path.basename(target)]
        report["iostore_containers"] = [container]
        report["limitations"] = _iostore_limitations()
        pkgs = iostore_packages(
            utoc_bytes, ucas_bytes, os.path.basename(target))
        if pkgs:
            report["iostore_packages"] = pkgs
            report["limitations"] += _package_limitations()
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
    asset_names = []
    extracted_paks = []
    packages = []
    io_packages = []
    with zipfile.ZipFile(target) as zf:
        names = zf.namelist()
        infos = {i.filename: i for i in zf.infolist()}
        by_lower = {n.lower(): n for n in names}
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
                    extracted_paks.append((name, tmp))
                else:
                    summary = {"entry": name,
                               "note": "pass --work DIR to parse "
                                       "bundled paks"}
                summary["entry"] = name
                paks.append(summary)
            elif ln.endswith((".utoc", ".ucas")):
                iostore.append(name)
            elif ln.endswith((".uasset", ".umap")):
                asset_names.append(name)
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
        for name in asset_names[:PACKAGE_CAP]:
            stem = name.rsplit(".", 1)[0]
            uexp_entry = by_lower.get((stem + ".uexp").lower())
            packages.append(package_summary(
                zf.read(name), name,
                zf.read(uexp_entry) if uexp_entry else None))
        for name in utoc_names[:2]:
            ucas_name = ucas_by_prefix.get(name[:-5].lower())
            if not ucas_name:
                continue
            io_packages.extend(iostore_packages(
                zf.read(name), zf.read(ucas_name), name))
            if len(io_packages) >= PACKAGE_CAP:
                io_packages = io_packages[:PACKAGE_CAP]
                break
    pak_pkgs = []
    pak_pkg_total = 0
    if work_dir:
        for entry_name, tmp in extracted_paks:
            pkgs, total = pak_packages(
                tmp, os.path.join(
                    work_dir, "pak-assets",
                    os.path.basename(entry_name)))
            pak_pkg_total += total
            for rec in pkgs:
                rec["container"] = entry_name
            pak_pkgs.extend(pkgs)
            if len(pak_pkgs) >= PACKAGE_CAP:
                pak_pkgs = pak_pkgs[:PACKAGE_CAP]
                break
    generation = None
    if iostore:
        generation = "UE5-era (IoStore packaging)"
    elif versions.get("unreal_engine"):
        generation = versions["unreal_engine"]
    if not generation:
        for pkg in packages + io_packages + pak_pkgs:
            generation = _package_generation(pkg)
            if generation:
                break
    limitations = [
        "Encrypted pak entries are counted, never decrypted "
        "(key extraction is out of scope).",
    ]
    if containers:
        limitations = _iostore_limitations() + limitations
    if packages or io_packages or pak_pkgs:
        limitations += _package_limitations()
    if paks and not work_dir:
        limitations.append(
            "Asset-level parsing inside .pak files needs "
            "--work DIR (entries are extracted there first); "
            "loose and IoStore-resident packages are parsed "
            "in place.")
    report.update({
        "verdict": "unreal" if (unreal_hint or paks or iostore
                                or asset_names)
                   else "absent",
        "generation": generation,
        "version_evidence": {k: v for k, v in versions.items()
                             if k.startswith("unreal")},
        "paks": paks,
        "iostore_files": iostore,
        "iostore_containers": containers,
        "config_files": configs[:25],
        "package_files": asset_names[:25],
        "package_file_count": len(asset_names),
        "packages": packages,
        "iostore_packages": io_packages,
        "pak_packages": pak_pkgs,
        "pak_package_file_count": pak_pkg_total,
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
    pkg_groups = (("packages", report.get("packages")),
                  ("iostore_packages",
                   report.get("iostore_packages")),
                  ("pak_packages", report.get("pak_packages")))
    for _label, group in pkg_groups:
        for pkg in group or []:
            _human_package(pkg)
    if report.get("package_file_count"):
        print(f"Package files in target: "
              f"{report['package_file_count']}")
    for lim in report.get("limitations", []):
        print(f"limitation: {lim}")


def _human_package(pkg):
    entry = pkg.get("entry", "")
    if pkg.get("error"):
        print(f"- package {entry}: {pkg['error']}")
        return
    if pkg.get("format") == "zen-package":
        counts = pkg.get("counts", {})
        if not counts:
            print(f"- package {entry}: Zen package "
                  f"(identification only)")
            return
        s = pkg.get("summary", {})
        print(f"- package {entry}: Zen package "
              f"({s.get('layout')}), "
              f"{s.get('package_name')}, "
              f"{counts.get('names')} names, "
              f"{counts.get('imports')} imports, "
              f"{counts.get('exports')} exports")
        for exp in pkg.get("exports", []):
            props = exp.get("properties") or {}
            print(f"    export {exp.get('object_name')}: "
                  f"class {exp.get('class_resolved')}, "
                  f"{exp.get('cooked_serial_size')} bytes in "
                  f"{(exp.get('data_location') or {}).get('file')}, "
                  f"properties {props.get('status')}")
        return
    s = pkg.get("summary", {})
    if s.get("file_version_ue5"):
        ver = f"UE5 object version {s['file_version_ue5']}"
    elif s.get("unversioned"):
        ver = "unversioned"
    else:
        ver = f"UE4 object version {s.get('file_version_ue4')}"
    counts = pkg.get("counts", {})
    print(f"- package {entry}: {ver}, {counts.get('names')} "
          f"names, {counts.get('imports')} imports, "
          f"{counts.get('exports')} exports")
    for exp in pkg.get("exports", []):
        props = exp.get("properties") or {}
        print(f"    export {exp.get('object_name')}: class "
              f"{exp.get('class_resolved')}, "
              f"{exp.get('serial_size')} bytes in "
              f"{(exp.get('data_location') or {}).get('file')}, "
              f"properties {props.get('status')}"
              + (f" ({props.get('tag_count')} tags)"
                 if props.get("tag_count") is not None else ""))


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Unreal deep dive: generation evidence, pak "
                    "inventory/encryption, IoStore parsing, and "
                    "UAsset-level package inspection.")
    p.add_argument("target",
                   help="path to an .apk, .pak, .utoc, .uasset "
                        "or .umap file")
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
