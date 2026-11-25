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
  whose every result carries a confidence note. Each
  package summary also carries a bounded `relationships`
  record: UObject class/super/outer/template and depends
  edges assembled from the parsed import/export/depends
  maps alone (table-derived; no extra decoding). Packages
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
import contextlib
import json
import os
import shutil
import subprocess
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import iostore as _iostore_mod  # noqa: E402
from narlib import uasset as _uasset_mod  # noqa: E402
from narlib import zen as _zen_mod  # noqa: E402
from narlib.hashing import sha256_of  # noqa: E402
from narlib.mmapio import mapped_file  # noqa: E402
from narlib.iostore import (IoStoreError, extract_chunk,  # noqa: E402
                            parse_utoc)
from narlib.uasset import UAssetError, parse_package  # noqa: E402
from narlib.zen import (ZenError, is_zen_package,  # noqa: E402
                        parse_zen_package)

HERE = os.path.dirname(os.path.abspath(__file__))

# Per-container chunk detail kept in JSON output; counts and
# totals always cover every chunk.
ENTRY_CAP = 250
CONTAINER_CAP = 5
# Packages fully parsed per source (loose / IoStore / pak);
# counts always cover every package found.
PACKAGE_CAP = 5
NAME_CAP = 500
# Searchable-names detail kept per package.
SEARCHABLE_CAP = 100
# Pure display lists in the APK report (config files and
# package files): their totals always appear alongside
# (package_file_count and the *_counts records), so a
# truncated display list never hides a total.
DISPLAY_CAP = 25
# In APK mode, IoStore package extraction considers this
# many .utoc containers (the package cap itself applies
# across them). --all-packages lifts this together with
# the package cap; the report's iostore_package_counts
# always records containers considered vs found.
IOSTORE_PACKAGE_CONTAINER_CAP = 2
# Relationship edges kept per package (class/super/outer/
# template/depends edges assembled from the parsed maps);
# the counts alongside always cover every edge derived.
# --all-details lifts it (B-18: the help text always
# promised detail caps lift; this one was wired to the
# constant directly and never lifted).
RELATIONSHIP_CAP = 250


class UnrealLimits:
    """Resolved detail/processing limits for one run.

    A field set to None means unlimited. The defaults are
    exactly the historical caps above; the CLI flags in
    main() are the only way to change them. Items are
    always processed one at a time and each extracted
    blob is released before the next item, so raising a
    limit grows the report, not the peak in-flight data.
    """

    def __init__(self, max_packages=PACKAGE_CAP,
                 max_containers=CONTAINER_CAP,
                 max_chunks=ENTRY_CAP, max_names=NAME_CAP,
                 max_searchable=SEARCHABLE_CAP,
                 max_display=DISPLAY_CAP,
                 max_relationships=RELATIONSHIP_CAP,
                 max_iostore_package_containers=
                 IOSTORE_PACKAGE_CONTAINER_CAP):
        self.max_packages = max_packages
        self.max_containers = max_containers
        self.max_chunks = max_chunks
        self.max_relationships = max_relationships
        self.max_names = max_names
        self.max_searchable = max_searchable
        self.max_display = max_display
        self.max_iostore_package_containers = \
            max_iostore_package_containers

    def describe(self):
        def show(value):
            return "unlimited" if value is None else value
        return {
            "max_packages": show(self.max_packages),
            "max_containers": show(self.max_containers),
            "max_chunks": show(self.max_chunks),
            "max_names": show(self.max_names),
            "max_searchable": show(self.max_searchable),
            "max_display": show(self.max_display),
            "max_iostore_package_containers":
                show(self.max_iostore_package_containers),
        }


def limits_from_args(args):
    """Build UnrealLimits from parsed CLI arguments.

    Defaults equal today's behaviour exactly; the --all-*
    flags lift their caps entirely (None)."""
    limits = UnrealLimits(
        max_packages=args.max_packages,
        max_containers=args.max_containers,
        max_chunks=args.max_chunks,
        max_names=args.max_names)
    if args.all_packages:
        limits.max_packages = None
        limits.max_iostore_package_containers = None
    if args.all_containers:
        limits.max_containers = None
    if args.all_details:
        limits.max_chunks = None
        limits.max_names = None
        limits.max_searchable = None
        limits.max_display = None
        limits.max_relationships = None
    return limits


def _account(total, processed, failed=0):
    """Structured cap accounting: every capped collection
    reports total / processed / skipped / failed, where
    failed counts items attempted but recorded with an
    error, and skipped counts items never attempted
    because of the cap."""
    return {"total": total, "processed": processed,
            "skipped": total - processed - failed,
            "failed": failed}


def _capped(items, cap):
    """Slice items to cap (None = unlimited); returns
    (shown, accounting for the full collection)."""
    if cap is None or len(items) <= cap:
        return list(items), _account(len(items), len(items))
    return list(items[:cap]), _account(len(items), cap)


def _failed_count(records):
    return sum(1 for r in records if r.get("error"))


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
                    ucas_size=None, limits=None):
    """Parse one .utoc into a presentation-ready container
    record (chunk detail capped; counts/totals complete)."""
    if limits is None:
        limits = UnrealLimits()
    try:
        parsed = parse_utoc(utoc_bytes, name)
    except IoStoreError as e:
        return {"entry": name, "error": f"IoStore parse failed: {e}"}
    parsed.pop("_blocks", None)
    entries = parsed.pop("entries")
    total = len(entries)
    shown, counts = _capped(entries, limits.max_chunks)
    parsed["entries"] = shown
    parsed["entries_counts"] = counts
    if counts["skipped"]:
        parsed["entries_capped"] = (
            f"chunk detail limited to {limits.max_chunks} "
            f"of {total} (--all-details to lift); "
            "counts and totals cover every chunk")
    parsed["entry"] = name
    if ucas_name:
        parsed["ucas_entry"] = ucas_name
        parsed["ucas_size"] = ucas_size
    return parsed


def _package_index_target(index, imports, exports):
    """Resolve one classic package index per the format:
    0 = none, positive = export (1-based), negative =
    import (1-based counting from -1). Returns a target
    record, or None for the none index."""
    if not index:
        return None
    if index > 0:
        i = index - 1
        target = {"kind": "export", "index": i}
        if i < len(exports):
            target["object_name"] = \
                exports[i].get("object_name")
            target["class_name"] = \
                exports[i].get("class_resolved")
        else:
            target["note"] = ("export index outside the "
                              "export map")
        return target
    i = -index - 1
    target = {"kind": "import", "index": i}
    if i < len(imports):
        imp = imports[i]
        target["object_name"] = imp.get("object_name")
        target["class_name"] = imp.get("class_name")
        target["class_package"] = imp.get("class_package")
    else:
        target["note"] = ("import index outside the "
                          "import map")
    return target


def classic_relationships(parsed, cap=RELATIONSHIP_CAP):
    """UObject relationship edges for a classic package,
    assembled only from the tables the parser already
    decoded: each export's class / super / outer /
    template package-index references, plus the depends
    map's per-export dependency edges. Every edge is
    table-derived; no property stream is consulted."""
    imports = parsed.get("imports") or []
    exports = parsed.get("exports") or []
    edges = []
    for exp in exports:
        src = {"kind": "export", "index": exp.get("index"),
               "object_name": exp.get("object_name")}
        for field, kind in (("class_index", "class"),
                            ("super_index", "super"),
                            ("outer_index", "outer"),
                            ("template_index", "template")):
            if field not in exp:
                continue
            target = _package_index_target(
                exp[field], imports, exports)
            if target is None:
                continue
            edges.append({
                "from": src, "to": target, "kind": kind,
                "evidence": f"export map {field} "
                            "(package-index resolution)"})
    for i, dep in enumerate(parsed.get("depends") or []):
        if i >= len(exports):
            break
        src = {"kind": "export",
               "index": exports[i].get("index", i),
               "object_name": exports[i].get("object_name")}
        for idx in dep.get("indices") or []:
            target = _package_index_target(
                idx, imports, exports)
            if target is None:
                continue
            edges.append({
                "from": src, "to": target, "kind": "depends",
                "evidence": "depends map entry "
                            "(package-index resolution)"})
    shown, counts = _capped(edges, cap)
    return {
        "edges": shown, "counts": counts,
        "evidence": "table-derived: assembled from the "
                    "parsed import/export/depends maps "
                    "only; no property-stream decoding",
    }


# FPackageObjectIndex kinds (top two bits of the u64),
# mirroring narlib.zen's OBJECT_INDEX_TYPES.
_ZEN_INDEX_KINDS = {0: "export", 1: "script-import",
                    2: "package-import", 3: "null"}


def zen_relationships(parsed, cap=RELATIONSHIP_CAP):
    """UObject relationship edges for a Zen package,
    assembled only from the export map the parser already
    decoded: each export's outer / class / super /
    template FPackageObjectIndex references, typed by
    the index kind (export / script-import /
    package-import) and carrying the parser's own
    resolution text. Null references carry no edge."""
    exports = parsed.get("exports") or []
    edges = []
    for exp in exports:
        src = {"kind": "export", "index": exp.get("index"),
               "object_name": exp.get("object_name")}
        for field in ("class", "super", "outer", "template"):
            raw = exp.get(field + "_index")
            if raw is None:
                continue
            kind_name = _ZEN_INDEX_KINDS.get(
                (raw >> 62) & 0x3, "null")
            if kind_name == "null":
                continue
            target = {"kind": kind_name,
                      "resolved": exp.get(field + "_resolved")}
            if kind_name == "export":
                target["index"] = raw & 0xFFFFFFFF
                # Mirror the classic path's unresolved
                # marking: a same-package export reference
                # the export map cannot resolve to a named
                # object carries a note, so downstream
                # consumers (the graph join) keep it
                # explicitly unresolved instead of reading
                # the bare index as a resolved target.
                idx = target["index"]
                if idx >= len(exports):
                    target["note"] = (
                        "export index outside the export map")
                elif exports[idx].get("object_name") is None:
                    target["note"] = (
                        "export object name does not resolve "
                        "through this package's name map")
            edges.append({
                "from": src, "to": target, "kind": field,
                "evidence": f"export map {field} object "
                            "index (FPackageObjectIndex)"})
    shown, counts = _capped(edges, cap)
    return {
        "edges": shown, "counts": counts,
        "evidence": "table-derived: assembled from the "
                    "parsed Zen export map only; no "
                    "property-stream decoding",
    }


def zen_package_summary(data, name, limits=None):
    """Parse one Zen package into a presentation-ready
    record (detail capped the same way as classic
    packages; counts complete). A chunk whose header
    does not validate for a full parse — a newer Zen
    layout than this build reads, or a damaged chunk —
    keeps its identification record with the parse
    reason in the note; it is never reported as a
    corrupt classic package."""
    if limits is None:
        limits = UnrealLimits()
    try:
        parsed = parse_zen_package(data, name)
    except ZenError as e:
        record = _zen_package_record(data, name)
        record["note"] += (
            f" A full Zen parse was attempted and "
            f"stopped: {e}")
        return record
    parsed["relationships"] = zen_relationships(
        parsed, limits.max_relationships)
    total_names = len(parsed["names"])
    shown, counts = _capped(parsed["names"], limits.max_names)
    parsed["names"] = shown
    parsed["names_counts"] = counts
    if counts["skipped"]:
        parsed["names_capped"] = (
            f"name detail limited to {limits.max_names} of "
            f"{total_names} (--max-names or --all-details "
            "to lift); counts cover every name")
    for key in ("imports", "exports"):
        total = len(parsed[key])
        shown, counts = _capped(parsed[key], limits.max_chunks)
        parsed[key] = shown
        parsed[key + "_counts"] = counts
        if counts["skipped"]:
            parsed[key + "_capped"] = (
                f"{key} detail limited to "
                f"{limits.max_chunks} of {total} "
                "(--max-chunks or --all-details to lift); "
                "counts cover every entry")
    parsed["entry"] = name
    parsed["zen_header_size"] = parsed["summary"]["header_size"]
    return parsed


def package_summary(data, name, uexp_data=None, limits=None):
    """Parse one package into a presentation-ready record
    (name/import/export detail capped; counts complete).
    Zen (IoStore-native) chunks dispatch to the Zen
    parser; everything else to the classic one."""
    if limits is None:
        limits = UnrealLimits()
    if is_zen_package(data):
        return zen_package_summary(data, name, limits)
    try:
        parsed = parse_package(data, name, uexp_data)
    except UAssetError as e:
        return {"entry": name, "error": f"package parse failed: {e}"}
    parsed["relationships"] = classic_relationships(
        parsed, limits.max_relationships)
    total_names = len(parsed["names"])
    shown, counts = _capped(parsed["names"], limits.max_names)
    parsed["names"] = shown
    parsed["names_counts"] = counts
    if counts["skipped"]:
        parsed["names_capped"] = (
            f"name detail limited to {limits.max_names} of "
            f"{total_names} (--max-names or --all-details "
            "to lift); counts cover every name")
    for key in ("imports", "exports", "depends"):
        total = len(parsed[key])
        shown, counts = _capped(parsed[key], limits.max_chunks)
        parsed[key] = shown
        parsed[key + "_counts"] = counts
        if counts["skipped"]:
            parsed[key + "_capped"] = (
                f"{key} detail limited to "
                f"{limits.max_chunks} of {total} "
                "(--max-chunks or --all-details to lift); "
                "counts cover every entry")
    searchable = parsed["searchable_names"]
    s_total = len(searchable)
    if limits.max_searchable is not None \
            and s_total > limits.max_searchable:
        parsed["searchable_names"] = dict(
            list(searchable.items())[:limits.max_searchable])
    parsed["searchable_names_counts"] = _account(
        s_total, len(parsed["searchable_names"]))
    if parsed["searchable_names_counts"]["skipped"]:
        parsed["searchable_names_capped"] = (
            f"searchable-names detail limited to "
            f"{limits.max_searchable} of {s_total} "
            "(--all-details to lift); counts cover every entry")
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


def unreal_capabilities():
    """Compose the per-module capability facts (each
    narlib module owns its own facts; this tool only
    composes them)."""
    return {
        "uasset": _uasset_mod.capabilities(),
        "zen": _zen_mod.capabilities(),
        "iostore": _iostore_mod.capabilities(),
    }


def _package_limitations(caps=None):
    """Generated from the narlib capability facts: every
    factual claim below traces to a capabilities() field,
    so the text cannot drift from the parsers."""
    if caps is None:
        caps = unreal_capabilities()
    ua = caps["uasset"]
    zn = caps["zen"]
    tag = {t["ue5_object_version"]: t
           for t in ua["tag_extension_layouts"]}
    t1011 = tag[1011]
    t1012 = tag["1012+"]
    unv = ua["unversioned"]
    zen_layouts = ", ".join(
        f"{lay['layout']} ({lay['status']}, verification: "
        f"{lay['verification']}"
        + (f", {lay['real_packages_verified']:,} real "
           f"packages verified"
           if lay.get("real_packages_verified") else "")
        + ")"
        for lay in zn["layouts"])
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
        f"UE5 property tag extensions are implemented: "
        f"UE5 object version 1011 uses the "
        f"{t1011['layout']} layout ({t1011['status']}, "
        f"verification: {t1011['verification']}) and UE5 "
        f"object version 1012+ uses the "
        f"{t1012['layout']} layout ({t1012['status']}, "
        f"verification: {t1012['verification']}); "
        f"{ua['tag_extension_note']}.",
        f"Unversioned packages are read under a stated "
        f"assumption: the UE5 {unv['assumed_ue5_object_version']} "
        f"table layout plus the final UE4 "
        f"({unv['assumed_ue4_object_version']}) layout, "
        f"accepted only when the structure validates end "
        f"to end.",
        "Kismet/Blueprint graphs are not decoded by "
        "this build.",
        f"Zen (IoStore-native) packages are parsed from "
        f"their Zen header (layouts: {zen_layouts}): "
        f"name map, import/export maps and bundle entries "
        f"are decoded, while the dependency-bundle and "
        f"imported-package-name sections are located and "
        f"measured, not decoded, and Zen export property "
        f"streams are located and measured, not decoded.",
    ]


def _zen_package_record(blob, path):
    """Presentation record for a Zen-format package
    chunk: identified and inventoried, never fed to the
    classic summary parser under a misleading corruption
    error, and no classic summary facts are claimed."""
    legacy_word = int.from_bytes(blob[0:4], "little") \
        if len(blob) >= 4 else None
    return {
        "entry": path,
        "format": "zen-package",
        "size": len(blob),
        # header_size sits in the SECOND word in the
        # UE5.3+ layout but in the FIRST word in the
        # legacy EA layout (narlib.zen.parse_summary).
        # This fallback record exists because the full
        # parse stopped, so the layout is undetermined:
        # report the 5.3+ word under the usual key and
        # disclose the legacy word alongside (B-17).
        "zen_header_size": int.from_bytes(blob[4:8],
                                          "little"),
        "zen_header_size_ea_legacy_word": legacy_word,
        "note": ("UE5 IoStore-native (Zen) package: the "
                 "chunk carries a Zen package header, not "
                 "an FPackageFileSummary, so the classic "
                 "package parser does not apply. Zen "
                 "headers record no UE4/UE5 object "
                 "version — packages are versioned by "
                 "the engine build, not per package. "
                 "zen_header_size is the UE5.3+ header "
                 "word; the legacy EA layout stores the "
                 "header size in the first word "
                 "(zen_header_size_ea_legacy_word) and "
                 "the layout could not be determined "
                 "here."),
    }


def iostore_packages(utoc_bytes, ucas_bytes, container_name,
                     limits=None):
    """Extract and parse the packages a container's
    directory index names (.uasset/.umap chunks).

    Returns (records, accounting): the accounting covers
    every package the index names, including the ones
    the cap skipped and the ones extraction failed on.
    Packages are extracted and parsed one at a time; each
    blob is released before the next chunk is read."""
    if limits is None:
        limits = UnrealLimits()
    out = []
    if ucas_bytes is None:
        # Zero packages because the container DATA is
        # missing is not the same fact as a container
        # with zero packages: the accounting must say
        # which (stability audit B-11).
        acct = _account(0, 0)
        acct["error"] = ("container data (.ucas) "
                         "unavailable; package inventory "
                         "not attempted")
        return out, acct
    try:
        container = parse_utoc(utoc_bytes, container_name)
    except IoStoreError as e:
        acct = _account(0, 0)
        acct["error"] = (f"container index (.utoc) did "
                         f"not parse: {e}")
        return out, acct
    if container.get("directory_index_error"):
        acct_note = container["directory_index_error"]
    else:
        acct_note = None
    named = [entry for entry in container["entries"]
             if (entry.get("file") or "").lower().endswith(
                 (".uasset", ".umap"))]
    total = len(named)
    for entry in named:
        if limits.max_packages is not None \
                and len(out) >= limits.max_packages:
            break
        path = entry.get("file") or ""
        try:
            blob = extract_chunk(container, ucas_bytes,
                                 entry["index"])
        except IoStoreError as e:
            out.append({"entry": path, "container": container_name,
                        "error": f"IoStore extraction failed: {e}"})
            continue
        record = package_summary(blob, path, limits=limits)
        record["container"] = container_name
        out.append(record)
        blob = None
    failed = _failed_count(out)
    acct = _account(total, len(out) - failed, failed)
    if acct_note:
        # The directory index named no files (its parse
        # failed inside parse_utoc): the zero total is a
        # failure fact, not an empty container (B-08/B-11).
        acct["error"] = acct_note
    return out, acct


def pak_packages(pak_path, out_dir, limits=None):
    """Extract and parse a pak's .uasset/.umap entries.

    Uses nar-pak's own extractor entry by entry (exact-name
    matches, .uexp siblings included); extraction failures
    (encrypted, unsupported compression) are recorded per
    package, never fatal.

    Returns (records, total, accounting): total counts
    every package entry in the pak, including the ones
    the cap skipped and the ones extraction failed on.
    Entries are extracted one at a time; each blob is
    released before the next entry is read.
    """
    if limits is None:
        limits = UnrealLimits()
    listing = run_json_tool("nar-pak.py", [pak_path])
    if not listing or not listing.get("supported"):
        return [], 0, _account(0, 0)
    entries = listing.get("entries") or []
    asset_names = [e["name"] for e in entries
                   if e["name"].lower().endswith(
                       (".uasset", ".umap"))]
    by_lower = {e["name"].lower(): e["name"] for e in entries}
    out = []
    wanted_names = asset_names if limits.max_packages is None \
        else asset_names[:limits.max_packages]
    for name in wanted_names:
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
            blobs.get(uexp_name) if uexp_name else None,
            limits=limits)
        out.append(record)
        blobs = {}
    failed = _failed_count(out)
    return out, len(asset_names), _account(
        len(asset_names), len(out) - failed, failed)


def analyze(target, work_dir=None, limits=None):
    if limits is None:
        limits = UnrealLimits()
    report = {"tool": "nar-unreal", "version": "2.6.2",
              "target": os.path.abspath(target),
              "target_sha256": sha256_of(target),
              "limits": limits.describe()}
    lower = target.lower()
    if lower.endswith((".uasset", ".umap")):
        stem = target.rsplit(".", 1)[0]
        # Bare packages are mapped, not read whole (the
        # parsers slice only what they touch); the mapping
        # lives until the package record is built.
        with contextlib.ExitStack() as stack:
            uexp_data = None
            if os.path.exists(stem + ".uexp"):
                uexp_data = stack.enter_context(
                    mapped_file(stem + ".uexp"))
            data = stack.enter_context(mapped_file(target))
            pkg = package_summary(
                data, os.path.basename(target), uexp_data,
                limits=limits)
        report["verdict"] = "package"
        report["generation"] = _package_generation(pkg)
        report["packages"] = [pkg]
        report["capabilities"] = unreal_capabilities()
        report["limitations"] = _package_limitations()
        return report
    if lower.endswith(".pak"):
        report["verdict"] = "pak-container"
        report["paks"] = [pak_summary(target)]
        if work_dir:
            pkgs, total, pkg_counts = pak_packages(
                target, os.path.join(work_dir, "pak-assets"),
                limits=limits)
            report["pak_packages"] = pkgs
            report["pak_package_file_count"] = total
            report["pak_package_counts"] = pkg_counts
            if pkg_counts["skipped"]:
                report["pak_packages_capped"] = (
                    f"package parsing limited to "
                    f"{limits.max_packages} of {total} "
                    "(--max-packages or --all-packages to "
                    "lift); counts cover every package")
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
        # Bare IoStore set: map the .utoc and the sibling
        # .ucas instead of reading them whole — the .ucas
        # is the large file (hundreds of MB in the wild)
        # and extract_chunk slices only the blocks of the
        # chunks actually extracted. The mappings live
        # until every record below is built (records hold
        # parsed data only, never mapping references).
        with contextlib.ExitStack() as stack:
            ucas_bytes = None
            if os.path.exists(sibling):
                ucas_name = os.path.basename(sibling)
                ucas_size = os.path.getsize(sibling)
                ucas_bytes = stack.enter_context(
                    mapped_file(sibling))
            utoc_bytes = stack.enter_context(
                mapped_file(target))
            container = iostore_summary(
                utoc_bytes, os.path.basename(target),
                ucas_name, ucas_size, limits=limits)
            report["verdict"] = "iostore-container"
            report["generation"] = "UE5-era (IoStore packaging)"
            report["iostore_files"] = [os.path.basename(target)]
            report["iostore_containers"] = [container]
            report["iostore_container_counts"] = _account(
                1, 0 if container.get("error") else 1,
                1 if container.get("error") else 0)
            report["capabilities"] = unreal_capabilities()
            report["limitations"] = _iostore_limitations()
            pkgs, pkg_counts = iostore_packages(
                utoc_bytes, ucas_bytes,
                os.path.basename(target), limits=limits)
            report["iostore_package_counts"] = pkg_counts
            if pkg_counts["skipped"]:
                report["iostore_packages_capped"] = (
                    f"package parsing limited to "
                    f"{limits.max_packages} of "
                    f"{pkg_counts['total']} (--max-packages or "
                    "--all-packages to lift); counts cover "
                    "every package")
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
        # APK/zip mode boundary: members materialize via
        # zf.read() (decompression requires it); only the
        # bare-file paths above map their files.
        container_names = utoc_names \
            if limits.max_containers is None \
            else utoc_names[:limits.max_containers]
        for name in container_names:
            ucas_name = ucas_by_prefix.get(name[:-5].lower())
            ucas_size = (infos[ucas_name].file_size
                         if ucas_name else None)
            containers.append(iostore_summary(
                zf.read(name), name, ucas_name, ucas_size,
                limits=limits))
        loose_names = asset_names \
            if limits.max_packages is None \
            else asset_names[:limits.max_packages]
        for name in loose_names:
            stem = name.rsplit(".", 1)[0]
            uexp_entry = by_lower.get((stem + ".uexp").lower())
            packages.append(package_summary(
                zf.read(name), name,
                zf.read(uexp_entry) if uexp_entry else None,
                limits=limits))
        # IoStore package extraction: the shared package
        # cap applies across the containers considered, in
        # order (today's behaviour). Each container is
        # visited with only the remaining allowance, so no
        # chunk is extracted past the cap; once the cap is
        # spent, later considered containers are still
        # visited with a zero allowance so their package
        # totals are counted (index parse only, no
        # extraction). Blobs live only inside
        # iostore_packages, one chunk at a time.
        io_considered = utoc_names \
            if limits.max_iostore_package_containers is None \
            else utoc_names[
                :limits.max_iostore_package_containers]
        io_counts_total = 0
        io_counts_failed = 0
        remaining = limits.max_packages
        for name in io_considered:
            ucas_name = ucas_by_prefix.get(name[:-5].lower())
            if not ucas_name:
                continue
            sub_limits = UnrealLimits(
                max_packages=remaining,
                max_containers=limits.max_containers,
                max_chunks=limits.max_chunks,
                max_names=limits.max_names,
                max_searchable=limits.max_searchable,
                max_display=limits.max_display,
                max_relationships=limits.max_relationships,
                max_iostore_package_containers=None)
            if work_dir:
                # Stream the .ucas to a work file and MAP
                # it instead of materializing the whole
                # container in memory (stability audit
                # B-12 — the bare-file path has always
                # mapped; the APK path read whole). The
                # records hold parsed data only, so the
                # mapping can close when the call returns.
                os.makedirs(work_dir, exist_ok=True)
                tmp_ucas = os.path.join(
                    work_dir,
                    os.path.basename(ucas_name) + ".nar-tmp")
                try:
                    with zf.open(ucas_name) as src, \
                            open(tmp_ucas, "wb") as dst:
                        shutil.copyfileobj(src, dst, 1 << 20)
                    with mapped_file(tmp_ucas) as ucas_bytes:
                        records, sub_counts = \
                            iostore_packages(
                                zf.read(name), ucas_bytes,
                                name, limits=sub_limits)
                finally:
                    try:
                        os.unlink(tmp_ucas)
                    except OSError:
                        pass
            else:
                records, sub_counts = iostore_packages(
                    zf.read(name), zf.read(ucas_name), name,
                    limits=sub_limits)
            io_counts_total += sub_counts["total"]
            io_counts_failed += sub_counts["failed"]
            io_packages.extend(records)
            if remaining is not None:
                remaining -= len(records)
                if remaining < 0:
                    remaining = 0
    pak_pkgs = []
    pak_pkg_total = 0
    pak_counts_failed = 0
    if work_dir:
        remaining = limits.max_packages
        for entry_name, tmp in extracted_paks:
            sub_limits = UnrealLimits(
                max_packages=remaining,
                max_containers=limits.max_containers,
                max_chunks=limits.max_chunks,
                max_names=limits.max_names,
                max_searchable=limits.max_searchable,
                max_display=limits.max_display,
                max_relationships=limits.max_relationships,
                max_iostore_package_containers=
                limits.max_iostore_package_containers)
            pkgs, total, sub_counts = pak_packages(
                tmp, os.path.join(
                    work_dir, "pak-assets",
                    os.path.basename(entry_name)),
                limits=sub_limits)
            pak_pkg_total += total
            pak_counts_failed += sub_counts["failed"]
            for rec in pkgs:
                rec["container"] = entry_name
            pak_pkgs.extend(pkgs)
            if remaining is not None:
                remaining -= len(pkgs)
                if remaining <= 0:
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
    container_failed = _failed_count(containers)
    container_counts = _account(
        len(utoc_names), len(containers) - container_failed,
        container_failed)
    loose_failed = _failed_count(packages)
    package_counts = _account(
        len(asset_names), len(packages) - loose_failed,
        loose_failed)
    io_failed = _failed_count(io_packages)
    io_package_counts = _account(
        io_counts_total, len(io_packages) - io_failed,
        io_failed)
    io_package_counts["containers_considered"] = \
        len(io_considered)
    io_package_counts["containers_total"] = len(utoc_names)
    pak_package_counts = _account(
        pak_pkg_total, len(pak_pkgs) - pak_counts_failed,
        pak_counts_failed)
    config_shown, config_counts = _capped(
        configs, limits.max_display)
    files_shown, files_counts = _capped(
        asset_names, limits.max_display)
    if container_counts["skipped"]:
        limitations.append(
            f"container parsing limited to "
            f"{limits.max_containers} of {len(utoc_names)} "
            "(--max-containers or --all-containers to "
            "lift); counts cover every container")
    if package_counts["skipped"]:
        limitations.append(
            f"loose package parsing limited to "
            f"{limits.max_packages} of {len(asset_names)} "
            "(--max-packages or --all-packages to lift); "
            "counts cover every package")
    if io_package_counts["skipped"]:
        limitations.append(
            f"IoStore package parsing limited to "
            f"{len(io_packages)} of {io_counts_total} "
            f"across the {len(io_considered)} container(s) "
            "considered for package extraction "
            "(--max-packages or --all-packages to lift); "
            "counts cover every package in the containers "
            "considered")
    if pak_package_counts["skipped"]:
        limitations.append(
            f"pak package parsing limited to "
            f"{len(pak_pkgs)} of {pak_pkg_total} "
            "(--max-packages or --all-packages to lift); "
            "counts cover every package in the paks visited")
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
        "iostore_container_counts": container_counts,
        "config_files": config_shown,
        "config_file_counts": config_counts,
        "package_files": files_shown,
        "package_file_counts": files_counts,
        "package_file_count": len(asset_names),
        "packages": packages,
        "package_counts": package_counts,
        "iostore_packages": io_packages,
        "iostore_package_counts": io_package_counts,
        "pak_packages": pak_pkgs,
        "pak_package_counts": pak_package_counts,
        "pak_package_file_count": pak_pkg_total,
        "capabilities": unreal_capabilities(),
        "limitations": limitations,
    })
    return report


def _iostore_limitations(caps=None):
    """Generated from narlib.iostore.capabilities()."""
    if caps is None:
        caps = unreal_capabilities()
    io = caps["iostore"]
    versions = io["toc_versions"]
    lo, hi = io["toc_version_range"]
    version_names = ", ".join(
        versions[str(v)] if str(v) in versions
        else versions[v]
        for v in range(lo, hi + 1))
    di_layouts = ", ".join(
        lay["layout"] for lay in io["directory_index_layouts"])
    decoded = ", ".join(io["compression_methods_decoded"])
    return [
        "IoStore chunk payloads are inventoried, not "
        "extracted, in APK mode; extraction is a narlib "
        "capability exercised by the unit suite.",
        f"IoStore TOC versions {lo}-{hi} are implemented "
        f"({version_names}); directory-index layouts are "
        f"implemented: {di_layouts}.",
        f"IoStore compression methods decoded: {decoded}; "
        f"compression methods other than {decoded} "
        f"(e.g. Oodle) are named, not decoded.",
        "IoStore containers flagged Encrypted, including "
        "AES-sealed indexes, are inventoried, never "
        "decrypted.",
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
    for key in ("iostore_container_counts", "package_counts",
                "iostore_package_counts", "pak_package_counts",
                "pak_package_counts"):
        counts = report.get(key)
        if counts and (counts.get("skipped")
                       or counts.get("failed")):
            print(f"{key}: {counts}")
    for capped_key in ("iostore_packages_capped",
                       "pak_packages_capped"):
        if report.get(capped_key):
            print(f"    {report[capped_key]}")
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
    p.add_argument("--max-packages", type=int,
                   default=PACKAGE_CAP, metavar="N",
                   help="packages fully parsed per source "
                        f"(default {PACKAGE_CAP})")
    p.add_argument("--max-containers", type=int,
                   default=CONTAINER_CAP, metavar="N",
                   help="IoStore containers parsed in APK "
                        f"mode (default {CONTAINER_CAP})")
    p.add_argument("--max-chunks", type=int,
                   default=ENTRY_CAP, metavar="N",
                   help="chunk/import/export detail kept per "
                        f"container or package (default "
                        f"{ENTRY_CAP})")
    p.add_argument("--max-names", type=int, default=NAME_CAP,
                   metavar="N",
                   help="name detail kept per package "
                        f"(default {NAME_CAP})")
    p.add_argument("--all-packages", action="store_true",
                   help="parse every package (lifts "
                        "--max-packages and the APK-mode "
                        "IoStore package-extraction container "
                        "limit); items are still processed "
                        "one at a time, but the report grows "
                        "with every package")
    p.add_argument("--all-containers", action="store_true",
                   help="parse every IoStore container "
                        "(lifts --max-containers)")
    p.add_argument("--all-details", action="store_true",
                   help="keep all chunk/name/import/export/"
                        "searchable detail and all display-"
                        "list entries (lifts --max-chunks, "
                        "--max-names and the detail caps); "
                        "the report grows with every entry")
    args = p.parse_args(argv)
    for flag in ("max_packages", "max_containers",
                 "max_chunks", "max_names"):
        if getattr(args, flag) < 0:
            p.error(f"--{flag.replace('_', '-')} must be >= 0")
    try:
        report = analyze(args.target, args.work,
                         limits_from_args(args))
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
