#!/usr/bin/env python3
"""nar-godot.py: inspect a Godot .pck pack (standalone or inside an APK).

Parses the PCK header and file directory directly, stdlib only:
magic GDPC, pack format version, engine version, the pack-level
encryption flag (format 2+), and the contained file list with sizes.
Format 3 (Godot 4.5+) moves the directory to the end of the pack:
the header gains a directory-offset field and entry offsets are
relative to the file base. When the stdlib parse cannot read the
directory (an encrypted pack encrypts its directory too),
GodotPckTool is used as a fallback when installed; if neither
works, the header facts are reported and the listing is honestly
marked unavailable.

Text scenes/resources (.tscn/.tres) — inside a pack, or a bare
file given as the target — get a relationship record from their
section headers: ext_resource paths + ids, sub_resource ids, node
count, and node instance= references resolved to the external
scene they instance. Encrypted entries are named, never decoded.

For an APK: embedded *.pck files are listed; an APK with the Godot
engine library but no .pck ships its project files loose under
assets/ instead, and that is what gets reported.

Usage:
    python3 nar-godot.py game.pck [--json] [--limit N]
    python3 nar-godot.py game.apk [--json] [--limit N]
    python3 nar-godot.py scene.tscn [--json]

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

PCK_MAGIC = b"GDPC"
FLAG_ENCRYPTED = 0x1
FLAG_RELATIVE_BASE = 0x2

# Phase 10 parser resource caps: whole-blob reads of
# attacker-controlled inputs are bounded. A .pck is parsed
# from memory by design, so its read is capped (real packs
# in the project corpora are far below this); a bare text
# scene is capped tighter. Above a cap the report carries
# a named error instead of an unbounded allocation.
MAX_PCK_BYTES = 512 * 1024 * 1024
MAX_SCENE_BYTES = 64 * 1024 * 1024


class PckError(Exception):
    pass


def parse_pck(data):
    """Parse header + directory. Returns a report dict (no file list
    truncation; callers slice for display). Raises PckError."""
    if len(data) < 32 or data[:4] != PCK_MAGIC:
        raise PckError("no GDPC magic: not a Godot .pck file")
    fmt, vmaj, vmin, vpatch = struct.unpack_from("<IIII", data, 4)
    report = {"format_version": fmt,
              "engine_version": f"{vmaj}.{vmin}.{vpatch}",
              "size_bytes": len(data)}
    if fmt >= 2:
        flags, file_base = struct.unpack_from("<IQ", data, 20)
        report["pack_flags"] = flags
        report["encrypted"] = bool(flags & FLAG_ENCRYPTED)
        # Entry offsets are stored relative to the file base in
        # format 3 (always) and in format 2 when the relative-base
        # flag is set; in plain format 2 they are absolute.
        base = file_base if (fmt >= 3
                             or flags & FLAG_RELATIVE_BASE) else 0
        if fmt == 2:
            dir_offset = 96  # header + 16 reserved uint32
        elif fmt == 3:
            # Format 3 header is 104 bytes and the directory sits
            # at the recorded offset (the end of the pack), not
            # right after the header.
            if len(data) < 40:
                raise PckError(
                    "truncated format-3 header (directory "
                    "offset field incomplete)")
            dir_offset = struct.unpack_from("<Q", data, 32)[0]
            report["directory_offset"] = dir_offset
        else:
            dir_offset = None  # newer layout this reader does not know
    elif fmt == 1:
        file_base = struct.unpack_from("<Q", data, 20)[0]
        report["pack_flags"] = None
        report["encrypted"] = None  # v1 header carries no flag field
        dir_offset = 92
        base = 0
    else:
        raise PckError(f"unknown pack format version {fmt}")
    report["file_base"] = file_base
    if report["encrypted"]:
        report["files"] = []
        report["file_count"] = None
        report["listing_error"] = (
            "pack is flagged encrypted; the directory is encrypted"
            " too and cannot be listed without the key")
        return report
    if dir_offset is None:
        report["files"] = []
        report["file_count"] = None
        report["listing_error"] = (
            f"pack format {fmt} directory layout is not supported"
            " by this reader; only the header facts above are"
            " reported")
        return report
    if dir_offset + 4 > len(data):
        raise PckError("directory offset points outside the pack")
    pos = dir_offset
    if pos + 4 > len(data):
        raise PckError("truncated before the file directory")
    count = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    if count > 1_000_000:
        raise PckError(f"implausible file count in directory: {count}")
    files = []
    for _ in range(count):
        if pos + 4 > len(data):
            raise PckError("directory is truncated")
        plen = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if plen == 0 or plen > 8192 or pos + plen > len(data):
            raise PckError("directory entry has an implausible path"
                           " length; the directory may be encrypted"
                           " or the layout differs")
        raw = data[pos:pos + plen]
        pos += (plen + 3) & ~3
        try:
            path = raw.rstrip(b"\x00").decode("utf-8")
        except UnicodeDecodeError as e:
            raise PckError(f"directory path does not decode: {e}") from e
        # Entry record: offset+size+MD5 = 32 bytes, plus a
        # 4-byte flags word in format >= 2 — the guard must
        # cover the flags read too (a directory truncated
        # at exactly 32–35 bytes used to leak struct.error
        # instead of PckError; stability audit B-05).
        need = 36 if fmt >= 2 else 32
        if pos + need > len(data):
            raise PckError("directory is truncated at entry data")
        off, size = struct.unpack_from("<QQ", data, pos)
        pos += 16
        pos += 16  # MD5 of the file data
        entry_flags = 0
        if fmt >= 2:
            entry_flags = struct.unpack_from("<I", data, pos)[0]
            pos += 4
        if base + off + size > len(data):
            raise PckError(f"entry {path!r} points outside the pack"
                           " (offset+size beyond end of file)")
        files.append({"path": path, "offset": base + off,
                      "size_bytes": size,
                      "flags": entry_flags,
                      "encrypted": bool(entry_flags & FLAG_ENCRYPTED)})
    report["file_types"] = _classify_files(files, data)
    report["files"] = files
    report["file_count"] = len(files)
    report["total_content_bytes"] = sum(f["size_bytes"] for f in files)
    rels, rel_counts = scene_relationships(files, data)
    report["scene_relationships"] = rels
    report["scene_relationship_counts"] = rel_counts
    if not rels:
        binary_scenes = sum(
            1 for f in files
            if f["path"].lower().endswith((".scn", ".res")))
        if binary_scenes:
            report["scene_relationships_note"] = (
                f"{binary_scenes} binary scene/resource "
                "entries (.scn/.res) carry no text section "
                "headers; relationships are extracted only "
                "from text .tscn/.tres files")
    return report


_EXT_TYPES = (
    ("scene", (".tscn", ".scn")),
    ("resource", (".tres", ".res", ".material", ".theme")),
    ("script", (".gd",)),
    ("compiled script", (".gdc",)),
    ("shader", (".gdshader", ".shader")),
    ("texture", (".png", ".jpg", ".jpeg", ".webp", ".svg",
                 ".bmp", ".dds", ".ktx", ".exr", ".hdr",
                 ".tga", ".stex", ".ctex")),
    ("audio", (".ogg", ".wav", ".mp3", ".opus", ".flac")),
    ("font", (".ttf", ".otf", ".font", ".fnt")),
    ("model", (".obj", ".gltf", ".glb", ".mesh", ".dae")),
    ("translation", (".translation", ".po", ".csv")),
    ("import metadata", (".import",)),
    ("text", (".txt", ".md", ".cfg", ".ini")),
)


def _header_type(head):
    """(type, detail) from content magic, or (None, None)."""
    if head.startswith(b"[gd_scene"):
        return "scene", None
    if head.startswith(b"[gd_resource"):
        return "resource", None
    if head.startswith(b"RSRC"):
        # Binary resource: after the magic come three u32
        # version fields, then the resource type as a
        # length-prefixed string. Claimed only when the
        # string validates as a printable identifier.
        if len(head) >= 20:
            ln = struct.unpack_from("<I", head, 16)[0]
            if 0 < ln <= 64 and 20 + ln <= len(head):
                raw = head[20:20 + ln].rstrip(b"\x00")
                try:
                    name = raw.decode("ascii")
                except UnicodeDecodeError:
                    name = ""
                if name and all(c.isalnum() or c in "_."
                                for c in name):
                    return "binary resource", name
        return "binary resource", None
    if head.startswith(b"\x89PNG") or head.startswith(b"\xff\xd8") \
            or head.startswith(b"DDS ") or head.startswith(b"\xabKTX") \
            or (head.startswith(b"RIFF")
                and head[8:12] == b"WEBP"):
        return "texture", None
    if head.startswith(b"OggS") or head.startswith(b"fLaC") \
            or head.startswith(b"ID3") \
            or (head.startswith(b"RIFF")
                and head[8:12] == b"WAVE"):
        return "audio", None
    if head.startswith((b"\x00\x01\x00\x00", b"OTTO", b"wOFF",
                        b"true")):
        return "font", None
    return None, None


def classify_godot_resource(path, head, encrypted=False):
    """Classify one pack entry by resource type.

    Returns (resource_type, evidence, detail). Header magic
    wins over the file extension; the extension is the
    fallback and is labeled as the evidence. Encrypted
    entries are NEVER typed — their content is not
    readable, so any type would be a guess.
    """
    if encrypted:
        return None, "encrypted entry: not classified", None
    if head:
        kind, detail = _header_type(head)
        if kind:
            return kind, "header", detail
    low = path.lower()
    base = low.rsplit("/", 1)[-1]
    if base in ("project.godot", "project.binary"):
        return "project config", "extension", None
    for kind, exts in _EXT_TYPES:
        if low.endswith(exts):
            return kind, "extension", None
    return "unknown", "none", None


def _classify_files(files, data=None):
    """Attach resource_type / type_evidence (/ type_detail)
    to listing entries and return per-type counts. `data`
    is the pack bytes for header evidence; without it only
    extension evidence is available."""
    counts = {}
    for f in files:
        head = None
        if data is not None and "offset" in f:
            head = data[f["offset"]:f["offset"] + 64]
        kind, evidence, detail = classify_godot_resource(
            f["path"], head, f.get("encrypted", False))
        f["resource_type"] = kind
        f["type_evidence"] = evidence
        if detail:
            f["type_detail"] = detail
        key = kind or "encrypted (unclassified)"
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def find_godotpcktool():
    cand = shutil.which("godotpcktool")
    if cand:
        return cand
    path = os.path.expanduser("~/workspace/tools/godotpcktool/godotpcktool")
    return path if os.path.isfile(path) else None


def tool_listing(pck_path):
    """Fallback listing via GodotPckTool. Returns (files, error)."""
    tool = find_godotpcktool()
    if not tool:
        return None, "GodotPckTool is not installed"
    try:
        proc = subprocess.run([tool, "-p", pck_path, "-a", "list"],
                              capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, f"GodotPckTool did not run: {e}"
    if proc.returncode != 0:
        # A failed run's stdout is not a listing, however
        # parseable its lines look (stability audit B-10).
        return None, (f"GodotPckTool exited "
                      f"{proc.returncode}: "
                      f"{(proc.stderr or '').strip()[:200]}")
    files = []
    for line in proc.stdout.splitlines():
        path, sep, size = line.rpartition(" size: ")
        if sep and size.strip().isdigit():
            files.append({"path": path.strip(),
                          "size_bytes": int(size.strip())})
    if not files:
        return None, ("GodotPckTool produced no parseable listing"
                      f" (exit {proc.returncode})")
    return files, None


# ---------------------------------------------------------------
# Text scene / resource relationships
#
# Godot's text formats (.tscn scenes, .tres resources) declare
# their references in section headers: [ext_resource ...] lines
# carry the external file path + the id other sections refer
# to, [sub_resource ...] lines mint internal ids, and [node ...]
# headers carry instance=ExtResource(<id>) when a node instances
# another scene. Parsing those headers yields the scene ->
# external-resource graph without interpreting property bodies.

_SCENE_PARSE_CAP = 25          # text scenes/resources per pack
_SCENE_TEXT_CAP = 4 * 1024 * 1024   # bytes per text file
_EXT_LIST_CAP = 100            # external resources listed per file

_SECTION_RE = re.compile(r"^\[(ext_resource|sub_resource|node)"
                         r"\s+(.*?)\]\s*$", re.M)
_ATTR_RE = re.compile(r'(\w+)\s*=\s*("[^"]*"|[^\s\]]+)')
_INSTANCE_RE = re.compile(
    r'instance\s*=\s*ExtResource\(\s*(?:"([^"]+)"|(\d+))\s*\)')


def _section_attrs(raw):
    attrs = {}
    for key, val in _ATTR_RE.findall(raw):
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        attrs[key] = val
    return attrs


def parse_text_scene(text, path):
    """Relationship record for one text scene/resource.

    ext_resource ids are strings in Godot 4 ("1_abcd") and
    integers in Godot 3 (1); both are kept as written so an
    instance= reference joins exactly.
    """
    kind = "scene" if text.startswith("[gd_scene") else \
        "resource"
    external = []
    sub_ids = []
    node_count = 0
    instanced = []
    for m in _SECTION_RE.finditer(text):
        section, raw = m.group(1), m.group(2)
        attrs = _section_attrs(raw)
        if section == "ext_resource":
            external.append({
                "id": attrs.get("id"),
                "path": attrs.get("path"),
                "type": attrs.get("type"),
                "uid": attrs.get("uid"),
            })
        elif section == "sub_resource":
            if attrs.get("id") is not None:
                sub_ids.append(attrs["id"])
        else:  # node
            node_count += 1
            inst = _INSTANCE_RE.search(raw)
            if inst:
                ref = inst.group(1) or inst.group(2)
                target = next(
                    (e["path"] for e in external
                     if e["id"] == ref), None)
                instanced.append({
                    "node": attrs.get("name"),
                    "ext_resource_id": ref,
                    "path": target,
                })
    return {
        "path": path,
        "kind": kind,
        "external_resources": external[:_EXT_LIST_CAP],
        "external_resource_count": len(external),
        "external_resources_truncated":
            len(external) > _EXT_LIST_CAP,
        "sub_resource_ids": sub_ids[:_EXT_LIST_CAP],
        "sub_resource_count": len(sub_ids),
        "node_count": node_count,
        "instanced_scenes": instanced,
        "evidence": "text section headers ([ext_resource] / "
                    "[sub_resource] / [node] instance=)",
    }


def scene_relationships(files, data):
    """Relationships for every text scene/resource in a
    parsed pack listing. Encrypted entries are counted as
    candidates but never decoded (their content is not
    readable); oversized files are skipped by size. Returns
    (records, accounting)."""
    candidates = [f for f in files
                  if f["path"].lower().endswith(
                      (".tscn", ".tres"))]
    records = []
    skipped = 0
    for f in candidates:
        if f.get("encrypted") or \
                f["size_bytes"] > _SCENE_TEXT_CAP or \
                len(records) >= _SCENE_PARSE_CAP:
            skipped += 1
            continue
        blob = data[f["offset"]:f["offset"] + f["size_bytes"]]
        if not blob.startswith((b"[gd_scene", b"[gd_resource")):
            skipped += 1
            continue
        records.append(parse_text_scene(
            blob.decode("utf-8", "replace"), f["path"]))
    return records, {"total": len(candidates),
                     "processed": len(records),
                     "skipped": skipped, "failed": 0}


def inspect_pck_bytes(data, label):
    report = {"source": label, "listing_via": "stdlib"}
    try:
        parsed = parse_pck(data)
        report.update(parsed)
    except PckError as e:
        report["parse_error"] = str(e)
    return report


def loose_project_files(names):
    """Entries that make up a loose (no-.pck) Godot export.

    The anchor is the compiled project file: exports ship
    assets/project.binary (Godot 3.1+ and 4) or, in source form,
    assets/project.godot. When the anchor is present, the whole
    assets/ tree except the dexopt profiles IS the exported
    project. Without an anchor, only the Godot-specific subtrees
    count: .godot/ (editor data), .import/ (the import cache with
    its .stex/.ctex resources), and stray project.godot files.
    """
    if any(n in ("assets/project.binary", "assets/project.godot")
           for n in names):
        return [n for n in names
                if n.startswith("assets/")
                and not n.startswith("assets/dexopt/")
                and not n.endswith("/")]
    return [n for n in names
            if n.startswith("assets/.godot/")
            or n.startswith("assets/.import/")
            or n.endswith("project.godot")]


def inspect(target):
    report = {"tool": "nar-godot", "target": os.path.abspath(target),
              "is_godot": False}
    if not os.path.isfile(target):
        raise FileNotFoundError(f"not a file: {target}")
    if target.lower().endswith((".tscn", ".tres")):
        if os.path.getsize(target) > MAX_SCENE_BYTES:
            report["error"] = (
                f"scene file exceeds the parser read cap "
                f"({MAX_SCENE_BYTES} bytes); not read")
            return report
        with open(target, "rb") as fh:
            blob = fh.read()
        if blob.startswith((b"[gd_scene", b"[gd_resource")):
            report["is_godot"] = True
            report["scene_relationships"] = [parse_text_scene(
                blob.decode("utf-8", "replace"),
                os.path.basename(target))]
            report["scene_relationship_counts"] = {
                "total": 1, "processed": 1,
                "skipped": 0, "failed": 0}
        else:
            report["error"] = ("file does not start with a "
                               "[gd_scene / [gd_resource text "
                               "header; binary scenes/resources "
                               "are not parsed for relationships")
        return report
    if target.lower().endswith(".pck"):
        if os.path.getsize(target) > MAX_PCK_BYTES:
            report["error"] = (
                f"pack file exceeds the parser read cap "
                f"({MAX_PCK_BYTES} bytes); not read")
            report["pck"] = {"source": os.path.basename(target),
                             "parse_error": report["error"]}
            return report
        with open(target, "rb") as fh:
            data = fh.read()
        sub = inspect_pck_bytes(data, os.path.basename(target))
        report["is_godot"] = "parse_error" not in sub
        report["pck"] = sub
        if "parse_error" in sub or "listing_error" in sub:
            # The fallback the module docstring promises
            # covers the listing_error outcomes too
            # (encrypted directory, unsupported format) —
            # it previously triggered only on parse_error,
            # so exactly the packs that need the tool most
            # never got it (B-10).
            files, err = tool_listing(target)
            if files is not None:
                sub["files"] = files
                sub["file_count"] = len(files)
                sub["file_types"] = _classify_files(files)
                sub["listing_via"] = "godotpcktool"
                report["is_godot"] = True
            else:
                sub["fallback_error"] = err
        return report
    if not zipfile.is_zipfile(target):
        report["error"] = "target is neither a .pck nor an APK/ZIP"
        return report
    with zipfile.ZipFile(target) as zf:
        names = zf.namelist()
        report["has_godot_engine_lib"] = any(
            "libgodot" in n for n in names)
        pcks = [n for n in names if n.lower().endswith(".pck")]
        report["embedded_pcks"] = pcks
        loose = loose_project_files(names)
        report["loose_project_files"] = len(loose)
        report["is_godot"] = bool(report["has_godot_engine_lib"]
                                  or pcks or loose)
        if pcks:
            # Bounded decompression: the entry's declared
            # uncompressed size is checked BEFORE zf.read
            # materializes it (Phase 10 parser cap).
            declared = zf.getinfo(pcks[0]).file_size
            if declared > MAX_PCK_BYTES:
                sub = {"source": pcks[0],
                       "parse_error": (
                           f"embedded pack declares {declared} "
                           f"bytes, over the parser read cap "
                           f"{MAX_PCK_BYTES}; not decompressed")}
                report["pck"] = sub
                return report
            data = zf.read(pcks[0])
            sub = inspect_pck_bytes(data, pcks[0])
            report["pck"] = sub
            if len(pcks) > 1:
                # Only the first embedded pack is parsed;
                # say so and name the rest (B-20).
                sub["packs_not_parsed"] = pcks[1:]
                sub["packs_note"] = (
                    f"{len(pcks)} embedded .pck files; "
                    "only the first was parsed")
            if "parse_error" in sub or "listing_error" in sub:
                # Temp dir is removed on BOTH the success and
                # failure paths (Phase 10 temp audit: this
                # mkdtemp previously leaked on every run).
                tmp_dir = tempfile.mkdtemp(prefix="nar-godot-")
                try:
                    tmp = os.path.join(
                        tmp_dir, os.path.basename(pcks[0]))
                    with open(tmp, "wb") as fh:
                        fh.write(data)
                    files, err = tool_listing(tmp)
                finally:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                if files is not None:
                    sub["files"] = files
                    sub["file_count"] = len(files)
                    sub["file_types"] = _classify_files(files)
                    sub["listing_via"] = "godotpcktool"
                else:
                    sub["fallback_error"] = err
        elif report["is_godot"]:
            report["note"] = (
                "no embedded .pck: this export ships its project files"
                f" loose ({len(loose)} project files under assets/),"
                " so there is no pack directory to list")
    return report


def human(report, limit):
    lines = [f"NAR Godot pack inspection: {report['target']}"]
    if not report.get("is_godot"):
        lines.append(f"NOT GODOT: {report.get('error') or 'no Godot engine lib, .pck, or project files found'}")
        return "\n".join(lines)
    pck = report.get("pck")
    if pck:
        lines.append(f"Pack: {pck['source']} (format {pck.get('format_version')},"
                     f" engine {pck.get('engine_version')},"
                     f" {pck.get('size_bytes', 0):,} bytes)")
        enc = pck.get("encrypted")
        lines.append("Encryption: " + (
            "YES (pack flag)" if enc else
            "no (pack flag clear)" if enc is False else
            "unknown (format 1 header has no flag field)"))
        if pck.get("file_count") is not None:
            lines.append(f"Files: {pck['file_count']} (listed via"
                         f" {pck.get('listing_via', 'stdlib')}),"
                         f" {pck.get('total_content_bytes', 0):,} content bytes")
            if pck.get("file_types"):
                lines.append(f"Resource types: {pck['file_types']}")
            shown = pck["files"] if limit <= 0 else pck["files"][:limit]
            for f in shown:
                mark = " [encrypted]" if f.get("encrypted") else ""
                rtype = f.get("resource_type")
                tmark = f" [{rtype}]" if rtype else ""
                lines.append(f"  {f['path']} ({f['size_bytes']:,} bytes)"
                             f"{mark}{tmark}")
            if len(shown) < pck["file_count"]:
                lines.append(f"  ... and {pck['file_count'] - len(shown)} more"
                             " (raise --limit, or use --json for all)")
        else:
            lines.append(f"Listing unavailable: "
                         f"{pck.get('listing_error') or pck.get('parse_error')}"
                         f"{'; fallback: ' + pck['fallback_error'] if pck.get('fallback_error') else ''}")
    for rel in report.get("scene_relationships") or []:
        inst = ", ".join(
            f"{i['node']} -> {i['path'] or i['ext_resource_id']}"
            for i in rel["instanced_scenes"])
        lines.append(
            f"Scene relationships: {rel['path']} "
            f"({rel['kind']}): {rel['node_count']} nodes, "
            f"{rel['external_resource_count']} external "
            f"resources, {rel['sub_resource_count']} "
            f"sub-resources"
            + (f"; instanced: {inst}" if inst else ""))
    if report.get("note"):
        lines.append(report["note"])
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR Godot .pck inspector (stdlib header/directory"
                    " parse, GodotPckTool fallback).")
    p.add_argument("target", help="path to a .pck file or an .apk")
    p.add_argument("--json", action="store_true",
                   help="machine-readable JSON output")
    p.add_argument("--limit", type=int, default=50,
                   help="max files to print in human output (default 50)")
    args = p.parse_args(argv)
    try:
        report = inspect(args.target)
    except FileNotFoundError as e:
        print(f"nar-godot: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(human(report, args.limit))
    return 0 if report.get("is_godot") else 1


if __name__ == "__main__":
    sys.exit(main())
