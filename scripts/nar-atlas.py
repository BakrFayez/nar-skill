#!/usr/bin/env python3
"""nar-atlas.py: texture atlas inventory (Part 4 section 4.1).

Finds texture atlases in a target's asset roots (resolved
through narlib.container, splits merged like nar-assets) and
normalises each one to a uniform record: page image, page
size, and every frame's rect, rotation, source size and trim
offset. Supported formats: Cocos plist atlases (XML and
binary) and Cocos particle plists, TexturePacker JSON (hash
and array) and Phaser multi-texture JSON, Starling XML and
TexturePacker XML, libGDX .atlas/.pack text, Godot .tres
AtlasTexture resources, and Unity .spriteatlas text YAML
(name and packed-sprite count only — packed sprites are
GUID references in text YAML, so frame names and rects are
not recoverable from the file alone and are never invented).

Frame names are then grouped by shared prefix and classified
with a generic part vocabulary into composition records
(schemas/composition.schema.json): atlas-side compositions
are name-based inference, labelled inferred, with driver
"unknown" because an atlas carries no driver data.

Reads are bounded: no member is read past 32 MiB, and JSON
parse attempts are capped at 16 MiB (skips are recorded in
limitations). A malformed member degrades to a per-file
error record, never a crashed run.

Usage:
    python3 nar-atlas.py app.apk [--json]

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import atlas as atlas_mod  # noqa: E402
from narlib import composition as composition_mod  # noqa: E402
from narlib import container as container_mod  # noqa: E402

VERSION = "3.0.1"

MEMBER_CAP_BYTES = 32 * 1024 * 1024
JSON_CAP_BYTES = 16 * 1024 * 1024

BASE_LIMITATIONS = [
    "Unity .spriteatlas text YAML references packed sprites "
    "by GUID only: frame names and rects are not recoverable "
    "from the .spriteatlas file alone, so those records "
    "carry the atlas name and packed-sprite count with "
    "names_recoverable=false.",
    "Godot AtlasTexture resources embedded as sub-resources "
    "in .tscn scene text are not scanned; only standalone "
    ".tres AtlasTexture files are parsed.",
    "Composition records are inferred from frame names only; "
    "an atlas carries no attachment or driver data, so "
    "attachment_points are empty and driver is unknown.",
]


def _read_member(zf, info, cap):
    """Bounded member read: bytes, or None when the member
    exceeds the cap (the caller records the skip)."""
    if info.file_size > cap:
        return None
    with zf.open(info) as fh:
        return fh.read(cap + 1)


def _sniff_json(data):
    """Parse bounded JSON bytes; the parsed doc or None."""
    try:
        return json.loads(data.decode("utf-8", "replace"))
    except ValueError:
        return None


def scan_target(target):
    resolved = container_mod.resolve_target(target)
    try:
        atlases = []
        particles = []
        limitations = list(BASE_LIMITATIONS)
        roots = list(resolved.assets_roots)
        if not roots and os.path.isfile(target) and \
                zipfile.is_zipfile(target):
            roots = [os.path.abspath(target)]
        for root in roots:
            archive_name = os.path.basename(root)
            try:
                zf = zipfile.ZipFile(root)
            except (zipfile.BadZipFile, OSError):
                continue
            with zf:
                for info in zf.infolist():
                    member = info.filename
                    if member.endswith("/"):
                        continue
                    low = member.lower()
                    ext = os.path.splitext(low)[1]
                    try:
                        _scan_member(zf, info, member, ext,
                                     archive_name, atlases,
                                     particles, limitations)
                    except Exception as exc:  # one bad member
                        # must never crash the run.
                        atlases.append({
                            "format": "unknown",
                            "texture": None,
                            "page_width": None,
                            "page_height": None,
                            "frames": [],
                            "frame_count": 0,
                            "packed_area": None,
                            "page_area": None,
                            "rotated_count": 0,
                            "error": f"member scan failed: {exc}",
                            "source": member,
                            "source_archive": archive_name,
                        })
        frames = []
        for rec in atlases:
            frames.extend(rec.get("frames") or [])
        compositions = composition_mod.compositions_from_frames(
            frames)
        totals = {
            "atlas_count": len(atlases),
            "frame_count": sum(r.get("frame_count", 0)
                               for r in atlases),
            "particle_count": len(particles),
        }
        report = {
            "tool": "nar-atlas",
            "version": VERSION,
            "target": os.path.abspath(target),
            "container": resolved.container_block(),
            "atlases": atlases,
            "particles": particles,
            "compositions": compositions,
            "totals": totals,
            "limitations": limitations,
        }
        return report
    finally:
        resolved.cleanup()


def _scan_member(zf, info, member, ext, archive_name, atlases,
                 particles, limitations):
    if ext == ".plist":
        data = _read_member(zf, info, MEMBER_CAP_BYTES)
        if data is None:
            limitations.append(
                f"{member}: plist member exceeds the "
                f"{MEMBER_CAP_BYTES}-byte read cap; skipped")
            return
        rec = atlas_mod.parse_cocos_plist(data)
        if rec.get("format") == "cocos-particle-plist":
            rec["source"] = member
            rec["source_archive"] = archive_name
            particles.append(rec)
            return
        if rec.get("error") and \
                "no 'frames' dictionary" in rec["error"]:
            return  # a plist that is neither atlas nor particle
        rec["source"] = member
        rec["source_archive"] = archive_name
        atlases.append(rec)
        return
    if ext == ".json":
        if info.file_size > JSON_CAP_BYTES:
            limitations.append(
                f"{member}: JSON member exceeds the "
                f"{JSON_CAP_BYTES}-byte atlas parse cap; "
                "skipped")
            return
        data = _read_member(zf, info, JSON_CAP_BYTES)
        if data is None:
            return
        doc = _sniff_json(data)
        if doc is None:
            return
        if atlas_mod.classify_json_atlas(doc) is None:
            return  # Lottie / Spine / arbitrary JSON: not ours
        for rec in atlas_mod.parse_texturepacker_json(doc):
            rec["source"] = member
            rec["source_archive"] = archive_name
            atlases.append(rec)
        return
    if ext == ".xml":
        data = _read_member(zf, info, MEMBER_CAP_BYTES)
        if data is None:
            limitations.append(
                f"{member}: XML member exceeds the "
                f"{MEMBER_CAP_BYTES}-byte read cap; skipped")
            return
        if b"TextureAtlas" not in data[:65536]:
            return  # layouts, manifests, other XML: not ours
        rec = atlas_mod.parse_xml_atlas(data)
        rec["source"] = member
        rec["source_archive"] = archive_name
        atlases.append(rec)
        return
    if ext in (".atlas", ".pack"):
        data = _read_member(zf, info, MEMBER_CAP_BYTES)
        if data is None:
            limitations.append(
                f"{member}: atlas text member exceeds the "
                f"{MEMBER_CAP_BYTES}-byte read cap; skipped")
            return
        for rec in atlas_mod.parse_libgdx_atlas(data):
            rec["source"] = member
            rec["source_archive"] = archive_name
            atlases.append(rec)
        return
    if ext == ".tres":
        data = _read_member(zf, info, MEMBER_CAP_BYTES)
        if data is None:
            return
        if b"AtlasTexture" not in data[:65536]:
            return
        rec = atlas_mod.parse_godot_tres(data, resource_path=member)
        rec["source"] = member
        rec["source_archive"] = archive_name
        atlases.append(rec)
        return
    if ext in (".spriteatlas", ".spriteatlasv2"):
        data = _read_member(zf, info, MEMBER_CAP_BYTES)
        if data is None:
            limitations.append(
                f"{member}: spriteatlas member exceeds the "
                f"{MEMBER_CAP_BYTES}-byte read cap; skipped")
            return
        rec = atlas_mod.parse_unity_spriteatlas(data)
        rec["source"] = member
        rec["source_archive"] = archive_name
        atlases.append(rec)
        return


def human(report):
    print(f"NAR atlas inventory: "
          f"{os.path.basename(report['target'])}")
    print("=" * 60)
    totals = report["totals"]
    print(f"Atlases: {totals['atlas_count']}  "
          f"Frames: {totals['frame_count']}  "
          f"Particle plists: {totals['particle_count']}")
    cont = report.get("container")
    if cont:
        print(f"Container: {cont['input_kind']} — base "
              f"{cont['base']}; splits merged: "
              f"{[s['name'] for s in cont['splits_merged']]}")
    for rec in report["atlases"]:
        page = (f"{rec['page_width']}x{rec['page_height']}"
                if rec.get("page_width") else "page size n/a")
        extra = ""
        if rec.get("names_recoverable") is False:
            extra = " (frame names not recoverable)"
        err = f" ERROR: {rec['error']}" if rec.get("error") else ""
        print(f"  [{rec['format']}] {rec.get('source')} — "
              f"texture {rec.get('texture')}, {page}, "
              f"{rec['frame_count']} frames, "
              f"{rec['rotated_count']} rotated{extra}{err}")
    for rec in report["particles"]:
        p = rec.get("particle") or {}
        print(f"  [cocos-particle-plist] {rec.get('source')} — "
              f"max_particles {p.get('max_particles')}, "
              f"lifespan {p.get('lifespan')}")
    for comp in report["compositions"]:
        print(f"  composition {comp['object']}: "
              f"{comp['classification']} (inferred), "
              f"{len(comp['parts'])} parts, "
              f"pattern {comp['naming_pattern']}, "
              f"driver {comp['driver']}")
    print("Limitations:")
    for line in report["limitations"]:
        print(f"  - {line}")


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Texture atlas inventory: Cocos plist, "
                    "TexturePacker/Phaser JSON, Starling and "
                    "TexturePacker XML, libGDX, Godot and "
                    "Unity sprite atlases, plus inferred "
                    "part compositions.")
    p.add_argument("target", help="path to an .apk (or "
                                  "container) file")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    if os.path.isdir(args.target):
        # Directory targets are an input error (exit 2) on
        # every platform. This cannot be left to the open()
        # below: POSIX raises IsADirectoryError for a
        # directory open (caught under the try), but Windows
        # raises PermissionError instead, which would escape
        # as a traceback and the wrong exit code.
        print(f"nar-atlas: is a directory: {args.target}",
              file=sys.stderr)
        return 2
    try:
        report = scan_target(args.target)
    except (FileNotFoundError, IsADirectoryError,
            zipfile.BadZipFile) as e:
        print(f"nar-atlas: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        human(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
