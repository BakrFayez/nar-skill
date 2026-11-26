#!/usr/bin/env python3
"""nar-libgdx.py: libGDX deep dive (Part 3.2).

Reads a target through narlib.container.resolve_target and
scans the resolved asset/native roots for the libGDX payload
families the shallow engine pass only names:

- texture atlases: .atlas/.pack members parsed with
  narlib.atlas.parse_libgdx_atlas (one record per page;
  the region total is the sum of parsed frames);
- Tiled tile maps: .tmx members parsed as XML — per map the
  orientation, grid and tile sizes, the tilesets (name,
  firstgid, tilecount when the attribute is present, else
  null), the layer kinds in document order (tilelayer /
  objectgroup / imagelayer / group) and a sample of the
  tile-data encodings used;
- runtime markers for the libGDX backends: GWT
  (*.nocache.js and *.gwt.xml members), RoboVM
  (librobovm*.so libraries and robovm.xml members) and a
  census of jars shipped loose in assets/;
- version evidence: a bounded byte scan of libgdx*.so
  libraries for a "libGDX" string with an adjacent version
  number. When no such string exists the version is null —
  it is never guessed from file names.

Usage:
    python3 nar-libgdx.py game.apk [--json]

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import re
import sys
import zipfile
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import atlas  # noqa: E402
from narlib import container as _container  # noqa: E402

TOOL = "nar-libgdx"
VERSION = "3.0.1"
MEMBER_CAP = 32 * 1024 * 1024        # per-member read cap
NATIVE_CAP = 64 * 1024 * 1024        # native string-scan cap
_VERSION_RE = re.compile(
    rb"libGDX[^0-9]{0,16}?(\d+\.\d+(?:\.\d+)?)")
# TMX XML spells a tile layer <layer>; the "tilelayer" kind
# name is what the report uses for it.
_LAYER_KINDS = {"layer": "tilelayer", "tilelayer": "tilelayer",
                "objectgroup": "objectgroup",
                "imagelayer": "imagelayer", "group": "group"}


class Scan:
    """Bounded member access across a resolved target's
    asset and native roots (deduplicated, base first)."""

    def __init__(self, resolved):
        self.members = []
        self._zfs = {}
        seen = set()
        for root in list(resolved.assets_roots) + \
                list(resolved.native_roots):
            if root in seen or not os.path.isfile(root):
                continue
            seen.add(root)
            try:
                zf = zipfile.ZipFile(root)
            except (zipfile.BadZipFile, OSError):
                continue
            self._zfs[root] = zf
            for info in zf.infolist():
                if info.filename.endswith("/"):
                    continue
                self.members.append({
                    "root": root,
                    "archive": os.path.basename(root),
                    "name": info.filename,
                    "size": info.file_size})

    def read(self, member, cap=MEMBER_CAP):
        if member["size"] > cap:
            return None
        try:
            return self._zfs[member["root"]].read(member["name"])
        except (KeyError, OSError, RuntimeError,
                zipfile.BadZipFile):
            return None

    def close(self):
        for zf in self._zfs.values():
            try:
                zf.close()
            except Exception:
                pass


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_tmx(data, name):
    """One .tmx member -> a map record (facts only; tile
    data itself is never decoded). Raises ValueError on
    malformed XML."""
    root = ET.fromstring(data)
    if root.tag != "map":
        raise ValueError(f"root element is {root.tag!r}, "
                         "not 'map'")
    tilesets = []
    for ts in root.iter("tileset"):
        tilesets.append({
            "name": ts.get("name"),
            "firstgid": _int_or_none(ts.get("firstgid")),
            "tilecount": _int_or_none(ts.get("tilecount"))})
    layers = []
    for child in root:
        kind = _LAYER_KINDS.get(child.tag)
        if kind:
            layers.append({"kind": kind,
                           "name": child.get("name")})
    encodings = []
    for data_el in root.iter("data"):
        enc = data_el.get("encoding")
        comp = data_el.get("compression")
        label = enc or "xml"
        if comp:
            label = f"{label}+{comp}"
        if label not in encodings:
            encodings.append(label)
    return {"file": name,
            "orientation": root.get("orientation"),
            "width": _int_or_none(root.get("width")),
            "height": _int_or_none(root.get("height")),
            "tilewidth": _int_or_none(root.get("tilewidth")),
            "tileheight": _int_or_none(root.get("tileheight")),
            "tilesets": tilesets,
            "layers": layers,
            "data_encodings": encodings}


def inspect(target):
    report = {"tool": TOOL, "version": VERSION,
              "target": os.path.abspath(target),
              "notes": []}
    resolved = _container.resolve_target(target)
    try:
        report["container"] = resolved.container_block()
        scan = Scan(resolved)
        try:
            atlas_files = 0
            atlas_pages = 0
            region_total = 0
            for m in scan.members:
                if not m["name"].lower().endswith(
                        (".atlas", ".pack")):
                    continue
                data = scan.read(m)
                if data is None:
                    continue
                records = atlas.parse_libgdx_atlas(data)
                good = [r for r in records
                        if not r.get("error")]
                if not good:
                    continue
                atlas_files += 1
                atlas_pages += len(good)
                region_total += sum(
                    r.get("frame_count", 0) for r in good)
            report["atlases"] = {
                "count": atlas_files, "pages": atlas_pages,
                "regions_total": region_total}

            maps = []
            map_errors = 0
            for m in scan.members:
                if not m["name"].lower().endswith(".tmx"):
                    continue
                data = scan.read(m)
                if data is None:
                    continue
                try:
                    maps.append(parse_tmx(data, m["name"]))
                except (ValueError, ET.ParseError):
                    map_errors += 1
            report["tile_maps"] = {"count": len(maps),
                                   "maps": maps[:50],
                                   "unparseable": map_errors}

            names = [m["name"] for m in scan.members]
            nocache = [n for n in names
                       if n.lower().endswith(".nocache.js")]
            gwt_xml = [n for n in names
                       if n.lower().endswith(".gwt.xml")]
            report["gwt"] = {
                "nocache_js": nocache[:20],
                "nocache_js_count": len(nocache),
                "gwt_xml": gwt_xml[:20],
                "gwt_xml_count": len(gwt_xml)}
            robovm_libs = [n for n in names
                           if os.path.basename(n).lower()
                           .startswith("librobovm")
                           and n.lower().endswith(".so")]
            robovm_xml = [n for n in names
                          if os.path.basename(n).lower()
                          == "robovm.xml"]
            report["robovm"] = {"libraries": robovm_libs,
                                "robovm_xml": robovm_xml}
            jars = [n for n in names
                    if n.startswith("assets/")
                    and n.lower().endswith(".jar")]
            report["asset_jars"] = {
                "count": len(jars),
                "names": [os.path.basename(n) for n in jars]}

            version = None
            version_evidence = []
            gdx_libs = []
            for m in scan.members:
                base = os.path.basename(m["name"]).lower()
                if not (base.startswith("libgdx")
                        and base.endswith(".so")):
                    continue
                gdx_libs.append(m["name"])
                data = scan.read(m, cap=NATIVE_CAP)
                if data is None:
                    continue
                match = _VERSION_RE.search(data)
                if match:
                    text = match.group(0).decode(
                        "utf-8", "replace")
                    version_evidence.append({
                        "library": m["name"], "match": text,
                        "evidence": "string scan of the raw "
                                    "library bytes"})
                    if version is None:
                        version = match.group(1).decode(
                            "ascii", "replace")
            report["native_libraries"] = gdx_libs
            report["libgdx_version"] = version
            report["version_evidence"] = version_evidence
        finally:
            scan.close()
    finally:
        resolved.cleanup()
    present = (
        report["atlases"]["count"] > 0
        or report["tile_maps"]["count"] > 0
        or report["gwt"]["nocache_js_count"] > 0
        or bool(report["robovm"]["libraries"])
        or bool(report["robovm"]["robovm_xml"])
        or report["asset_jars"]["count"] > 0
        or bool(report["native_libraries"]))
    report["verdict"] = "present" if present else "absent"
    return report


def human(report):
    lines = [f"NAR libGDX deep dive: {report['target']}",
             f"Verdict: {report['verdict']}"]
    a = report["atlases"]
    lines.append(f"Atlases: {a['count']} files, {a['pages']} "
                 f"pages, {a['regions_total']} regions")
    tm = report["tile_maps"]
    lines.append(f"Tile maps (.tmx): {tm['count']}")
    for mp in tm["maps"]:
        lines.append(
            f"  {mp['file']}: {mp['orientation']} "
            f"{mp['width']}x{mp['height']} tiles of "
            f"{mp['tilewidth']}x{mp['tileheight']}, "
            f"{len(mp['tilesets'])} tilesets, "
            f"{len(mp['layers'])} layers, encodings "
            f"{mp['data_encodings']}")
    lines.append(f"GWT: {report['gwt']['nocache_js_count']} "
                 f"*.nocache.js, "
                 f"{report['gwt']['gwt_xml_count']} *.gwt.xml")
    lines.append(f"RoboVM libraries: "
                 f"{report['robovm']['libraries']}")
    lines.append(f"Jars in assets/: "
                 f"{report['asset_jars']['names']}")
    lines.append(f"libGDX native libraries: "
                 f"{report['native_libraries']}")
    lines.append(f"Version (string evidence): "
                 f"{report['libgdx_version']}")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR libGDX deep dive.")
    p.add_argument("target", help="APK / container to inspect")
    p.add_argument("--json", action="store_true",
                   help="machine-readable JSON output")
    args = p.parse_args(argv)
    if os.path.isdir(args.target):
        # Directory targets are an input error (exit 2) on
        # every platform. This cannot be left to the open()
        # below: POSIX raises IsADirectoryError for a
        # directory open (caught under the try), but Windows
        # raises PermissionError instead, which would escape
        # as a traceback and the wrong exit code.
        print(f"{TOOL}: is a directory: {args.target}",
              file=sys.stderr)
        return 2
    if not os.path.exists(args.target):
        print(f"{TOOL}: no such target: {args.target}",
              file=sys.stderr)
        return 2
    report = inspect(args.target)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(human(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
