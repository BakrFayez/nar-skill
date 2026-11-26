#!/usr/bin/env python3
"""nar-cocos.py: Cocos2d-x / Cocos Creator deep dive (Part 3.2).

Reads a target through narlib.container.resolve_target and
scans the resolved asset/native roots for the Cocos payload
families the shallow engine pass only names:

- sprite atlases and particle definitions: every .plist
  member is run through narlib.atlas.parse_cocos_plist, which
  separates frame atlases (record format "cocos-plist") from
  particle plists ("cocos-particle-plist");
- CocosBuilder / Cocos Studio files: .ccb/.csb members go
  through narlib.anim.classify_and_parse (a plist .ccb
  decodes its node graph; a .csb is identification-grade);
- compiled JavaScript: a .jsc census (count + total bytes).
  .jsc is SpiderMonkey bytecode: it is identified and
  measured here, never decoded;
- asset layout: member counts under assets/res/,
  assets/src/ and assets/ as a whole;
- engine version evidence: a bounded byte scan of every
  lib/*.so up to 64 MiB for the "cocos2d-x 3." /
  "cocos2d-x 4." / "Cocos Creator" strings, reported as
  labelled string evidence with the library that carried
  each match (a string hit is evidence, not a parsed
  version field).

The verdict is "present" when at least one plist atlas
parsed, or any .ccb/.csb or .jsc evidence exists.

Usage:
    python3 nar-cocos.py game.apk [--json]

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import anim, atlas  # noqa: E402
from narlib import container as _container  # noqa: E402

TOOL = "nar-cocos"
VERSION = "3.0.1"
MEMBER_CAP = 32 * 1024 * 1024        # per-member read cap
NATIVE_CAP = 64 * 1024 * 1024        # native string-scan cap
_VERSION_PATTERNS = (b"cocos2d-x 3.", b"cocos2d-x 4.",
                     b"Cocos Creator")


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


def _string_evidence(data, library):
    """Labelled string evidence for the Cocos version
    patterns in one native library's raw bytes."""
    out = []
    for pattern in _VERSION_PATTERNS:
        pos = data.find(pattern)
        while pos >= 0:
            end = data.find(b"\x00", pos)
            if end < 0 or end - pos > 64:
                end = min(len(data), pos + 64)
            text = data[pos:end].decode("utf-8", "replace")
            out.append({"library": library, "pattern":
                        pattern.decode("ascii"),
                        "match": text,
                        "evidence": "string scan of the raw "
                                    "library bytes"})
            pos = data.find(pattern, pos + 1)
    return out


def inspect(target):
    report = {"tool": TOOL, "version": VERSION,
              "target": os.path.abspath(target),
              "notes": []}
    resolved = _container.resolve_target(target)
    try:
        report["container"] = resolved.container_block()
        scan = Scan(resolved)
        try:
            atlas_count = 0
            atlas_frames = 0
            atlas_files = []
            particle_count = 0
            for m in scan.members:
                if not m["name"].lower().endswith(".plist"):
                    continue
                data = scan.read(m)
                if data is None:
                    continue
                record = atlas.parse_cocos_plist(data)
                if record.get("error"):
                    continue
                if record.get("format") == "cocos-plist":
                    atlas_count += 1
                    atlas_frames += record.get("frame_count", 0)
                    atlas_files.append(m["name"])
                elif record.get("format") == \
                        "cocos-particle-plist":
                    particle_count += 1
            report["atlases"] = {
                "count": atlas_count,
                "total_frames": atlas_frames,
                "files": atlas_files[:50]}
            report["particles"] = {"count": particle_count}

            ccb_records = []
            ccb_bytes = 0
            for m in scan.members:
                if not m["name"].lower().endswith(
                        (".ccb", ".csb")):
                    continue
                data = scan.read(m)
                if data is None:
                    continue
                ccb_bytes += len(data)
                record = anim.classify_and_parse(
                    m["name"], data, m["archive"])
                if record is not None:
                    ccb_records.append(record)
            report["cocos_files"] = {
                "count": len(ccb_records),
                "total_bytes": ccb_bytes,
                "records": ccb_records[:50]}

            jsc = [m for m in scan.members
                   if m["name"].lower().endswith(".jsc")]
            report["jsc"] = {
                "count": len(jsc),
                "total_bytes": sum(m["size"] for m in jsc),
                "note": ".jsc members are SpiderMonkey "
                        "bytecode; identified and measured, "
                        "not decoded"}

            names = [m["name"] for m in scan.members]
            report["asset_layout"] = {
                "assets_total": sum(
                    1 for n in names if n.startswith("assets/")),
                "assets_res": sum(
                    1 for n in names
                    if n.startswith("assets/res/")),
                "assets_src": sum(
                    1 for n in names
                    if n.startswith("assets/src/"))}

            evidence = []
            for m in scan.members:
                low = m["name"].lower()
                if not (low.startswith("lib/")
                        and low.endswith(".so")):
                    continue
                data = scan.read(m, cap=NATIVE_CAP)
                if data is None:
                    continue
                evidence.extend(
                    _string_evidence(data, m["name"]))
            report["version_evidence"] = evidence
        finally:
            scan.close()
    finally:
        resolved.cleanup()
    report["verdict"] = "present" if (
        report["atlases"]["count"] > 0
        or report["cocos_files"]["count"] > 0
        or report["jsc"]["count"] > 0) else "absent"
    return report


def human(report):
    lines = [f"NAR Cocos deep dive: {report['target']}",
             f"Verdict: {report['verdict']}"]
    a = report["atlases"]
    lines.append(f"Plist atlases: {a['count']} "
                 f"({a['total_frames']} frames total)")
    lines.append(f"Particle plists: "
                 f"{report['particles']['count']}")
    cf = report["cocos_files"]
    lines.append(f"CocosBuilder/Studio files: {cf['count']} "
                 f"({cf['total_bytes']:,} bytes)")
    j = report["jsc"]
    lines.append(f"Compiled JS (.jsc, SpiderMonkey bytecode, "
                 f"identification only): {j['count']} "
                 f"({j['total_bytes']:,} bytes)")
    lay = report["asset_layout"]
    lines.append(f"Asset layout: assets/ {lay['assets_total']}, "
                 f"assets/res/ {lay['assets_res']}, "
                 f"assets/src/ {lay['assets_src']}")
    for ev in report["version_evidence"]:
        lines.append(f"Version string evidence: {ev['match']!r} "
                     f"in {ev['library']}")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR Cocos2d-x / Cocos Creator deep dive.")
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
