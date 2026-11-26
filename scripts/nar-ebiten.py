#!/usr/bin/env python3
"""nar-ebiten.py: Ebitengine (Go) deep dive (Part 3.2).

Reads a target through narlib.container.resolve_target and
scans the resolved native roots for the Go runtime build
information block every Go binary carries:

- for each lib/*.so member up to 64 MiB, the block is
  located by its magic ("\\xff Go buildinf:"). After the
  14-byte magic come a pointer-size byte and a flags byte.
  When flags bit 1 (value 2) is set, the version and
  module-info strings follow inline as uvarint
  length-prefixed strings and are parsed: the Go version,
  the module path and version from the modinfo "path" /
  "mod" lines, and a sample of the "build" settings lines.
  In the pointer form (bit clear) the strings live behind
  runtime pointers and are not statically readable; that
  is reported as-is, with no version claimed;
- an embedded-assets census: members under assets/ counted
  in total and by extension (top 5).

The verdict is "present" when a Go buildinf block is found
in any native library.

Usage:
    python3 nar-ebiten.py game.apk [--json]

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import collections
import json
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import container as _container  # noqa: E402

TOOL = "nar-ebiten"
VERSION = "3.0.1"
MEMBER_CAP = 32 * 1024 * 1024        # per-member read cap
NATIVE_CAP = 64 * 1024 * 1024        # native scan cap
BUILDINF_MAGIC = b"\xff Go buildinf:"   # 14 bytes


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


def _read_uvarint(data, pos):
    """Unsigned LEB128. Returns (value, new_pos); raises
    ValueError on overrun / overlong encodings."""
    result = 0
    shift = 0
    while True:
        if pos >= len(data) or shift > 63:
            raise ValueError("uvarint overruns the data")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7


def _read_prefixed_string(data, pos):
    length, pos = _read_uvarint(data, pos)
    if length > len(data) - pos:
        raise ValueError("length-prefixed string overruns "
                         "the data")
    return data[pos:pos + length].decode(
        "utf-8", "replace"), pos + length


def parse_modinfo(modinfo):
    """Facts from a Go module-info string: its lines are
    tab-separated records — "path\\t<module path>",
    "mod\\t<module>\\t<version>\\t<hash>", "dep\\t..." and
    "build\\t<key>=<value>"."""
    facts = {"module_path": None, "module_version": None,
             "settings": {}}
    for line in modinfo.split("\n"):
        fields = line.split("\t")
        if len(fields) < 2:
            continue
        kind = fields[0]
        if kind == "path" and facts["module_path"] is None:
            facts["module_path"] = fields[1]
        elif kind == "mod":
            if facts["module_path"] is None:
                facts["module_path"] = fields[1]
            if len(fields) >= 3:
                facts["module_version"] = fields[2]
        elif kind == "build" and \
                len(facts["settings"]) < 8:
            key, _, value = fields[1].partition("=")
            facts["settings"][key] = value
    return facts


def parse_buildinf(data, library):
    """One library's Go buildinf record, or None when the
    magic is absent. Malformed inline strings degrade to a
    record with an error note."""
    idx = data.find(BUILDINF_MAGIC)
    if idx < 0:
        return None
    record = {"library": library, "offset": idx}
    pos = idx + len(BUILDINF_MAGIC)
    if pos + 2 > len(data):
        record["error"] = "buildinf header is truncated"
        return record
    record["pointer_size"] = data[pos]
    flags = data[pos + 1]
    record["flags"] = flags
    pos += 2
    if not flags & 2:
        record["buildinf"] = "pointer-form"
        record["go_version"] = None
        record["note"] = ("version stored as runtime "
                          "pointers, not statically readable")
        return record
    record["buildinf"] = "string-form"
    try:
        version, pos = _read_prefixed_string(data, pos)
        modinfo, pos = _read_prefixed_string(data, pos)
    except ValueError as exc:
        record["error"] = f"buildinf strings unreadable: {exc}"
        record["go_version"] = None
        return record
    record["go_version"] = version
    record.update(parse_modinfo(modinfo))
    return record


def inspect(target):
    report = {"tool": TOOL, "version": VERSION,
              "target": os.path.abspath(target),
              "notes": []}
    resolved = _container.resolve_target(target)
    try:
        report["container"] = resolved.container_block()
        scan = Scan(resolved)
        try:
            builds = []
            for m in scan.members:
                low = m["name"].lower()
                if not (low.startswith("lib/")
                        and low.endswith(".so")):
                    continue
                data = scan.read(m, cap=NATIVE_CAP)
                if data is None:
                    continue
                record = parse_buildinf(data, m["name"])
                if record is not None:
                    builds.append(record)
            report["go_builds"] = builds

            assets = [m["name"] for m in scan.members
                      if m["name"].startswith("assets/")]
            by_ext = collections.Counter()
            for name in assets:
                ext = os.path.splitext(name)[1].lower() \
                    or "(none)"
                by_ext[ext] += 1
            report["embedded_assets"] = {
                "count": len(assets),
                "by_ext_top5": dict(
                    by_ext.most_common(5))}
        finally:
            scan.close()
    finally:
        resolved.cleanup()
    report["verdict"] = "present" if report["go_builds"] \
        else "absent"
    return report


def human(report):
    lines = [f"NAR Ebitengine deep dive: {report['target']}",
             f"Verdict: {report['verdict']}"]
    for b in report["go_builds"]:
        lines.append(
            f"  {b['library']}: Go {b.get('go_version')}, "
            f"module {b.get('module_path')} "
            f"{b.get('module_version') or ''} "
            f"({b.get('buildinf')})")
        if b.get("settings"):
            lines.append(f"    build settings: {b['settings']}")
        if b.get("note"):
            lines.append(f"    note: {b['note']}")
        if b.get("error"):
            lines.append(f"    error: {b['error']}")
    ea = report["embedded_assets"]
    lines.append(f"Embedded assets: {ea['count']} "
                 f"(by extension: {ea['by_ext_top5']})")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR Ebitengine (Go) deep dive.")
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
