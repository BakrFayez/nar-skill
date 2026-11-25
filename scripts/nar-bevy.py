#!/usr/bin/env python3
"""nar-bevy.py: Bevy / Rust deep dive (Part 3.2).

Reads a target through narlib.container.resolve_target and
scans the resolved asset/native roots for:

- the assets census: members under assets/ counted in
  total and by extension, with dedicated counts for RON
  data files (*.ron) and Bevy scene files (*.scn.ron);
- RON facts: for each .ron member up to 256 KiB (at most
  20 files), a top-level key census from a light textual
  scan — identifiers sitting at bracket depth 1 that are
  followed by ':'. This is a labelled textual
  approximation of the RON structure, not a RON parser;
- Rust evidence from the largest native library: a bounded
  scan for the "rustc version " string (the version is
  extracted when the string is present) and occurrence
  counts for the Bevy crate name strings (bevy_ecs,
  bevy_render, bevy_asset, bevy_winit, winit), reported as
  labelled string evidence.

The verdict is "present" when RON assets exist or at least
two distinct Bevy crate strings are found.

Usage:
    python3 nar-bevy.py game.apk [--json]

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import collections
import json
import os
import re
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import container as _container  # noqa: E402

TOOL = "nar-bevy"
VERSION = "3.0.1"
MEMBER_CAP = 32 * 1024 * 1024        # per-member read cap
NATIVE_CAP = 64 * 1024 * 1024        # native scan cap
RON_CAP = 256 * 1024                 # per-.ron textual scan cap
RON_FILE_CAP = 20
RON_KEY_CAP = 20
_CRATE_PATTERNS = (b"bevy_ecs", b"bevy_render", b"bevy_asset",
                   b"bevy_winit", b"winit")
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_RUSTC_RE = re.compile(rb"rustc version ([0-9][0-9A-Za-z.+-]*)")


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


def ron_top_level_keys(text):
    """Identifiers at bracket depth 1 followed by ':' —
    a light textual scan (strings are skipped so braces
    inside them do not move the depth). Approximation,
    capped at RON_KEY_CAP distinct keys."""
    keys = []
    depth = 0
    i = 0
    n = len(text)
    while i < n and len(keys) < RON_KEY_CAP:
        ch = text[i]
        if ch == '"':
            i += 1
            while i < n and text[i] != '"':
                if text[i] == "\\":
                    i += 1
                i += 1
            i += 1
            continue
        if ch in "([{":
            depth += 1
            i += 1
            continue
        if ch in ")]}":
            depth -= 1
            i += 1
            continue
        if depth == 1 and (ch.isalpha() or ch == "_"):
            match = _IDENT_RE.match(text, i)
            if match:
                j = match.end()
                k = j
                while k < n and text[k] in " \t":
                    k += 1
                if k < n and text[k] == ":":
                    key = match.group(0)
                    if key not in keys:
                        keys.append(key)
                    i = k + 1
                    continue
                i = j
                continue
        i += 1
    return keys


def inspect(target):
    report = {"tool": TOOL, "version": VERSION,
              "target": os.path.abspath(target),
              "notes": []}
    resolved = _container.resolve_target(target)
    try:
        report["container"] = resolved.container_block()
        scan = Scan(resolved)
        try:
            asset_members = [m for m in scan.members
                             if m["name"].startswith("assets/")]
            by_ext = collections.Counter()
            for m in asset_members:
                ext = os.path.splitext(m["name"])[1].lower() \
                    or "(none)"
                by_ext[ext] += 1
            ron_members = [m for m in asset_members
                           if m["name"].lower()
                           .endswith(".ron")]
            report["assets"] = {
                "count": len(asset_members),
                "by_ext": dict(sorted(by_ext.items())),
                "ron_count": len(ron_members),
                "scn_ron_count": sum(
                    1 for m in ron_members
                    if m["name"].lower()
                    .endswith(".scn.ron"))}

            ron_facts = []
            for m in ron_members[:RON_FILE_CAP]:
                data = scan.read(m, cap=RON_CAP)
                if data is None:
                    continue
                ron_facts.append({
                    "file": m["name"],
                    "top_level_keys": ron_top_level_keys(
                        data.decode("utf-8", "replace")),
                    "method": "textual scan: identifiers at "
                              "bracket depth 1 followed by "
                              "':' (approximation, not a RON "
                              "parse)"})
            report["ron"] = {
                "files_scanned": len(ron_facts),
                "files": ron_facts}

            libs = [m for m in scan.members
                    if m["name"].lower().startswith("lib/")
                    and m["name"].lower().endswith(".so")]
            rust = {"library": None, "rustc_version": None,
                    "crate_hits": {},
                    "evidence": "string scan of the raw "
                                "library bytes"}
            if libs:
                biggest = max(libs, key=lambda m: m["size"])
                rust["library"] = biggest["name"]
                data = scan.read(biggest, cap=NATIVE_CAP)
                if data is not None:
                    match = _RUSTC_RE.search(data)
                    if match:
                        rust["rustc_version"] = match.group(1) \
                            .decode("ascii", "replace")
                    for pattern in _CRATE_PATTERNS:
                        hits = data.count(pattern)
                        if hits:
                            rust["crate_hits"][
                                pattern.decode("ascii")] = hits
            report["rust_evidence"] = rust
        finally:
            scan.close()
    finally:
        resolved.cleanup()
    distinct_crates = len(report["rust_evidence"]["crate_hits"])
    report["verdict"] = "present" if (
        report["assets"]["ron_count"] > 0
        or distinct_crates >= 2) else "absent"
    return report


def human(report):
    lines = [f"NAR Bevy deep dive: {report['target']}",
             f"Verdict: {report['verdict']}"]
    a = report["assets"]
    lines.append(f"Assets: {a['count']} members, "
                 f"{a['ron_count']} .ron, "
                 f"{a['scn_ron_count']} .scn.ron")
    lines.append(f"By extension: {a['by_ext']}")
    for fact in report["ron"]["files"]:
        lines.append(f"  {fact['file']}: top-level keys "
                     f"{fact['top_level_keys']}")
    rust = report["rust_evidence"]
    lines.append(f"Rust evidence in {rust['library']}: "
                 f"rustc {rust['rustc_version']}, crate "
                 f"string hits {rust['crate_hits']}")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR Bevy / Rust deep dive.")
    p.add_argument("target", help="APK / container to inspect")
    p.add_argument("--json", action="store_true",
                   help="machine-readable JSON output")
    args = p.parse_args(argv)
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
