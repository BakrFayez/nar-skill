#!/usr/bin/env python3
"""nar-sdl.py: SDL deep dive (Part 3.2).

Reads a target through narlib.container.resolve_target and
scans the resolved native roots for the SDL libraries:

- the native census: libSDL2*.so / libSDL*.so members with
  sizes. The main SDL library (libSDL2.so / libSDL.so and
  versioned variants) is separated from the satellite
  libraries (SDL2_mixer / SDL2_image / SDL2_ttf / SDL2_net),
  which are reported as a presence list;
- per main library, a dynamic-symbol census via
  narlib.elf: the defined export count, the SDL_* export
  count, whether SDL_main / SDL_Init / SDL_CreateWindow
  are among the defined exports, and a sample of SDL_*
  names;
- revision evidence: a bounded byte scan of the SDL
  library for "SDL revision" / "release-2." / "release-3."
  strings, reported as labelled string evidence (null when
  no such string exists — the version is never guessed).

The verdict is "present" when an SDL library with at least
one defined SDL_* export exists: a bare file name is not
enough.

Usage:
    python3 nar-sdl.py game.apk [--json]

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import re
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import container as _container  # noqa: E402
from narlib.elf import Elf, ElfError, SHT_DYNSYM  # noqa: E402

TOOL = "nar-sdl"
VERSION = "3.0.1"
MEMBER_CAP = 32 * 1024 * 1024        # per-member read cap
NATIVE_CAP = 64 * 1024 * 1024        # native scan cap
_MAIN_LIB_RE = re.compile(
    r"^libsdl2?(-\d+\.\d+)?\.so(\.\d+)*$", re.IGNORECASE)
_SATELLITES = ("libsdl2_mixer", "libsdl_mixer", "libsdl2_image",
               "libsdl_image", "libsdl2_ttf", "libsdl_ttf",
               "libsdl2_net", "libsdl_net")
_REVISION_PATTERNS = (b"SDL revision", b"release-2.",
                      b"release-3.")


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


def _revision_evidence(data, library):
    """Labelled string evidence for SDL revision strings
    in one library's raw bytes (first hit per pattern)."""
    out = []
    for pattern in _REVISION_PATTERNS:
        pos = data.find(pattern)
        if pos < 0:
            continue
        end = data.find(b"\x00", pos)
        if end < 0 or end - pos > 64:
            end = min(len(data), pos + 64)
        out.append({"library": library,
                    "pattern": pattern.decode("ascii"),
                    "match": data[pos:end].decode(
                        "utf-8", "replace"),
                    "evidence": "string scan of the raw "
                                "library bytes"})
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
            census = []
            satellites = []
            revision = []
            for m in scan.members:
                base = os.path.basename(m["name"])
                low = base.lower()
                if not low.endswith(".so"):
                    continue
                if any(low.startswith(sat)
                       for sat in _SATELLITES):
                    satellites.append(m["name"])
                    continue
                if not _MAIN_LIB_RE.match(base):
                    continue
                entry = {"path": m["name"], "size": m["size"]}
                data = scan.read(m, cap=NATIVE_CAP)
                if data is None:
                    entry["error"] = ("library exceeds the "
                                      "native scan cap; not "
                                      "parsed")
                    census.append(entry)
                    continue
                revision.extend(
                    _revision_evidence(data, m["name"]))
                try:
                    elf = Elf(data, base)
                    dynsyms = elf.symbols(SHT_DYNSYM)
                except ElfError as exc:
                    entry["error"] = f"ELF parse failed: {exc}"
                    census.append(entry)
                    continue
                defined = sorted({
                    s["name"] for s in dynsyms
                    if s.get("defined") and s.get("name")})
                sdl_exports = [n for n in defined
                               if n.startswith("SDL_")]
                entry.update({
                    "defined_exports": len(defined),
                    "sdl_exports": len(sdl_exports),
                    "has_sdl_main": "SDL_main" in sdl_exports,
                    "has_sdl_init": "SDL_Init" in sdl_exports,
                    "has_sdl_create_window":
                        "SDL_CreateWindow" in sdl_exports,
                    "sdl_export_sample": sdl_exports[:15]})
                census.append(entry)
            report["libraries"] = census
            report["satellites"] = satellites
            report["revision_evidence"] = revision
            report["revision"] = revision[0]["match"] \
                if revision else None
        finally:
            scan.close()
    finally:
        resolved.cleanup()
    report["verdict"] = "present" if any(
        entry.get("sdl_exports", 0) >= 1
        for entry in report["libraries"]) else "absent"
    return report


def human(report):
    lines = [f"NAR SDL deep dive: {report['target']}",
             f"Verdict: {report['verdict']}"]
    for entry in report["libraries"]:
        if "error" in entry:
            lines.append(f"  {entry['path']}: {entry['error']}")
            continue
        lines.append(
            f"  {entry['path']} ({entry['size']:,} bytes): "
            f"{entry['defined_exports']} defined exports, "
            f"{entry['sdl_exports']} SDL_*, SDL_main="
            f"{entry['has_sdl_main']}, SDL_Init="
            f"{entry['has_sdl_init']}, SDL_CreateWindow="
            f"{entry['has_sdl_create_window']}")
    lines.append(f"Satellite libraries: "
                 f"{report['satellites']}")
    lines.append(f"Revision (string evidence): "
                 f"{report['revision']}")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR SDL deep dive.")
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
