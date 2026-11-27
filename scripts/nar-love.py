#!/usr/bin/env python3
"""nar-love.py: deep-dive inspection of a LÖVE (Love2D) game:
a .love archive inside an APK (or split set / container), or
a bare .love file given as the target.

A .love is a ZIP. This tool lists it, checks main.lua, reads
conf.lua facts textually (bounded regex over the Lua source:
t.identity, t.title, t.version, t.window.width/height and
the t.modules.* = false disabled list — values as written,
labelled textual evidence, never executed), and censuses the
.lua sources. A .love member that is not a valid ZIP is
still identified, with an error note. Stdlib only; reads
are capped and malformed members degrade to notes.

Usage:
    python3 nar-love.py app.apk [--json]
    python3 nar-love.py game.love [--json]

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import io
import json
import os
import re
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import container as container_mod  # noqa: E402
from narlib.safearchive import read_member_capped  # noqa: E402

VERSION = "3.0.2"
MEMBER_CAP = 32 * 1024 * 1024
CONF_CAP = 256 * 1024

_STR_FACT_RE = re.compile(
    r"""t\.(identity|title|version)\s*=\s*["']([^"']*)["']""")
_WIN_FACT_RE = re.compile(
    r"t\.window\.(width|height)\s*=\s*(\d+)")
_MODULE_OFF_RE = re.compile(
    r"t\.modules\.(\w+)\s*=\s*false")


def build_index(resolved):
    index = {}
    for root in resolved.assets_roots:
        try:
            zf = zipfile.ZipFile(root)
        except (zipfile.BadZipFile, OSError):
            continue
        with zf:
            for info in zf.infolist():
                if info.filename.endswith("/"):
                    continue
                if info.filename not in index:
                    index[info.filename] = (root, info.file_size)
    return index


def read_member(index, name, cap=MEMBER_CAP):
    root, _size = index[name]
    with zipfile.ZipFile(root) as zf:
        return read_member_capped(zf, name, cap)


def parse_conf(text):
    """Textual facts from conf.lua source (regex over the
    file as written; nothing is executed)."""
    facts = {"identity": None, "title": None, "version": None,
             "window_width": None, "window_height": None,
             "modules_disabled": [],
             "evidence": "textual regex over conf.lua source; "
                         "values as written, not evaluated"}
    for key, val in _STR_FACT_RE.findall(text):
        facts[key] = val
    for key, val in _WIN_FACT_RE.findall(text):
        facts[f"window_{key}"] = int(val)
    facts["modules_disabled"] = sorted(
        set(_MODULE_OFF_RE.findall(text)))
    return facts


def inspect_love_bytes(data, source):
    """Inspect one .love archive's bytes."""
    out = {"source": source, "valid_zip": False,
           "listing": [], "file_count": 0,
           "main_lua_present": False, "conf": None,
           "lua_census": {"count": 0, "total_bytes": 0,
                          "largest": None},
           "love_version_hint": None}
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        out["error"] = f".love member is not a valid ZIP ({e})"
        return out
    with zf:
        out["valid_zip"] = True
        infos = [i for i in zf.infolist()
                 if not i.filename.endswith("/")]
        out["listing"] = [{"name": i.filename,
                           "size_bytes": i.file_size}
                          for i in infos]
        out["file_count"] = len(infos)
        names = {i.filename for i in infos}
        out["main_lua_present"] = "main.lua" in names
        lua = [i for i in infos
               if i.filename.lower().endswith(".lua")]
        total = sum(i.file_size for i in lua)
        largest = None
        if lua:
            big = max(lua, key=lambda i: i.file_size)
            largest = {"name": big.filename,
                       "size_bytes": big.file_size}
        out["lua_census"] = {"count": len(lua),
                             "total_bytes": total,
                             "largest": largest}
        if "conf.lua" in names:
            try:
                raw = read_member_capped(zf, "conf.lua", CONF_CAP)
                facts = parse_conf(
                    raw.decode("utf-8", "replace"))
                out["conf"] = facts
                out["love_version_hint"] = facts.get("version")
            except (KeyError, OSError, ValueError,
                    zipfile.BadZipFile) as e:
                out["conf_error"] = f"conf.lua unreadable ({e})"
    return out


def inspect(target):
    report = {"tool": "nar-love", "version": VERSION,
              "target": os.path.abspath(target),
              "verdict": "absent", "love_archives": [],
              "notes": []}
    notes = report["notes"]
    resolved = container_mod.resolve_target(target)
    try:
        report["container"] = resolved.container_block()
        # Bare .love target: the file itself is the archive.
        if target.lower().endswith(".love") and \
                not resolved.assets_roots:
            try:
                with open(target, "rb") as fh:
                    data = fh.read(MEMBER_CAP + 1)
                if len(data) > MEMBER_CAP:
                    notes.append("bare .love exceeds the member "
                                 "read cap; not parsed")
                    data = None
            except OSError as e:
                notes.append(f"bare .love unreadable: {e}")
                data = None
            if data is not None:
                report["love_archives"].append(inspect_love_bytes(
                    data, os.path.basename(target)))
                report["verdict"] = "present"
            return report
        index = build_index(resolved)
        love_names = sorted(n for n in index
                            if n.lower().endswith(".love"))
        if not love_names:
            notes.append("no .love archive found in the "
                         "resolved roots")
            return report
        report["verdict"] = "present"
        for name in love_names:
            try:
                data = read_member(index, name)
            except (KeyError, OSError, ValueError,
                    zipfile.BadZipFile) as e:
                report["love_archives"].append({
                    "source": name, "valid_zip": False,
                    "error": f"member unreadable ({e})"})
                continue
            report["love_archives"].append(
                inspect_love_bytes(data, name))
        return report
    finally:
        resolved.cleanup()


def human(report):
    lines = [f"NAR LÖVE deep dive: {report['target']}"]
    if report["verdict"] != "present":
        lines.append("ABSENT: no .love archive found")
        for n in report["notes"]:
            lines.append(f"  note: {n}")
        return "\n".join(lines)
    for arch in report["love_archives"]:
        if not arch.get("valid_zip"):
            lines.append(f"{arch['source']}: identified as "
                         f".love but {arch.get('error')}")
            continue
        conf = arch.get("conf") or {}
        lines.append(
            f"{arch['source']}: {arch['file_count']} files, "
            f"main.lua={'yes' if arch['main_lua_present'] else 'no'}"
            f", {arch['lua_census']['count']} .lua files "
            f"({arch['lua_census']['total_bytes']:,} bytes)")
        lines.append(
            f"  conf.lua (textual): title={conf.get('title')} "
            f"identity={conf.get('identity')} "
            f"love version hint={arch.get('love_version_hint')} "
            f"window={conf.get('window_width')}x"
            f"{conf.get('window_height')} "
            f"modules disabled={conf.get('modules_disabled')}")
    for n in report["notes"]:
        lines.append(f"  note: {n}")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR LÖVE (Love2D) deep dive.")
    p.add_argument("target", help="path to an .apk / container "
                                  "or a bare .love file")
    p.add_argument("--json", action="store_true",
                   help="machine-readable JSON output")
    args = p.parse_args(argv)
    if not os.path.isfile(args.target):
        print(f"nar-love: not a file: {args.target}",
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
