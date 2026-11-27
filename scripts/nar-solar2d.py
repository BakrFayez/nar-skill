#!/usr/bin/env python3
"""nar-solar2d.py: inspect a Solar2D (Corona) resource.car.

Finds resource.car in a target's asset roots (resolved
through narlib.container, splits merged) and also accepts a
bare resource.car file as the target.

Many Solar2D builds ship resource.car as a plain ZIP: when
the blob is a valid ZIP this reader lists it (count, by-
extension census, total bytes), extracts textual facts from
config.lua / build.settings when they ship as stored text
(orientation.default, application.content.scale / fps —
bounded regexes over the text, labelled textual), and
censuses compiled Lua (.luac members plus extensionless
members carrying the Lua bytecode header magic). When the
blob is not a ZIP, only header facts (size + first 16 bytes
hex) are reported and the verdict is present only when the
file is actually named resource.car — the non-ZIP car
variant is identification level.

Corona markers in the surrounding APK are censused too:
assets/*.luac members and libcorona.so presence (path
evidence list).

Usage:
    python3 nar-solar2d.py app.apk [--json]
    python3 nar-solar2d.py resource.car [--json]

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

VERSION = "3.0.3"
MEMBER_CAP_BYTES = 32 * 1024 * 1024
TEXT_CAP_BYTES = 1024 * 1024
LUA_MAGIC = b"\x1bLua"

_ORIENTATION_RE = re.compile(
    r"orientation\s*=\s*\{[^}]*?default\s*=\s*[\"']([^\"']+)[\"']",
    re.S)
_SCALE_RE = re.compile(r"scale\s*=\s*[\"']([^\"']+)[\"']")
_FPS_RE = re.compile(r"fps\s*=\s*(\d+)")


def _textual_facts(text):
    """Labelled textual facts from config.lua/build.settings
    text. Every value comes from a bounded regex over the
    shipped text; nothing is executed or evaluated."""
    facts = {"orientation_default": None, "content_scale": None,
             "content_fps": None, "evidence": "textual regex "
             "over the shipped config text"}
    m = _ORIENTATION_RE.search(text)
    if m:
        facts["orientation_default"] = m.group(1)
    m = _SCALE_RE.search(text)
    if m:
        facts["content_scale"] = m.group(1)
    m = _FPS_RE.search(text)
    if m:
        facts["content_fps"] = int(m.group(1))
    return facts


def parse_car(data, source):
    """Parse one resource.car blob. Never raises on bad data."""
    rec = {"source": source, "size_bytes": len(data),
           "is_zip": False, "listing": None, "config": None,
           "compiled_lua": None, "header_hex": None,
           "note": None}
    if not zipfile.is_zipfile(io.BytesIO(data)):
        rec["header_hex"] = data[:16].hex()
        rec["note"] = ("non-ZIP car variant: identification "
                       "level only (header facts reported; "
                       "the payload layout is not a plain ZIP "
                       "and is not decoded)")
        return rec
    rec["is_zip"] = True
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        rec["is_zip"] = False
        rec["header_hex"] = data[:16].hex()
        rec["note"] = f"ZIP open failed: {e}"
        return rec
    with zf:
        by_ext = {}
        total = 0
        count = 0
        luac = 0
        bytecode_extless = 0
        config_text = None
        settings_text = None
        for info in zf.infolist():
            if info.is_dir():
                continue
            count += 1
            total += info.file_size
            base = info.filename.rsplit("/", 1)[-1]
            _stem, dot, ext = base.rpartition(".")
            ext_key = f".{ext.lower()}" if dot and ext else "(none)"
            by_ext[ext_key] = by_ext.get(ext_key, 0) + 1
            low = info.filename.lower()
            if low.endswith(".luac"):
                luac += 1
            elif not dot:
                if info.file_size >= 4 and \
                        info.file_size <= MEMBER_CAP_BYTES:
                    try:
                        head = zf.read(info.filename)[:4]
                    except (KeyError, OSError, RuntimeError):
                        head = b""
                    if head.startswith(LUA_MAGIC):
                        bytecode_extless += 1
            if base.lower() == "config.lua" and \
                    info.file_size <= TEXT_CAP_BYTES:
                config_text = zf.read(info.filename).decode(
                    "utf-8", "replace")
            elif base.lower() == "build.settings" and \
                    info.file_size <= TEXT_CAP_BYTES:
                settings_text = zf.read(info.filename).decode(
                    "utf-8", "replace")
        rec["listing"] = {"count": count,
                          "by_ext": dict(sorted(by_ext.items())),
                          "total_bytes": total}
        rec["compiled_lua"] = {
            "luac_count": luac,
            "extensionless_bytecode_count": bytecode_extless,
            "total": luac + bytecode_extless}
        facts = {}
        if config_text is not None:
            facts["config.lua"] = _textual_facts(config_text)
        if settings_text is not None:
            facts["build.settings"] = _textual_facts(settings_text)
        rec["config"] = facts if facts else None
    return rec


def _markers(resolved, roots):
    luac_members = []
    corona_libs = []
    for root in roots:
        try:
            zf = zipfile.ZipFile(root)
        except (zipfile.BadZipFile, OSError):
            continue
        with zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                low = info.filename.lower()
                if low.startswith("assets/") and \
                        low.endswith(".luac"):
                    luac_members.append(info.filename)
                if low.rsplit("/", 1)[-1] == "libcorona.so":
                    corona_libs.append(info.filename)
    return {"luac_members": luac_members,
            "luac_count": len(luac_members),
            "libcorona_so": corona_libs,
            "libcorona_present": bool(corona_libs)}


def inspect(target):
    if not os.path.isfile(target):
        raise FileNotFoundError(f"not a file: {target}")
    resolved = container_mod.resolve_target(target)
    try:
        report = {"tool": "nar-solar2d", "version": VERSION,
                  "target": os.path.abspath(target),
                  "container": resolved.container_block(),
                  "verdict": "absent", "cars": [],
                  "listing": None, "config": None,
                  "compiled_lua": None, "markers": None,
                  "limitations": []}
        cars = []
        low = os.path.basename(target).lower()
        roots = list(resolved.assets_roots)
        if not roots and not resolved.is_container and \
                zipfile.is_zipfile(target):
            roots = [os.path.abspath(target)]
        if not resolved.is_container and low == "resource.car":
            with open(target, "rb") as fh:
                data = fh.read(MEMBER_CAP_BYTES + 1)
            if len(data) > MEMBER_CAP_BYTES:
                cars.append({"source": os.path.basename(target),
                             "size_bytes": os.path.getsize(target),
                             "is_zip": False, "listing": None,
                             "note": "file exceeds the 32 MiB "
                                     "read cap"})
            else:
                cars.append(parse_car(data, os.path.basename(target)))
        else:
            for root in roots:
                label = os.path.basename(root)
                try:
                    zf = zipfile.ZipFile(root)
                except (zipfile.BadZipFile, OSError):
                    continue
                with zf:
                    for info in zf.infolist():
                        if info.is_dir():
                            continue
                        if info.filename.rsplit(
                                "/", 1)[-1].lower() != "resource.car":
                            continue
                        if info.file_size > MEMBER_CAP_BYTES:
                            cars.append({
                                "source": info.filename,
                                "source_archive": label,
                                "size_bytes": info.file_size,
                                "is_zip": False, "listing": None,
                                "note": "member exceeds the "
                                        "32 MiB read cap"})
                            continue
                        rec = parse_car(
                            zf.read(info.filename), info.filename)
                        rec["source_archive"] = label
                        cars.append(rec)
        report["cars"] = cars
        if cars:
            first = cars[0]
            report["listing"] = first.get("listing")
            report["config"] = first.get("config")
            report["compiled_lua"] = first.get("compiled_lua")
        markers = _markers(resolved, roots)
        report["markers"] = markers
        if cars or markers["libcorona_present"]:
            report["verdict"] = "present"
        return report
    finally:
        resolved.cleanup()


def human(report):
    lines = [f"NAR Solar2D inspection: {report['target']}",
             f"Verdict: {report['verdict']}"]
    for rec in report["cars"]:
        lines.append(f"Car: {rec.get('source')} "
                     f"({rec.get('size_bytes')} bytes, "
                     f"zip: {rec.get('is_zip')})")
        if rec.get("listing"):
            lines.append(f"  listing: {rec['listing']}")
        if rec.get("config"):
            lines.append(f"  config facts (textual): {rec['config']}")
        if rec.get("compiled_lua"):
            lines.append(f"  compiled lua: {rec['compiled_lua']}")
        if rec.get("note"):
            lines.append(f"  note: {rec['note']}")
        if rec.get("header_hex"):
            lines.append(f"  header: {rec['header_hex']}")
    lines.append(f"Markers: {report.get('markers')}")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR Solar2D resource.car inspector.")
    p.add_argument("target", help="path to an .apk, a container, "
                                  "or a bare resource.car file")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    try:
        report = inspect(args.target)
    except FileNotFoundError as e:
        print(f"nar-solar2d: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(human(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
