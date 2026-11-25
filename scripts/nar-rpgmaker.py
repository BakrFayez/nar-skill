#!/usr/bin/env python3
"""nar-rpgmaker.py: deep-dive inspection of an RPG Maker
MV/MZ web export inside an APK (or split set / container).

Layouts covered: assets/www/ (MV/MZ export root),
assets/js/ + assets/data/ (root = assets/), a Game.rpgproject
or package.json member, or a bare Game.rpgproject /
package.json file as the target. The database census parses
the standard data/*.json files (top-level array lengths for
Actors, Classes, Skills, ... plus the MapNNN.json count and
one sampled map's dimensions / event count), js/plugins.js
is parsed for its $plugins array, and the engine generation
(MV vs MZ) is an inference from file markers (js/rpg_* vs
js/rmmz_*, data/Effects.json, Game.rpgproject) — labelled as
inference. Stdlib only; reads are capped and malformed
members degrade to notes, never a crash.

Usage:
    python3 nar-rpgmaker.py app.apk [--json]

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
from narlib import container as container_mod  # noqa: E402
from narlib.safearchive import read_member_capped  # noqa: E402

VERSION = "3.0.0"
MEMBER_CAP = 32 * 1024 * 1024

DB_FILES = ("Actors", "Classes", "Skills", "Items", "Weapons",
            "Armors", "Enemies", "States", "Animations",
            "Tilesets", "CommonEvents", "Troops", "MapInfos")
_MAP_RE = re.compile(r"data/Map(\d+)\.json$")
_PLUGINS_RE = re.compile(r"\$plugins\s*=\s*(\[.*\])\s*;", re.S)
_ASSET_FOLDERS = ("audio/bgm", "audio/se", "img/pictures",
                  "movies")


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


def find_root(index):
    """The export root prefix: the directory holding data/
    and js/, a Game.rpgproject, or a package.json."""
    for name in sorted(index):
        if name.endswith("Game.rpgproject"):
            return name[:-len("Game.rpgproject")]
    for name in sorted(index):
        if re.search(r"data/(Actors|MapInfos)\.json$", name):
            return _root_of_data_member(name)
    for name in sorted(index):
        if name.endswith("package.json"):
            return name[:-len("package.json")]
    return None


def _root_of_data_member(name):
    """Prefix before 'data/' for a member path."""
    idx = name.rfind("data/")
    return name[:idx] if idx != -1 else ""


def inspect(target):
    report = {"tool": "nar-rpgmaker", "version": VERSION,
              "target": os.path.abspath(target),
              "verdict": "absent", "root": None,
              "data_census": {}, "map_count": 0,
              "map_sample": None, "plugins": [],
              "package": None, "asset_census": {},
              "engine_generation": {"guess": "unknown",
                                    "evidence": [],
                                    "basis": "file markers; "
                                             "inference"},
              "notes": []}
    notes = report["notes"]
    # Bare Game.rpgproject / package.json target.
    base = os.path.basename(target)
    if base in ("Game.rpgproject", "package.json") and \
            target.lower().endswith((".rpgproject", ".json")):
        report["container"] = {"input_kind": "file",
                               "base": base, "base_entry": None,
                               "splits_merged": [],
                               "split_skipped": [], "obbs": []}
        report["root"] = ""
        report["verdict"] = "present"
        if base == "Game.rpgproject":
            report["engine_generation"] = {
                "guess": "MV", "evidence": ["Game.rpgproject"],
                "basis": "file markers; inference"}
        else:
            try:
                with open(target, "rb") as fh:
                    doc = json.loads(fh.read(MEMBER_CAP).decode(
                        "utf-8", "replace"))
                if isinstance(doc, dict):
                    report["package"] = {
                        "name": doc.get("name"),
                        "main": doc.get("main")}
            except (OSError, ValueError) as e:
                notes.append(f"package.json unreadable ({e})")
        notes.append("bare file target: no archive census "
                     "applies")
        return report
    resolved = container_mod.resolve_target(target)
    try:
        report["container"] = resolved.container_block()
        index = build_index(resolved)
        root = find_root(index)
        if root is None:
            # Fall back to a data/ anchor anywhere.
            for name in sorted(index):
                if _MAP_RE.search(name):
                    root = _root_of_data_member(name)
                    break
        if root is None:
            notes.append("no RPG Maker export root found (no "
                         "Game.rpgproject, data/*.json database "
                         "or package.json anchor)")
            return report
        report["root"] = root
        report["verdict"] = "present"
        # --- database census --------------------------------
        census = {}
        for db in DB_FILES:
            name = f"{root}data/{db}.json"
            if name not in index:
                census[db] = None
                continue
            try:
                doc = json.loads(read_member(index, name).decode(
                    "utf-8", "replace"))
                census[db] = len(doc) if isinstance(doc, list) \
                    else None
                if not isinstance(doc, list):
                    notes.append(f"{name}: JSON root is not an "
                                 "array; length not counted")
            except (KeyError, OSError, ValueError,
                    zipfile.BadZipFile) as e:
                census[db] = None
                notes.append(f"{name}: unreadable ({e})")
        report["data_census"] = census
        maps = sorted(n for n in index
                      if _MAP_RE.search(n)
                      and n.startswith(root))
        report["map_count"] = len(maps)
        if maps:
            sample_name = maps[0]
            try:
                doc = json.loads(read_member(
                    index, sample_name).decode(
                        "utf-8", "replace"))
                if isinstance(doc, dict):
                    events = doc.get("events") or []
                    report["map_sample"] = {
                        "file": sample_name,
                        "width": doc.get("width"),
                        "height": doc.get("height"),
                        "events_count": sum(
                            1 for e in events if e is not None),
                    }
            except (KeyError, OSError, ValueError,
                    zipfile.BadZipFile) as e:
                notes.append(f"{sample_name}: sample map "
                             f"unreadable ({e})")
        # --- plugins.js --------------------------------------
        plugins_name = f"{root}js/plugins.js"
        if plugins_name in index:
            try:
                text = read_member(index, plugins_name).decode(
                    "utf-8", "replace")
                m = _PLUGINS_RE.search(text)
                if m:
                    doc = json.loads(m.group(1))
                    if isinstance(doc, list):
                        report["plugins"] = [{
                            "name": p.get("name"),
                            "status": p.get("status"),
                            "description_present": bool(
                                p.get("description")),
                        } for p in doc if isinstance(p, dict)]
                    else:
                        notes.append("plugins.js: $plugins is "
                                     "not an array")
                else:
                    notes.append("plugins.js: no $plugins array "
                                 "literal found")
            except (KeyError, OSError, ValueError,
                    zipfile.BadZipFile) as e:
                notes.append(f"{plugins_name}: unreadable ({e})")
        # --- package.json ------------------------------------
        pkg_name = f"{root}package.json"
        if pkg_name in index:
            try:
                doc = json.loads(read_member(
                    index, pkg_name).decode("utf-8", "replace"))
                if isinstance(doc, dict):
                    report["package"] = {
                        "name": doc.get("name"),
                        "main": doc.get("main")}
            except (KeyError, OSError, ValueError,
                    zipfile.BadZipFile) as e:
                notes.append(f"{pkg_name}: unreadable ({e})")
        # --- asset census ------------------------------------
        asset_census = {}
        for folder in _ASSET_FOLDERS:
            prefix = f"{root}{folder}/"
            asset_census[folder] = sum(
                1 for n in index if n.startswith(prefix))
        report["asset_census"] = asset_census
        # --- engine generation (inference from markers) -----
        evidence = []
        js_names = [n for n in index
                    if n.startswith(f"{root}js/")]
        if f"{root}data/Effects.json" in index:
            evidence.append("data/Effects.json (MZ database "
                            "file)")
        if any(n.rsplit("/", 1)[-1].startswith("rmmz_")
               for n in js_names):
            evidence.append("js/rmmz_* core scripts")
        if any(n.rsplit("/", 1)[-1].startswith("rpg_")
               for n in js_names):
            evidence.append("js/rpg_* core scripts")
        if f"{root}Game.rpgproject" in index:
            evidence.append("Game.rpgproject")
        guess = "unknown"
        if any("MZ" in e or "rmmz" in e for e in evidence):
            guess = "MZ"
        elif evidence:
            guess = "MV"
        report["engine_generation"] = {
            "guess": guess, "evidence": evidence,
            "basis": "file markers; inference, not a version "
                     "string read from the engine"}
        return report
    finally:
        resolved.cleanup()


def human(report):
    lines = [f"NAR RPG Maker deep dive: {report['target']}"]
    if report["verdict"] != "present":
        lines.append("ABSENT: no RPG Maker web export found")
        for n in report["notes"]:
            lines.append(f"  note: {n}")
        return "\n".join(lines)
    lines.append(f"PRESENT: export root {report['root']!r}, "
                 f"generation guess "
                 f"{report['engine_generation']['guess']} "
                 f"({'; '.join(report['engine_generation']['evidence'])})")
    lines.append(f"Database: {report['data_census']}")
    lines.append(f"Maps: {report['map_count']}; sample: "
                 f"{report['map_sample']}")
    lines.append(f"Plugins ({len(report['plugins'])}):")
    for p in report["plugins"]:
        lines.append(f"  {p['name']} status={p['status']} "
                     f"description="
                     f"{'yes' if p['description_present'] else 'no'}")
    if report["package"]:
        lines.append(f"package.json: {report['package']}")
    lines.append(f"Assets: {report['asset_census']}")
    for n in report["notes"]:
        lines.append(f"  note: {n}")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR RPG Maker MV/MZ web-export deep dive.")
    p.add_argument("target", help="path to an .apk / container")
    p.add_argument("--json", action="store_true",
                   help="machine-readable JSON output")
    args = p.parse_args(argv)
    if not os.path.isfile(args.target):
        print(f"nar-rpgmaker: not a file: {args.target}",
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
