#!/usr/bin/env python3
"""nar-cordova.py: deep-dive inspection of a Cordova / PhoneGap
hybrid app inside an APK (or split set / container).

Evidence is the family's own: a config.xml whose root element
is <widget> (assets/www/config.xml, res/xml/config.xml, or any
*/config.xml), the www/ web root census, and the plugin list
formed by merging config.xml <feature> entries with the
module.exports.metadata object at the end of
www/cordova_plugins.js. Stdlib only; member reads are capped
and malformed members degrade to per-item notes, never a
crash. Nothing is executed.

Usage:
    python3 nar-cordova.py app.apk [--json]

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
from narlib import container as container_mod  # noqa: E402
from narlib.safearchive import read_member_capped  # noqa: E402

VERSION = "3.0.2"
MEMBER_CAP = 32 * 1024 * 1024
TEXT_CAP = 2 * 1024 * 1024

_METADATA_ASSIGN_RE = re.compile(
    r"module\.exports\.metadata\s*=")
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)


def _local(tag):
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _children(elem, name):
    return [c for c in elem if _local(c.tag) == name]


def _child(elem, name):
    for c in elem:
        if _local(c.tag) == name:
            return c
    return None


def build_index(resolved):
    """name -> (archive_path, size) across the resolved roots,
    base first (first occurrence wins)."""
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


def _ext(name):
    base = name.rsplit("/", 1)[-1]
    return base.rsplit(".", 1)[-1].lower() if "." in base else "(none)"


def census(index, prefix):
    by_ext = {}
    total_bytes = 0
    count = 0
    for name, (_root, size) in index.items():
        if not name.startswith(prefix):
            continue
        count += 1
        total_bytes += size
        by_ext[_ext(name)] = by_ext.get(_ext(name), 0) + 1
    return {"root": prefix, "file_count": count,
            "total_bytes": total_bytes,
            "by_extension": dict(sorted(by_ext.items()))}


def parse_config(data):
    """Parse one config.xml candidate. Returns (descriptor,
    features) or raises ValueError when it is not a Cordova
    <widget> descriptor."""
    root = ET.fromstring(data)
    if _local(root.tag) != "widget":
        raise ValueError(f"root element is <{_local(root.tag)}>, "
                         "not <widget>")
    name_el = _child(root, "name")
    desc_el = _child(root, "description")
    prefs = _children(root, "preference")
    descriptor = {
        "id": root.get("id"),
        "version": root.get("version"),
        "name": (name_el.text or "").strip() if name_el is not None
                else None,
        "description_present": desc_el is not None,
        "preference_count": len(prefs),
        "preference_names": sorted(
            p.get("name") for p in prefs if p.get("name")),
        "access_origins": [a.get("origin") for a in
                           _children(root, "access")
                           if a.get("origin")],
    }
    features = []
    for feat in _children(root, "feature"):
        params = {}
        for param in _children(feat, "param"):
            if param.get("name"):
                params[param.get("name")] = param.get("value")
        features.append({
            "name": feat.get("name"),
            "android_package": params.get("android-package"),
            "params": params,
        })
    return descriptor, features


def plugins_js_metadata(index, notes):
    """plugin id -> version from cordova_plugins.js metadata."""
    candidates = [n for n in index
                  if n.endswith("cordova_plugins.js")]
    for name in sorted(candidates):
        try:
            text = read_member(index, name).decode(
                "utf-8", "replace")
        except (KeyError, OSError, ValueError,
                zipfile.BadZipFile) as e:
            notes.append(f"{name}: unreadable ({e})")
            continue
        # The metadata object literal follows the assignment
        # (real files interleave // TOP OF METADATA comments);
        # locate it with a bounded regex, then JSON-decode the
        # object literal itself (raw_decode stops at its end).
        tail = text[-TEXT_CAP:]
        m = _METADATA_ASSIGN_RE.search(tail)
        brace = tail.find("{", m.end()) if m else -1
        if brace == -1:
            notes.append(f"{name}: no module.exports.metadata "
                         "object found")
            return {}
        try:
            meta, _end = json.JSONDecoder().raw_decode(
                tail[brace:])
        except ValueError as e:
            notes.append(f"{name}: metadata object did not "
                         f"parse as JSON ({e})")
            return {}
        if isinstance(meta, dict):
            return {str(k): str(v) for k, v in meta.items()}
        notes.append(f"{name}: metadata is not a JSON object")
        return {}
    return {}


def inspect(target):
    report = {"tool": "nar-cordova", "version": VERSION,
              "target": os.path.abspath(target),
              "verdict": "absent", "descriptor": {},
              "web_root": {}, "plugins": [], "notes": []}
    notes = report["notes"]
    resolved = container_mod.resolve_target(target)
    try:
        report["container"] = resolved.container_block()
        index = build_index(resolved)
        # --- config.xml candidates, canonical paths first ---
        candidates = [n for n in index if n.endswith("config.xml")]
        candidates.sort(key=lambda n: (
            n not in ("assets/www/config.xml",
                      "res/xml/config.xml"), n))
        descriptor = None
        features = []
        config_path = None
        for name in candidates:
            try:
                data = read_member(index, name)
            except (KeyError, OSError, ValueError,
                    zipfile.BadZipFile) as e:
                notes.append(f"{name}: unreadable ({e})")
                continue
            try:
                descriptor, features = parse_config(data)
            except (ET.ParseError, ValueError) as e:
                notes.append(f"{name}: not a Cordova widget "
                             f"descriptor ({e})")
                continue
            config_path = name
            break
        if descriptor is None:
            notes.append("no config.xml with a <widget> root "
                         "found in the resolved roots")
            return report
        descriptor["path"] = config_path
        report["descriptor"] = descriptor
        report["verdict"] = "present"
        # --- web root census: the www/ tree the config lives
        # in, else the canonical assets/www/ ----------------
        prefix = None
        if "/www/" in config_path or \
                config_path.startswith("www/"):
            prefix = config_path.rsplit("/", 1)[0] + "/"
        elif any(n.startswith("assets/www/") for n in index):
            prefix = "assets/www/"
        if prefix:
            web = census(index, prefix)
            idx_name = prefix + "index.html"
            web["index_html_present"] = idx_name in index
            web["index_title"] = None
            if web["index_html_present"]:
                try:
                    html = read_member(
                        index, idx_name).decode(
                            "utf-8", "replace")
                    m = _TITLE_RE.search(html[:TEXT_CAP])
                    if m:
                        web["index_title"] = m.group(1).strip()
                except (KeyError, OSError, ValueError,
                        zipfile.BadZipFile) as e:
                    notes.append(f"{idx_name}: unreadable ({e})")
            report["web_root"] = web
        # --- plugins: config features merged with
        # cordova_plugins.js metadata ------------------------
        meta = plugins_js_metadata(index, notes)
        merged = {}
        for feat in features:
            if not feat["name"]:
                continue
            entry = merged.setdefault(feat["name"], {
                "id": feat["name"], "source": "config",
                "version": None,
                "android_package": feat["android_package"]})
            if feat["android_package"]:
                entry["android_package"] = feat["android_package"]
        for pid, ver in meta.items():
            if pid in merged:
                merged[pid]["source"] = "both"
                merged[pid]["version"] = ver
            else:
                merged[pid] = {"id": pid, "source": "plugins_js",
                               "version": ver,
                               "android_package": None}
        report["plugins"] = [merged[k] for k in sorted(merged)]
        return report
    finally:
        resolved.cleanup()


def human(report):
    lines = [f"NAR Cordova deep dive: {report['target']}"]
    if report["verdict"] != "present":
        lines.append("ABSENT: no Cordova <widget> config.xml "
                     "found")
        for n in report["notes"]:
            lines.append(f"  note: {n}")
        return "\n".join(lines)
    d = report["descriptor"]
    lines.append(f"PRESENT: {d.get('id')} version "
                 f"{d.get('version')} (name: {d.get('name')}) "
                 f"via {d.get('path')}")
    lines.append(f"Preferences: {d['preference_count']} "
                 f"({', '.join(d['preference_names'])})")
    lines.append(f"Access origins: "
                 f"{', '.join(d['access_origins']) or 'none'}")
    web = report["web_root"]
    if web:
        lines.append(f"Web root {web['root']}: "
                     f"{web['file_count']} files, "
                     f"{web['total_bytes']:,} bytes; "
                     f"index.html: "
                     f"{'yes, title ' + repr(web['index_title']) if web['index_html_present'] else 'no'}")
    lines.append(f"Plugins ({len(report['plugins'])}):")
    for p in report["plugins"]:
        lines.append(f"  {p['id']} [{p['source']}] "
                     f"version={p['version']} "
                     f"android-package={p['android_package']}")
    for n in report["notes"]:
        lines.append(f"  note: {n}")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR Cordova/PhoneGap hybrid deep dive.")
    p.add_argument("target", help="path to an .apk / container")
    p.add_argument("--json", action="store_true",
                   help="machine-readable JSON output")
    args = p.parse_args(argv)
    if not os.path.isfile(args.target):
        print(f"nar-cordova: not a file: {args.target}",
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
