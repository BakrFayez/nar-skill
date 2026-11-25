#!/usr/bin/env python3
"""nar-capacitor.py: deep-dive inspection of a Capacitor
hybrid app inside an APK (or split set / container).

Evidence is the family's own: capacitor.config.json
(appId / appName / webDir / server / bundledWebRuntime), the
bundled web root census (assets/public/ or the webDir-named
root), the shipped capacitor.plugins.json inventory when
present, and the native-bridge / capacitor.js web markers.
Server URLs are reported as presence + host only — a full
URL can carry credentials and is never printed. Capacitor
plugins are native-side code; when no plugins.json ships,
this tool says so and leaves DEX evidence to nar-engines /
nar-dex. Stdlib only; reads are capped and malformed members
degrade to notes, never a crash.

Usage:
    python3 nar-capacitor.py app.apk [--json]

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import re
import sys
import zipfile
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import container as container_mod  # noqa: E402
from narlib.safearchive import read_member_capped  # noqa: E402

VERSION = "3.0.0"
MEMBER_CAP = 32 * 1024 * 1024
TEXT_CAP = 2 * 1024 * 1024

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)


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


def _host_only(url):
    if not isinstance(url, str) or not url:
        return None
    try:
        return urlparse(url).hostname
    except ValueError:
        return None


def inspect(target):
    report = {"tool": "nar-capacitor", "version": VERSION,
              "target": os.path.abspath(target),
              "verdict": "absent", "descriptor": {},
              "web_root": {}, "plugins": [],
              "native_markers": {}, "notes": []}
    notes = report["notes"]
    resolved = container_mod.resolve_target(target)
    try:
        report["container"] = resolved.container_block()
        index = build_index(resolved)
        candidates = [n for n in index
                      if n.endswith("capacitor.config.json")]
        candidates.sort(key=lambda n: (
            n != "assets/capacitor.config.json", n))
        config = None
        config_path = None
        for name in candidates:
            try:
                doc = json.loads(read_member(index, name).decode(
                    "utf-8", "replace"))
            except (KeyError, OSError, ValueError,
                    zipfile.BadZipFile) as e:
                notes.append(f"{name}: unreadable or invalid "
                             f"JSON ({e})")
                continue
            if isinstance(doc, dict):
                config, config_path = doc, name
                break
            notes.append(f"{name}: JSON root is not an object")
        if config is None:
            notes.append("no parseable capacitor.config.json "
                         "found in the resolved roots")
            return report
        server = config.get("server") or {}
        if not isinstance(server, dict):
            server = {}
        url = server.get("url")
        report["descriptor"] = {
            "path": config_path,
            "appId": config.get("appId"),
            "appName": config.get("appName"),
            "webDir": config.get("webDir"),
            "bundledWebRuntime": config.get("bundledWebRuntime"),
            "server": {
                "androidScheme": server.get("androidScheme"),
                "hostname": server.get("hostname"),
                "url_present": bool(url),
                "url_host": _host_only(url),
            },
        }
        report["verdict"] = "present"
        # --- web root: webDir-named root, else assets/public/
        webdir = config.get("webDir")
        prefix = None
        if isinstance(webdir, str) and webdir:
            suffix = webdir.strip("/") + "/"
            hits = sorted({n[:n.find(suffix) + len(suffix)]
                           for n in index if suffix in n})
            if hits:
                prefix = hits[0]
        if prefix is None:
            for cand in ("assets/public/", "assets/www/"):
                if any(n.startswith(cand) for n in index):
                    prefix = cand
                    break
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
        else:
            notes.append("no bundled web root found for the "
                         "configured webDir")
        # --- plugins inventory ------------------------------
        plugin_files = [n for n in index
                        if n.endswith("capacitor.plugins.json")]
        plugin_files.sort(key=lambda n: (
            n != "assets/capacitor.plugins.json", n))
        parsed_plugins = None
        for name in plugin_files:
            try:
                doc = json.loads(read_member(index, name).decode(
                    "utf-8", "replace"))
            except (KeyError, OSError, ValueError,
                    zipfile.BadZipFile) as e:
                notes.append(f"{name}: unreadable or invalid "
                             f"JSON ({e})")
                continue
            if isinstance(doc, list):
                parsed_plugins = [{
                    "id": p.get("id"), "name": p.get("name"),
                    "version": p.get("version"),
                } for p in doc if isinstance(p, dict)]
                break
            notes.append(f"{name}: JSON root is not an array")
        if parsed_plugins is not None:
            report["plugins"] = parsed_plugins
        else:
            notes.append(
                "no capacitor.plugins.json shipped: Capacitor "
                "plugins are native-side code, so plugin "
                "evidence lives in the DEX layer (nar-engines "
                "/ nar-dex), not in web assets")
        # --- native bridge markers --------------------------
        markers = {"native_bridge_js": [], "capacitor_js": []}
        for name in sorted(index):
            base = name.rsplit("/", 1)[-1]
            if base == "native-bridge.js":
                markers["native_bridge_js"].append(name)
            elif base == "capacitor.js":
                markers["capacitor_js"].append(name)
        report["native_markers"] = {
            "native_bridge_js_present":
                bool(markers["native_bridge_js"]),
            "native_bridge_js_paths": markers["native_bridge_js"],
            "capacitor_js_present": bool(markers["capacitor_js"]),
            "capacitor_js_paths": markers["capacitor_js"],
        }
        return report
    finally:
        resolved.cleanup()


def human(report):
    lines = [f"NAR Capacitor deep dive: {report['target']}"]
    if report["verdict"] != "present":
        lines.append("ABSENT: no capacitor.config.json found")
        for n in report["notes"]:
            lines.append(f"  note: {n}")
        return "\n".join(lines)
    d = report["descriptor"]
    lines.append(f"PRESENT: {d.get('appId')} "
                 f"({d.get('appName')}) webDir={d.get('webDir')} "
                 f"via {d.get('path')}")
    srv = d["server"]
    lines.append(f"Server: scheme={srv['androidScheme']} "
                 f"hostname={srv['hostname']} "
                 f"url={'present, host ' + str(srv['url_host']) if srv['url_present'] else 'absent'}")
    web = report["web_root"]
    if web:
        lines.append(f"Web root {web['root']}: "
                     f"{web['file_count']} files, "
                     f"{web['total_bytes']:,} bytes; "
                     f"index.html: "
                     f"{'yes, title ' + repr(web['index_title']) if web['index_html_present'] else 'no'}")
    lines.append(f"Plugins ({len(report['plugins'])}):")
    for p in report["plugins"]:
        lines.append(f"  {p['id']} ({p['name']}) "
                     f"version={p['version']}")
    nm = report["native_markers"]
    lines.append(f"Native markers: native-bridge.js="
                 f"{nm.get('native_bridge_js_present')}, "
                 f"capacitor.js={nm.get('capacitor_js_present')}")
    for n in report["notes"]:
        lines.append(f"  note: {n}")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR Capacitor hybrid deep dive.")
    p.add_argument("target", help="path to an .apk / container")
    p.add_argument("--json", action="store_true",
                   help="machine-readable JSON output")
    args = p.parse_args(argv)
    if not os.path.isfile(args.target):
        print(f"nar-capacitor: not a file: {args.target}",
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
