#!/usr/bin/env python3
"""nar-webassets.py: deep-dive census of generic web assets
(www-like roots) inside an APK (or split set / container).

Roots covered: assets/www, assets/web, assets/public,
assets/html. For each root: a census by extension and an
index.html parse (title, <script src> list, <link href>
list, <base href>). For the largest few .js bundles, a
bounded prefix scan counts framework string markers
(webpack / Angular / React / Vue / Svelte / Ionic) — string
evidence only, labelled heuristic: a marker count shows a
string ships in the bundle, not that the framework runs.
Roots claimed by a framework config (Cordova / Capacitor)
are still reported; the overlap is named in a field. Stdlib
only; reads are capped and malformed members degrade to
notes, never a crash.

Usage:
    python3 nar-webassets.py app.apk [--json]

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

VERSION = "3.0.1"
MEMBER_CAP = 32 * 1024 * 1024
TEXT_CAP = 2 * 1024 * 1024
JS_PREFIX_CAP = 256 * 1024
JS_BUNDLE_LIMIT = 8

ROOTS = ("assets/www/", "assets/web/", "assets/public/",
         "assets/html/")

# Framework string markers: label -> literal strings counted
# in bundle prefixes (and, for Angular, the ng-version
# attribute in index.html). Heuristic string evidence.
MARKERS = {
    "webpack": ("__webpack_require__", "webpackJsonp"),
    "angular": ("@angular",),
    "react": ("react", "ReactDOM", "data-reactroot"),
    "vue": ("Vue", "__vue__", "createApp"),
    "svelte": ("svelte",),
    "ionic": ("ion-app", "@ionic"),
}

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)
_SCRIPT_RE = re.compile(
    r"<script[^>]+src\s*=\s*[\"']([^\"']+)[\"']", re.I)
_LINK_RE = re.compile(
    r"<link[^>]+href\s*=\s*[\"']([^\"']+)[\"']", re.I)
_BASE_RE = re.compile(
    r"<base[^>]+href\s*=\s*[\"']([^\"']+)[\"']", re.I)
_NG_VERSION_RE = re.compile(r"ng-version\s*=", re.I)


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


def read_prefix(index, name, cap):
    """First `cap` bytes of a member, streamed (no full
    materialization of a large bundle)."""
    root, _size = index[name]
    with zipfile.ZipFile(root) as zf:
        with zf.open(name) as fh:
            return fh.read(cap)


def _ext(name):
    base = name.rsplit("/", 1)[-1]
    return base.rsplit(".", 1)[-1].lower() if "." in base else "(none)"


def parse_index_html(html):
    title = _TITLE_RE.search(html)
    base = _BASE_RE.search(html)
    return {
        "title": title.group(1).strip() if title else None,
        "script_srcs": _SCRIPT_RE.findall(html),
        "link_hrefs": _LINK_RE.findall(html),
        "base_href": base.group(1) if base else None,
        "ng_version_present": bool(_NG_VERSION_RE.search(html)),
    }


def scan_bundle(text):
    """Marker counts for one bundle prefix: per framework
    label, the summed literal-string counts, plus the
    per-string detail."""
    labels = {}
    detail = {}
    for label, markers in MARKERS.items():
        total = 0
        for marker in markers:
            n = text.count(marker)
            if n:
                detail[marker] = n
            total += n
        labels[label] = total
    return labels, detail


def inspect(target):
    report = {"tool": "nar-webassets", "version": VERSION,
              "target": os.path.abspath(target),
              "verdict": "absent", "roots": [],
              "bundles": [], "framework_evidence": {},
              "framework_overlap": [],
              "heuristic_note": "framework markers are literal "
                                "string counts in bounded "
                                "bundle prefixes (string "
                                "evidence, heuristic): they "
                                "show a string ships, not that "
                                "the framework runs",
              "notes": []}
    notes = report["notes"]
    resolved = container_mod.resolve_target(target)
    try:
        report["container"] = resolved.container_block()
        index = build_index(resolved)
        # Overlap: a framework config claiming the same roots
        # does not suppress this census; it is named instead.
        if any(n.endswith("capacitor.config.json")
               for n in index):
            report["framework_overlap"].append(
                "capacitor.config.json present: the web root "
                "is also claimed by Capacitor (nar-capacitor)")
        if any(n.endswith("config.xml") for n in index) or \
                any(n.rsplit("/", 1)[-1].startswith("cordova")
                    and n.endswith(".js") for n in index):
            report["framework_overlap"].append(
                "Cordova evidence present (config.xml / "
                "cordova*.js): the web root is also claimed "
                "by Cordova (nar-cordova)")
        present_roots = []
        for prefix in ROOTS:
            members = {n: s for n, (r, s) in index.items()
                       if n.startswith(prefix)}
            if not members:
                continue
            by_ext = {}
            total = 0
            for n, size in members.items():
                by_ext[_ext(n)] = by_ext.get(_ext(n), 0) + 1
                total += size
            root_rec = {"root": prefix,
                        "file_count": len(members),
                        "total_bytes": total,
                        "by_extension": dict(
                            sorted(by_ext.items())),
                        "index_html_present":
                            prefix + "index.html" in members,
                        "index": None}
            if root_rec["index_html_present"]:
                present_roots.append(prefix)
                try:
                    html = read_member(
                        index, prefix + "index.html").decode(
                            "utf-8", "replace")
                    root_rec["index"] = parse_index_html(
                        html[:TEXT_CAP])
                except (KeyError, OSError, ValueError,
                        zipfile.BadZipFile) as e:
                    notes.append(f"{prefix}index.html: "
                                 f"unreadable ({e})")
            report["roots"].append(root_rec)
        if present_roots:
            report["verdict"] = "present"
        else:
            notes.append("no www-like root with an index.html "
                         "found (roots checked: "
                         + ", ".join(ROOTS) + ")")
        # --- JS bundle marker census: largest <= 8 .js
        # members under the www-like roots ------------------
        js_members = [(n, s) for n, (r, s) in index.items()
                      if n.lower().endswith(".js")
                      and any(n.startswith(p) for p in ROOTS)]
        js_members.sort(key=lambda t: (-t[1], t[0]))
        aggregate = {label: 0 for label in MARKERS}
        aggregate_detail = {}
        for name, size in js_members[:JS_BUNDLE_LIMIT]:
            try:
                prefix_bytes = read_prefix(
                    index, name, JS_PREFIX_CAP)
            except (KeyError, OSError, ValueError,
                    RuntimeError, zipfile.BadZipFile) as e:
                notes.append(f"{name}: bundle prefix "
                             f"unreadable ({e})")
                continue
            text = prefix_bytes.decode("utf-8", "replace")
            labels, detail = scan_bundle(text)
            for label, total in labels.items():
                aggregate[label] += total
            for marker, n in detail.items():
                aggregate_detail[marker] = \
                    aggregate_detail.get(marker, 0) + n
            report["bundles"].append({
                "file": name, "size_bytes": size,
                "scanned_bytes": len(prefix_bytes),
                "markers": labels, "marker_detail": detail})
        # Angular also leaves ng-version in index.html.
        ng = any((r["index"] or {}).get("ng_version_present")
                 for r in report["roots"])
        if ng:
            aggregate["angular"] += 1
            aggregate_detail["ng-version (index.html)"] = 1
        report["framework_evidence"] = {
            "by_framework": aggregate,
            "by_marker": dict(sorted(aggregate_detail.items())),
            "bundles_scanned": len(report["bundles"]),
            "basis": "literal string counts in the first "
                     f"{JS_PREFIX_CAP} bytes of the largest "
                     f"{JS_BUNDLE_LIMIT} .js members, plus the "
                     "ng-version attribute in index.html",
        }
        return report
    finally:
        resolved.cleanup()


def human(report):
    lines = [f"NAR web-assets deep dive: {report['target']}"]
    if report["verdict"] != "present":
        lines.append("ABSENT: no www-like root with an "
                     "index.html found")
    else:
        lines.append("PRESENT: www-like web root(s) with "
                     "index.html")
    for r in report["roots"]:
        lines.append(f"Root {r['root']}: {r['file_count']} "
                     f"files, {r['total_bytes']:,} bytes, "
                     f"by extension {r['by_extension']}")
        if r["index"]:
            lines.append(f"  index.html: title="
                         f"{r['index']['title']!r}, scripts="
                         f"{r['index']['script_srcs']}, links="
                         f"{r['index']['link_hrefs']}, base="
                         f"{r['index']['base_href']}")
    fe = report["framework_evidence"]
    if fe:
        lines.append(f"Framework string evidence (heuristic): "
                     f"{fe['by_framework']} over "
                     f"{fe['bundles_scanned']} bundles")
    for o in report["framework_overlap"]:
        lines.append(f"Overlap: {o}")
    for n in report["notes"]:
        lines.append(f"  note: {n}")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR generic web-assets deep dive.")
    p.add_argument("target", help="path to an .apk / container")
    p.add_argument("--json", action="store_true",
                   help="machine-readable JSON output")
    args = p.parse_args(argv)
    if not os.path.isfile(args.target):
        print(f"nar-webassets: not a file: {args.target}",
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
