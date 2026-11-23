#!/usr/bin/env python3
"""nar-report.py: offline HTML dashboard for a NAR case.

Reads a case directory written by nar-analyze (report.json
plus whichever companion documents exist) and renders ONE
self-contained report.html: all data embedded, no external
requests, no CDN, no fonts to fetch. Dark and light themes
(follows the OS preference, with a manual toggle), section
navigation, and client-side search/filter for the endpoint,
findings, and asset tables.

Usage:
    python3 nar-report.py CASE_DIR [--out FILE]

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import html
import json
import os
import sys


def load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def esc(value):
    return html.escape(str(value if value is not None else ""))


def table(headers, rows):
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = ""
    for row in rows:
        body += "<tr>" + "".join(
            f"<td>{esc(c)}</td>" for c in row) + "</tr>"
    return (f'<table><thead><tr>{head}</tr></thead>'
            f"<tbody>{body}</tbody></table>")


def render(case_dir):
    report = load_json(os.path.join(case_dir, "report.json"))
    if report is None:
        raise RuntimeError(f"no readable report.json in {case_dir}")
    fingerprint = load_json(os.path.join(case_dir,
                                         "fingerprint.json")) or {}
    engines = load_json(os.path.join(case_dir, "engines.json")) or {}
    endpoints = load_json(os.path.join(case_dir,
                                       "endpoints.json")) or {}
    security = load_json(os.path.join(case_dir,
                                      "security-findings.json")) or {}
    assets = load_json(os.path.join(case_dir, "assets.json")) or {}
    exec_log = load_json(os.path.join(case_dir,
                                      "execution-log.json")) or {}
    identity = report.get("identity") or {}
    parts = []
    parts.append(f"<h2>Identity</h2><p>"
                 f"<b>{esc(identity.get('package'))}</b> "
                 f"v{esc(identity.get('version_name'))} "
                 f"(code {esc(identity.get('version_code'))}) — "
                 f"{esc(identity.get('app_label'))}<br>"
                 f"min SDK {esc(identity.get('min_sdk'))} / "
                 f"target {esc(identity.get('target_sdk'))} · "
                 f"kind: {esc(identity.get('kind'))}<br>"
                 f"SHA-256: <code>"
                 f"{esc(report.get('target_sha256'))}</code></p>")
    props = (fingerprint.get("properties") or {})
    if props:
        rows = [(name, json.dumps(p.get("value"))[:120],
                 p.get("provenance"), p.get("confidence"))
                for name, p in sorted(props.items())]
        parts.append("<h2>Fingerprint</h2>" + table(
            ["Property", "Value", "Provenance", "Confidence"],
            rows))
    verdicts = engines.get("verdicts") or []
    if verdicts:
        rows = [(v["engine"], "detected" if v["detected"]
                 else "weak", v["confidence"], v.get("score"),
                 v.get("version") or "")
                for v in verdicts]
        parts.append("<h2>Engines</h2>" + table(
            ["Engine", "State", "Confidence", "Score", "Version"],
            rows))
    eps = endpoints.get("endpoints") or []
    if eps:
        rows = [(e["classification"], e["kind"], e["url"][:140])
                for e in eps]
        parts.append(
            '<h2>Network endpoints</h2>'
            '<input class="filter" type="search" '
            'placeholder="Filter endpoints…" '
            'oninput="filterTable(this)">'
            + table(["Class", "Kind", "URL"], rows))
    findings = security.get("findings") or []
    if findings:
        rows = [(f["severity"], f["id"], f["title"],
                 f["confidence"]) for f in findings]
        parts.append(
            '<h2>Security findings</h2>'
            '<input class="filter" type="search" '
            'placeholder="Filter findings…" '
            'oninput="filterTable(this)">'
            + table(["Severity", "ID", "Title", "Confidence"],
                    rows))
    asset_list = assets.get("assets") or []
    if asset_list:
        largest = sorted(asset_list,
                         key=lambda a: -a["size_bytes"])[:50]
        rows = [(a["category"], a["type"], a["size_bytes"],
                 a["path"]) for a in largest]
        parts.append(
            '<h2>Assets (50 largest)</h2>'
            '<input class="filter" type="search" '
            'placeholder="Filter assets…" '
            'oninput="filterTable(this)">'
            + table(["Category", "Type", "Bytes", "Path"], rows))
    entries = exec_log.get("entries") or []
    if entries:
        rows = [(e["stage"], e["status"], e.get("duration_s"))
                for e in entries]
        parts.append("<h2>Execution log</h2>" + table(
            ["Stage", "Status", "Seconds"], rows))
    limitations = report.get("limitations") or []
    if limitations:
        items = "".join(f"<li>{esc(x)}</li>" for x in limitations)
        parts.append(f"<h2>Limitations and unknowns</h2>"
                     f"<ul>{items}</ul>")
    body = "\n".join(parts)
    return TEMPLATE.replace("<!--BODY-->", body).replace(
        "<!--TITLE-->",
        esc(identity.get("package") or
            os.path.basename(case_dir)))


TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NAR case — <!--TITLE--></title>
<style>
:root{--bg:#ffffff;--fg:#1a1d21;--mut:#5b6470;--card:#f4f6f8;
--line:#d8dde3;--acc:#0e7c86}
@media (prefers-color-scheme:dark){:root{--bg:#12151a;--fg:#e8ecf1;
--mut:#9aa7b4;--card:#1a1f27;--line:#2c3542;--acc:#39c2d7}}
html[data-theme="light"]{--bg:#ffffff;--fg:#1a1d21;--mut:#5b6470;
--card:#f4f6f8;--line:#d8dde3;--acc:#0e7c86}
html[data-theme="dark"]{--bg:#12151a;--fg:#e8ecf1;--mut:#9aa7b4;
--card:#1a1f27;--line:#2c3542;--acc:#39c2d7}
body{background:var(--bg);color:var(--fg);margin:0;
font:15px/1.55 system-ui,sans-serif}
main{max-width:1080px;margin:0 auto;padding:24px 18px 64px}
h1{font-size:22px}h2{font-size:17px;margin-top:34px;
border-bottom:2px solid var(--acc);padding-bottom:4px}
table{border-collapse:collapse;width:100%;margin:10px 0;
font-size:13px}th,td{border:1px solid var(--line);
padding:5px 8px;text-align:left;vertical-align:top}
th{background:var(--card)}code{font-size:12px;word-break:break-all}
.filter{width:100%;box-sizing:border-box;padding:8px;margin:6px 0;
background:var(--card);color:var(--fg);
border:1px solid var(--line);border-radius:6px}
button{background:var(--card);color:var(--fg);
border:1px solid var(--line);border-radius:6px;
padding:6px 12px;cursor:pointer}
.sub{color:var(--mut)}
</style>
</head>
<body>
<main>
<h1>NAR 2.0 — NIROUS ANDROID INTELLIGENCE</h1>
<p class="sub">Case report · Research by Bakr Fayez ·
<button onclick="toggleTheme()">Toggle theme</button></p>
<!--BODY-->
</main>
<script>
function filterTable(input){
  var table=input.nextElementSibling; if(!table) return;
  var q=input.value.toLowerCase();
  table.querySelectorAll('tbody tr').forEach(function(tr){
    tr.style.display=tr.textContent.toLowerCase().includes(q)
      ? '' : 'none';});
}
function toggleTheme(){
  var h=document.documentElement;
  var cur=h.getAttribute('data-theme');
  var dark=window.matchMedia('(prefers-color-scheme: dark)').matches;
  h.setAttribute('data-theme',
    cur ? (cur==='dark' ? 'light' : 'dark')
        : (dark ? 'light' : 'dark'));
}
</script>
</body>
</html>
"""


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Render the offline HTML dashboard for a "
                    "nar-analyze case directory.")
    p.add_argument("case_dir", help="case directory with "
                                    "report.json")
    p.add_argument("--out", metavar="FILE",
                   help="output file (default CASE_DIR/report.html)")
    args = p.parse_args(argv)
    try:
        page = render(args.case_dir)
    except RuntimeError as e:
        print(f"nar-report: {e}", file=sys.stderr)
        return 2
    out = args.out or os.path.join(args.case_dir, "report.html")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(page)
    print(f"nar-report: wrote {out} ({len(page):,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
