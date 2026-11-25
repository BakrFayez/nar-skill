#!/usr/bin/env python3
"""nar-report.py: offline HTML dashboard for a NAR case.

Reads a case directory written by nar-analyze (report.json
plus whichever companion documents exist) and renders ONE
self-contained report.html: all data embedded, no external
requests, no CDN, no fonts to fetch. Dark and light themes
(follows the OS preference, with a manual toggle), section
navigation, and client-side search/filter for the endpoint,
findings, and asset tables. When native.json carries a
bundled-library dependency graph, the dashboard renders it
as an inline SVG (stdlib-generated, deterministic layered
layout, still zero external references). When the case
carries the Phase 7/8 companions, the dashboard also renders
a Unified graph section (graph.json node/edge counts by
kind, tabular) and an Investigation section
(investigation.json: verified facts, ranked paths,
hypotheses and unknowns in separate tables, each capped at
50 rows with the full data left in the companion file).
Sections are absent when their companion is missing.

Usage:
    python3 nar-report.py CASE_DIR [--out FILE]

Part of NAR (Nirous Android Reversing).
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


def _doc(path):
    """A companion document as a dict: a missing,
    unparsable or non-object companion renders as an
    absent section, never a crashed report (C-11)."""
    doc = load_json(path)
    return doc if isinstance(doc, dict) else {}


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


MAX_GRAPH_NODES = 120
_NODE_H = 22
_ROW_PITCH = 38
_LAYER_GAP = 72
_PAD = 16


def dep_graph_svg(graph):
    """Render a bundled-library dependency graph (the
    dependency_graph map of native.json: display name ->
    sorted bundled dependencies) as one inline SVG string.

    Deterministic layered layout: a node's layer is the
    longest dependency chain reaching it (relaxation is
    bounded, so cyclic graphs still terminate and render).
    All labels are HTML-escaped; the SVG references nothing
    external. Returns (svg, truncated) where truncated says
    the graph exceeded MAX_GRAPH_NODES and only the first
    nodes (sorted order) are drawn.
    """
    nodes = sorted({*graph.keys(),
                    *(d for deps in graph.values() for d in deps)})
    truncated = len(nodes) > MAX_GRAPH_NODES
    if truncated:
        keep = set(nodes[:MAX_GRAPH_NODES])
        nodes = nodes[:MAX_GRAPH_NODES]
        edges = [(s, d) for s in nodes for d in graph.get(s, [])
                 if d in keep]
    else:
        edges = [(s, d) for s, deps in graph.items() for d in deps]
    layer = {n: 0 for n in nodes}
    for _ in range(len(nodes)):
        changed = False
        for src, dst in edges:
            if layer[dst] < layer[src] + 1:
                layer[dst] = layer[src] + 1
                changed = True
        if not changed:
            break
    by_layer = {}
    for n in nodes:
        by_layer.setdefault(layer[n], []).append(n)
    pos = {}
    x = _PAD
    width = _PAD
    for lv in sorted(by_layer):
        members = sorted(by_layer[lv])
        w = max(84, max(int(len(n) * 7.0) + 18 for n in members))
        for i, n in enumerate(members):
            pos[n] = (x, _PAD + i * _ROW_PITCH, w)
        width = x + w + _PAD
        x += w + _LAYER_GAP
    rows = max((len(v) for v in by_layer.values()), default=0)
    height = _PAD * 2 + max(rows - 1, 0) * _ROW_PITCH + _NODE_H
    out = [f'<svg viewBox="0 0 {width} {height}" width="100%" '
           f'role="img" aria-label="Native dependency graph" '
           f'style="max-width:{width}px">',
           "<defs><marker id=\"nar-arr\" viewBox=\"0 0 8 8\" "
           "refX=\"7\" refY=\"4\" markerWidth=\"6\" "
           "markerHeight=\"6\" orient=\"auto\">"
           "<path d=\"M0,0 L8,4 L0,8 z\" fill=\"var(--acc)\"/>"
           "</marker></defs>"]
    for src, dst in edges:
        sx, sy, sw = pos[src]
        dx, dy, _dw = pos[dst]
        out.append(
            f'<line x1="{sx + sw}" y1="{sy + _NODE_H // 2}" '
            f'x2="{dx - 2}" y2="{dy + _NODE_H // 2}" '
            f'stroke="var(--acc)" stroke-opacity="0.55" '
            f'stroke-width="1.2" marker-end="url(#nar-arr)"/>')
    for n in nodes:
        nx, ny, nw = pos[n]
        out.append(
            f'<g><rect x="{nx}" y="{ny}" width="{nw}" '
            f'height="{_NODE_H}" rx="5" fill="var(--card)" '
            f'stroke="var(--line)"/>'
            f'<text x="{nx + 9}" y="{ny + 15}" font-size="11.5" '
            f'fill="var(--fg)">{esc(n)}</text></g>')
    out.append("</svg>")
    return "".join(out), truncated


def render(case_dir):
    report = load_json(os.path.join(case_dir, "report.json"))
    if report is None:
        raise RuntimeError(f"no readable report.json in {case_dir}")
    fingerprint = _doc(os.path.join(case_dir,
                                         "fingerprint.json")) or {}
    engines = _doc(os.path.join(case_dir, "engines.json")) or {}
    endpoints = _doc(os.path.join(case_dir,
                                       "endpoints.json")) or {}
    security = _doc(os.path.join(case_dir,
                                      "security-findings.json")) or {}
    assets = _doc(os.path.join(case_dir, "assets.json")) or {}
    native = _doc(os.path.join(case_dir, "native.json")) or {}
    exec_log = _doc(os.path.join(case_dir,
                                      "execution-log.json")) or {}
    graph_doc = _doc(os.path.join(case_dir,
                                       "graph.json")) or {}
    investigation = _doc(os.path.join(
        case_dir, "investigation.json")) or {}
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
        rows = [(v.get("engine"), "detected" if v.get("detected")
                 else "weak", v.get("confidence"), v.get("score"),
                 v.get("version") or "")
                for v in verdicts if isinstance(v, dict)]
        parts.append("<h2>Engines</h2>" + table(
            ["Engine", "State", "Confidence", "Score", "Version"],
            rows))
    graph = native.get("dependency_graph") or {}
    if graph:
        svg, truncated = dep_graph_svg(graph)
        n_nodes = len({*graph.keys(),
                       *(d for deps in graph.values() for d in deps)})
        n_edges = sum(len(deps) for deps in graph.values())
        note = (f" — first {MAX_GRAPH_NODES} libraries drawn; "
                f"the full graph is in native.json"
                if truncated else "")
        parts.append(
            "<h2>Native dependency graph</h2>"
            f'<p class="sub">{n_nodes} libraries, {n_edges} '
            f"bundled-to-bundled dependencies (from native.json)"
            f"{esc(note)}</p>" + svg)
    eps = endpoints.get("endpoints") or []
    if eps:
        rows = [(e.get("classification"), e.get("kind"),
                 (e.get("url") or "")[:140])
                for e in eps if isinstance(e, dict)]
        parts.append(
            '<h2>Network endpoints</h2>'
            '<input class="filter" type="search" '
            'placeholder="Filter endpoints…" '
            'oninput="filterTable(this)">'
            + table(["Class", "Kind", "URL"], rows))
    findings = security.get("findings") or []
    if findings:
        rows = [(f.get("severity"), f.get("id"), f.get("title"),
                 f.get("confidence"))
                for f in findings if isinstance(f, dict)]
        parts.append(
            '<h2>Security findings</h2>'
            '<input class="filter" type="search" '
            'placeholder="Filter findings…" '
            'oninput="filterTable(this)">'
            + table(["Severity", "ID", "Title", "Confidence"],
                    rows))
    asset_list = assets.get("assets") or []
    if asset_list:
        largest = sorted(
            (a for a in asset_list if isinstance(a, dict)),
            key=lambda a: -(a.get("size_bytes") or 0))[:50]
        rows = [(a.get("category"), a.get("type"),
                 a.get("size_bytes"), a.get("path"))
                for a in largest]
        parts.append(
            '<h2>Assets (50 largest)</h2>'
            '<input class="filter" type="search" '
            'placeholder="Filter assets…" '
            'oninput="filterTable(this)">'
            + table(["Category", "Type", "Bytes", "Path"], rows))
    g_counts = graph_doc.get("counts") or {}
    g_nodes = graph_doc.get("nodes") or []
    g_edges = graph_doc.get("edges") or []
    if g_nodes or g_edges:
        by_kind = g_counts.get("nodes_by_kind") or {}
        if not by_kind:
            for n in g_nodes:
                if isinstance(n, dict):
                    by_kind[n.get("kind")] = \
                        by_kind.get(n.get("kind"), 0) + 1
        e_by_kind = g_counts.get("edges_by_kind") or {}
        if not e_by_kind:
            for e in g_edges:
                if isinstance(e, dict):
                    e_by_kind[e.get("kind")] = \
                        e_by_kind.get(e.get("kind"), 0) + 1
        n_nodes = g_counts.get("nodes", len(g_nodes))
        n_edges = g_counts.get("edges", len(g_edges))
        rows = [(k, by_kind.get(k, 0), e_by_kind.get(k, 0))
                for k in sorted(set(by_kind) | set(e_by_kind),
                                key=str)]
        stages = ", ".join(
            graph_doc.get("contributing_stages") or [])
        parts.append(
            "<h2>Unified graph</h2>"
            f'<p class="sub">{esc(n_nodes)} nodes, '
            f"{esc(n_edges)} edges (from graph.json"
            f"{'; stages: ' + esc(stages) if stages else ''})"
            "</p>" + table(
                ["Kind", "Nodes", "Edges"], rows))
    inv_counts = investigation.get("counts") or {}
    facts = investigation.get("verified_facts") or []
    # 2.6.1: unverified findings render in their own
    # table, never among the verified facts. Cases from
    # before the separation lack the key entirely and
    # render exactly as they did (tolerant .get).
    unverified = investigation.get("unverified_findings") or []
    inv_paths = investigation.get("paths") or []
    hyps = investigation.get("hypotheses") or []
    unknowns = investigation.get("unknowns") or []
    if facts or unverified or inv_paths or hyps or unknowns:
        parts.append(
            "<h2>Investigation</h2>"
            f'<p class="sub">{esc(inv_counts.get("verified_facts", len(facts)))} '
            f"verified facts · "
            f"{esc(inv_counts.get('unverified_findings', len(unverified)))} "
            f"unverified findings · "
            f"{esc(inv_counts.get('paths', len(inv_paths)))} "
            f"ranked paths · "
            f"{esc(inv_counts.get('hypotheses', len(hyps)))} "
            f"hypotheses · "
            f"{esc(inv_counts.get('unknowns', len(unknowns)))} "
            "unknowns (from investigation.json; facts, "
            "recommendations, hypotheses and unknowns are "
            "kept in separate tables)</p>")
        if facts:
            rows = [(f.get("fact"), f.get("kind"),
                     f.get("subject"),
                     f.get("verification_status"))
                    for f in facts[:50]]
            note = (" — first 50 shown; the full list is in "
                    "investigation.json" if len(facts) > 50
                    else "")
            parts.append(
                f"<h3>Verified facts{esc(note)}</h3>" + table(
                    ["Fact", "Kind", "Subject", "Verification"],
                    rows))
        if unverified:
            rows = [(f.get("fact"), f.get("kind"),
                     f.get("subject"),
                     f.get("verification_status"))
                    for f in unverified[:50]]
            note = (" — first 50 shown; the full list is in "
                    "investigation.json" if len(unverified) > 50
                    else "")
            parts.append(
                f"<h3>Unverified findings (reported, not "
                f"verified){esc(note)}</h3>" + table(
                    ["Finding", "Kind", "Subject",
                     "Verification"], rows))
        if inv_paths:
            rows = [(p.get("rank"), p.get("rule_id"),
                     p.get("priority"),
                     p.get("recommendation"), p.get("subject"),
                     p.get("confidence"))
                    for p in inv_paths[:50]]
            note = (" — first 50 shown; the full list is in "
                    "investigation.json" if len(inv_paths) > 50
                    else "")
            parts.append(
                f"<h3>Ranked paths{esc(note)}</h3>" + table(
                    ["Rank", "Rule", "Priority",
                     "Recommendation", "Subject", "Confidence"],
                    rows))
        if hyps:
            rows = [(h.get("statement"), h.get("subject"),
                     h.get("confirm"), h.get("refute"))
                    for h in hyps[:50]]
            note = (" — first 50 shown; the full list is in "
                    "investigation.json" if len(hyps) > 50
                    else "")
            parts.append(
                f"<h3>Hypotheses (unverified){esc(note)}</h3>"
                + table(["Hypothesis", "Subject",
                         "Would confirm", "Would refute"], rows))
        if unknowns:
            rows = [(u.get("question"), u.get("reason"))
                    for u in unknowns[:50]]
            note = (" — first 50 shown; the full list is in "
                    "investigation.json" if len(unknowns) > 50
                    else "")
            parts.append(
                f"<h3>Unknowns{esc(note)}</h3>" + table(
                    ["Question", "Why static data cannot "
                     "answer it"], rows))
    entries = exec_log.get("entries") or []
    if entries:
        rows = [(e.get("stage"), e.get("status"),
                 e.get("duration_s"))
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
<p class="sub">Case report ·
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
