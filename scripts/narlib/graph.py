"""narlib.graph: unified application intelligence graph
(2.6.0 Phase 7, R-008).

Builds graph.json, a case companion, from the stage
documents nar-analyze already produced and from the
correlations document built over them. Correlations stay
the flat join lists they have always been; the graph is
an ADDITIVE companion that re-expresses those joins —
plus the containment relations the stage inventories
directly support — as nodes and edges.

Rules:
- Only relationships the underlying stage data supports
  become edges. A one-sided join (declaration-only,
  export-only, implementation-only, no-code-reference,
  library-only) becomes an edge / node with that explicit
  status, never silently dropped and never upgraded.
- Every node and edge carries provenance (producing stage
  + field path) and an evidence reference in the same
  {stage, document, field_path} shape used across the
  investigation layer.
- Confidence is a string level copied or derived only
  from the source verification_status / detection
  confidence; no new confidence is invented.

The graph rebuilds from cached stage outputs: nar-analyze
re-runs only changed stages (its existing cache) and then
rebuilds this document from whatever stage documents are
current. There is deliberately no separate incremental
engine; the document records contributing_stages.

Part of NAR (Nirous Android Reversing). Research by Bakr
Fayez. MIT License. See LICENSE in the repo root.
"""

NODE_KINDS = (
    "application", "dex_file", "class", "native_library",
    "jni_function", "network_endpoint", "component",
    "permission", "engine", "security_finding", "asset",
    "network_library",
)

EDGE_KINDS = (
    "contains", "declares", "implements", "exports_jni",
    "binds_jni", "references_endpoint", "uses_library",
    "declares_component", "requests_permission",
    "detected_as", "finding_about", "depends_on",
    "references_class",
)

# verification_status -> graph confidence label
_CONF = {
    "CONFIRMED": "high",
    "STRONGLY_INDICATED": "medium",
    "POTENTIAL": "low",
    "UNVERIFIED": "low",
    "CONTRADICTED": "low",
}


def _ev(stage, document, field_path):
    return {"stage": stage, "document": document,
            "field_path": field_path}


def _dotted(descriptor):
    d = descriptor or ""
    if d.startswith("L") and d.endswith(";"):
        d = d[1:-1]
    return d.replace("/", ".")


class _Graph:
    def __init__(self):
        self.nodes = {}
        self.edges = []
        self._edge_keys = set()
        self.stages = set()

    def node(self, kind, key, label, stage, document,
             field_path, status=None):
        nid = f"{kind}:{key}"
        self.stages.add(stage)
        if nid not in self.nodes:
            self.nodes[nid] = {
                "id": nid, "kind": kind, "label": label,
                "source_stage": stage,
                "evidence": _ev(stage, document, field_path),
                "status": status,
            }
        elif status and not self.nodes[nid].get("status"):
            self.nodes[nid]["status"] = status
        return nid

    def edge(self, source, target, kind, confidence, stage,
             document, field_path, status=None):
        key = (source, target, kind, status)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self.stages.add(stage)
        self.edges.append({
            "source": source, "target": target, "kind": kind,
            "confidence": confidence or "low",
            "status": status,
            "provenance": {"stage": stage,
                           "field_path": field_path},
            "evidence": _ev(stage, document, field_path),
        })


def build_graph(dex_data=None, native_data=None,
                perms_data=None, network_data=None,
                fingerprint_data=None, engines_data=None,
                security_data=None, assets_data=None,
                correlations_data=None, version="2.6.0"):
    """Build the graph document. Any input may be None (a
    degraded stage): its nodes/edges are then absent and a
    note records the gap, mirroring correlations."""
    g = _Graph()
    notes = []
    for label, data in (
            ("dex", dex_data), ("native", native_data),
            ("permissions", perms_data),
            ("network", network_data),
            ("fingerprint", fingerprint_data),
            ("engines", engines_data),
            ("security", security_data),
            ("assets", assets_data),
            ("correlations", correlations_data)):
        if data is None:
            notes.append(
                f"{label} stage data unavailable; its graph "
                "nodes/edges are absent, not fabricated")

    # --- application node ---------------------------------
    app_id = None
    pkg = None
    if fingerprint_data:
        props = fingerprint_data.get("properties") or {}
        entry = props.get("package") or {}
        if isinstance(entry, dict):
            pkg = entry.get("value")
    if not pkg and perms_data:
        pkg = perms_data.get("package")
    if pkg:
        app_id = g.node(
            "application", pkg, pkg, "fingerprint",
            "fingerprint.json", "properties.package")
    else:
        # A generic application node still anchors
        # containment edges when the package is unknown.
        app_id = g.node(
            "application", "application", "application",
            "fingerprint", "fingerprint.json", "properties",
            status="unidentified")

    # --- permissions --------------------------------------
    perm_ids = {}
    if perms_data:
        for i, perm in enumerate(
                perms_data.get("permissions") or []):
            name = perm.get("name") if isinstance(perm, dict) \
                else None
            if not name:
                continue
            pid = g.node(
                "permission", name, name, "permissions",
                "permissions.json",
                f"permissions[{i}].name")
            perm_ids[name] = pid
            if app_id:
                g.edge(app_id, pid, "requests_permission",
                       "high", "permissions",
                       "permissions.json",
                       f"permissions[{i}]")

    # --- components (from perms, richer than corr.) -------
    comp_ids = {}
    comp_meta = {}  # name -> (exported, permission)
    if perms_data:
        for kind, items in (
                (perms_data.get("components") or {}).items()):
            for i, item in enumerate(items or []):
                name = item.get("name")
                if not name:
                    continue
                cid = g.node(
                    "component", name, name, "permissions",
                    "permissions.json",
                    f"components.{kind}[{i}].name")
                comp_ids[name] = cid
                comp_meta[name] = (
                    item.get("exported"),
                    item.get("permission"))
                if app_id:
                    g.edge(app_id, cid, "declares_component",
                           "high", "permissions",
                           "permissions.json",
                           f"components.{kind}[{i}]")
                pname = item.get("permission")
                if pname:
                    pid = perm_ids.get(pname) or g.node(
                        "permission", pname, pname,
                        "permissions", "permissions.json",
                        f"components.{kind}[{i}].permission")
                    perm_ids[pname] = pid
                    g.edge(cid, pid, "requests_permission",
                           "high", "permissions",
                           "permissions.json",
                           f"components.{kind}[{i}].permission")

    # --- DEX files and classes ----------------------------
    dex_ids = {}
    class_ids = {}
    if dex_data:
        for di, dex in enumerate(
                dex_data.get("dex_files") or []):
            dname = dex.get("name")
            if not dname:
                continue
            did = g.node(
                "dex_file", dname, dname, "dex", "dex.json",
                f"dex_files[{di}].name")
            dex_ids[dname] = did
            if app_id:
                g.edge(app_id, did, "contains", "high", "dex",
                       "dex.json", f"dex_files[{di}]")
            for ci, cls in enumerate(dex.get("classes") or []):
                cname = cls.get("class") if isinstance(
                    cls, dict) else cls
                if not cname:
                    continue
                dotted = _dotted(cname)
                cid = g.node(
                    "class", dotted, dotted, "dex", "dex.json",
                    f"dex_files[{di}].classes[{ci}].class")
                # class node may already exist via another
                # dex; containment edge is per-dex anyway
                class_ids[dotted] = cid
                g.edge(did, cid, "contains", "high", "dex",
                       "dex.json",
                       f"dex_files[{di}].classes[{ci}]")

    # --- native libraries ---------------------------------
    lib_ids = {}
    if native_data:
        for li, lib in enumerate(
                native_data.get("libraries") or []):
            lname = lib.get("display_name") or lib.get("name")
            if not lname:
                continue
            lid = g.node(
                "native_library", lname, lname, "native",
                "native.json", f"libraries[{li}]",
                status=("error" if "error" in lib else None))
            lib_ids[lname] = lid
            # also index by bare soname/name for dep graph
            bare = lib.get("name")
            if bare:
                lib_ids.setdefault(bare, lid)
                lib_ids.setdefault(
                    bare.rsplit("/", 1)[-1], lid)
            if app_id:
                g.edge(app_id, lid, "contains", "high",
                       "native", "native.json",
                       f"libraries[{li}]")
        for src, deps in (
                (native_data.get("dependency_graph")
                 or {}).items()):
            sid = lib_ids.get(src)
            if not sid:
                sid = g.node(
                    "native_library", src, src, "native",
                    "native.json", "dependency_graph")
                lib_ids[src] = sid
            for dep in deps or []:
                tid = lib_ids.get(dep)
                if not tid:
                    tid = g.node(
                        "native_library", dep, dep, "native",
                        "native.json", "dependency_graph",
                        status="external")
                    lib_ids[dep] = tid
                g.edge(sid, tid, "depends_on", "high",
                       "native", "native.json",
                       "dependency_graph")

    # --- engines / frameworks -----------------------------
    if engines_data:
        for vi, verdict in enumerate(
                engines_data.get("verdicts") or []):
            if not verdict.get("detected"):
                continue
            ename = verdict.get("engine")
            if not ename:
                continue
            eid = g.node(
                "engine", ename, ename, "engines",
                "engines.json", f"verdicts[{vi}].engine")
            if app_id:
                g.edge(app_id, eid, "detected_as",
                       verdict.get("confidence") or "low",
                       "engines", "engines.json",
                       f"verdicts[{vi}]")

    # --- network endpoints --------------------------------
    ep_ids = {}
    if network_data:
        for ei, ep in enumerate(
                network_data.get("endpoints") or []):
            url = ep.get("url")
            if not url or url in ep_ids:
                continue
            eid = g.node(
                "network_endpoint", url, url, "network",
                "endpoints.json", f"endpoints[{ei}].url")
            ep_ids[url] = eid
            if app_id:
                g.edge(app_id, eid, "contains", "medium",
                       "network", "endpoints.json",
                       f"endpoints[{ei}]")

    # --- assets / containers ------------------------------
    if assets_data:
        for ai, asset in enumerate(
                assets_data.get("assets") or []):
            path = asset.get("path") if isinstance(
                asset, dict) else None
            if not path:
                continue
            aid = g.node(
                "asset", path, path, "assets", "assets.json",
                f"assets[{ai}].path")
            if app_id:
                g.edge(app_id, aid, "contains", "high",
                       "assets", "assets.json", f"assets[{ai}]")

    # --- security findings --------------------------------
    if security_data:
        for fi, finding in enumerate(
                security_data.get("findings") or []):
            fid_key = finding.get("id") or f"finding-{fi}"
            label = finding.get("title") or fid_key
            fid = g.node(
                "security_finding", fid_key, label, "security",
                "security-findings.json", f"findings[{fi}].id")
            target_name = finding.get("affected_component")
            # Link only to a component/class that already
            # exists in the graph; otherwise anchor to the
            # application node. Never invent a target node
            # from a free-text component field.
            target = comp_ids.get(target_name) or \
                class_ids.get(target_name) or app_id
            if target:
                g.edge(fid, target, "finding_about",
                       finding.get("confidence") or "low",
                       "security", "security-findings.json",
                       f"findings[{fi}]")

    # --- correlations: the explicit joins -----------------
    if correlations_data:
        for ji, entry in enumerate(
                correlations_data.get("jni_bindings") or []):
            symbol = entry.get("symbol")
            if not symbol:
                continue
            jid = g.node(
                "jni_function", symbol, symbol, "correlations",
                "correlations.json",
                f"jni_bindings[{ji}].symbol",
                status=entry.get("status"))
            conf = _CONF.get(
                entry.get("verification_status"), "low")
            status = entry.get("status")
            cls = entry.get("class")
            if cls:
                cid = class_ids.get(cls)
                if not cid:
                    cid = g.node(
                        "class", cls, cls, "correlations",
                        "correlations.json",
                        f"jni_bindings[{ji}].class",
                        status="unmatched")
                    class_ids[cls] = cid
                g.edge(cid, jid, "declares", conf,
                       "correlations", "correlations.json",
                       f"jni_bindings[{ji}]", status=status)
            for lib_name in entry.get("libraries") or []:
                lid = lib_ids.get(lib_name) or lib_ids.get(
                    lib_name.rsplit("/", 1)[-1])
                if not lid:
                    lid = g.node(
                        "native_library", lib_name, lib_name,
                        "correlations", "correlations.json",
                        f"jni_bindings[{ji}].libraries",
                        status="unmatched")
                    lib_ids[lib_name] = lid
                g.edge(lid, jid, "exports_jni", conf,
                       "correlations", "correlations.json",
                       f"jni_bindings[{ji}]", status=status)
            if status in ("declaration-only", "export-only") \
                    and not cls and not entry.get("libraries"):
                # node alone carries the one-sided status
                pass
        for ci, entry in enumerate(
                correlations_data.get("components") or []):
            name = entry.get("component")
            if not name:
                continue
            status = entry.get("status")
            cid = comp_ids.get(name)
            if not cid:
                cid = g.node(
                    "component", name, name, "correlations",
                    "correlations.json",
                    f"components[{ci}].component",
                    status=status)
                comp_ids[name] = cid
            conf = _CONF.get(
                entry.get("verification_status"), "low")
            if status == "matched":
                # implementation class node shares the
                # dotted name
                cls_id = class_ids.get(name)
                if not cls_id:
                    cls_id = g.node(
                        "class", name, name, "correlations",
                        "correlations.json",
                        f"components[{ci}].component")
                    class_ids[name] = cls_id
                g.edge(cls_id, cid, "implements", conf,
                       "correlations", "correlations.json",
                       f"components[{ci}]", status=status)
            elif app_id:
                # declaration-only / implementation-only:
                # keep an explicit edge from the app with
                # the one-sided status, never dropped.
                g.edge(app_id, cid, "declares_component", conf,
                       "correlations", "correlations.json",
                       f"components[{ci}]", status=status)
        for ei, entry in enumerate(
                correlations_data.get("endpoints") or []):
            url = entry.get("url")
            if not url:
                continue
            eid = ep_ids.get(url)
            if not eid:
                eid = g.node(
                    "network_endpoint", url, url,
                    "correlations", "correlations.json",
                    f"endpoints[{ei}].url",
                    status=entry.get("status"))
                ep_ids[url] = eid
            conf = _CONF.get(
                entry.get("verification_status"), "low")
            for cls in entry.get("referencing_classes") or []:
                cid = class_ids.get(cls)
                if not cid:
                    cid = g.node(
                        "class", cls, cls, "correlations",
                        "correlations.json",
                        f"endpoints[{ei}].referencing_classes",
                        status="unmatched")
                    class_ids[cls] = cid
                g.edge(cid, eid, "references_endpoint", conf,
                       "correlations", "correlations.json",
                       f"endpoints[{ei}]",
                       status=entry.get("status"))
            if entry.get("status") == "no-code-reference" \
                    and app_id:
                g.edge(app_id, eid, "references_endpoint",
                       conf, "correlations",
                       "correlations.json", f"endpoints[{ei}]",
                       status="no-code-reference")
        for li, entry in enumerate(
                correlations_data.get("network_libraries")
                or []):
            name = entry.get("library")
            if not name:
                continue
            nid = g.node(
                "network_library", name, name, "correlations",
                "correlations.json",
                f"network_libraries[{li}].library",
                status=entry.get("status"))
            conf = _CONF.get(
                entry.get("verification_status"), "low")
            if app_id:
                g.edge(app_id, nid, "uses_library", conf,
                       "correlations", "correlations.json",
                       f"network_libraries[{li}]",
                       status=entry.get("status"))

    nodes = [g.nodes[k] for k in sorted(g.nodes)]
    edges = sorted(
        g.edges,
        key=lambda e: (e["source"], e["target"], e["kind"],
                       e["status"] or ""))
    return {
        "tool": "nar-analyze", "version": version,
        "kind": "graph",
        "nodes": nodes, "edges": edges,
        "counts": {
            "nodes": len(nodes), "edges": len(edges),
            "nodes_by_kind": {
                k: sum(1 for n in nodes if n["kind"] == k)
                for k in sorted({n["kind"] for n in nodes})},
            "edges_by_kind": {
                k: sum(1 for e in edges if e["kind"] == k)
                for k in sorted({e["kind"] for e in edges})},
        },
        "contributing_stages": sorted(g.stages),
        "rebuild_note": (
            "graph.json is rebuilt by nar-analyze from the "
            "case's cached stage outputs on every run; only "
            "changed stages re-run (the existing stage "
            "cache), so the graph is incremental through "
            "that cache, not through a separate engine."),
        "notes": notes,
    }


def query_graph(graph_doc, kind=None, edge_kind=None,
                min_confidence=None, text=None):
    """Filter a graph document. Returns a new document with
    the filtered nodes/edges; an edge survives only when
    both endpoints survive the node filters."""
    order = {"low": 0, "medium": 1, "high": 2}
    nodes = list((graph_doc or {}).get("nodes") or [])
    if kind:
        nodes = [n for n in nodes if n.get("kind") == kind]
    if text:
        needle = text.lower()
        nodes = [n for n in nodes
                 if needle in (n.get("label") or "").lower()
                 or needle in (n.get("id") or "").lower()]
    keep = {n["id"] for n in nodes}
    edges = list((graph_doc or {}).get("edges") or [])
    # When no node filter is active, keep is every node.
    if not kind and not text:
        keep = {n["id"] for n in
                (graph_doc or {}).get("nodes") or []}
    edges = [e for e in edges
             if e.get("source") in keep
             and e.get("target") in keep]
    if edge_kind:
        edges = [e for e in edges if e.get("kind") == edge_kind]
    if min_confidence is not None:
        # Accept a level name or a numeric 0..1 threshold.
        if isinstance(min_confidence, str):
            floor = order.get(min_confidence.lower(), 0)
        else:
            floor = 2 if min_confidence > 0.66 else \
                1 if min_confidence > 0.33 else 0
        edges = [e for e in edges
                 if order.get(e.get("confidence"), 0) >= floor]
        keep = {e["source"] for e in edges} | \
            {e["target"] for e in edges}
        # Nodes with no surviving edge are dropped only
        # when an edge filter was applied.
        if edge_kind or min_confidence is not None:
            nodes = [n for n in nodes if n["id"] in keep]
    return {
        "tool": (graph_doc or {}).get("tool", "nar-analyze"),
        "version": (graph_doc or {}).get("version"),
        "kind": "graph",
        "nodes": nodes, "edges": edges,
        "counts": {"nodes": len(nodes), "edges": len(edges)},
        "query": {"kind": kind, "edge_kind": edge_kind,
                  "min_confidence": min_confidence,
                  "text": text},
    }
