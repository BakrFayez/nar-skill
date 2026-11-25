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
- Since 2.6.1, nar-unreal's package relationship records
  (classic + Zen, produced by the analyze engine deep
  dive) join as unreal_package / unreal_object nodes with
  unreal_* edges under the same discipline: resolved
  table references are direct evidence, unresolved ones
  stay explicitly unresolved.

The graph rebuilds from cached stage outputs: nar-analyze
re-runs only changed stages (its existing cache) and then
rebuilds this document from whatever stage documents are
current. There is deliberately no separate incremental
engine; the document records contributing_stages.

Part of NAR (Nirous Android Reversing). MIT License.
See LICENSE in the repo root.
"""

NODE_KINDS = (
    "application", "dex_file", "class", "native_library",
    "jni_function", "network_endpoint", "component",
    "permission", "engine", "security_finding", "asset",
    "network_library", "unreal_package", "unreal_object",
)

EDGE_KINDS = (
    "contains", "declares", "implements", "exports_jni",
    "binds_jni", "references_endpoint", "uses_library",
    "declares_component", "requests_permission",
    "detected_as", "finding_about", "depends_on",
    "references_class",
    "unreal_class", "unreal_super", "unreal_outer",
    "unreal_template", "unreal_depends",
)

# nar-unreal relationship kind -> graph edge kind (2.6.1:
# Unreal package relationships joined into the graph).
try:
    from . import formats_registry as _formats_registry
except Exception:  # registry unavailable: names pass through
    _formats_registry = None


def _canonical_engine_name(name):
    """Resolve an engine verdict name through formats.json
    (Part 16): a registry id or display name maps to the
    registry's canonical display name; an unknown name passes
    through unchanged (never dropped)."""
    if _formats_registry is None or not name:
        return name
    try:
        doc = _formats_registry.load_formats()
    except Exception:
        return name
    entry = (doc.get("engines") or {}).get(name)
    if entry:
        return entry.get("name") or name
    found = _formats_registry.engine_by_name(name, doc)
    return found["name"] if found else name


_UNREAL_EDGE_KINDS = {
    "class": "unreal_class", "super": "unreal_super",
    "outer": "unreal_outer", "template": "unreal_template",
    "depends": "unreal_depends",
}

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


# Cap on accumulated merge evidence (2.6.1): a node or
# edge merged from many sources keeps its first evidence
# in "evidence" and up to this many further distinct
# references in "evidence_also" — the list stays bounded.
# References past the cap ARE discarded, and the graph
# builder now counts them and records the count in its
# notes: the earlier "never silently discard" wording
# overstated the mechanism (stability audit C-12).
_EVIDENCE_ALSO_CAP = 8

_CONF_RANK = {"low": 0, "medium": 1, "high": 2}


def _add_also(record, ev):
    """Accumulate one merge-evidence reference. Returns
    True when the reference was kept (or was already
    present), False when the cap dropped it."""
    if ev == record["evidence"]:
        return True
    also = record.setdefault("evidence_also", [])
    if ev in also:
        return True
    if len(also) >= _EVIDENCE_ALSO_CAP:
        return False
    also.append(ev)
    return True


class _Graph:
    def __init__(self):
        self.nodes = {}
        self.edges = []
        self._edge_index = {}
        self.stages = set()
        self.provenance_dropped = 0

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
        else:
            existing = self.nodes[nid]
            if status and not existing.get("status"):
                existing["status"] = status
            if not _add_also(existing,
                             _ev(stage, document, field_path)):
                self.provenance_dropped += 1
        return nid

    def edge(self, source, target, kind, confidence, stage,
             document, field_path, status=None):
        key = (source, target, kind, status)
        if key in self._edge_index:
            record = self._edge_index[key]
            if not _add_also(record,
                             _ev(stage, document, field_path)):
                self.provenance_dropped += 1
            # A later, stronger source for the same edge
            # raises its confidence: first-writer-wins
            # understated the evidence behind merged
            # edges (stability audit C-12).
            new_conf = confidence or "low"
            if _CONF_RANK.get(new_conf, 0) > _CONF_RANK.get(
                    record["confidence"], 0):
                record["confidence"] = new_conf
            return
        self.stages.add(stage)
        record = {
            "source": source, "target": target, "kind": kind,
            "confidence": confidence or "low",
            "status": status,
            "provenance": {"stage": stage,
                           "field_path": field_path},
            "evidence": _ev(stage, document, field_path),
        }
        self._edge_index[key] = record
        self.edges.append(record)


def _unreal_object_node(g, pkg_entry, side, index, label,
                        field_path, status=None):
    """One Unreal object node (an export, import, or Zen
    object-index target inside one package)."""
    if index is not None:
        key = f"{pkg_entry}#{side}:{index}"
    else:
        key = f"{pkg_entry}#{side}:{label}"
    return g.node("unreal_object", key, label, "unreal",
                  "report.json", field_path, status=status)


def _unreal_section(g, app_id, unreal_data, notes):
    """Unreal package relationships (2.6.1): nar-unreal's
    table-derived classic + Zen relationship records,
    joined from the analyze report's engine sections.
    unreal_data is a list of {"field_path", "record"}
    items, one per inspected package; the record is the
    nar-unreal package summary (itself possibly trimmed
    by nar-analyze for the report companion).

    Confidence follows the graph discipline: a reference
    the package tables resolve to a named object is
    direct evidence ("high"); a Zen cross-package
    resolution text is the parser's own resolution
    ("medium"); a reference the tables could not resolve
    (index outside the map, no resolution text) is kept
    as an explicitly "unresolved" node with a "low"
    confidence edge — present, never upgraded, never
    dropped. Capped relationship lists record their cap
    in the graph notes, mirroring nar-unreal's own
    accounting."""
    for item in unreal_data or []:
        record = item.get("record") or {}
        base_path = item.get("field_path") or "engines"
        entry = record.get("entry") or record.get("name")
        rel = record.get("relationships")
        if not entry or not isinstance(rel, dict):
            continue
        pid = g.node("unreal_package", entry, entry,
                     "unreal", "report.json", base_path)
        if app_id:
            g.edge(app_id, pid, "contains", "high",
                   "unreal", "report.json", base_path)
        exports_by_index = {}
        for exp in record.get("exports") or []:
            if isinstance(exp, dict) \
                    and exp.get("index") is not None:
                exports_by_index[exp["index"]] = \
                    exp.get("object_name")
        counts = rel.get("counts") or {}
        if counts.get("skipped"):
            notes.append(
                f"unreal package {entry}: relationship "
                f"detail capped by nar-unreal "
                f"({counts.get('processed')} of "
                f"{counts.get('total')} edges joined into "
                "the graph; counts in nar-unreal's own "
                "record are complete)")
        for j, edge in enumerate(rel.get("edges") or []):
            kind = _UNREAL_EDGE_KINDS.get(edge.get("kind"))
            if kind is None:
                continue
            src = edge.get("from") or {}
            dst = edge.get("to") or {}
            epath = f"{base_path}.relationships.edges[{j}]"
            src_label = src.get("object_name") or \
                f"export {src.get('index')}"
            sid = _unreal_object_node(
                g, entry, "export", src.get("index"),
                src_label, epath)
            dst_kind = dst.get("kind")
            if dst_kind == "export":
                label = dst.get("object_name") or \
                    exports_by_index.get(dst.get("index")) or \
                    f"export {dst.get('index')}"
                status = None
                conf = "high"
                if dst.get("note"):
                    status, conf = "unresolved", "low"
                tid = _unreal_object_node(
                    g, entry, "export", dst.get("index"),
                    label, epath, status=status)
            elif dst_kind == "import":
                label = dst.get("object_name") or \
                    f"import {dst.get('index')}"
                status = None
                conf = "high"
                if dst.get("note") or \
                        not dst.get("object_name"):
                    status, conf = "unresolved", "low"
                tid = _unreal_object_node(
                    g, entry, "import", dst.get("index"),
                    label, epath, status=status)
            elif dst_kind in ("script-import",
                              "package-import"):
                resolved = dst.get("resolved")
                if resolved:
                    tid = _unreal_object_node(
                        g, entry, dst_kind, None, resolved,
                        epath)
                    conf = "medium"
                else:
                    tid = _unreal_object_node(
                        g, entry, dst_kind, None,
                        f"unresolved {dst_kind} (from "
                        f"export {src.get('index')}, "
                        f"{edge.get('kind')})",
                        epath, status="unresolved")
                    conf = "low"
            else:
                continue
            g.edge(sid, tid, kind, conf, "unreal",
                   "report.json", epath)


def build_graph(dex_data=None, native_data=None,
                perms_data=None, network_data=None,
                fingerprint_data=None, engines_data=None,
                security_data=None, assets_data=None,
                correlations_data=None, unreal_data=None,
                version="3.0.0"):
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
    # The node's evidence cites the document the package
    # actually came from (2.6.1 deep-audit remediation:
    # previously the node cited fingerprint.json even when
    # the fingerprint stage was absent or the package came
    # from the permissions data — a reference to evidence
    # that does not exist in the case). The generic anchor
    # node's provenance is the graph builder itself.
    app_id = None
    pkg = None
    pkg_ev = None
    if fingerprint_data:
        props = fingerprint_data.get("properties") or {}
        entry = props.get("package") or {}
        if isinstance(entry, dict):
            pkg = entry.get("value")
        if pkg:
            pkg_ev = ("fingerprint", "fingerprint.json",
                      "properties.package")
    if not pkg and perms_data:
        pkg = perms_data.get("package")
        if pkg:
            pkg_ev = ("permissions", "permissions.json",
                      "package")
    if pkg:
        app_id = g.node("application", pkg, pkg, *pkg_ev)
    else:
        # A generic application node still anchors
        # containment edges when the package is unknown.
        app_id = g.node(
            "application", "application", "application",
            "graph", "graph.json", "nodes",
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
            ename = _canonical_engine_name(verdict.get("engine"))
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

    # --- Unreal package relationships (2.6.1) ------------
    if unreal_data:
        _unreal_section(g, app_id, unreal_data, notes)

    if g.provenance_dropped:
        notes.append(
            f"{g.provenance_dropped} merge-evidence "
            "reference(s) exceeded the per-record "
            f"evidence_also cap ({_EVIDENCE_ALSO_CAP}) and "
            "were not retained; the retained references "
            "are in the records' evidence/evidence_also "
            "fields")
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
            if min_confidence.lower() not in order:
                # A misspelled level used to map to floor
                # 0 and silently return the unfiltered
                # graph (stability audit C-18).
                raise ValueError(
                    f"unknown confidence level "
                    f"{min_confidence!r} (expected low, "
                    "medium or high)")
            floor = order[min_confidence.lower()]
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
