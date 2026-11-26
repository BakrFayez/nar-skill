"""narlib.companions: the brief-named case companion
documents (Evolution Phase 2; network companions added in
Phase 5).

application.json, manifest.json, native-inventory.json and
frameworks.json are PROJECTIONS of data the analysis stages
already compute — no stage is re-run, nothing is re-derived,
and no value is invented to fill a gap. Fingerprint
properties keep their provenance envelope (value /
provenance / confidence / fact class). When a source stage
degraded, the projection says so in an "unavailable" field
instead of emitting an empty success document.

network-analysis.json and api-architecture.json (Phase 5)
project the network stage's endpoints document the same
way. Endpoint URLs reach the projection already redacted
by nar-network; the architecture projection additionally
drops query strings entirely, keeping paths only.

Part of NAR (Nirous Android Reversing). MIT License.
See LICENSE in the repo root.
"""
import urllib.parse

APPLICATION_KEYS = (
    "package", "app_label", "version_name", "version_code",
    "min_sdk", "target_sdk", "compile_sdk", "abis",
    "dex_count", "dex_versions", "native_library_count",
    "form_factors", "signing_schemes", "sha256", "size_bytes",
)


def _base(kind, version):
    return {"tool": "nar-analyze", "version": version,
            "kind": kind, "projected": True}


def project_application(fingerprint_doc, version):
    """application.json from the fingerprint document."""
    doc = _base("application", version)
    if not fingerprint_doc:
        doc["unavailable"] = "fingerprint stage produced no data"
        doc["properties"] = {}
        return doc
    props = fingerprint_doc.get("properties") or {}
    doc["source_sha256"] = fingerprint_doc.get("source_sha256")
    doc["properties"] = {k: props[k] for k in APPLICATION_KEYS
                         if k in props}
    doc["notes"] = list(fingerprint_doc.get("notes") or [])
    return doc


def project_manifest(permissions_summary, identity, version):
    """manifest.json from the permission-audit summary the
    orchestrator already computed (plus identity fallback)."""
    doc = _base("manifest", version)
    summary = permissions_summary or {}
    if "error" in summary or "skipped" in summary:
        doc["unavailable"] = (summary.get("error")
                              or summary.get("skipped"))
        return doc
    doc["package"] = (summary.get("package")
                      or (identity or {}).get("package"))
    for key in ("permission_count", "permissions_by_group",
                "dangerous_permissions", "component_counts",
                "exported_count", "debuggable", "allow_backup",
                "target_sdk", "is_split"):
        doc[key] = summary.get(key)
    return doc


def project_native_inventory(native_doc, version):
    """native-inventory.json from the nar-native document."""
    doc = _base("native-inventory", version)
    if not native_doc:
        doc["unavailable"] = "native stage produced no data"
        doc["libraries"] = []
        return doc
    libraries = []
    for lib in native_doc.get("libraries", []):
        if "error" in lib:
            libraries.append({"name": lib.get("name"),
                              "error": lib["error"]})
            continue
        libraries.append({
            "name": lib.get("display_name") or lib.get("name"),
            "elf_class": lib.get("elf_class"),
            "arch": lib.get("arch"),
            "soname": lib.get("soname"),
            "size_bytes": lib.get("size_bytes"),
            "needed": lib.get("needed") or [],
            "build_id": lib.get("build_id"),
            "jni_exports": lib.get("jni_exports") or [],
        })
    doc["libraries"] = libraries
    doc["library_count"] = len(libraries)
    doc["jni_libraries"] = sorted(
        (native_doc.get("jni_map") or {}).keys())
    doc["dependency_graph"] = native_doc.get(
        "dependency_graph") or {}
    return doc


def project_frameworks(engines_doc, fingerprint_doc, version):
    """frameworks.json from the engine-fusion verdicts plus
    the fingerprint's marker-level evidence."""
    doc = _base("frameworks", version)
    if not engines_doc:
        doc["unavailable"] = "engine stage produced no data"
        doc["verdicts"] = []
        return doc
    doc["verdicts"] = [
        {"engine": v.get("engine"), "detected": v.get("detected"),
         "confidence": v.get("confidence"), "score": v.get("score"),
         "version": v.get("version")}
        for v in engines_doc.get("verdicts", [])]
    doc["ambiguities"] = engines_doc.get("ambiguities", [])
    props = (fingerprint_doc or {}).get("properties") or {}
    markers = {}
    for key in ("engine_hints", "framework_markers",
                "engine_versions"):
        if key in props:
            markers[key] = props[key].get("value")
    doc["markers"] = markers
    return doc


def project_network_analysis(endpoints_doc, version):
    """network-analysis.json from the network stage's
    endpoints document: posture-level view (counts, hosts,
    libraries, services, cleartext posture, redaction)."""
    doc = _base("network-analysis", version)
    if not endpoints_doc:
        doc["unavailable"] = "network stage produced no data"
        doc["endpoint_count"] = 0
        return doc
    doc["endpoint_count"] = len(endpoints_doc.get("endpoints")
                                or [])
    doc["classification_counts"] = endpoints_doc.get(
        "classification_counts") or {}
    doc["hosts"] = endpoints_doc.get("hosts") or []
    doc["api_hosts"] = endpoints_doc.get("api_hosts") or []
    doc["network_libraries"] = endpoints_doc.get(
        "network_libraries") or []
    doc["services"] = [s.get("service") for s in
                       endpoints_doc.get("services") or []]
    nsc = endpoints_doc.get("network_security_config") or {}
    doc["cleartext"] = {
        "uses_cleartext_traffic": nsc.get(
            "uses_cleartext_traffic"),
        "base_cleartext_permitted": nsc.get(
            "base_cleartext_permitted"),
        "pin_set_present": nsc.get("pin_set_present"),
        "debug_overrides_present": nsc.get(
            "debug_overrides_present")}
    doc["redaction"] = endpoints_doc.get("redaction") or {
        "endpoint_values_redacted": 0}
    doc["notes"] = list(endpoints_doc.get("notes") or [])
    return doc


def project_api_architecture(endpoints_doc, version):
    """api-architecture.json from the endpoints document:
    per-host API shape (kinds, classifications, sample
    paths with query strings dropped), endpoint-kind totals,
    and the backend-service inventory."""
    doc = _base("api-architecture", version)
    if not endpoints_doc:
        doc["unavailable"] = "network stage produced no data"
        doc["host_profiles"] = []
        return doc
    by_host = {}
    kinds = {}
    websockets = 0
    for e in endpoints_doc.get("endpoints") or []:
        kind = e.get("kind") or "web"
        kinds[kind] = kinds.get(kind, 0) + 1
        # Phase 2 fix round (M2-03): the endpoint "kind" is
        # now the purpose kind; the transport moved to its
        # own field. Count websockets from the transport /
        # URL scheme, falling back to the legacy kind value
        # for documents written before the change.
        if e.get("transport") == "websocket" or \
                (e.get("url") or "").startswith(
                    ("ws://", "wss://")) or \
                kind == "websocket":
            websockets += 1
        host = e.get("host")
        if not host:
            continue
        slot = by_host.setdefault(host, {
            "host": host, "endpoint_count": 0, "kinds": {},
            "classifications": {}, "paths": []})
        slot["endpoint_count"] += 1
        slot["kinds"][kind] = slot["kinds"].get(kind, 0) + 1
        cls = e.get("classification") or "unverified"
        slot["classifications"][cls] = \
            slot["classifications"].get(cls, 0) + 1
        if len(slot["paths"]) < 5:
            try:
                path = urllib.parse.urlsplit(
                    e.get("url") or "").path
            except ValueError:
                path = ""
            if path and path not in slot["paths"]:
                slot["paths"].append(path)
    doc["host_profiles"] = [by_host[h] for h in sorted(by_host)]
    doc["api_hosts"] = endpoints_doc.get("api_hosts") or []
    doc["endpoint_kinds"] = kinds
    doc["websocket_endpoint_count"] = websockets
    doc["services"] = endpoints_doc.get("services") or []
    return doc
