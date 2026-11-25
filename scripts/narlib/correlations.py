"""Cross-module correlation records (Evolution Phase 8).

The stage tools each see one side of a relationship; this
module joins them into explicit correlation entries so a
claim never rests on a single module's view:

- JNI bindings: DEX native-method declarations
  (nar-dex native_methods) joined with ELF JNI exports
  (nar-native jni_map / libraries). Each declaration is
  "matched" (its mangled Java_* symbol is exported),
  "declaration-only" (no export; a RegisterNatives-capable
  library may still bind it dynamically — runtime
  confirmation needs a device), and each unclaimed export
  is "export-only".
- Components: manifest components (nar-perms) joined
  with DEX entry points (nar-dex entry_points):
  matched / declaration-only / implementation-only.
- Endpoints: network endpoints (nar-network) joined
  with DEX string references — the classes that reference
  the URL or its host are the client-code evidence.
- Network libraries: libraries detected by nar-network
  joined with DEX class presence for the library's
  package prefix.

Deduplication: a declaration appearing in several DEX
files, or an endpoint referenced from several places, is
ONE correlation entry — the same evidence is never
counted twice; the counts block states the merged
totals. Every entry carries a verification_status from
narlib.VERIFICATION_STATUSES: a two-sided static match
is CONFIRMED; a string-reference join is
STRONGLY_INDICATED (a referenced string is not a call);
one-sided entries are UNVERIFIED.
"""
# Known network-library package prefixes (descriptor form).
LIBRARY_PREFIXES = (
    ("okhttp", "Lokhttp3/"),
    ("retrofit", "Lretrofit2/"),
    ("volley", "Lcom/android/volley/"),
    ("ktor", "Lio/ktor/"),
    ("httpurlconnection", "Ljava/net/HttpURLConnection;"),
    ("cronet", "Lorg/chromium/net/"),
    ("apache httpclient", "Lorg/apache/http/"),
)


def _dotted(descriptor):
    """Lcom/example/App; -> com.example.App"""
    d = descriptor or ""
    if d.startswith("L") and d.endswith(";"):
        d = d[1:-1]
    return d.replace("/", ".")


def _mangle(text):
    """JNI name mangling for one component: '_' -> '_1',
    '$' -> '_00024', '.' and '/' -> '_'."""
    out = []
    for ch in text:
        if ch == "_":
            out.append("_1")
        elif ch == "$":
            out.append("_00024")
        elif ch in "./":
            out.append("_")
        else:
            out.append(ch)
    return "".join(out)


def jni_symbol(dotted_class, method):
    return "Java_" + _mangle(dotted_class) + "_" + _mangle(method)


def _dex_classes(dex_data):
    out = set()
    for dex in (dex_data or {}).get("dex_files", []):
        for c in dex.get("classes", []):
            out.add(c["class"])
    return out


def _jni_correlations(dex_data, native_data):
    declared = {}
    for dex in (dex_data or {}).get("dex_files", []):
        for nm in dex.get("native_methods", []):
            key = (_dotted(nm["class"]), nm["name"])
            declared.setdefault(key, []).append(dex.get("name"))
    exports = {}  # symbol -> [library paths]
    dynamic_capable = False
    for lib_path, symbols in ((native_data or {})
                              .get("jni_map") or {}).items():
        for sym in symbols:
            exports.setdefault(sym, []).append(lib_path)
    # Union in each library's own jni_exports (the map is
    # derived from them, but a partial document may carry
    # only one of the two views).
    for lib in (native_data or {}).get("libraries", []):
        label = lib.get("display_name") or lib.get("name")
        for sym in lib.get("jni_exports") or []:
            bucket = exports.setdefault(sym, [])
            if label and label not in bucket:
                bucket.append(label)
    for lib in (native_data or {}).get("libraries", []):
        if lib.get("register_natives_hint"):
            dynamic_capable = True
        if "JNI_OnLoad" in (lib.get("exports") or []):
            dynamic_capable = True
    entries = []
    matched_symbols = set()
    for (cls, name), dex_names in sorted(declared.items()):
        symbol = jni_symbol(cls, name)
        libs = sorted(exports.get(symbol, []))
        if libs:
            matched_symbols.add(symbol)
            entries.append({
                "class": cls, "method": name, "symbol": symbol,
                "status": "matched", "binding": "static-export",
                "libraries": libs,
                "declared_in": sorted(set(dex_names)),
                "verification_status": "CONFIRMED"})
        else:
            entries.append({
                "class": cls, "method": name, "symbol": symbol,
                "status": "declaration-only",
                "binding": ("dynamic-registration-possible"
                            if dynamic_capable
                            else "none-observed"),
                "libraries": [],
                "declared_in": sorted(set(dex_names)),
                "verification_status": "UNVERIFIED"})
    for symbol, libs in sorted(exports.items()):
        if symbol not in matched_symbols:
            entries.append({
                "class": None, "method": None, "symbol": symbol,
                "status": "export-only", "binding": "static-export",
                "libraries": sorted(libs), "declared_in": [],
                "verification_status": "UNVERIFIED"})
    return entries


def _component_correlations(perms_data, dex_data):
    declared = {}  # dotted name -> kind
    for kind, items in ((perms_data or {})
                        .get("components") or {}).items():
        for item in items or []:
            declared[item["name"]] = kind
    entry_points = {}
    for dex in (dex_data or {}).get("dex_files", []):
        for ep in dex.get("entry_points", []):
            entry_points[_dotted(ep["class"])] = \
                ep.get("via_superclass")
    entries = []
    for name, kind in sorted(declared.items()):
        if name in entry_points:
            entries.append({
                "component": name, "kind": kind,
                "status": "matched",
                "via_superclass": entry_points[name],
                "verification_status": "CONFIRMED"})
        else:
            entries.append({
                "component": name, "kind": kind,
                "status": "declaration-only",
                "via_superclass": None,
                "verification_status": "UNVERIFIED"})
    for name, via in sorted(entry_points.items()):
        if name not in declared:
            entries.append({
                "component": name, "kind": None,
                "status": "implementation-only",
                "via_superclass": via,
                "verification_status": "UNVERIFIED"})
    return entries


def _endpoint_correlations(network_data, dex_data):
    refs = {}  # string -> set of dotted sample classes
    for dex in (dex_data or {}).get("dex_files", []):
        for ref in dex.get("string_references", []):
            bucket = refs.setdefault(ref.get("string"), set())
            for cls in ref.get("sample_classes", []):
                bucket.add(_dotted(cls))
    entries = []
    seen = set()
    for ep in (network_data or {}).get("endpoints", []):
        url = ep.get("url")
        if not url or url in seen:
            continue
        seen.add(url)
        classes = set(refs.get(url, set()))
        host = ep.get("host")
        if host:
            for s, cs in refs.items():
                if s and host in s:
                    classes |= cs
        entries.append({
            "url": url, "host": host,
            "classification": ep.get("classification"),
            "referencing_classes": sorted(classes),
            "status": ("code-referenced" if classes
                       else "no-code-reference"),
            "verification_status": ("STRONGLY_INDICATED"
                                    if classes else "UNVERIFIED")})
    return entries


def _library_correlations(network_data, dex_data):
    classes = _dex_classes(dex_data)
    entries = []
    for lib in (network_data or {}).get("network_libraries", []):
        # The endpoints producer (nar-network) emits this
        # list as label STRINGS; an object form with a
        # "library" field is also accepted. The pre-fix
        # code called .get() unconditionally, so any real
        # target WITH a detected network library crashed
        # this builder (silently degrading the whole
        # correlations document since the C-06 hardening);
        # every retained case had an empty list, which is
        # why it never fired (stability audit S-03).
        if isinstance(lib, str):
            name = lib
        elif isinstance(lib, dict):
            name = lib.get("library") or ""
        else:
            continue
        prefix = None
        for key, pfx in LIBRARY_PREFIXES:
            if key in name.lower():
                prefix = pfx
                break
        if prefix is None:
            entries.append({
                "library": name, "status": "unverified",
                "class_prefix": None, "classes_found": 0,
                "verification_status": "UNVERIFIED"})
            continue
        found = sum(1 for c in classes if c.startswith(prefix))
        entries.append({
            "library": name,
            "status": "matched" if found else "library-only",
            "class_prefix": prefix, "classes_found": found,
            "verification_status": ("CONFIRMED" if found
                                    else "UNVERIFIED")})
    return entries


def build_correlations(dex_data, native_data, perms_data,
                       network_data, version):
    """Build the correlations document from stage data.
    Any input may be None (a degraded stage): its section
    is then empty and a note records the gap."""
    notes = []
    for label, data in (("dex", dex_data), ("native", native_data),
                        ("permissions", perms_data),
                        ("network", network_data)):
        if data is None:
            notes.append(f"{label} stage data unavailable; its "
                         "correlations are empty, not fabricated")
    jni = _jni_correlations(dex_data, native_data) \
        if dex_data is not None or native_data is not None else []
    components = _component_correlations(perms_data, dex_data) \
        if perms_data is not None or dex_data is not None else []
    endpoints = _endpoint_correlations(network_data, dex_data) \
        if network_data is not None else []
    libraries = _library_correlations(network_data, dex_data) \
        if network_data is not None else []

    def count(entries, status):
        return sum(1 for e in entries if e["status"] == status)

    return {
        "tool": "nar-analyze", "version": version,
        "kind": "correlations",
        "jni_bindings": jni,
        "components": components,
        "endpoints": endpoints,
        "network_libraries": libraries,
        "counts": {
            "jni_matched": count(jni, "matched"),
            "jni_declaration_only": count(jni, "declaration-only"),
            "jni_export_only": count(jni, "export-only"),
            "components_matched": count(components, "matched"),
            "components_declaration_only":
                count(components, "declaration-only"),
            "components_implementation_only":
                count(components, "implementation-only"),
            "endpoints_code_referenced":
                count(endpoints, "code-referenced"),
            "endpoints_no_code_reference":
                count(endpoints, "no-code-reference"),
            "network_libraries_matched":
                count(libraries, "matched"),
            "network_libraries_only":
                count(libraries, "library-only"),
        },
        "deduplication": (
            "A declaration or endpoint appearing in several "
            "DEX files or referenced from several places is "
            "one correlation entry; counts are over merged "
            "entries, so the same evidence is never "
            "double-counted."),
        "notes": notes,
    }
