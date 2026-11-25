"""narlib.formats_registry: loader for scripts/formats.json,
the single source of truth for engine / format knowledge
(Part 16 + Part 1).

Before Part 16 the engine marker matrix was duplicated as
Python literals across nar-engines.py (ENGINES +
JNI_SYMBOL_MARKERS), nar-triage.py (ENGINE_SIGNATURES + the
engine part of DEX_MARKERS), nar-analyze.py (deep-dive
routing markers) and narlib/graph.py (engine naming). All of
those consumers now derive their tables from formats.json
through this module; adding an engine or format is one JSON
row, not edits in several files.

The registry path is scripts/formats.json next to this
package. The NAR_FORMATS_JSON environment variable overrides
it — test-only plumbing used by the generality test to point
the tools at a temporary overlay; default behaviour always
reads the in-tree file.

Coverage (Part 1): build_coverage() projects formats.json
into the coverage document shape; scripts/coverage.json is
generated from it by nar-coverage.py --write and a freshness
test fails when the committed copy is stale. A `supported`
entry without a test_ref is a hard error here, never a
silent omission.

Part of NAR (Nirous Android Reversing). MIT License.
See LICENSE in the repo root.
"""
import json
import os

from .chains import FIDELITY_LADDER

STATUSES = ("supported", "partial", "identified_only",
            "unsupported", "server_side")

SECTIONS = ("input_types", "engines", "asset_formats",
            "script_formats", "animation_systems",
            "app_frameworks", "protection_kinds")

_DEFAULT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "formats.json")

_cache = {}


def formats_path():
    """The registry path in force (env override wins)."""
    return os.environ.get("NAR_FORMATS_JSON") or _DEFAULT_PATH


def load_formats(path=None):
    """Load and validate formats.json (cached per path)."""
    path = path or formats_path()
    if path not in _cache:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        validate_formats(doc)
        _cache[path] = doc
    return _cache[path]


def validate_formats(doc):
    """Structural validation. Raises ValueError on any
    malformed entry; a supported entry MUST carry a
    test_ref, and a non-supported entry MUST carry a
    reason and a probe (Part 1: no silent omission)."""
    if doc.get("version") != "1":
        raise ValueError("formats.json: version must be '1'")
    for section in SECTIONS:
        entries = doc.get(section)
        if entries is None:
            if section in ("app_frameworks", "protection_kinds",
                            "input_types"):
                continue
            raise ValueError(f"formats.json: missing {section}")
        for entry_id, entry in entries.items():
            where = f"formats.json:{section}/{entry_id}"
            status = entry.get("status")
            if status not in STATUSES:
                raise ValueError(f"{where}: bad status {status!r}")
            if entry.get("fidelity") not in FIDELITY_LADDER:
                raise ValueError(
                    f"{where}: bad fidelity {entry.get('fidelity')!r}")
            if status == "supported" and not entry.get("test_ref"):
                raise ValueError(
                    f"{where}: supported entry has no test_ref")
            if status != "supported":
                if not entry.get("reason"):
                    raise ValueError(
                        f"{where}: non-supported entry has no reason")
                if not entry.get("probe"):
                    raise ValueError(
                        f"{where}: non-supported entry has no probe")
    return doc


# ------------------------------------------------------------------
# Derived views for the migrated consumers.
# ------------------------------------------------------------------
def engines_table(doc=None):
    """nar-engines' ENGINES shape: {display name: {hints,
    deep, version_keys}}, in registry order."""
    doc = doc or load_formats()
    out = {}
    for entry in doc["engines"].values():
        out[entry["name"]] = {
            "hints": list(entry.get("hints") or []),
            "deep": entry.get("deep"),
            "version_keys": list(entry.get("version_keys") or []),
        }
    return out


def jni_markers(doc=None):
    """nar-engines' JNI_SYMBOL_MARKERS shape, for the
    families that carry any symbol evidence."""
    doc = doc or load_formats()
    out = {}
    for entry in doc["engines"].values():
        jni = entry.get("jni") or {}
        spec = {
            "prefixes": list(jni.get("prefixes") or []),
            "exact": list(jni.get("exact") or []),
            "substrings": list(jni.get("substrings") or []),
            "weak_prefixes": list(jni.get("weak_prefixes") or []),
            "weak_substrings": list(jni.get("weak_substrings") or []),
        }
        if jni.get("also_requires"):
            spec["also_requires"] = jni["also_requires"]
        if any(spec[k] for k in ("prefixes", "exact", "substrings",
                                 "weak_prefixes", "weak_substrings")):
            out[entry["name"]] = spec
    return out


def triage_signatures(doc=None):
    """nar-triage's ENGINE_SIGNATURES shape: [(hint name,
    [path markers])] in the registry's signature order."""
    doc = doc or load_formats()
    rows = []
    for entry in doc["engines"].values():
        for sig in entry.get("signatures") or []:
            rows.append((sig.get("order", 999), sig["hint"],
                         list(sig.get("paths") or [])))
    rows.sort(key=lambda r: r[0])
    return [(hint, paths) for _order, hint, paths in rows]


def engine_dex_markers(doc=None):
    """The engine part of nar-triage's DEX_MARKERS:
    [(order, label, [byte patterns])] sorted by the
    historical list position each entry carries."""
    doc = doc or load_formats()
    rows = []
    for entry in doc["engines"].values():
        for marker in entry.get("dex_markers") or []:
            pats = [p.encode("latin-1")
                    for p in marker.get("patterns") or []]
            rows.append((marker.get("order", 999),
                         marker["label"], pats))
    rows.sort(key=lambda r: r[0])
    return rows


def engine_by_name(name, doc=None):
    """One engine entry by display name, or None."""
    doc = doc or load_formats()
    for entry in doc["engines"].values():
        if entry["name"] == name:
            return entry
    return None


def path_markers(engine_id, doc=None):
    """Flat path markers for one engine id."""
    doc = doc or load_formats()
    entry = doc["engines"].get(engine_id) or {}
    return list(entry.get("paths") or [])


# ------------------------------------------------------------------
# Coverage projection (Part 1).
# ------------------------------------------------------------------
def _coverage_entry(entry_id, entry):
    out = {"id": entry_id,
           "name": entry.get("name") or entry_id,
           "status": entry.get("status"),
           "fidelity": entry.get("fidelity"),
           "reason": entry.get("reason"),
           "probe": entry.get("probe"),
           "test_ref": entry.get("test_ref")}
    if entry.get("deep") is not None or "deep" in entry:
        out["deep"] = entry.get("deep")
    if entry.get("ext"):
        out["ext"] = list(entry["ext"])
    if entry.get("parser"):
        out["parser"] = entry["parser"]
    if entry.get("chains"):
        out["chains"] = list(entry["chains"])
    return out


def build_coverage(doc=None):
    """The coverage document, generated from formats.json
    (single source of truth)."""
    doc = doc or load_formats()
    out = {"version": "1", "generated_from": "formats.json"}
    for section in SECTIONS:
        entries = doc.get(section) or {}
        out[section] = [_coverage_entry(eid, e)
                        for eid, e in entries.items()]
    return out


def jni_exclusions(doc=None):
    """{library basename: [canonical engine names whose JNI
    matches from that library are excluded]} — e.g. the
    Xamarin family's mono_* matches are dropped when they
    come from the IL2CPP runtime library, whose Mono-derived
    exports are Unity internals, not Xamarin evidence."""
    doc = doc or load_formats()
    out = {}
    for entry in doc["engines"].values():
        for lib in entry.get("jni_excluded_from") or []:
            out.setdefault(lib, []).append(entry["name"])
    return out


def metadata_file(engine_id, doc=None):
    """The engine's metadata payload filename, if declared."""
    doc = doc or load_formats()
    entry = doc["engines"].get(engine_id) or {}
    return entry.get("metadata_file")
