"""narlib.signatures: the versioned protection-signature
database (Evolution Phase 5).

The packer / RASP / licensing markers that nar-triage used
to embed as Python literals now live in a data artifact —
scripts/protection-signatures.json — with its own
database_version, so the signature set can be reviewed,
diffed, and extended without touching code. This loader is
the only reader: it validates the artifact structurally
(schema field, category shape, matcher kinds, hex payload
integrity, thresholds) and reconstructs the exact Python
structures the protection scan consumes. A missing or
malformed database is a hard error (SignaturesError),
never a silent fallback to a second, drifting copy of the
signatures.

Detection and reporting only: a hit means protection
artifacts or protection code ship inside the package. It
says nothing about whether a check passed at runtime, and
NAR never uses this to bypass anything (see the
legitimate-use boundary in SKILL.md).

Part of NAR (Nirous Android Reversing). Research by Bakr
Fayez. MIT License. See LICENSE in the repo root.
"""
import hashlib
import json
import os
import re

DB_FILENAME = "protection-signatures.json"
SUPPORTED_SCHEMA = 1
_MATCHER_KINDS = ("exact", "prefix", "contains")


class SignaturesError(Exception):
    """The signature database is missing or malformed."""


def default_db_path():
    """scripts/protection-signatures.json, beside narlib/."""
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        DB_FILENAME)


def _fail(msg):
    raise SignaturesError(msg)


def _dex_patterns(entry, where):
    patterns = []
    for raw in entry.get("dex_patterns", []):
        if not isinstance(raw, str):
            _fail(f"{where}: dex pattern is not a string: {raw!r}")
        try:
            raw.encode("ascii")
        except UnicodeEncodeError:
            _fail(f"{where}: dex pattern is not ASCII: {raw!r}")
        patterns.append(raw.encode("ascii"))
    return patterns


def _hex_bytes(value, where):
    if not isinstance(value, str):
        _fail(f"{where}: expected a hex string")
    try:
        out = bytes.fromhex(value)
    except ValueError:
        _fail(f"{where}: invalid hex: {value!r}")
    if not out:
        # An empty pattern is worse than a missing one:
        # buf.find(b"") matches at every position, so an
        # empty Widevine form would manufacture hit counts
        # on every DEX (stability audit D-09).
        _fail(f"{where}: empty hex value")
    return out


def load_signatures(path=None):
    """Load and validate the signature database.

    Returns a dict with the reconstructed structures:
    database_version, schema, categories (list of
    (key, label) tuples), category_labels, category_order,
    packer_markers (list of (name, [(kind, value)...],
    [bytes...], [str...]) tuples), rasp_dex_markers and
    licensing_dex_markers (list of (name, [bytes...],
    note) tuples), widevine (dict of the four byte forms +
    dex_patterns), pin_constant_re / stub_descriptor_re
    (compiled patterns), the three stub thresholds, and
    counts for reporting.
    """
    path = path or default_db_path()
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except OSError as e:
        raise SignaturesError(
            f"signature database not readable at {path}: {e}")
    except ValueError as e:
        raise SignaturesError(
            f"signature database at {path} is not valid JSON: {e}")
    if not isinstance(doc, dict):
        _fail("signature database root is not an object")
    if doc.get("schema") != SUPPORTED_SCHEMA:
        _fail(f"unsupported signature database schema: "
              f"{doc.get('schema')!r} (expected {SUPPORTED_SCHEMA})")
    version = doc.get("database_version")
    if not isinstance(version, str) or not version:
        _fail("signature database has no database_version")

    categories = []
    seen_keys = set()
    for entry in doc.get("categories") or []:
        if not isinstance(entry, dict) \
                or not isinstance(entry.get("key"), str) \
                or not entry.get("key") \
                or not isinstance(entry.get("label"), str) \
                or not entry.get("label"):
            _fail(f"malformed category entry: {entry!r}")
        if entry["key"] in seen_keys:
            _fail(f"duplicate category key: {entry['key']}")
        seen_keys.add(entry["key"])
        categories.append((entry["key"], entry["label"]))
    if not categories:
        _fail("signature database declares no categories")

    packers = []
    seen_packer_names = set()
    for entry in doc.get("packers") or []:
        if not isinstance(entry, dict):
            _fail(f"packer entry is not an object: {entry!r}")
        name = entry.get("name")
        if not name:
            _fail(f"packer entry without a name: {entry!r}")
        if name in seen_packer_names:
            _fail(f"duplicate packer name: {name}")
        seen_packer_names.add(name)
        matchers = []
        for m in entry.get("so_matchers", []):
            if not isinstance(m, dict) \
                    or m.get("kind") not in _MATCHER_KINDS \
                    or not isinstance(m.get("value"), str):
                _fail(f"{name}: malformed .so matcher: {m!r}")
            matchers.append((m["kind"], m["value"]))
        subs = entry.get("entry_substrings", [])
        if not all(isinstance(s, str) for s in subs):
            _fail(f"{name}: entry substrings must be strings")
        dex_patterns = _dex_patterns(entry, name)
        if not matchers and not dex_patterns and not subs:
            # A signature that can never fire is dead
            # weight counted as coverage (D-09).
            _fail(f"{name}: packer declares no matchers, "
                  "no DEX patterns and no entry substrings")
        packers.append((name, matchers,
                        dex_patterns, list(subs)))
    if not packers:
        _fail("signature database declares no packers")

    def marker_list(field):
        out = []
        seen = set()
        for entry in doc.get(field) or []:
            if not isinstance(entry, dict):
                _fail(f"{field}: entry is not an object: "
                      f"{entry!r}")
            name = entry.get("name")
            if not name:
                _fail(f"{field}: entry without a name: {entry!r}")
            if name in seen:
                _fail(f"{field}: duplicate entry name: {name}")
            seen.add(name)
            note = entry.get("note")
            if note is not None and not isinstance(note, str):
                _fail(f"{field}/{name}: note must be a string or null")
            patterns = _dex_patterns(entry, name)
            if not patterns:
                _fail(f"{field}/{name}: entry declares no "
                      "DEX patterns and can never fire")
            out.append((name, patterns, note))
        return out

    rasp = marker_list("rasp_dex_markers")
    licensing = marker_list("licensing_dex_markers")

    wv = doc.get("widevine") or {}
    if not isinstance(wv, dict):
        _fail("widevine section is not an object")
    widevine = {
        "uuid_string": _hex_bytes(wv.get("uuid_string_hex"),
                                  "widevine.uuid_string"),
        "uuid_raw": _hex_bytes(wv.get("uuid_raw_hex"),
                               "widevine.uuid_raw"),
        "uuid_msb_le": _hex_bytes(wv.get("uuid_msb_le_hex"),
                                  "widevine.uuid_msb_le"),
        "uuid_lsb_le": _hex_bytes(wv.get("uuid_lsb_le_hex"),
                                  "widevine.uuid_lsb_le"),
    }
    widevine["dex_patterns"] = [widevine["uuid_string"],
                                widevine["uuid_raw"],
                                widevine["uuid_msb_le"],
                                widevine["uuid_lsb_le"]]

    def compiled(field):
        pattern = doc.get(field)
        if not isinstance(pattern, str) or not pattern:
            _fail(f"signature database missing {field}")
        try:
            return re.compile(pattern.encode("ascii"))
        except (re.error, UnicodeEncodeError) as e:
            _fail(f"signature database {field} does not compile: {e}")

    thresholds = doc.get("thresholds") or {}
    if not isinstance(thresholds, dict):
        _fail("thresholds section is not an object")
    ints = {}
    for key in ("stub_dex_max_bytes", "stub_app_min_bytes",
                "stub_payload_min_bytes"):
        value = thresholds.get(key)
        if not isinstance(value, int) or isinstance(value, bool) \
                or value <= 0:
            _fail(f"threshold {key} is not a positive integer")
        if value > (1 << 40):
            # These are byte counts for stub/payload sizes;
            # anything past 1 TiB is a data error, not a
            # tuning choice (D-09).
            _fail(f"threshold {key} is absurdly large: "
                  f"{value}")
        ints[key] = value

    sig = {
        "database_version": version,
        "schema": doc["schema"],
        "path": path,
        "categories": categories,
        "category_labels": dict(categories),
        "category_order": {key: i for i, (key, _)
                           in enumerate(categories)},
        "packer_markers": packers,
        "rasp_dex_markers": rasp,
        "licensing_dex_markers": licensing,
        "widevine": widevine,
        "pin_constant_re": compiled("pin_constant_pattern"),
        "stub_descriptor_re": compiled("stub_descriptor_pattern"),
        "stub_dex_max_bytes": ints["stub_dex_max_bytes"],
        "stub_app_min_bytes": ints["stub_app_min_bytes"],
        "stub_payload_min_bytes": ints["stub_payload_min_bytes"],
    }
    sig["counts"] = {
        "categories": len(categories),
        "packers": len(packers),
        "packer_dex_patterns": sum(len(p[2]) for p in packers),
        "rasp_markers": len(rasp),
        "rasp_dex_patterns": sum(len(m[1]) for m in rasp),
        "licensing_markers": len(licensing),
        "licensing_dex_patterns": sum(len(m[1]) for m in licensing),
        "widevine_dex_patterns": len(widevine["dex_patterns"]),
    }
    return sig


def canonical_form(sig):
    """Plain-data canonical form of a loaded database, for
    equivalence digests: every byte pattern as hex, every
    structure in load order. Two databases with the same
    canonical form are behaviorally identical for the
    protection scan."""
    def pats(patterns):
        return [p.hex() for p in patterns]

    return {
        "database_version": sig["database_version"],
        "schema": sig["schema"],
        "categories": [[k, v] for k, v in sig["categories"]],
        "packers": [
            {"name": name,
             "so_matchers": [[k, v] for k, v in matchers],
             "dex_patterns": pats(dex),
             "entry_substrings": list(subs)}
            for name, matchers, dex, subs in sig["packer_markers"]],
        "rasp_dex_markers": [
            {"name": name, "dex_patterns": pats(p), "note": note}
            for name, p, note in sig["rasp_dex_markers"]],
        "licensing_dex_markers": [
            {"name": name, "dex_patterns": pats(p), "note": note}
            for name, p, note in sig["licensing_dex_markers"]],
        "widevine": {
            key: sig["widevine"][key].hex()
            for key in ("uuid_string", "uuid_raw", "uuid_msb_le",
                        "uuid_lsb_le")},
        "pin_constant_pattern": sig["pin_constant_re"].pattern.decode(
            "ascii"),
        "stub_descriptor_pattern": sig[
            "stub_descriptor_re"].pattern.decode("ascii"),
        "thresholds": {
            "stub_dex_max_bytes": sig["stub_dex_max_bytes"],
            "stub_app_min_bytes": sig["stub_app_min_bytes"],
            "stub_payload_min_bytes": sig["stub_payload_min_bytes"],
        },
    }


def canonical_digest(sig):
    """SHA-256 over the canonical form (sorted keys)."""
    blob = json.dumps(canonical_form(sig), sort_keys=True,
                      separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()
