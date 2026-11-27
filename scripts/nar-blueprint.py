#!/usr/bin/env python3
"""nar-blueprint.py: the rebuild layer (Part 8).

    python3 nar-blueprint.py <target> --out spec/
                             [--case DIR] [--json]

Emits a rebuild specification from VERIFIED case evidence
only — the nine files of the Part 8 contract:

    features.md       every feature: trigger, effect,
                      implementing components
    architecture.md   engine/framework, layering, threading
                      evidence, module boundaries, SDK roles
    data-model.md     storage keys/tables, types, ownership,
                      lifecycle, cloud-sync evidence
    flows.md          screen-by-screen, module-by-module
                      sequences with state (static limits
                      stated where order is not knowable)
    assets.md         asset inventory by role/type; atlas
                      and animation notes at identification
                      fidelity from the case inventory
                      (composition decoding lives in
                      `nar atlas` / `nar anim`, Part 4)
    network.md        endpoints with classified purposes
                      and request/response SHAPE only;
                      values redacted
    build-order.md    ordered implementation plan, each
                      step with a concrete acceptance check
    unrecoverable.md  what cannot be recovered from the
                      artifact, per category, with reason,
                      chain outcome and cheapest probe
    unknowns.json     machine-readable unknowns (validates
                      against schemas/blueprint.schema.json)

Rules (pinned by tests/unit/test_blueprint.py):

- Every claim in features.md carries a machine-checkable
  citation of the form `(evidence: <companion> — <item>)`;
  a claim that is inference, not observation, is marked
  `inferred` inline (and still cites its basis).
- An evidence-free section is written as a section headed
  NOT RECOVERABLE + reason, never skipped or omitted. All
  nine files are always emitted.
- The Part 0.3 boundary line appears verbatim exactly once
  per spec, in the features.md preface.
- No proprietary asset copying: assets are described by
  role, type and count only — never contents, string dumps
  or code.
- Case handling mirrors nar-ask.py: --case DIR is reused
  when its case.json input hash matches the target and is
  otherwise (re)built by nar-analyze.py; without --case a
  per-target cache under the system temp dir is used (the
  nar-ask cache for the same target is reused read-only
  when present). Target resolution goes through
  narlib.container.ResolvedTarget.
- unknowns.json feed contract: the document is
  {"version", "generated_by", "target_sha256",
   "consumer_note", "unknowns": [{area, reason, probe,
   detail, evidence}]} where reason is from the closed
  taxonomy (encrypted | unsupported-codec | server-side |
  stripped | absent). `nar coverage --gap` consumers can
  ingest the unknowns array directly: each entry already
  carries the reason + probe pair the gap report renders.
  nar-coverage itself is not modified in this part.

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from narlib import container as _container  # noqa: E402
from narlib import dex as _dexlib  # noqa: E402
from narlib import formats_registry  # noqa: E402

VERSION = "3.0.2"

BOUNDARY_LINE = (
    "the spec describes behaviour and architecture so you "
    "can implement your own original work. It does not "
    "license copying proprietary assets, art, audio, "
    "trademarks, or code.")

UNKNOWN_REASONS = ("encrypted", "unsupported-codec",
                   "server-side", "stripped", "absent")

SPEC_FILES = ("features.md", "architecture.md",
              "data-model.md", "flows.md", "assets.md",
              "network.md", "build-order.md",
              "unrecoverable.md", "unknowns.json")

_SECRET_PARAM = re.compile(
    r"((?:token|key|secret|password|passwd|auth|session|"
    r"cookie|credential|signature|sig)=)[^&\s\"'<>]+", re.I)


def scrub(text):
    """Redact secret-shaped values from companion text
    before it is quoted into the spec (defence in depth:
    endpoints.json already redacts at the source)."""
    if text is None:
        return ""
    out = _SECRET_PARAM.sub(r"\1REDACTED", str(text))
    out = re.sub(r"(https?://)[^/\s:@]+:[^/\s@]+@",
                 r"\1REDACTED@", out)
    return out


def safe_url(url):
    """URL with userinfo dropped and every query value
    replaced by REDACTED (parameter names and the path
    shape are the request shape; values never print)."""
    try:
        parts = urlsplit(str(url))
        port = parts.port
    except ValueError:
        # Malformed URL (e.g. a format-string URL harvested
        # from native strings, whose "port" is not numeric):
        # fall back to the regex scrub, which still redacts
        # credential-shaped values.
        return _SECRET_PARAM.sub(
            r"\1REDACTED", str(url))
    netloc = parts.hostname or ""
    if port:
        netloc = "%s:%s" % (netloc, port)
    query = urlencode([(k, "REDACTED")
                       for k, _v in parse_qsl(
                           parts.query, keep_blank_values=True)])
    fragment = _SECRET_PARAM.sub(r"\1REDACTED",
                                 parts.fragment)
    return urlunsplit((parts.scheme, netloc, parts.path,
                       query, fragment))


def ev(companion, item):
    """The one machine-checkable citation form."""
    return "(evidence: %s — %s)" % (companion, scrub(item))


def bullet(text, companion=None, item=None, inferred=False):
    line = "- " + text
    if inferred and "inferred" not in line:
        line += " — inferred"
    if companion:
        line += " " + ev(companion, item)
    return line


# ------------------------------------------------------------------
# Case access (mirrors nar-ask.py)
# ------------------------------------------------------------------
def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def case_matches(case_dir, target_sha):
    try:
        with open(os.path.join(case_dir, "case.json"),
                  encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return False
    return (doc.get("input") or {}).get("sha256") == target_sha


def run_analyze(target, case_dir):
    os.makedirs(case_dir, exist_ok=True)
    cmd = [sys.executable, os.path.join(HERE, "nar-analyze.py"),
           target, "--out", case_dir]
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=7200)
    return proc.returncode == 0


def ensure_case(target, target_sha, case_arg):
    """Return (case_dir, origin_note)."""
    if case_arg:
        case_dir = os.path.abspath(case_arg)
        if case_matches(case_dir, target_sha):
            return case_dir, "supplied case reused (hash match)"
        ok = run_analyze(target, case_dir)
        return case_dir, ("supplied case rebuilt by nar-analyze"
                          if ok else
                          "supplied case build attempted; "
                          "companions present are used as-is")
    candidates = [
        os.path.join(tempfile.gettempdir(),
                     "nar-blueprint-cache", target_sha[:24]),
        os.path.join(tempfile.gettempdir(),
                     "nar-ask-cache", target_sha[:24]),
    ]
    for cand in candidates:
        if case_matches(cand, target_sha):
            return cand, "per-target cache case reused"
    cache_dir = candidates[0]
    ok = run_analyze(target, cache_dir)
    return cache_dir, ("per-target cache case built by "
                       "nar-analyze" if ok else
                       "per-target cache case build attempted; "
                       "companions present are used as-is")


class Case:
    """Lazy companion reader over one case directory."""

    def __init__(self, case_dir):
        self.dir = case_dir
        self._cache = {}

    def get(self, name):
        if name in self._cache:
            return self._cache[name]
        doc = None
        path = os.path.join(self.dir, name)
        if os.path.isfile(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    doc = json.load(fh)
            except (OSError, ValueError):
                doc = None
        self._cache[name] = doc
        return doc

    def dex_classes(self):
        """[(descriptor, [methods], [fields], [supers])];
        raw-text scan fallback for very large dex.json."""
        if "_dex" in self._cache:
            return self._cache["_dex"]
        out = []
        path = os.path.join(self.dir, "dex.json")
        if os.path.isfile(path):
            if os.path.getsize(path) <= 96 * 1024 * 1024:
                doc = self.get("dex.json")
                for dex_file in (doc or {}).get("dex_files") or []:
                    # Both dex shapes (full + 3.0 compact)
                    # read identically through the narlib
                    # expansion path.
                    for cls in _dexlib.expand_dex_classes(dex_file):
                        supers = []
                        if cls.get("superclass"):
                            supers.append(cls["superclass"])
                        supers.extend(cls.get("interfaces") or [])
                        out.append((
                            cls.get("class") or "",
                            [m.get("name") or "" for m in
                             cls.get("methods") or []],
                            [f.get("name") or "" for f in
                             cls.get("fields") or []],
                            supers))
            else:
                with open(path, encoding="utf-8",
                          errors="replace") as fh:
                    text = fh.read()
                for name in re.findall(
                        r'"class":\s*"((?:L|I|\[)[^"]+;)"', text):
                    out.append((name, [], [], []))
        self._cache["_dex"] = out
        return out


def _props(doc):
    return (doc or {}).get("properties") or {}


def _prop(doc, key):
    entry = _props(doc).get(key) or {}
    return entry.get("value")


def _not_recoverable(title, reason, companion_note):
    return ("# %s\n\n## NOT RECOVERABLE\n\n%s %s\n"
            % (title, reason, companion_note))


class Spec:
    """Accumulates the unknowns list while sections render."""

    def __init__(self, case, target_sha):
        self.case = case
        self.target_sha = target_sha
        self.unknowns = []

    def add_unknown(self, area, reason, probe, detail,
                    evidence):
        if reason not in UNKNOWN_REASONS:
            reason = "absent"
        self.unknowns.append({
            "area": area, "reason": reason, "probe": probe,
            "detail": scrub(detail), "evidence": scrub(evidence),
        })


def _reason_from_text(text):
    t = (text or "").lower()
    if "encrypt" in t:
        return "encrypted"
    if "codec" in t or "decode" in t or "unsupported" in t:
        return "unsupported-codec"
    if "server" in t or "runtime" in t:
        return "server-side"
    if "strip" in t or "symbol" in t:
        return "stripped"
    return "absent"


# ------------------------------------------------------------------
# Section builders. Each returns markdown text; each appends
# its unknowns to the Spec.
# ------------------------------------------------------------------
_STORAGE_MARKERS = [
    ("SharedPreferences", ("sharedpreferences",)),
    ("SQLite (SQLiteOpenHelper/SQLiteDatabase)",
     ("sqliteopenhelper", "sqlitedatabase")),
    ("Room", ("androidx/room", "roomdatabase")),
    ("DataStore", ("androidx/datastore",)),
    ("EncryptedSharedPreferences",
     ("encryptedsharedpreferences", "security/crypto")),
    ("MMKV", ("mmkv",)),
    ("Realm", ("io/realm",)),
    ("ObjectBox", ("objectbox",)),
]


def storage_hits(case):
    """[(label, [(class, via_super), ...])] from dex.json,
    superclass signals included."""
    classes = case.dex_classes()
    found = []
    for label, needles in _STORAGE_MARKERS:
        hits = []
        for c, _m, _f, supers in classes:
            hay = (c + " " + " ".join(supers)).lower()
            if any(n in hay for n in needles):
                via = next((s for s in supers
                            if any(n in s.lower()
                                   for n in needles)), None)
                hits.append((c, via))
        if hits:
            found.append((label, hits))
    found = [entry for entry in found
             if not _room_refuted(case, entry)]
    return found


def _room_refuted(case, entry):
    """True when a Room marker entry is refuted by the
    app census: app.json's room_sqlite block marks the
    library absent, names no RoomDatabase classes and no
    shipped databases, and every marker hit is the
    MultiInstanceInvalidationService class, an AndroidX
    runtime artifact that also ships in targets with no
    Room library at all."""
    label, hits = entry
    if label != "Room":
        return False
    app = case.get("app.json") or {}
    room = (app.get("storage") or {}).get(
        "room_sqlite") or {}
    library = room.get("room_library") or {}
    if library.get("present") is not False:
        return False
    if room.get("room_database_classes") \
            or room.get("shipped_databases"):
        return False
    return all(
        c.rsplit("/", 1)[-1].rstrip(";")
        == "MultiInstanceInvalidationService"
        for c, _via in hits)


def build_features(spec):
    case = spec.case
    lines = [
        "# Rebuild specification — features",
        "",
        "Boundary: " + BOUNDARY_LINE,
        "",
        "Generated from verified case evidence only. Every "
        "claim below cites its evidence in the form "
        "`(evidence: <companion> — <item>)`; a claim marked "
        "`inferred` is a derivation from the cited evidence, "
        "not a direct observation.",
        "",
        "## Features",
        "",
    ]
    bullets = []
    inv = case.get("investigation.json")
    facts = (inv or {}).get("verified_facts") or []
    for f in facts[:40]:
        bullets.append(bullet(
            "**%s** — Trigger: not statically recorded; "
            "Effect: %s; Implementing components: %s"
            % (scrub(f.get("fact")), scrub(f.get("detail")),
               scrub(f.get("subject"))),
            "investigation.json",
            "verified_fact [%s] %s"
            % (f.get("verification_status"), f.get("fact"))))
    perms = case.get("permissions.json")
    components = (perms or {}).get("components") or {}
    for kind in ("activity", "service", "receiver", "provider"):
        comps = components.get(kind) or []
        if comps:
            names = ", ".join(c.get("name") or "?"
                              for c in comps[:5])
            bullets.append(bullet(
                "**Declared %s surface (%d)** — Trigger: "
                "Android system or in-app navigation; Effect: "
                "the component exists and is reachable per "
                "its manifest record; Implementing "
                "components: %s"
                % (kind, len(comps), names),
                "permissions.json",
                "components.%s (%d entries, first: %s)"
                % (kind, len(comps),
                   comps[0].get("name"))))
    for label, hits in storage_hits(case)[:4]:
        bullets.append(bullet(
            "**Persistence via %s** — Trigger: feature code "
            "reads/writes app state; Effect: state survives "
            "process death in the %s store; Implementing "
            "components: %s"
            % (label, label, hits[0][0]),
            "dex.json", "class %s -> %s" % (hits[0][0], label)))
    classes = case.dex_classes()
    billing = [c for c, _m, _f, _s in classes
               if "billing" in c.lower()
               or "purchases" in c.lower()]
    ads = [c for c, _m, _f, _s in classes
           if "/ads" in c.lower() or "admob" in c.lower()]
    if billing:
        bullets.append(bullet(
            "**In-app purchase surface** — Trigger: user "
            "purchase action; Effect: billing flow handled "
            "by %s; Implementing components: %s"
            % (billing[0], billing[0]),
            "dex.json", "class %s (billing surface)"
            % billing[0], inferred=True))
    if ads:
        bullets.append(bullet(
            "**Advertising surface** — Trigger: ad placement "
            "in the UI flow; Effect: ads served through %s; "
            "Implementing components: %s"
            % (ads[0], ads[0]),
            "dex.json", "class %s (advertising surface)"
            % ads[0], inferred=True))
    endpoints = case.get("endpoints.json")
    if endpoints and (endpoints.get("endpoints") or []):
        bullets.append(bullet(
            "**Network-backed behaviour** — Trigger: "
            "features that need remote data; Effect: %d "
            "endpoints are statically recorded (purposes "
            "in network.md); which of them are contacted "
            "at runtime is not observed. Implementing "
            "components: network libraries %s"
            % (len(endpoints.get("endpoints") or []),
               endpoints.get("network_libraries") or
               "(none named)"),
            "endpoints.json",
            "classification_counts = %s"
            % (endpoints.get("classification_counts"),)))
    engines = case.get("engines.json")
    detected = [v for v in (engines or {}).get("verdicts") or []
                if v.get("detected")]
    for v in detected[:2]:
        bullets.append(bullet(
            "**Engine runtime (%s)** — Trigger: application "
            "launch; Effect: the %s runtime drives the "
            "experience; Implementing components: engine "
            "verdict indicators in engines.json"
            % (v.get("engine"), v.get("engine")),
            "engines.json",
            "verdict %s detected, confidence %s, score %s"
            % (v.get("engine"), v.get("confidence"),
               v.get("score"))))
    if not bullets:
        spec.add_unknown(
            "features", "absent",
            "run nar-analyze on the target to produce "
            "investigation, permissions and dex companions",
            "no verified fact, component, storage, network "
            "or engine evidence exists in the case",
            "investigation.json, permissions.json, dex.json")
        return _not_recoverable(
            "Rebuild specification — features",
            "No feature evidence exists in the case: "
            "investigation.json carries no verified facts "
            "and no companion records a component, storage, "
            "network or engine feature.",
            ev("investigation.json",
               "verified_facts = %d" % len(facts)))
    lines.extend(bullets)
    lines.append("")
    return "\n".join(lines)


def build_architecture(spec):
    case = spec.case
    engines = case.get("engines.json")
    frameworks = case.get("frameworks.json")
    fp = case.get("fingerprint.json")
    native = case.get("native.json")
    decompile = case.get("decompile.json")
    if not engines and not frameworks and not native \
            and not case.dex_classes():
        spec.add_unknown(
            "architecture", "absent",
            "run nar-analyze on the target to produce the "
            "engine, framework, dex and native companions",
            "no architecture companion exists in the case",
            "engines.json, frameworks.json, dex.json, "
            "native.json")
        return _not_recoverable(
            "Architecture",
            "No engine, framework, DEX or native companion "
            "exists in the case, so no layering claim can "
            "be evidenced.",
            ev("case.json", "companions absent"))
    lines = ["# Architecture", "",
             "## Engine and framework", ""]
    verdicts = (engines or {}).get("verdicts") or \
        (frameworks or {}).get("verdicts") or []
    detected = [v for v in verdicts if v.get("detected")]
    if detected:
        for v in detected[:4]:
            lines.append(bullet(
                "Engine/framework: **%s** (confidence %s, "
                "score %s, version %s)"
                % (v.get("engine"), v.get("confidence"),
                   v.get("score"), v.get("version")),
                "engines.json",
                "verdict %s detected" % v.get("engine")))
    else:
        lines.append(bullet(
            "No game engine detected; the build is a native "
            "Android application build",
            "engines.json",
            "verdicts = %d, none detected" % len(verdicts),
            inferred=True))
    markers = (frameworks or {}).get("markers") or {}
    for m in (markers.get("framework_markers") or [])[:8]:
        lines.append(bullet(
            "Framework marker: %s" % m,
            "frameworks.json", "framework_markers: %s" % m))
    for k, val in list(
            (markers.get("engine_versions") or {}).items())[:4]:
        lines.append(bullet(
            "Toolchain version evidence: %s = %s" % (k, val),
            "frameworks.json", "engine_versions.%s" % k))
    abis = _prop(fp, "abis")
    if abis:
        lines.append(bullet(
            "Native ABIs shipped: %s" % (abis,),
            "fingerprint.json", "properties.abis = %s" % (abis,)))
    totals = (case.get("dex.json") or {}).get("totals") or {}
    if totals:
        lines.append(bullet(
            "Managed layer size: %s classes, %s methods "
            "across the DEX set"
            % (totals.get("classes"), totals.get("methods")),
            "dex.json", "totals = %s" % (totals,)))
    lines += ["", "## Module boundaries (DEX package groups)",
              ""]
    classes = case.dex_classes()
    package = _prop(case.get("application.json"), "package") \
        or (case.get("manifest.json") or {}).get("package") or ""
    app_prefix = "L" + package.replace(".", "/") + "/" \
        if package else None
    groups = {}
    third_party = {}
    for c, _m, _f, _s in classes:
        parts = [p for p in c.strip("L;").split("/") if p]
        if len(parts) >= 3:
            key = ".".join(parts[:3])
        elif parts:
            key = ".".join(parts)
        else:
            continue
        groups[key] = groups.get(key, 0) + 1
        if app_prefix and not c.startswith(app_prefix):
            third_party[key] = third_party.get(key, 0) + 1
    for key, n in sorted(groups.items(),
                         key=lambda kv: -kv[1])[:10]:
        lines.append(bullet(
            "Package group %s: %d classes" % (key, n),
            "dex.json", "class descriptor prefix %s" % key))
    if not groups:
        lines.append(bullet(
            "No DEX classes recorded, so no managed module "
            "boundary can be drawn",
            "dex.json", "dex_files classes = 0"))
    lines += ["", "## Native layer", ""]
    libs = (native or {}).get("libraries") or []
    if libs:
        for lib in libs[:10]:
            lines.append(bullet(
                "Native library %s (%s, %s): %d declared "
                "dependencies, symbol table %s"
                % (lib.get("name"), lib.get("elf_class"),
                   lib.get("arch"),
                   len(lib.get("needed") or []),
                   "present" if lib.get("has_symtab")
                   else "absent (stripped)"),
                "native.json",
                "libraries entry %s" % lib.get("name")))
    else:
        lines.append(bullet(
            "No native libraries recorded",
            "native.json", "libraries = 0"))
    lines += ["", "## Threading and event model", ""]
    threading = [c for c, _m, _f, _s in classes
                 if re.search(r"thread|executor|handler|"
                              r"coroutine|asynctask",
                              c, re.I)]
    looper_libs = [lib.get("name") for lib in libs
                   if any(str(i).startswith("ALooper_")
                          for i in lib.get("imports") or [])]
    if looper_libs:
        lines.append(bullet(
            "Native event loop: ALooper imports present in "
            "%s, so native code polls an Android looper"
            % ", ".join(looper_libs[:3]),
            "native.json",
            "imports ALooper_* in %s" % looper_libs[0]))
    if threading:
        lines.append(bullet(
            "Managed concurrency surface: %d classes named "
            "for threading/executors/handlers/coroutines "
            "(first: %s)"
            % (len(threading), threading[0]),
            "dex.json", "class %s" % threading[0]))
    if not looper_libs and not threading:
        lines.append(bullet(
            "No direct threading evidence: no ALooper "
            "imports and no threading-named classes were "
            "recorded; the concurrency model is not "
            "statically knowable beyond this absence",
            "dex.json", "class scan for threading names = 0",
            inferred=True))
        spec.add_unknown(
            "architecture/threading", "absent",
            "observe thread creation at runtime on a device "
            "you own (thread dump during use)",
            "no threading-named class and no native looper "
            "import in static evidence",
            "dex.json, native.json")
    lines += ["", "## Third-party SDK roles", ""]
    sdk_lines = []
    for key, n in sorted(third_party.items(),
                         key=lambda kv: -kv[1])[:8]:
        sdk_lines.append(bullet(
            "Third-party package group %s: %d classes — "
            "role is the library's own function; only its "
            "API surface is in the artifact"
            % (key, n),
            "dex.json",
            "class descriptor prefix %s (outside the "
            "application package)" % key, inferred=True))
    for lib in ((case.get("endpoints.json") or {})
                .get("network_libraries") or [])[:6]:
        sdk_lines.append(bullet(
            "Network SDK/library: %s" % lib,
            "endpoints.json", "network_libraries: %s" % lib))
    if sdk_lines:
        lines.extend(sdk_lines)
    else:
        lines.append(bullet(
            "No third-party SDK group identified from "
            "framework markers, network libraries or DEX "
            "package groups",
            "frameworks.json", "framework_markers scanned"))
    if decompile:
        lines += ["", "## Decompilation fidelity", ""]
        lines.append(bullet(
            "Managed code was served by %s at %s fidelity; "
            "the rebuild must treat decompiled output at "
            "that fidelity, never as original source"
            % (decompile.get("served_by"),
               decompile.get("fidelity")),
            "decompile.json",
            "served_by = %s, fidelity = %s"
            % (decompile.get("served_by"),
               decompile.get("fidelity"))))
    lines.append("")
    return "\n".join(lines)


def build_data_model(spec):
    case = spec.case
    found = storage_hits(case)
    assets = case.get("assets.json")
    save_like = [a for a in (assets or {}).get("assets") or []
                 if re.search(r"save|playerprefs|\.sav$|"
                              r"progress",
                              a.get("path") or "", re.I)]
    classes = case.dex_classes()
    storage_named = [c for c, _m, _f, _s in classes
                     if re.search(r"prefs|store|database|"
                                  r"repository|storage",
                                  c, re.I)][:400]
    endpoints = case.get("endpoints.json")
    api_hosts = (endpoints or {}).get("api_hosts") or []
    _app_pre = case.get("app.json")
    _app_room = ((_app_pre or {}).get("storage") or {}).get(
        "room_sqlite") or {}
    app_has_storage = bool(
        _app_room.get("shipped_databases")
        or _app_room.get("room_database_classes")
        or (((_app_pre or {}).get("storage") or {})
            .get("shared_preferences") or {}).get("referenced"))
    if not found and not save_like and not storage_named \
            and not app_has_storage:
        spec.add_unknown(
            "data-model", "absent",
            "inspect app-private storage at runtime on a "
            "device you own, which shows the actual store "
            "files static code only implies",
            "no storage-API class, storage-named class or "
            "save-like asset exists in the case",
            "dex.json, assets.json")
        return _not_recoverable(
            "Data model",
            "No storage evidence exists in the case: no "
            "DEX class implements or extends a known "
            "storage API, no storage-named class exists, "
            "and no save/config asset is inventoried. "
            "Storage keys, tables and lifecycle cannot be "
            "recovered from this artifact's static "
            "evidence.",
            ev("dex.json",
               "storage-API class scan = 0 hits"))
    lines = ["# Data model", "",
             "## Storage mechanisms", ""]
    for label, hits in found:
        for c, via in hits[:4]:
            if via and via not in c:
                lines.append(bullet(
                    "**%s** storage-shaped class %s "
                    "(extends %s) — the class matches the "
                    "%s signal by name/superclass; whether "
                    "it implements a store at runtime is "
                    "not observed. Ownership (if used): "
                    "application-private store; Lifecycle: "
                    "persists across process death until "
                    "uninstall or clear-data"
                    % (label, c, via, label),
                    "dex.json",
                    "class %s extends %s" % (c, via),
                    inferred=True))
            else:
                lines.append(bullet(
                    "**%s** storage-shaped class %s — "
                    "Ownership: application-private store; "
                    "Lifecycle: persists across process "
                    "death until uninstall or clear-data"
                    % (label, c),
                    "dex.json", "class %s -> %s" % (c, label),
                    inferred=True))
    if not found:
        lines.append(bullet(
            "No known storage-API implementation class; "
            "storage-named classes below are the only "
            "static persistence signal",
            "dex.json", "storage-API class scan = 0 hits"))
    lines += ["", "## Storage-shaped classes", ""]
    if storage_named:
        for c in storage_named[:12]:
            lines.append(bullet(
                "Storage-shaped class %s (name signal only; "
                "its keys/tables are runtime-written values, "
                "not artifact content)" % c,
                "dex.json", "class %s" % c, inferred=True))
    else:
        lines.append(bullet(
            "No storage-named classes recorded",
            "dex.json", "class name scan = 0"))
    lines += ["", "## Asset-side save/config files", ""]
    if save_like:
        for a in save_like[:8]:
            lines.append(bullet(
                "Save/config-shaped asset %s (type %s, "
                "%s bytes) — described by role only; "
                "contents are not copied"
                % (a.get("path"), a.get("type"),
                   a.get("size_bytes")),
                "assets.json", "asset %s" % a.get("path")))
    else:
        lines.append(bullet(
            "No save/config-shaped asset in the inventory",
            "assets.json",
            "assets scanned for save-like names = %d"
            % len((assets or {}).get("assets") or [])))
    app = case.get("app.json")
    if app:
        # Part 6: nar-app storage detail — shipped database
        # schemas (sqlite_master), prefs candidates and
        # token storage locations join the data model.
        storage = app.get("storage") or {}
        room = storage.get("room_sqlite") or {}
        dbs = room.get("shipped_databases") or []
        if dbs:
            lines += ["", "## Shipped database schemas "
                      "(nar-app, sqlite_master)", ""]
            for db in dbs[:6]:
                db_facts = db.get("facts") or {}
                for t in (db_facts.get("tables") or [])[:12]:
                    cols = ", ".join(
                        "%s %s" % (c.get("name"),
                                   c.get("declared_type") or "")
                        for c in t.get("columns") or [])
                    lines.append(bullet(
                        "Table **%s** in %s (%s)"
                        % (t.get("name"), db.get("file"), cols),
                        "app.json",
                        "shipped database %s table %s"
                        % (db.get("file"), t.get("name"))))
        prefs = storage.get("shared_preferences") or {}
        if prefs.get("candidate_file_names") or \
                prefs.get("candidate_keys"):
            lines += ["", "## SharedPreferences (nar-app)", ""]
            lines.append(bullet(
                "Candidate prefs files %s; candidate keys %s "
                "(DEX co-occurrence heuristic — a constant "
                "can be a key, a file name or an unrelated "
                "literal in the same method)"
                % ((prefs.get("candidate_file_names") or [])[:6],
                   (prefs.get("candidate_keys") or [])[:12]),
                "app.json",
                "storage.shared_preferences candidates",
                inferred=True))
        auth = app.get("auth") or {}
        if auth.get("token_storage_locations"):
            lines.append(bullet(
                "Token storage locations (mechanisms only, "
                "values never read): %s"
                % ", ".join(auth["token_storage_locations"]),
                "app.json", "auth.token_storage_locations"))
    lines += ["", "## Cloud sync", ""]
    if api_hosts:
        lines.append(bullet(
            "API hosts recorded (%s): remote state sync is "
            "possible through these hosts; what is synced "
            "is decided server-side"
            % ", ".join(str(h) for h in api_hosts[:6]),
            "endpoints.json", "api_hosts = %s" % (api_hosts,),
            inferred=True))
    elif endpoints and (endpoints.get("endpoints") or []):
        lines.append(bullet(
            "Endpoints are recorded but no API host is "
            "classified, so no cloud-sync path is "
            "evidenced; treat state as local unless a "
            "runtime probe shows otherwise",
            "endpoints.json", "api_hosts = []", inferred=True))
    else:
        lines.append(bullet(
            "No endpoint evidence, so no cloud-sync path "
            "is evidenced",
            "endpoints.json", "endpoints absent or empty"))
    lines += ["",
              "Types note: static evidence names the store "
              "mechanism and the implementing classes; "
              "individual key/table schemas are written at "
              "runtime and are enumerated only where a "
              "class or asset above names them.",
              ""]
    return "\n".join(lines)


def build_flows(spec):
    case = spec.case
    perms = case.get("permissions.json")
    manifest = case.get("manifest.json")
    if not perms and not manifest and not case.get("app.json"):
        spec.add_unknown(
            "flows", "absent",
            "run nar-analyze on the target to produce the "
            "manifest companions",
            "no manifest companion exists in the case",
            "permissions.json, manifest.json")
        return _not_recoverable(
            "Flows",
            "No manifest companion exists in the case, so "
            "no screen or component sequence can be "
            "evidenced.",
            ev("case.json", "companions absent"))
    lines = ["# Flows", "",
             "## Screens (manifest declaration order, "
             "launcher first)", ""]
    components = (perms or {}).get("components") or {}
    activities = list(components.get("activity") or [])
    launcher = (perms or {}).get("launcher_activity")
    ordered = []
    if launcher:
        ordered.extend(a for a in activities
                       if a.get("name") == launcher)
    ordered.extend(a for a in activities
                   if a.get("name") != launcher)
    if ordered:
        for i, a in enumerate(ordered, 1):
            filters = a.get("intent_filters") or []
            deep = []
            for f in filters:
                deep.extend(f.get("data") or [])
            role = "launcher (entry point)" \
                if a.get("name") == launcher else \
                "declared screen %d" % i
            lines.append(bullet(
                "**%s** — %s; exported=%s; intent "
                "filters=%d%s; State: reached from the "
                "launcher flow in-app (exact tap sequence "
                "is runtime behaviour)"
                % (a.get("name"), role, a.get("exported"),
                   len(filters),
                   "; deep links: %s" % (deep[:2],) if deep
                   else ""),
                "permissions.json",
                "components.activity entry %s" % a.get("name")))
    else:
        counts = (perms or {}).get("component_counts") or \
            (manifest or {}).get("component_counts") or {}
        lines.append(bullet(
            "Component counts recorded (%s) but no "
            "per-activity list is in the case"
            % (counts,),
            "manifest.json", "component_counts = %s"
            % (counts,)))
    lines += ["", "## Background and system components", ""]
    extra = []
    for kind in ("service", "receiver", "provider"):
        for c in (components.get(kind) or [])[:6]:
            extra.append(bullet(
                "%s %s (exported=%s) — runs outside the "
                "screen flow; state changes it performs are "
                "runtime behaviour"
                % (kind, c.get("name"), c.get("exported")),
                "permissions.json",
                "components.%s entry %s"
                % (kind, c.get("name"))))
    if extra:
        lines.extend(extra)
    else:
        lines.append(bullet(
            "No service, receiver or provider components "
            "recorded",
            "permissions.json", "components scanned"))
    app = case.get("app.json")
    if app:
        # Part 6: the nar-app screen map + route map deepen
        # the manifest flow with in-activity screens.
        nav = app.get("navigation") or {}
        ui = app.get("ui_frameworks") or {}
        compose = ui.get("jetpack_compose") or {}
        lines += ["", "## In-activity screens and routes "
                  "(nar-app)", ""]
        lines.append(bullet(
            "nar-app screen map: %d @Composable methods, "
            "%d XML layouts, %d fragment classes — screens "
            "rendered inside activities, which the manifest "
            "list above cannot see"
            % (compose.get("composable_method_count", 0),
               (ui.get("view_xml") or {}).get("layout_count", 0),
               nav.get("fragment_class_count", 0)),
            "app.json", "screen_map + ui_frameworks census",
            inferred=True))
        for d in (nav.get("deep_links") or [])[:8]:
            lines.append(bullet(
                "Deep link %s://%s -> %s"
                % (d.get("scheme"), d.get("host") or "",
                   d.get("component")),
                "app.json",
                "navigation.deep_links entry %s"
                % d.get("component")))
        for edge in (app.get("data_flow") or [])[:8]:
            lines.append(bullet(
                "Data flow: %s -> %s (via %s)"
                % (edge.get("from"), edge.get("to"),
                   edge.get("via")),
                "app.json", "data_flow edge", inferred=True))
    lines += ["",
              "Boundary: the launcher is the only statically "
              "known entry point. The order in which the "
              "remaining screens are visited, and any "
              "screens rendered inside a single activity by "
              "an engine or a web view, are not statically "
              "knowable from the manifest; they need a "
              "runtime walkthrough on a device you own.",
              ""]
    return "\n".join(lines)


_ANIM_RE = re.compile(
    r"spine|lottie|\.skel$|\.riv$|dragonbones|aseprite|"
    r"anim|_ske\.json|_tex\.json", re.I)


def build_assets(spec):
    case = spec.case
    assets = case.get("assets.json")
    if not assets:
        spec.add_unknown(
            "assets", "absent",
            "run nar-analyze on the target to produce the "
            "asset inventory",
            "assets.json is absent from the case",
            "assets.json")
        return _not_recoverable(
            "Assets",
            "assets.json is absent from the case, so no "
            "asset inventory can be evidenced.",
            ev("case.json", "companions absent"))
    items = assets.get("assets") or []
    lines = ["# Assets", "",
             "Inventory by role and type only; asset "
             "contents are never copied into the spec.",
             "", "## Inventory", ""]
    lines.append(bullet(
        "Total inventoried assets: %s (%s bytes); "
        "duplicates recorded: %d"
        % (assets.get("total_assets"),
           assets.get("total_bytes"),
           len(assets.get("duplicates") or [])),
        "assets.json",
        "total_assets = %s" % (assets.get("total_assets"),)))
    for cat, n in sorted(
            (assets.get("by_category") or {}).items(),
            key=lambda kv: -kv[1])[:12]:
        lines.append(bullet(
            "Category %s: %d asset(s)" % (cat, n),
            "assets.json", "by_category.%s = %d" % (cat, n)))
    by_type = {}
    for a in items:
        by_type[a.get("type") or "unknown"] = \
            by_type.get(a.get("type") or "unknown", 0) + 1
    for t, n in sorted(by_type.items(),
                       key=lambda kv: -kv[1])[:12]:
        lines.append(bullet(
            "Type %s: %d asset(s)" % (t, n),
            "assets.json", "asset type %s count" % t))
    largest = assets.get("largest") or items[:5]
    if largest:
        lines += ["", "## Largest assets (role view)", ""]
        for a in largest[:8]:
            lines.append(bullet(
                "Asset %s — type %s, %s bytes (role/type "
                "only; content not copied)"
                % (a.get("path"), a.get("type"),
                   a.get("size_bytes")),
                "assets.json", "asset %s" % a.get("path")))
    if not items:
        lines.append(bullet(
            "The inventory is empty: payload content, "
            "where present, lives inside engine "
            "containers or the base/split archives rather "
            "than the inventoried asset roots",
            "assets.json", "assets = []", inferred=True))
    lines += ["", "## Atlas and animation notes", ""]
    anim = [a for a in items
            if _ANIM_RE.search(a.get("path") or "")]
    for a in anim[:8]:
        lines.append(bullet(
            "Animation-shaped asset %s (type %s) — "
            "identified by name/extension only"
            % (a.get("path"), a.get("type")),
            "assets.json", "asset %s" % a.get("path")))
    lines.append(bullet(
        "Atlas composition and animation drivers are "
        "not derived in this spec: the composition "
        "machinery (Part 4) is delivered by `nar atlas` "
        "and `nar anim`, which decode part grouping, "
        "attachment points and drivers from the target "
        "directly; the notes above stay at identification "
        "level (name/extension) from the case inventory",
        "assets.json",
        "animation-shaped assets identified = %d"
        % len(anim), inferred=True))
    spec.add_unknown(
        "assets/composition", "absent",
        "run `nar atlas <target>` and `nar anim "
        "<target>` (Part 4) for atlas composition and "
        "animation drivers",
        "atlas composition and animation drivers are "
        "identification-level in this spec; the Part 4 "
        "tools decode them from the target",
        "assets.json")
    lines.append("")
    return "\n".join(lines)


def build_network(spec):
    case = spec.case
    endpoints = case.get("endpoints.json")
    analysis = case.get("network-analysis.json")
    if not endpoints and not analysis:
        spec.add_unknown(
            "network", "absent",
            "run nar-analyze on the target to produce the "
            "network companions",
            "no network companion exists in the case",
            "endpoints.json, network-analysis.json")
        return _not_recoverable(
            "Network",
            "No network companion exists in the case, so "
            "no endpoint or purpose can be evidenced.",
            ev("case.json", "companions absent"))
    eps = (endpoints or {}).get("endpoints") or []
    lines = ["# Network", "",
             "Endpoints with classified purposes and "
             "request/response SHAPE only. Values are "
             "redacted: query values and userinfo never "
             "print (endpoints.json redacts at the source; "
             "this spec re-redacts before writing).",
             "", "## Endpoints", ""]
    if eps:
        for e in eps[:60]:
            lines.append(bullet(
                "Endpoint %s — kind %s, classified "
                "purpose: %s; sources: %s; Shape: URL + "
                "kind + classification + source only "
                "(method, headers and body are not in "
                "static evidence)"
                % (safe_url(e.get("url") or ""),
                   e.get("kind"), e.get("classification"),
                   e.get("sources")),
                "endpoints.json",
                "endpoint host %s classification %s"
                % (e.get("host"), e.get("classification"))))
        if len(eps) > 60:
            lines.append(bullet(
                "Endpoint list truncated in this view: "
                "%d further endpoints are in the companion"
                % (len(eps) - 60),
                "endpoints.json",
                "endpoints total = %d" % len(eps)))
    else:
        lines.append(bullet(
            "No endpoints recorded in static evidence",
            "endpoints.json", "endpoints = 0"))
        spec.add_unknown(
            "network/endpoints", "server-side",
            "observe traffic at runtime on a device you "
            "own with a proxy you control",
            "the endpoint inventory is empty; runtime "
            "calls, if any, are not statically recorded",
            "endpoints.json")
    counts = (endpoints or {}).get("classification_counts") \
        or (analysis or {}).get("classification_counts") or {}
    if counts:
        lines += ["", "## Classification summary", ""]
        lines.append(bullet(
            "Classification counts: %s" % (counts,),
            "endpoints.json",
            "classification_counts = %s" % (counts,)))
    libs = (endpoints or {}).get("network_libraries") or \
        (analysis or {}).get("network_libraries") or []
    if libs:
        lines += ["", "## Network libraries", ""]
        for lib in libs[:6]:
            lines.append(bullet(
                "Network library: %s" % lib,
                "endpoints.json",
                "network_libraries: %s" % lib))
    cleartext = (analysis or {}).get("cleartext") or {}
    if cleartext:
        lines += ["", "## Transport posture", ""]
        lines.append(bullet(
            "Cleartext permitted (base config): %s; "
            "certificate pin set present: %s"
            % (cleartext.get("base_cleartext_permitted"),
               cleartext.get("pin_set_present")),
            "network-analysis.json",
            "cleartext = %s" % (cleartext,)))
    lines.append("")
    return "\n".join(lines)


def build_build_order(spec):
    case = spec.case
    app = case.get("application.json")
    perms = case.get("permissions.json")
    manifest = case.get("manifest.json")
    engines = case.get("engines.json")
    if not app and not perms and not manifest and not engines:
        spec.add_unknown(
            "build-order", "absent",
            "run nar-analyze on the target to produce a "
            "case before deriving an implementation plan",
            "no identity, manifest or engine companion "
            "exists in the case",
            "case.json")
        return _not_recoverable(
            "Build order",
            "No identity, manifest or engine evidence "
            "exists in the case, so no implementation "
            "order can be derived.",
            ev("case.json", "companions absent"))
    lines = ["# Build order", "",
             "Ordered implementation plan derived from "
             "the architecture evidence: foundation, data, "
             "features, polish. Each step carries a "
             "concrete acceptance check.", ""]
    steps = []
    counts = (perms or {}).get("component_counts") or \
        (manifest or {}).get("component_counts") or {}
    launcher = (perms or {}).get("launcher_activity")
    steps.append((
        "Foundation: project shell and manifest surface "
        "(%s components; launcher %s)"
        % (counts, launcher or "(not recorded)"),
        "the built app declares the same component "
        "counts and cold-starts to the launcher component",
        "permissions.json",
        "component_counts = %s, launcher_activity = %s"
        % (counts, launcher)))
    detected = [v for v in (engines or {}).get("verdicts") or []
                if v.get("detected")]
    if detected:
        steps.append((
            "Runtime layer: integrate the %s runtime "
            "(version evidence %s) behind the shell"
            % (detected[0].get("engine"),
               detected[0].get("version")),
            "the shell hands off to the engine runtime "
            "and renders its first frame/scene without "
            "the managed layer crashing",
            "engines.json",
            "verdict %s detected, confidence %s"
            % (detected[0].get("engine"),
               detected[0].get("confidence"))))
    else:
        steps.append((
            "Application layer: managed Android app "
            "structure (no engine runtime in evidence)",
            "the app navigates between the declared "
            "activities with state intact",
            "engines.json", "verdicts: none detected"))
    found = storage_hits(case)
    if found:
        steps.append((
            "Data layer: implement the %s store(s) behind "
            "a repository boundary"
            % ", ".join(label for label, _h in found[:3]),
            "state written by a feature survives process "
            "death and is read back unchanged",
            "dex.json",
            "storage classes: %s"
            % (found[0][1][0][0],)))
    else:
        steps.append((
            "Data layer: no storage mechanism is in "
            "evidence — run the runtime storage probe "
            "before designing persistence",
            "the probe's file listing is recorded and "
            "the persistence design names a store for "
            "each file found",
            "dex.json", "storage-API class scan = 0 hits"))
    facts = (case.get("investigation.json") or {}) \
        .get("verified_facts") or []
    if facts:
        steps.append((
            "Features: implement the features listed in "
            "features.md (derived from the %d verified "
            "facts in investigation.json) in features.md "
            "order (security and network facts last, "
            "behind their own layers)"
            % len(facts),
            "each feature demonstrably produces the "
            "effect its features.md entry records",
            "investigation.json",
            "verified_facts = %d" % len(facts)))
    endpoints = case.get("endpoints.json")
    if endpoints and (endpoints.get("endpoints") or []):
        steps.append((
            "Network layer: typed clients for the %d "
            "recorded endpoints, grouped by classification "
            "in network.md"
            % len(endpoints.get("endpoints") or []),
            "each client reproduces the recorded URL "
            "shape; no client ships a value copied from "
            "the artifact",
            "endpoints.json",
            "classification_counts = %s"
            % (endpoints.get("classification_counts"),)))
    assets = case.get("assets.json")
    if assets:
        steps.append((
            "Asset pipeline: recreate (do not copy) the "
            "asset inventory by category in assets.md "
            "(%s assets inventoried)"
            % (assets.get("total_assets"),),
            "the rebuilt inventory matches the recorded "
            "category counts with original assets",
            "assets.json",
            "by_category = %s"
            % (assets.get("by_category"),)))
    steps.append((
        "Verification: re-run the full analysis on the "
        "rebuilt app and diff the two specifications",
        "the rebuilt app's blueprint shows no feature "
        "from features.md missing and no new "
        "unrecoverable category",
        "case.json", "case_id present for both runs"))
    for i, (text, check, comp, item) in enumerate(steps, 1):
        lines.append(bullet(
            "**Step %d.** %s. Acceptance: %s"
            % (i, text, check), comp, item))
    lines.append("")
    return "\n".join(lines)


def build_unrecoverable(spec):
    case = spec.case
    lines = ["# Unrecoverable", "",
             "What cannot be recovered from the artifact, "
             "per category. Each entry names (a) the "
             "reason, (b) the chain outcome where a "
             "fallback chain was involved, and (c) the "
             "cheapest black-box probe where one exists. "
             "A category with no instance in this case "
             "says so explicitly.", ""]
    any_entry = False

    def section(title, bullets_list, area, reason, probe,
                detail, evidence):
        nonlocal any_entry
        lines.extend(["## " + title, ""])
        if bullets_list:
            lines.extend(bullets_list)
            any_entry = True
            spec.add_unknown(area, reason, probe, detail,
                             evidence)
        else:
            lines.append(bullet(
                "No instance identified in this case: the "
                "scanned evidence records none (this is a "
                "statement about this case, not a proof "
                "about the running app)",
                "case.json", "category scan: %s" % title))
        lines.append("")

    # --- server-side logic --------------------------------
    endpoints = case.get("endpoints.json")
    eps = (endpoints or {}).get("endpoints") or []
    inv = case.get("investigation.json")
    inv_unknowns = (inv or {}).get("unknowns") or []
    srv = []
    if eps:
        srv.append(bullet(
            "Server-side logic behind %d recorded "
            "endpoints — Reason: only client-side URL "
            "strings and classifications are in the "
            "artifact; the server implementation, its "
            "data and its verdicts are not. Chain outcome: "
            "static network stage served the inventory; "
            "no fallback chain reaches server code. Probe: "
            "exercise the feature on a device you own "
            "behind a proxy you control and record "
            "request/response shapes"
            % len(eps),
            "endpoints.json",
            "classification_counts = %s"
            % ((endpoints or {}).get(
                "classification_counts"),)))
    for u in inv_unknowns[:4]:
        srv.append(bullet(
            "Runtime/server question: %s — Reason: %s "
            "Probe: an authorized runtime session on a "
            "device you own"
            % (scrub(u.get("question")),
               scrub(u.get("reason"))),
            "investigation.json",
            "unknowns entry: %s" % u.get("question")))
    section("Server-side logic", srv, "server-side",
            "server-side",
            "exercise the feature on a device you own "
            "behind a proxy you control",
            "server implementations and runtime verdicts "
            "are not in the artifact",
            "endpoints.json, investigation.json")

    # --- encrypted payloads -------------------------------
    enc = []
    try:
        coverage = formats_registry.build_coverage()
        for sec_name, entries in coverage.items():
            if not isinstance(entries, list):
                continue
            for e in entries:
                if "encrypt" in (e.get("reason") or "").lower():
                    enc.append(bullet(
                        "Coverage entry %s/%s — Reason: %s "
                        "Probe: %s"
                        % (sec_name, e.get("id"),
                           e.get("reason"), e.get("probe")),
                        "formats.json",
                        "coverage %s/%s status %s"
                        % (sec_name, e.get("id"),
                           e.get("status"))))
    except Exception:
        pass
    report = case.get("report.json")
    for p in (report or {}).get("protections") or []:
        if isinstance(p, dict) and \
                p.get("category") == "encryption":
            enc.append(bullet(
                "Encryption protection recorded: %s — "
                "Reason: %s Probe: runtime observation of "
                "the decrypted values on a device you own"
                % (p.get("name"),
                   (p.get("evidence") or ["see report"])[0]),
                "report.json",
                "protections entry %s" % p.get("name")))
    section("Encrypted payloads", enc[:6], "encrypted",
            "encrypted",
            "runtime observation on a device you own, "
            "where values exist decrypted in memory",
            "encrypted payloads cannot be read from the "
            "artifact without keys that are not in it",
            "formats.json coverage, report.json")

    # --- stripped native code -----------------------------
    native = case.get("native.json")
    stripped = [lib for lib in
                (native or {}).get("libraries") or []
                if not lib.get("has_symtab")]
    strip_bullets = []
    for lib in stripped[:8]:
        strip_bullets.append(bullet(
            "Native library %s — Reason: the symbol table "
            "is absent (stripped), so function-level "
            "recovery needs dynamic analysis; the ELF "
            "structure, dependencies and dynamic exports "
            "remain readable. Chain outcome: native stage "
            "served structural evidence via the built-in "
            "ELF parser (no decompiler rung ran). Probe: "
            "dynamic instrumentation on a device you own "
            "(hook the exported JNI surface and observe)"
            % lib.get("name"),
            "native.json",
            "libraries entry %s has_symtab = false"
            % lib.get("name")))
    section("Stripped native code", strip_bullets,
            "stripped-native", "stripped",
            "dynamic instrumentation on a device you own",
            "stripped libraries expose structure and "
            "exports, not function bodies",
            "native.json")

    # --- licence checks -----------------------------------
    lic = []
    for p in (report or {}).get("protections") or []:
        if isinstance(p, dict) and \
                p.get("category") == "licensing_drm":
            lic.append(bullet(
                "Licence/DRM check recorded: %s — Reason: "
                "the verdict is computed with store/server "
                "participation; the client code path is "
                "visible but the entitlement decision is "
                "not in the artifact. Evidence: %s Probe: "
                "run the app with and without a valid "
                "licence on a device you own and diff "
                "behaviour"
                % (p.get("name"),
                   (p.get("evidence") or [""])[0]),
                "report.json",
                "protections entry %s" % p.get("name")))
    perms = case.get("permissions.json")
    perm_names = [p.get("name") for p in
                  (perms or {}).get("permissions") or []]
    if any("CHECK_LICENSE" in (n or "") for n in perm_names):
        lic.append(bullet(
            "Licence-check permission declared "
            "(com.android.vending.CHECK_LICENSE) — the "
            "check's server side is unrecoverable for the "
            "same reason",
            "permissions.json",
            "permissions include CHECK_LICENSE"))
    section("Licence checks", lic, "licence-checks",
            "server-side",
            "run the app with and without a valid licence "
            "on a device you own and diff behaviour",
            "licence verdicts are store/server decisions",
            "report.json, permissions.json")

    # --- third-party internals ----------------------------
    markers = ((case.get("frameworks.json") or {})
               .get("markers") or {})
    third = []
    for m in (markers.get("framework_markers") or [])[:5]:
        third.append(bullet(
            "Third-party framework %s — Reason: the "
            "artifact carries the library's compiled API "
            "surface, not its source or internal design; "
            "only the surface the app calls is evidenced. "
            "Probe: the vendor's public documentation for "
            "the recorded version"
            % m,
            "frameworks.json", "framework_markers: %s" % m))
    section("Third-party internals", third,
            "third-party-internals", "absent",
            "the vendor's public documentation for the "
            "recorded version",
            "third-party internals are compiled surface "
            "only in the artifact",
            "frameworks.json")

    # --- decompile chain outcome --------------------------
    decompile = case.get("decompile.json")
    chain_bullets = []
    if decompile:
        attempts = "; ".join(
            "%s:%s (%s)" % (a.get("rung"), a.get("status"),
                            a.get("classification"))
            for a in decompile.get("attempts") or [])
        chain_bullets.append(bullet(
            "Decompilation fidelity gap — Reason: code "
            "was served by %s at %s fidelity, below "
            "source-equivalent; the difference (original "
            "names, comments, exact control flow where "
            "the rung approximated) is not recoverable "
            "from the artifact. Chain outcome: chain %s; "
            "attempts: %s; caveats: %s. Probe: re-run the "
            "analysis with the missing higher rung "
            "installed (see the attempt reasons)"
            % (decompile.get("served_by"),
               decompile.get("fidelity"),
               " -> ".join(decompile.get("chain") or []),
               attempts or "none",
               "; ".join(decompile.get("caveats") or [])),
            "decompile.json",
            "served_by = %s, fidelity = %s"
            % (decompile.get("served_by"),
               decompile.get("fidelity"))))
        spec.add_unknown(
            "decompile-fidelity",
            _reason_from_text(
                " ".join(str(a.get("reason"))
                         for a in
                         decompile.get("attempts") or [])),
            "re-run the analysis with the failed higher "
            "rung's tool installed and working",
            "decompilation served at %s fidelity by %s"
            % (decompile.get("fidelity"),
               decompile.get("served_by")),
            "decompile.json")
    else:
        chain_bullets.append(bullet(
            "No Fallback Record (decompile.json) exists "
            "in this case — Reason: the decompile chain "
            "outcome is unrecorded, so the fidelity of "
            "any code-level claim is unknown. Probe: "
            "re-run nar-analyze, which records the chain",
            "case.json", "decompile.json absent"))
        spec.add_unknown(
            "decompile-fidelity", "absent",
            "re-run nar-analyze, which records the "
            "decompile Fallback Record",
            "no Fallback Record in the case",
            "decompile.json")
    lines.extend(["## Decompile chain outcome", ""])
    lines.extend(chain_bullets)
    lines.append("")
    any_entry = True
    if not any_entry:  # defensive: the file is never empty
        lines.append(bullet(
            "No unrecoverable category produced an entry; "
            "runtime and server-side behaviour remain "
            "outside static recovery by construction",
            "case.json", "category scans completed"))
    return "\n".join(lines)


_BUILDERS = [
    ("features.md", build_features),
    ("architecture.md", build_architecture),
    ("data-model.md", build_data_model),
    ("flows.md", build_flows),
    ("assets.md", build_assets),
    ("network.md", build_network),
    ("build-order.md", build_build_order),
    ("unrecoverable.md", build_unrecoverable),
]


def build_spec(case, target_sha):
    """{filename: text} for the 8 markdown files, plus
    the unknowns document."""
    spec = Spec(case, target_sha)
    files = {}
    for name, builder in _BUILDERS:
        files[name] = builder(spec)
    # Coverage-registry gaps feed the same unknowns list
    # (the nar coverage --gap ingestion contract).
    try:
        coverage = formats_registry.build_coverage()
        for sec_name, entries in coverage.items():
            if not isinstance(entries, list):
                continue
            for e in entries:
                if e.get("status") in (
                        "identified_only", "unsupported",
                        "server_side"):
                    spec.add_unknown(
                        "coverage/%s/%s" % (sec_name,
                                            e.get("id")),
                        "server-side"
                        if e.get("status") == "server_side"
                        else _reason_from_text(
                            e.get("reason") or ""),
                        e.get("probe") or
                        "see nar coverage --gap for this "
                        "entry",
                        e.get("reason") or
                        "coverage status %s" % e.get("status"),
                        "formats.json coverage %s/%s"
                        % (sec_name, e.get("id")))
    except Exception:
        pass
    inv = case.get("investigation.json")
    for u in (inv or {}).get("unknowns") or []:
        spec.add_unknown(
            "investigation",
            _reason_from_text(u.get("reason") or ""),
            "an authorized runtime session on a device "
            "you own",
            "%s — %s" % (u.get("question"),
                         u.get("reason")),
            "investigation.json unknowns")
    unknowns_doc = {
        "version": "1",
        "generated_by": "nar-blueprint",
        "target_sha256": target_sha,
        "consumer_note": (
            "Feed contract: nar coverage --gap consumers "
            "ingest the unknowns array directly; each "
            "entry carries area, reason (closed taxonomy: "
            "encrypted | unsupported-codec | server-side | "
            "stripped | absent), probe, detail and "
            "evidence, mirroring the gap report's "
            "reason + probe pairs."),
        "unknowns": spec.unknowns,
    }
    files["unknowns.json"] = json.dumps(
        unknowns_doc, indent=2, sort_keys=True) + "\n"
    return files, unknowns_doc


def generate(target, out_dir, case_arg=None):
    """Build the spec; returns (files_written, summary)."""
    try:
        resolved = _container.resolve_target(target)
        resolved.cleanup()
    except Exception:
        pass  # advisory; the case build is authoritative
    target_sha = sha256_of(target)
    case_dir, origin = ensure_case(target, target_sha,
                                   case_arg)
    case = Case(case_dir)
    files, unknowns_doc = build_spec(case, target_sha)
    os.makedirs(out_dir, exist_ok=True)
    for name in SPEC_FILES:
        with open(os.path.join(out_dir, name), "w",
                  encoding="utf-8") as fh:
            fh.write(files[name])
    summary = {
        "target": target,
        "out": os.path.abspath(out_dir),
        "case_dir": case_dir,
        "case_origin": origin,
        "files": list(SPEC_FILES),
        "unknowns_count": len(unknowns_doc["unknowns"]),
    }
    return list(SPEC_FILES), summary


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Emit a rebuild specification from "
                    "verified case evidence (Part 8): "
                    "features, architecture, data model, "
                    "flows, assets, network, build order, "
                    "unrecoverable list and unknowns.json.")
    parser.add_argument("target",
                        help="path to the APK/AAB/container "
                             "target")
    parser.add_argument("--out", required=True,
                        metavar="DIR",
                        help="directory the 9 spec files "
                             "are written to")
    parser.add_argument("--case", metavar="DIR",
                        help="case directory to read (built "
                             "or rebuilt by nar-analyze when "
                             "missing or stale)")
    parser.add_argument("--json", action="store_true",
                        help="print a JSON summary of the "
                             "run instead of text")
    args = parser.parse_args(argv)
    if not os.path.isfile(args.target):
        print("nar-blueprint: target not found: %s"
              % args.target, file=sys.stderr)
        return 2
    _files, summary = generate(args.target, args.out,
                               case_arg=args.case)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print("nar-blueprint: wrote %d files to %s "
              "(case: %s; %s; unknowns: %d)"
              % (len(summary["files"]), summary["out"],
                 summary["case_dir"], summary["case_origin"],
                 summary["unknowns_count"]))
        for name in summary["files"]:
            print("  %s" % name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
