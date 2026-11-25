#!/usr/bin/env python3
"""nar-ask.py: the Q&A layer (Part 7).

    python3 nar-ask.py "<question>" <target> [--json]
                       [--case DIR] [--second PATH]

Answers a natural-language question about one target from the
evidence in a nar-analyze case, always in the Part 0.1 Answer
Contract shape:

    QUESTION / ANSWER / EVIDENCE / CONFIDENCE / WHY / CHAIN /
    BOUNDARY, plus REASON / PROBE / COST when the confidence is
    unknown.

Design rules (pinned by tests/unit/test_ask.py):

- Intent classification is deterministic: an ordered table of
  keyword + structural regex rules in this file. No LLM, no
  network, no runtime dependency beyond the stdlib.
- Evidence comes only from case companions. When --case DIR
  holds a case whose case.json input hash matches the target,
  its companions are read directly; a missing or stale case is
  (re)built by running nar-analyze.py into it (the analyze
  stage cache does the reuse). Without --case, a per-target
  cache directory under the system temp dir (keyed by the
  target SHA-256) is used the same way.
- Target resolution goes through narlib.container
  (ResolvedTarget), so containers and split sets work.
- Confidence mapping is fixed: a direct companion observation
  is `confirmed`; a derived/fused conclusion is
  `strongly-indicated`; heuristic or string-only evidence is
  `inferred`; no evidence is `unknown`, and an unknown answer
  always names a REASON from the closed taxonomy (encrypted /
  unsupported-codec / server-side / stripped / absent), the
  cheapest PROBE that would resolve it, and its COST.
- A bare refusal is never emitted: every question produces the
  full contract block.

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

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from narlib import container as _container  # noqa: E402
from narlib import dex as _dexlib  # noqa: E402
from narlib import formats_registry  # noqa: E402

VERSION = "3.0.1"

CONFIDENCES = ("confirmed", "strongly-indicated", "inferred",
               "unknown")
UNKNOWN_REASONS = ("encrypted", "unsupported-codec",
                   "server-side", "stripped", "absent")

#: Phrasings that must never appear as (or as the substance of)
#: an ANSWER. Pinned by test.
FORBIDDEN_ANSWER_PHRASES = (
    "i don't know", "i do not know", "cannot determine",
    "can not determine", "could not determine", "unable to "
    "determine", "no information available", "please provide "
    "more information",
)

INTENTS = ("identity", "build", "screens", "behaviour",
           "storage", "network", "security", "monetisation",
           "assets", "animation", "scripts", "rebuild", "compare",
           "gaps", "other")

# ------------------------------------------------------------------
# Intent classification: ordered rule table. The FIRST intent
# whose patterns match wins, so the order encodes precedence:
# explicit gap/compare/rebuild asks outrank topical keywords,
# and specific topics (animation, monetisation) outrank the
# generic "how does X work" behaviour pattern.
# ------------------------------------------------------------------
INTENT_RULES = [
    ("gaps", [
        r"what can you not tell me", r"what can'?t you tell me",
        r"what do you not know", r"what don'?t you know",
        r"what is unknown", r"what'?s unknown",
        r"what can you not answer", r"what can'?t you answer",
        r"unknowns?\b", r"\bgaps?\b", r"limitations?",
        r"what is missing", r"what'?s missing",
        r"not tell me", r"cannot tell me", r"can'?t tell me",
    ]),
    ("compare", [
        r"\bcompare\b", r"\bcomparison\b", r"\bdiff(erence|erences)?\b.*\bbetween\b",
        r"\bchanged between\b", r"\bwhat changed\b",
        r"\bbetween v\d", r"\bv1 and v2\b", r"\bversion diff",
        r"\bold and new\b", r"\bnewer version\b.*\bdifferent",
        r"\bdifferent between\b", r"\bhow do .* compare\b",
    ]),
    ("rebuild", [
        r"\brebuild\b", r"\bre-?build\b", r"\brebuilding\b",
        r"\brecreate\b",
        r"\bre-?create\b", r"\breimplement", r"\bre-?implement",
        r"how (do|would|can) i build", r"build my own",
        r"build an equivalent", r"build a clone",
        r"\bclone (it|this|the app|the game)\b",
        r"implementation (plan|order)", r"build order",
    ]),
    ("animation", [
        r"\banimat", r"\bspine\b", r"\blottie\b", r"\brive\b",
        r"\bdragonbones\b", r"\bskeletal\b", r"\bbones?\b.*\banimat",
        r"\bkeyframe", r"\bsprite ?sheet\b.*\banimat",
        r"how is .* animated", r"how are .* animated",
    ]),
    ("scripts", [
        r"\bscripts?\b", r"\bscripting\b", r"\blua(jit)?\b",
        r"\bhermes\b", r"\bbytecode\b", r"\bwasm\b",
        r"\bwebassembly\b", r"\bgdscript\b", r"\bpyc\b",
        r"\bpython bytecode\b", r"\bsource ?maps?\b",
        r"\bsquirrel\b", r"\bangelscript\b", r"\bpawn\b",
        r"\bcil\b", r"\bdart\b.*\b(snapshot|kernel)",
        r"\bsnapshot\b.*\bdart\b",
    ]),
    ("monetisation", [
        r"\bmonetis", r"\bmonetiz", r"\brevenue\b", r"\bpaywall\b",
        r"\bsubscription", r"\bin-?app purchas", r"\biap\b",
        r"\bbilling\b", r"\bpurchas(e|es|ed|ing)\b",
        r"\bad(s|vertising|vertisements)?\b.*\b(flow|sdk|network|shown|served)",
        r"how .* make(s)? money", r"\bpremium\b.*\b(unlock|tier|feature)",
        r"where is .* verified", r"\bads?\b",
    ]),
    ("security", [
        r"\bprotect", r"\bpacker\b", r"\bobfuscat", r"\brasp\b",
        r"\bcertificate pinning\b", r"\bpinning\b", r"\bdrm\b",
        r"\btamper", r"\broot (detect|check)", r"\banti-?tamper",
        r"static analysis (see|read|recover)",
        r"can .* see the (logic|code)", r"\bsecur(e|ity)\b",
        r"\bvulnerab", r"\bhardening\b", r"\bsignature verif",
    ]),
    ("network", [
        r"\bendpoint", r"\btalk(s|ing)? to\b", r"\bservers?\b",
        r"\bapi\b", r"\burls?\b", r"\bdomains?\b", r"\bhosts?\b",
        r"\bnetwork\b", r"\bhttps?\b", r"\bbackend\b",
        r"communicat\w+ with", r"\brequests?\b.*\b(make|send)",
        r"what does it connect to", r"\bconnect(s|ion)? to\b",
    ]),
    ("storage", [
        r"\bstored\b", r"\bstorage\b", r"\bsaved\b", r"\bsave(s|d)?\b.*\b(progress|game|data|state)",
        r"\bcoins?\b", r"\bcurrency\b.*\b(stored|kept|saved)",
        r"progress (saved|stored|kept)", r"\bdatabase\b",
        r"\bsqlite\b", r"\bshared ?preferences\b", r"\bdatastore\b",
        r"\broom\b.*\b(database|storage)", r"where .* kept",
        r"where .* stored", r"how is .* stored", r"how are .* stored",
        r"\bpersistence\b", r"\bpersist",
    ]),
    ("screens", [
        r"\bscreens?\b", r"\bactivit", r"\bnavigation\b",
        r"\bdeep ?links?\b", r"how do i get to", r"\bget to\b.*\bscreen",
        r"\buser interface\b", r"\bui\b.*\b(screen|flow)",
        r"\bpages?\b.*\b(app|game|has|have)", r"\bmenus?\b",
    ]),
    ("behaviour", [
        r"how does\b", r"how do\b", r"how is\b.*\b(work|done|handled|implemented)",
        r"\bhow\b.*\bwork(s|ing)?\b", r"what happens when",
        r"\bflow\b", r"\bbehaviou?r\b", r"\bfeature\b.*\bwork",
        r"trace\b.*\b(feature|flow)",
    ]),
    ("assets", [
        r"\bassets?\b", r"\btextures?\b", r"\bsprites?\b",
        r"\bimages?\b", r"\baudio\b", r"\bsounds?\b", r"\bmusic\b",
        r"\bfonts?\b", r"\bmodels?\b", r"\bresources?\b",
        r"files? (does|in|inside|contained)", r"\bcontent\b.*\bcontain",
        r"\bfiles?\b.*\binside\b",
        r"what'?s inside", r"what is inside",
    ]),
    ("build", [
        r"\bengine\b", r"\blanguages?\b", r"\btoolchain\b",
        r"\bframework", r"built with", r"\bkotlin\b", r"\bjava\b.*\bor\b.*\bkotlin",
        r"\bcompiler\b", r"\bsdk\b.*\b(version|level|built)",
        r"what .* made (with|in)\b", r"\btechnology\b", r"\bstack\b",
        r"how (was|is) it built\b",
        r"\bil2cpp\b", r"\bmono\b.*\bor\b",
    ]),
    ("identity", [
        r"what is this", r"what is it\b", r"\bpackage\b",
        r"\bversion\b", r"who (made|developed|built) (it|this)",
        r"\bapp name\b", r"\bname of (the|this) (app|game)",
        r"\bsize\b", r"\bidentity\b", r"\blabel\b",
        r"which app is", r"which game is",
    ]),
]

_COMPILED_RULES = [
    (intent, [re.compile(p, re.I) for p in patterns])
    for intent, patterns in INTENT_RULES
]


def classify_intent(question):
    """Deterministic intent for one question (ordered rules)."""
    text = (question or "").strip()
    for intent, patterns in _COMPILED_RULES:
        for pat in patterns:
            if pat.search(text):
                return intent
    return "other"


_SUBJECT_PATTERNS = [
    r"how does (.+?) work\b",
    r"how is (.+?) (?:stored|saved|animated|implemented|handled|verified)\b",
    r"how are (.+?) (?:stored|saved|animated)\b",
    r"where (?:are|is) (?:my |the )?(.+?) (?:stored|kept|saved)\b",
    r"how do i get to (?:the )?(.+?)(?:\?|$)",
    r"get to (?:the )?(.+?) screen",
    r"what is this (.+?) for\b",
    r"how does the (.+?) (?:feature|flow|system) work\b",
    r"\bthe (.+?) (?:feature|system|flow)\b",
]


def extract_subject(question):
    """The feature/entity a question asks about, if named."""
    text = (question or "").strip()
    for pat in _SUBJECT_PATTERNS:
        m = re.search(pat, text, re.I)
        if m:
            subject = m.group(1).strip(" ?.")
            subject = re.sub(r"^(the|my|a|an)\s+", "", subject,
                             flags=re.I)
            if 0 < len(subject) <= 60:
                return subject
    return None


# ------------------------------------------------------------------
# Case access
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
    """Run nar-analyze.py into case_dir (stage cache reuses)."""
    os.makedirs(case_dir, exist_ok=True)
    cmd = [sys.executable, os.path.join(HERE, "nar-analyze.py"),
           target, "--out", case_dir]
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=7200)
    return proc.returncode == 0


def ensure_case(target, target_sha, case_arg):
    """Return (case_dir, origin_note). Builds the case if the
    supplied/cached one is missing or stale."""
    if case_arg:
        case_dir = os.path.abspath(case_arg)
        if case_matches(case_dir, target_sha):
            return case_dir, "supplied case reused (hash match)"
        ok = run_analyze(target, case_dir)
        return case_dir, ("supplied case rebuilt by nar-analyze"
                          if ok else
                          "supplied case build attempted; "
                          "companions present are used as-is")
    cache_dir = os.path.join(tempfile.gettempdir(),
                             "nar-ask-cache", target_sha[:24])
    if case_matches(cache_dir, target_sha):
        return cache_dir, "per-target cache case reused"
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
        self.loaded = []
        self.absent = []

    def get(self, name):
        if name in self._cache:
            return self._cache[name]
        path = os.path.join(self.dir, name)
        doc = None
        if os.path.isfile(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    doc = json.load(fh)
            except (OSError, ValueError):
                doc = None
        if doc is None:
            self.absent.append(name)
        else:
            self.loaded.append(name)
        self._cache[name] = doc
        return doc

    def dex_classes(self):
        """[(class_name, [method names], [field names],
        [superclass + interfaces])] from dex.json; for very
        large dex documents a raw-text scan recovers class
        names only (methods/fields/supers empty). Supers are
        evidence: a class extending SQLiteOpenHelper or
        RoomDatabase is storage evidence even though the API
        class itself is not defined in the app."""
        if "_dex_classes" in self._cache:
            return self._cache["_dex_classes"]
        out = []
        path = os.path.join(self.dir, "dex.json")
        if os.path.isfile(path):
            self.loaded.append("dex.json")
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
                        supers.extend(
                            cls.get("interfaces") or [])
                        out.append((
                            cls.get("class") or "",
                            [m.get("name") or ""
                             for m in cls.get("methods") or []],
                            [f.get("name") or ""
                             for f in cls.get("fields") or []],
                            supers))
            else:
                with open(path, encoding="utf-8",
                          errors="replace") as fh:
                    text = fh.read()
                for name in re.findall(
                        r'"class":\s*"((?:L|I|\[)[^"]+;)"', text):
                    out.append((name, [], [], []))
        else:
            self.absent.append("dex.json")
        self._cache["_dex_classes"] = out
        return out


def _props(doc):
    return (doc or {}).get("properties") or {}


def _prop(doc, key):
    entry = _props(doc).get(key) or {}
    return entry.get("value")


def _chain_text(case, used_decompile, extra_absent=()):
    """The CHAIN field: the decompile Fallback Record when the
    answer used decompilation, else the serving companions."""
    served = sorted(set(case.loaded))
    record = case.get("decompile.json")
    if used_decompile and record:
        attempts = []
        for a in record.get("attempts") or []:
            attempts.append("%s:%s" % (a.get("rung"),
                                       a.get("status")))
        return ("java-decompile chain [%s]; served_by=%s; "
                "fidelity=%s; attempts: %s"
                % (" -> ".join(record.get("chain") or []),
                   record.get("served_by"),
                   record.get("fidelity"),
                   ", ".join(attempts) or "none"))
    absent = sorted(set(case.absent) | set(extra_absent))
    text = "companions served: %s" % (
        ", ".join(served) or "none")
    if absent:
        text += "; companions absent: %s" % ", ".join(absent)
    return text


def _answer(question, intent, answer, evidence, confidence, why,
            chain, boundary, reason=None, probe=None, cost=None):
    doc = {
        "question": question,
        "intent": intent,
        "answer": answer,
        "evidence": list(evidence),
        "confidence": confidence,
        "why": list(why),
        "chain": chain,
        "boundary": boundary,
    }
    if confidence == "unknown":
        doc["reason"] = reason or "absent"
        doc["probe"] = probe or (
            "re-run the question against a complete nar-analyze "
            "case for the target")
        doc["cost"] = cost or (
            "nar-analyze on this machine; minutes; no device "
            "required")
    return doc


def _unknown(question, intent, case, searched, reason, probe,
             cost, why, boundary, used_decompile=False):
    evidence = ["searched %s: no matching entry" % s
                for s in searched]
    return _answer(
        question, intent,
        "No static evidence in the case answers this question; "
        "the searched locations and the named reason below are "
        "the complete answer the artifact supports.",
        evidence, "unknown", why,
        _chain_text(case, used_decompile), boundary,
        reason=reason, probe=probe, cost=cost)


def _tokens(text):
    return [t for t in re.split(r"[^a-z0-9]+",
                                (text or "").lower())
            if len(t) >= 3]


def _class_simple(descriptor):
    name = (descriptor or "").strip()
    name = name.lstrip("L[").rstrip(";")
    return name.rsplit("/", 1)[-1]


# ------------------------------------------------------------------
# Answer builders (one per intent)
# ------------------------------------------------------------------
def build_identity(q, case, ctx):
    app = case.get("application.json")
    fp = case.get("fingerprint.json")
    manifest = case.get("manifest.json")
    case_doc = case.get("case.json")
    src = app if app else fp
    if not src and not manifest:
        return _unknown(
            q, "identity", case,
            ["application.json", "fingerprint.json",
             "manifest.json"], "absent",
            "run nar-analyze on the target to produce the "
            "identity companions",
            "one nar-analyze run; minutes; no device required",
            ["no identity companion exists in the case"],
            "identity facts only; behaviour is out of scope")
    evidence, why = [], []
    package = _prop(src, "package") or (manifest or {}).get(
        "package")
    label = _prop(src, "app_label")
    vname = _prop(src, "version_name")
    vcode = _prop(src, "version_code")
    min_sdk = _prop(src, "min_sdk") or (
        case.get("permissions.json") or {}).get("min_sdk")
    target_sdk = _prop(src, "target_sdk") or (
        manifest or {}).get("target_sdk")
    if package:
        evidence.append("application.json properties.package "
                        "= %s" % package)
    if label:
        evidence.append("application.json properties.app_label "
                        "= %s" % label)
    if vname is not None:
        evidence.append("application.json properties."
                        "version_name = %s (version_code %s)"
                        % (vname, vcode))
    inp = (case_doc or {}).get("input") or {}
    if inp.get("sha256"):
        evidence.append("case.json input.sha256 = %s, "
                        "size_bytes = %s"
                        % (inp["sha256"], inp.get("size_bytes")))
    if manifest:
        evidence.append("manifest.json component_counts = %s, "
                        "permission_count = %s"
                        % (manifest.get("component_counts"),
                           manifest.get("permission_count")))
    parts = []
    if label:
        parts.append("'%s'" % label)
    if package:
        parts.append("package %s" % package)
    if vname is not None:
        parts.append("version %s (code %s)" % (vname, vcode))
    if min_sdk is not None:
        parts.append("min SDK %s, target SDK %s"
                     % (min_sdk, target_sdk))
    answer = ("This target is %s." % ", ".join(parts)
              if parts else
              "Identity companions exist but carry no package "
              "or label property; the evidence list is what "
              "the case records.")
    why.append("identity properties are direct companion "
               "observations (verification_status CONFIRMED in "
               "application.json/fingerprint.json)")
    if case_doc and case_doc.get("container"):
        why.append("case.json records a container input; the "
                   "identity is the resolved base application")
    return _answer(q, "identity", answer, evidence, "confirmed",
                   why, _chain_text(case, False),
                   "identity, version and SDK levels only; "
                   "runtime behaviour and server-side state are "
                   "not covered")


def build_build(q, case, ctx):
    engines = case.get("engines.json")
    frameworks = case.get("frameworks.json")
    fp = case.get("fingerprint.json")
    dex = case.get("dex.json")
    verdicts = (engines or {}).get("verdicts") or \
        (frameworks or {}).get("verdicts") or []
    detected = [v for v in verdicts if v.get("detected")]
    markers = (frameworks or {}).get("markers") or {}
    fw_markers = markers.get("framework_markers") or \
        _prop(fp, "framework_markers") or []
    engine_versions = markers.get("engine_versions") or \
        _prop(fp, "engine_versions") or {}
    evidence, why = [], []
    for v in detected[:4]:
        inds = "; ".join(
            "%s: %s" % (i.get("kind"), i.get("detail"))
            for i in (v.get("indicators") or [])[:3])
        evidence.append("engines.json verdict %s detected, "
                        "confidence %s, score %s (%s)"
                        % (v.get("engine"), v.get("confidence"),
                           v.get("score"), inds or "no detail"))
        if v.get("jni_symbols"):
            evidence.append("engines.json verdict %s "
                            "jni_symbols matched %s symbol(s)"
                            % (v.get("engine"),
                               v["jni_symbols"].get(
                                   "match_count")))
    for m in fw_markers[:8]:
        evidence.append("frameworks.json framework marker: %s"
                        % m)
    for key, val in list(engine_versions.items())[:4]:
        evidence.append("frameworks.json engine_versions.%s "
                        "= %s" % (key, val))
    totals = (dex or {}).get("totals") or {}
    if totals:
        evidence.append("dex.json totals: %s classes, %s "
                        "methods across %s DEX file(s)"
                        % (totals.get("classes"),
                           totals.get("methods"),
                           len((dex or {}).get("dex_files")
                               or [])))
    dex_versions = _prop(fp, "dex_versions")
    if dex_versions:
        evidence.append("fingerprint.json dex_versions = %s"
                        % dex_versions)
    if not evidence:
        return _unknown(
            q, "build", case,
            ["engines.json", "frameworks.json",
             "fingerprint.json", "dex.json"], "absent",
            "run nar-analyze on the target to produce the "
            "build companions",
            "one nar-analyze run; minutes; no device required",
            ["no build companion exists in the case"],
            "build/toolchain facts only")
    if detected:
        names = ", ".join("%s (confidence %s)"
                          % (v.get("engine"), v.get("confidence"))
                          for v in detected[:3])
        answer = "Built with %s." % names
        confidence = "strongly-indicated"
        why.append("engine verdicts fuse path, DEX and JNI "
                   "symbol indicators, so the engine "
                   "conclusion is derived, not a single direct "
                   "observation")
    else:
        answer = ("No game engine was detected; the build is a "
                  "native Android application build (framework "
                  "markers and DEX evidence are listed).")
        confidence = "strongly-indicated"
        why.append("every engine verdict in engines.json is "
                   "detected:false, and the framework markers "
                   "identify the app stack instead")
    if fw_markers:
        answer += " Framework/language markers: %s." % ", ".join(
            str(m) for m in fw_markers[:6])
    if engine_versions:
        answer += " Toolchain versions: %s." % ", ".join(
            "%s=%s" % (k, v)
            for k, v in list(engine_versions.items())[:3])
    return _answer(q, "build", answer, evidence, confidence,
                   why, _chain_text(case, False),
                   "engine, language and toolchain identity "
                   "only; source-level build settings (compiler "
                   "flags, signing config) are not in the "
                   "artifact")


def _app_doc(case):
    """The Part 6 app.json companion, when the case has one."""
    try:
        return case.get("app.json")
    except Exception:
        return None


def build_screens(q, case, ctx):
    perms = case.get("permissions.json")
    manifest = case.get("manifest.json")
    app = _app_doc(case)
    if not perms and not manifest and app:
        # Part 6 deepening: the app companion carries the
        # screen map even when the manifest companions are
        # absent.
        nav = app.get("navigation") or {}
        ui = app.get("ui_frameworks") or {}
        compose = ui.get("jetpack_compose") or {}
        evidence = [
            "app.json navigation: %d activities, launcher %s, "
            "%d deep links" % (nav.get("activity_count", 0),
                               nav.get("launcher_activity"),
                               nav.get("deep_link_count", 0)),
            "app.json ui_frameworks: %d @Composable methods, "
            "%d layouts, %d fragments"
            % (compose.get("composable_method_count", 0),
               (ui.get("view_xml") or {}).get("layout_count", 0),
               nav.get("fragment_class_count", 0)),
        ]
        for entry in (app.get("screen_map") or [])[:8]:
            evidence.append("app.json screen_map %s (%s)"
                            % (entry.get("name"),
                               entry.get("kind")))
        answer = ("Screen map from nar-app (app.json): %d "
                  "activities (launcher %s), %d @Composable "
                  "methods, %d XML layouts, %d fragment "
                  "classes, %d deep links. Entries are cited "
                  "in the evidence."
                  % (nav.get("activity_count", 0),
                     nav.get("launcher_activity"),
                     compose.get("composable_method_count", 0),
                     (ui.get("view_xml") or {}).get(
                         "layout_count", 0),
                     nav.get("fragment_class_count", 0),
                     nav.get("deep_link_count", 0)))
        return _answer(
            q, "screens", answer, evidence,
            "strongly-indicated",
            ["the screen map is assembled by nar-app from "
             "the manifest, DEX annotation census and layout "
             "census of the target itself"],
            _chain_text(case, False),
            "manifest + DEX + layout evidence only; the "
            "exact tap-by-tap navigation sequence is runtime "
            "behaviour")
    if not perms and not manifest:
        return _unknown(
            q, "screens", case,
            ["permissions.json", "manifest.json"], "absent",
            "run nar-analyze on the target to produce the "
            "manifest companions",
            "one nar-analyze run; minutes; no device required",
            ["no manifest companion exists in the case"],
            "screen inventory only")
    components = (perms or {}).get("components") or {}
    activities = components.get("activity") or []
    launcher = (perms or {}).get("launcher_activity")
    evidence, why = [], []
    if launcher:
        evidence.append("permissions.json launcher_activity "
                        "= %s" % launcher)
    subject = ctx.get("subject")
    if subject:
        toks = _tokens(subject)
        hits = [a for a in activities
                if any(t in (a.get("name") or "").lower()
                       for t in toks)]
        if hits:
            for a in hits[:5]:
                filters = a.get("intent_filters") or []
                evidence.append(
                    "permissions.json component activity %s "
                    "(exported=%s, intent_filters=%s)"
                    % (a.get("name"), a.get("exported"),
                       len(filters)))
                for f in filters[:2]:
                    evidence.append(
                        "intent filter on %s: actions=%s "
                        "data=%s"
                        % (a.get("name"), f.get("actions"),
                           f.get("data")))
            answer = (
                "Screen matching '%s': %s. Entry point is the "
                "launcher activity %s; the listed component is "
                "reached in-app from there, and its manifest "
                "record (exported flag and intent filters "
                "above) is the static route evidence."
                % (subject,
                   ", ".join(a.get("name") for a in hits[:5]),
                   launcher or "(not recorded)"))
            why.append("the component name matches the asked "
                       "screen token in permissions.json")
            why.append("the launcher activity is the manifest "
                       "entry point, so every route starts "
                       "there statically")
            return _answer(
                q, "screens", answer, evidence,
                "strongly-indicated", why,
                _chain_text(case, False),
                "the exact tap-by-tap in-app navigation "
                "sequence is runtime behaviour; static "
                "evidence names the entry point and the "
                "destination component only")
        return _unknown(
            q, "screens", case,
            ["permissions.json components.activity (%d entries)"
             % len(activities)], "absent",
            "check the name against the activity list in "
            "permissions.json, or observe the screen at runtime "
            "on a device you own",
            "static: no tool needed; runtime check needs a "
            "device and minutes",
            ["no activity name contains the asked screen "
             "token '%s'" % subject],
            "screen inventory only; engine-rendered screens "
            "inside a single activity are not separate "
            "manifest components")
    counts = (perms or {}).get("component_counts") or \
        (manifest or {}).get("component_counts") or {}
    evidence.append("permissions.json component_counts = %s"
                    % counts)
    for a in activities[:10]:
        evidence.append("permissions.json component activity "
                        "%s (exported=%s)"
                        % (a.get("name"), a.get("exported")))
    deep = []
    for a in activities:
        for f in a.get("intent_filters") or []:
            data = f.get("data") or []
            if data:
                deep.append("%s -> %s" % (a.get("name"), data))
    for d in deep[:5]:
        evidence.append("deep link intent filter: %s" % d)
    answer = ("The target declares %d activities (screens), "
              "%d services, %d receivers and %d providers; the "
              "launcher screen is %s. First activities and any "
              "deep-link routes are in the evidence."
              % (counts.get("activity", len(activities)),
                 counts.get("service", 0),
                 counts.get("receiver", 0),
                 counts.get("provider", 0),
                 launcher or "(not recorded)"))
    why.append("the screen inventory is the manifest "
               "component list, a direct observation")
    boundary = ("manifest-declared screens only; screens "
                "rendered inside one activity by an engine "
                "or a web view are not separate components")
    if app:
        # Part 6 deepening from app.json: Compose screens,
        # layouts, fragments and the route map join the
        # manifest inventory.
        nav = app.get("navigation") or {}
        ui = app.get("ui_frameworks") or {}
        compose = ui.get("jetpack_compose") or {}
        evidence.append(
            "app.json navigation: %d deep links, %d routes, "
            "%d fragment classes"
            % (nav.get("deep_link_count", 0),
               nav.get("route_count", 0),
               nav.get("fragment_class_count", 0)))
        evidence.append(
            "app.json ui_frameworks: %d @Composable methods, "
            "%d XML layouts"
            % (compose.get("composable_method_count", 0),
               (ui.get("view_xml") or {}).get("layout_count", 0)))
        answer += (" nar-app adds: %d @Composable methods, "
                   "%d XML layouts, %d fragment classes and "
                   "%d deep-link routes (app.json screen map)."
                   % (compose.get("composable_method_count", 0),
                      (ui.get("view_xml") or {}).get(
                          "layout_count", 0),
                      nav.get("fragment_class_count", 0),
                      nav.get("deep_link_count", 0)))
        why.append("nar-app's DEX annotation census and "
                   "layout census deepen the manifest "
                   "inventory with in-activity screens")
        boundary = ("manifest-declared screens plus the "
                    "nar-app in-activity census (Compose, "
                    "layouts, fragments); the exact "
                    "tap-by-tap navigation sequence is "
                    "runtime behaviour")
    return _answer(q, "screens", answer, evidence, "confirmed",
                   why, _chain_text(case, False), boundary)


def _search_dex(case, subject):
    toks = _tokens(subject or "")
    hits = []
    if not toks:
        return hits
    for cls_name, methods, fields, supers in \
            case.dex_classes():
        simple = _class_simple(cls_name).lower()
        full = (cls_name + " " + " ".join(supers)).lower()
        score = sum(1 for t in toks if t in simple) * 2 + \
            sum(1 for t in toks if t in full)
        method_hits = [m for m in methods
                       if any(t in m.lower() for t in toks)]
        if score or method_hits:
            hits.append((score + len(method_hits), cls_name,
                         method_hits[:4], fields[:4]))
    hits.sort(key=lambda h: -h[0])
    return hits[:8]


def build_behaviour(q, case, ctx):
    subject = ctx.get("subject")
    inv = case.get("investigation.json")
    facts = (inv or {}).get("verified_facts") or []
    evidence, why = [], []
    hits = _search_dex(case, subject) if subject else []
    for _score, cls_name, method_hits, _f in hits:
        evidence.append("dex.json class %s (methods: %s)"
                        % (cls_name,
                           ", ".join(method_hits) or "see class"))
    fact_hits = []
    if subject:
        toks = _tokens(subject)
        for f in facts:
            blob = ("%s %s %s" % (f.get("fact"), f.get("subject"),
                                  f.get("detail"))).lower()
            if any(t in blob for t in toks):
                fact_hits.append(f)
    for f in fact_hits[:4]:
        evidence.append("investigation.json verified_fact "
                        "[%s] %s — %s"
                        % (f.get("verification_status"),
                           f.get("fact"), f.get("detail")))
    perms = case.get("permissions.json")
    comp_hits = []
    if subject and perms:
        toks = _tokens(subject)
        for kind, comps in ((perms.get("components") or {})
                            .items()):
            for c in comps or []:
                if any(t in (c.get("name") or "").lower()
                       for t in toks):
                    comp_hits.append((kind, c.get("name")))
    for kind, name in comp_hits[:4]:
        evidence.append("permissions.json component %s %s"
                        % (kind, name))
    app = _app_doc(case)
    if app and subject:
        # Part 6 deepening from app.json: data-flow edges and
        # SDK/background records that name the subject join
        # the trace.
        toks = _tokens(subject)
        flow_hits = []
        for edge in app.get("data_flow") or []:
            blob = ("%s %s %s" % (edge.get("from"),
                                  edge.get("to"),
                                  edge.get("via"))).lower()
            if any(t in blob for t in toks):
                flow_hits.append(edge)
        for edge in flow_hits[:4]:
            evidence.append("app.json data_flow %s -> %s "
                            "(via %s)"
                            % (edge.get("from"), edge.get("to"),
                               edge.get("via")))
        for sdk in app.get("sdks") or []:
            if any(t in (sdk.get("name") or "").lower()
                   for t in toks):
                evidence.append("app.json sdk %s: %s"
                                % (sdk.get("name"),
                                   sdk.get("evidence")))
    if not evidence:
        searched = ["dex.json (%d classes)"
                    % len(case.dex_classes()),
                    "permissions.json components",
                    "investigation.json verified_facts (%d)"
                    % len(facts)]
        return _unknown(
            q, "behaviour", case, searched, "absent",
            "name the feature with the vocabulary the code "
            "uses (class or component name), or observe it at "
            "runtime on a device you own",
            "static: no tool needed; runtime observation "
            "needs a device and minutes",
            ["no class, component or verified fact matches "
             "the asked subject"],
            "static tracing only; runtime behaviour is out "
            "of scope", used_decompile=True)
    trace = []
    if comp_hits:
        trace.append("component %s" % comp_hits[0][1])
    if hits:
        trace.append("class %s" % hits[0][1])
        if hits[0][2]:
            trace.append("methods %s" % ", ".join(hits[0][2]))
    if fact_hits:
        trace.append("verified effect: %s"
                     % fact_hits[0].get("fact"))
    answer = ("Static trace for '%s': %s. The chain runs "
              "component -> code -> recorded effect as far as "
              "the case evidence reaches; each link is cited "
              "in the evidence."
              % (subject or "the asked feature",
                 " -> ".join(trace) if trace else
                 "see evidence"))
    why.append("classes and components are direct DEX/"
               "manifest observations")
    if fact_hits:
        why.append("effects are investigation verified_facts "
                   "(CONFIRMED / STRONGLY_INDICATED gate), so "
                   "the fused trace is strongly-indicated")
    else:
        why.append("no verified fact covers the effect, so "
                   "the trace stops at code structure and is "
                   "strongly-indicated")
    return _answer(q, "behaviour", answer, evidence,
                   "strongly-indicated", why,
                   _chain_text(case, True),
                   "static evidence only: runtime order, "
                   "server responses and user-specific state "
                   "changes are not observable from the "
                   "artifact")


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


def build_storage(q, case, ctx):
    classes = case.dex_classes()
    evidence, why = [], []
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
            found.append(label)
            for h, via in hits[:3]:
                if via and via not in h:
                    evidence.append("dex.json class %s "
                                    "extends %s -> %s"
                                    % (h, via, label))
                else:
                    evidence.append("dex.json class %s -> %s"
                                    % (h, label))
    subject = ctx.get("subject")
    subj_hits = _search_dex(case, subject) if subject else []
    storage_subj = [h for h in subj_hits
                    if any(k in h[1].lower() for k in
                           ("prefs", "store", "save", "database",
                            "repository", "storage", "progress",
                            "wallet", "inventory", "player"))]
    for _s, cls_name, method_hits, field_hits in \
            storage_subj[:4]:
        evidence.append("dex.json class %s (methods: %s; "
                        "fields: %s)"
                        % (cls_name,
                           ", ".join(method_hits) or "-",
                           ", ".join(field_hits) or "-"))
    assets = case.get("assets.json")
    save_like = [a for a in (assets or {}).get("assets") or []
                 if re.search(r"save|playerprefs|\.sav$|"
                              r"progress", a.get("path") or "",
                              re.I)]
    for a in save_like[:4]:
        evidence.append("assets.json asset %s (type %s)"
                        % (a.get("path"), a.get("type")))
    app = _app_doc(case)
    app_storage_bits = []
    if app:
        # Part 6 deepening from app.json: prefs candidates,
        # Room/SQLite schemas of shipped databases, DataStore
        # and encrypted-storage locations.
        storage = app.get("storage") or {}
        prefs = storage.get("shared_preferences") or {}
        if prefs.get("candidate_file_names"):
            app_storage_bits.append(
                "SharedPreferences files %s"
                % (prefs["candidate_file_names"][:5],))
            evidence.append(
                "app.json storage.shared_preferences "
                "candidate_file_names = %s"
                % (prefs["candidate_file_names"][:5],))
        if prefs.get("candidate_keys"):
            evidence.append(
                "app.json storage.shared_preferences "
                "candidate_keys (co-occurrence heuristic) = %s"
                % (prefs["candidate_keys"][:8],))
        room = storage.get("room_sqlite") or {}
        for db in room.get("shipped_databases") or []:
            db_facts = db.get("facts") or {}
            tables = [t.get("name")
                      for t in db_facts.get("tables") or []]
            app_storage_bits.append(
                "shipped database %s with tables %s"
                % (db.get("file"), tables[:6]))
            evidence.append(
                "app.json shipped database %s: %s tables %s "
                "(sqlite_master page walk)"
                % (db.get("file"), db.get("status"), tables[:6]))
        if room.get("room_database_classes"):
            app_storage_bits.append(
                "Room databases %s"
                % (room["room_database_classes"][:3],))
            evidence.append(
                "app.json storage.room_sqlite "
                "room_database_classes = %s"
                % (room["room_database_classes"][:3],))
        if (storage.get("datastore") or {}).get("present"):
            app_storage_bits.append("DataStore")
        enc = app.get("encrypted_storage") or {}
        if (enc.get("sqlcipher") or {}).get("present"):
            app_storage_bits.append("SQLCipher (detected, "
                                    "never decrypted)")
        if (enc.get("encrypted_shared_preferences")
                or {}).get("present"):
            app_storage_bits.append("EncryptedSharedPreferences")
        auth = app.get("auth") or {}
        if auth.get("token_storage_locations"):
            evidence.append(
                "app.json auth.token_storage_locations = %s "
                "(mechanism names only; values never read)"
                % (auth["token_storage_locations"],))
    if not evidence:
        return _unknown(
            q, "storage", case,
            ["dex.json (%d classes scanned for storage APIs)"
             % len(classes), "assets.json save-like files"],
            "absent",
            "inspect runtime files on a device you own "
            "(app private storage), which shows the actual "
            "store files static code only implies",
            "device + minutes; static tooling already "
            "exhausted",
            ["no storage-API class and no save-like asset "
             "was found"],
            "storage mechanisms only; stored values are "
            "runtime data, not artifact content")
    answer = ("Storage mechanisms identified: %s."
              % ", ".join(found or ["(subject classes below)"]))
    if app_storage_bits:
        answer += (" From nar-app (app.json): %s."
                   % "; ".join(app_storage_bits))
        why.append("nar-app's storage census (DEX code scan "
                   "+ sqlite_master walk of shipped "
                   "databases) is direct artifact evidence")
    if subject:
        answer += (" For '%s', the subject-linked classes in "
                   "the evidence are the static storage path; "
                   "values themselves are written at runtime."
                   % subject)
    why.append("storage APIs are identified by the classes "
               "that implement them in dex.json (direct "
               "observation)")
    if storage_subj:
        why.append("the subject link is a name match between "
                   "the question and storage-shaped classes, "
                   "so that part is derived")
    confidence = "confirmed" if found and not subject else \
        "strongly-indicated"
    return _answer(q, "storage", answer, evidence, confidence,
                   why, _chain_text(case, False),
                   "which mechanism stores data is static; "
                   "the actual stored values (balances, "
                   "progress) are runtime state and are not "
                   "in the artifact")


def build_network(q, case, ctx):
    endpoints = case.get("endpoints.json")
    analysis = case.get("network-analysis.json")
    if not endpoints and not analysis:
        return _unknown(
            q, "network", case,
            ["endpoints.json", "network-analysis.json"],
            "absent",
            "run nar-analyze on the target to produce the "
            "network companions",
            "one nar-analyze run; minutes; no device required",
            ["no network companion exists in the case"],
            "static network surface only")
    eps = (endpoints or {}).get("endpoints") or []
    evidence, why = [], []
    subject = ctx.get("subject")
    named = None
    m = re.search(r"https?://[^\s\"']+|[a-z0-9.-]+\.[a-z]{2,}"
                  r"(?:/[^\s\"']*)?", q or "")
    if m:
        needle = m.group(0)
        for e in eps:
            if needle in (e.get("url") or "") or \
                    needle == e.get("host"):
                named = e
                break
    if named:
        evidence.append("endpoints.json endpoint %s "
                        "(kind %s, classification %s, "
                        "sources %s)"
                        % (named.get("url"), named.get("kind"),
                           named.get("classification"),
                           named.get("sources")))
        answer = ("Endpoint %s is classified '%s' (kind %s) "
                  "from static sources %s; that classification "
                  "is the recorded purpose evidence."
                  % (named.get("url"),
                     named.get("classification"),
                     named.get("kind"), named.get("sources")))
        why.append("the endpoint record is a direct companion "
                   "observation; its purpose classification "
                   "is a classified-pattern judgement")
        return _answer(q, "network", answer, evidence,
                       "inferred", why, _chain_text(case, False),
                       "purpose is classified from static "
                       "patterns; the live request/response "
                       "behaviour of the endpoint is runtime "
                       "and server-side")
    hosts = [h for h in (endpoints or {}).get("hosts") or []
             if "%" not in h][:10]
    for h in hosts[:6]:
        evidence.append("endpoints.json host %s" % h)
    with_host = [e for e in eps if e.get("host")][:6]
    for e in with_host:
        evidence.append("endpoints.json endpoint %s "
                        "(classification %s)"
                        % (e.get("url"),
                           e.get("classification")))
    if not with_host:
        for e in eps[:6]:
            evidence.append("endpoints.json endpoint %s "
                            "(kind %s, classification %s, "
                            "sources %s)"
                            % (e.get("url"), e.get("kind"),
                               e.get("classification"),
                               e.get("sources")))
    libs = (endpoints or {}).get("network_libraries") or []
    for lib in libs[:4]:
        evidence.append("endpoints.json network library %s"
                        % lib)
    counts = (endpoints or {}).get("classification_counts") \
        or (analysis or {}).get("classification_counts") or {}
    if counts:
        evidence.append("endpoints.json "
                        "classification_counts = %s" % counts)
    cleartext = (analysis or {}).get("cleartext") or {}
    if cleartext:
        evidence.append("network-analysis.json cleartext = "
                        "%s, pin_set_present = %s"
                        % (cleartext.get(
                            "base_cleartext_permitted"),
                           cleartext.get("pin_set_present")))
    if not evidence:
        return _unknown(
            q, "network", case,
            ["endpoints.json endpoints (%d)" % len(eps)],
            "absent",
            "observe traffic at runtime on a device you own "
            "with a proxy you control",
            "device + proxy; minutes to set up",
            ["the endpoint inventory is empty"],
            "static network surface only")
    answer = ("Static network surface: %d endpoints recorded "
              "(classification counts %s); hosts and example "
              "endpoints are cited in the evidence."
              % (len(eps), counts))
    why.append("endpoints are extracted strings and "
               "classified patterns, so purposes are "
               "inferred, not observed traffic")
    return _answer(q, "network", answer, evidence, "inferred",
                   why, _chain_text(case, False),
                   "static inventory only: which endpoints "
                   "are actually called, with what payloads, "
                   "is runtime and server-side behaviour")


def build_security(q, case, ctx):
    findings_doc = case.get("security-findings.json")
    report = case.get("report.json")
    decompile = case.get("decompile.json")
    text = (q or "").lower()
    evidence, why = [], []
    protections = (report or {}).get("protections") or []
    if "see the logic" in text or "static analysis" in text:
        totals = (case.get("dex.json") or {}).get("totals") \
            or {}
        if totals:
            evidence.append("dex.json totals: %s classes, %s "
                            "methods visible to static "
                            "analysis"
                            % (totals.get("classes"),
                               totals.get("methods")))
        if decompile:
            evidence.append("decompile.json served_by = %s, "
                            "fidelity = %s"
                            % (decompile.get("served_by"),
                               decompile.get("fidelity")))
        for p in protections[:4]:
            evidence.append("report.json protection record "
                            "%s" % p)
        if not evidence:
            return _unknown(
                q, "security", case,
                ["dex.json", "decompile.json",
                 "report.json protections"], "absent",
                "run nar-analyze on the target to produce "
                "the dex and decompile companions",
                "one nar-analyze run; minutes; no device "
                "required",
                ["no code-visibility companion exists"],
                "code visibility only")
        answer = ("Static analysis can see the code at %s "
                  "fidelity (served by %s); %s classes are "
                  "structurally visible. Native or encrypted "
                  "payloads, where present, are outside that "
                  "visibility."
                  % ((decompile or {}).get("fidelity",
                                           "structural-summary"),
                     (decompile or {}).get("served_by",
                                           "nar-dex"),
                     totals.get("classes", "the recorded")))
        why.append("visibility is a direct observation of "
                   "the decompile Fallback Record and the "
                   "DEX inventory")
        return _answer(q, "security", answer, evidence,
                       "confirmed", why,
                       _chain_text(case, True),
                       "visibility of managed code only; "
                       "native logic and encrypted payloads "
                       "need their own probes")
    findings = (findings_doc or {}).get("findings") or []
    for f in findings[:8]:
        evidence.append("security-findings.json %s %s "
                        "(severity %s, %s): %s"
                        % (f.get("id"), f.get("title"),
                           f.get("severity"),
                           f.get("verification_status"),
                           f.get("evidence")))
    for p in protections[:6]:
        evidence.append("report.json protection record %s" % p)
    try:
        coverage = formats_registry.build_coverage()
        for entry in coverage.get("protection_kinds") or []:
            evidence.append("coverage protection_kinds %s: "
                            "status %s"
                            % (entry.get("id"),
                               entry.get("status")))
    except Exception:
        pass
    packer_named = [p for p in protections
                    if isinstance(p, dict)
                    and p.get("kind") in ("packer",
                                          "commercial_packer")]
    if not findings and not protections:
        answer = ("No security findings and no protection "
                  "records were recorded for this target; "
                  "the detector coverage that produced that "
                  "negative result is cited in the evidence.")
        why.append("the negative result is the fused output "
                   "of the security stage and the protection "
                   "signature scan, so it is derived")
        return _answer(q, "security", answer, evidence,
                       "strongly-indicated", why,
                       _chain_text(case, False),
                       "absence of recorded findings is not "
                       "proof of absence of protection; "
                       "runtime-only protections are out of "
                       "static scope")
    if packer_named:
        answer = "Protection records name: %s." % ", ".join(
            str(p.get("name") or p) for p in packer_named)
    else:
        answer = ("Security posture: %d findings recorded "
                  "(severity counts %s); protection records: "
                  "%s."
                  % (len(findings),
                     (findings_doc or {}).get(
                         "severity_counts"),
                     protections if protections else
                     "none named"))
    why.append("findings are direct companion observations "
               "with their own verification_status")
    return _answer(q, "security", answer, evidence, "confirmed",
                   why, _chain_text(case, False),
                   "static findings only; server-side verdicts "
                   "(for example Play Integrity) and runtime "
                   "protections are not decided by the "
                   "artifact")


_BILLING_NEEDLES = ("billingclient", "com/android/vending",
                    "billing", "purchases", "inappbilling")
_ADS_NEEDLES = ("google/android/gms/ads", "applovin",
                "unity3d/ads", "facebook/ads", "adsdk",
                "admob", "mbridge", "vungle", "ironsource")


def build_monetisation(q, case, ctx):
    classes = case.dex_classes()
    evidence, why = [], []
    billing = [c for c, _m, _f, _s in classes
               if any(n in c.lower() for n in _BILLING_NEEDLES)]
    ads = [c for c, _m, _f, _s in classes
           if any(n in c.lower() for n in _ADS_NEEDLES)]
    for c in billing[:5]:
        evidence.append("dex.json class %s (billing/purchase "
                        "surface)" % c)
    for c in ads[:5]:
        evidence.append("dex.json class %s (advertising SDK "
                        "surface)" % c)
    perms = case.get("permissions.json")
    for p in (perms or {}).get("permissions") or []:
        name = p.get("name") or ""
        if "BILLING" in name or "AD_ID" in name or \
                "ADSERVICES" in name:
            evidence.append("permissions.json permission %s"
                            % name)
    endpoints = case.get("endpoints.json")
    for e in (endpoints or {}).get("endpoints") or []:
        url = e.get("url") or ""
        if re.search(r"ad|purchase|billing|pay", url, re.I):
            evidence.append("endpoints.json endpoint %s "
                            "(classification %s)"
                            % (url, e.get("classification")))
            if len(evidence) > 14:
                break
    if not evidence:
        return _answer(
            q, "monetisation",
            "No monetisation surface was found: no billing "
            "or purchase classes, no advertising SDK classes, "
            "no billing/ad permissions and no ad or purchase "
            "endpoints appear in the case evidence listed.",
            ["dex.json: %d classes scanned for billing/ads "
             "needles, 0 hits" % len(classes),
             "permissions.json: no BILLING / AD_ID / "
             "ADSERVICES permission",
             "endpoints.json: no ad/purchase endpoint"],
            "inferred",
            ["the negative result is a scan across three "
             "companions, each listed as evidence of absence"],
            _chain_text(case, False),
            "server-side entitlement checks and store-side "
            "catalogue data are not in the artifact; a "
            "monetisation SDK loaded dynamically at runtime "
            "would not appear statically")
    parts = []
    if billing:
        parts.append("%d billing/purchase classes" % len(billing))
    if ads:
        parts.append("%d advertising SDK classes" % len(ads))
    answer = ("Monetisation surface: %s. Concrete classes, "
              "permissions and endpoints are cited in the "
              "evidence; purchase verification itself is "
              "completed server-side by the store, which the "
              "artifact cannot show."
              % (", ".join(parts) or "see evidence"))
    why.append("SDK presence is a direct class observation; "
               "the revenue conclusion drawn from it is "
               "derived")
    return _answer(q, "monetisation", answer, evidence,
                   "strongly-indicated", why,
                   _chain_text(case, False),
                   "what is sold and at what price is "
                   "store/server data; the artifact shows the "
                   "client-side billing and ads machinery "
                   "only")


def build_assets(q, case, ctx):
    assets = case.get("assets.json")
    if not assets:
        return _unknown(
            q, "assets", case, ["assets.json"], "absent",
            "run nar-analyze on the target to produce the "
            "asset inventory",
            "one nar-analyze run; minutes; no device required",
            ["assets.json is absent from the case"],
            "asset inventory only")
    items = assets.get("assets") or []
    by_type = {}
    for a in items:
        by_type[a.get("type") or "unknown"] = \
            by_type.get(a.get("type") or "unknown", 0) + 1
    evidence = ["assets.json total_assets = %s, "
                "total_bytes = %s, by_category = %s"
                % (assets.get("total_assets"),
                   assets.get("total_bytes"),
                   assets.get("by_category"))]
    top_types = sorted(by_type.items(), key=lambda kv: -kv[1])
    for t, n in top_types[:6]:
        evidence.append("assets.json type %s: %d asset(s)"
                        % (t, n))
    for a in (assets.get("largest") or items[:5])[:5]:
        evidence.append("assets.json asset %s (type %s, "
                        "%s bytes)"
                        % (a.get("path"), a.get("type"),
                           a.get("size_bytes")))
    answer = ("The target carries %s inventoried assets "
              "(%s bytes). By type: %s."
              % (assets.get("total_assets"),
                 assets.get("total_bytes"),
                 ", ".join("%s %d" % (t, n)
                           for t, n in top_types[:6])))
    return _answer(q, "assets", answer, evidence, "confirmed",
                   ["the inventory is a direct companion "
                    "observation"],
                   _chain_text(case, False),
                   "inventory and typing only; the decoded "
                   "content of each asset class is covered "
                   "per-format by nar coverage")


_ANIM_NEEDLES = re.compile(
    r"spine|lottie|\.skel$|\.riv$|dragonbones|aseprite|"
    r"anim|_ske\.json|_tex\.json", re.I)


_ANIM_COUNT_KEYS = ("bones_count", "slots_count",
                    "animation_count", "layers_count",
                    "layer_count", "cel_count",
                    "frame_count", "frames_parsed",
                    "entity_count", "clip_count",
                    "controller_count", "node_count",
                    "armature_count", "precomp_count")


def _run_nar_anim(target):
    """Run nar-anim.py --json against the target (the
    build_rebuild runtime-detection pattern: only when the
    script exists in this tree), with a bounded timeout.
    Returns the parsed report when it names at least one
    animation system, else None — any failure, absence or
    empty result leaves the caller on the pre-Part-4
    identification behaviour, unchanged."""
    script = os.path.join(HERE, "nar-anim.py")
    if not target or not os.path.isfile(target) \
            or not os.path.isfile(script):
        return None
    try:
        proc = subprocess.run(
            [sys.executable, script, target, "--json"],
            capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        doc = json.loads(proc.stdout)
    except ValueError:
        return None
    if not isinstance(doc, dict) or not doc.get("systems"):
        return None
    return doc


def _run_nar_atlas(target):
    """Run nar-atlas.py --json against the target (same
    runtime-detection pattern as _run_nar_anim). Returns the
    parsed report when it decoded at least one atlas or
    composition, else None."""
    script = os.path.join(HERE, "nar-atlas.py")
    if not target or not os.path.isfile(target) \
            or not os.path.isfile(script):
        return None
    try:
        proc = subprocess.run(
            [sys.executable, script, target, "--json"],
            capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        doc = json.loads(proc.stdout)
    except ValueError:
        return None
    if not isinstance(doc, dict) or not (
            doc.get("atlases") or doc.get("compositions")):
        return None
    return doc


def _anim_counts_text(facts):
    return ", ".join("%s=%s" % (k, facts[k])
                     for k in _ANIM_COUNT_KEYS
                     if k in facts)


def build_animation(q, case, ctx):
    deep = _run_nar_anim(ctx.get("target"))
    if deep is not None:
        systems = deep.get("systems") or []
        compositions = deep.get("compositions") or []
        rigs = deep.get("physics_rigs") or []
        decoded = [s for s in systems
                   if s.get("status") == "decoded"]
        identified = [s for s in systems
                      if s.get("status") != "decoded"]
        evidence, why = [], []
        summaries = []
        for rec in systems[:12]:
            counts = _anim_counts_text(rec.get("facts")
                                       or {})
            summaries.append(
                "%s in %s: %s%s"
                % (rec.get("system"), rec.get("file"),
                   rec.get("status"),
                   " (%s)" % counts if counts else ""))
            evidence.append(
                "nar-anim %s %s: status %s%s"
                % (rec.get("system"), rec.get("file"),
                   rec.get("status"),
                   ", " + counts if counts else ""))
            if rec.get("status") != "decoded" \
                    and rec.get("reason"):
                evidence.append(
                    "nar-anim %s %s identified_only "
                    "reason: %s"
                    % (rec.get("system"), rec.get("file"),
                       rec["reason"]))
        for comp in compositions[:6]:
            evidence.append(
                "nar-anim composition %s: driver %s "
                "(%s), %d parts, attachment_points=%s, "
                "confidence %s"
                % (comp.get("object"), comp.get("driver"),
                   comp.get("driver_label"),
                   len(comp.get("parts") or []),
                   comp.get("attachment_points"),
                   comp.get("confidence")))
        for rig in rigs[:4]:
            evidence.append(
                "nar-anim physics rig %s: %s symbols in "
                "%s (sample %s)"
                % (rig.get("engine_guess"),
                   rig.get("symbol_count"),
                   rig.get("libraries"),
                   ", ".join((rig.get("sample") or [])[:3])))
        if decoded and identified:
            lead = ("Animation systems found by nar-anim "
                    "(%d decoded, %d identified only): "
                    % (len(decoded), len(identified)))
        elif decoded:
            lead = "Animation systems decoded by nar-anim: "
        else:
            lead = ("Animation systems identified by "
                    "nar-anim (none decoded): ")
        answer = lead + "%s." % "; ".join(summaries)
        if compositions:
            answer += (" Composition drivers: %s."
                       % "; ".join(
                           "%s -> %s (%s)"
                           % (c.get("object"),
                              c.get("driver"),
                              c.get("driver_label"))
                           for c in compositions[:6]))
        if rigs:
            answer += (" Physics rigs: %s."
                       % "; ".join(
                           "%s (%s symbols)"
                           % (r.get("engine_guess"),
                              r.get("symbol_count"))
                           for r in rigs[:4]))
        if decoded:
            why.append("nar-anim structural parsers decoded "
                       "%d of the listed systems from the "
                       "target itself, so their counts are "
                       "direct observations of the shipped "
                       "files" % len(decoded))
        if identified:
            why.append("the remaining %d system(s) were "
                       "identified only: the format was "
                       "recognised but the contents were "
                       "not decoded, so no content counts "
                       "are claimed for them"
                       % len(identified))
        if compositions:
            why.append("composition drivers rest on "
                       "decoded slot->bone attachment data "
                       "and named symbol/part evidence, so "
                       "the composition conclusion is "
                       "strongly-indicated")
        confidence = "strongly-indicated" if compositions \
            or decoded else "inferred"
        if identified:
            boundary = ("decoded at structural level: %s; "
                        "still undecoded: %s"
                        % (", ".join(s.get("system")
                                     for s in decoded)
                           or "none",
                           "; ".join(
                               "%s in %s (%s)"
                               % (s.get("system"),
                                  s.get("file"),
                                  s.get("reason"))
                               for s in identified)))
        else:
            boundary = ("every animation system found was "
                        "decoded at structural level; "
                        "animation produced procedurally in "
                        "code, and clips embedded in engine "
                        "bundles without loose animation "
                        "assets, remain outside this scan")
        chain = _chain_text(case, False) + \
            "; nar-anim.py --json deep scan: %d systems, " \
            "%d compositions" % (len(systems),
                                  len(compositions))
        return _answer(q, "animation", answer, evidence,
                       confidence, why, chain, boundary)
    atlas = _run_nar_atlas(ctx.get("target"))
    if atlas is not None:
        totals = atlas.get("totals") or {}
        # Present classified compositions first (unknown
        # last), larger groups first: the answer summarises,
        # so it leads with the informative records.
        comps = sorted(
            atlas.get("compositions") or [],
            key=lambda c: (
                c.get("classification") in (None, "unknown"),
                -len(c.get("parts") or [])))
        evidence, why = [], []
        evidence.append(
            "nar-atlas totals: %s atlases, %s frames, "
            "%s particle systems"
            % (totals.get("atlas_count"),
               totals.get("frame_count"),
               totals.get("particle_count")))
        for a in (atlas.get("atlases") or [])[:8]:
            evidence.append(
                "nar-atlas %s (%s): %s frames"
                % (a.get("source") or a.get("file"),
                   a.get("format"), a.get("frame_count")))
        comp_text = []
        for c in comps[:8]:
            parts = c.get("parts") or []
            sample = ", ".join(
                p.get("name") for p in parts[:5])
            evidence.append(
                "nar-atlas composition %s: classification "
                "%s (inferred), %d parts (%s), naming "
                "pattern %s, driver %s"
                % (c.get("object"),
                   c.get("classification"), len(parts),
                   sample, c.get("naming_pattern"),
                   c.get("driver")))
            comp_text.append(
                "%s = %s (%d parts)"
                % (c.get("object"),
                   c.get("classification"), len(parts)))
        answer = (
            "Sprite atlases decoded by nar-atlas: %s "
            "atlases, %s frames, %s particle systems. "
            "Part-group compositions inferred from frame "
            "naming: %s. nar-anim found no decodable "
            "animation-system files (Spine / Lottie / "
            "skeletal formats) in this target, so its "
            "animation is atlas/sprite-based at this "
            "evidence level."
            % (totals.get("atlas_count"),
               totals.get("frame_count"),
               totals.get("particle_count"),
               "; ".join(comp_text) or "none"))
        why.append("atlas frames are decoded from the "
                   "shipped plist/JSON/XML atlas files "
                   "themselves (direct observation); the "
                   "composition classification is inferred "
                   "from generalised frame-naming patterns "
                   "and is labelled inferred")
        why.append("nar-anim's system scan of the same "
                   "target named no animation-system "
                   "files, so no skeletal/timeline claim "
                   "is made")
        boundary = (
            "composition classification is name-based "
            "inference; atlases carry no attachment or "
            "driver data, so no skeletal or physics "
            "driver is claimed from them — a physics "
            "driver would need native symbol evidence "
            "(absent when the game library is stripped) "
            "or runtime observation")
        chain = _chain_text(case, False) + \
            "; nar-atlas.py --json deep scan: %s atlases, " \
            "%d compositions" % (totals.get("atlas_count"),
                                 len(comps))
        return _answer(q, "animation", answer, evidence,
                       "inferred", why, chain, boundary)
    assets = case.get("assets.json")
    items = (assets or {}).get("assets") or []
    evidence, why = [], []
    hits = [a for a in items
            if _ANIM_NEEDLES.search(a.get("path") or "")]
    for a in hits[:8]:
        evidence.append("assets.json asset %s (type %s) — "
                        "animation-shaped by name/extension"
                        % (a.get("path"), a.get("type")))
    coverage_note = []
    try:
        coverage = formats_registry.build_coverage()
        for entry in coverage.get("animation_systems") or []:
            coverage_note.append(entry)
            evidence.append("coverage animation_systems %s: "
                            "status %s (reason: %s)"
                            % (entry.get("id"),
                               entry.get("status"),
                               entry.get("reason")))
    except Exception:
        pass
    if not assets and not coverage_note:
        return _unknown(
            q, "animation", case,
            ["assets.json", "coverage animation_systems"],
            "absent",
            "run nar-analyze on the target to produce the "
            "asset inventory",
            "one nar-analyze run; minutes; no device required",
            ["no asset inventory and no coverage data"],
            "animation identification only")
    if hits:
        answer = ("Animation-shaped assets identified: %d "
                  "(cited). The Part 4 parsers (nar atlas / "
                  "nar anim) found no decodable atlas or "
                  "animation-system data in this target; "
                  "every system in the coverage registry is "
                  "listed with its decode status in the "
                  "evidence."
                  % len(hits))
        confidence = "inferred"
        why.append("asset identification is by file name "
                   "and extension, a heuristic signal")
    else:
        answer = ("No animation-typed assets were identified "
                  "in the asset inventory; animation may "
                  "still be produced procedurally in code or "
                  "inside engine bundles, which the inventory "
                  "does not type as animation.")
        confidence = "inferred"
        why.append("the negative result is a name/extension "
                   "scan over assets.json, a heuristic signal")
    why.append("coverage animation_systems statuses come "
               "from formats.json, the single source of "
               "truth")
    return _answer(
        q, "animation", answer, evidence, confidence, why,
        _chain_text(case, False),
        "identification only in this answer: the Part 4 "
        "parsers (nar atlas / nar anim) found no decodable "
        "atlas or animation-system data in this target, so "
        "no composition report is claimed")


_SCRIPT_COUNT_KEYS = ("version", "bytecode_version",
                      "cpython_version", "function_count",
                      "string_count", "identifier_count",
                      "token_count", "constant_count",
                      "typedef_count", "methoddef_count",
                      "code_object_count", "total_functions",
                      "public_count", "module_count_estimate")


def _run_nar_script(target):
    """Run nar-script.py --json against the target (the
    build_animation runtime-detection pattern: only when
    the script exists in this tree), with a bounded
    timeout. Returns the parsed report when it found at
    least one script file, else None — any failure,
    absence or empty result leaves the caller on the
    coverage-based fallback, unchanged."""
    script = os.path.join(HERE, "nar-script.py")
    if not target or not os.path.isfile(target) \
            or not os.path.isfile(script):
        return None
    try:
        proc = subprocess.run(
            [sys.executable, script, target, "--json"],
            capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        doc = json.loads(proc.stdout)
    except ValueError:
        return None
    if not isinstance(doc, dict) or not doc.get("files"):
        return None
    return doc


def build_scripts(q, case, ctx):
    deep = _run_nar_script(ctx.get("target"))
    if deep is not None:
        files = deep.get("files") or []
        totals = deep.get("totals") or {}
        evidence, why = [], []
        summaries = []
        for rec in files[:12]:
            facts = rec.get("facts") or {}
            counts = ", ".join(
                "%s=%s" % (k, facts[k]) for k in
                _SCRIPT_COUNT_KEYS if facts.get(k) is not None)
            summaries.append(
                "%s in %s: %s%s"
                % (rec.get("format"), rec.get("file"),
                   rec.get("status"),
                   " (%s)" % counts if counts else ""))
            evidence.append(
                "nar-script %s %s: status %s%s"
                % (rec.get("format"), rec.get("file"),
                   rec.get("status"),
                   ", " + counts if counts else ""))
            if rec.get("status") != "supported" \
                    and rec.get("reason"):
                evidence.append(
                    "nar-script %s %s identified_only "
                    "reason: %s"
                    % (rec.get("format"), rec.get("file"),
                       rec["reason"]))
        answer = ("Script & bytecode content decoded by "
                  "nar-script: %s."
                  % "; ".join(summaries))
        why.append("nar-script's structural parsers walked "
                   "the listed files in the target itself, "
                   "so their counts are direct observations "
                   "of the shipped bytecode")
        supported = [r for r in files
                     if r.get("status") == "supported"]
        identified = [r for r in files
                      if r.get("status") != "supported"]
        confidence = "strongly-indicated" if supported \
            else "inferred"
        if identified:
            boundary = (
                "decoded at structural level: %s; still "
                "undecoded: %s. Bytecode is reported "
                "structurally, never as source"
                % (", ".join(r.get("format")
                             for r in supported) or "none",
                   "; ".join(
                       "%s in %s (%s)"
                       % (r.get("format"), r.get("file"),
                          r.get("reason"))
                       for r in identified)))
        else:
            boundary = ("every script file found was parsed "
                        "at structural level; bytecode is "
                        "reported structurally (headers, "
                        "counts, string pools), never as "
                        "source code")
        chain = _chain_text(case, False) + \
            "; nar-script.py --json deep scan: %d files, " \
            "by_format %s" % (len(files),
                              totals.get("by_format"))
        return _answer(q, "scripts", answer, evidence,
                       confidence, why, chain, boundary)
    evidence, why = [], []
    coverage_note = []
    try:
        coverage = formats_registry.build_coverage()
        for entry in coverage.get("script_formats") or []:
            coverage_note.append(entry)
            evidence.append("coverage script_formats %s: "
                            "status %s (reason: %s)"
                            % (entry.get("id"),
                               entry.get("status"),
                               entry.get("reason")))
    except Exception:
        pass
    if not coverage_note:
        return _unknown(
            q, "scripts", case,
            ["coverage script_formats"], "absent",
            "run nar-analyze on the target to produce a "
            "case, or run nar script on the target directly",
            "one nar script run; seconds; no device "
            "required",
            ["no script scan and no coverage data"],
            "script identification only")
    answer = ("nar-script found no script-bearing files "
              "in this target; the coverage registry's "
              "per-format statuses are listed in the "
              "evidence. Script logic may still ship as "
              "DEX or native code, which this intent does "
              "not census.")
    why.append("the negative result is nar-script's scan "
               "of the target's members, a direct "
               "observation of the shipped files")
    why.append("coverage script_formats statuses come "
               "from formats.json, the single source of "
               "truth")
    return _answer(
        q, "scripts", answer, evidence, "inferred", why,
        _chain_text(case, False),
        "identification only in this answer: nar-script "
        "found no decodable script files in this target, "
        "so no per-file counts are claimed")


def build_rebuild(q, case, ctx):
    blueprint_script = os.path.join(HERE, "nar-blueprint.py")
    if os.path.isfile(blueprint_script):
        out_dir = os.path.join(case.dir, "blueprint")
        proc = subprocess.run(
            [sys.executable, blueprint_script, ctx["target"],
             "--out", out_dir],
            capture_output=True, text=True, timeout=7200)
        files = sorted(os.listdir(out_dir)) \
            if os.path.isdir(out_dir) else []
        evidence = ["nar-blueprint.py run exit %s; files: %s"
                    % (proc.returncode, ", ".join(files))]
        feats = os.path.join(out_dir, "features.md")
        summary = ""
        if os.path.isfile(feats):
            with open(feats, encoding="utf-8",
                      errors="replace") as fh:
                lines = [ln.strip() for ln in fh
                         if ln.strip().startswith(("-", "#"))]
            summary = "; ".join(lines[:8])
            evidence.append("blueprint/features.md entries: "
                            "%s" % summary)
        answer = ("Rebuild specification generated by nar "
                  "blueprint into the case blueprint "
                  "directory (%s). Feature summary: %s"
                  % (", ".join(files) or "no files",
                     summary or "see features.md"))
        return _answer(q, "rebuild", answer, evidence,
                       "strongly-indicated",
                       ["the specification is assembled from "
                        "verified case evidence by "
                        "nar-blueprint"],
                       _chain_text(case, False),
                       "the spec describes behaviour and "
                       "architecture for an original "
                       "implementation; it does not license "
                       "copying proprietary assets or code")
    # nar-blueprint not in this tree yet (Part 8): assemble
    # the summary from the case itself.
    evidence, why = [], []
    build = build_build(q, case, ctx)
    evidence.extend(build["evidence"][:4])
    inv = case.get("investigation.json")
    facts = (inv or {}).get("verified_facts") or []
    features = []
    for f in facts[:10]:
        features.append(f.get("fact"))
        evidence.append("investigation.json verified_fact "
                        "[%s] %s"
                        % (f.get("verification_status"),
                           f.get("fact")))
    storage = build_storage(q, case, ctx)
    if storage["confidence"] != "unknown":
        evidence.extend(storage["evidence"][:3])
    network = build_network(q, case, ctx)
    if network["confidence"] != "unknown":
        evidence.extend(network["evidence"][:3])
    if not evidence:
        return _unknown(
            q, "rebuild", case,
            ["engines.json", "investigation.json",
             "dex.json", "endpoints.json"], "absent",
            "run nar-analyze on the target to produce a "
            "complete case first",
            "one nar-analyze run; minutes; no device "
            "required",
            ["no companion carries rebuild evidence"],
            "rebuild summary only")
    answer = ("Rebuild summary from verified evidence: "
              "build stack per the engine/framework evidence; "
              "verified features: %s; storage and network "
              "summaries are cited in the evidence. Suggested "
              "build order: (1) shell + navigation from the "
              "manifest components, (2) core features in "
              "verified-fact order, (3) storage layer, "
              "(4) network layer, (5) monetisation and "
              "security posture."
              % ("; ".join(str(f) for f in features[:6])
                 or "see evidence"))
    why.append("every element of the summary traces to a "
               "case companion cited in the evidence")
    why.append("the assembly is a derived fusion across "
               "companions, so it is strongly-indicated")
    return _answer(
        q, "rebuild", answer, evidence, "strongly-indicated",
        why, _chain_text(case, False),
        "summary only: the full rebuild specification "
        "(features, architecture, data model, flows, "
        "build order, unrecoverable list) is produced by "
        "nar blueprint (Part 8), which is not in this tree "
        "yet; server-side logic stays unrecoverable either "
        "way")


def build_compare(q, case, ctx):
    paths = list(ctx.get("extra_targets") or [])
    if ctx.get("second"):
        paths.append(ctx["second"])
    for token in re.findall(r"[^\s\"']+\.(?:apk|aab|xapk|"
                            r"apkm|apks)", q or ""):
        if os.path.isfile(token):
            paths.append(token)
    ordered = []
    for p in [ctx["target"]] + paths:
        if p and os.path.abspath(p) not in \
                [os.path.abspath(x) for x in ordered]:
            ordered.append(p)
    if len(ordered) < 2:
        return _unknown(
            q, "compare", case,
            ["question text and target argument: one "
             "artifact located (%s)" % ctx["target"]],
            "absent",
            "supply the second artifact path as an extra "
            "argument (nar ask \"<question>\" old.apk "
            "new.apk) — a comparison needs two artifacts",
            "no tooling and no device; seconds once the "
            "second path is supplied",
            ["only one artifact path was supplied, so no "
             "diff can be computed"],
            "comparison only; single-target questions are "
            "served by the other intents")
    old, new = ordered[0], ordered[1]
    out_dir = os.path.join(case.dir, "ask-compare")
    os.makedirs(out_dir, exist_ok=True)
    proc = subprocess.run(
        [sys.executable, os.path.join(HERE, "nar-compare.py"),
         old, new, "--json", "--out", out_dir],
        capture_output=True, text=True, timeout=3600)
    try:
        doc = json.loads(proc.stdout)
    except ValueError:
        doc = None
    if doc is None:
        return _unknown(
            q, "compare", case,
            ["nar-compare.py output for %s vs %s"
             % (old, new)], "absent",
            "run nar-compare.py on the pair directly to "
            "see its error output",
            "one nar-compare run; seconds; no device "
            "required",
            ["nar-compare.py exited %s without a JSON "
             "report" % proc.returncode],
            "comparison only")
    evidence, why = [], []
    ident = doc.get("identity") or {}
    evidence.append("nar-compare identity: %s" % ident)
    for key in ("summary", "counts", "similarity"):
        if doc.get(key) is not None:
            evidence.append("nar-compare %s: %s"
                            % (key, doc[key]))
    for key in ("dex", "native", "assets", "entries"):
        sub = doc.get(key)
        if isinstance(sub, dict):
            evidence.append("nar-compare %s: %s"
                            % (key, {k: sub[k] for k in
                                      list(sub)[:6]}))
    if not evidence:
        evidence.append("nar-compare report keys: %s"
                        % sorted(doc.keys()))
    answer = ("Comparison of the two supplied artifacts "
              "completed; identity and per-dimension "
              "differences are cited in the evidence (full "
              "report written under the case ask-compare "
              "directory).")
    why.append("the diff is computed by nar-compare.py "
               "from both artifacts directly")
    return _answer(q, "compare", answer, evidence,
                   "confirmed", why, _chain_text(case, False),
                   "structural diff only; behavioural "
                   "equivalence of changed code is not "
                   "decided by a static diff")


def build_gaps(q, case, ctx):
    evidence, why = [], []
    gaps = []
    try:
        coverage = formats_registry.build_coverage()
        for section, entries in coverage.items():
            if not isinstance(entries, list):
                continue
            for e in entries:
                if e.get("status") != "supported":
                    gaps.append((section, e))
        evidence.append("coverage registry: %d non-supported "
                        "entries across %d sections"
                        % (len(gaps),
                           len({s for s, _e in gaps})))
        for section, e in gaps[:12]:
            evidence.append("coverage gap %s/%s: status %s; "
                            "reason: %s; probe: %s"
                            % (section, e.get("id"),
                               e.get("status"), e.get("reason"),
                               e.get("probe")))
    except Exception:
        pass
    inv = case.get("investigation.json")
    for u in (inv or {}).get("unknowns") or []:
        evidence.append("investigation.json unknown: %s — %s"
                        % (u.get("question"), u.get("reason")))
    report = case.get("report.json")
    for lim in (report or {}).get("limitations") or []:
        evidence.append("report.json limitation: %s" % lim)
    if not evidence:
        return _unknown(
            q, "gaps", case,
            ["coverage registry", "investigation.json "
             "unknowns", "report.json limitations"], "absent",
            "run nar coverage --gap and nar-analyze on the "
            "target",
            "seconds for coverage; minutes for analyze; no "
            "device required",
            ["no gap source produced entries"],
            "gap enumeration only")
    answer = ("Named gaps: %d coverage entries are not "
              "fully supported (each with reason and probe "
              "in the registry), plus the case-level "
              "unknowns and limitations cited in the "
              "evidence. Runtime behaviour and server-side "
              "verdicts are the standing static-analysis "
              "boundary."
              % len(gaps))
    why.append("gaps are enumerated from the coverage "
               "registry (formats.json) and the case's own "
               "unknowns, both direct observations")
    return _answer(q, "gaps", answer, evidence, "confirmed",
                   why, _chain_text(case, False),
                   "the gap list is complete for registered "
                   "coverage and this case; unregistered "
                   "format families would appear as "
                   "unsupported input, not as a named entry")


def build_other(q, case, ctx):
    inv = case.get("investigation.json")
    facts = (inv or {}).get("verified_facts") or []
    toks = _tokens(q)
    hits = [f for f in facts
            if any(t in ("%s %s %s" % (f.get("fact"),
                                       f.get("subject"),
                                       f.get("detail"))).lower()
                   for t in toks)]
    if hits:
        evidence = ["investigation.json verified_fact [%s] "
                    "%s — %s"
                    % (f.get("verification_status"),
                       f.get("fact"), f.get("detail"))
                    for f in hits[:6]]
        answer = ("Matched verified facts: %s."
                  % "; ".join(str(f.get("fact"))
                              for f in hits[:4]))
        return _answer(q, "other", answer, evidence,
                       "strongly-indicated",
                       ["the question matched verified facts "
                        "in investigation.json by keyword"],
                       _chain_text(case, False),
                       "keyword-matched facts only; a more "
                       "specific question shape routes to a "
                       "dedicated intent")
    ident = build_identity(q, case, ctx)
    if ident["confidence"] != "unknown":
        ident["intent"] = "other"
        ident["answer"] = ("No dedicated intent matched the "
                           "question; the case identity "
                           "summary is the grounded answer "
                           "available: " + ident["answer"])
        ident["boundary"] = ("general fallback: identity "
                             "summary only; rephrase with a "
                             "topic keyword (engine, screen, "
                             "storage, network, security, "
                             "assets, animation) for a "
                             "dedicated answer")
        return ident
    return _unknown(
        q, "other", case,
        ["investigation.json verified_facts",
         "application.json", "fingerprint.json",
         "manifest.json"], "absent",
        "rephrase with a topic keyword (engine, screen, "
        "storage, network, security, assets, animation, "
        "scripts, rebuild), or run nar-analyze to complete "
        "the case",
        "no device; seconds to rephrase, minutes for a "
        "fresh analyze",
        ["no intent rule matched and no verified fact or "
         "identity property matched the question"],
        "general fallback only")


BUILDERS = {
    "identity": build_identity,
    "build": build_build,
    "screens": build_screens,
    "behaviour": build_behaviour,
    "storage": build_storage,
    "network": build_network,
    "security": build_security,
    "monetisation": build_monetisation,
    "assets": build_assets,
    "animation": build_animation,
    "scripts": build_scripts,
    "rebuild": build_rebuild,
    "compare": build_compare,
    "gaps": build_gaps,
    "other": build_other,
}

#: Companions each intent needs (documentation + the
#: question library's module vocabulary).
INTENT_MODULES = {
    "identity": ["case", "manifest", "application",
                 "fingerprint"],
    "build": ["engines", "frameworks", "fingerprint", "dex"],
    "screens": ["permissions", "manifest"],
    "behaviour": ["dex", "permissions", "investigation",
                  "decompile"],
    "storage": ["dex", "assets"],
    "network": ["endpoints", "network-analysis"],
    "security": ["security-findings", "report", "decompile",
                 "coverage"],
    "monetisation": ["dex", "endpoints", "permissions"],
    "assets": ["assets"],
    "animation": ["assets", "coverage"],
    "scripts": ["coverage"],
    "rebuild": ["engines", "frameworks", "investigation",
                "dex", "endpoints", "blueprint"],
    "compare": ["compare"],
    "gaps": ["coverage", "investigation", "report"],
    "other": ["investigation", "application", "fingerprint"],
}


def answer_question(question, target, case_dir, second=None,
                    extra_targets=()):
    intent = classify_intent(question)
    case = Case(case_dir)
    ctx = {"subject": extract_subject(question),
           "target": target, "second": second,
           "extra_targets": list(extra_targets)}
    builder = BUILDERS[intent]
    doc = builder(question, case, ctx)
    doc["target"] = target
    doc["case_dir"] = case_dir
    return doc


def render_human(doc):
    lines = ["QUESTION: %s" % doc["question"],
             "ANSWER: %s" % doc["answer"],
             "EVIDENCE:"]
    lines += ["  - %s" % e for e in doc["evidence"]]
    lines.append("CONFIDENCE: %s" % doc["confidence"])
    lines.append("WHY:")
    lines += ["  - %s" % w for w in doc["why"]]
    lines.append("CHAIN: %s" % doc["chain"])
    lines.append("BOUNDARY: %s" % doc["boundary"])
    if doc["confidence"] == "unknown":
        lines.append("REASON: %s" % doc["reason"])
        lines.append("PROBE: %s" % doc["probe"])
        lines.append("COST: %s" % doc["cost"])
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Answer a question about a target from "
                    "its nar-analyze case evidence (Part 7 "
                    "Answer Contract).")
    parser.add_argument("question",
                        help="the question, in quotes")
    parser.add_argument("target",
                        help="path to the APK/AAB/container "
                             "target")
    parser.add_argument("extra", nargs="*",
                        help="extra artifact path(s), used "
                             "by compare questions")
    parser.add_argument("--json", action="store_true",
                        help="emit the answer document as JSON "
                             "(schemas/ask.schema.json)")
    parser.add_argument("--case", metavar="DIR",
                        help="case directory to read (built "
                             "or rebuilt by nar-analyze when "
                             "missing or stale)")
    parser.add_argument("--second", metavar="PATH",
                        help="second artifact path for "
                             "compare questions")
    args = parser.parse_args(argv)
    if not os.path.isfile(args.target):
        print("nar-ask: target not found: %s" % args.target,
              file=sys.stderr)
        return 2
    try:
        resolved = _container.resolve_target(args.target)
        resolved.cleanup()
    except Exception:
        pass  # resolution is advisory; the case build is the
        # authoritative path and reports its own failures.
    target_sha = sha256_of(args.target)
    case_dir, _origin = ensure_case(args.target, target_sha,
                                    args.case)
    doc = answer_question(args.question, args.target, case_dir,
                          second=args.second,
                          extra_targets=args.extra)
    if args.json:
        print(json.dumps(doc, indent=2, sort_keys=True))
    else:
        print(render_human(doc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
