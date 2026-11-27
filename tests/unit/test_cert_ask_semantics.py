"""Certification Wave 3: semantic tests for `nar ask`
(F-01, F-02, F-05, F-10 of ANNEX_FG_READINESS_PLANS F.3).

These are CI-shaped SUBSETS of the Phase 5 entry criteria, run
against ONE frozen analysed case: the synthetic mini case built
by tests/unit/test_ask.py's make_mini_case helper (the smallest
case the existing infrastructure already builds; no parallel
case pipeline is invented here). Subset sizes vs the full
criteria, stated honestly:

  F-01 full: >=100 unseen questions, >=5 per intent x 15
       intents, >=3 frozen cases.
       HERE: 60 authored unseen questions (42 in the passing
       set, 18 recorded as newly-classified candidates) across
       all 15 intents, on 1 frozen case. NF-04 fix: all 18
       candidates converted to the passing set (60/60).
  F-02 full: >=180 paraphrases (60 library questions x 3).
       HERE: 60 paraphrases (20 library questions x 3, 14
       intent families); 30 pass, 30 are candidates. NF-04
       fix: all 30 candidates converted (60/60).
  F-05 full: >=4 planted cases + >=20 aimed questions.
       HERE: 5 planted cases + 14 aimed questions. Observed
       behaviour (probed BEFORE assertions were written):
       0/14 answers surface the conflict; every aimed answer
       silently asserts one side. The conflict-surfacing
       assertions are therefore encoded as xfail(strict=True)
       candidates -- NO assertion in this file codifies a
       silent pick as correct behaviour.
  F-10 full: >=150 human-scored answers.
       HERE: a deterministic scorer over >=40 answers (the
       F-01/F-02 pool plus library questions on the same
       frozen case; ~120 answers in practice). The scorer is
       deterministic, not human; the sample is one case, not
       stratified across cases.

Method notes:
- Non-membership (F-01/F-02 paraphrases are NOT in
  references/question-library.json) is verified
  programmatically in test_f01_f02_membership below, on exact
  and case-normalised text.
- Ground truth was frozen from the mini case's companions
  (package com.example.synthetic, label Synthetic, version
  1.0/1, FakeEngine + Kotlin, 1 activity MainActivity,
  SharedPreferences + SQLite storage, api.example.com /
  OkHttp, 1 high Debuggable finding, bytecode-listing via
  nar-dex-disasm, 2 assets / 100 bytes, hero_spine.json
  animation-shaped asset, wallet verified fact, 51
  non-supported coverage entries) BEFORE the passing/xfail
  split was made. The split follows observed behaviour only
  in WHICH registry an item sits in; no expected intent or
  fact was edited to fit the product.

PHASE 5 DELIBERATE RE-BASELINE (2026-11-26) — the ONLY
sanctioned expectation change in this file. The formats
registry now registers the gif, pag and android-view
animation systems (the Phase 2 M2-10 registration, landed
in ca21b29 and reverted in 4fb4c64 precisely so it could be
re-baselined here, not mid-round). gif and android-view are
"supported"; pag is "partial" (identified-only), so the
registry's non-supported count — which the gaps builder
counts live from the registry, and which the F-10 scorer
below recounts dynamically — moves 50 -> 51. The four
frozen "50 coverage entries" expectation sites (two F-01
gaps entries, one converted F-01 gaps entry, the F-02 gaps
family record that also feeds its three paraphrases) were
each individually reviewed against the new registry state
and updated to "51 coverage entries"; the seven affected
tests are exactly the ones that failed on the registration
commit. No other expectation in this file changed, and no
product code changed to meet an expectation: the product
was already answering with the registry-true count.
- Candidate items assert the CORRECT behaviour under
  xfail(strict=True): the suite stays green while the defect
  stands, and turns red (XPASS) when the product is fixed,
  forcing reclassification into the passing set.
"""
import ast
import importlib.util
import json
import os
import re
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

_spec = importlib.util.spec_from_file_location(
    "test_ask_helpers_cert", ROOT / "tests" / "unit" / "test_ask.py")
_helpers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_helpers)
ask = _helpers.ask
make_mini_case = _helpers.make_mini_case

from narlib import formats_registry  # noqa: E402

LIB = json.loads((ROOT / "references" / "question-library.json")
                 .read_text(encoding="utf-8"))
LIB_BY_Q = {r["question"]: r for r in LIB["questions"]}
LIB_SET = set(LIB_BY_Q)
LIB_NORM = {q.strip().lower() for q in LIB_SET}

# ------------------------------------------------------------------
# Registries. Entry shape:
#   q: question text
#   intent: frozen expected intent
#   facts: headline fact tokens that must appear
#   scope: where facts are checked -- "answer", "evidence"
#          or "either" (answer + evidence joined)
#   ev_facts: extra tokens that must appear in evidence
#   unknown: expected unknown reason (answer must be a
#          contract-complete unknown with this reason);
#          None for non-unknown expectations
# ------------------------------------------------------------------


def E(q, intent, facts=(), scope="answer", ev_facts=(),
      unknown=None):
    return {"q": q, "intent": intent, "facts": list(facts),
            "scope": scope, "ev_facts": list(ev_facts),
            "unknown": unknown}


F01_PASS = [
    # identity (4)
    E("Under what package identifier does this target ship?",
      "identity", ["com.example.synthetic"]),
    E("Can you give me the label and release of this program?",
      "identity", ["Synthetic", "1.0"]),
    E("Tell me the identity of this software: its designation, "
      "identifier and release.",
      "identity", ["com.example.synthetic"]),
    E("What version is installed here, and what is it called?",
      "identity", ["Synthetic", "1.0"]),
    # build (3)
    E("Which runtime technology powers this title?",
      "build", ["FakeEngine"]),
    E("Is this a Kotlin program or a Java program?",
      "build", ["FakeEngine", "Kotlin"]),
    E("Name the game-making technology sitting underneath "
      "this title.", "build", ["FakeEngine"]),
    # screens (3; one expected unknown)
    E("How many activities are declared, and which one "
      "launches first?", "screens",
      ["com.example.MainActivity", "1 activities"]),
    E("List every activity the manifest declares, starting "
      "with the launcher.", "screens",
      ["com.example.MainActivity"]),
    E("How do I get to the leaderboard screen?", "screens",
      unknown="absent"),
    # storage (4)
    E("Through which on-device repository does my money "
      "balance persist?", "storage",
      ["SharedPreferences", "SQLite"]),
    E("In what form is the player's hoard stored between "
      "launches?", "storage", ["SharedPreferences"]),
    E("What on-device persistence keeps user data across "
      "restarts?", "storage",
      ["SharedPreferences", "SQLite"]),
    E("How does saving coins work in practice?", "storage",
      ["SharedPreferences"], ev_facts=["CoinWallet"]),
    # network (3)
    E("Name the remote host this software contacts.",
      "network", ["api.example.com"], scope="either"),
    E("What URLs are embedded in the binary?",
      "network", ["api.example.com"], scope="either"),
    E("What backend does it rely on for its coin data?",
      "network", ["api.example.com"], scope="either"),
    # security (4)
    E("Tell me the hardening posture of this binary.",
      "security", ["1 findings"],
      ev_facts=["Debuggable build"]),
    E("What weaknesses did the security scan record?",
      "security", ["1 findings"],
      ev_facts=["Debuggable build"]),
    E("Detail the recorded security problem and how serious "
      "it is.", "security", ["1 findings"],
      ev_facts=["Debuggable build", "high"]),
    E("Can a static analysis see the code paths?",
      "security", ["bytecode-listing", "nar-dex-disasm"]),
    # monetisation (3)
    E("Are ads shown to players in this title?",
      "monetisation", ["advertising"], ev_facts=["AdView"]),
    E("How does the billing flow work?", "monetisation",
      ["billing/purchase"], ev_facts=["BillingClient"]),
    E("Is there a paywall anywhere in this program?",
      "monetisation", ["billing/purchase"],
      ev_facts=["BillingClient"]),
    # assets (3)
    E("What media and data files does the package ship "
      "inside?", "assets",
      ["2 inventoried assets", "100 bytes"]),
    E("Give me an inventory count of the packaged resources.",
      "assets", ["2 inventoried assets"]),
    E("Tell me the total footprint of the bundled asset "
      "collection.", "assets",
      ["2 inventoried assets", "100 bytes"]),
    # animation (2)
    E("Describe the animation setup for the hero sprite.",
      "animation", ["Animation-shaped assets identified: 1"],
      ev_facts=["hero_spine.json"]),
    E("Which skeletal system, if any, moves the characters?",
      "animation", ["Animation-shaped assets identified: 1"],
      ev_facts=["hero_spine.json"]),
    # scripts (3)
    E("Does the package embed any Lua code?", "scripts",
      ["found no script-bearing files"]),
    E("Any sign of Hermes or WebAssembly in the package?",
      "scripts", ["found no script-bearing files"]),
    E("What bytecode formats beyond DEX ship inside?",
      "scripts", ["found no script-bearing files"]),
    # behaviour (3; one expected unknown)
    E("How does the wallet feature operate under the hood?",
      "behaviour", ["CoinWallet"],
      ev_facts=["Coins are kept in the wallet"]),
    E("How does the prefs store work?", "behaviour",
      ["PrefsStore"]),
    E("How does teleportation work?", "behaviour",
      unknown="absent"),
    # gaps (2) — count re-baselined 50 -> 51 in the Phase 5
    # registry re-baseline (see module docstring).
    E("What is missing from your picture of this target?",
      "gaps", ["51 coverage entries"]),
    E("Summarise the limitations that bound this analysis.",
      "gaps", ["51 coverage entries"]),
    # compare (1; expected contract-complete unknown)
    E("Has anything changed between the first release and "
      "this one?", "compare", unknown="absent"),
    # rebuild (2)
    E("Could you rebuild this software from its evidence, "
      "and in what order?", "rebuild",
      ["Rebuild specification generated"]),
    E("What is the build order for reconstructing the whole "
      "program?", "rebuild",
      ["Rebuild specification generated"]),
    # other (2)
    E("What is the wallet?", "other",
      ["Coins are kept in the wallet"]),
    E("Describe the wallet in detail.", "other",
      ["Coins are kept in the wallet"]),
    # Converted from F01_XFAIL by the NF-04 fix (general
    # classifier lexicon/stem rules and the build_other
    # stopword + relevance bar; no expected intent or fact
    # was changed in the move).
    E("Which application am I looking at here?", "identity",
      ["com.example.synthetic"]),
    E("What was this constructed on top of?", "build",
      ["FakeEngine"]),
    E("Enumerate the declared interface components for me.",
      "screens", ["com.example.MainActivity"]),
    E("By what mechanism does the program keep the player's "
      "balance between sessions?", "storage",
      ["SharedPreferences"]),
    E("Where does the balance live when the program is "
      "closed?", "storage", ["SharedPreferences"]),
    E("To which machine on the internet does this program "
      "send its traffic?", "network", ["api.example.com"],
      scope="either"),
    E("List the destinations this program phones home to.",
      "network", ["api.example.com"], scope="either"),
    E("Does this title carry advertising?", "monetisation",
      ["advertising"]),
    E("How does this program earn its keep?", "monetisation",
      ["billing/purchase"]),
    E("Does the program charge for extra content through "
      "the store?", "monetisation", ["billing/purchase"]),
    E("Which purchasable-offer machinery is embedded in "
      "the code?", "monetisation", ["billing/purchase"]),
    E("Walk me through recreating this program from "
      "scratch.", "rebuild",
      ["Rebuild specification generated"]),
    E("What movement technology drives the hero figure?",
      "animation", ["Animation-shaped assets identified: 1"]),
    E("How does the hero figure move on screen?", "animation",
      ["Animation-shaped assets identified: 1"]),
    E("Are any interpreted-language programs bundled with "
      "this target?", "scripts",
      ["found no script-bearing files"]),
    E("What would differ if a newer release were placed "
      "beside this one?", "compare", unknown="absent"),
    E("If I handed you a second build alongside this one, "
      "could you contrast them?", "compare", unknown="absent"),
    E("Where does your knowledge of this target run out?",
      "gaps", ["51 coverage entries"]),  # Phase 5 re-baseline
]

# Newly-classified candidates exposed by the F-01 probe.
# Classification for every entry: Accuracy Defect candidate
# (P1 shape per Annex F F-02/F-05 reasoning: a misroute that
# yields a confident, non-responsive answer counts double).
# `observed` records the probed behaviour verbatim in short.
# NF-04 FIX: all 18 candidates were converted into F01_PASS
# above by general classifier/matcher rules; the registry is
# empty and F01_OBSERVED is kept as the pre-fix record.
F01_XFAIL = []
F01_OBSERVED = {
    "Which application am I looking at here?":
        "intent other (identity facts via fallback, confirmed)",
    "What was this constructed on top of?":
        "intent other (identity fallback, confirmed)",
    "Enumerate the declared interface components for me.":
        "intent other; wallet verified-fact answer, "
        "strongly-indicated, non-responsive",
    "By what mechanism does the program keep the player's "
    "balance between sessions?":
        "intent other; wallet verified-fact answer",
    "Where does the balance live when the program is closed?":
        "intent other; wallet verified-fact answer",
    "To which machine on the internet does this program "
    "send its traffic?":
        "intent other; wallet verified-fact answer",
    "List the destinations this program phones home to.":
        "intent other; wallet verified-fact answer",
    "Does this title carry advertising?":
        "intent other (identity fallback, confirmed)",
    "How does this program earn its keep?":
        "intent behaviour; unknown/absent instead of the "
        "monetisation surface",
    "Does the program charge for extra content through "
    "the store?":
        "intent other; wallet verified-fact answer",
    "Which purchasable-offer machinery is embedded in "
    "the code?":
        "intent other; wallet verified-fact answer",
    "Walk me through recreating this program from scratch.":
        "intent other; 'recreating' misses the rebuild rule",
    "What movement technology drives the hero figure?":
        "intent build (technology keyword wins)",
    "How does the hero figure move on screen?":
        "intent screens (screen keyword wins)",
    "Are any interpreted-language programs bundled with "
    "this target?":
        "intent build (language keyword wins)",
    "What would differ if a newer release were placed "
    "beside this one?":
        "intent other (identity fallback, confirmed)",
    "If I handed you a second build alongside this one, "
    "could you contrast them?":
        "intent other (identity fallback, confirmed)",
    "Where does your knowledge of this target run out?":
        "intent other (identity fallback, confirmed)",
}

# ------------------------------------------------------------------
# F-02: paraphrases. Canonical questions are verbatim library
# questions; their expected intent is the library record's
# intent and their headline facts are the canonical answer's
# headline facts on this frozen case (probed as baselines
# before the paraphrases were split). Paraphrases deliberately
# avoid the canonical wording; several avoid every classifier
# keyword for the intent (the keyword-poor subset the annex
# calls for).
# ------------------------------------------------------------------


def C(canonical, intent, facts=(), scope="answer",
      unknown=None, passing=(), xfail=()):
    return {"canonical": canonical, "intent": intent,
            "facts": list(facts), "scope": scope,
            "unknown": unknown, "passing": list(passing),
            "xfail": list(xfail)}


F02 = [
    C("What engine does it use?", "build", ["FakeEngine"],
      passing=[
          "Which game-making technology sits underneath "
          "this title?",
          "Name the underlying runtime technology.",
          "What powers this title under the hood?"],
      xfail=[]),
    C("What language is it written in?", "build", ["Kotlin"],
      passing=[
          "Is this a Kotlin program or a Java program?",
          "Kotlin or Java \u2014 which one produced this "
          "code?",
          "In which programming tongue was the code "
          "authored?"],
      xfail=[]),
    C("What is this app?", "identity",
      ["com.example.synthetic"],
      passing=[
          "Under what package identifier does this target "
          "ship?",
          "Identify the program in front of you.",
          "Give me the designation and identifier of "
          "this software."],
      xfail=[]),
    C("What version is this app?", "identity", ["1.0"],
      passing=[
          "What version is installed here, and what is "
          "it called?",
          "Which release of the program is this?",
          "State the release number carried by this "
          "build."],
      xfail=[]),
    C("What screens does it have?", "screens",
      ["com.example.MainActivity"],
      passing=[
          "How many activities are declared, and which "
          "one launches first?",
          "List every activity the manifest declares, "
          "starting with the launcher.",
          "Enumerate the declared interface components "
          "for me."],
      xfail=[]),
    C("What is the main screen?", "screens",
      ["com.example.MainActivity"],
      passing=["Which screen greets the user at launch?",
               "Name the entry-point view of the program.",
               "What is the first page a user lands on?"],
      xfail=[]),
    C("Where are my coins?", "storage", ["SharedPreferences"],
      passing=[
          "Through which on-device repository does my "
          "money balance persist?",
          "In what form is the player's hoard stored "
          "between launches?",
          "By what mechanism does the program keep the "
          "player's balance between sessions?"],
      xfail=[]),
    C("What database does it use?", "storage", ["SQLite"],
      passing=[
          "Does its persistence layer rest on SQLite "
          "tables?",
          "Which SQL store backs this program's data?",
          "Name the relational store embedded in the "
          "program."],
      xfail=[]),
    C("What does it talk to?", "network",
      ["api.example.com"], scope="either",
      passing=[
          "Name the remote host this software contacts.",
          "What URLs are embedded in the binary?",
          "To which machine on the internet does this "
          "program send its traffic?"],
      xfail=[]),
    C("What API does it call?", "network",
      ["api.example.com"], scope="either",
      passing=["What backend does it rely on for its "
               "coin data?",
               "Which remote interface does the code invoke "
               "for data?",
               "List the web destinations the code reaches "
               "out to."],
      xfail=[]),
    C("Is it protected?", "security", ["1 findings"],
      passing=[
          "Tell me the hardening posture of this binary.",
          "What weaknesses did the security scan record?",
          "How safe is this binary from tampering?"]),
    C("How is it monetised?", "monetisation",
      ["billing/purchase"],
      passing=["Are ads shown to players in this title?",
               "How does this program earn its keep?",
               "Which purchasable-offer machinery is "
               "embedded in the code?"],
      xfail=[]),
    C("Does it show ads?", "monetisation", ["advertising"],
      passing=["Does this title carry advertising?",
               "Are commercial messages displayed inside "
               "the program?",
               "Is there advertising anywhere in this "
               "title?"],
      xfail=[]),
    C("What assets does it contain?", "assets",
      ["2 inventoried assets"],
      passing=[
          "What media and data files does the package "
          "ship inside?",
          "Give me an inventory count of the packaged "
          "resources.",
          "How many bundled files were catalogued, "
          "and how large are they together?"],
      xfail=[]),
    C("How is the character animated?", "animation",
      ["Animation-shaped assets identified: 1"],
      passing=[
          "Describe the animation setup for the hero "
          "sprite.",
          "Which skeletal system, if any, moves the "
          "characters?",
          "What movement technology drives the hero "
          "figure?"],
      xfail=[]),
    C("What can you not tell me?", "gaps",
      ["51 coverage entries"],  # Phase 5 re-baseline (docstring)
      passing=[
          "What is missing from your picture of this "
          "target?",
          "Summarise the limitations that bound this "
          "analysis.",
          "Where does your knowledge of this target "
          "run out?"],
      xfail=[]),
    C("What changed between v1 and v2?", "compare",
      unknown="absent",
      passing=[
          "Has anything changed between the first release "
          "and this one?",
          "What would differ if a newer release were "
          "placed beside this one?",
          "If I handed you a second build alongside "
          "this one, could you contrast them?"],
      xfail=[]),
    C("What scripts does it ship?", "scripts",
      ["found no script-bearing files"],
      passing=[
          "Does the package embed any Lua code?",
          "Any sign of Hermes or WebAssembly in the "
          "package?",
          "Are any interpreted-language programs "
          "bundled with this target?"],
      xfail=[]),
    C("How do I rebuild this app?", "rebuild",
      ["Rebuild specification generated"],
      passing=[
          "Could you rebuild this software from its "
          "evidence, and in what order?",
          "What is the build order for reconstructing "
          "the whole program?",
          "Walk me through recreating this program "
          "from scratch."],
      xfail=[]),
    C("How does login work?", "behaviour", unknown="absent",
      passing=["Walk me through the sign-in process step "
               "by step.",
               "In what way does a user authenticate here?",
               "Explain the login mechanism in detail."],
      xfail=[]),
]

F02_PASS = [E(q, c["intent"], c["facts"], scope=c["scope"],
              unknown=c["unknown"])
            for c in F02 for q in c["passing"]]
F02_XFAIL = [E(q, c["intent"], c["facts"], scope=c["scope"],
               unknown=c["unknown"])
             for c in F02 for q in c["xfail"]]

# Extra library questions joining the F-10 pool only (their
# intents are pinned by the library/classifier parity test in
# test_ask.py; facts are the mini-case headline facts).
LIB_EXTRA = [
    E("What is the package name?", "identity",
      ["com.example.synthetic"]),
    E("Does it use SQLite?", "storage", ["SQLite"]),
    E("Which packer?", "security", ["1 findings"]),
    E("What are the largest assets?", "assets",
      ["2 inventoried assets"]),
]

# ------------------------------------------------------------------
# F-05: planted contradictions. Each case starts from the
# frozen mini case and mutates exactly the companions named;
# `sides` are the two distinctive strings a conflict-surfacing
# answer would have to cite (one per side of the planted
# disagreement). Annex examples mapped: manifest declaration
# vs DEX-era census -> identity package (application vs
# manifest/permissions companions); asset counts vs atlas/
# inventory contents -> assets totals vs item list; engine
# verdict vs second inventory -> engines vs frameworks
# verdicts; endpoint classification counts -> endpoints vs
# network-analysis companions; component counts vs component
# list -> permissions counts vs permissions list + manifest.
# ------------------------------------------------------------------
F05_CASES = [
    {"id": "identity-package",
     "mutate": {"manifest.json": {"package": "com.example.impostor"},
                "permissions.json": {"package": "com.example.impostor"}},
     "planted": "application.json package com.example.synthetic "
                "vs manifest.json/permissions.json package "
                "com.example.impostor",
     "sides": ["com.example.synthetic", "com.example.impostor"],
     "questions": ["What is this app?", "What package is this?",
                   "Under what package identifier does this "
                   "target ship?"]},
    {"id": "assets-totals",
     "mutate": {"assets.json": {"total_assets": 42,
                                "total_bytes": 9999}},
     "planted": "assets.json totals 42 assets / 9999 bytes vs "
                "the same companion's item list (2 items, "
                "by_category sums to 2, sizes sum to 100)",
     "sides": ["42 inventoried assets",
               "By type: png-image 1, json 1"],
     "questions": ["What assets does it contain?",
                   "How many assets are there?",
                   "What media and data files does the "
                   "package ship inside?"]},
    {"id": "screens-counts",
     "mutate": {"permissions.json": {
         "component_counts": {"activity": 7, "service": 0,
                              "receiver": 0, "provider": 0}}},
     "planted": "permissions.json component_counts activity=7 "
                "vs permissions.json component list (1 "
                "activity) and manifest.json component_counts "
                "activity=1",
     "sides": ["7 activities",
               "component activity com.example.MainActivity"],
     "questions": ["What screens does it have?",
                   "How many activities are declared, and "
                   "which one launches first?"]},
    {"id": "build-verdicts",
     "mutate": {"frameworks.json": {"verdicts": [{
         "engine": "OtherEngine", "detected": True,
         "confidence": "high", "score": 95,
         "indicators": [{"kind": "path",
                         "detail": "libother.so"}]}]}},
     "planted": "engines.json verdict FakeEngine (score 90) "
                "vs frameworks.json verdict OtherEngine "
                "(score 95), both detected",
     "sides": ["FakeEngine", "OtherEngine"],
     "questions": ["What engine does it use?",
                   "Which runtime technology powers this "
                   "title?",
                   "What framework does it use?"]},
    {"id": "network-counts",
     "mutate": {"network-analysis.json": {
         "classification_counts": {"first-party": 7}}},
     "planted": "endpoints.json classification_counts "
                "{third-party: 1} (and the endpoint's own "
                "classification) vs network-analysis.json "
                "classification_counts {first-party: 7}",
     "sides": ["third-party", "first-party"],
     "questions": ["What does it talk to?",
                   "What endpoints are classified as "
                   "third-party?",
                   "Name the remote host this software "
                   "contacts."]},
]

CONFLICT_WORDS = ("conflict", "disagree", "contradict",
                  "inconsistent", "inconsistency", "mismatch",
                  "discrepan", "two different", "both sides")


def conflict_surfaced(doc, sides):
    """The F-05 acceptance predicate: both sides cited AND
    (confidence reduced from confirmed OR the disagreement
    named in answer/boundary), OR a contract-complete
    unknown whose text names the conflict."""
    blob = doc["answer"] + " " + " ".join(doc["evidence"])
    both = all(s in blob for s in sides)
    named = any(w in (doc["answer"] + " " + doc["boundary"])
                .lower() for w in CONFLICT_WORDS)
    if doc["confidence"] == "unknown":
        text = (doc["answer"] + " " + doc.get("reason", "")
                + " " + doc.get("probe", "")).lower()
        return any(w in text for w in CONFLICT_WORDS)
    return both and (named or doc["confidence"] != "confirmed")

# ------------------------------------------------------------------
# Fixtures and shared helpers
# ------------------------------------------------------------------


@pytest.fixture(scope="module")
def case_env(tmp_path_factory):
    base = tmp_path_factory.mktemp("cert-ask-case")
    case_dir = base / "case"
    case_dir.mkdir()
    target = base / "target.apk"
    make_mini_case(str(case_dir), str(target))
    return {"case_dir": str(case_dir), "target": str(target)}


def _all_gt_entries():
    """question -> ground-truth entry (first registry wins;
    overlapping registries agree on intent/facts)."""
    gt = {}
    for entry in F01_PASS + F01_XFAIL:
        gt.setdefault(entry["q"], entry)
    for c in F02:
        gt.setdefault(c["canonical"], E(
            c["canonical"], c["intent"], c["facts"],
            scope=c["scope"], unknown=c["unknown"]))
    for entry in F02_PASS + F02_XFAIL + LIB_EXTRA:
        gt.setdefault(entry["q"], entry)
    return gt


@pytest.fixture(scope="module")
def pool(case_env):
    gt = _all_gt_entries()
    docs = {}
    for q in gt:
        docs[q] = ask.answer_question(
            q, case_env["target"], case_env["case_dir"])
    return {"docs": docs, "gt": gt, **case_env}


@pytest.fixture(scope="module")
def f05_env(tmp_path_factory):
    base = tmp_path_factory.mktemp("cert-ask-f05")
    src = base / "src-case"
    src.mkdir()
    target = base / "target.apk"
    make_mini_case(str(src), str(target))
    out = {}
    for case in F05_CASES:
        cdir = base / case["id"]
        shutil.copytree(str(src), str(cdir))
        for fname, updates in case["mutate"].items():
            path = cdir / fname
            doc = json.loads(path.read_text(encoding="utf-8"))
            if fname == "frameworks.json" and "verdicts" in updates:
                doc["verdicts"] = updates["verdicts"]
                # keep the Kotlin marker so only the verdict
                # side of the companion changes
            else:
                doc.update(updates)
            path.write_text(json.dumps(doc), encoding="utf-8")
        docs = {q: ask.answer_question(q, str(target), str(cdir))
                for q in case["questions"]}
        out[case["id"]] = {"dir": str(cdir), "docs": docs,
                           "case": case}
    return {"target": str(target), "cases": out}


def assert_contract(doc):
    for field in ("question", "answer", "evidence",
                  "confidence", "why", "chain", "boundary"):
        assert doc.get(field), "missing/empty %s in %r" % (
            field, doc.get("question"))
    assert doc["confidence"] in ask.CONFIDENCES
    assert doc["evidence"], "evidence must never be empty"
    for phrase in ask.FORBIDDEN_ANSWER_PHRASES:
        assert phrase not in doc["answer"].lower()
    if doc["confidence"] == "unknown":
        assert doc["reason"] in ask.UNKNOWN_REASONS
        assert doc["probe"] and doc["cost"]


def entry_satisfied(doc, entry):
    if doc["intent"] != entry["intent"]:
        return False
    if entry["unknown"] is not None:
        return (doc["confidence"] == "unknown"
                and doc.get("reason") == entry["unknown"])
    if doc["confidence"] == "unknown":
        return False
    if entry["scope"] == "answer":
        text = doc["answer"]
    elif entry["scope"] == "evidence":
        text = " ".join(doc["evidence"])
    else:
        text = doc["answer"] + " " + " ".join(doc["evidence"])
    if any(f not in text for f in entry["facts"]):
        return False
    ev = " ".join(doc["evidence"])
    return all(f in ev for f in entry["ev_facts"])


def check_entry(doc, entry):
    assert_contract(doc)
    assert doc["intent"] == entry["intent"], (
        "%r routed to %s, expected %s; answer: %s"
        % (entry["q"], doc["intent"], entry["intent"],
           doc["answer"][:200]))
    if entry["unknown"] is not None:
        assert doc["confidence"] == "unknown", (
            "%r expected contract-complete unknown, got %s"
            % (entry["q"], doc["confidence"]))
        assert doc.get("reason") == entry["unknown"]
        return
    assert doc["confidence"] != "unknown", (
        "%r unexpectedly unknown" % entry["q"])
    if entry["scope"] == "answer":
        text = doc["answer"]
    elif entry["scope"] == "evidence":
        text = " ".join(doc["evidence"])
    else:
        text = doc["answer"] + " " + " ".join(doc["evidence"])
    for fact in entry["facts"]:
        assert fact in text, (
            "%r: headline fact %r missing from %s: %s"
            % (entry["q"], fact, entry["scope"], text[:300]))
    ev = " ".join(doc["evidence"])
    for fact in entry["ev_facts"]:
        assert fact in ev, (
            "%r: evidence fact %r missing: %s"
            % (entry["q"], fact, ev[:300]))


def _param(entry, xfail_reason=None):
    if xfail_reason:
        return pytest.param(
            entry, id=entry["q"][:70],
            marks=pytest.mark.xfail(
                strict=True, reason=xfail_reason))
    return pytest.param(entry, id=entry["q"][:70])


F01_PASS_PARAMS = [_param(e) for e in F01_PASS]
F01_XFAIL_PARAMS = [
    _param(e, "F-01 candidate (Accuracy Defect shape): "
           + F01_OBSERVED[e["q"]]) for e in F01_XFAIL]
F02_PASS_PARAMS = [_param(e) for e in F02_PASS]
F02_XFAIL_PARAMS = [
    _param(e, "F-02 candidate (Accuracy Defect shape): "
           "paraphrase does not preserve the canonical "
           "intent/facts on the frozen case")
    for e in F02_XFAIL]

# ------------------------------------------------------------------
# Membership + subset-shape guards
# ------------------------------------------------------------------


def test_f01_f02_membership():
    """F-01 questions and F-02 paraphrases are NOT in the
    shipped library (exact and case-normalised); F-02
    canonicals and LIB_EXTRA ARE, with matching intents."""
    for entry in F01_PASS + F01_XFAIL + F02_PASS + F02_XFAIL:
        assert entry["q"] not in LIB_SET, (
            "supposedly unseen question is in the library: "
            "%r" % entry["q"])
        assert entry["q"].strip().lower() not in LIB_NORM
    for c in F02:
        assert c["canonical"] in LIB_SET
        assert LIB_BY_Q[c["canonical"]]["intent"] == c["intent"]
    for entry in LIB_EXTRA:
        assert entry["q"] in LIB_SET
        assert LIB_BY_Q[entry["q"]]["intent"] == entry["intent"]


def test_f01_subset_shape():
    # CI subset of F-01 full (>=100 q, >=5/intent, 3 cases):
    # >=24 passing unseen questions over >=8 intents, 1 case.
    assert len(F01_PASS) >= 24
    assert len({e["intent"] for e in F01_PASS}) >= 8
    assert len(F01_PASS) + len(F01_XFAIL) >= 40


def test_f02_subset_shape():
    # CI subset of F-02 full (60 canonicals x 3 = 180):
    # >=15 canonicals, >=6 families, >=45 paraphrases.
    assert len(F02) >= 15
    assert len({c["intent"] for c in F02}) >= 6
    total = sum(len(c["passing"]) + len(c["xfail"])
                for c in F02)
    assert total >= 45


# ------------------------------------------------------------------
# F-01 / F-02 behaviour tests (over the shared pool)
# ------------------------------------------------------------------


@pytest.mark.parametrize("entry", F01_PASS_PARAMS)
def test_f01_unseen_passing(pool, entry):
    check_entry(pool["docs"][entry["q"]], entry)


@pytest.mark.parametrize("entry", F01_XFAIL_PARAMS)
def test_f01_unseen_candidates(pool, entry):
    # Asserts the CORRECT behaviour; xfail(strict) while the
    # recorded misroute stands. See F01_OBSERVED.
    check_entry(pool["docs"][entry["q"]], entry)


@pytest.mark.parametrize("c", F02, ids=lambda c: c["canonical"][:60])
def test_f02_canonical_baselines(pool, c):
    entry = E(c["canonical"], c["intent"], c["facts"],
              scope=c["scope"], unknown=c["unknown"])
    check_entry(pool["docs"][c["canonical"]], entry)


@pytest.mark.parametrize("entry", F02_PASS_PARAMS)
def test_f02_paraphrase_passing(pool, entry):
    check_entry(pool["docs"][entry["q"]], entry)


@pytest.mark.parametrize("entry", F02_XFAIL_PARAMS)
def test_f02_paraphrase_candidates(pool, entry):
    check_entry(pool["docs"][entry["q"]], entry)


# ------------------------------------------------------------------
# F-05: contradictory evidence
# ------------------------------------------------------------------


def _read(case_dir, name):
    return json.loads((Path(case_dir) / name).read_text(
        encoding="utf-8"))


@pytest.mark.parametrize("case", F05_CASES,
                         ids=lambda c: c["id"])
def test_f05_construction(f05_env, case):
    """The planted disagreement is really in the companions
    (product-independent ground-truth sanity)."""
    d = f05_env["cases"][case["id"]]["dir"]
    if case["id"] == "identity-package":
        assert _read(d, "application.json")["properties"][
            "package"]["value"] == "com.example.synthetic"
        assert _read(d, "manifest.json")[
            "package"] == "com.example.impostor"
        assert _read(d, "permissions.json")[
            "package"] == "com.example.impostor"
    elif case["id"] == "assets-totals":
        a = _read(d, "assets.json")
        assert a["total_assets"] == 42
        assert len(a["assets"]) == 2
        assert sum(x["size_bytes"] for x in a["assets"]) == 100
        assert a["total_bytes"] == 9999
    elif case["id"] == "screens-counts":
        p = _read(d, "permissions.json")
        assert p["component_counts"]["activity"] == 7
        assert len(p["components"]["activity"]) == 1
        assert _read(d, "manifest.json")[
            "component_counts"]["activity"] == 1
    elif case["id"] == "build-verdicts":
        e = _read(d, "engines.json")["verdicts"][0]
        f = _read(d, "frameworks.json")["verdicts"][0]
        assert e["engine"] == "FakeEngine" and e["detected"]
        assert f["engine"] == "OtherEngine" and f["detected"]
    elif case["id"] == "network-counts":
        assert _read(d, "endpoints.json")[
            "classification_counts"] == {"third-party": 1}
        assert _read(d, "network-analysis.json")[
            "classification_counts"] == {"first-party": 7}


@pytest.mark.parametrize("case", F05_CASES,
                         ids=lambda c: c["id"])
def test_f05_answers_still_contract_complete(f05_env, case):
    """The F-05 failure is semantic, not contract shape:
    every aimed answer on a contradicted case still honours
    the Answer Contract."""
    for q, doc in f05_env["cases"][case["id"]]["docs"].items():
        assert_contract(doc)


@pytest.mark.parametrize(
    "case,question",
    [pytest.param(c, q, id=(c["id"] + " :: " + q[:40]))
     for c in F05_CASES for q in c["questions"]])
def test_f05_conflict_surfaced(f05_env, case, question):
    doc = f05_env["cases"][case["id"]]["docs"][question]
    assert conflict_surfaced(doc, case["sides"]), (
        "planted contradiction (%s) not surfaced for %r; "
        "confidence=%s answer=%s"
        % (case["planted"], question, doc["confidence"],
           doc["answer"][:250]))

# ------------------------------------------------------------------
# F-10: deterministic semantic scorer
# ------------------------------------------------------------------


@pytest.fixture(scope="module")
def score_ctx(pool):
    case_dir = pool["case_dir"]
    comp, dumps = {}, {}
    for path in sorted(Path(case_dir).glob("*.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            continue
        comp[path.name] = doc
        dumps[path.name] = json.dumps(doc)
    case = ask.Case(case_dir)
    return {"comp": comp, "dumps": dumps,
            "coverage": formats_registry.build_coverage(),
            "dex_classes": case.dex_classes(),
            "case_dir": case_dir, "target": pool["target"]}


def _coverage_entry(ctx, section, entry_id):
    for e in ctx["coverage"].get(section) or []:
        if e.get("id") == entry_id:
            return e
    return None


def _resolve_searched(ev, ctx):
    comp = ctx["comp"]
    for fname in re.findall(r"([\w-]+\.json)", ev):
        if fname not in comp:
            return False
    m = re.search(r"dex\.json \((\d+) classes\)", ev)
    if m and int(m.group(1)) != len(ctx["dex_classes"]):
        return False
    m = re.search(r"components\.activity \((\d+) entries\)", ev)
    if m:
        acts = (comp["permissions.json"].get("components")
                or {}).get("activity") or []
        if int(m.group(1)) != len(acts):
            return False
    m = re.search(r"verified_facts \((\d+)\)", ev)
    if m:
        facts = comp["investigation.json"].get(
            "verified_facts") or []
        if int(m.group(1)) != len(facts):
            return False
    if "one artifact located" in ev and ctx["target"] not in ev:
        return False
    return True


def _resolve_companion(fname, rest, ctx):
    comp = ctx["comp"]
    doc = comp.get(fname)
    if doc is None:
        return False

    def props(name):
        return (comp[name].get("properties") or {})

    if fname == "application.json":
        m = re.match(r"properties\.(\w+) = (.+)$", rest)
        if m:
            entry = props(fname).get(m.group(1)) or {}
            val = entry.get("value")
            if val is None:
                return False
            shown = m.group(2)
            return shown == str(val) or shown.startswith(
                str(val) + " ")
        return False
    if fname == "case.json":
        m = re.match(r"input\.sha256 = (\w+), size_bytes = "
                     r"(\d+)$", rest)
        inp = doc.get("input") or {}
        return bool(m) and m.group(1) == inp.get("sha256") \
            and int(m.group(2)) == inp.get("size_bytes")
    if fname == "manifest.json":
        m = re.match(r"component_counts = (\{.*\})"
                     r"(?:, permission_count = (\d+))?$", rest)
        if not m:
            return False
        if ast.literal_eval(m.group(1)) != doc.get(
                "component_counts"):
            return False
        return m.group(2) is None or int(m.group(2)) == doc.get(
            "permission_count")
    if fname == "permissions.json":
        m = re.match(r"launcher_activity = (\S+)$", rest)
        if m:
            return m.group(1) == doc.get("launcher_activity")
        m = re.match(r"component_counts = (\{.*\})$", rest)
        if m:
            return ast.literal_eval(m.group(1)) == doc.get(
                "component_counts")
        m = re.match(r"component activity (\S+) "
                     r"\(exported=(\w+)\)$", rest)
        if m:
            for a in (doc.get("components") or {}).get(
                    "activity") or []:
                if a.get("name") == m.group(1):
                    return str(a.get("exported")) == m.group(2)
            return False
        m = re.match(r"permission (\S+)$", rest)
        if m:
            names = {p.get("name")
                     for p in doc.get("permissions") or []}
            return m.group(1) in names
        return False
    if fname == "engines.json":
        m = re.match(r"verdict (\S+) detected, confidence "
                     r"(\w+), score (\d+)", rest)
        if m:
            for v in doc.get("verdicts") or []:
                if (v.get("engine") == m.group(1)
                        and v.get("confidence") == m.group(2)
                        and int(m.group(3)) == v.get("score")):
                    return True
            return False
        return False
    if fname == "frameworks.json":
        m = re.match(r"framework marker: (.+)$", rest)
        if m:
            markers = (doc.get("markers") or {}).get(
                "framework_markers") or []
            return m.group(1) in markers
        m = re.match(r"engine_versions\.(\S+) = (.+)$", rest)
        if m:
            versions = (doc.get("markers") or {}).get(
                "engine_versions") or {}
            return str(versions.get(m.group(1))) == m.group(2)
        return False
    if fname == "dex.json":
        totals = doc.get("totals") or {}
        m = re.match(r"totals: (\d+) classes, (\d+) methods "
                     r"across (\d+) DEX file\(s\)$", rest)
        if m:
            return (int(m.group(1)) == totals.get("classes")
                    and int(m.group(2)) == totals.get("methods")
                    and int(m.group(3)) == len(
                        doc.get("dex_files") or []))
        m = re.match(r"totals: (\d+) classes, (\d+) methods "
                     r"visible to static analysis$", rest)
        if m:
            return (int(m.group(1)) == totals.get("classes")
                    and int(m.group(2)) == totals.get("methods"))
        m = re.match(r"class (L[^ ]*?;)"
                     r"(?: extends (L[^ ]*?;))?(?: \(| ->|;|$)",
                     rest)
        if m:
            for name, _meth, _fld, supers in ctx["dex_classes"]:
                if name == m.group(1):
                    return m.group(2) is None or m.group(2) in supers
            return False
        m = re.match(r": (\d+) classes scanned", rest)
        if m:
            return int(m.group(1)) == len(ctx["dex_classes"])
        return False
    if fname == "assets.json":
        m = re.match(r"total_assets = (\d+), total_bytes = "
                     r"(\d+), by_category = (\{.*\})$", rest)
        if m:
            return (int(m.group(1)) == doc.get("total_assets")
                    and int(m.group(2)) == doc.get("total_bytes")
                    and ast.literal_eval(m.group(3)) == doc.get(
                        "by_category"))
        items = doc.get("assets") or []
        m = re.match(r"type (\S+): (\d+) asset\(s\)$", rest)
        if m:
            n = sum(1 for a in items
                    if a.get("type") == m.group(1))
            return n == int(m.group(2))
        m = re.match(r"asset (\S+) \(type (\S+?)"
                     r"(?:, (\d+) bytes)?\)", rest)
        if m:
            for a in items:
                if a.get("path") == m.group(1):
                    if a.get("type") != m.group(2):
                        return False
                    return m.group(3) is None or int(
                        m.group(3)) == a.get("size_bytes")
            return False
        return False
    if fname == "endpoints.json":
        m = re.match(r"host (\S+)$", rest)
        if m:
            return m.group(1) in (doc.get("hosts") or [])
        m = re.match(r"endpoint (\S+) \(kind (\S+), "
                     r"classification (\w+), sources (.*)\)$",
                     rest)
        if m:
            for e in doc.get("endpoints") or []:
                if e.get("url") == m.group(1):
                    return (e.get("kind") == m.group(2)
                            and e.get("classification")
                            == m.group(3))
            return False
        m = re.match(r"endpoint (\S+) \(classification "
                     r"([\w-]+)\)$", rest)
        if m:
            for e in doc.get("endpoints") or []:
                if e.get("url") == m.group(1):
                    return e.get("classification") == m.group(2)
            return False
        m = re.match(r"network library (.+)$", rest)
        if m:
            return m.group(1) in (
                doc.get("network_libraries") or [])
        m = re.match(r"classification_counts = (\{.*\})$", rest)
        if m:
            return ast.literal_eval(m.group(1)) == doc.get(
                "classification_counts")
        return False
    if fname == "network-analysis.json":
        m = re.match(r"cleartext = (\w+), pin_set_present = "
                     r"(\w+)$", rest)
        if m:
            clear = doc.get("cleartext") or {}
            return (m.group(1) == str(clear.get(
                        "base_cleartext_permitted"))
                    and m.group(2) == str(clear.get(
                        "pin_set_present")))
        m = re.match(r"classification_counts = (\{.*\})$", rest)
        if m:
            return ast.literal_eval(m.group(1)) == doc.get(
                "classification_counts")
        return False
    if fname == "security-findings.json":
        m = re.match(r"(\S+) (.*) \(severity (\w+), (\w+)\): "
                     r"(.*)$", rest)
        if m:
            for f in doc.get("findings") or []:
                if f.get("id") == m.group(1):
                    return (f.get("title") == m.group(2)
                            and f.get("severity") == m.group(3)
                            and f.get("verification_status")
                            == m.group(4)
                            and f.get("evidence") == m.group(5))
            return False
        return False
    if fname == "decompile.json":
        m = re.match(r"served_by = (\S+), fidelity = (\S+)$",
                     rest)
        if m:
            return (m.group(1) == doc.get("served_by")
                    and m.group(2) == doc.get("fidelity"))
        return False
    if fname == "investigation.json":
        m = re.match(r"verified_fact \[(\w+)\] (.*?) \u2014 "
                     r"(.*)$", rest)
        if m:
            for f in doc.get("verified_facts") or []:
                if (f.get("verification_status") == m.group(1)
                        and f.get("fact") == m.group(2)
                        and f.get("detail") == m.group(3)):
                    return True
            return False
        m = re.match(r"unknown: (.*?) \u2014 (.*)$", rest)
        if m:
            for u in doc.get("unknowns") or []:
                if (u.get("question") == m.group(1)
                        and u.get("reason") == m.group(2)):
                    return True
            return False
        return False
    if fname == "report.json":
        m = re.match(r"limitation: (.*)$", rest)
        if m:
            return m.group(1) in (doc.get("limitations") or [])
        m = re.match(r"protection record (.*)$", rest)
        if m:
            return m.group(1) in [str(p) for p in
                                  doc.get("protections") or []]
        return False
    # Generic fallback for any other companion-prefixed item:
    # at least one salient token must appear in that
    # companion's own serialised content.
    tokens = re.findall(r"[A-Za-z0-9_./$-]{5,}", rest)
    dump = ctx["dumps"].get(fname, "")
    return any(t in dump for t in tokens)


def resolve_evidence(ev, ctx):
    """True iff the evidence item resolves to a real item:
    a companion field/value, a coverage-registry entry, a
    searched location in a real companion, or a blueprint
    file the rebuild answer generated."""
    if ev.startswith("searched "):
        return _resolve_searched(ev, ctx)
    if ev.startswith("coverage registry:"):
        m = re.match(r"coverage registry: (\d+) "
                     r"non-supported entries across (\d+) "
                     r"sections", ev)
        if not m:
            return False
        gaps = [(s, e) for s, entries
                in ctx["coverage"].items()
                if isinstance(entries, list)
                for e in entries
                if e.get("status") != "supported"]
        return (int(m.group(1)) == len(gaps)
                and int(m.group(2)) == len({s for s, _ in gaps}))
    if ev.startswith("coverage gap "):
        m = re.match(r"coverage gap ([\w-]+)/([\w-]+): "
                     r"status (\w+);", ev)
        if not m:
            return False
        entry = _coverage_entry(ctx, m.group(1), m.group(2))
        return entry is not None and entry.get(
            "status") == m.group(3)
    if ev.startswith("coverage "):
        m = re.match(r"coverage (\S+) (\S+): status (\w+)"
                     r"(?: \(reason: (.*)\))?$", ev)
        if not m:
            return False
        entry = _coverage_entry(ctx, m.group(1), m.group(2))
        if entry is None or entry.get("status") != m.group(3):
            return False
        if m.group(4) is not None:
            return m.group(4) == str(entry.get("reason"))
        return True
    if ev.startswith("nar-blueprint.py run exit "):
        m = re.match(r"nar-blueprint.py run exit (\d+); "
                     r"files: (.*)$", ev)
        if not m or m.group(1) != "0":
            return False
        bp = Path(ctx["case_dir"]) / "blueprint"
        files = [f.strip() for f in m.group(2).split(",")]
        return all((bp / f).is_file() for f in files)
    if ev.startswith("blueprint/features.md entries:"):
        feats = Path(ctx["case_dir"]) / "blueprint" / "features.md"
        if not feats.is_file():
            return False
        lines = {ln.strip() for ln in feats.read_text(
            encoding="utf-8", errors="replace").splitlines()}
        entries = ev.split("entries:", 1)[1].strip().split("; ")
        return all(e in lines for e in entries)
    if ev.startswith("intent filter on "):
        m = re.match(r"intent filter on (\S+):", ev)
        acts = ((ctx["comp"]["permissions.json"].get(
            "components") or {}).get("activity") or [])
        return bool(m) and any(
            a.get("name") == m.group(1) for a in acts)
    if ev.startswith("deep link intent filter:"):
        m = re.match(r"deep link intent filter: (\S+) ->", ev)
        acts = ((ctx["comp"]["permissions.json"].get(
            "components") or {}).get("activity") or [])
        return bool(m) and any(
            a.get("name") == m.group(1) for a in acts)
    m = re.match(r"^([\w-]+\.json)\s+(.*)$", ev)
    if m:
        return _resolve_companion(m.group(1), m.group(2), ctx)
    return False


_STORAGE_GT = [
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


def confirmed_violations(doc, ctx):
    """Structured fact checks for one confirmed-band answer.
    Returns a list of unsupported-claim descriptions (empty
    when every asserted structured fact equals the frozen
    companion value)."""
    comp = ctx["comp"]
    ans = doc["answer"]
    out = []
    intent = doc["intent"]
    if intent == "identity" or "case identity summary" in ans \
            or "This target is" in ans:
        props = (comp["application.json"].get("properties")
                 or {})
        m = re.search(r"This target is '([^']+)'", ans)
        if m and m.group(1) != str(
                (props.get("app_label") or {}).get("value")):
            out.append("label %r != companion" % m.group(1))
        m = re.search(r"package ([\w.]+)", ans)
        if m and m.group(1) != (props.get("package")
                                or {}).get("value"):
            out.append("package %r != companion" % m.group(1))
        m = re.search(r"version ([\d.]+) \(code (\S+?)\)", ans)
        if m and (m.group(1) != str((props.get("version_name")
                                     or {}).get("value"))
                  or m.group(2) != str((props.get("version_code")
                                        or {}).get("value"))):
            out.append("version %r/%r != companion"
                       % (m.group(1), m.group(2)))
        m = re.search(r"min SDK (\d+), target SDK (\d+)", ans)
        if m and (int(m.group(1)) != int((props.get("min_sdk")
                                          or {}).get("value"))
                  or int(m.group(2)) != int(
                      (props.get("target_sdk")
                       or {}).get("value"))):
            out.append("sdk levels != companion")
    if intent == "assets":
        a = comp["assets.json"]
        m = re.search(r"carries (\d+) inventoried assets "
                      r"\((\d+) bytes\)", ans)
        if not m:
            out.append("assets headline shape not found")
        elif (int(m.group(1)) != a.get("total_assets")
              or int(m.group(2)) != a.get("total_bytes")):
            out.append("assets totals != companion")
        m = re.search(r"By type: (.+)\.$", ans)
        if m:
            by_type = {}
            for item in a.get("assets") or []:
                t = item.get("type") or "unknown"
                by_type[t] = by_type.get(t, 0) + 1
            shown = {t: int(n) for t, n in re.findall(
                r"(\S+) (\d+)", m.group(1))}
            if shown != by_type:
                out.append("assets by-type %r != companion %r"
                           % (shown, by_type))
    if intent == "screens":
        m = re.search(
            r"declares (\d+) activities \(screens\), (\d+) "
            r"services, (\d+) receivers and (\d+) providers; "
            r"the launcher screen is (\S+)\.", ans)
        if not m:
            out.append("screens headline shape not found")
        else:
            shown = {"activity": int(m.group(1)),
                     "service": int(m.group(2)),
                     "receiver": int(m.group(3)),
                     "provider": int(m.group(4))}
            candidates = [
                comp["permissions.json"].get("component_counts"),
                comp["manifest.json"].get("component_counts")]
            if shown not in candidates:
                out.append("screens counts %r != companions"
                           % shown)
            if m.group(5) != comp["permissions.json"].get(
                    "launcher_activity"):
                out.append("launcher %r != companion"
                           % m.group(5))
    if intent == "security":
        if "Static analysis can see the code at" in ans:
            m = re.search(r"at (\S+) fidelity \(served by "
                          r"(\S+)\); (\d+) classes", ans)
            dec = comp["decompile.json"]
            totals = comp["dex.json"].get("totals") or {}
            if not m:
                out.append("visibility shape not found")
            elif (m.group(1) != dec.get("fidelity")
                  or m.group(2) != dec.get("served_by")
                  or int(m.group(3)) != totals.get("classes")):
                out.append("visibility facts != companion")
        else:
            m = re.search(r"Security posture: (\d+) findings "
                          r"recorded \(severity counts "
                          r"(\{.*?\})\)", ans)
            findings = comp["security-findings.json"]
            if not m:
                out.append("security headline shape not found")
            elif (int(m.group(1)) != len(
                    findings.get("findings") or [])
                  or ast.literal_eval(m.group(2))
                  != findings.get("severity_counts")):
                out.append("security counts != companion")
    if intent == "gaps":
        m = re.search(r"Named gaps: (\d+) coverage entries",
                      ans)
        gaps = [e for entries in ctx["coverage"].values()
                if isinstance(entries, list)
                for e in entries
                if e.get("status") != "supported"]
        if not m or int(m.group(1)) != len(gaps):
            out.append("gaps count != registry recount")
    if intent == "storage":
        m = re.search(r"Storage mechanisms identified: "
                      r"(.+)\.$", ans)
        if not m:
            out.append("storage headline shape not found")
        else:
            shown = {s.strip() for s in m.group(1).split(", ")}
            expected = set()
            for label, needles in _STORAGE_GT:
                for name, _meth, _fld, supers in \
                        ctx["dex_classes"]:
                    hay = (name + " " + " ".join(supers)).lower()
                    if any(n in hay for n in needles):
                        expected.add(label)
                        break
            if shown != expected:
                out.append("storage labels %r != companion-"
                           "derived %r" % (shown, expected))
    # Generic sweep: every dotted identifier asserted in a
    # confirmed answer must occur in some companion.
    dumps_all = " ".join(ctx["dumps"].values())
    for tok in set(re.findall(
            r"\b[a-z][\w-]*(?:\.[\w-]+){2,}\b", ans)):
        if tok not in dumps_all:
            out.append("unsupported dotted identifier %r" % tok)
    return out


def test_f10_pool_size(pool):
    # F-10 subset: >=40 scored answers on the frozen case
    # (full criterion: >=150 human-scored, stratified).
    assert len(pool["docs"]) >= 40


def test_f10_evidence_validity(pool, score_ctx):
    total, failures = 0, []
    for q, doc in pool["docs"].items():
        for ev in doc["evidence"]:
            total += 1
            if not resolve_evidence(ev, score_ctx):
                failures.append((q, ev))
    print("F-10 evidence validity: %d/%d resolved"
          % (total - len(failures), total))
    assert not failures, (
        "%d evidence items do not resolve: %s"
        % (len(failures), failures[:5]))


def test_f10_confirmed_band_discipline(pool, score_ctx):
    checked, violations = 0, []
    for q, doc in pool["docs"].items():
        if doc["confidence"] != "confirmed":
            continue
        checked += 1
        for v in confirmed_violations(doc, score_ctx):
            violations.append((q, v))
    print("F-10 confirmed band: %d answers checked, %d "
          "unsupported claims" % (checked, len(violations)))
    assert checked >= 10
    assert not violations, (
        "unsupported claims in confirmed band: %s"
        % (violations[:5],))


def test_f10_factual_accuracy_measured(pool):
    """Reports (does not threshold) the pool's factual
    accuracy against frozen ground truth: an answer counts
    correct iff routed intent, headline facts and expected
    unknown reason all match. The F-01/F-02 thresholds
    (>=95%) are assessed in the wave report from these
    numbers; this test pins that the measurement itself is
    over the full ground-truth pool with no exclusions."""
    gt = pool["gt"]
    correct = sum(1 for q, entry in gt.items()
                  if entry_satisfied(pool["docs"][q], entry))
    total = len(gt)
    rate = correct / total if total else 0.0
    print("F-10 factual accuracy on pool: %d/%d = %.1f%%"
          % (correct, total, rate * 100))
    assert total >= 40
    assert 0 <= correct <= total
