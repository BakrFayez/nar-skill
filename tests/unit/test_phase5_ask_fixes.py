"""Phase 5 ask fixes — regression tests.

Each test pins one accuracy correction landed in the
Phase 5 certification round (see the Phase 5 report):
a companion-consistency surfacing in the NF-03 pattern,
the compare builder's evidence wiring, the graph wiring
in the residual builder, comparative routing, and the
blueprint generator's overstatement corrections. Cases
are the frozen mini case (tests/unit/test_ask.py's
make_mini_case) with exactly the companions a fix reads
mutated; the unmutated mini case is the control and its
answers must stay conflict-free.
"""
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

UNIT = Path(__file__).parent
_spec = importlib.util.spec_from_file_location(
    "nar_ask_p5", UNIT.parent.parent / "scripts" / "nar-ask.py")
ask = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ask)
_hspec = importlib.util.spec_from_file_location(
    "test_ask_helpers_p5", UNIT / "test_ask.py")
_helpers = importlib.util.module_from_spec(_hspec)
_hspec.loader.exec_module(_helpers)
make_mini_case = _helpers.make_mini_case

CONFLICT = "companions disagree"


@pytest.fixture()
def mini(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    target = tmp_path / "target.apk"
    make_mini_case(str(case_dir), str(target))
    return {"dir": str(case_dir), "target": str(target)}


def _mutate(case_dir, fname, updates):
    path = Path(case_dir) / fname
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc.update(updates)
    path.write_text(json.dumps(doc), encoding="utf-8")


def _copy_case(mini, tmp_path, name):
    dst = tmp_path / name
    shutil.copytree(mini["dir"], str(dst))
    return str(dst)


# ------------------------------------------------------------------
# FIX-1: build_security — severity_counts must sum to the
# number of findings the same headline cites.
# ------------------------------------------------------------------

def test_security_counts_consistent_stays_confirmed(mini):
    doc = ask.answer_question(
        "What is the security posture?", mini["target"],
        mini["dir"])
    assert doc["intent"] == "security"
    assert doc["confidence"] == "confirmed"
    assert CONFLICT not in doc["answer"]


def test_security_counts_contradiction_surfaced(mini, tmp_path):
    case_dir = _copy_case(mini, tmp_path, "sev")
    path = Path(case_dir) / "security-findings.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    findings = doc.get("findings") or []
    assert findings, "mini case must carry findings"
    doc["severity_counts"] = {"high": len(findings) + 5}
    path.write_text(json.dumps(doc), encoding="utf-8")
    out = ask.answer_question(
        "What is the security posture?", mini["target"],
        case_dir)
    assert CONFLICT in out["answer"]
    assert "security finding counts" in out["answer"]
    assert out["confidence"] != "confirmed"
    blob = out["answer"] + " " + " ".join(out["evidence"])
    assert str(len(findings)) in blob
    assert str(len(findings) + 5) in blob


# ------------------------------------------------------------------
# FIX-2: build_security visibility branch — the stated DEX
# class total must agree with the DEX class list.
# ------------------------------------------------------------------

def _align_dex_totals(case_dir):
    """Make the copied case's dex totals agree with its
    class list (the shared mini fixture's totals predate
    its sixth class; real pipeline cases always agree —
    verified on three real cases in the Phase 5 round)."""
    path = Path(case_dir) / "dex.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    listed = len(ask.Case(case_dir).dex_classes())
    totals = dict(doc.get("totals") or {})
    totals["classes"] = listed
    doc["totals"] = totals
    path.write_text(json.dumps(doc), encoding="utf-8")
    return listed


def test_visibility_total_consistent_stays_confirmed(mini,
                                                     tmp_path):
    case_dir = _copy_case(mini, tmp_path, "visok")
    _align_dex_totals(case_dir)
    doc = ask.answer_question(
        "Can static analysis see the logic?",
        mini["target"], case_dir)
    assert doc["intent"] == "security"
    assert doc["confidence"] == "confirmed"
    assert CONFLICT not in doc["answer"]


def test_visibility_total_contradiction_surfaced(mini,
                                                 tmp_path):
    case_dir = _copy_case(mini, tmp_path, "vis")
    listed = _align_dex_totals(case_dir)
    path = Path(case_dir) / "dex.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    totals = dict(doc.get("totals") or {})
    totals["classes"] = listed + 999
    doc["totals"] = totals
    path.write_text(json.dumps(doc), encoding="utf-8")
    out = ask.answer_question(
        "Can static analysis see the logic?",
        mini["target"], case_dir)
    assert CONFLICT in out["answer"]
    assert "DEX class count" in out["answer"]
    assert out["confidence"] != "confirmed"
    assert str(listed + 999) in out["answer"]
    assert str(listed) in out["answer"]


# ------------------------------------------------------------------
# FIX-3: build_screens — the named launcher activity must
# appear in the component census of the same companions.
# ------------------------------------------------------------------

def test_launcher_in_census_stays_confirmed(mini):
    doc = ask.answer_question(
        "How many screens are there?", mini["target"],
        mini["dir"])
    assert doc["intent"] == "screens"
    assert doc["confidence"] == "confirmed"
    assert CONFLICT not in doc["answer"]


def test_ghost_launcher_surfaced(mini, tmp_path):
    case_dir = _copy_case(mini, tmp_path, "ghost")
    _mutate(case_dir, "permissions.json",
            {"launcher_activity":
             "com.example.ghost.GhostActivity"})
    out = ask.answer_question(
        "How many screens are there?", mini["target"],
        case_dir)
    assert CONFLICT in out["answer"]
    assert "launcher activity" in out["answer"]
    assert "com.example.ghost.GhostActivity" in out["answer"]
    assert out["confidence"] != "confirmed"


# ------------------------------------------------------------------
# FIX-4: build_behaviour — a verified fact with no DEX,
# component or app corroboration is flagged as such.
# ------------------------------------------------------------------

def test_corroborated_trace_has_no_note(mini):
    doc = ask.answer_question(
        "How does the wallet work?", mini["target"],
        mini["dir"])
    assert doc["intent"] == "behaviour"
    assert "not corroborated" not in doc["answer"]


def test_uncorroborated_fact_flagged(mini, tmp_path):
    case_dir = _copy_case(mini, tmp_path, "uncorroborated")
    path = Path(case_dir) / "investigation.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    facts = doc.get("verified_facts") or []
    facts.append({
        "fact": "Ghost service records telemetry",
        "subject": "com.example.ghost.GhostService",
        "detail": "declared in the manifest and "
                  "implemented in DEX",
        "verification_status": "CONFIRMED"})
    doc["verified_facts"] = facts
    path.write_text(json.dumps(doc), encoding="utf-8")
    out = ask.answer_question(
        "How does the ghost service work?", mini["target"],
        case_dir)
    assert out["intent"] == "behaviour"
    assert "not corroborated" in out["answer"]
    assert "verified effect" in out["answer"]


# ------------------------------------------------------------------
# FIX-5: build_network — endpoints.json classification
# counts must agree with the endpoint items it lists.
# ------------------------------------------------------------------

def test_network_counts_match_items_stays_clean(mini):
    doc = ask.answer_question(
        "What endpoints does it contact?", mini["target"],
        mini["dir"])
    assert doc["intent"] == "network"
    assert CONFLICT not in doc["answer"]


def test_network_counts_vs_items_contradiction_surfaced(
        mini, tmp_path):
    case_dir = _copy_case(mini, tmp_path, "netitems")
    path = Path(case_dir) / "endpoints.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    counts = dict(doc.get("classification_counts") or {})
    assert counts, "mini case must carry classification counts"
    counts["third-party"] = counts.get("third-party", 0) + 7
    doc["classification_counts"] = counts
    path.write_text(json.dumps(doc), encoding="utf-8")
    out = ask.answer_question(
        "What endpoints does it contact?", mini["target"],
        case_dir)
    assert CONFLICT in out["answer"]
    assert "endpoint classification counts" in out["answer"]
    assert out["confidence"] != "confirmed"


# ------------------------------------------------------------
# FIX-6 (F-06): build_compare read identity/summary/counts/
# similarity keys nar-compare never emits; answers cited an
# empty identity dict at confirmed. It now renders the real
# report shape (old/new/identical_files/diff/extended).
# ------------------------------------------------------------
FIXTURES = os.path.join(
    os.path.expanduser("~"), "workspace",
    "nar-e2e-fixtures", "demo")


def test_compare_real_shape_renders_diff_facts(mini):
    demo1 = os.path.join(FIXTURES, "NarDemo.apk")
    demo2 = os.path.join(FIXTURES, "NarDemo_v2.apk")
    doc = ask.answer_question(
        "What changed between v1 and v2?", demo1,
        mini["dir"], second=demo2)
    assert doc["intent"] == "compare"
    assert doc["confidence"] == "confirmed"
    joined = " ".join(doc["evidence"])
    assert "nar-compare diff:" in joined
    assert "android.permission.VIBRATE" in joined
    assert "identity: {}" not in joined


def test_compare_identical_pair_states_identical(mini,
                                                 tmp_path):
    demo1 = os.path.join(FIXTURES, "NarDemo.apk")
    twin = str(tmp_path / "twin.apk")
    shutil.copyfile(demo1, twin)
    doc = ask.answer_question(
        "What is the difference between the two builds?",
        demo1, mini["dir"], second=twin)
    assert doc["intent"] == "compare"
    assert "identical" in doc["answer"]
    joined = " ".join(doc["evidence"])
    assert "size_delta_bytes 0" in joined


# ------------------------------------------------------------
# FIX-7 (F-07): the residual builder never read graph.json;
# graph questions fell to identity summaries that cited no
# graph evidence. _graph_answer now serves counts, node
# existence/absence, edges, neighbours, degree and paths
# from the graph companion. The mini case has no graph.json
# (control: unchanged routing to the identity fallback).
# ------------------------------------------------------------
def _add_graph(case_dir):
    graph = {
        "nodes": [
            {"id": "application:com.example.app",
             "kind": "application",
             "label": "com.example.app"},
            {"id": "component:com.example.app.MainActivity",
             "kind": "component",
             "label": "com.example.app.MainActivity"},
            {"id": "permission:android.permission.INTERNET",
             "kind": "permission",
             "label": "android.permission.INTERNET"},
        ],
        "edges": [
            {"source": "application:com.example.app",
             "target":
                 "component:com.example.app.MainActivity",
             "kind": "contains"},
            {"source":
                 "component:com.example.app.MainActivity",
             "target":
                 "permission:android.permission.INTERNET",
             "kind": "requires"},
        ],
    }
    path = Path(case_dir) / "graph.json"
    path.write_text(json.dumps(graph), encoding="utf-8")


def test_graph_counts_and_absence(mini):
    _add_graph(mini["dir"])
    doc = ask.answer_question(
        "How many nodes does the investigation graph "
        "contain?", mini["target"], mini["dir"])
    assert doc["intent"] == "other"
    assert "3 nodes" in doc["answer"]
    assert any(e.startswith("graph.json:")
               for e in doc["evidence"])
    doc = ask.answer_question(
        "Is there a node for com.example.ghost.GhostActivity "
        "in the investigation graph?", mini["target"],
        mini["dir"])
    assert "contain no node labelled" in doc["answer"]
    assert doc["confidence"] == "strongly-indicated"


def test_graph_neighbours_and_path(mini):
    _add_graph(mini["dir"])
    doc = ask.answer_question(
        "What is com.example.app connected to in the "
        "investigation graph?", mini["target"], mini["dir"])
    assert "MainActivity" in doc["answer"]
    doc = ask.answer_question(
        "Is there a path in the investigation graph from "
        "com.example.app to android.permission.INTERNET?",
        mini["target"], mini["dir"])
    assert "path of 2 edge(s)" in doc["answer"]


def test_graph_absent_case_unchanged(mini):
    doc = ask.answer_question(
        "How many nodes does the investigation graph "
        "contain?", mini["target"], mini["dir"])
    assert not any(e.startswith("graph.json:")
                   for e in doc["evidence"])


# ------------------------------------------------------------
# FIX-8 (F-01/F-06): comparative phrasings the frozen
# routing missed ("added compared with the earlier
# version", "larger than the one before", "Are the two
# files identical?") reached topical builders or the
# residual summary despite a supplied second artifact.
# The compare group gains the measured phrasings; a
# within-app count comparison must NOT flip.
# ------------------------------------------------------------
@pytest.mark.parametrize("q", [
    "Which screens were added compared with the earlier "
    "version?",
    "Is this build larger than the one before it, and by "
    "how much?",
    "How much bigger is the other build?",
    "Are the two files identical?",
    "Were any permissions removed?",
    "How many more entries does the newer build have?",
    "What changed between the two builds?",
])
def test_comparative_phrasings_route_compare(q):
    assert ask.classify_intent(q) == "compare"


def test_within_app_comparison_not_stolen():
    q = ("How many receivers does the manifest declare "
         "compared with its activities?")
    assert ask.classify_intent(q) != "compare"


def test_compare_no_second_still_unknown(mini):
    doc = ask.answer_question(
        "Are the two files identical?", mini["target"],
        mini["dir"])
    assert doc["intent"] == "compare"
    assert doc["confidence"] == "unknown"


# ------------------------------------------------------------
# FIX-9 (F-09): blueprint overstatements — build-order
# stated the verified-FACT count as the feature count;
# features.md said recorded endpoints "are contacted";
# data-model.md called marker-matched classes store
# implementations; network.md dropped URL fragments,
# collapsing distinct endpoints into identical rows; and
# the storage marker labelled a target "Room" when the
# app census explicitly refutes a Room library.
# ------------------------------------------------------------
_bspec = importlib.util.spec_from_file_location(
    "nar_blueprint_p5",
    UNIT.parent.parent / "scripts" / "nar-blueprint.py")
bp = importlib.util.module_from_spec(_bspec)
_bspec.loader.exec_module(bp)
_bpspec = importlib.util.spec_from_file_location(
    "test_blueprint_helpers_p5",
    UNIT / "test_blueprint.py")
_bp_helpers = importlib.util.module_from_spec(_bpspec)
_bpspec.loader.exec_module(_bp_helpers)


def test_safe_url_keeps_fragment_and_redacts():
    url = bp.safe_url(
        "https://www.xmlpull.org/doc/features.html#indent")
    assert url.endswith("#indent")
    url = bp.safe_url(
        "https://user:pw@example.com/x?a=secret&b=2")
    assert "secret" not in url and "user" not in url
    assert "REDACTED" in url


def test_blueprint_wording_corrections(tmp_path):
    case_dir = tmp_path / "bpcase"
    case_dir.mkdir()
    target = tmp_path / "target.apk"
    _bp_helpers.make_mini_case(str(case_dir), str(target))
    out = tmp_path / "spec"
    rc = bp.main([str(target), "--out", str(out),
                  "--case", str(case_dir)])
    assert rc == 0
    features = (out / "features.md").read_text(
        encoding="utf-8")
    assert "endpoints are contacted" not in features
    data_model = (out / "data-model.md").read_text(
        encoding="utf-8")
    assert "store implemented by" not in data_model
    build_order = (out / "build-order.md").read_text(
        encoding="utf-8")
    assert "verified features" not in build_order


def _room_case(tmp_path, extra_classes):
    case_dir = tmp_path / ("roomcase%d" % len(extra_classes))
    case_dir.mkdir()
    classes = [{
        "class": "Landroidx/room/"
                 "MultiInstanceInvalidationService;",
        "methods": [], "fields": []}] + extra_classes
    (case_dir / "dex.json").write_text(json.dumps({
        "dex_files": [{"name": "classes.dex",
                       "classes": classes}],
        "totals": {"classes": len(classes)}}),
        encoding="utf-8")
    (case_dir / "app.json").write_text(json.dumps({
        "storage": {"room_sqlite": {
            "room_library": {"present": False},
            "room_database_classes": [],
            "shipped_databases": []}}}), encoding="utf-8")
    return bp.Case(str(case_dir))


def test_blueprint_room_guard(tmp_path):
    case = _room_case(tmp_path, [])
    labels = [label for label, _hits in bp.storage_hits(case)]
    assert "Room" not in labels
    case = _room_case(tmp_path, [{
        "class": "Lcom/example/AppDatabase;",
        "superclass": "Landroidx/room/RoomDatabase;",
        "methods": [], "fields": []}])
    labels = [label for label, _hits in bp.storage_hits(case)]
    assert "Room" in labels


# ------------------------------------------------------------
# FIX-10 (F-10): build_screens' subject matcher accepted
# the generic token "screen", presenting fullscreen-ad
# activities as matches for unrelated asked screens at
# strongly-indicated. Generic screen vocabulary no longer
# matches; a distinctive token is required.
# ------------------------------------------------------------
def _add_fullscreen_activity(case_dir):
    path = Path(case_dir) / "permissions.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["components"]["activity"].append({
        "name": "com.example.ads.FullScreenAdActivity",
        "exported": False, "intent_filters": []})
    path.write_text(json.dumps(doc), encoding="utf-8")


def test_screens_generic_token_no_false_match(mini):
    _add_fullscreen_activity(mini["dir"])
    doc = ask.answer_question(
        "How do I get to the map screen?", mini["target"],
        mini["dir"])
    assert doc["intent"] == "screens"
    assert doc["confidence"] == "unknown"
    assert "FullScreenAdActivity" not in doc["answer"]


def test_screens_distinctive_token_still_matches(mini):
    path = Path(mini["dir"]) / "permissions.json"
    doc_p = json.loads(path.read_text(encoding="utf-8"))
    doc_p["components"]["activity"].append({
        "name": "com.example.WalletActivity",
        "exported": False, "intent_filters": []})
    path.write_text(json.dumps(doc_p), encoding="utf-8")
    doc = ask.answer_question(
        "How do I get to the wallet screen?",
        mini["target"], mini["dir"])
    assert doc["confidence"] == "strongly-indicated"
    assert "WalletActivity" in doc["answer"]


# ------------------------------------------------------------
# FIX-11 (F-09 root, ask side): the shared storage marker
# claimed "Room" from the androidx/room name signal of the
# MultiInstanceInvalidationService runtime artifact alone,
# although app.json's own Room census explicitly refutes a
# Room library for such targets. build_storage now defers
# to the census; a genuine RoomDatabase subclass keeps the
# label even under the refutation record.
# ------------------------------------------------------------
_ROOM_SVC = {
    "class": "Landroidx/room/"
             "MultiInstanceInvalidationService;",
    "methods": [], "fields": []}
_ROOM_DB = {
    "class": "Lcom/example/AppDatabase;",
    "superclass": "Landroidx/room/RoomDatabase;",
    "methods": [], "fields": []}
_ROOM_REFUTATION = {"storage": {"room_sqlite": {
    "room_library": {"present": False},
    "room_database_classes": [],
    "shipped_databases": []}}}


def _storage_doc(mini, extra_classes, app_doc=None):
    path = Path(mini["dir"]) / "dex.json"
    dex = json.loads(path.read_text(encoding="utf-8"))
    dex["dex_files"][0]["classes"] += extra_classes
    path.write_text(json.dumps(dex), encoding="utf-8")
    if app_doc is not None:
        (Path(mini["dir"]) / "app.json").write_text(
            json.dumps(app_doc), encoding="utf-8")
    return ask.answer_question(
        "What storage does it use?", mini["target"],
        mini["dir"])


def test_storage_room_artifact_only_claimed_without_census(
        mini):
    doc = _storage_doc(mini, [_ROOM_SVC])
    assert "Room" in doc["answer"]


def test_storage_room_dropped_when_census_refutes(mini):
    doc = _storage_doc(mini, [_ROOM_SVC], _ROOM_REFUTATION)
    assert "Room" not in doc["answer"]
    assert "SharedPreferences" in doc["answer"]


def test_storage_room_kept_with_real_database_class(mini):
    doc = _storage_doc(mini, [_ROOM_SVC, _ROOM_DB],
                       _ROOM_REFUTATION)
    assert "Room" in doc["answer"]
