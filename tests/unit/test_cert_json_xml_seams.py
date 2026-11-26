"""Certification Phase 3, workstream SEAMS: D-03 malformed-
JSON seams + XML parsing seams (XXE / entity expansion).

D-03 (Phase 1 audit, ANNEX_CD_INVENTORIES.md): malformed
JSON was covered at the stage-cache layer and at verify
time, but NOT at two seams:

  (1) a child stage tool emitting malformed JSON on its
      output channel — the orchestrator's parse-failure
      path exists in scripts/nar-analyze.py (run_json_tool)
      but no test fed it a garbage-emitting tool;
  (2) a companion / stage document corrupted after the
      stages complete, before the graph / investigation /
      correlations builders read it — builder-level handling
      was asserted only at verify time, not build time.

Empirical findings while writing these tests (tree at the
Phase-2-fixed state):

  * Non-JSON garbage from a child IS handled as designed:
    run_json_tool returns (None, "<script> produced no
    JSON ..."), a 2.0 stage degrades to the named
    limitation "2.0 stage <stage> degraded: ... produced
    no JSON", and a garbage triage ends analyze() with the
    named fatal "triage failed: ... produced no JSON".
  * Valid JSON of a NON-OBJECT shape from a child was NOT
    handled: run_json_tool returned the string / list /
    number as a successful document and analyze()'s direct
    consumers (triage .get, summarize_perms,
    summarize_strings) died on AttributeError — a traceback
    escaping the whole analysis. FIXED in run_json_tool
    (a non-object document is now a named failure, the
    C-02 discipline applied at the channel seam); the
    fake-tool tests below are its regression.
  * Builder build-time handling EXISTS: a wrong-shape
    stage document is stopped by the stage schema gate
    ("stage document failed its companion schema"), and a
    wrong-shape permissions document reaches the builders
    and degrades each companion to a NAMED limitation
    ("companion correlations.json not emitted: build
    failed (...)", "companion graph.json not emitted:
    graph builder failed (...)", same for investigation)
    while the rest of the case is still emitted.
  * A corrupted stage cache on a continuation run is a
    cache miss (classic stages) or, for the streamed DEX
    stage, a projection failure that falls back to the
    classic stage path and re-runs the tool — never a
    traceback, never a silently empty companion.

XML seams: every XML parse site in scripts/ was
enumerated by grep (xml.etree / plistlib / minidom / sax;
minidom and sax have no sites):

  ET.fromstring — nar-air.py parse_descriptor,
    nar-cordova.py parse_config, nar-libgdx.py parse_tmx,
    narlib/atlas.py parse_xml_atlas,
    narlib/anim.py parse_spriter,
    narlib/anim.py _parse_text_xml_tree (android-view);
  plistlib.loads — narlib/atlas.py parse_cocos_plist,
    narlib/anim.py parse_ccb.

Python's expat / ElementTree behaviour, established
empirically on this interpreter: external entities are
never resolved (an external entity in content is an
"undefined entity" ParseError, in an attribute a
"reference to external entity" ParseError; external DTDs
and parameter entities are ignored, never fetched), and
expat's input-amplification limit refuses billion-laughs
and large quadratic-blowup documents with a ParseError.
plistlib rejects ANY entity declaration in a plist
("XML entity declarations are not supported"). Every
site is therefore safe by construction against XXE and
large expansion; the tests below PIN that behaviour per
site, with a timeout guard so an expansion hang is a
test failure, never a stuck suite. Small internal
entities still expand (bounded by the same amplification
limit), and legitimate documents still parse — both
pinned as controls.

One XML defect WAS found, in depth handling rather than
entities: narlib/anim.py _et_node built its node tree
recursively, so a text-XML animation member nested past
the interpreter recursion limit (~1000 levels) escaped
parse_android_view with a RecursionError and was
silently dropped (returned as None) by the dispatch
layer. FIXED by building the tree iteratively; the
deep-nesting tests at the end of this file are its
regression. Every other site walks its tree iteratively
or shallowly and handles 3000-level nesting without a
crash (pinned per site).
"""
import hashlib
import importlib.util
import json
import os
import signal
import sys
import time
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import xml.etree.ElementTree as ET  # noqa: E402

from narlib import anim, atlas  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_test_helper(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "tests" / "unit" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


az = _load("nar_analyze_cert_seams", "nar-analyze.py")
nar_air = _load("nar_air_cert_seams", "nar-air.py")
nar_cordova = _load("nar_cordova_cert_seams", "nar-cordova.py")
nar_libgdx = _load("nar_libgdx_cert_seams", "nar-libgdx.py")
gi = _load_test_helper(
    "test_graph_investigation_cert_seams",
    "test_graph_investigation.py")

STAGE_DATA = dict(gi.OrchestrationDegradationTest.STAGE_DATA)
PERMS = gi.PERMS

SECRET = "XXE_SECRET_12345"


class _Timeout:
    """SIGALRM guard: an expansion hang fails the test
    instead of sticking the suite."""

    def __init__(self, seconds=20):
        self.seconds = seconds

    def __enter__(self):
        def _raise(signum, frame):
            raise TimeoutError(
                f"parse exceeded {self.seconds}s guard")
        self._old = signal.signal(signal.SIGALRM, _raise)
        signal.alarm(self.seconds)
        return self

    def __exit__(self, *exc):
        signal.alarm(0)
        signal.signal(signal.SIGALRM, self._old)
        return False


@pytest.fixture(autouse=True)
def _clean_az_state():
    az.EXEC_LOG.clear()
    yield
    az.EXEC_LOG.clear()
    az.set_layers(graph=True, investigation=True)


# ==================================================================
# TASK A (1): a child stage tool emitting malformed output
# on its channel — real fake-tool scripts through the real
# subprocess path (az.HERE pointed at the fake bin dir).
# ==================================================================

def _fake_bin(tmp_path, scripts):
    """Write real executable fake stage tools; return the
    dir to assign to az.HERE."""
    bin_dir = tmp_path / "fakebin"
    bin_dir.mkdir(exist_ok=True)
    for name, body in scripts.items():
        path = bin_dir / name
        path.write_text(
            "#!/usr/bin/env python3\n" + body, encoding="utf-8")
        path.chmod(0o755)
    return str(bin_dir)


def _run_tool_with_fake(monkeypatch, tmp_path, body,
                        script="nar-fake.py"):
    monkeypatch.setattr(az, "HERE", _fake_bin(
        tmp_path, {script: body}))
    return az.run_json_tool(script, [])


def test_child_garbage_stdout_is_named_failure(
        monkeypatch, tmp_path):
    data, err = _run_tool_with_fake(
        monkeypatch, tmp_path,
        "print('this is not json {{{')\n")
    assert data is None
    assert "nar-fake.py produced no JSON" in err
    assert az.EXEC_LOG[-1]["status"] == "failed"


def test_child_garbage_stdout_nonzero_exit_named_failure(
        monkeypatch, tmp_path):
    data, err = _run_tool_with_fake(
        monkeypatch, tmp_path,
        "import sys\nprint('garbage', file=sys.stderr)\n"
        "print('<html>not json</html>')\nsys.exit(3)\n")
    assert data is None
    assert "produced no JSON (exit 3)" in err
    assert az.EXEC_LOG[-1]["status"] == "failed"


def test_child_empty_stdout_is_named_failure(
        monkeypatch, tmp_path):
    data, err = _run_tool_with_fake(
        monkeypatch, tmp_path, "# prints nothing\n")
    assert data is None
    assert "produced no JSON" in err


def test_child_valid_object_still_serves(monkeypatch, tmp_path):
    data, err = _run_tool_with_fake(
        monkeypatch, tmp_path,
        "import json\nprint(json.dumps({'ok': True}))\n")
    assert err is None
    assert data == {"ok": True}
    assert az.EXEC_LOG[-1]["status"] == "ok"


@pytest.mark.parametrize("payload,shape", [
    ("\"just a string\"", "str"),
    ("[1, 2, 3]", "list"),
    ("42", "int"),
    ("null", "NoneType"),
    ("true", "bool"),
])
def test_child_nonobject_json_is_named_failure(
        monkeypatch, tmp_path, payload, shape):
    """Regression (D-03 seam defect): valid JSON of a
    non-object shape used to be returned as a successful
    stage document and crashed analyze() downstream with
    an AttributeError traceback."""
    data, err = _run_tool_with_fake(
        monkeypatch, tmp_path, f"print({payload!r})\n")
    assert data is None
    assert "returned a non-object JSON document" in err
    assert f"({shape})" in err
    assert az.EXEC_LOG[-1]["status"] == "failed"


def test_analyze_garbage_triage_is_named_fatal(
        monkeypatch, tmp_path):
    monkeypatch.setattr(az, "run_doctor", lambda: (
        {"core_ok": True, "core_problems": [],
         "optional_missing": [], "checks": []}, None))
    monkeypatch.setattr(az, "HERE", _fake_bin(tmp_path, {
        "nar-triage.py": "print('GARBAGE not json')\n"}))
    target = tmp_path / "t.apk"
    target.write_bytes(b"PK\x03\x04 dummy")
    report = az.analyze(str(target), str(tmp_path / "work"),
                        out_dir=str(tmp_path / "case"))
    assert report["fatal"].startswith("triage failed:")
    assert "produced no JSON" in report["fatal"]


def test_analyze_nonobject_triage_is_named_fatal(
        monkeypatch, tmp_path):
    """Regression: a triage tool emitting '[1, 2]' used to
    crash analyze() at triage.get with AttributeError."""
    monkeypatch.setattr(az, "run_doctor", lambda: (
        {"core_ok": True, "core_problems": [],
         "optional_missing": [], "checks": []}, None))
    monkeypatch.setattr(az, "HERE", _fake_bin(tmp_path, {
        "nar-triage.py": "print('[1, 2, 3]')\n"}))
    target = tmp_path / "t.apk"
    target.write_bytes(b"PK\x03\x04 dummy")
    report = az.analyze(str(target), str(tmp_path / "work"),
                        out_dir=str(tmp_path / "case"))
    assert report["fatal"].startswith("triage failed:")
    assert "non-object JSON document" in report["fatal"]


def test_analyze_nonobject_perms_degrades_named(
        monkeypatch, tmp_path):
    """Regression: a perms tool emitting a JSON string used
    to crash analyze() inside summarize_perms."""
    triage_doc = {"is_obb": False, "is_container": False,
                  "is_aab": False, "badging": {},
                  "container_manifest": {}}
    monkeypatch.setattr(az, "run_doctor", lambda: (
        {"core_ok": True, "core_problems": [],
         "optional_missing": [], "checks": []}, None))
    monkeypatch.setattr(az, "HERE", _fake_bin(tmp_path, {
        "nar-triage.py":
            "import json, sys\n"
            f"print(json.dumps({triage_doc!r}))\n",
        "nar-perms.py": "print('\"garbage-string\"')\n",
        "nar-strings.py":
            "import json\nprint(json.dumps({'groups': {}}))\n",
    }))
    target = tmp_path / "t.apk"
    with zipfile.ZipFile(target, "w") as zf:
        zf.writestr("classes.dex", b"dex\n035\x00")
    report = az.analyze(str(target), str(tmp_path / "work"),
                        out_dir=str(tmp_path / "case"))
    assert "fatal" not in report
    assert report["permissions"]["error"]
    assert "non-object JSON document" in \
        report["permissions"]["error"]
    assert any("Permission audit failed" in lim
               and "non-object" in lim
               for lim in report["limitations"])


def test_stage_garbage_child_degrades_to_named_limitation(
        monkeypatch, tmp_path):
    """run_2_0_stages through the REAL run_cached_stage:
    a fingerprint child emitting garbage degrades that one
    stage to a named limitation; the run completes and the
    builders still emit their companions over the
    remaining (absent) stage data with explicit notes."""
    def fake_tool(script, args, timeout=1800):
        if "fingerprint" in script:
            return None, ("nar-fingerprint.py produced no "
                          "JSON (exit 0): GARBAGE")
        return None, "stubbed unavailable"
    monkeypatch.setattr(az, "run_json_tool", fake_tool)
    target = tmp_path / "t.apk"
    target.write_bytes(b"dummy-target")
    out = tmp_path / "case"
    report = {"limitations": []}
    az.run_2_0_stages(report, str(target), str(out),
                      str(tmp_path), perms_data=PERMS)
    assert any(
        lim.startswith("2.0 stage fingerprint degraded:")
        and "produced no JSON" in lim
        for lim in report["limitations"])
    assert not (out / "fingerprint.json").exists()
    assert "fingerprint" not in report["companions"]
    # The optional layers are not silently dropped: they
    # are emitted over the degraded inputs.
    for name in ("graph.json", "investigation.json",
                 "correlations.json"):
        assert (out / name).is_file(), name
        doc = json.loads((out / name).read_text())
        assert isinstance(doc, dict)


# ==================================================================
# TASK A (2): companion / stage documents corrupted after
# the stages, driven through the builders at build time.
# ==================================================================

def _run_2_0_with_stub_stages(monkeypatch, tmp_path,
                              stage_data, perms_data):
    monkeypatch.setattr(
        az, "run_cached_stage",
        lambda stage, script, args, key, out:
            (stage_data[stage], None, False))
    target = tmp_path / "t.apk"
    target.write_bytes(b"dummy-target")
    out = tmp_path / "case"
    report = {"limitations": []}
    az.run_2_0_stages(report, str(target), str(out),
                      str(tmp_path), perms_data=perms_data)
    return report, out


@pytest.mark.parametrize("corrupt", [
    "garbage-string", [1, 2, 3], 42,
])
def test_builders_wrong_shape_perms_named_failure(
        monkeypatch, tmp_path, corrupt):
    """A permissions companion whose parsed shape is not
    an object reaches build_correlations / build_graph /
    build_investigation through run_2_0_stages: each
    companion degrades to a NAMED build-time limitation,
    none is written, and the rest of the case completes."""
    report, out = _run_2_0_with_stub_stages(
        monkeypatch, tmp_path, STAGE_DATA, corrupt)
    lims = report["limitations"]
    assert any("companion correlations.json not emitted: "
               "build failed" in lim for lim in lims)
    assert any("companion graph.json not emitted: "
               "graph builder failed" in lim for lim in lims)
    assert any("companion investigation.json not emitted: "
               "investigation builder failed" in lim
               for lim in lims)
    for name in ("correlations.json", "graph.json",
                 "investigation.json"):
        assert not (out / name).exists(), name
    # The failure is recorded in the execution log too.
    failed = {e["stage"] for e in az.EXEC_LOG
              if e["status"] == "failed"}
    assert {"graph", "investigation"} <= failed
    # Other companions still emitted: not an empty success
    # dressed as complete, and not a dead run.
    assert (out / "application.json").is_file()


def test_builders_wrong_shape_stage_doc_schema_gated(
        monkeypatch, tmp_path):
    """A stage document that parses but carries wrong-
    typed fields is stopped at build time by the stage
    schema gate with a named degradation, and the
    builders run over its absence (None) instead."""
    stage_data = dict(STAGE_DATA)
    stage_data["network"] = {"endpoints": "not-a-list",
                             "hosts": "not-a-list",
                             "services": "not-a-list"}
    report, out = _run_2_0_with_stub_stages(
        monkeypatch, tmp_path, stage_data, PERMS)
    assert any(
        lim.startswith("2.0 stage network degraded:")
        and "failed its companion schema" in lim
        for lim in report["limitations"])
    assert not (out / "endpoints.json").exists()
    # Builders still produced their companions.
    assert (out / "graph.json").is_file()
    assert (out / "investigation.json").is_file()


def test_builders_none_inputs_record_explicit_notes():
    """Direct builder entry points over fully degraded
    (None) stage data: the documents are built with
    explicit 'stage data unavailable' notes — an empty
    result is labelled, never silent."""
    from narlib import correlations, graph, investigation
    corr = correlations.build_correlations(
        None, None, None, None, "3.0.1")
    assert corr["counts"]["jni_matched"] == 0
    assert any("unavailable" in n for n in corr["notes"])
    gdoc = graph.build_graph()
    assert any("unavailable" in n for n in gdoc["notes"])
    idoc = investigation.build_investigation()
    assert any("unavailable" in n for n in idoc["notes"])


# ------------------------------------------------------------------
# Continuation: on-disk corruption after a completed run.
# ------------------------------------------------------------------

FINGERPRINT_DOC = gi.FINGERPRINT
DEX_DOC = {**gi.DEX, "tool": "nar-dex", "version": "3.0.1",
           "target": "t.apk", "target_sha256": "a" * 64,
           "totals": {"classes": 2}}


def _seed_case_with_cache(az_module, target, out):
    cache_key_base = (az_module.sha256_of(str(target))
                      + "|" + az_module.NAR_VERSION)
    return cache_key_base


def test_continuation_corrupt_stage_cache_reruns(
        monkeypatch, tmp_path):
    """Classic stage: corrupt cache/<stage>.json on disk
    (truncate / non-JSON / wrong-shape) after a completed
    run; the continuation treats it as a miss, re-runs the
    tool and rebuilds the companion — no traceback."""
    target = tmp_path / "t.apk"
    target.write_bytes(b"dummy-target")
    out = tmp_path / "case"

    def fake_tool(script, args, timeout=1800):
        if "fingerprint" in script:
            return dict(FINGERPRINT_DOC), None
        return None, "stubbed unavailable"
    monkeypatch.setattr(az, "run_json_tool", fake_tool)

    report1 = {"limitations": []}
    az.run_2_0_stages(report1, str(target), str(out),
                      str(tmp_path), perms_data=PERMS)
    assert report1["companions"]["fingerprint"]["cached"] \
        is False
    cache_path = Path(az._stage_cache_path(str(out),
                                           "fingerprint"))
    assert cache_path.is_file()

    for corruption in (b'{"source_sha256": "aa', b"not json",
                       b"[1, 2, 3]", b'"a string"'):
        cache_path.write_bytes(corruption)
        report2 = {"limitations": []}
        az.run_2_0_stages(report2, str(target), str(out),
                          str(tmp_path), perms_data=PERMS)
        assert report2["companions"]["fingerprint"][
            "cached"] is False, corruption
        rebuilt = json.loads(
            (out / "fingerprint.json").read_text())
        assert rebuilt["source_sha256"] == "a" * 64
        # The cache pair is whole again after the re-run.
        assert json.loads(cache_path.read_text())[
            "source_sha256"] == "a" * 64


def test_continuation_corrupt_dex_cache_falls_back(
        monkeypatch, tmp_path):
    """Streamed DEX stage: a cache corrupted after the
    run makes the streamed projection fail; the run falls
    back to the classic stage path, which treats the
    corrupt cache as a miss and re-runs the tool."""
    target = tmp_path / "t.apk"
    target.write_bytes(b"dummy-target")
    out = tmp_path / "case"
    (out / "cache").mkdir(parents=True)
    cache_key_base = _seed_case_with_cache(az, target, out)
    key = hashlib.sha256(
        f"{cache_key_base}|dex".encode()).hexdigest()
    cache_path = Path(az._stage_cache_path(str(out), "dex"))
    cache_path.write_text(json.dumps(DEX_DOC))
    (Path(str(cache_path) + ".key")).write_text(key)

    # Run 1: the streamed path serves the valid cache.
    report1 = {"limitations": []}
    az.run_2_0_stages(report1, str(target), str(out),
                      str(tmp_path), perms_data=PERMS)
    assert report1["companions"]["dex"]["cached"] is True

    def fake_tool(script, args, timeout=1800):
        if "dex" in script:
            return dict(DEX_DOC), None
        return None, "stubbed unavailable"
    monkeypatch.setattr(az, "run_json_tool", fake_tool)

    for corruption in (b'{"dex_files": [', b"not json",
                       b"[1, 2, 3]",
                       b'{"dex_files": "garbage", '
                       b'"totals": {}}'):
        cache_path.write_bytes(corruption)
        report2 = {"limitations": []}
        az.run_2_0_stages(report2, str(target), str(out),
                          str(tmp_path), perms_data=PERMS)
        # No traceback (we are here). Two named outcomes
        # are designed, depending on the corruption class:
        # unparseable / non-object cache is a miss and the
        # dex companion is rebuilt from the re-run tool;
        # a wrong-typed OBJECT cache is served by the
        # classic cache check but stopped by the stage
        # schema gate as a named degradation.
        if "dex" in report2["companions"]:
            assert report2["companions"]["dex"]["cached"] \
                is False, corruption
            rebuilt = json.loads(
                (out / "dex.json").read_text())
            assert rebuilt["tool"] == "nar-dex"
            assert rebuilt["totals"] == {"classes": 2}
        else:
            assert any(
                lim.startswith("2.0 stage dex degraded:")
                for lim in report2["limitations"]), corruption


def test_continuation_corrupt_companion_file_rebuilt(
        monkeypatch, tmp_path):
    """A companion FILE corrupted on disk after the run
    (the graph builder's own output) is rebuilt whole by
    the continuation run from the stage data — the
    corruption does not propagate into the new case."""
    report, out = _run_2_0_with_stub_stages(
        monkeypatch, tmp_path, STAGE_DATA, PERMS)
    graph_path = out / "graph.json"
    assert graph_path.is_file()
    graph_path.write_bytes(b'{"nodes": [corrupted')
    report2, _ = _run_2_0_with_stub_stages(
        monkeypatch, tmp_path, STAGE_DATA, PERMS)
    rebuilt = json.loads(graph_path.read_text())
    assert isinstance(rebuilt, dict)
    assert "counts" in rebuilt


# ==================================================================
# TASK B: XML parse sites — XXE / entity expansion probes.
#
# Site inventory (grep over scripts/, this tree):
#   ET.fromstring:
#     nar-air.py       parse_descriptor
#     nar-cordova.py   parse_config
#     nar-libgdx.py    parse_tmx
#     narlib/atlas.py  parse_xml_atlas
#     narlib/anim.py   parse_spriter
#     narlib/anim.py   _parse_text_xml_tree -> parse_android_view
#   plistlib.loads:
#     narlib/atlas.py  parse_cocos_plist
#     narlib/anim.py   parse_ccb
# No minidom / sax sites exist.
# ==================================================================

def _xxe_doc(secret_path, open_tag, close_tag, in_attr=False):
    if in_attr:
        return (
            '<?xml version="1.0"?>'
            '<!DOCTYPE r [<!ENTITY xxe SYSTEM '
            f'"file://{secret_path}">]>'
            + open_tag[0] + ' data="&xxe;"' + open_tag[1]
            + close_tag).encode()
    return (
        '<?xml version="1.0"?>'
        '<!DOCTYPE r [<!ENTITY xxe SYSTEM '
        f'"file://{secret_path}">]>'
        + open_tag + "&xxe;" + close_tag).encode()


def _laughs_doc(open_tag, close_tag):
    return (
        '<?xml version="1.0"?>'
        '<!DOCTYPE lolz ['
        '<!ENTITY lol "lollollollollollollollollollol">'
        '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;'
        '&lol;&lol;&lol;&lol;">'
        '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;'
        '&lol2;&lol2;&lol2;&lol2;&lol2;">'
        '<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;'
        '&lol3;&lol3;&lol3;&lol3;&lol3;">'
        '<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;'
        '&lol4;&lol4;&lol4;&lol4;&lol4;">'
        '<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;'
        '&lol5;&lol5;&lol5;&lol5;&lol5;">'
        '<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;'
        '&lol6;&lol6;&lol6;&lol6;&lol6;">'
        '<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;'
        '&lol7;&lol7;&lol7;&lol7;&lol7;">'
        '<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;'
        '&lol8;&lol8;&lol8;&lol8;&lol8;">'
        ']>' + open_tag + "&lol9;" + close_tag).encode()


def _quad_doc(open_tag, close_tag, entity_len=100_000,
              repeats=100):
    return (
        '<?xml version="1.0"?>'
        '<!DOCTYPE r [<!ENTITY a "' + "a" * entity_len
        + '">]>' + open_tag + "&a;" * repeats
        + close_tag).encode()


def _deep_dtd_doc(open_tag, close_tag):
    decls = "".join(
        f'<!ENTITY e{i} "v{i}">' for i in range(300))
    return (
        '<?xml version="1.0"?>'
        f'<!DOCTYPE r [{decls}]>' + open_tag + "text"
        + close_tag).encode()


def _deep_nest_doc(open_tag, close_tag, depth=3000):
    return (open_tag + "<x>" * depth + "deep"
            + "</x>" * depth + close_tag).encode()


@pytest.fixture()
def secret_file(tmp_path):
    path = tmp_path / "secret.txt"
    path.write_text(SECRET)
    return str(path)


# Per-site shapes: (open, close) wrapping the probe payload
# at a position the parser actually reads (element content
# or an attribute it surfaces).
AIR_OPEN = ('<application '
            'xmlns="http://ns.adobe.com/air/application/3.1">'
            '<id>')
AIR_CLOSE = '</id></application>'
CORDOVA_OPEN = '<widget id="com.example.x"><name>'
CORDOVA_CLOSE = '</name></widget>'
TMX_OPEN = '<map><layer name="'
TMX_CLOSE = '"/></map>'
ATLAS_OPEN = '<TextureAtlas imagePath="'
ATLAS_CLOSE = ('"><SubTexture name="a" x="1" y="2" '
               'width="3" height="4"/></TextureAtlas>')
SPRITER_OPEN = '<spriter_data><entity name="'
SPRITER_CLOSE = '"/></spriter_data>'
VIEW_OPEN = '<set><alpha android:duration="'
VIEW_CLOSE = '"/></set>'


def _assert_parse_error_only(fn):
    """The raising ET sites (air / cordova / libgdx) may
    surface only the errors their analyze() callers catch:
    ET.ParseError or ValueError. Anything else is a crash
    escaping as a traceback."""
    with _Timeout():
        with pytest.raises((ET.ParseError, ValueError)):
            fn()


# --- nar-air.py parse_descriptor ---------------------------------

def test_air_xxe_file_and_url_refused(secret_file):
    for payload in (
            _xxe_doc(secret_file, AIR_OPEN, AIR_CLOSE),
            _xxe_doc("http://127.0.0.1:9/evil",
                     AIR_OPEN, AIR_CLOSE)):
        _assert_parse_error_only(
            lambda: nar_air.parse_descriptor(payload))


def test_air_laughs_and_quad_refused():
    _assert_parse_error_only(lambda: nar_air.parse_descriptor(
        _laughs_doc(AIR_OPEN, AIR_CLOSE)))
    _assert_parse_error_only(lambda: nar_air.parse_descriptor(
        _quad_doc(AIR_OPEN, AIR_CLOSE)))


def test_air_deep_dtd_and_nesting_no_crash():
    with _Timeout():
        try:
            doc = nar_air.parse_descriptor(
                _deep_dtd_doc(AIR_OPEN, AIR_CLOSE))
            assert SECRET not in str(doc)
        except (ET.ParseError, ValueError):
            pass
        doc = nar_air.parse_descriptor(
            _deep_nest_doc(
                '<application xmlns="http://ns.adobe.com/'
                'air/application/3.1"><id>x</id>',
                '</application>'))
        assert doc["id"] == "x"


def test_air_legitimate_and_internal_entity_controls():
    doc = nar_air.parse_descriptor(
        b'<application '
        b'xmlns="http://ns.adobe.com/air/application/3.1">'
        b'<id>com.example.app</id></application>')
    assert doc["id"] == "com.example.app"
    doc = nar_air.parse_descriptor(
        b'<?xml version="1.0"?><!DOCTYPE a '
        b'[<!ENTITY v "1.2.3">]>'
        b'<application '
        b'xmlns="http://ns.adobe.com/air/application/3.1">'
        b'<id>x</id><versionNumber>&v;</versionNumber>'
        b'</application>')
    assert doc["versionNumber"] == "1.2.3"


# --- nar-cordova.py parse_config ---------------------------------

def test_cordova_xxe_file_and_url_refused(secret_file):
    for payload in (
            _xxe_doc(secret_file, CORDOVA_OPEN, CORDOVA_CLOSE),
            _xxe_doc("http://127.0.0.1:9/evil",
                     CORDOVA_OPEN, CORDOVA_CLOSE)):
        _assert_parse_error_only(
            lambda: nar_cordova.parse_config(payload))


def test_cordova_laughs_and_quad_refused():
    _assert_parse_error_only(
        lambda: nar_cordova.parse_config(
            _laughs_doc(CORDOVA_OPEN, CORDOVA_CLOSE)))
    _assert_parse_error_only(
        lambda: nar_cordova.parse_config(
            _quad_doc(CORDOVA_OPEN, CORDOVA_CLOSE)))


def test_cordova_deep_no_crash_and_control():
    with _Timeout():
        try:
            result = nar_cordova.parse_config(
                _deep_dtd_doc(CORDOVA_OPEN, CORDOVA_CLOSE))
            assert SECRET not in str(result)
        except (ET.ParseError, ValueError):
            pass
        result = nar_cordova.parse_config(_deep_nest_doc(
            '<widget id="x"><name>n</name>', '</widget>'))
        assert result[0]["name"] == "n"
    descriptor, _features = nar_cordova.parse_config(
        b'<widget id="com.example.x" version="1.0">'
        b'<name>Demo</name></widget>')
    assert descriptor["name"] == "Demo"


# --- nar-libgdx.py parse_tmx --------------------------------------

def test_libgdx_xxe_file_and_url_refused(secret_file):
    # The probe entity sits in the layer name ATTRIBUTE
    # (a value parse_tmx surfaces in its record).
    for payload in (
            _xxe_doc(secret_file, ("<map><layer ", 'name='),
                     '" x="1"/></map>', in_attr=False)
            if False else
            ('<?xml version="1.0"?>'
             '<!DOCTYPE m [<!ENTITY xxe SYSTEM '
             f'"file://{secret_file}">]>'
             '<map><layer name="&xxe;"/></map>').encode(),
            ('<?xml version="1.0"?>'
             '<!DOCTYPE m [<!ENTITY xxe SYSTEM '
             '"http://127.0.0.1:9/evil">]>'
             '<map><layer name="&xxe;"/></map>').encode()):
        _assert_parse_error_only(
            lambda: nar_libgdx.parse_tmx(payload, "m.tmx"))


def test_libgdx_laughs_and_quad_refused():
    payload = _laughs_doc('<map><layer name="', '"/></map>')
    _assert_parse_error_only(
        lambda: nar_libgdx.parse_tmx(payload, "m.tmx"))
    payload = _quad_doc('<map><layer name="', '"/></map>')
    _assert_parse_error_only(
        lambda: nar_libgdx.parse_tmx(payload, "m.tmx"))


def test_libgdx_deep_no_crash_and_control():
    with _Timeout():
        rec = nar_libgdx.parse_tmx(
            _deep_nest_doc("<map>", "</map>"), "m.tmx")
        assert rec["file"] == "m.tmx"
    rec = nar_libgdx.parse_tmx(
        b'<map><layer name="ground"/></map>', "m.tmx")
    assert rec["layers"] == [{"kind": "tilelayer",
                              "name": "ground"}]


# --- narlib/atlas.py parse_xml_atlas ------------------------------

def test_atlas_xml_xxe_no_external_content(secret_file):
    for payload in (
            _xxe_doc(secret_file,
                     '<TextureAtlas imagePath="',
                     ATLAS_CLOSE),
            _xxe_doc("http://127.0.0.1:9/evil",
                     '<TextureAtlas imagePath="',
                     ATLAS_CLOSE)):
        with _Timeout():
            rec = atlas.parse_xml_atlas(payload)
        # A named error record, never a crash, and the
        # external content is nowhere in the output.
        assert rec["format"] == "xml-atlas"
        assert rec["error"]
        assert SECRET not in str(rec)


def test_atlas_xml_laughs_and_quad_bounded():
    with _Timeout():
        rec = atlas.parse_xml_atlas(
            _laughs_doc('<TextureAtlas imagePath="',
                        ATLAS_CLOSE))
    assert rec["error"]
    with _Timeout():
        rec = atlas.parse_xml_atlas(
            _quad_doc('<TextureAtlas imagePath="',
                      ATLAS_CLOSE))
    assert rec["error"]
    # A small quadratic document under the amplification
    # limit parses, but its expansion stays bounded by
    # that limit (entity 50k x 10 repeats = 500k chars).
    with _Timeout():
        rec = atlas.parse_xml_atlas(_quad_doc(
            '<TextureAtlas imagePath="', ATLAS_CLOSE,
            entity_len=50_000, repeats=10))
    assert rec.get("texture") is not None
    assert len(rec["texture"]) <= 500_000


def test_atlas_xml_deep_and_control():
    with _Timeout():
        rec = atlas.parse_xml_atlas(_deep_nest_doc(
            '<TextureAtlas imagePath="t.png">',
            '</TextureAtlas>'))
    assert rec["format"] in ("xml-atlas", "starling-xml",
                             "texturepacker-xml") \
        or rec.get("error")
    rec = atlas.parse_xml_atlas(
        b'<TextureAtlas imagePath="sheet.png">'
        b'<SubTexture name="a" x="1" y="2" width="3" '
        b'height="4"/></TextureAtlas>')
    assert rec["texture"] == "sheet.png"
    assert rec["frame_count"] == 1


# --- narlib/anim.py parse_spriter ---------------------------------

def test_spriter_xxe_no_external_content(secret_file):
    for payload in (
            _xxe_doc(secret_file,
                     '<spriter_data><entity name="',
                     SPRITER_CLOSE),
            _xxe_doc("http://127.0.0.1:9/evil",
                     '<spriter_data><entity name="',
                     SPRITER_CLOSE)):
        with _Timeout():
            rec = anim.parse_spriter(payload, "t.scml")
        assert rec is not None
        assert rec["status"] == "identified_only"
        assert "XML parse failed" in rec["reason"]
        assert SECRET not in str(rec)


def test_spriter_laughs_and_quad_refused():
    for payload in (
            _laughs_doc('<spriter_data><entity name="',
                        SPRITER_CLOSE),
            _quad_doc('<spriter_data><entity name="',
                      SPRITER_CLOSE)):
        with _Timeout():
            rec = anim.parse_spriter(payload, "t.scml")
        assert rec["status"] == "identified_only"
        assert "XML parse failed" in rec["reason"]


def test_spriter_deep_and_control():
    with _Timeout():
        rec = anim.parse_spriter(
            _deep_nest_doc("<spriter_data>",
                           "</spriter_data>"), "t.scml")
    assert rec is None or rec["status"] in (
        "identified_only", "decoded")
    rec = anim.parse_spriter(
        b'<spriter_data><entity id="0" name="hero">'
        b'<animation id="0" name="idle" length="1000">'
        b'<mainline><key id="0"/></mainline>'
        b'</animation></entity></spriter_data>', "t.scml")
    assert rec is not None
    assert rec["status"] == "decoded"


# --- narlib/anim.py _parse_text_xml_tree (android-view) -----------

def test_android_view_xxe_no_external_content(secret_file):
    for payload in (
            _xxe_doc(secret_file,
                     '<set><alpha android:duration="',
                     VIEW_CLOSE),
            _xxe_doc("http://127.0.0.1:9/evil",
                     '<set><alpha android:duration="',
                     VIEW_CLOSE)):
        with _Timeout():
            rec = anim.parse_android_view(
                payload, "res/anim/t.xml")
        assert rec is not None
        assert rec["status"] == "identified_only"
        assert SECRET not in str(rec)


def test_android_view_laughs_and_quad_refused():
    for payload in (
            _laughs_doc('<set><alpha android:duration="',
                        VIEW_CLOSE),
            _quad_doc('<set><alpha android:duration="',
                      VIEW_CLOSE)):
        with _Timeout():
            rec = anim.parse_android_view(
                payload, "res/anim/t.xml")
        assert rec["status"] == "identified_only"


def test_android_view_control():
    rec = anim.parse_android_view(
        b'<set xmlns:android="http://schemas.android.com/'
        b'apk/res/android"><alpha android:duration="300" '
        b'android:fromAlpha="0" android:toAlpha="1"/>'
        b'</set>', "res/anim/fade.xml")
    assert rec is not None
    assert rec["status"] == "decoded"
    assert rec["facts"]["durations_ms"] == [300]


# --- plistlib sites -------------------------------------------------

def _plist_doc(inner):
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        + inner).encode()


def _plist_xxe(secret_path):
    return _plist_doc(
        '<!DOCTYPE plist [<!ENTITY xxe SYSTEM '
        f'"file://{secret_path}">]>'
        '<plist version="1.0"><dict><key>frames</key>'
        '<dict><key>a</key><dict><key>frame</key>'
        '<string>&xxe;</string></dict></dict></dict>'
        '</plist>')


def _plist_laughs():
    return _plist_doc(
        '<!DOCTYPE plist [<!ENTITY lol "lollollol">'
        '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;'
        '&lol;&lol;&lol;&lol;">'
        '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;'
        '&lol2;&lol2;&lol2;&lol2;&lol2;">'
        '<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;'
        '&lol3;&lol3;&lol3;&lol3;&lol3;">'
        '<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;'
        '&lol4;&lol4;&lol4;&lol4;&lol4;">]>'
        '<plist version="1.0"><dict><key>frames</key>'
        '<dict><key>a</key><dict><key>frame</key>'
        '<string>&lol5;</string></dict></dict></dict>'
        '</plist>')


def test_atlas_plist_xxe_and_laughs_refused(secret_file):
    for payload in (_plist_xxe(secret_file),
                    _plist_xxe("http://127.0.0.1:9/evil"),
                    _plist_laughs()):
        with _Timeout():
            rec = atlas.parse_cocos_plist(payload)
        # plistlib refuses entity declarations outright;
        # the site surfaces that as a named error record.
        assert rec["format"] == "cocos-plist"
        assert rec["error"]
        assert "entity" in rec["error"] or \
            "plist" in rec["error"]
        assert SECRET not in str(rec)


def test_ccb_plist_xxe_and_laughs_refused(secret_file):
    for payload in (_plist_xxe(secret_file),
                    _plist_laughs()):
        with _Timeout():
            rec = anim.parse_ccb(payload, "t.ccb")
        assert rec["status"] == "identified_only"
        assert "plistlib could not parse" in rec["reason"]
        assert SECRET not in str(rec)


def test_plist_controls_still_parse():
    good = _plist_doc(
        '<plist version="1.0"><dict><key>frames</key>'
        '<dict><key>a.png</key><dict>'
        '<key>frame</key>'
        '<string>{{1,2},{3,4}}</string>'
        '<key>rotated</key><false/>'
        '<key>offset</key><string>{0,0}</string>'
        '<key>sourceSize</key><string>{3,4}</string>'
        '</dict></dict>'
        '<key>metadata</key><dict><key>format</key>'
        '<integer>2</integer><key>textureFileName</key>'
        '<string>sheet.png</string></dict></dict></plist>')
    rec = atlas.parse_cocos_plist(good)
    assert rec["error"] is None
    assert rec["frame_count"] == 1


# --- deeply nested XML: the anim text-XML tree builder -------

def test_android_view_deeply_nested_no_recursion_crash():
    """Regression (XML seam defect): _et_node built the
    node tree recursively, so a text-XML animation member
    nested past the interpreter recursion limit escaped
    parse_android_view with a RecursionError traceback.
    The builder is iterative now: the member decodes (its
    facts walker was already stack-based)."""
    payload = (
        '<set xmlns:android="http://schemas.android.com/'
        'apk/res/android">'
        + "<x>" * 3000 + "<alpha android:duration=\"300\"/>"
        + "</x>" * 3000 + "</set>").encode()
    with _Timeout():
        rec = anim.parse_android_view(payload,
                                      "res/anim/deep.xml")
    assert rec is not None
    assert rec["status"] == "decoded"
    assert rec["facts"]["element_count"] == 3002
    assert rec["facts"]["durations_ms"] == [300]
    # The dispatch entry point agrees (no silent drop).
    with _Timeout():
        rec2 = anim.classify_and_parse("res/anim/deep.xml",
                                       payload)
    assert rec2 is not None
    assert rec2["status"] == "decoded"


def test_android_view_deep_dtd_no_crash():
    payload = _deep_dtd_doc(
        '<set xmlns:android="http://schemas.android.com/'
        'apk/res/android"><alpha android:duration="100"/>',
        '</set>')
    with _Timeout():
        rec = anim.parse_android_view(payload,
                                      "res/anim/t.xml")
    assert rec is not None
    assert rec["status"] in ("decoded", "identified_only")
    assert SECRET not in str(rec)
