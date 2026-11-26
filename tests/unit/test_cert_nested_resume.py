"""Certification Phase 3, workstream NEST (findings D-02 + D-04).

D-02 — nested-archive depth at the CALLER level. The safe
archive layer lists nested archives and flags the depth
limit but never recurses itself; recursion is each caller's
decision. These tests drive an archive nested deeper than
every configured bound (zip-in-zip, ``limit + 3`` layers,
each layer also carrying a plain payload file) through the
three real extraction callers and prove, per caller, that
the run terminates, the depth bound is honoured (nothing
beyond the bound is extracted or resolved), and the outcome
is NAMED (a limit flag, a refusal record, or a named error
— never silence, a crash, or unbounded recursion):

- ``nar-input extract`` (never recurses; the nested archive
  is extracted as an opaque file and named in the report),
- ``narlib.container.resolve_target`` (recurses under
  ``MAX_CONTAINER_DEPTH``; both recursion sites — a nested
  container member with no direct base, and a base/split
  that is itself a container — must record the depth-limit
  refusal in ``split_skipped``),
- ``nar-analyze`` over a container target (the container
  block + step notes must name the depth limit), and
  ``nar-analyze import_case`` (the bundle extraction at the
  safearchive call site: a non-bundle deep archive is
  refused by name before extraction; a valid bundle
  carrying a deep member imports with the member opaque
  and surfaced, never opened).

D-04 — violent interruption + resume. The polite
budget-boundary resume was already proven elsewhere; these
tests SIGKILL a running ``nar-analyze`` (whole process
group) at an early, a mid, and a late stage milestone,
then rerun into the SAME case directory and prove: the
rerun exits 0 with no traceback on either run, the case
verifies clean through the repo's own verify path, and no
partial stage document is ever presented as valid — a kill
mid-write leaves at worst a cache MISS. The MISS property
is also proven deterministically by planting the exact
on-disk states a kill can leave (truncated document with a
matching key, document without its key, a lone temp file)
against the generic, streamed-DEX, and decompile stage
cache writers and asserting each is treated as a miss and
re-run, never served.

Synthetic inputs only for D-02; the retained demo fixture
for D-04 (its full run spans enough stages to kill at
three distinct points).
"""
import hashlib
import importlib.util
import io
import json
import os
import signal
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from narlib import container as C  # noqa: E402
from narlib import safearchive  # noqa: E402

FIXTURES = os.environ.get(
    "NAR_FIXTURES",
    os.path.expanduser("~/workspace/nar-e2e-fixtures"))
DEMO = os.path.join(FIXTURES, "demo", "NarDemo.apk")

#: The configured bounds the hostile chains are built
#: against: safearchive nesting (2) and the container
#: resolver's own recursion ceiling (3).
SA_LIMIT = safearchive.DEFAULT_LIMITS["max_nesting"]
CT_LIMIT = C.MAX_CONTAINER_DEPTH


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, str(SCRIPTS / filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


az = _load("nar_analyze_certnr", "nar-analyze.py")


def _run(script, args, timeout=900):
    return subprocess.run(
        [sys.executable, str(SCRIPTS / script)] + args,
        capture_output=True, text=True, timeout=timeout)


def _zip_bytes(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


def _fake_apk(extra=()):
    """An APK-shaped zip: enough structure for content-based
    container detection (manifest + dex + resources)."""
    return _zip_bytes([
        ("AndroidManifest.xml", b"<manifest/>"),
        ("classes.dex", b"dex\n039\x00" + b"\x00" * 100),
        ("resources.arsc", b"\x02\x00\x0c\x00")] + list(extra))


def _deep_zip_chain(wraps):
    """A zip nested ``wraps`` times around an innermost zip
    holding ``secret.txt``; every layer also carries a plain
    payload file. Returns the outermost archive's bytes.
    The innermost archive is stored as ``level0.zip``, the
    next as ``level1.zip``, and so on."""
    data = _zip_bytes([("secret.txt", b"innermost secret")])
    name = "level0.zip"
    for i in range(1, wraps + 1):
        data = _zip_bytes([
            (f"payload_{i}.txt", f"payload-{i}".encode()),
            (name, data)])
        name = f"level{i}.zip"
    return data


def _apk_chain(wraps):
    """A real-shaped APK wrapped in ``wraps`` plain zip
    layers (each also carrying a payload file): the
    container resolver's no-direct-base recursion path."""
    data = _fake_apk()
    name = "base.apk"
    for i in range(wraps):
        data = _zip_bytes([
            (f"payload_{i}.txt", b"x"), (name, data)])
        name = f"wrap_{i}.zip"
    return data


def _xapk_chain(wraps):
    """An XAPK whose base entry is itself an XAPK, wrapped
    ``wraps`` times: the container resolver's
    base-is-a-container recursion path. Manifests are
    consistent at every level (the outer declares the
    ``base.apk`` it carries; the innermost declares the
    real APK it carries), so a within-limit resolution is
    record-clean."""
    inner_manifest = json.dumps({
        "package_name": "com.example.game",
        "split_apks": [{"file": "com.example.game.apk",
                        "id": "base"}]}).encode()
    outer_manifest = json.dumps({
        "package_name": "com.example.game",
        "split_apks": [{"file": "base.apk",
                        "id": "base"}]}).encode()
    data = _zip_bytes([
        ("manifest.json", inner_manifest),
        ("com.example.game.apk", _fake_apk())])
    for _i in range(wraps):
        data = _zip_bytes([
            ("manifest.json", outer_manifest),
            ("base.apk", data)])
    return data


def _depth_records(resolved):
    return [s for s in resolved.split_skipped
            if "depth limit" in s["reason"]]


# ------------------------------------------------------------------
# D-02 — the configured bounds, pinned
# ------------------------------------------------------------------

def test_configured_depth_bounds():
    from narlib.budget import ResourceBudget
    assert SA_LIMIT == 2
    assert ResourceBudget().max_nesting_depth == SA_LIMIT
    assert CT_LIMIT == 3


def test_safearchive_flag_contract_at_the_limit(tmp_path):
    """The flag callers rely on: at ``_depth == max_nesting``
    a nested archive is listed AND the limit flag is set;
    below the limit it is listed without the flag."""
    src = tmp_path / "outer.zip"
    src.write_bytes(_deep_zip_chain(1))
    report = safearchive.safe_extract(
        str(src), str(tmp_path / "o1"), _depth=SA_LIMIT)
    assert report["nested_archives"] == ["level0.zip"]
    assert report.get("nesting_limit_reached") is True
    report = safearchive.safe_extract(
        str(src), str(tmp_path / "o2"), _depth=0)
    assert report["nested_archives"] == ["level0.zip"]
    assert report.get("nesting_limit_reached") is not True


# ------------------------------------------------------------------
# D-02 — caller 1: nar-input extract
# ------------------------------------------------------------------

def test_nar_input_extract_over_depth_named_and_bounded(tmp_path):
    wraps = SA_LIMIT + 3
    src = tmp_path / "deep.zip"
    src.write_bytes(_deep_zip_chain(wraps))
    out = tmp_path / "out"
    proc = _run("nar-input.py",
                ["extract", str(src), "--out", str(out),
                 "--json"], timeout=120)
    assert proc.returncode == 0, proc.stderr[-500:]
    assert "Traceback" not in proc.stderr
    data = json.loads(proc.stdout)
    # Only the outermost layer is extracted: its payload and
    # the first inner archive as an opaque file. The nested
    # archive is NAMED in the report, never auto-opened.
    assert {e["entry"] for e in data["extracted"]} == \
        {f"payload_{wraps}.txt", f"level{wraps - 1}.zip"}
    assert data["nested_archives"] == [f"level{wraps - 1}.zip"]
    assert data["rejected"] == []
    on_disk = {p.name for p in out.rglob("*") if p.is_file()}
    assert on_disk == {f"payload_{wraps}.txt",
                       f"level{wraps - 1}.zip"}
    assert "secret.txt" not in on_disk
    # The human rendering names it too.
    proc = _run("nar-input.py",
                ["extract", str(src), "--out",
                 str(tmp_path / "out2")], timeout=120)
    assert proc.returncode == 0, proc.stderr[-500:]
    assert "nested archive (not auto-opened)" in proc.stdout
    assert f"level{wraps - 1}.zip" in proc.stdout


# ------------------------------------------------------------------
# D-02 — caller 2: narlib.container.resolve_target
# ------------------------------------------------------------------

def test_container_pure_zip_chain_depth_limit_named(tmp_path):
    wraps = CT_LIMIT + 2
    src = tmp_path / "deep.zip"
    src.write_bytes(_deep_zip_chain(wraps))
    with C.resolve_target(str(src)) as r:
        # Bound honoured: nothing was resolved out of the
        # chain — no base, no roots, no splits.
        assert r.base_entry is None
        assert r.assets_roots == []
        assert r.splits == []
        # …and the stop is NAMED: exactly one depth-limit
        # record, for the nested member the resolver would
        # have followed at the deepest resolved level.
        records = _depth_records(r)
        assert len(records) == 1
        assert records[0]["name"] == "level1.zip"
        assert str(CT_LIMIT) in records[0]["reason"]


def test_container_pure_zip_chain_within_limit_no_record(tmp_path):
    src = tmp_path / "deep.zip"
    src.write_bytes(_deep_zip_chain(CT_LIMIT - 1))
    with C.resolve_target(str(src)) as r:
        assert r.base_entry is None
        assert _depth_records(r) == []


def test_container_apk_chain_over_depth_named(tmp_path):
    src = tmp_path / "deep.zip"
    src.write_bytes(_apk_chain(CT_LIMIT + 2))
    with C.resolve_target(str(src)) as r:
        assert r.base_entry is None
        assert r.assets_roots == []
        assert r.splits == []
        records = _depth_records(r)
        assert len(records) == 1
        assert records[0]["name"].endswith(".zip")
        assert str(CT_LIMIT) in records[0]["reason"]


def test_container_apk_chain_at_boundary_resolves(tmp_path):
    """Boundary control: a chain whose deepest container
    sits exactly at the limit but holds the APK as a direct
    member resolves fully, with no depth-limit record."""
    src = tmp_path / "deep.zip"
    src.write_bytes(_apk_chain(CT_LIMIT + 1))
    with C.resolve_target(str(src)) as r:
        assert r.base_entry == "base.apk"
        assert os.path.basename(r.base) == "base.apk"
        assert r.assets_roots == [r.base]
        assert _depth_records(r) == []


def test_container_base_is_container_over_depth_named(tmp_path):
    src = tmp_path / "deep.xapk"
    src.write_bytes(_xapk_chain(CT_LIMIT + 1))
    with C.resolve_target(str(src)) as r:
        # Resolution stopped at a file that is itself a
        # container — and the stop is NAMED, for the base
        # entry that was left unopened.
        assert C.detect_container(r.base) in C.CONTAINER_KINDS
        records = _depth_records(r)
        assert len(records) == 1
        assert records[0]["name"] == "base.apk"
        assert str(CT_LIMIT) in records[0]["reason"]


def test_container_base_is_container_at_boundary_resolves(tmp_path):
    src = tmp_path / "deep.xapk"
    src.write_bytes(_xapk_chain(CT_LIMIT))
    with C.resolve_target(str(src)) as r:
        # The base path resolved all the way to the real
        # APK; base_entry keeps this container's provenance
        # (the base.apk entry whose content resolved there).
        assert os.path.basename(r.base) == \
            "com.example.game.apk"
        assert r.base_entry == "base.apk"
        assert r.split_skipped == []


# ------------------------------------------------------------------
# D-02 — caller 2b: nar-analyze (container path + bundle import)
# ------------------------------------------------------------------

@pytest.mark.skipif(not os.path.isfile(DEMO),
                    reason="demo fixture absent")
def test_analyze_over_depth_container_names_limit(tmp_path):
    demo_bytes = Path(DEMO).read_bytes()
    data = demo_bytes
    name = "base.apk"
    for i in range(CT_LIMIT + 2):
        data = _zip_bytes([(f"payload_{i}.txt", b"x"),
                           (name, data)])
        name = f"wrap_{i}.zip"
    target = tmp_path / "deep.zip"
    target.write_bytes(data)
    case = tmp_path / "case"
    proc = _run("nar-analyze.py",
                [str(target), "--out", str(case), "--no-html"],
                timeout=600)
    assert proc.returncode == 0, proc.stderr[-1000:]
    assert "Traceback" not in proc.stderr
    report = json.loads(
        (case / "report.json").read_text(encoding="utf-8"))
    block = report["container"]
    # The bound was honoured (no base APK was resolved out
    # of the over-depth chain) and the limit is named in
    # both the container block and the step notes.
    assert block["base_entry"] is None
    assert any("depth limit" in s["reason"]
               for s in block["split_skipped"])
    assert any("depth limit" in n
               for n in report["step_notes"])


def test_import_case_deep_archive_refused_by_name(tmp_path):
    src = tmp_path / "deep.zip"
    src.write_bytes(_deep_zip_chain(SA_LIMIT + 3))
    out = tmp_path / "imported"
    with pytest.raises(ValueError) as ei:
        az.import_case(str(src), str(out))
    assert "not a NAR case bundle" in str(ei.value)
    assert not out.exists()


@pytest.fixture(scope="module")
def demo_case(tmp_path_factory):
    if not os.path.isfile(DEMO):
        pytest.skip("demo fixture absent")
    case = tmp_path_factory.mktemp("certnr-case") / "case"
    proc = _run("nar-analyze.py",
                [DEMO, "--out", str(case), "--no-html"],
                timeout=600)
    assert proc.returncode == 0, proc.stderr[-1000:]
    return str(case)


def test_import_case_bundle_member_stays_opaque(tmp_path,
                                                 demo_case):
    bundle = str(tmp_path / "case.zip")
    summary = az.export_case(demo_case, bundle)
    assert summary["files"] > 0
    with zipfile.ZipFile(bundle, "a",
                         zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("payload/deep-nest.zip",
                    _deep_zip_chain(SA_LIMIT + 3))
    out = str(tmp_path / "imported")
    result = az.import_case(bundle, out)
    assert result["ok"] is True
    # The deep member is surfaced by name (not in the bundle
    # manifest), carried as one opaque file, and never
    # opened: none of its layers' payloads — let alone the
    # innermost secret — appear in the imported case.
    assert result["files_not_in_manifest"] == \
        ["payload/deep-nest.zip"]
    assert os.path.isfile(
        os.path.join(out, "payload", "deep-nest.zip"))
    names = {p.name for p in Path(out).rglob("*")
             if p.is_file()}
    assert "secret.txt" not in names
    assert not any(n.startswith("payload_")
                   and n.endswith(".txt") for n in names)
    assert not any(n.startswith("level") for n in names)


# ------------------------------------------------------------------
# D-04 — planted kill states: a mid-write kill is a MISS,
# never a corrupt HIT (deterministic, per cache writer)
# ------------------------------------------------------------------

def _plant_pair(out_dir, stage, doc_bytes, key_text):
    cache_dir = Path(out_dir) / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    doc = cache_dir / f"{stage}.json"
    if doc_bytes is not None:
        doc.write_bytes(doc_bytes)
    if key_text is not None:
        Path(str(doc) + ".key").write_text(key_text)
    return doc


def test_generic_stage_planted_kill_states_are_misses(
        tmp_path, monkeypatch):
    """The generic stage writer (temp + rename, key last):
    each state a SIGKILL can leave behind — a truncated
    document whose key already matches, a document whose
    key was never written, a lone temp file — is a cache
    MISS (the stage re-runs), never a corrupt HIT. The
    control pair (valid document + matching key) still
    HITs, so the miss behaviour is discrimination, not a
    disabled cache."""
    fresh = {"fresh": True, "tool": "nar-fingerprint"}
    calls = {"n": 0}

    def fake_tool(script, args):
        calls["n"] += 1
        return dict(fresh), None

    monkeypatch.setattr(az, "run_json_tool", fake_tool)
    key = "ab" * 32
    truncated = b'{"tool": "nar-fingerprint", "propert'

    # (a) truncated document + matching key: corrupt pair.
    out_a = tmp_path / "a"
    doc = _plant_pair(out_a, "fingerprint", truncated, key)
    data, err, cached = az._run_cached_stage_inner(
        "fingerprint", "nar-fingerprint.py", [], key,
        str(out_a))
    assert (data, err, cached) == (fresh, None, False)
    assert json.loads(doc.read_text(encoding="utf-8")) == fresh

    # (b) valid document, key never written (kill landed
    # between the document rename and the key write).
    out_b = tmp_path / "b"
    _plant_pair(out_b, "fingerprint",
                json.dumps({"stale": True}).encode(), None)
    data, err, cached = az._run_cached_stage_inner(
        "fingerprint", "nar-fingerprint.py", [], key,
        str(out_b))
    assert (data, cached) == (fresh, False)

    # (c) lone temp file (kill landed mid document write,
    # before any rename).
    out_c = tmp_path / "c"
    cache_dir = out_c / "cache"
    cache_dir.mkdir(parents=True)
    (cache_dir / "fingerprint.json.tmp").write_bytes(truncated)
    data, err, cached = az._run_cached_stage_inner(
        "fingerprint", "nar-fingerprint.py", [], key,
        str(out_c))
    assert (data, cached) == (fresh, False)

    # (d) control: a complete pair HITs and the tool does
    # not run again.
    out_d = tmp_path / "d"
    planted = {"planted": "complete"}
    _plant_pair(out_d, "fingerprint",
                json.dumps(planted).encode(), key)
    before = calls["n"]
    data, err, cached = az._run_cached_stage_inner(
        "fingerprint", "nar-fingerprint.py", [], key,
        str(out_d))
    assert (data, err, cached) == (planted, None, True)
    assert calls["n"] == before
    az.EXEC_LOG.clear()


def test_dex_streamed_planted_corrupt_pair_not_served(tmp_path):
    """The streamed DEX writer promotes its spool to the
    cache path and then writes the key. A planted pair in
    the worst state a kill can leave — a truncated cache
    document whose key file already carries the matching
    key — must not be served as a valid stage document:
    the projection read fails loudly (the orchestrator's
    caller catches it, drops the pair, and falls back to
    the classic stage path), and no companion is written
    from the corrupt bytes."""
    if not os.path.isfile(DEMO):
        pytest.skip("demo fixture absent")
    out_dir = tmp_path / "case"
    cache_key_base = az.sha256_of(DEMO) + "|" + az.NAR_VERSION
    key = hashlib.sha256(
        f"{cache_key_base}|dex".encode()).hexdigest()
    _plant_pair(out_dir, "dex",
                b'{"tool": "nar-dex", "dex_files": [{"name": "cl',
                key)
    report = {"limitations": []}
    companions = {}
    with pytest.raises(Exception):
        az._dex_stage_streamed_inner(
            report, companions, DEMO, str(out_dir),
            str(out_dir / "dex"), cache_key_base,
            lambda data: None)
    assert "dex" not in companions
    assert not (out_dir / "dex.json").exists()
    az.EXEC_LOG.clear()


def test_decompile_planted_corrupt_pair_is_miss(tmp_path):
    """The decompile stage writer (temp + rename, key
    last): a truncated record with a matching key is
    dropped and the stage re-runs — here against a target
    with no DEX, which the chain answers with an
    identified-only record and no external tools."""
    if az._chains is None:
        pytest.skip("narlib.chains unavailable")
    target = tmp_path / "nodex.zip"
    target.write_bytes(_zip_bytes([("readme.txt", b"hi")]))
    out_dir = tmp_path / "case"
    cache_key_base = az.sha256_of(str(target)) + \
        "|" + az.NAR_VERSION
    key = hashlib.sha256(
        f"{cache_key_base}|decompile".encode()).hexdigest()
    doc = _plant_pair(out_dir, "decompile",
                      b'{"capability": "java-decompile", "ser',
                      key)
    report = {"limitations": []}
    companions = {}
    record = az._decompile_stage(
        report, companions, str(target), str(out_dir),
        cache_key_base)
    assert isinstance(record, dict)
    assert companions["decompile"]["cached"] is False
    assert report["decompile"] == record
    # The corrupt bytes are gone: the cache now holds the
    # fresh record, parseable, under the same key.
    assert json.loads(doc.read_text(encoding="utf-8")) == record
    az.EXEC_LOG.clear()


# ------------------------------------------------------------------
# D-04 — violent interruption: SIGKILL, then resume into
# the SAME case directory
# ------------------------------------------------------------------

def _expected_stage_key(stage):
    input_sha = hashlib.sha256(Path(DEMO).read_bytes()).hexdigest()
    return hashlib.sha256(
        f"{input_sha}|{az.NAR_VERSION}|{stage}"
        .encode()).hexdigest()


def _assert_no_corrupt_hit(case_dir):
    """The kill-time invariant, checked on whatever state
    the SIGKILL left: any stage cache document whose key
    file already carries the expected key must be a
    complete, parseable JSON object. A document with a
    missing or mismatched key is a MISS state (the resume
    re-runs that stage) and is allowed; a document with a
    matching key that does not parse would be a corrupt
    HIT waiting to be served, and fails here."""
    cache = Path(case_dir) / "cache"
    if not cache.is_dir():
        return
    for doc in sorted(cache.glob("*.json")):
        key_file = Path(str(doc) + ".key")
        if not key_file.is_file():
            continue
        if key_file.read_text(encoding="utf-8").strip() != \
                _expected_stage_key(doc.name[:-len(".json")]):
            continue
        parsed = json.loads(doc.read_text(encoding="utf-8"))
        assert isinstance(parsed, dict), \
            f"cache document {doc.name} keyed as valid but " \
            "not a JSON object"


def _kill_analyze_at(case_dir, log_path, milestone,
                     settle_s=0.0, timeout=240):
    """Start nar-analyze on the demo fixture, SIGKILL the
    whole process group the moment ``milestone(case_dir)``
    holds, and return the combined output. Asserts the run
    really died by the kill (exit -SIGKILL) with no
    traceback."""
    with open(log_path, "wb") as log:
        proc = subprocess.Popen(
            [sys.executable, str(SCRIPTS / "nar-analyze.py"),
             DEMO, "--out", str(case_dir), "--no-html"],
            stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True)
        try:
            t0 = time.time()
            while not milestone(case_dir):
                if proc.poll() is not None:
                    raise AssertionError(
                        "nar-analyze exited (rc="
                        f"{proc.returncode}) before the kill "
                        "milestone was reached")
                if time.time() - t0 > timeout:
                    raise AssertionError(
                        "kill milestone not reached within "
                        f"{timeout}s")
                time.sleep(0.05)
            if settle_s:
                time.sleep(settle_s)
            os.killpg(proc.pid, signal.SIGKILL)
        finally:
            rc = proc.wait()
    assert rc == -signal.SIGKILL, \
        f"expected death by SIGKILL, got exit {rc}"
    output = Path(log_path).read_text(
        encoding="utf-8", errors="replace")
    assert "Traceback" not in output
    return output


def _resume_and_verify(case_dir):
    proc = _run("nar-analyze.py",
                [DEMO, "--out", str(case_dir), "--no-html"],
                timeout=600)
    assert proc.returncode == 0, proc.stderr[-1000:]
    assert "Traceback" not in proc.stderr
    assert "Traceback" not in proc.stdout
    verify = _run("nar-analyze.py",
                  ["--verify", str(case_dir), "--json"],
                  timeout=300)
    assert verify.returncode == 0, verify.stdout[-1000:]
    assert json.loads(verify.stdout)["ok"] is True
    json.loads((Path(case_dir) / "case.json").read_text(
        encoding="utf-8"))
    json.loads((Path(case_dir) / "report.json").read_text(
        encoding="utf-8"))


@pytest.mark.skipif(not os.path.isfile(DEMO),
                    reason="demo fixture absent")
def test_sigkill_early_stage_then_resume_verifies(tmp_path):
    """Kill point: the first stage-cache write is under
    way (the early 2.0 stages)."""
    case = tmp_path / "case"
    _kill_analyze_at(
        case, tmp_path / "kill.log",
        milestone=lambda c: os.path.isdir(
            os.path.join(c, "cache")))
    _assert_no_corrupt_hit(case)
    _resume_and_verify(case)


@pytest.mark.skipif(not os.path.isfile(DEMO),
                    reason="demo fixture absent")
def test_sigkill_mid_run_then_resume_verifies(tmp_path):
    """Kill point: the DEX stage has completed and been
    cached; the kill lands in the decompile window that
    follows it (mid-run)."""
    case = tmp_path / "case"
    _kill_analyze_at(
        case, tmp_path / "kill.log",
        milestone=lambda c: os.path.isfile(
            os.path.join(c, "cache", "dex.json.key")),
        settle_s=0.5)
    _assert_no_corrupt_hit(case)
    _resume_and_verify(case)


@pytest.mark.skipif(not os.path.isfile(DEMO),
                    reason="demo fixture absent")
def test_sigkill_late_stage_then_resume_verifies(tmp_path):
    """Kill point: the security stage (a late stage) has
    been cached; the kill lands in the remaining assets /
    app / builder / final-write phase."""
    case = tmp_path / "case"
    _kill_analyze_at(
        case, tmp_path / "kill.log",
        milestone=lambda c: os.path.isfile(
            os.path.join(c, "cache", "security.json.key")))
    _assert_no_corrupt_hit(case)
    _resume_and_verify(case)
