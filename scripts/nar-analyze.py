#!/usr/bin/env python3
"""nar-analyze.py: the one-command full static workup.

Given an APK, AAB, XAPK/APKM container, or OBB, runs the whole NAR
static workflow and writes ONE evidence report (Markdown + JSON):

- a doctor-lite environment note (core toolchain verdict),
- triage: identity, engines, frameworks, protections, versions,
- the nar-perms audit summary,
- the nar-strings summary (group counts and top findings),
- engine deep dives routed by what the package actually contains:
  Unity IL2CPP (nar-il2cpp), Unreal .pak listing (nar-pak),
  Godot pack (nar-godot), Flutter fingerprint (nar-flutter),
  React Native bundle (nar-rn),
- a closing Limitations and unknowns section.

Every step REUSES the bundled scripts through their --json output;
no analysis logic is duplicated here. Optional tools that are
missing degrade the matching section to an explicit note, never to
a fabricated result. Everything reported is a static observation:
this tool never runs the app and never claims runtime behavior.

Usage:
    python3 nar-analyze.py target.apk [--out DIR] [--work DIR]

The report lands in --out (default ./nar-analyze-<target name>) as
report.md and report.json. Stdlib only.

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import hashlib
import json
import mmap
import os
import subprocess
import sys
import tempfile
import time
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL_TIMEOUT = 1800
sys.path.insert(0, HERE)
try:
    from narlib import __version__ as NAR_VERSION
    from narlib import companions as _companions
    from narlib import correlations as _correlations
    from narlib import evidence as _evidence
    from narlib import graph as _graph
    from narlib import investigation as _investigation
    from narlib import safearchive as _safearchive
except Exception:  # narlib missing: keep the tool usable
    NAR_VERSION = "2.6.1"
    _companions = None
    _correlations = None
    _evidence = None
    _graph = None
    _investigation = None
    _safearchive = None

# Optional layers (2.6.0 Phases 7/8): graph + investigation
# companions, on by default, disabled by --no-graph /
# --no-investigation or the NAR_NO_GRAPH /
# NAR_NO_INVESTIGATION environment variables.
LAYER_OPTS = {"graph": True, "investigation": True}


def set_layers(graph=True, investigation=True):
    LAYER_OPTS["graph"] = bool(graph)
    LAYER_OPTS["investigation"] = bool(investigation)

# One entry per bundled-tool run, in execution order. main()
# turns this into execution-log.json (2.0 orchestrator record).
EXEC_LOG = []

# Orchestration budgets (Evolution Phase 8): a per-stage
# timeout cap and an optional total budget for the whole
# run, set from the CLI / case config by main(). A run that
# hits a budget stops the affected stage with status
# "budget-exceeded" in the execution log — recorded,
# never a hang and never a silent truncation.
BUDGET = {"stage_timeout_s": None, "total_budget_s": None,
          "t0": None}


def set_budgets(stage_timeout_s=None, total_budget_s=None):
    BUDGET["stage_timeout_s"] = stage_timeout_s
    BUDGET["total_budget_s"] = total_budget_s
    BUDGET["t0"] = time.time()


def _effective_timeout(requested):
    """(effective timeout, budget_bound) for one tool run."""
    eff = requested
    bound = False
    if BUDGET["stage_timeout_s"]:
        if BUDGET["stage_timeout_s"] < eff:
            bound = True
        eff = min(eff, BUDGET["stage_timeout_s"])
    if BUDGET["total_budget_s"] and BUDGET["t0"]:
        remaining = BUDGET["total_budget_s"] - (
            time.time() - BUDGET["t0"])
        if remaining < eff:
            bound = True
        eff = min(eff, max(remaining, 0.01))
    return eff, bound


def _budget_snapshot():
    return {"stage_timeout_s": BUDGET["stage_timeout_s"],
            "total_budget_s": BUDGET["total_budget_s"]}


def run_json_tool(script, args, timeout=TOOL_TIMEOUT):
    """Run a bundled script with --json; return (data, error)."""
    path = os.path.join(HERE, script)
    if not os.path.isfile(path):
        return None, f"{script} is missing from the skill"
    cmd = [sys.executable, path] + args + ["--json"]
    eff_timeout, budget_bound = _effective_timeout(timeout)
    started = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=eff_timeout)
    except subprocess.TimeoutExpired:
        EXEC_LOG.append({"stage": script, "module": script,
                         "tool": script, "tool_version": None,
                         "status": ("budget-exceeded" if budget_bound
                                    else "failed"),
                         "duration_s": round(time.time() - started, 3),
                         "budget": _budget_snapshot()})
        return None, f"{script} did not finish within {eff_timeout}s"
    except OSError as e:
        EXEC_LOG.append({"stage": script, "module": script,
                         "tool": script, "tool_version": None,
                         "status": "failed",
                         "duration_s": round(time.time() - started, 3)})
        return None, f"{script} could not start: {e}"
    try:
        data = json.loads(proc.stdout)
        EXEC_LOG.append({"stage": script, "module": script,
                         "tool": script, "tool_version": None,
                         "status": "ok",
                         "duration_s": round(time.time() - started, 3)})
        return data, None
    except ValueError:
        EXEC_LOG.append({"stage": script, "module": script,
                         "tool": script, "tool_version": None,
                         "status": "failed",
                         "duration_s": round(time.time() - started, 3)})
        tail = (proc.stderr or proc.stdout or "").strip()[-300:]
        return None, f"{script} produced no JSON (exit {proc.returncode})" \
                     + (f": {tail}" if tail else "")


def run_doctor():
    path = os.path.join(HERE, "nar-doctor.sh")
    if not os.path.isfile(path):
        return None, "nar-doctor.sh is missing from the skill"
    try:
        proc = subprocess.run(["bash", path, "--json"],
                              capture_output=True, text=True, timeout=300)
        data = json.loads(proc.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired) as e:
        return None, f"doctor did not run: {e}"
    checks = data.get("checks", [])
    return {
        "core_ok": data.get("core_ok"),
        "core_problems": [c["name"] for c in checks
                          if c.get("status") in ("missing", "warning")],
        "optional_missing": [c["name"] for c in checks
                             if c.get("status") == "optional-missing"],
        "checks": checks,
    }, None


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pick_base_apk(triage, names):
    """Choose the base APK inside a container: the one named after
    the package when known, else a canonical base name
    (base-master.apk / base.apk, the bundletool .apks layout),
    else the largest."""
    contained = triage.get("contained_apks") or []
    if not contained:
        return None
    package = (triage.get("container_manifest") or {}).get("package")
    for item in contained:
        if package and item["name"] == f"{package}.apk":
            return item["name"]
    contained = [c for c in contained if c["name"] in names]
    if not contained:
        return None
    for item in contained:
        if os.path.basename(item["name"]) in ("base-master.apk",
                                              "base.apk"):
            return item["name"]
    return max(contained, key=lambda c: c.get("size_bytes", 0))["name"]


# Container-extraction discipline (2.6.1 deep-audit
# remediation): every entry nar-analyze materializes from
# a target container goes through _contained_join (no
# absolute or '..' escape from the work directory — the
# entry name is attacker-controlled) and the extraction
# budget below. The ceilings are generous — far above any
# real base APK / OBB / pak / utoc — and only refuse
# absurd inflation; they are enforced on the declared
# size and again on the streamed byte count, because a
# crafted central directory can understate the size.
MAX_EXTRACT_ENTRY_BYTES = 4 * 1024 * 1024 * 1024
MAX_EXTRACT_TOTAL_BYTES = 8 * 1024 * 1024 * 1024
_EXTRACT_BUDGET = {"used": 0}


def _contained_join(root, *parts):
    """Join parts under root, refusing any result that
    escapes root (absolute parts, '..' traversal)."""
    dest = os.path.normpath(os.path.join(root, *parts))
    root_abs = os.path.abspath(root)
    if dest != root_abs and \
            not dest.startswith(root_abs + os.sep):
        raise ValueError(
            "archive entry path escapes the work "
            f"directory: {os.path.join(*parts)!r}")
    return dest


def extract_entry(zf, name, root, *rel_parts):
    """Extract one archive entry under root, contained
    and capped. Raises ValueError when the destination
    would escape root or the entry exceeds the extraction
    budget; a partially written file is removed first."""
    dest = _contained_join(root, *rel_parts)
    info = zf.getinfo(name)
    if info.file_size > MAX_EXTRACT_ENTRY_BYTES:
        raise ValueError(
            f"archive entry {name!r} declares "
            f"{info.file_size} bytes, over the "
            f"{MAX_EXTRACT_ENTRY_BYTES}-byte extraction cap")
    if _EXTRACT_BUDGET["used"] + info.file_size \
            > MAX_EXTRACT_TOTAL_BYTES:
        raise ValueError(
            f"archive entry {name!r} would exceed the "
            f"{MAX_EXTRACT_TOTAL_BYTES}-byte total "
            "extraction budget for this run")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    written = 0
    try:
        with zf.open(name) as src, open(dest, "wb") as dst:
            while True:
                chunk = src.read(1 << 20)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_EXTRACT_ENTRY_BYTES or \
                        _EXTRACT_BUDGET["used"] + written \
                        > MAX_EXTRACT_TOTAL_BYTES:
                    raise ValueError(
                        f"archive entry {name!r} exceeded "
                        "the extraction budget while "
                        "streaming (declared size "
                        "understated)")
                dst.write(chunk)
    except ValueError:
        try:
            os.unlink(dest)
        except OSError:
            pass
        raise
    _EXTRACT_BUDGET["used"] += written
    return dest


def zip_entry_flags(names):
    return {
        "il2cpp": any(n.endswith("/libil2cpp.so") or n == "libil2cpp.so"
                      for n in names),
        "flutter": any(n.endswith("/libflutter.so")
                       or n.endswith("/libapp.so") for n in names),
        # React Native routing: the contract asset name, any
        # *.jsbundle, or a top-level assets/*.bundle. Deep assets/**.bundle
        # files are Unity Addressables territory; nar-rn content-
        # validates whatever it is handed either way.
        "rn_bundle": any(n.endswith(".jsbundle")
                         or n.rsplit("/", 1)[-1]
                         in ("index.android.bundle",)
                         or (n.startswith("assets/")
                             and n.count("/") == 1
                             and n.endswith(".bundle"))
                         for n in names),
        "godot": any(n.lower().endswith(".pck")
                     or "libgodot" in n
                     or n.startswith("assets/.godot/") for n in names),
        "paks": [n for n in names if n.lower().endswith(".pak")],
        "utocs": [n for n in names if n.lower().endswith(".utoc")],
        "uassets": [n for n in names
                    if n.lower().endswith((".uasset", ".umap"))],
    }


def summarize_strings(data):
    groups = {}
    for name, group in (data.get("groups") or {}).items():
        if isinstance(group, dict):
            hits = group.get("hits") or []
            count = group.get("count", len(hits))
        elif isinstance(group, list):
            hits = group
            count = len(hits)
        else:
            hits, count = [], 0
        top = []
        for hit in hits[:5]:
            if isinstance(hit, str):
                text = hit
            elif isinstance(hit, dict):
                value = hit.get("value") or hit.get("string") or ""
                sources = hit.get("sources") or []
                text = str(value)
                if sources:
                    text += " [" + ", ".join(
                        str(s) for s in sources[:2]) + "]"
                if not text.strip():
                    text = json.dumps(hit, sort_keys=True)
            else:
                text = str(hit)
            # One clean line per hit: collapse whitespace and
            # neutralize Markdown code-span backticks so a
            # structured hit can never leak as a raw JSON blob.
            text = " ".join(text.split()).replace("`", "'")
            top.append(text[:200])
        groups[name] = {"count": count, "top": top}
    return {"total_raw_strings": data.get("total_raw_strings"),
            "unique_strings": data.get("unique_strings"),
            "sources_scanned": data.get("sources_scanned"),
            "groups": groups}


def summarize_perms(data):
    by_group = {}
    for group, items in (data.get("permissions_by_group") or {}).items():
        by_group[group] = (len(items) if isinstance(items, list)
                           else items)
    app = data.get("application") or {}
    return {
        "package": data.get("package"),
        "permission_count": data.get("permission_count"),
        "permissions_by_group": by_group,
        "dangerous_permissions": [
            p.get("name") for p in (data.get("permissions") or [])
            if isinstance(p, dict) and p.get("group") == "dangerous"
            and p.get("name")],
        "component_counts": data.get("component_counts"),
        "exported_count": data.get("exported_count"),
        "debuggable": app.get("debuggable"),
        "allow_backup": app.get("allow_backup"),
        "target_sdk": data.get("target_sdk"),
        "is_split": bool(data.get("split_name")),
    }


def _stage_cache_path(out_dir, stage):
    return os.path.join(out_dir, "cache", f"{stage}.json")


def run_cached_stage(stage, script, args, cache_key, out_dir):
    """Run one 2.0 stage with case-workspace caching.

    The cache key binds the input hash + stage + NAR version;
    a hit returns the stored document with status "cached"
    instead of re-running the tool (resume semantics)."""
    cache_path = _stage_cache_path(out_dir, stage)
    key_path = cache_path + ".key"
    if BUDGET["total_budget_s"] and BUDGET["t0"] and (
            time.time() - BUDGET["t0"] > BUDGET["total_budget_s"]):
        EXEC_LOG.append({
            "stage": stage, "module": script, "tool": script,
            "tool_version": NAR_VERSION,
            "status": "budget-exceeded", "duration_s": 0.0,
            "budget": _budget_snapshot()})
        return None, (f"total budget of "
                      f"{BUDGET['total_budget_s']}s exhausted "
                      f"before stage {stage}"), False
    if os.path.isfile(cache_path) and os.path.isfile(key_path):
        with open(key_path, encoding="utf-8") as fh:
            if fh.read().strip() == cache_key:
                with open(cache_path, encoding="utf-8") as fh:
                    EXEC_LOG.append({
                        "stage": stage, "module": script,
                        "tool": script, "tool_version": NAR_VERSION,
                        "status": "cached", "duration_s": 0.0})
                    return json.load(fh), None, True
    data, err = run_json_tool(script, args)
    if data is not None and out_dir:
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        with open(cache_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with open(key_path, "w", encoding="utf-8") as fh:
            fh.write(cache_key)
    return data, err, False


# ------------------------------------------------------------------
# Streaming DEX stage (2.6.1 W4 — R-006 remediation).
#
# The DEX stage document is the pipeline's one giant stage
# payload (hundreds of MB on large targets): the classic
# path captured it as subprocess text, parsed it into a
# full in-memory dict (~1.9 GB peak on the 273 MB fixture)
# and retained the dict for the whole downstream. The
# builders downstream, however, read only a slim
# projection of it (class names, native-method refs,
# entry points, string references — see narlib.correlations
# and narlib.graph), and the cache/companion files are
# serializations of the document, not consumers of the
# dict. The streaming path therefore:
#   1. spools the tool's stdout to a file (never a string),
#   2. promotes the spool to the stage cache verbatim
#      (minus print's trailing newline — byte-identical to
#      the classic json.dump cache),
#   3. extracts the projection + totals by streaming the
#      cached document element by element (each dex_files
#      element is parsed, projected and discarded),
#   4. writes the indent=1 companion with a token-level
#      re-serializer that copies scalar/string tokens
#      verbatim and regenerates only whitespace — byte-
#      identical to json.dump(doc, indent=1).
# Any failure in the streaming machinery falls back to the
# classic stage path (the caller performs the fallback);
# behavior on malformed stage output mirrors run_json_tool
# (a "produced no JSON" degradation, never a crash).

def _json_skip_ws(mm, i):
    n = len(mm)
    while i < n and mm[i] in b" \t\r\n":
        i += 1
    return i


def _json_value_end(mm, i):
    """End offset (exclusive) of the JSON value starting at
    or after offset i in the mapped bytes. Pure structural
    scan — strings are skipped escape-aware and no value is
    materialized. Raises ValueError on malformed input."""
    i = _json_skip_ws(mm, i)
    n = len(mm)
    if i >= n:
        raise ValueError("unexpected end of JSON input")
    c = mm[i]
    if c == 0x22:  # string
        i += 1
        while i < n:
            b = mm[i]
            if b == 0x5C:
                i += 2
                continue
            if b == 0x22:
                return i + 1
            i += 1
        raise ValueError("unterminated string in JSON input")
    if c in (0x7B, 0x5B):  # { or [
        depth = 0
        while i < n:
            b = mm[i]
            if b == 0x22:
                i = _json_value_end(mm, i)
                continue
            if b in (0x7B, 0x5B):
                depth += 1
            elif b in (0x7D, 0x5D):
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        raise ValueError("unterminated container in JSON")
    while i < n and mm[i] not in b",}] \t\r\n":
        i += 1
    return i


def _json_object_items(mm):
    """Yield (key, value_start, value_end) for each member
    of the top-level object of the mapped JSON document."""
    i = _json_skip_ws(mm, 0)
    if i >= len(mm) or mm[i] != 0x7B:
        raise ValueError("top-level JSON value is not an object")
    i = _json_skip_ws(mm, i + 1)
    if i < len(mm) and mm[i] == 0x7D:
        return
    while True:
        i = _json_skip_ws(mm, i)
        kend = _json_value_end(mm, i)
        key = json.loads(mm[i:kend])
        i = _json_skip_ws(mm, kend)
        if i >= len(mm) or mm[i] != 0x3A:
            raise ValueError("expected ':' in JSON object")
        vstart = _json_skip_ws(mm, i + 1)
        vend = _json_value_end(mm, vstart)
        yield key, vstart, vend
        i = _json_skip_ws(mm, vend)
        if i < len(mm) and mm[i] == 0x2C:
            i += 1
            continue
        if i < len(mm) and mm[i] == 0x7D:
            return
        raise ValueError("expected ',' or '}' in JSON object")


def _json_array_items(mm, start):
    """Yield (start, end) spans of the elements of the
    array whose '[' is at offset start."""
    i = _json_skip_ws(mm, start + 1)
    if i < len(mm) and mm[i] == 0x5D:
        return
    while True:
        vstart = _json_skip_ws(mm, i)
        vend = _json_value_end(mm, vstart)
        yield vstart, vend
        i = _json_skip_ws(mm, vend)
        if i < len(mm) and mm[i] == 0x2C:
            i += 1
            continue
        if i < len(mm) and mm[i] == 0x5D:
            return
        raise ValueError("expected ',' or ']' in JSON array")


def _dex_file_projection(f):
    """The slim per-file projection the report summary and
    the correlation/graph builders consume — exactly the
    fields they read, nothing else (the full document
    lives on in the cache + companion files)."""
    def _cname(c):
        return c.get("class") if isinstance(c, dict) else c
    out = {
        "name": f.get("name"),
        "class_count": f.get("class_count"),
        "kotlin": f.get("kotlin"),
        "classes": [{"class": _cname(c)}
                    for c in f.get("classes") or []],
        "native_methods": [
            {"class": nm["class"], "name": nm["name"]}
            for nm in f.get("native_methods") or []],
        "entry_points": [
            {"class": ep["class"],
             "via_superclass": ep.get("via_superclass")}
            for ep in f.get("entry_points") or []],
        "string_references": [
            {"string": r.get("string"),
             "sample_classes": r.get("sample_classes")}
            for r in f.get("string_references") or []],
    }
    if "error" in f:
        out["error"] = f["error"]
    return out


def _dex_projection_from_file(path):
    """Stream a DEX stage document from disk and return
    {totals, dex_files: [projections]}. Each dex_files
    element is parsed, projected and discarded before the
    next is read, so the full document is never resident."""
    totals = None
    files = []
    with open(path, "rb") as fh:
        mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            for key, vs, ve in _json_object_items(mm):
                if key == "dex_files":
                    for es, ee in _json_array_items(mm, vs):
                        files.append(_dex_file_projection(
                            json.loads(mm[es:ee])))
                elif key == "totals":
                    totals = json.loads(mm[vs:ve])
        finally:
            mm.close()
    return {"totals": totals, "dex_files": files}


def _json_emit_value(mm, i, out, depth):
    """Write the JSON value starting at/after offset i to
    the binary file `out`, formatted exactly as
    json.dump(value, indent=1) formats it at this depth:
    string/scalar tokens are copied verbatim from the
    source; only inter-token whitespace is generated.
    Returns the offset just past the value."""
    i = _json_skip_ws(mm, i)
    c = mm[i]
    if c not in (0x7B, 0x5B):
        end = _json_value_end(mm, i)
        out.write(mm[i:end])
        return end
    is_obj = c == 0x7B
    close = 0x7D if is_obj else 0x5D
    j = _json_skip_ws(mm, i + 1)
    if j < len(mm) and mm[j] == close:
        out.write(b"{}" if is_obj else b"[]")
        return j + 1
    out.write(b"{" if is_obj else b"[")
    i += 1
    count = 0
    while True:
        i = _json_skip_ws(mm, i)
        if i < len(mm) and mm[i] == close:
            out.write(b"\n" + b" " * depth
                      + (b"}" if is_obj else b"]"))
            return i + 1
        if count:
            out.write(b",")
        out.write(b"\n" + b" " * (depth + 1))
        if is_obj:
            kend = _json_value_end(mm, i)
            out.write(mm[i:kend])
            i = _json_skip_ws(mm, kend) + 1  # past ':'
            out.write(b": ")
        i = _json_emit_value(mm, i, out, depth + 1)
        count += 1
        i = _json_skip_ws(mm, i)
        if i < len(mm) and mm[i] == 0x2C:
            i += 1


def _dex_companion_from_cache(cache_path, companion_path):
    """Write the indent=1 companion (dex.json) from the
    cached stage document via the token re-serializer."""
    with open(cache_path, "rb") as fh:
        mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            with open(companion_path, "wb") as out:
                _json_emit_value(mm, 0, out, 0)
        finally:
            mm.close()


def _dex_stage_streamed(report, companions, apk_path,
                        out_dir, dex_dir, cache_key_base,
                        summarize):
    """The DEX stage over the streaming path. Mirrors the
    generic stage() bookkeeping (cache, companion,
    registry, summary, limitation on degradation) while
    never materializing the stage document. Returns the
    slim projection document, or None on degradation.
    Raises on streaming-machinery failures — the caller
    falls back to the classic stage path."""
    stage_name, script = "dex", "nar-dex.py"
    key = hashlib.sha256(
        f"{cache_key_base}|{stage_name}".encode()).hexdigest()
    cache_path = _stage_cache_path(out_dir, stage_name)
    key_path = cache_path + ".key"
    if BUDGET["total_budget_s"] and BUDGET["t0"] and (
            time.time() - BUDGET["t0"]
            > BUDGET["total_budget_s"]):
        EXEC_LOG.append({
            "stage": stage_name, "module": script,
            "tool": script, "tool_version": NAR_VERSION,
            "status": "budget-exceeded", "duration_s": 0.0,
            "budget": _budget_snapshot()})
        report["limitations"].append(
            f"2.0 stage {stage_name} degraded: total budget "
            f"of {BUDGET['total_budget_s']}s exhausted "
            f"before stage {stage_name}")
        return None
    cached = False
    if os.path.isfile(cache_path) and os.path.isfile(key_path):
        with open(key_path, encoding="utf-8") as fh:
            if fh.read().strip() == key:
                cached = True
                EXEC_LOG.append({
                    "stage": stage_name, "module": script,
                    "tool": script, "tool_version": NAR_VERSION,
                    "status": "cached", "duration_s": 0.0})
    if not cached:
        path = os.path.join(HERE, script)
        cmd = [sys.executable, path, apk_path, "--out",
               dex_dir, "--json"]
        eff_timeout, budget_bound = _effective_timeout(
            TOOL_TIMEOUT)
        started = time.time()
        os.makedirs(os.path.dirname(cache_path),
                    exist_ok=True)
        spool_path = cache_path + ".spool"
        try:
            with open(spool_path, "wb") as spool:
                proc = subprocess.run(
                    cmd, stdout=spool,
                    stderr=subprocess.PIPE, text=True,
                    timeout=eff_timeout)
        except subprocess.TimeoutExpired:
            EXEC_LOG.append({
                "stage": script, "module": script,
                "tool": script, "tool_version": None,
                "status": ("budget-exceeded" if budget_bound
                           else "failed"),
                "duration_s": round(time.time() - started, 3),
                "budget": _budget_snapshot()})
            _quiet_unlink(spool_path)
            report["limitations"].append(
                f"2.0 stage {stage_name} degraded: {script} "
                f"did not finish within {eff_timeout}s")
            return None
        except OSError as e:
            EXEC_LOG.append({
                "stage": script, "module": script,
                "tool": script, "tool_version": None,
                "status": "failed",
                "duration_s": round(time.time() - started, 3)})
            _quiet_unlink(spool_path)
            report["limitations"].append(
                f"2.0 stage {stage_name} degraded: {script} "
                f"could not start: {e}")
            return None
        try:
            data = _dex_projection_from_file(spool_path)
        except Exception:
            EXEC_LOG.append({
                "stage": script, "module": script,
                "tool": script, "tool_version": None,
                "status": "failed",
                "duration_s": round(time.time() - started, 3)})
            tail = ""
            if proc.stderr:
                tail = proc.stderr.strip()[-300:]
            if not tail:
                try:
                    with open(spool_path, "rb") as fh:
                        fh.seek(0, 2)
                        size = fh.tell()
                        fh.seek(max(0, size - 4096))
                        tail = fh.read().decode(
                            "utf-8", "replace").strip()[-300:]
                except OSError:
                    tail = ""
            _quiet_unlink(spool_path)
            err = (f"{script} produced no JSON "
                   f"(exit {proc.returncode})"
                   + (f": {tail}" if tail else ""))
            report["limitations"].append(
                f"2.0 stage {stage_name} degraded: {err}")
            return None
        EXEC_LOG.append({
            "stage": script, "module": script,
            "tool": script, "tool_version": None,
            "status": "ok",
            "duration_s": round(time.time() - started, 3)})
        # Promote the spool to the stage cache: the tool's
        # stdout is json.dumps(report) + print's newline;
        # the classic cache is json.dump of the same
        # document (no trailing newline) — stream-copy all
        # but a single trailing newline.
        with open(spool_path, "rb") as src, \
                open(cache_path, "wb") as dst:
            _copy_minus_trailing_newline(src, dst)
        _quiet_unlink(spool_path)
        with open(key_path, "w", encoding="utf-8") as fh:
            fh.write(key)
    else:
        data = _dex_projection_from_file(cache_path)
    _dex_companion_from_cache(
        cache_path, os.path.join(out_dir, "dex.json"))
    companions[stage_name] = {"file": "dex.json",
                              "cached": cached}
    summarize(data)
    return data


def _quiet_unlink(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def _copy_minus_trailing_newline(src, dst):
    """Stream-copy src to dst, dropping exactly one
    trailing newline if the source ends with one."""
    hold = b""
    while True:
        chunk = src.read(1 << 22)
        if not chunk:
            break
        data = hold + chunk
        if len(data) > 1:
            dst.write(data[:-1])
            hold = data[-1:]
        else:
            hold = data
    if hold and hold != b"\n":
        dst.write(hold)


def _unreal_graph_input(report):
    """Assemble the graph builder's Unreal input (2.6.1)
    from the report's engine deep-dive sections: one
    {"field_path", "record"} item per inspected Unreal
    package, in section order. Packages without a
    relationships record contribute nothing."""
    engines = report.get("engines") or {}
    items = []
    for section in ("unreal_packages",
                    "unreal_iostore_packages",
                    "unreal_pak_packages"):
        for i, pkg in enumerate(engines.get(section) or []):
            if isinstance(pkg, dict) \
                    and isinstance(pkg.get("relationships"),
                                   dict):
                items.append({
                    "field_path": f"engines.{section}[{i}]",
                    "record": pkg})
    return items


def run_2_0_stages(report, apk_path, out_dir, work_dir,
                   perms_data=None):
    """The 2.0 module stages: fingerprint, engine fusion, DEX,
    native, network, security, assets. Each writes its
    standardized companion document into the case directory
    and a summary into the report. Failures degrade to a
    limitation line, never to a fabricated result."""
    companions = {}
    report["companions"] = companions
    if not out_dir:
        report["limitations"].append(
            "2.0 module stages skipped: no case output directory")
        return
    os.makedirs(out_dir, exist_ok=True)
    cache_key_base = sha256_of(apk_path) + "|" + NAR_VERSION

    def stage(stage_name, script, args, companion_file, summarize):
        key = hashlib.sha256(
            f"{cache_key_base}|{stage_name}".encode()).hexdigest()
        data, err, cached = run_cached_stage(
            stage_name, script, args, key, out_dir)
        if data is None:
            report["limitations"].append(
                f"2.0 stage {stage_name} degraded: {err}")
            return None
        with open(os.path.join(out_dir, companion_file),
                  "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1)
        companions[stage_name] = {"file": companion_file,
                                  "cached": cached}
        summarize(data)
        return data

    def sum_fingerprint(data):
        report["fingerprint_summary"] = {
            "properties": sorted((data.get("properties") or {}).keys())}

    def sum_engines(data):
        report["engine_verdicts"] = [
            {"engine": v["engine"], "detected": v["detected"],
             "confidence": v["confidence"], "score": v["score"],
             "version": v.get("version")}
            for v in data.get("verdicts", [])]
        report["engine_ambiguities"] = data.get("ambiguities", [])

    def sum_dex(data):
        report["dex_summary"] = {
            "totals": data.get("totals"),
            "dex_files": [{"name": d.get("name"),
                           "class_count": d.get("class_count"),
                           "kotlin": d.get("kotlin")}
                          for d in data.get("dex_files", [])
                          if "error" not in d]}

    def sum_native(data):
        report["native_summary"] = {
            "libraries": len(data.get("libraries", [])),
            "jni_libraries": len(data.get("jni_map", {})),
            "dependency_edges": sum(
                len(v) for v in
                (data.get("dependency_graph") or {}).values())}

    def sum_network(data):
        report["network_summary"] = {
            "endpoint_count": len(data.get("endpoints", [])),
            "hosts": len(data.get("hosts", [])),
            "api_hosts": data.get("api_hosts", []),
            "classification_counts": data.get(
                "classification_counts"),
            "services": [s["service"]
                         for s in data.get("services", [])],
            "network_security_config": data.get(
                "network_security_config")}

    def sum_security(data):
        report["security_summary"] = {
            "severity_counts": data.get("severity_counts"),
            "findings": len(data.get("findings", [])),
            "positive_observations": data.get(
                "positive_observations", [])}

    def sum_assets(data):
        report["assets_summary"] = {
            "total_assets": data.get("total_assets"),
            "total_bytes": data.get("total_bytes"),
            "by_category": data.get("by_category"),
            "duplicate_groups": len(data.get("duplicates", []))}

    fp_data = stage("fingerprint", "nar-fingerprint.py", [apk_path],
                    "fingerprint.json", sum_fingerprint)
    eng_data = stage("engines", "nar-engines.py", [apk_path],
                     "engines.json", sum_engines)
    dex_dir = os.path.join(out_dir, "dex")
    # The DEX stage runs over the streaming path (2.6.1
    # W4): its document is the pipeline's one giant payload
    # and the classic capture/parse/retain round-trip set
    # the whole run's memory peak. Any failure in the
    # streaming machinery removes its partial artifacts
    # and falls back to the classic stage path unchanged.
    try:
        dex_data = _dex_stage_streamed(
            report, companions, apk_path, out_dir, dex_dir,
            cache_key_base, sum_dex)
    except Exception:
        _cache_path = _stage_cache_path(out_dir, "dex")
        for _p in (_cache_path, _cache_path + ".key",
                   _cache_path + ".spool",
                   os.path.join(out_dir, "dex.json")):
            _quiet_unlink(_p)
        dex_data = stage("dex", "nar-dex.py",
                         [apk_path, "--out", dex_dir],
                         "dex.json", sum_dex)
    nat_data = stage("native", "nar-native.py", [apk_path],
                     "native.json", sum_native)
    net_data = stage("network", "nar-network.py",
                     [apk_path, "--work",
                      os.path.join(work_dir, "network")],
                     "endpoints.json", sum_network)
    sec_data = stage("security", "nar-security.py", [apk_path],
                     "security-findings.json", sum_security)
    assets_data = stage("assets", "nar-assets.py", [apk_path],
                        "assets.json", sum_assets)

    # permissions.json: the raw nar-perms document, written
    # verbatim as a case companion (2.6.1 W3 integration
    # fix). The graph and investigation builders cite it as
    # evidence (permissions[i].name, components.<kind>[i],
    # package), but no stage ever wrote it — those evidence
    # references pointed at a document that did not exist
    # in the case. It is the permissions stage's own
    # output, not a projection, so it is registered
    # without the "projected" marker the projections use.
    if perms_data is not None:
        with open(os.path.join(out_dir, "permissions.json"),
                  "w", encoding="utf-8") as fh:
            json.dump(perms_data, fh, indent=1)
        companions["permissions"] = {"file": "permissions.json",
                                      "cached": False}

    # Brief-named companion projections (Evolution Phase 2):
    # application.json / manifest.json / native-inventory.json
    # / frameworks.json, projected from the stage data above —
    # no stage re-runs. Each is schema-validated before it is
    # written; a projection that fails validation degrades to
    # a limitation line, never to a written bad document.
    if _companions is not None and _evidence is not None:
        schema_dir = os.path.join(
            os.path.dirname(HERE), "schemas")
        projections = [
            ("application", "application.json",
             "application.schema.json",
             _companions.project_application(fp_data, NAR_VERSION)),
            ("manifest", "manifest.json", "manifest.schema.json",
             _companions.project_manifest(
                 report.get("permissions"), report.get("identity"),
                 NAR_VERSION)),
            ("native-inventory", "native-inventory.json",
             "native-inventory.schema.json",
             _companions.project_native_inventory(
                 nat_data, NAR_VERSION)),
            ("frameworks", "frameworks.json",
             "frameworks.schema.json",
             _companions.project_frameworks(
                 eng_data, fp_data, NAR_VERSION)),
            # Network companions (Evolution Phase 5), projected
            # from the network stage's endpoints document.
            ("network-analysis", "network-analysis.json",
             "network-analysis.schema.json",
             _companions.project_network_analysis(
                 net_data, NAR_VERSION)),
            ("api-architecture", "api-architecture.json",
             "api-architecture.schema.json",
             _companions.project_api_architecture(
                 net_data, NAR_VERSION)),
        ]
        for key, filename, schema_name, doc in projections:
            try:
                with open(os.path.join(schema_dir, schema_name),
                          encoding="utf-8") as fh:
                    schema = json.load(fh)
                errors = _evidence.validate(doc, schema)
            except (OSError, ValueError) as e:
                errors = [f"schema unavailable: {e}"]
            if errors:
                report["limitations"].append(
                    f"companion {filename} not emitted: "
                    f"projection failed validation ({errors[0]})")
                continue
            with open(os.path.join(out_dir, filename),
                      "w", encoding="utf-8") as fh:
                json.dump(doc, fh, indent=1)
            companions[key] = {"file": filename, "projected": True}

    # Cross-module correlations (Evolution Phase 8): explicit
    # join records across the stage documents, emitted as the
    # correlations.json companion (schema-validated). The JNI
    # entries are also embedded into native.json and counted
    # in the report, per the phase spec.
    corr = None
    if _correlations is not None and _evidence is not None:
        corr = _correlations.build_correlations(
            dex_data, nat_data, perms_data, net_data, NAR_VERSION)
        try:
            with open(os.path.join(
                    os.path.dirname(HERE), "schemas",
                    "correlations.schema.json"),
                    encoding="utf-8") as fh:
                corr_schema = json.load(fh)
            corr_errors = _evidence.validate(corr, corr_schema)
        except (OSError, ValueError) as e:
            corr_errors = [f"schema unavailable: {e}"]
        if corr_errors:
            report["limitations"].append(
                "companion correlations.json not emitted: "
                f"failed validation ({corr_errors[0]})")
        else:
            with open(os.path.join(out_dir, "correlations.json"),
                      "w", encoding="utf-8") as fh:
                json.dump(corr, fh, indent=1)
            companions["correlations"] = {
                "file": "correlations.json", "projected": True}
            report["correlations_summary"] = corr["counts"]
            native_path = os.path.join(out_dir, "native.json")
            if os.path.isfile(native_path):
                try:
                    with open(native_path, encoding="utf-8") as fh:
                        native_doc = json.load(fh)
                    native_doc["jni_correlations"] = \
                        corr["jni_bindings"]
                    with open(native_path, "w",
                              encoding="utf-8") as fh:
                        json.dump(native_doc, fh, indent=1)
                except (OSError, ValueError) as e:
                    report["limitations"].append(
                        "native.json JNI correlation enrichment "
                        f"failed: {e}")
            if isinstance(report.get("native_summary"), dict):
                report["native_summary"]["jni_correlations"] = {
                    "matched": corr["counts"]["jni_matched"],
                    "declaration_only":
                        corr["counts"]["jni_declaration_only"],
                    "export_only":
                        corr["counts"]["jni_export_only"]}

    # Optional layers (2.6.0 Phases 7/8, R-008/R-009/R-020):
    # graph.json + investigation.json companions, built from
    # the same stage documents (rebuilt from the stage cache
    # on every run). Each builder runs as an ordinary stage
    # under the existing budget machinery: a failure is
    # recorded in the execution log + limitations and the
    # analysis continues — an optional layer never fails
    # the whole run.
    def emit_optional(stage_name, filename, schema_name, builder):
        started = time.time()
        try:
            doc = builder()
        except Exception as e:  # builder failure degrades
            EXEC_LOG.append({
                "stage": stage_name, "module": stage_name,
                "tool": "nar-analyze",
                "tool_version": NAR_VERSION, "status": "failed",
                "duration_s": round(time.time() - started, 3),
                "budget": _budget_snapshot()})
            report["limitations"].append(
                f"companion {filename} not emitted: "
                f"{stage_name} builder failed ({e})")
            return None
        try:
            with open(os.path.join(
                    os.path.dirname(HERE), "schemas", schema_name),
                    encoding="utf-8") as fh:
                schema = json.load(fh)
            errors = _evidence.validate(doc, schema)
        except (OSError, ValueError) as e:
            errors = [f"schema unavailable: {e}"]
        if errors:
            EXEC_LOG.append({
                "stage": stage_name, "module": stage_name,
                "tool": "nar-analyze",
                "tool_version": NAR_VERSION, "status": "failed",
                "duration_s": round(time.time() - started, 3),
                "budget": _budget_snapshot()})
            report["limitations"].append(
                f"companion {filename} not emitted: "
                f"failed validation ({errors[0]})")
            return None
        with open(os.path.join(out_dir, filename),
                  "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1)
        companions[stage_name] = {"file": filename,
                                  "projected": True}
        EXEC_LOG.append({
            "stage": stage_name, "module": stage_name,
            "tool": "nar-analyze", "tool_version": NAR_VERSION,
            "status": "ok",
            "duration_s": round(time.time() - started, 3),
            "budget": _budget_snapshot()})
        return doc

    if _evidence is not None and _graph is not None \
            and LAYER_OPTS.get("graph", True) \
            and not (_investigation is not None
                     and _investigation.graph_disabled()):
        graph_doc = emit_optional(
            "graph", "graph.json", "graph.schema.json",
            lambda: _graph.build_graph(
                dex_data=dex_data, native_data=nat_data,
                perms_data=perms_data, network_data=net_data,
                fingerprint_data=fp_data, engines_data=eng_data,
                security_data=sec_data, assets_data=assets_data,
                correlations_data=corr,
                unreal_data=_unreal_graph_input(report),
                version=NAR_VERSION))
        if graph_doc is not None:
            report["graph_summary"] = graph_doc["counts"]
    if _evidence is not None and _investigation is not None \
            and LAYER_OPTS.get("investigation", True) \
            and not _investigation.investigation_disabled():
        inv_doc = emit_optional(
            "investigation", "investigation.json",
            "investigation.schema.json",
            lambda: _investigation.build_investigation(
                dex_data=dex_data, native_data=nat_data,
                perms_data=perms_data, network_data=net_data,
                security_data=sec_data, correlations_data=corr,
                engines_data=eng_data, version=NAR_VERSION))
        if inv_doc is not None:
            report["investigation_summary"] = inv_doc["counts"]


def analyze(target, work_dir, out_dir=None):
    _EXTRACT_BUDGET["used"] = 0
    report = {"tool": "nar-analyze", "version": NAR_VERSION,
              "nar_version": NAR_VERSION,
              "target": os.path.abspath(target),
              "target_name": os.path.basename(target),
              "limitations": []}
    if not os.path.isfile(target):
        raise FileNotFoundError(f"not a file: {target}")
    report["target_sha256"] = sha256_of(target)
    report["target_size_bytes"] = os.path.getsize(target)
    os.makedirs(work_dir, exist_ok=True)

    doctor, err = run_doctor()
    report["environment"] = doctor or {"error": err}
    if err:
        report["limitations"].append(f"Environment check unavailable: {err}")
    elif doctor and not doctor["core_ok"]:
        report["limitations"].append(
            "Core toolchain is incomplete (doctor): "
            + ", ".join(doctor["core_problems"]))

    triage, err = run_json_tool("nar-triage.py", [target])
    if triage is None:
        report["fatal"] = f"triage failed: {err}"
        return report
    report["triage"] = triage
    # Triage records a hard error for a target that is not
    # a ZIP/APK container at all (nar-triage's own CLI exits
    # nonzero on it). Proceeding would dress a garbage file
    # up as a degraded workup — including a default "apk"
    # identity — so record the same fatal the missing-JSON
    # path records. OBBs are exempt: an OBB may legitimately
    # be a non-ZIP container, and the string stage below
    # still runs on it by design.
    if triage.get("error") and not triage.get("is_obb"):
        report["fatal"] = f"triage failed: {triage['error']}"
        return report
    badging = triage.get("badging") or {}
    manifest = triage.get("container_manifest") or {}
    report["identity"] = {
        "package": badging.get("package") or manifest.get("package")
                   or triage.get("obb_package"),
        "version_name": badging.get("version_name")
                        or manifest.get("version_name"),
        "version_code": badging.get("version_code")
                        or manifest.get("version_code")
                        or triage.get("obb_version_code"),
        "app_label": badging.get("app_label") or manifest.get("app_label"),
        "min_sdk": badging.get("min_sdk") or manifest.get("min_sdk"),
        "target_sdk": badging.get("target_sdk")
                      or manifest.get("target_sdk"),
        "form_factors": badging.get("form_factors") or [],
        "signature_schemes": triage.get("signature_schemes"),
        "kind": ("xapk/apkm/apks container" if triage.get("is_container")
                 else "aab" if triage.get("is_aab")
                 else "obb" if triage.get("is_obb") else "apk"),
    }
    report["protections"] = triage.get("protections") or []

    # Resolve the APK that perms/strings/engine steps should run on.
    apk_for_steps = target
    step_notes = []
    if triage.get("is_aab"):
        step_notes.append(
            "target is an AAB bundle: permission, string, and engine"
            " steps need an APK built from it (bundletool build-apks)"
            " and were skipped")
        apk_for_steps = None
    elif triage.get("is_container"):
        with zipfile.ZipFile(target) as zf:
            names = zf.namelist()
            base = pick_base_apk(triage, names)
            if base:
                try:
                    apk_for_steps = extract_entry(
                        zf, base, work_dir, "container", base)
                    step_notes.append(
                        f"container: steps ran on the contained"
                        f" base APK {base}")
                except ValueError as e:
                    apk_for_steps = None
                    step_notes.append(
                        f"container base APK entry refused: "
                        f"{e}; APK-level steps skipped")
            else:
                apk_for_steps = None
                step_notes.append("container holds no triageable base"
                                  " APK; APK-level steps skipped")
            report["contained_obbs"] = [
                n for n in names if n.lower().endswith(".obb")]
    elif triage.get("is_obb"):
        step_notes.append("target is an OBB: it carries no manifest,"
                          " so the permission audit was skipped")
    report["step_notes"] = step_notes

    # A container without a manifest (e.g. a bundletool .apks set)
    # leaves the identity empty even though the steps run on a
    # real base APK: take the identity from that base instead of
    # reporting an unnamed target.
    if (triage.get("is_container") and apk_for_steps
            and not report["identity"].get("package")):
        base_triage, base_err = run_json_tool(
            "nar-triage.py", [apk_for_steps])
        if base_triage:
            bb = base_triage.get("badging") or {}
            ident = report["identity"]
            for key in ("package", "version_name", "version_code",
                        "app_label", "min_sdk", "target_sdk"):
                if not ident.get(key) and bb.get(key):
                    ident[key] = bb[key]
            if not ident.get("form_factors") and bb.get("form_factors"):
                ident["form_factors"] = bb["form_factors"]
            if ident.get("package"):
                step_notes.append(
                    "container has no manifest identity; identity"
                    " taken from the contained base APK")
                report["step_notes"] = step_notes

    if apk_for_steps and not triage.get("is_obb"):
        perms, err = run_json_tool("nar-perms.py", [apk_for_steps])
        report["permissions"] = (summarize_perms(perms) if perms
                                 else {"error": err})
        if err:
            report["limitations"].append(f"Permission audit failed: {err}")
    elif triage.get("is_obb"):
        report["permissions"] = {"skipped": "OBB files have no manifest"}

    strings_target = apk_for_steps or (target if triage.get("is_obb")
                                       else None)
    if strings_target:
        strings, err = run_json_tool("nar-strings.py", [strings_target])
        report["strings"] = (summarize_strings(strings) if strings
                             else {"error": err})
        if err:
            report["limitations"].append(f"String scan failed: {err}")

    # Engine deep dives, routed by the analyzed APK's own contents.
    engines = {}
    scan_path = apk_for_steps
    if scan_path and zipfile.is_zipfile(scan_path):
        with zipfile.ZipFile(scan_path) as zf:
            flags = zip_entry_flags(zf.namelist())
            pak_sources = [(scan_path, n) for n in flags["paks"]]
        if triage.get("is_container"):
            for obb_name in report.get("contained_obbs", []):
                with zipfile.ZipFile(target) as zf:
                    try:
                        obb_path = extract_entry(
                            zf, obb_name, work_dir, "container",
                            os.path.basename(obb_name))
                    except ValueError as e:
                        report["limitations"].append(
                            f"contained OBB {obb_name} not "
                            f"extracted: {e}")
                        continue
                with zipfile.ZipFile(obb_path) as ozf:
                    for n in ozf.namelist():
                        if n.lower().endswith(".pak"):
                            pak_sources.append((obb_path, n))
        if flags["il2cpp"]:
            data, err = run_json_tool(
                "nar-il2cpp.py",
                [scan_path, "--out", os.path.join(work_dir, "il2cpp")])
            engines["unity_il2cpp"] = data or {"error": err}
        else:
            # Metadata without the native library: the IL2CPP pair
            # is split across APKs and the dive cannot run on this
            # file alone. Say so explicitly instead of silently
            # omitting the section.
            hints = triage.get("engine_hints") or []
            meta_hint = bool(
                (triage.get("engine_versions") or {}).get(
                    "unity_metadata_version")) or any(
                        "global-metadata.dat" in marker
                        for hint in hints
                        for marker in (hint.get("markers") or []))
            if meta_hint:
                step_notes.append(
                    "Unity IL2CPP metadata present but no"
                    " libil2cpp.so in this file; the IL2CPP deep"
                    " dive was skipped (the native pair likely"
                    " lives in a split APK — see triage"
                    " split_native_suspected)")
                report["step_notes"] = step_notes
        if flags["flutter"]:
            data, err = run_json_tool("nar-flutter.py", [scan_path])
            engines["flutter"] = data or {"error": err}
        if flags["rn_bundle"]:
            data, err = run_json_tool(
                "nar-rn.py",
                [scan_path, "--work", os.path.join(work_dir, "rn")])
            engines["react_native"] = data or {"error": err}
        if flags["godot"]:
            data, err = run_json_tool("nar-godot.py", [scan_path])
            engines["godot"] = data or {"error": err}
        pak_reports = []
        for src_zip, entry in pak_sources[:3]:
            with zipfile.ZipFile(src_zip) as zf:
                try:
                    pak_path = extract_entry(
                        zf, entry, work_dir, "pak",
                        os.path.basename(entry))
                except ValueError as e:
                    pak_reports.append(
                        {"error": str(e), "entry": entry})
                    continue
            data, err = run_json_tool("nar-pak.py", [pak_path])
            if data:
                data = dict(data)
                data.pop("entries", None)  # counts/stats stay; the
                # full listing is one nar-pak run away and would bloat
                # this report
                data["contained_in"] = os.path.basename(src_zip)
                data["entry"] = entry
            pak_reports.append(data or {"error": err, "entry": entry})
        if len(pak_sources) > 3:
            report["limitations"].append(
                f"{len(pak_sources)} .pak files found; only the first"
                " 3 were listed")
        if pak_reports:
            engines["unreal_pak"] = pak_reports
        utoc_reports = []
        utoc_sources = [(scan_path, n) for n in flags["utocs"]]
        for src_zip, entry in utoc_sources[:3]:
            with zipfile.ZipFile(src_zip) as zf:
                try:
                    utoc_path = extract_entry(
                        zf, entry, work_dir, "utoc",
                        os.path.basename(entry))
                except ValueError as e:
                    utoc_reports.append(
                        {"error": str(e), "entry": entry})
                    continue
            data, err = run_json_tool("nar-unreal.py", [utoc_path])
            containers = (data or {}).get("iostore_containers") or []
            if containers:
                summary = dict(containers[0])
                summary.pop("entries", None)  # per-chunk detail is
                # one nar-unreal run away; counts/totals stay here
                summary["contained_in"] = os.path.basename(src_zip)
                summary["entry"] = entry
                utoc_reports.append(summary)
            else:
                utoc_reports.append({"error": err or "no container"
                                     " parsed", "entry": entry})
        if len(utoc_sources) > 3:
            report["limitations"].append(
                f"{len(utoc_sources)} .utoc containers found; only"
                " the first 3 were parsed")
        if utoc_reports:
            engines["unreal_iostore"] = utoc_reports
        if flags["paks"] or flags["utocs"] or flags["uassets"]:
            # One nar-unreal run over the APK lifts the
            # UAsset-level package inspections (loose, IoStore
            # and --work-extracted pak packages) into the
            # companions; name strings are dropped here (the
            # counts stay complete) and export detail is
            # capped harder than in a direct nar-unreal run.
            data, err = run_json_tool(
                "nar-unreal.py",
                [scan_path, "--work",
                 os.path.join(work_dir, "unreal")])
            for key, out_key in (
                    ("packages", "unreal_packages"),
                    ("iostore_packages",
                     "unreal_iostore_packages"),
                    ("pak_packages", "unreal_pak_packages")):
                pkgs = (data or {}).get(key) or []
                trimmed = []
                for pkg in pkgs:
                    pkg = dict(pkg)
                    pkg.pop("names", None)
                    exps = pkg.get("exports") or []
                    if len(exps) > 25:
                        pkg["exports"] = exps[:25]
                        pkg["exports_capped"] = (
                            f"export detail capped at 25 of "
                            f"{len(exps)} in the analyze "
                            "companion; counts are complete")
                    trimmed.append(pkg)
                if trimmed:
                    engines[out_key] = trimmed
    report["engines"] = engines

    # 2.0 module stages (fingerprint / engine fusion / DEX /
    # native / network / security / assets) with case caching.
    if apk_for_steps and not triage.get("is_obb"):
        run_2_0_stages(report, apk_for_steps, out_dir, work_dir,
                       perms_data=perms)

    # Limitations and unknowns: the honest tail of every report.
    lim = report["limitations"]
    lim.append("Static analysis only: nothing was executed, so no"
               " runtime behavior, network traffic, or server-side"
               " verdict (for example Play Integrity's) is claimed.")
    lim.append("Decompilation (jadx) is not part of this workup; see"
               " references/dex-smali-and-decompile.md for that step.")
    key_hits = ((report.get("strings") or {}).get("groups") or {}
                ).get("key_patterns", {}).get("count")
    if key_hits:
        lim.append(f"Strings: {key_hits} strings match key/token"
                   " patterns. A pattern match means a string LOOKS"
                   " like a key; it is not proof of a real secret.")
    for name, section in engines.items():
        if isinstance(section, dict) and section.get("error"):
            lim.append(f"Engine step {name} degraded: {section['error']}")
        if name == "unity_il2cpp" and isinstance(section, dict):
            dumper = section.get("dumper") or {}
            if dumper.get("error"):
                lim.append(f"IL2CPP dump degraded: {dumper['error']}")
            cpp2il = section.get("cpp2il") or {}
            if cpp2il.get("error"):
                lim.append("IL2CPP dump degraded (Cpp2IL): "
                           f"{cpp2il['error']}")
    for pak in engines.get("unreal_pak", []):
        if pak.get("encrypted_entry_count"):
            lim.append(f"Pak {pak.get('entry')}: "
                       f"{pak['encrypted_entry_count']} entries are"
                       " flagged encrypted and were not opened.")
    report["limitations"] = lim
    return report


def _fmt(value):
    return "unknown" if value in (None, "") else str(value)


def _flag_text(value, perms):
    """Render android:debuggable the way nar-perms does: an absent
    attribute is not "unknown" — the platform default is false.
    A split stub carries no value of its own."""
    if value is not None:
        return str(value)
    if perms.get("is_split"):
        return "unknown (split stub; value lives in the base APK)"
    return "false (platform default; attribute absent)"


def _backup_text(value, perms):
    """Render android:allowBackup the way nar-perms does: absent
    defaults to true below target 31, and to cloud-backup-off at
    target 31+ (device-to-device transfer still allowed)."""
    if value is not None:
        return str(value)
    if perms.get("is_split"):
        return "unknown (split stub; value lives in the base APK)"
    target = perms.get("target_sdk")
    if target is not None and target >= 31:
        return ("false for cloud backup (platform default for "
                "target 31+; attribute absent)")
    return "true (platform default; attribute absent)"


def render_md(report):
    t = report.get("triage") or {}
    ident = report.get("identity") or {}
    lines = [f"# NAR analysis: {report['target_name']}", ""]
    lines.append(f"- File: `{report['target']}`")
    lines.append(f"- SHA-256: `{report.get('target_sha256')}`")
    lines.append(f"- Size: {report.get('target_size_bytes', 0):,} bytes")
    lines.append(f"- Kind: {ident.get('kind')}")
    lines.append("- Produced by: nar-analyze.py (NAR 1.1.1), reusing"
                 " nar-doctor, nar-triage, nar-perms, nar-strings and"
                 " the engine scripts. Static analysis only.")
    env = report.get("environment") or {}
    lines += ["", "## Environment", ""]
    if env.get("error"):
        lines.append(f"Doctor unavailable: {env['error']}")
    else:
        lines.append(f"Core toolchain READY: {env.get('core_ok')}")
        if env.get("core_problems"):
            lines.append(f"Core problems: {', '.join(env['core_problems'])}")
        if env.get("optional_missing"):
            lines.append("Optional tools missing (deep dives degrade): "
                         + ", ".join(env["optional_missing"]))
    lines += ["", "## Identity", ""]
    lines.append(f"- Package: `{_fmt(ident.get('package'))}`")
    lines.append(f"- Version: {_fmt(ident.get('version_name'))}"
                 f" (code {_fmt(ident.get('version_code'))})")
    lines.append(f"- Label: {_fmt(ident.get('app_label'))}")
    lines.append(f"- SDK: min {_fmt(ident.get('min_sdk'))},"
                 f" target {_fmt(ident.get('target_sdk'))}")
    if ident.get("form_factors"):
        lines.append("- Form factors: "
                     + ", ".join(ident["form_factors"]))
    sig = ident.get("signature_schemes") or {}
    if sig:
        lines.append(f"- Signing: verifies={sig.get('verifies')},"
                     f" v1={sig.get('v1')}, v2={sig.get('v2')},"
                     f" v3={sig.get('v3')}, v3.1={sig.get('v3_1')},"
                     f" signers={sig.get('signers')}")
    for note in report.get("step_notes", []):
        lines.append(f"- Note: {note}")
    lines += ["", "## Engines and frameworks", ""]
    hints = t.get("engine_hints") or []
    if hints:
        for h in hints:
            lines.append(f"- Engine hint: {h.get('engine')}"
                         f" ({h.get('marker_count')} markers)")
    else:
        lines.append("- No engine hints from triage markers.")
    if t.get("engine_versions"):
        lines.append(f"- Engine versions: "
                     f"{json.dumps(t['engine_versions'])}")
    markers = t.get("dex_markers") or []
    for m in markers[:12]:
        lines.append(f"- DEX marker: {m.get('marker')}"
                     f" ({m.get('total_hits')} hits)")
    libs = t.get("library_versions") or {}
    if libs:
        top = list(libs.items())[:10]
        lines.append(f"- Library versions recorded: {len(libs)}"
                     f" (first: {', '.join(f'{k} {v}' for k, v in top)})")
    lines += ["", "## Protections", ""]
    protections = report.get("protections") or []
    if not protections:
        lines.append("- No protection markers found by static scan.")
    current = None
    for p in protections:
        if p.get("category_label") != current:
            current = p.get("category_label")
            lines.append(f"### {current}")
        ev = "; ".join((p.get("evidence") or [])[:2])
        lines.append(f"- {p.get('name')}"
                     f"{' (attributed)' if p.get('attributed') else ''}"
                     f": {ev}")
    lines += ["", "## Permissions audit", ""]
    perms = report.get("permissions") or {}
    if perms.get("error"):
        lines.append(f"Unavailable: {perms['error']}")
    elif perms.get("skipped"):
        lines.append(f"Skipped: {perms['skipped']}")
    else:
        lines.append(f"- Declared permissions: {perms.get('permission_count')}")
        lines.append(f"- By group: {json.dumps(perms.get('permissions_by_group'))}")
        lines.append(f"- Components: {json.dumps(perms.get('component_counts'))};"
                     f" exported: {perms.get('exported_count')}")
        lines.append(f"- debuggable: {_flag_text(perms.get('debuggable'), perms)};"
                     f" allowBackup: {_backup_text(perms.get('allow_backup'), perms)}")
    lines += ["", "## Strings scan", ""]
    strings = report.get("strings") or {}
    if strings.get("error"):
        lines.append(f"Unavailable: {strings['error']}")
    elif not strings:
        lines.append("Not run for this target kind.")
    else:
        lines.append(f"- Raw strings: {strings.get('total_raw_strings')};"
                     f" unique: {strings.get('unique_strings')};"
                     f" sources: {', '.join(strings.get('sources_scanned') or [])}")
        for name, group in (strings.get("groups") or {}).items():
            lines.append(f"### {name}: {group['count']} hits")
            for top in group["top"]:
                lines.append(f"- `{top}`")
    lines += ["", "## Engine deep dives", ""]
    engines = report.get("engines") or {}
    if not engines:
        lines.append("No engine deep dive applied to this target.")
    for name, section in engines.items():
        lines.append(f"### {name}")
        if isinstance(section, list):
            for pak in section:
                if pak.get("error"):
                    lines.append(f"- {pak.get('entry')}: {pak['error']}")
                else:
                    lines.append(
                        f"- {pak.get('entry')} (in {pak.get('contained_in')}):"
                        f" pak v{pak.get('pak_version')},"
                        f" {pak.get('entry_count')} entries,"
                        f" encrypted entries:"
                        f" {pak.get('encrypted_entry_count')},"
                        f" {pak.get('total_uncompressed_bytes')} bytes"
                        " uncompressed")
        elif section.get("error"):
            lines.append(f"- Unavailable: {section['error']}")
        elif name == "unity_il2cpp":
            meta = section.get("metadata") or {}
            summary = section.get("summary") or {}
            lines.append(f"- Metadata version: {meta.get('version')}"
                         f" (magic ok: {meta.get('magic_ok')})")
            if summary:
                basis = summary.get("method_count_basis") \
                    or "RVA-marked methods"
                lines.append(f"- Dump: {summary.get('types')} types,"
                             f" {summary.get('methods')} methods"
                             f" ({basis}); top namespaces:"
                             f" {json.dumps(summary.get('top_namespaces'))}")
            dumper = section.get("dumper") or {}
            if dumper.get("error"):
                lines.append(f"- Dumper: {dumper['error']}")
            cpp2il = section.get("cpp2il") or {}
            if cpp2il.get("error"):
                lines.append(f"- Cpp2IL: {cpp2il['error']}")
        elif name == "flutter":
            lines.append(f"- Dart: {section.get('dart_version')};"
                         f" Flutter: {section.get('flutter_version')};"
                         f" ABIs: {', '.join(section.get('abis') or [])};"
                         f" {section.get('build_mode')}")
        elif name == "react_native":
            if section.get("is_react_native") is False:
                lines.append(f"- Not React Native:"
                             f" {section.get('note') or 'no JS bundle'}")
            else:
                lines.append(f"- Engine: {section.get('engine')};"
                             f" bundle: {section.get('bundle_entry')}"
                             f" ({section.get('bundle_size_bytes')} bytes)")
                hermes = section.get("hermes") or {}
                if hermes:
                    lines.append(f"- Hermes bytecode v"
                                 f"{hermes.get('bytecode_version')},"
                                 f" {hermes.get('function_count')} functions,"
                                 f" {hermes.get('string_count')} strings")
        elif name == "godot":
            pck = section.get("pck") or {}
            if pck:
                lines.append(f"- Pack: format {pck.get('format_version')},"
                             f" engine {pck.get('engine_version')},"
                             f" files: {pck.get('file_count')},"
                             f" encrypted: {pck.get('encrypted')}")
            if section.get("note"):
                lines.append(f"- {section['note']}")
        else:
            lines.append(f"- `{json.dumps(section)[:400]}`")
    lines += ["", "## Limitations and unknowns", ""]
    for item in report.get("limitations", []):
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


BUNDLE_MANIFEST = "case-bundle-manifest.json"


def _case_files(case_dir):
    out = []
    for root, _dirs, names in os.walk(case_dir):
        for name in names:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, case_dir)
            out.append((rel.replace(os.sep, "/"), full))
    return sorted(out)


def export_case(case_dir, bundle_path):
    """Export a case directory to a single portable bundle
    (zip) with a per-file SHA-256 manifest. Returns a
    summary dict. The manifest travels inside the bundle
    and lands in the imported case, where verify_case
    re-checks every file against it."""
    case_doc = {}
    case_json = os.path.join(case_dir, "case.json")
    if os.path.isfile(case_json):
        with open(case_json, encoding="utf-8") as fh:
            case_doc = json.load(fh)
    files = []
    with zipfile.ZipFile(bundle_path, "w",
                         zipfile.ZIP_DEFLATED) as zf:
        for rel, full in _case_files(case_dir):
            if rel == BUNDLE_MANIFEST:
                continue
            files.append({"path": rel,
                          "sha256": sha256_of(full),
                          "size_bytes": os.path.getsize(full)})
        manifest = {
            "tool": "nar-analyze", "version": NAR_VERSION,
            "kind": "nar-case-bundle",
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                     time.gmtime()),
            "case_id": case_doc.get("case_id"),
            "input_sha256": (case_doc.get("input") or {}).get(
                "sha256"),
            "files": files}
        zf.writestr(BUNDLE_MANIFEST, json.dumps(manifest, indent=1))
        for rel, full in _case_files(case_dir):
            if rel == BUNDLE_MANIFEST:
                continue
            zf.write(full, rel)
    return {"bundle": os.path.abspath(bundle_path),
            "files": len(files),
            "case_id": manifest["case_id"],
            "input_sha256": manifest["input_sha256"]}


def import_case(bundle_path, out_dir):
    """Import a case bundle into out_dir, then verify the
    imported case. Extraction goes through
    narlib.safearchive (Phase 10): the previous raw
    ZipFile.extractall path checked only absolute/'..'
    names and applied NO entry-count, size, ratio,
    symlink or non-regular-entry limits, so a crafted
    bundle could act as an archive bomb or plant symlink
    entries the guarded layer exists to refuse. Any
    rejected entry aborts the import with the reasons.
    Returns the verify summary plus import facts."""
    with zipfile.ZipFile(bundle_path) as zf:
        names = zf.namelist()
        if BUNDLE_MANIFEST not in names:
            raise ValueError("not a NAR case bundle: "
                             f"{BUNDLE_MANIFEST} missing")
    if _safearchive is None:
        raise ValueError("narlib.safearchive is unavailable; "
                         "refusing unguarded extraction")
    report = _safearchive.safe_extract(bundle_path, out_dir)
    if report["rejected"]:
        reasons = "; ".join(
            f"{r['entry']}: {r['reason']}"
            for r in report["rejected"][:10])
        raise ValueError(f"unsafe entries in bundle: {reasons}")
    result = verify_case(out_dir)
    result["imported_to"] = os.path.abspath(out_dir)
    result["files_imported"] = len(report["extracted"])
    return result


def verify_case(case_dir):
    """Verify a case directory's integrity: the recorded
    input hash (re-checked when the input file is still at
    its recorded path), the bundle manifest when present
    (every file's hash + size), and the stage-cache
    integrity keys (recomputed from the case's recorded
    input hash + its recorded NAR version + stage name).
    Returns {ok, checks, failures, notes} — a check that
    cannot run is a note, never a silent pass."""
    checks, failures, notes = [], [], []

    def check(name, ok, detail=""):
        checks.append({"check": name, "ok": bool(ok),
                       "detail": detail})
        if not ok:
            failures.append(f"{name}: {detail}")

    case_json = os.path.join(case_dir, "case.json")
    if not os.path.isfile(case_json):
        check("case.json present", False, "case.json missing")
        return {"ok": False, "checks": checks,
                "failures": failures, "notes": notes}
    check("case.json present", True)
    with open(case_json, encoding="utf-8") as fh:
        case_doc = json.load(fh)
    inp = case_doc.get("input") or {}
    input_sha = inp.get("sha256")
    check("input hash recorded", bool(input_sha))
    input_path = inp.get("path")
    if input_path and os.path.isfile(input_path):
        actual = sha256_of(input_path)
        check("input file hash matches the record",
              actual == input_sha,
              "recorded input file changed on disk"
              if actual != input_sha else "re-hashed OK")
    else:
        notes.append("input file not present at its recorded "
                     "path; its hash was not re-checked "
                     "(normal for an imported case)")
    manifest_path = os.path.join(case_dir, BUNDLE_MANIFEST)
    if os.path.isfile(manifest_path):
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
        check("bundle input hash matches case record",
              manifest.get("input_sha256") == input_sha)
        bad = []
        for entry in manifest.get("files", []):
            full = os.path.join(case_dir, entry["path"])
            if not os.path.isfile(full):
                bad.append(f"{entry['path']} missing")
            elif sha256_of(full) != entry["sha256"] or \
                    os.path.getsize(full) != entry["size_bytes"]:
                bad.append(f"{entry['path']} hash/size mismatch")
        check("bundle manifest: every file intact", not bad,
              "; ".join(bad[:5]) if bad else
              f"{len(manifest.get('files', []))} files verified")
    else:
        notes.append("no bundle manifest in this case "
                     "(not an imported bundle); manifest "
                     "checks not applicable")
    cache_dir = os.path.join(case_dir, "cache")
    if os.path.isdir(cache_dir) and input_sha:
        case_version = case_doc.get("nar_version") or NAR_VERSION
        bad = []
        checked = 0
        for name in sorted(os.listdir(cache_dir)):
            if not name.endswith(".json"):
                continue
            stage = name[:-len(".json")]
            key_path = os.path.join(cache_dir, name + ".key")
            if not os.path.isfile(key_path):
                bad.append(f"{stage}: cache key file missing")
                continue
            with open(key_path, encoding="utf-8") as fh:
                recorded = fh.read().strip()
            # Recompute exactly as run_2_0_stages derives
            # it: sha256 of "<input sha>|<version>|<stage>".
            expected = hashlib.sha256(
                f"{input_sha}|{case_version}|{stage}".encode()
            ).hexdigest()
            checked += 1
            if recorded != expected:
                bad.append(f"{stage}: cache key mismatch")
            try:
                with open(os.path.join(cache_dir, name),
                          encoding="utf-8") as fh:
                    json.load(fh)
            except ValueError:
                bad.append(f"{stage}: cache JSON unparsable")
        check("stage cache integrity keys", not bad,
              "; ".join(bad[:5]) if bad else
              f"{checked} cache entries verified")
    stages = case_doc.get("stages") or {}
    failed = [s for s, v in stages.items()
              if v.get("status") not in ("ok", "cached")]
    if failed:
        notes.append("stages recorded as not-ok in this "
                     f"case: {', '.join(sorted(failed))} "
                     "(integrity is unaffected; the case "
                     "records its own degraded stages)")
    return {"ok": not failures, "checks": checks,
            "failures": failures, "notes": notes}


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR one-command full static workup: writes"
                    " report.md + report.json for an APK/AAB/XAPK/OBB.")
    p.add_argument("target", nargs="?", help="path to the .apk, .aab, .xapk,"
                                  " .apkm, or .obb file")
    p.add_argument("--export", metavar="CASE_DIR",
                   help="export a case directory to a bundle "
                        "(with --bundle FILE) and exit")
    p.add_argument("--bundle", metavar="FILE",
                   help="bundle path for --export / --import")
    p.add_argument("--import", dest="import_bundle", metavar="FILE",
                   help="import a case bundle (with --out DIR) "
                        "and exit")
    p.add_argument("--verify", metavar="CASE_DIR",
                   help="verify a case directory's integrity "
                        "and exit")
    p.add_argument("--graph", metavar="CASE_DIR",
                   help="print a case's graph.json as JSON, "
                        "filtered by --kind / --edge-kind / "
                        "--min-confidence / --text, and exit")
    p.add_argument("--investigation", metavar="CASE_DIR",
                   help="print a case's investigation.json "
                        "summary as JSON and exit")
    p.add_argument("--kind", metavar="KIND",
                   help="graph view: keep only nodes of this "
                        "node kind")
    p.add_argument("--edge-kind", metavar="KIND",
                   help="graph view: keep only edges of this "
                        "edge kind")
    p.add_argument("--min-confidence", metavar="LEVEL",
                   help="graph view: minimum edge confidence "
                        "(low|medium|high or 0..1)")
    p.add_argument("--text", metavar="TEXT",
                   help="graph view: free-text filter on "
                        "node labels / ids")
    p.add_argument("--no-graph", action="store_true",
                   help="skip the graph.json companion "
                        "(or set NAR_NO_GRAPH=1)")
    p.add_argument("--no-investigation", action="store_true",
                   help="skip the investigation.json companion "
                        "(or set NAR_NO_INVESTIGATION=1)")
    p.add_argument("--stage-timeout", type=float, metavar="S",
                   help="per-stage timeout cap in seconds "
                        "(orchestration budget)")
    p.add_argument("--total-budget", type=float, metavar="S",
                   help="total budget in seconds for the whole "
                        "run (orchestration budget)")
    p.add_argument("--out", metavar="DIR",
                   help="report directory (default ./nar-analyze-<name>)")
    p.add_argument("--work", metavar="DIR",
                   help="scratch directory for engine tools"
                        " (default: temp dir)")
    p.add_argument("--json", action="store_true",
                   help="also print the JSON report to stdout")
    p.add_argument("--no-html", action="store_true",
                   help="skip the offline HTML dashboard")
    p.add_argument("--no-cache", action="store_true",
                   help="ignore the case stage cache and re-run "
                        "every 2.0 stage")
    args = p.parse_args(argv)
    # Case view modes (2.6.0 Phases 7/8): graph query and
    # investigation summary over an existing case directory.
    if args.graph or args.investigation:
        case_dir = args.graph or args.investigation
        fname = "graph.json" if args.graph else \
            "investigation.json"
        path = os.path.join(case_dir, fname)
        if not os.path.isfile(path):
            print(f"nar-analyze: {fname} not found in case "
                  f"directory {case_dir}", file=sys.stderr)
            return 2
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError) as e:
            print(f"nar-analyze: cannot read {fname} in case "
                  f"directory {case_dir}: {e}",
                  file=sys.stderr)
            return 2
        if args.graph:
            if _graph is None:
                print("nar-analyze: graph module unavailable",
                      file=sys.stderr)
                return 1
            min_conf = args.min_confidence
            if min_conf is not None:
                try:
                    min_conf = float(min_conf)
                except ValueError:
                    pass  # a level name such as "high"
            doc = _graph.query_graph(
                doc, kind=args.kind, edge_kind=args.edge_kind,
                min_confidence=min_conf, text=args.text)
        else:
            if _investigation is None:
                print("nar-analyze: investigation module "
                      "unavailable", file=sys.stderr)
                return 1
            doc = _investigation.summarize_investigation(doc)
        print(json.dumps(doc, indent=2))
        return 0
    set_layers(graph=not args.no_graph,
               investigation=not args.no_investigation)
    # Case bundle modes (Phase 8): export / import / verify
    # operate on case directories, not on targets.
    if args.export or args.import_bundle or args.verify:
        if args.export:
            if not args.bundle:
                print("nar-analyze: --export needs --bundle FILE",
                      file=sys.stderr)
                return 2
            summary = export_case(args.export, args.bundle)
            print(json.dumps(summary, indent=2) if args.json
                  else f"exported {summary['files']} files to "
                       f"{summary['bundle']}")
            return 0
        if args.import_bundle:
            out_dir = args.out or os.path.join(
                os.getcwd(), "nar-case-imported")
            try:
                result = import_case(args.import_bundle, out_dir)
            except (ValueError, zipfile.BadZipFile) as e:
                print(f"nar-analyze: import failed: {e}",
                      file=sys.stderr)
                return 1
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"imported to {result['imported_to']}: "
                      f"verify {'OK' if result['ok'] else 'FAILED'}")
                for f in result["failures"]:
                    print(f"  FAIL {f}")
            return 0 if result["ok"] else 1
        result = verify_case(args.verify)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"case verify: "
                  f"{'OK' if result['ok'] else 'FAILED'}")
            for c in result["checks"]:
                print(f"  [{'ok' if c['ok'] else 'FAIL'}] "
                      f"{c['check']} {c['detail']}")
            for n in result["notes"]:
                print(f"  note: {n}")
        return 0 if result["ok"] else 1
    if not args.target:
        p.error("a target file is required (or use --export / "
                "--import / --verify)")
    set_budgets(args.stage_timeout, args.total_budget)
    stem = os.path.splitext(os.path.basename(args.target))[0] or "target"
    out_dir = args.out or os.path.join(os.getcwd(), f"nar-analyze-{stem}")
    # Default work dir via mkdtemp (Phase 10): the previous
    # predictable gettempdir()/nar-analyze-work-<stem> path
    # could be pre-created or symlinked by another local
    # user before the run; mkdtemp creates it atomically
    # with an unpredictable suffix and 0700 permissions.
    work_dir = args.work or tempfile.mkdtemp(
        prefix=f"nar-analyze-work-{stem}-")
    if args.no_cache and os.path.isdir(os.path.join(out_dir, "cache")):
        import shutil
        shutil.rmtree(os.path.join(out_dir, "cache"))
    try:
        report = analyze(args.target, work_dir, out_dir)
    except FileNotFoundError as e:
        print(f"nar-analyze: {e}", file=sys.stderr)
        return 2
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, "report.json")
    md_path = os.path.join(out_dir, "report.md")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(render_md(report))
    # Case workspace record + execution log (2.0).
    case_id = "nar-" + report.get("target_sha256", "unknown")[:12]
    report["case_id"] = case_id
    stages = {}
    for entry in EXEC_LOG:
        stages[entry["stage"]] = {
            "status": entry["status"],
            "duration_s": entry["duration_s"]}
    case_doc = {
        "case_id": case_id, "nar_version": NAR_VERSION,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                 time.gmtime()),
        "input": {"path": report.get("target"),
                  "sha256": report.get("target_sha256"),
                  "size_bytes": report.get("target_size_bytes")},
        "config": {"profile": "full",
                   "budgets": _budget_snapshot()},
        "tool_versions": {"nar": NAR_VERSION,
                          "python": sys.version.split()[0]},
        "stages": stages,
    }
    with open(os.path.join(out_dir, "case.json"), "w",
              encoding="utf-8") as fh:
        json.dump(case_doc, fh, indent=2)
    exec_doc = {"tool": "nar-analyze", "case_id": case_id,
                "input_sha256": report.get("target_sha256"),
                "entries": EXEC_LOG}
    with open(os.path.join(out_dir, "execution-log.json"), "w",
              encoding="utf-8") as fh:
        json.dump(exec_doc, fh, indent=2)
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    if not args.no_html:
        try:
            proc = subprocess.run(
                [sys.executable,
                 os.path.join(HERE, "nar-report.py"), out_dir],
                capture_output=True, text=True, timeout=300)
            if proc.returncode != 0:
                print(f"nar-analyze: HTML dashboard degraded: "
                      f"{proc.stderr.strip()[-200:]}",
                      file=sys.stderr)
        except (OSError, subprocess.TimeoutExpired) as e:
            print(f"nar-analyze: HTML dashboard skipped: {e}",
                  file=sys.stderr)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(render_md(report))
    print(f"\nReport written: {md_path} and {json_path}",
          file=sys.stderr)
    return 1 if report.get("fatal") else 0


if __name__ == "__main__":
    sys.exit(main())
