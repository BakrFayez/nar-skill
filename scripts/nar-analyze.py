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

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
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
    from narlib import chains as _chains
    from narlib import container as _container_mod
    from narlib import companions as _companions
    from narlib import correlations as _correlations
    from narlib import evidence as _evidence
    from narlib import formats_registry as _formats
    from narlib import graph as _graph
    from narlib import investigation as _investigation
    from narlib import safearchive as _safearchive
except Exception:  # narlib missing: keep the tool usable
    NAR_VERSION = "3.0.1"
    _chains = None
    _formats = None
    _container_mod = None
    _companions = None
    _correlations = None
    _evidence = None
    _graph = None
    _investigation = None
    _safearchive = None

try:
    import resource as _resource
except Exception:  # non-Unix (Windows has no resource
    # module): peak RSS comes from the ctypes psapi source
    # in _peak_rss_bytes_win32 instead
    _resource = None

try:
    import ctypes as _ctypes
except Exception:  # no ctypes: the win32 RSS source is
    # unavailable and reports None (see _peak_rss_bytes)
    _ctypes = None


if _ctypes is not None:
    class _ProcessMemoryCountersEx(_ctypes.Structure):
        """PROCESS_MEMORY_COUNTERS_EX (psapi.h), the struct
        GetProcessMemoryInfo fills. PeakWorkingSetSize is
        the process's peak RSS in bytes. The two leading
        fields are DWORDs (fixed 32-bit here, not c_ulong,
        whose width differs between Windows and POSIX)."""

        _fields_ = [
            ("cb", _ctypes.c_uint32),
            ("PageFaultCount", _ctypes.c_uint32),
            ("PeakWorkingSetSize", _ctypes.c_size_t),
            ("WorkingSetSize", _ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", _ctypes.c_size_t),
            ("QuotaPagedPoolUsage", _ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", _ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", _ctypes.c_size_t),
            ("PagefileUsage", _ctypes.c_size_t),
            ("PeakPagefileUsage", _ctypes.c_size_t),
            ("PrivateUsage", _ctypes.c_size_t),
        ]
else:
    _ProcessMemoryCountersEx = None

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
#
# Memory budget (3.0 Part 11): --budget-mb N caps the peak
# RSS of this process and its stage subprocesses. Stage
# boundaries check the peak; crossing it raises
# _MemoryBudgetExceeded with the NAMED boundary
# "memory-budget:<stage>", which analyze()/main() record
# in the case + execution state (case.json resume_boundary,
# a budget-exceeded execution-log entry, report
# budget_abort) and turn into a clean abort — never an
# OOM kill, never a traceback. Stages completed before the
# boundary are already in the case stage cache, so
# re-running the same --out directory without the budget
# (or with a sufficient one) RESUMES from the boundary.
BUDGET = {"stage_timeout_s": None, "total_budget_s": None,
          "budget_mb": None, "t0": None}

# DEX document shape for the analyze pipeline (3.0
# Part 11): compact by default (nar-dex's default);
# --dex-full selects the full 2.6.2 shape. The choice is
# recorded in case.json config and bound into the dex
# stage's cache key, so the two shapes never serve each
# other's cache entries in one case directory.
DEX_FULL = {"enabled": False}


def set_dex_full(enabled=False):
    DEX_FULL["enabled"] = bool(enabled)


def set_budgets(stage_timeout_s=None, total_budget_s=None,
                budget_mb=None):
    BUDGET["stage_timeout_s"] = stage_timeout_s
    BUDGET["total_budget_s"] = total_budget_s
    BUDGET["budget_mb"] = budget_mb
    BUDGET["t0"] = time.time()
    _RSS_UNAVAILABLE_NOTED.clear()


# Stage names whose memory-budget check already recorded a
# "budget-unavailable" entry this run (one per stage, so a
# platform with no RSS source is named in the log once per
# boundary instead of at every entry/exit check).
_RSS_UNAVAILABLE_NOTED = set()


class _MemoryBudgetExceeded(Exception):
    """Raised at a stage boundary when the peak RSS crosses
    --budget-mb. Carries the named boundary so the abort
    can be recorded and resumed from."""

    def __init__(self, stage, peak_rss_bytes, budget_mb):
        self.stage = stage
        self.boundary = f"memory-budget:{stage}"
        self.peak_rss_bytes = peak_rss_bytes
        self.budget_mb = budget_mb
        super().__init__(
            f"memory budget of {budget_mb} MB exceeded at "
            f"{self.boundary} (peak RSS "
            f"{peak_rss_bytes} bytes)")


def _peak_rss_bytes_win32():
    """Peak RSS in bytes on Windows, via stdlib ctypes:
    GetProcessMemoryInfo (psapi, falling back to kernel32's
    K32GetProcessMemoryInfo) fills PROCESS_MEMORY_COUNTERS_EX
    and PeakWorkingSetSize is this process's peak working
    set. Windows exposes no per-children peak through this
    API, so unlike the POSIX source this is the self peak
    only. Returns None when the source is genuinely
    unavailable (no ctypes, DLL or entry point missing, or
    the call fails) — a failed lookup is reported as None,
    never as an AttributeError/OSError leak and never as
    a fabricated value."""
    if _ctypes is None or _ProcessMemoryCountersEx is None:
        return None
    counters = _ProcessMemoryCountersEx()
    counters.cb = _ctypes.sizeof(counters)
    try:
        kernel32 = _ctypes.WinDLL("kernel32",
                                  use_last_error=True)
        # Declare the prototypes before calling: ctypes'
        # default restype is C int (32-bit) and, without
        # argtypes, arguments are likewise passed as C int,
        # so the 64-bit GetCurrentProcess pseudo-handle
        # (0xFFFFFFFFFFFFFFFF) would be truncated on both
        # legs of the round trip and GetProcessMemoryInfo
        # would receive an invalid handle, fail, and make
        # this source look spuriously unavailable. The
        # assignments are defensive: a plain-Python stand-in
        # for the DLL functions (a bound method, say) may
        # refuse attribute assignment, and such a stand-in
        # performs no ctypes conversion anyway, so a refused
        # prototype must not fail the call.
        try:
            kernel32.GetCurrentProcess.restype = (
                _ctypes.c_void_p)
        except (AttributeError, TypeError):
            pass
        handle = kernel32.GetCurrentProcess()
        try:
            psapi = _ctypes.WinDLL("psapi",
                                   use_last_error=True)
            get_info = psapi.GetProcessMemoryInfo
        except (AttributeError, OSError):
            get_info = kernel32.K32GetProcessMemoryInfo
        try:
            get_info.argtypes = [_ctypes.c_void_p,
                                 _ctypes.c_void_p,
                                 _ctypes.c_uint32]
            get_info.restype = _ctypes.c_int
        except (AttributeError, TypeError):
            pass
        if not get_info(handle, _ctypes.byref(counters),
                        _ctypes.sizeof(counters)):
            return None
    except (AttributeError, OSError, ValueError):
        return None
    peak = int(counters.PeakWorkingSetSize)
    return peak if peak > 0 else None


def _peak_rss_bytes():
    """Peak RSS in bytes: the max of this process's peak
    and the peak of its terminated children (the stage
    subprocesses), or None when the platform cannot
    report it (the memory budget then does not engage).
    On Windows the source is _peak_rss_bytes_win32 (the
    resource module does not exist there); the POSIX
    getrusage path below is unchanged."""
    if sys.platform == "win32":
        return _peak_rss_bytes_win32()
    if _resource is None:
        return None
    try:
        factor = 1 if sys.platform == "darwin" else 1024
        self_peak = _resource.getrusage(
            _resource.RUSAGE_SELF).ru_maxrss * factor
        child_peak = _resource.getrusage(
            _resource.RUSAGE_CHILDREN).ru_maxrss * factor
        return max(self_peak, child_peak)
    except (ValueError, OSError):
        return None


def _check_memory_budget(stage):
    """Abort the run when the memory budget is crossed.

    Called at stage boundaries (stage entry and exit).
    Records the budget-exceeded execution-log entry with
    the named boundary, then raises _MemoryBudgetExceeded;
    analyze()/main() convert it into the recorded,
    resumable abort. When the platform has no RSS source
    the budget cannot be enforced: a budget-unavailable
    entry is recorded under the same named boundary
    instead of silently passing."""
    if not BUDGET.get("budget_mb"):
        return
    peak = _peak_rss_bytes()
    if peak is None:
        # No RSS source on this platform: the budget cannot
        # be enforced at this boundary. That is an honest
        # named failure, not a silent pass — record it once
        # per stage in the execution log under the same
        # named boundary, and let the run continue (the
        # budget is unenforceable here, not exceeded).
        if stage not in _RSS_UNAVAILABLE_NOTED:
            _RSS_UNAVAILABLE_NOTED.add(stage)
            EXEC_LOG.append({
                "stage": stage, "module": "nar-analyze",
                "tool": "nar-analyze",
                "tool_version": NAR_VERSION,
                "status": "budget-unavailable",
                "duration_s": 0.0,
                "boundary": f"memory-budget:{stage}",
                "reason": "peak RSS source unavailable on "
                          "this platform; memory budget "
                          "not enforced at this boundary",
                "budget": _budget_snapshot()})
        return
    if peak > BUDGET["budget_mb"] * 1024 * 1024:
        EXEC_LOG.append({
            "stage": stage, "module": "nar-analyze",
            "tool": "nar-analyze", "tool_version": NAR_VERSION,
            "status": "budget-exceeded", "duration_s": 0.0,
            "boundary": f"memory-budget:{stage}",
            "peak_rss_bytes": peak,
            "budget": _budget_snapshot()})
        raise _MemoryBudgetExceeded(stage, peak,
                                    BUDGET["budget_mb"])


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
            "total_budget_s": BUDGET["total_budget_s"],
            "budget_mb": BUDGET["budget_mb"]}


# ------------------------------------------------------------------
# Streaming JSON writer (3.0 Part 11).
#
# Writes a document incrementally, token by token,
# producing bytes IDENTICAL to json.dump(doc, fh,
# indent=N) — the case-file format every NAR writer has
# always used — without ever holding the serialized text
# in memory next to the document itself. The classic
# write path made the serialized form a second full-size
# resident copy; on the large companions (dex, graph,
# investigation) that copy is a measurable share of the
# peak. The emitter walks the object graph with an
# explicit stack (no recursion limit, no intermediate
# string) and emits each scalar through the stdlib
# encoder, so leaf formatting (floats, string escapes,
# ensure_ascii) matches the classic path exactly; it is
# pinned byte-identical by tests/unit/test_part11_perf.py
# and tests/unit/test_streaming_dex_stage.py conventions.
# Lives in nar-analyze (the write path it serves) rather
# than a new module file.

_STREAM_ENCODER = json.encoder.encode_basestring_ascii


def _stream_key_token(key):
    """The emitted token for a dict key, mirroring the
    stdlib encoder's key coercion under ensure_ascii."""
    if isinstance(key, str):
        return _STREAM_ENCODER(key)
    if key is True:
        return '"true"'
    if key is False:
        return '"false"'
    if key is None:
        return '"null"'
    if isinstance(key, (int, float)):
        return '"' + json.dumps(key) + '"'
    raise TypeError(
        f"keys must be str, int, float, bool or None, "
        f"not {type(key).__name__}")


def _stream_scalar_token(value):
    if isinstance(value, str):
        return _STREAM_ENCODER(value)
    return json.dumps(value)


def dump_json_streaming(doc, fh, indent=1):
    """Write doc to the BINARY file object fh, byte-
    identical to json.dump(doc, indent=indent), without
    materializing the serialized text."""
    unit = " " * indent
    buf = []
    buf_len = 0

    def push(token):
        nonlocal buf_len
        buf.append(token)
        buf_len += len(token)
        if buf_len >= 65536:
            fh.write("".join(buf).encode("utf-8"))
            buf.clear()
            buf_len = 0

    stack = [("value", doc, 0)]
    while stack:
        item = stack.pop()
        if item[0] == "raw":
            push(item[1])
            continue
        _tag, value, depth = item
        if isinstance(value, dict):
            if not value:
                push("{}")
                continue
            items = list(value.items())
            push("{")
            stack.append(("raw", "\n" + unit * depth + "}"))
            for i in range(len(items) - 1, -1, -1):
                k, v = items[i]
                prefix = (",\n" if i else "\n") \
                    + unit * (depth + 1) \
                    + _stream_key_token(k) + ": "
                stack.append(("value", v, depth + 1))
                stack.append(("raw", prefix))
        elif isinstance(value, (list, tuple)):
            if not value:
                push("[]")
                continue
            push("[")
            stack.append(("raw", "\n" + unit * depth + "]"))
            for i in range(len(value) - 1, -1, -1):
                prefix = (",\n" if i else "\n") \
                    + unit * (depth + 1)
                stack.append(("value", value[i], depth + 1))
                stack.append(("raw", prefix))
        elif isinstance(value, (str, int, float, bool)) \
                or value is None:
            push(_stream_scalar_token(value))
        else:
            raise TypeError(
                f"Object of type {type(value).__name__} is "
                "not JSON serializable")
    if buf:
        fh.write("".join(buf).encode("utf-8"))


def write_json_streaming(path, doc, indent=1):
    """Write doc to path (UTF-8, no trailing newline) via
    dump_json_streaming."""
    with open(path, "wb") as fh:
        dump_json_streaming(doc, fh, indent=indent)
    return path


def _write_report_json(path, doc):
    """Write report.json / case.json / execution-log.json
    (indent=2) through the streaming writer."""
    write_json_streaming(path, doc, indent=2)


def _write_companion(path, doc):
    """Write one case companion (indent=1) through the
    streaming writer (3.0 Part 11): the serialized text is
    never held whole in memory next to the document."""
    write_json_streaming(path, doc)


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
        # A child that exits non-zero but prints parseable
        # JSON (usually an in-band error document) is not
        # an unqualified success: the execution log said
        # "ok" whenever stdout parsed, ignoring the exit
        # code (stability audit C-17). The data is still
        # returned — consumers handle in-band errors — but
        # the log now records the run as degraded.
        EXEC_LOG.append({"stage": script, "module": script,
                         "tool": script, "tool_version": None,
                         "status": ("ok" if proc.returncode == 0
                                    else "degraded"),
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
    """Choose the base APK inside a container.

    The rule itself lives in narlib.container (the shared
    container home since 3.0 Part 2): the entry named after
    the manifest package, else a canonical base name
    (base-master.apk / base.apk, the bundletool .apks
    layout), else the largest non-config APK. This wrapper
    keeps the historical (triage, names) call shape."""
    contained = triage.get("contained_apks") or []
    if not contained:
        return None
    package = (triage.get("container_manifest") or {}).get("package")
    if _container_mod is not None:
        filtered = [c for c in contained if c["name"] in names]
        return _container_mod.pick_base_apk(
            filtered or contained, package=package)
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
try:
    from narlib.budget import ResourceBudget as _ResourceBudget
except Exception:  # pragma: no cover - narlib always ships it
    _ResourceBudget = None

#: The contained-extraction policy as a named budget instance
#: (2.6.2): per-entry 4 GiB / whole-run 8 GiB -- the same values
#: the ad-hoc constants carried in 2.6.1. The MAX_* names stay
#: as aliases of the budget fields; extract_entry reads them
#: (through _effective_extract_caps) at call time so tests and
#: embedders that patch the constants keep working.
ANALYZE_EXTRACT_BUDGET = _ResourceBudget(
    max_entries=20_000,
    max_file_bytes=4 * 1024 * 1024 * 1024,
    max_total_bytes=8 * 1024 * 1024 * 1024) if _ResourceBudget else None
MAX_EXTRACT_ENTRY_BYTES = 4 * 1024 * 1024 * 1024
MAX_EXTRACT_TOTAL_BYTES = 8 * 1024 * 1024 * 1024
_EXTRACT_BUDGET = {"used": 0}


def _effective_extract_caps():
    """(per-entry cap, total cap) for the next extraction:
    the module-level MAX_* values, read at call time so a
    patched constant takes effect (the 2.6.1 regression tests
    patch them). Unpatched, they equal ANALYZE_EXTRACT_BUDGET."""
    return MAX_EXTRACT_ENTRY_BYTES, MAX_EXTRACT_TOTAL_BYTES


def _contained_join(root, *parts):
    """Join parts under root, refusing any result that
    escapes root (absolute parts, '..' traversal).

    Two proofs, mirroring narlib.safearchive (stability
    audit C-01/C-09): the root is first made absolute —
    comparing a relative destination against an absolute
    root used to refuse EVERY entry for a relative --work
    dir — and the joined destination is then resolved
    with realpath, so a symlink component already inside
    the root cannot redirect the write outside it (the
    lexical check alone was blind to pre-existing links,
    the exact gap safearchive was hardened against in
    Phase 10 and this extractor never got)."""
    root_real = os.path.realpath(root)
    dest = os.path.normpath(os.path.join(root_real, *parts))
    if dest != root_real and \
            not dest.startswith(root_real + os.sep):
        raise ValueError(
            "archive entry path escapes the work "
            f"directory: {os.path.join(*parts)!r}")
    dest_real = os.path.realpath(dest)
    if dest_real != root_real and \
            not dest_real.startswith(root_real + os.sep):
        raise ValueError(
            "archive entry path escapes the work "
            "directory through a symlink: "
            f"{os.path.join(*parts)!r}")
    return dest


def extract_entry(zf, name, root, *rel_parts):
    """Extract one archive entry under root, contained
    and capped. Raises ValueError when the destination
    would escape root or the entry exceeds the extraction
    budget; a partially written file is removed first."""
    dest = _contained_join(root, *rel_parts)
    info = zf.getinfo(name)
    cap_entry, cap_total = _effective_extract_caps()
    if info.file_size > cap_entry:
        raise ValueError(
            f"archive entry {name!r} declares "
            f"{info.file_size} bytes, over the "
            f"{cap_entry}-byte extraction cap")
    if _EXTRACT_BUDGET["used"] + info.file_size \
            > cap_total:
        raise ValueError(
            f"archive entry {name!r} would exceed the "
            f"{cap_total}-byte total "
            "extraction budget for this run")
    if os.path.islink(dest):
        # Never write through a pre-existing symlink at
        # the destination itself (C-01 companion guard,
        # as in safearchive C-15).
        raise ValueError(
            f"archive entry {name!r} destination is a "
            "pre-existing symlink; refusing to write "
            "through it")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    written = 0
    try:
        with zf.open(name) as src, open(dest, "wb") as dst:
            while True:
                chunk = src.read(1 << 20)
                if not chunk:
                    break
                written += len(chunk)
                if written > cap_entry or \
                        _EXTRACT_BUDGET["used"] + written \
                        > cap_total:
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
    except (zipfile.BadZipFile, RuntimeError, EOFError,
            OSError) as e:
        # A corrupt entry (bad CRC, truncated stream) is a
        # refusal like any other: remove the partial file and
        # surface it as the same ValueError the budget and
        # containment refusals use, never a leaked zipfile
        # error (2.6.2).
        try:
            os.unlink(dest)
        except OSError:
            pass
        raise ValueError(
            f"archive entry {name!r} unreadable: {e}") from e
    _EXTRACT_BUDGET["used"] += written
    return dest


def extract_entry_record(zf, name, root, *rel_parts):
    """Structured form of extract_entry (2.6.2): never raises
    for a refusal. Returns (dest, None) on success or
    (None, {"entry": name, "reason": str}) on refusal -- the
    same {entry, reason} record shape narlib.safearchive
    produces, so callers can accumulate rejections uniformly.
    The record's ``entry`` cites the RAW name as stored in
    the archive (ZipInfo.orig_filename) when the member can
    be looked up: zipfile normalises ``filename`` on
    Windows, and a rejection report is evidence of what the
    archive actually carries."""
    try:
        return extract_entry(zf, name, root, *rel_parts), None
    except ValueError as e:
        return None, {"entry": _raw_entry_name(zf, name),
                      "reason": str(e)}


def _raw_entry_name(zf, name):
    """The member name as stored in the archive
    (ZipInfo.orig_filename), falling back to ``name`` when
    the member cannot be looked up. Report citations use
    the raw name; lookups and extraction keep using the
    normalised name, unchanged."""
    try:
        return zf.getinfo(name).orig_filename or name
    except (KeyError, AttributeError, TypeError):
        return name


def _registry_lib_markers(engine_id):
    """Native-library path markers for one engine, read from
    formats.json (Part 16 single source of truth). Empty when
    the registry is unavailable (degraded narlib)."""
    if _formats is None:
        return []
    return [m for m in _formats.path_markers(engine_id)
            if m.endswith(".so") or m.startswith("lib")]


def zip_entry_flags(names):
    # The engine library markers derive from formats.json;
    # the .pck / bundle / container extensions below are
    # payload-format facts, not engine markers.
    il2cpp_libs = _registry_lib_markers("unity-il2cpp")
    flutter_libs = _registry_lib_markers("flutter")
    godot_libs = _registry_lib_markers("godot")
    return {
        "il2cpp": any(n.rsplit("/", 1)[-1] == m
                      for n in names for m in il2cpp_libs
                      if m.endswith(".so")),
        "flutter": any(n.endswith("/" + m)
                       for n in names for m in flutter_libs),
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
                     or any(m in n for m in godot_libs)
                     or n.startswith("assets/.godot/")
                     for n in names),
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
    _check_memory_budget(stage)
    result = _run_cached_stage_inner(stage, script, args,
                                     cache_key, out_dir)
    _check_memory_budget(stage)
    return result


def _run_cached_stage_inner(stage, script, args, cache_key,
                            out_dir):
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
        try:
            with open(key_path, encoding="utf-8") as fh:
                key_matches = fh.read().strip() == cache_key
            cached_doc = None
            if key_matches:
                with open(cache_path, encoding="utf-8") as fh:
                    cached_doc = json.load(fh)
            if key_matches and isinstance(cached_doc, dict):
                EXEC_LOG.append({
                    "stage": stage, "module": script,
                    "tool": script, "tool_version": NAR_VERSION,
                    "status": "cached", "duration_s": 0.0})
                return cached_doc, None, True
            if key_matches:
                # The key matched but the document is
                # unreadable or not an object: the cache
                # pair is corrupt (or was poisoned). The
                # pre-audit code let json.load raise and
                # killed the whole analysis with a
                # traceback (stability audit C-05). Treat
                # it as a miss, drop the pair, re-run.
                for stale in (cache_path, key_path):
                    try:
                        os.unlink(stale)
                    except OSError:
                        pass
        except (OSError, ValueError):
            for stale in (cache_path, key_path):
                try:
                    os.unlink(stale)
                except OSError:
                    pass
    data, err = run_json_tool(script, args)
    if data is not None and out_dir:
        # Write the pair atomically (temp + rename, key
        # LAST): an interrupted run must never leave a
        # key claiming a half-written document (C-05).
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        tmp_doc = cache_path + ".tmp"
        with open(tmp_doc, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        os.replace(tmp_doc, cache_path)
        tmp_key = key_path + ".tmp"
        with open(tmp_key, "w", encoding="utf-8") as fh:
            fh.write(cache_key)
        os.replace(tmp_key, key_path)
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
#
# 2.6.2 WS-D1: steps 3–4 read the document through
# _WindowedReader (a bounded 1 MiB window) instead of an
# mmap: the file is never mapped, so no file-backed pages
# are charged to the process beyond the resident window,
# and the whole document is never held. Outputs are
# byte-identical to the mmap path (hard gate, 2.6.2
# benchmark record).

def _json_skip_ws(mm, i):
    n = len(mm)
    while i < n and mm[i] in b" \t\r\n":
        i += 1
    return i


def _json_value_end(mm, i):
    """End offset (exclusive) of the JSON value starting at
    or after offset i in the source bytes. Pure structural
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


class _WindowedReader:
    """Bounded-window random-access reader over a file
    (2.6.2 WS-D1: replaces the mmap-backed reads of the
    DEX stage document).

    Presents exactly the interface the JSON span scanners
    consume — len(), integer indexing returning an int,
    slicing returning bytes — but never maps the file and
    never holds more than one fixed-size window of it
    (default 1 MiB) plus whatever slice a caller explicitly
    requests (a single dex_files element, a single token).
    The scanners and the re-serializer scan sequentially,
    so accesses hit the resident window; a slice spanning
    windows is assembled window by window. The bytes are
    the file's bytes, unchanged, so the projection and the
    companion outputs are byte-identical to the mmap path
    they replace (hard gate: see the 2.6.2 benchmark
    record)."""

    def __init__(self, path, window_size=1 << 20):
        self._fh = open(path, "rb")
        self._size = os.fstat(self._fh.fileno()).st_size
        self._window_size = max(4096, int(window_size))
        self._wstart = -1
        self._wdata = b""

    def __len__(self):
        return self._size

    def close(self):
        self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def _window(self, i):
        """(window_bytes, offset_of_i_within_window),
        loading the window containing offset i if needed."""
        if not (self._wstart <= i
                < self._wstart + len(self._wdata)):
            self._wstart = (i // self._window_size) \
                * self._window_size
            self._fh.seek(self._wstart)
            self._wdata = self._fh.read(self._window_size)
        return self._wdata, i - self._wstart

    def __getitem__(self, key):
        if isinstance(key, slice):
            start, stop, step = key.indices(self._size)
            if step != 1:
                return bytes(self[i]
                             for i in range(start, stop, step))
            if stop <= start:
                return b""
            parts = []
            i = start
            while i < stop:
                data, off = self._window(i)
                take = min(len(data) - off, stop - i)
                if take <= 0:
                    break
                parts.append(data[off:off + take])
                i += take
            return b"".join(parts)
        i = key + self._size if key < 0 else key
        if not 0 <= i < self._size:
            raise IndexError(
                "windowed reader index out of range")
        data, off = self._window(i)
        return data[off]


def _dex_projection_from_file(path):
    """Stream a DEX stage document from disk and return
    {totals, dex_files: [projections]}. Each dex_files
    element is parsed, projected and discarded before the
    next is read, so the full document is never resident.
    Reads go through the bounded-window reader (2.6.2
    WS-D1): the file is never mapped or held whole."""
    totals = None
    files = []
    with _WindowedReader(path) as mm:
        for key, vs, ve in _json_object_items(mm):
            if key == "dex_files":
                for es, ee in _json_array_items(mm, vs):
                    files.append(_dex_file_projection(
                        json.loads(mm[es:ee])))
            elif key == "totals":
                totals = json.loads(mm[vs:ve])
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
    cached stage document via the token re-serializer,
    reading through the bounded-window reader (2.6.2
    WS-D1) — the cache file is never mapped or held
    whole, and the emitted bytes are unchanged."""
    with _WindowedReader(cache_path) as mm:
        with open(companion_path, "wb") as out:
            _json_emit_value(mm, 0, out, 0)


def _dex_stage_streamed(report, companions, apk_path,
                        out_dir, dex_dir, cache_key_base,
                        summarize):
    """Wrapper: memory-budget boundary checks around the
    streamed DEX stage (3.0 Part 11)."""
    _check_memory_budget("dex")
    result = _dex_stage_streamed_inner(
        report, companions, apk_path, out_dir, dex_dir,
        cache_key_base, summarize)
    _check_memory_budget("dex")
    return result


def _dex_stage_streamed_inner(report, companions, apk_path,
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
    if DEX_FULL["enabled"]:
        # The full-shape document is a different stage
        # product from the compact one: bind the shape
        # into the cache key so one case directory never
        # serves the other shape's cache entry.
        cache_key_base = cache_key_base + "|dex-full"
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
        if DEX_FULL["enabled"]:
            cmd.append("--full")
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


def _target_has_dex(path):
    """True when the target is a bare DEX or a ZIP/APK
    carrying a classes*.dex entry."""
    try:
        with open(path, "rb") as fh:
            if fh.read(4) == b"dex\n":
                return True
    except OSError:
        return False
    if zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as zf:
                for name in zf.namelist():
                    base = name.rsplit("/", 1)[-1]
                    if re.fullmatch(r"classes\d*\.dex", base):
                        return True
        except zipfile.BadZipFile:
            return False
    return False


def _decompile_stage(report, companions, apk_path, out_dir,
                     cache_key_base):
    """The Part 10.5 decompile stage: run the
    java-decompile fallback chain (narlib.chains) against
    the target's DEX, write decompile.json, and ride the
    same per-stage cache as every other stage (key =
    sha256(cache_key_base|stage)), so a resumed case does
    not re-attempt any rung. A target with no DEX records
    identified-only / not-applicable instead of failing.
    Returns the Fallback Record, or None on degradation
    (recorded as a limitation, never a fabricated record).
    """
    stage_name = "decompile"
    key = hashlib.sha256(
        f"{cache_key_base}|{stage_name}".encode()).hexdigest()
    cache_path = _stage_cache_path(out_dir, stage_name)
    key_path = cache_path + ".key"
    if BUDGET["total_budget_s"] and BUDGET["t0"] and (
            time.time() - BUDGET["t0"]
            > BUDGET["total_budget_s"]):
        EXEC_LOG.append({
            "stage": stage_name, "module": "narlib.chains",
            "tool": "nar-analyze",
            "tool_version": NAR_VERSION,
            "status": "budget-exceeded", "duration_s": 0.0,
            "budget": _budget_snapshot()})
        report["limitations"].append(
            f"2.0 stage {stage_name} degraded: total budget "
            f"of {BUDGET['total_budget_s']}s exhausted "
            f"before stage {stage_name}")
        return None
    record = None
    cached = False
    if os.path.isfile(cache_path) and os.path.isfile(key_path):
        try:
            with open(key_path, encoding="utf-8") as fh:
                key_matches = fh.read().strip() == key
            cached_doc = None
            if key_matches:
                with open(cache_path, encoding="utf-8") as fh:
                    cached_doc = json.load(fh)
            if key_matches and isinstance(cached_doc, dict):
                record = cached_doc
                cached = True
                EXEC_LOG.append({
                    "stage": stage_name,
                    "module": "narlib.chains",
                    "tool": "nar-analyze",
                    "tool_version": NAR_VERSION,
                    "status": "cached", "duration_s": 0.0})
            elif key_matches:
                for stale in (cache_path, key_path):
                    _quiet_unlink(stale)
        except (OSError, ValueError):
            for stale in (cache_path, key_path):
                _quiet_unlink(stale)
    if record is None:
        started = time.time()
        try:
            if not _target_has_dex(apk_path):
                record = _chains.identified_only_record(
                    "java-decompile",
                    _chains.CHAIN_REGISTRY[
                        "java-decompile"]["chain"],
                    "target contains no DEX; decompilation "
                    "is not applicable to this target")
            else:
                record = _chains.run_decompile_chain(
                    apk_path,
                    os.path.join(out_dir, "decompile"))
        except Exception as e:
            EXEC_LOG.append({
                "stage": stage_name, "module": "narlib.chains",
                "tool": "nar-analyze",
                "tool_version": NAR_VERSION,
                "status": "failed",
                "duration_s": round(time.time() - started, 3),
                "budget": _budget_snapshot()})
            report["limitations"].append(
                f"2.0 stage {stage_name} degraded: "
                f"decompile chain failed ({e})")
            return None
        # Validate against the companion schema before the
        # record enters the case (same C-02 discipline as
        # the generic stage path).
        if _evidence is not None:
            try:
                with open(os.path.join(
                        os.path.dirname(HERE), "schemas",
                        "decompile.schema.json"),
                        encoding="utf-8") as fh:
                    schema = json.load(fh)
                violations = _evidence.validate(record, schema)
            except (OSError, ValueError):
                violations = []
            if violations:
                report["limitations"].append(
                    f"2.0 stage {stage_name} degraded: "
                    "decompile record failed its companion "
                    f"schema: {violations[0]}")
                return None
        os.makedirs(os.path.dirname(cache_path),
                    exist_ok=True)
        tmp_doc = cache_path + ".tmp"
        with open(tmp_doc, "w", encoding="utf-8") as fh:
            json.dump(record, fh)
        os.replace(tmp_doc, cache_path)
        tmp_key = key_path + ".tmp"
        with open(tmp_key, "w", encoding="utf-8") as fh:
            fh.write(key)
        os.replace(tmp_key, key_path)
        EXEC_LOG.append({
            "stage": stage_name, "module": "narlib.chains",
            "tool": "nar-analyze",
            "tool_version": NAR_VERSION, "status": "ok",
            "duration_s": round(time.time() - started, 3),
            "budget": _budget_snapshot()})
    _write_companion(
        os.path.join(out_dir, "decompile.json"), record)
    companions[stage_name] = {"file": "decompile.json",
                              "cached": cached}
    report["decompile"] = record
    report["decompile_summary"] = {
        "capability": record.get("capability"),
        "served_by": record.get("served_by"),
        "fidelity": record.get("fidelity"),
        "chain": record.get("chain"),
        "caveats": record.get("caveats"),
        "attempts": [
            {"rung": a.get("rung"), "status": a.get("status"),
             "classification": a.get("classification")}
            for a in record.get("attempts", [])],
    }
    return record


def run_2_0_stages(report, apk_path, out_dir, work_dir,
                   perms_data=None, key_path=None,
                   stage_target=None, merged=False):
    """The 2.0 module stages: fingerprint, engine fusion, DEX,
    native, network, security, assets. Each writes its
    standardized companion document into the case directory
    and a summary into the report. Failures degrade to a
    limitation line, never to a fabricated result.

    key_path names the file whose hash keys the stage
    cache. It MUST be the file the case itself is keyed
    to (the user's target): the pre-audit form hashed
    apk_path, which for container targets is the
    EXTRACTED base APK — a different file from the one
    case.json records — so every container-built case
    failed its own verify cache-integrity check
    (stability audit S-01)."""
    companions = {}
    report["companions"] = companions
    if not out_dir:
        report["limitations"].append(
            "2.0 module stages skipped: no case output directory")
        return
    os.makedirs(out_dir, exist_ok=True)
    cache_key_base = sha256_of(key_path or apk_path) \
        + "|" + NAR_VERSION
    if merged:
        # Merged-container stage documents differ from the
        # base-only documents for the same input hash: keep
        # their cache entries separate so a merged run and a
        # --no-merge-splits run into one case directory never
        # serve each other's documents.
        cache_key_base += "|container-merged"
    # Stage tools that resolve containers themselves
    # (engines / dex / native / network / security / assets)
    # receive the ORIGINAL target in merged mode and merge
    # splits on their own; the fingerprint and decompile
    # stages keep running on the base APK (apk_path).
    tool_target = stage_target or apk_path
    # The two stages whose merged output changes shape
    # (nar-assets / nar-native) are told to stay in their
    # legacy single-archive mode whenever this case is not
    # a merged-container case — so a --no-merge-splits run
    # (and any plain-APK run) keeps byte-identical stage
    # documents.
    split_flag = [] if merged else ["--no-merge-splits"]

    def stage(stage_name, script, args, companion_file, summarize,
              key_base_extra=""):
        key = hashlib.sha256(
            f"{cache_key_base}{key_base_extra}|{stage_name}"
            .encode()).hexdigest()
        data, err, cached = run_cached_stage(
            stage_name, script, args, key, out_dir)
        if data is None:
            report["limitations"].append(
                f"2.0 stage {stage_name} degraded: {err}")
            return None
        # A stage document is evidence: it must be a JSON
        # object, and where a companion schema is mapped
        # it must satisfy it, BEFORE it is written into
        # the case (stability audit C-02 — companions were
        # previously written with no validation at all,
        # so a poisoned or malformed document entered the
        # case unchecked and verify only ever looked at
        # the file's manifest hash).
        problem = None
        if not isinstance(data, dict):
            problem = "stage returned a non-object document"
        else:
            schema_name = _COMPANION_SCHEMAS.get(companion_file)
            if schema_name:
                try:
                    from narlib import evidence as _ev
                    schema = json.load(open(os.path.join(
                        os.path.dirname(HERE), "schemas",
                        schema_name), encoding="utf-8"))
                    violations = _ev.validate(data, schema)
                    if violations:
                        problem = ("stage document failed "
                                   "its companion schema: "
                                   + violations[0])
                except (OSError, ValueError):
                    problem = None  # schema unreadable: the
                    # dict check above still applied
        if problem:
            report["limitations"].append(
                f"2.0 stage {stage_name} degraded: {problem}")
            return None
        _write_companion(
            os.path.join(out_dir, companion_file), data)
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
    eng_data = stage("engines", "nar-engines.py", [tool_target],
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
            report, companions, tool_target, out_dir, dex_dir,
            cache_key_base, sum_dex)
    except _MemoryBudgetExceeded:
        # A budget abort is not a streaming failure: the
        # stage's cache + companion are valid resume
        # state and must not be unlinked or re-run.
        raise
    except Exception:
        _cache_path = _stage_cache_path(out_dir, "dex")
        for _p in (_cache_path, _cache_path + ".key",
                   _cache_path + ".spool",
                   os.path.join(out_dir, "dex.json")):
            _quiet_unlink(_p)
        dex_data = stage("dex", "nar-dex.py",
                         [tool_target, "--out", dex_dir]
                         + (["--full"] if DEX_FULL["enabled"]
                            else []),
                         "dex.json", sum_dex,
                         key_base_extra=("|dex-full"
                                         if DEX_FULL["enabled"]
                                         else ""))
    # Decompile stage (Part 10.5): the java-decompile
    # fallback chain, after the DEX stage, riding the same
    # stage cache. A chain failure degrades to a
    # limitation; the case continues.
    if _chains is not None:
        try:
            _decompile_stage(report, companions, apk_path,
                             out_dir, cache_key_base)
        except _MemoryBudgetExceeded:
            raise
        except Exception as e:
            report["limitations"].append(
                f"2.0 stage decompile degraded: {e}")
    else:
        report["limitations"].append(
            "2.0 stage decompile degraded: narlib.chains "
            "unavailable")
    nat_data = stage("native", "nar-native.py",
                     [tool_target] + split_flag,
                     "native.json", sum_native)
    net_data = stage("network", "nar-network.py",
                     [tool_target, "--work",
                      os.path.join(work_dir, "network")],
                     "endpoints.json", sum_network)
    sec_data = stage("security", "nar-security.py", [tool_target],
                     "security-findings.json", sum_security)
    assets_data = stage("assets", "nar-assets.py",
                        [tool_target] + split_flag,
                        "assets.json", sum_assets)

    def sum_app(data):
        totals = data.get("totals") or {}
        perm = data.get("permissions_in_use") or {}
        report["app_summary"] = {
            "verdict": data.get("verdict"),
            "activities": totals.get("activities"),
            "fragments": totals.get("fragments"),
            "composable_methods": totals.get("composable_methods"),
            "layouts": totals.get("layouts"),
            "deep_links": totals.get("deep_links"),
            "shipped_databases": totals.get("shipped_databases"),
            "sdks": totals.get("sdks"),
            "over_requested_permissions":
                perm.get("declared_but_unreferenced"),
            "jwt_structures": totals.get("jwt_structures"),
            "screen_map_entries": totals.get("screen_map_entries"),
            "data_flow_edges": totals.get("data_flow_edges"),
        }

    app_data = stage("app", "nar-app.py", [tool_target],
                     "app.json", sum_app)

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
        _write_companion(
            os.path.join(out_dir, "permissions.json"), perms_data)
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
        # The projection CALLS run inside the per-item try:
        # the pre-audit code built the list eagerly, so a
        # projection raising on a malformed stage document
        # (a bare dict .get chain over attacker-shaped
        # data) crashed the whole analysis before the
        # validation guard was ever reached (stability
        # audit C-06). Builders now receive thunks.
        projection_builders = [
            ("application", "application.json",
             "application.schema.json",
             lambda: _companions.project_application(
                 fp_data, NAR_VERSION)),
            ("manifest", "manifest.json", "manifest.schema.json",
             lambda: _companions.project_manifest(
                 report.get("permissions"),
                 report.get("identity"), NAR_VERSION)),
            ("native-inventory", "native-inventory.json",
             "native-inventory.schema.json",
             lambda: _companions.project_native_inventory(
                 nat_data, NAR_VERSION)),
            ("frameworks", "frameworks.json",
             "frameworks.schema.json",
             lambda: _companions.project_frameworks(
                 eng_data, fp_data, NAR_VERSION)),
            # Network companions (Evolution Phase 5), projected
            # from the network stage's endpoints document.
            ("network-analysis", "network-analysis.json",
             "network-analysis.schema.json",
             lambda: _companions.project_network_analysis(
                 net_data, NAR_VERSION)),
            ("api-architecture", "api-architecture.json",
             "api-architecture.schema.json",
             lambda: _companions.project_api_architecture(
                 net_data, NAR_VERSION)),
        ]
        for key, filename, schema_name, build_doc in \
                projection_builders:
            try:
                doc = build_doc()
                with open(os.path.join(schema_dir, schema_name),
                          encoding="utf-8") as fh:
                    schema = json.load(fh)
                errors = _evidence.validate(doc, schema)
            except Exception as e:
                errors = [f"projection failed: {e}"]
            if errors:
                report["limitations"].append(
                    f"companion {filename} not emitted: "
                    f"projection failed validation ({errors[0]})")
                continue
            _write_companion(
                os.path.join(out_dir, filename), doc)
            companions[key] = {"file": filename, "projected": True}

    # Cross-module correlations (Evolution Phase 8): explicit
    # join records across the stage documents, emitted as the
    # correlations.json companion (schema-validated). The JNI
    # entries are also embedded into native.json and counted
    # in the report, per the phase spec.
    corr = None
    if _correlations is not None and _evidence is not None:
        try:
            corr = _correlations.build_correlations(
                dex_data, nat_data, perms_data, net_data,
                NAR_VERSION)
        except Exception as e:
            # Same C-06 discipline: a correlations build
            # that raises on malformed stage data degrades
            # to a limitation, never a crashed analysis.
            report["limitations"].append(
                "companion correlations.json not emitted: "
                f"build failed ({e})")
            corr = None
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
            _write_companion(
                os.path.join(out_dir, "correlations.json"), corr)
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
                    _write_companion(native_path, native_doc)
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
        _check_memory_budget(stage_name)
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
        _write_companion(os.path.join(out_dir, filename), doc)
        companions[stage_name] = {"file": filename,
                                  "projected": True}
        EXEC_LOG.append({
            "stage": stage_name, "module": stage_name,
            "tool": "nar-analyze", "tool_version": NAR_VERSION,
            "status": "ok",
            "duration_s": round(time.time() - started, 3),
            "budget": _budget_snapshot()})
        _check_memory_budget(stage_name)
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


def analyze(target, work_dir, out_dir=None, merge_splits=True):
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
    # Container resolution (3.0 Part 2): with split merging
    # on (the default), a container target is resolved once
    # through narlib.container — base + splits extracted via
    # safearchive — and the stages consume the ResolvedTarget.
    # With --no-merge-splits the historical single-base
    # extraction below runs unchanged.
    resolved_target = None
    scan_roots = None
    _detected_kind = None
    if merge_splits and _container_mod is not None:
        try:
            _detected_kind = _container_mod.detect_container(target)
        except Exception:
            _detected_kind = None
    _is_container_input = bool(triage.get("is_container")) or \
        _detected_kind in (_container_mod.CONTAINER_KINDS
                           if _container_mod else ())
    if triage.get("is_aab"):
        step_notes.append(
            "target is an AAB bundle: permission, string, and engine"
            " steps need an APK built from it (bundletool build-apks)"
            " and were skipped")
        apk_for_steps = None
    elif _is_container_input and merge_splits and \
            _container_mod is not None:
        resolved_target = _container_mod.resolve_target(
            target, work_dir=os.path.join(
                work_dir, "container-resolved"))
        report["container"] = resolved_target.container_block()
        if report["identity"].get("kind") == "apk":
            report["identity"]["kind"] = (
                f"{resolved_target.input_kind} container")
        if resolved_target.base_entry is not None and \
                os.path.isfile(resolved_target.base):
            apk_for_steps = resolved_target.base
            scan_roots = list(resolved_target.assets_roots)
            merged_names = [s["name"] for s in
                            resolved_target.splits_merged]
            step_notes.append(
                f"container: steps ran on the contained base "
                f"APK {resolved_target.base_entry} resolved "
                f"through narlib.container; splits merged: "
                f"{merged_names or 'none'}")
            for skipped in resolved_target.split_skipped:
                step_notes.append(
                    f"container split skipped: "
                    f"{skipped['name']} ({skipped['reason']})")
        else:
            apk_for_steps = None
            step_notes.append(
                "container holds no triageable base APK; "
                "APK-level steps skipped")
        report["contained_obbs"] = [
            o.get("source_entry") or o["name"]
            for o in resolved_target.obbs
            if o.get("source") == "container"]
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
    if ((triage.get("is_container") or resolved_target is not None)
            and apk_for_steps
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
    if resolved_target is not None:
        # nar-strings resolves and merges splits itself.
        strings_target = target
    if strings_target:
        strings, err = run_json_tool("nar-strings.py", [strings_target])
        report["strings"] = (summarize_strings(strings) if strings
                             else {"error": err})
        if err:
            report["limitations"].append(f"String scan failed: {err}")

    # Engine deep dives, routed by the analyzed APK's own contents.
    _check_memory_budget("engines")
    engines = {}
    scan_path = apk_for_steps
    if scan_path and zipfile.is_zipfile(scan_path):
        # Merged mode: the scan spans every resolved root
        # (base + splits) — .pak/.pck/.utoc members inside
        # splits reach the engine stages through the roots,
        # and each deep dive runs on the root that carries
        # its marker.
        roots = scan_roots or [scan_path]
        root_flags = {}
        for root in roots:
            if zipfile.is_zipfile(root):
                with zipfile.ZipFile(root) as zf:
                    root_flags[root] = zip_entry_flags(
                        zf.namelist())
        flags = {"il2cpp": False, "flutter": False,
                 "rn_bundle": False, "godot": False,
                 "paks": [], "utocs": [], "uassets": []}
        for root in roots:
            rf = root_flags.get(root)
            if not rf:
                continue
            for key in ("il2cpp", "flutter", "rn_bundle",
                        "godot"):
                flags[key] = flags[key] or rf[key]
            flags["paks"].extend(rf["paks"])
            flags["utocs"].extend(rf["utocs"])
            flags["uassets"].extend(rf["uassets"])

        def _root_with(key, _flags=root_flags, _roots=roots):
            for root in _roots:
                rf = _flags.get(root)
                if rf and rf.get(key):
                    return root
            return scan_path

        pak_sources = [(root, n) for root in roots
                       for n in (root_flags.get(root) or {})
                       .get("paks", [])]
        if resolved_target is not None:
            for obb in resolved_target.obbs:
                if not zipfile.is_zipfile(obb["path"]):
                    continue
                with zipfile.ZipFile(obb["path"]) as ozf:
                    for n in ozf.namelist():
                        if n.lower().endswith(".pak"):
                            pak_sources.append((obb["path"], n))
        if triage.get("is_container") and \
                resolved_target is None:
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
                [_root_with("il2cpp"), "--out",
                 os.path.join(work_dir, "il2cpp")])
            engines["unity_il2cpp"] = data or {"error": err}
        else:
            # Metadata without the native library: the IL2CPP pair
            # is split across APKs and the dive cannot run on this
            # file alone. Say so explicitly instead of silently
            # omitting the section.
            hints = triage.get("engine_hints") or []
            _meta_name = _formats.metadata_file(
                "unity-il2cpp") if _formats else None
            _il2cpp_lib = next(
                (m for m in (_formats.path_markers(
                    "unity-il2cpp") if _formats else [])
                 if m.endswith(".so")), "the IL2CPP library")
            meta_hint = bool(
                (triage.get("engine_versions") or {}).get(
                    "unity_metadata_version")) or any(
                        _meta_name and _meta_name in marker
                        for hint in hints
                        for marker in (hint.get("markers") or []))
            if meta_hint:
                step_notes.append(
                    "Unity IL2CPP metadata present but no"
                    f" {_il2cpp_lib} in this file; the IL2CPP deep"
                    " dive was skipped (the native pair likely"
                    " lives in a split APK — see triage"
                    " split_native_suspected)")
                report["step_notes"] = step_notes
        if flags["flutter"]:
            data, err = run_json_tool(
                "nar-flutter.py", [_root_with("flutter")])
            engines["flutter"] = data or {"error": err}
        if flags["rn_bundle"]:
            data, err = run_json_tool(
                "nar-rn.py",
                [_root_with("rn_bundle"), "--work",
                 os.path.join(work_dir, "rn")])
            engines["react_native"] = data or {"error": err}
        if flags["godot"]:
            data, err = run_json_tool(
                "nar-godot.py", [_root_with("godot")])
            engines["godot"] = data or {"error": err}
        pak_reports = []
        for src_zip, entry in pak_sources[:3]:
            with zipfile.ZipFile(src_zip) as zf:
                # Citation form of the member name (raw, as
                # stored); extraction keeps the normalised
                # ``entry`` lookup name.
                cited = _raw_entry_name(zf, entry)
                try:
                    pak_path = extract_entry(
                        zf, entry, work_dir, "pak",
                        os.path.basename(entry))
                except ValueError as e:
                    pak_reports.append(
                        {"error": str(e), "entry": cited})
                    continue
            data, err = run_json_tool("nar-pak.py", [pak_path])
            if data:
                data = dict(data)
                data.pop("entries", None)  # counts/stats stay; the
                # full listing is one nar-pak run away and would bloat
                # this report
                data["contained_in"] = os.path.basename(src_zip)
                data["entry"] = cited
            pak_reports.append(data or {"error": err, "entry": cited})
        if len(pak_sources) > 3:
            report["limitations"].append(
                f"{len(pak_sources)} .pak files found; only the first"
                " 3 were listed")
        if pak_reports:
            engines["unreal_pak"] = pak_reports
        utoc_reports = []
        utoc_sources = [(root, n) for root in roots
                        for n in (root_flags.get(root) or {})
                        .get("utocs", [])]
        for src_zip, entry in utoc_sources[:3]:
            with zipfile.ZipFile(src_zip) as zf:
                cited = _raw_entry_name(zf, entry)
                try:
                    utoc_path = extract_entry(
                        zf, entry, work_dir, "utoc",
                        os.path.basename(entry))
                except ValueError as e:
                    utoc_reports.append(
                        {"error": str(e), "entry": cited})
                    continue
            data, err = run_json_tool("nar-unreal.py", [utoc_path])
            containers = (data or {}).get("iostore_containers") or []
            if containers:
                summary = dict(containers[0])
                summary.pop("entries", None)  # per-chunk detail is
                # one nar-unreal run away; counts/totals stay here
                summary["contained_in"] = os.path.basename(src_zip)
                summary["entry"] = cited
                utoc_reports.append(summary)
            else:
                utoc_reports.append({"error": err or "no container"
                                     " parsed", "entry": cited})
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
        try:
            run_2_0_stages(
                report, apk_for_steps, out_dir, work_dir,
                perms_data=perms, key_path=target,
                stage_target=target if resolved_target is not None
                else None,
                merged=resolved_target is not None)
        except _MemoryBudgetExceeded as e:
            # Named, resumable abort (3.0 Part 11): the
            # stages completed before the boundary are in
            # the case stage cache + companions; the case
            # record (written by main) carries the boundary
            # as resume_boundary, and a re-run of the same
            # --out directory without the budget (or with a
            # sufficient one) resumes from it.
            report["budget_abort"] = {
                "boundary": e.boundary,
                "stage": e.stage,
                "budget_mb": e.budget_mb,
                "peak_rss_bytes": e.peak_rss_bytes,
                "resumable": True,
                "resume": "re-run the same command and "
                          "--out directory without "
                          "--budget-mb (or with a higher "
                          "budget); completed stages are "
                          "served from the case stage cache"}
            report["limitations"].append(
                f"run aborted at {e.boundary}: memory "
                f"budget of {e.budget_mb} MB exceeded "
                f"(peak RSS {e.peak_rss_bytes} bytes); "
                "the case is resumable from this boundary "
                "via the stage cache")

    # Limitations and unknowns: the honest tail of every report.
    lim = report["limitations"]
    lim.append("Static analysis only: nothing was executed, so no"
               " runtime behavior, network traffic, or server-side"
               " verdict (for example Play Integrity's) is claimed.")
    _dec = report.get("decompile_summary") or {}
    if _dec:
        lim.append(
            "Decompilation served by "
            f"{_dec.get('served_by') or 'no rung'} at "
            f"{_dec.get('fidelity')} fidelity (fallback "
            "chain in decompile.json); decompiled output is "
            "an approximation, and a bytecode listing is "
            "not Java source.")
    else:
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
    dec = report.get("decompile") or \
        report.get("decompile_summary")
    if dec:
        lines += ["", "## Decompilation", ""]
        lines.append(f"- Served by: {dec.get('served_by')}")
        lines.append(f"- Fidelity: {dec.get('fidelity')}")
        lines.append("- Chain: "
                     + " -> ".join(dec.get("chain") or []))
        for a in dec.get("attempts") or []:
            if isinstance(a, dict):
                lines.append(
                    f"- Attempt {a.get('rung')}: "
                    f"{a.get('status')}"
                    + (f" ({a.get('classification')})"
                       if a.get("classification") else ""))
        lines.append("- Caveats:")
        for c in dec.get("caveats") or []:
            lines.append(f"  - {c}")
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
            if os.path.islink(full):
                # Never follow a symlink out of the case:
                # export would otherwise bundle (and the
                # manifest would bless) content that lives
                # outside the case directory (C-18).
                continue
            rel = os.path.relpath(full, case_dir)
            out.append((rel.replace(os.sep, "/"), full))
    return sorted(out)


def export_case(case_dir, bundle_path):
    """Export a case directory to a single portable bundle
    (zip) with a per-file SHA-256 manifest. Returns a
    summary dict. The manifest travels inside the bundle
    and lands in the imported case, where verify_case
    re-checks every file against it."""
    # Refuse non-cases (stability audit C-10): the
    # pre-audit form exported a nonexistent directory as
    # a "successful" 0-file bundle, and a bundle path
    # INSIDE the case directory made the export include
    # the bundle it was writing and then fail its own
    # verify.
    if not os.path.isdir(case_dir):
        raise ValueError(
            f"not a case directory: {case_dir}")
    case_json = os.path.join(case_dir, "case.json")
    if not os.path.isfile(case_json):
        raise ValueError(
            f"not a NAR case (case.json missing): {case_dir}")
    bundle_real = os.path.realpath(bundle_path)
    case_real = os.path.realpath(case_dir)
    if bundle_real == case_real or bundle_real.startswith(
            case_real + os.sep):
        raise ValueError(
            "bundle path must be outside the case "
            "directory (an in-case bundle would include "
            "itself)")
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
    # Extract + verify in a STAGING directory first; the
    # destination is touched only after the imported
    # case verifies (stability audit C-03). The pre-audit
    # form extracted straight into out_dir, so a bundle
    # that failed verification had already overwritten
    # the destination's files with unverified content.
    parent = os.path.dirname(os.path.abspath(out_dir)) \
        or "."
    os.makedirs(parent, exist_ok=True)
    staging = tempfile.mkdtemp(prefix=".nar-import-",
                               dir=parent)
    try:
        report = _safearchive.safe_extract(bundle_path,
                                           staging)
        if report["rejected"]:
            reasons = "; ".join(
                f"{r['entry']}: {r['reason']}"
                for r in report["rejected"][:10])
            raise ValueError(
                f"unsafe entries in bundle: {reasons}")
        result = verify_case(staging)
        if result.get("ok") is False:
            raise ValueError(
                "imported case failed verification ("
                + "; ".join(result.get("failures", [])[:5])
                + "); destination left untouched")
        # Files the bundle carried that its manifest does
        # not list (C-07): surfaced, never silent.
        try:
            with zipfile.ZipFile(bundle_path) as zf:
                manifest = json.loads(
                    zf.read(BUNDLE_MANIFEST))
            listed = {f.get("path")
                      for f in manifest.get("files", [])}
        except (ValueError, KeyError):
            listed = set()
        extracted_names = [
            e.get("entry") if isinstance(e, dict) else e
            for e in report["extracted"]]
        extra = sorted(
            e for e in extracted_names
            if e not in listed and e != BUNDLE_MANIFEST)
        if os.path.isdir(out_dir) and os.listdir(out_dir):
            shutil.rmtree(out_dir)
        elif os.path.isdir(out_dir):
            os.rmdir(out_dir)
        os.rename(staging, out_dir)
        staging = None
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
    result["imported_to"] = os.path.abspath(out_dir)
    result["files_imported"] = len(report["extracted"])
    if extra:
        result["files_not_in_manifest"] = extra
    return result


# ----------------------------------------------------------------
# Evidence & case integrity (2.6.2, Workstream F).
#
# verify_case historically checked the input hash, the
# bundle manifest and the stage-cache keys. The checks
# below add the evidence layer the 2.6.1 verification
# round ran EXTERNALLY over produced cases (report §3,
# 19 programmatic checks) as ENFORCED validation inside
# `nar case verify`: evidence references resolve, graph
# structure is internally consistent, counts reconcile,
# hypotheses are complete, companions listed by the
# report are present and schema-valid, and companion
# version fields agree with the case record.
#
# Hard-failure vs warning policy (backward compatibility
# is a hard constraint: cases produced by 2.6.0 / 2.6.1
# must still verify):
#
# HARD FAILURES in every era — invariants the pipeline
# has never legitimately broken: duplicate node / edge
# identifiers, graph edges pointing at missing nodes,
# header counts that disagree with the arrays they
# count, a companion the report lists but the case does
# not contain, a companion that fails its repo schema,
# and a companion version field that disagrees with the
# case's recorded NAR version (one run writes one case
# at one version; disagreement means a stale or mixed
# copy, not a legacy case).
#
# WARNINGS (reported, never failing verify) for the two
# defect families a pre-2.6.1 case can LEGITIMATELY
# carry, both documented in the 2.6.1 report itself:
# (a) evidence references citing a document or field
# path that does not resolve — §4 records that 2.6.0
# cases cite permissions.json, which that pipeline
# never wrote, and §2 item 4 records the pre-fix
# application-node citation; failing every archived
# 2.6.0 case for the pipeline's own known defect would
# make verify useless on the existing archive, while a
# case recorded at 2.6.1+ was produced by a pipeline
# proven to write every cited document (§3), so the
# same finding there is a hard failure; (b) a
# pre-2.6.1 investigation without the
# unverified_findings section (the 2.6.1 separation)
# and hypothesis-field gaps in such a legacy document.
# A counts block that is ABSENT (rather than wrong) is
# likewise a warning: there is nothing to reconcile,
# and absence is a legacy shape, not tampering.
# ----------------------------------------------------------------

_COMPANION_SCHEMAS = {
    "graph.json": "graph.schema.json",
    "investigation.json": "investigation.schema.json",
    "correlations.json": "correlations.schema.json",
    "application.json": "application.schema.json",
    "manifest.json": "manifest.schema.json",
    "native-inventory.json": "native-inventory.schema.json",
    "frameworks.json": "frameworks.schema.json",
    "network-analysis.json": "network-analysis.schema.json",
    "api-architecture.json": "api-architecture.schema.json",
    "fingerprint.json": "fingerprint.schema.json",
    "engines.json": "engine.schema.json",
    "dex.json": "dex.schema.json",
    "app.json": "app.schema.json",
    "decompile.json": "decompile.schema.json",
    "native.json": "native.schema.json",
    "endpoints.json": "endpoints.schema.json",
    "security-findings.json": "security-findings.schema.json",
    "assets.json": "assets.schema.json",
    "case.json": "case.schema.json",
    "execution-log.json": "execution-log.schema.json",
    "permissions.json": "permissions.schema.json",
}


def _version_tuple(value):
    if not isinstance(value, str):
        return None
    parts = []
    for piece in value.strip().split("."):
        if not piece.isdigit():
            return None
        parts.append(int(piece))
    return tuple(parts) or None


def _version_lt(value, floor):
    """True when dotted-numeric version `value` is below
    `floor`. Unparseable values are NOT less (strictness
    is the default; legacy treatment must be earned by a
    parseable old version)."""
    vt, ft = _version_tuple(value), _version_tuple(floor)
    if vt is None or ft is None:
        return False
    width = max(len(vt), len(ft))
    return vt + (0,) * (width - len(vt)) < \
        ft + (0,) * (width - len(ft))


def _resolve_evidence_path(document, field_path):
    """Resolve an evidence field path inside a document.

    Grammar (the one the builders actually emit — see
    narlib.graph / narlib.investigation): dot-separated
    dictionary keys, each optionally followed by one or
    more [integer] list indexes, e.g.
    "properties.package", "permissions[3].name",
    "components.activity-alias[0].name" (component keys
    are manifest tag names verbatim and CAN contain
    hyphens — a narrower tokenizer was the 2.6.1
    checker-side defect recorded in report §3),
    "dex_files[0].classes[2].class",
    "engines.unreal_packages[0].relationships.edges[1]".
    A key is any run of characters other than '.' and
    '['; resolution requires the key to EXIST (a present
    key with a null value still resolves)."""
    if not isinstance(field_path, str) or not field_path:
        return False
    cur = document
    i, n = 0, len(field_path)
    while i < n:
        start = i
        while i < n and field_path[i] not in ".[":
            i += 1
        key = field_path[start:i]
        if not key or not isinstance(cur, dict) \
                or key not in cur:
            return False
        cur = cur[key]
        while i < n and field_path[i] == "[":
            end = field_path.find("]", i)
            if end < 0:
                return False
            token = field_path[i + 1:end]
            if not token.isdigit():
                return False
            idx = int(token)
            if not isinstance(cur, list) or idx >= len(cur):
                return False
            cur = cur[idx]
            i = end + 1
        if i < n:
            if field_path[i] != ".":
                return False
            i += 1
            if i >= n:
                return False
    return True


def _hypothesis_field_problems(hyp):
    """Ways an investigation hypothesis is incomplete:
    it must carry a basis evidence reference plus
    non-empty confirm and refute criteria (the same
    gate narlib.investigation enforces at build time)."""
    if not isinstance(hyp, dict):
        return ["not an object"]
    problems = []
    basis = hyp.get("basis")
    if not isinstance(basis, dict) or not all(
            str(basis.get(k) or "").strip()
            for k in ("stage", "document", "field_path")):
        problems.append(
            "missing basis evidence reference "
            "(stage/document/field_path)")
    if not str(hyp.get("confirm") or "").strip():
        problems.append("missing confirm criterion")
    if not str(hyp.get("refute") or "").strip():
        problems.append("missing refute criterion")
    return problems


def _verify_evidence_integrity(case_dir, case_doc):
    """The evidence-integrity section of verify_case:
    structured per-check results over graph.json /
    investigation.json / correlations.json (when present)
    plus the report's companion list. Returns
    {ok, checks, failures, warnings, notes} where each
    check is {check, status: pass|fail|warning, detail}.
    Only "fail" checks land in failures (and therefore
    in verify's exit code); "warning" checks are the
    documented legacy tolerances above."""
    checks, failures, warnings, notes = [], [], [], []

    def record(name, status, detail=""):
        checks.append({"check": name, "status": status,
                       "detail": detail})
        if status == "fail":
            failures.append(f"{name}: {detail}")
        elif status == "warning":
            warnings.append(f"{name}: {detail}")

    case_version = (case_doc or {}).get("nar_version")
    legacy_case = _version_lt(case_version, "2.6.1")
    # Severity for evidence-reference and legacy-shape
    # findings (see the policy block above).
    ref_status = "warning" if legacy_case else "fail"

    cache = {}

    def present(name):
        return os.path.isfile(os.path.join(case_dir, name))

    def load(name):
        if name not in cache:
            doc = None
            if present(name):
                try:
                    with open(os.path.join(case_dir, name),
                              encoding="utf-8") as fh:
                        doc = json.load(fh)
                except (OSError, ValueError):
                    doc = None
            cache[name] = doc
        return cache[name]

    # ---- report + companion list -------------------------
    report_doc = load("report.json")
    if present("report.json") and report_doc is None:
        record("report.json parses", "fail",
               "report.json is not valid JSON")
    companions = {}
    if isinstance(report_doc, dict) and isinstance(
            report_doc.get("companions"), dict):
        companions = report_doc["companions"]
    listed = {}
    for key, entry in companions.items():
        if isinstance(entry, dict) and entry.get("file"):
            listed[entry["file"]] = key
    if listed:
        missing = [f for f in sorted(listed)
                   if not present(f)]
        record(
            "companion files listed in report.json present",
            "fail" if missing else "pass",
            "missing from case: " + ", ".join(missing)
            if missing else
            f"{len(listed)} listed companions present")
    elif present("report.json"):
        notes.append("report.json lists no companions; "
                     "companion-presence check not applicable")

    # ---- schema validity + version fields ----------------
    targets = set(listed)
    for name in ("graph.json", "investigation.json",
                 "correlations.json"):
        if present(name):
            targets.add(name)
    inv_doc = load("investigation.json") \
        if present("investigation.json") else None
    inv_legacy = isinstance(inv_doc, dict) and \
        "unverified_findings" not in inv_doc and \
        (_version_lt(inv_doc.get("version"), "2.6.1")
         or legacy_case)
    if targets:
        schema_dir = os.path.join(
            os.path.dirname(HERE), "schemas")
        schema_bad = []
        for fname in sorted(targets):
            schema_name = _COMPANION_SCHEMAS.get(fname)
            if present(fname) and load(fname) is None:
                schema_bad.append(
                    f"{fname}: not valid JSON")
                continue
            if not schema_name or _evidence is None:
                continue
            doc = load(fname)
            if not isinstance(doc, (dict, list)):
                continue
            try:
                with open(os.path.join(schema_dir, schema_name),
                          encoding="utf-8") as fh:
                    schema = json.load(fh)
            except (OSError, ValueError) as e:
                schema_bad.append(
                    f"{fname}: schema unavailable: {e}")
                continue
            candidate = doc
            if fname == "investigation.json" and inv_legacy:
                # Validate the legacy shape on its own
                # terms: inject the section the 2.6.1
                # separation added, so the ONLY tolerated
                # schema gap is that section's absence.
                candidate = dict(doc)
                candidate["unverified_findings"] = []
            if fname == "endpoints.json" and isinstance(
                    doc, dict) and _version_lt(
                    case_version, "2.6.2"):
                # Era mapping (stability audit S-02): the
                # endpoint classification 'confirmed' was
                # renamed 'dex-string' in 2.6.2 (a
                # calibration correction — a string
                # reference was never confirmation of
                # traffic). Cases written before the
                # rename carry the old label legitimately;
                # validate them under the mapping, the
                # same era discipline as inv_legacy above,
                # instead of hard-failing every archived
                # case on the pipeline's own rename.
                eps = doc.get("endpoints")
                if isinstance(eps, list) and any(
                        isinstance(e, dict) and
                        e.get("classification") == "confirmed"
                        for e in eps):
                    candidate = dict(doc)
                    candidate["endpoints"] = [
                        {**e, "classification": "dex-string"}
                        if isinstance(e, dict) and e.get(
                            "classification") == "confirmed"
                        else e for e in eps]
                    notes.append(
                        "endpoints.json carries the "
                        "pre-2.6.2 'confirmed' endpoint "
                        "label; validated under the era "
                        "mapping to 'dex-string' (the "
                        "2.6.2 calibration rename)")
            errs = _evidence.validate(candidate, schema)
            if fname == "investigation.json" and inv_legacy:
                # Hypothesis-field gaps in a legacy
                # document are reported (as warnings) by
                # the dedicated hypothesis check below;
                # the schema layer must not re-report
                # them as hard failures.
                errs = [e for e in errs if not (
                    "$.hypotheses" in e
                    and "missing required" in e
                    and any(k in e for k in
                            ("basis", "confirm", "refute")))]
            if errs:
                schema_bad.append(
                    f"{fname}: {errs[0]}"
                    + (f" (+{len(errs) - 1} more)"
                       if len(errs) > 1 else ""))
        record(
            "companion schema validity",
            "fail" if schema_bad else "pass",
            "; ".join(schema_bad[:5]) if schema_bad else
            "listed/present companions validate against "
            "the repo schemas")
        version_bad = []
        version_seen = 0
        for fname in sorted(targets):
            doc = load(fname)
            if not isinstance(doc, dict) \
                    or "version" not in doc:
                continue
            version_seen += 1
            value = doc.get("version")
            if not isinstance(value, str) or not value.strip():
                version_bad.append(
                    f"{fname}: version field is not a "
                    "non-empty string")
            elif case_version and value != case_version:
                version_bad.append(
                    f"{fname}: version {value} does not "
                    f"match case nar_version {case_version} "
                    "(stale or mixed-version companion)")
        if version_seen:
            record(
                "companion version fields match the case "
                "record",
                "fail" if version_bad else "pass",
                "; ".join(version_bad[:5]) if version_bad
                else f"{version_seen} version fields agree "
                     f"with nar_version {case_version}")
    if inv_legacy:
        record(
            "investigation legacy sections", "warning",
            "pre-2.6.1 investigation without an "
            "unverified_findings section; accepted as a "
            "legacy case (the section was added by the "
            "2.6.1 fact separation)")

    # ---- graph structure ---------------------------------
    graph_doc = load("graph.json") \
        if present("graph.json") else None
    if present("graph.json") and graph_doc is None:
        record("graph.json parses", "fail",
               "graph.json is not valid JSON")
    refs = []  # (owner description, evidence dict)

    def collect_refs(owner, record):
        if not isinstance(record, dict):
            return
        for slot in ("evidence", "basis",
                     "triggering_evidence"):
            ev = record.get(slot)
            if isinstance(ev, dict):
                refs.append((owner, ev))
        for ev in record.get("evidence_also") or []:
            if isinstance(ev, dict):
                refs.append((owner, ev))

    if isinstance(graph_doc, dict):
        nodes = [n for n in graph_doc.get("nodes") or []
                 if isinstance(n, dict)]
        edges = [e for e in graph_doc.get("edges") or []
                 if isinstance(e, dict)]
        ids = [n.get("id") for n in nodes]
        dup_nodes = sorted({i for i in ids
                            if ids.count(i) > 1})
        record(
            "graph node identifiers are unique",
            "fail" if dup_nodes else "pass",
            "duplicate node ids: " + ", ".join(
                str(d) for d in dup_nodes[:5])
            if dup_nodes else
            f"{len(ids)} node ids unique")
        edge_keys = [(e.get("source"), e.get("target"),
                      e.get("kind"), e.get("status"))
                     for e in edges]
        dup_edges = sorted(
            {k for k in edge_keys if edge_keys.count(k) > 1},
            key=str)
        record(
            "graph edge identifiers are unique",
            "fail" if dup_edges else "pass",
            "duplicate edges (source, target, kind, "
            "status): " + "; ".join(
                str(d) for d in dup_edges[:5])
            if dup_edges else
            f"{len(edge_keys)} edge identities unique")
        node_set = set(ids)
        orphans = [e for e in edges
                   if e.get("source") not in node_set
                   or e.get("target") not in node_set]
        orphan_detail = "; ".join(
            f"{e.get('source')} -> {e.get('target')} "
            f"({e.get('kind')})" for e in orphans[:5])
        record(
            "graph edge endpoints exist as nodes",
            "fail" if orphans else "pass",
            f"{len(orphans)} edge endpoints reference "
            f"missing nodes: {orphan_detail}"
            if orphans else
            f"all {len(edges)} edges join existing nodes")
        record(
            "graph orphaned relationships",
            "fail" if orphans else "pass",
            f"{len(orphans)} orphaned relationships "
            f"(edges referencing missing nodes): "
            f"{orphan_detail}" if orphans else
            "no orphaned relationships")
        counts = graph_doc.get("counts")
        if isinstance(counts, dict):
            problems = []
            if counts.get("nodes") != len(nodes):
                problems.append(
                    f"counts.nodes is {counts.get('nodes')} "
                    f"but the nodes array has {len(nodes)}")
            if counts.get("edges") != len(edges):
                problems.append(
                    f"counts.edges is {counts.get('edges')} "
                    f"but the edges array has {len(edges)}")
            for label, key, items in (
                    ("nodes_by_kind", "kind", nodes),
                    ("edges_by_kind", "kind", edges)):
                recorded = counts.get(label)
                if isinstance(recorded, dict):
                    actual = {}
                    for item in items:
                        actual[item.get(key)] = \
                            actual.get(item.get(key), 0) + 1
                    for kind in sorted(
                            set(recorded) | set(actual),
                            key=str):
                        if recorded.get(kind) != \
                                actual.get(kind):
                            problems.append(
                                f"counts.{label}[{kind}] is "
                                f"{recorded.get(kind)} but "
                                f"the array has "
                                f"{actual.get(kind)}")
            record(
                "graph counts reconcile with the arrays",
                "fail" if problems else "pass",
                "; ".join(problems[:5]) if problems else
                "header counts match the node/edge arrays")
        else:
            record(
                "graph counts reconcile with the arrays",
                "warning",
                "graph.json carries no counts block; "
                "nothing to reconcile (legacy shape)")
        for node in nodes:
            collect_refs(
                f"graph.json node {node.get('id')}", node)
        for edge in edges:
            collect_refs(
                f"graph.json edge {edge.get('source')} -> "
                f"{edge.get('target')} ({edge.get('kind')})",
                edge)

    # ---- investigation structure --------------------------
    if present("investigation.json") and inv_doc is None:
        record("investigation.json parses", "fail",
               "investigation.json is not valid JSON")
    if isinstance(inv_doc, dict):
        counts = inv_doc.get("counts")
        if isinstance(counts, dict):
            problems = []
            for section in ("verified_facts",
                            "unverified_findings", "paths",
                            "hypotheses", "unknowns"):
                if section not in counts:
                    continue
                if section not in inv_doc:
                    if section == "unverified_findings" \
                            and inv_legacy:
                        continue
                    problems.append(
                        f"counts.{section} is recorded but "
                        f"the section is absent")
                elif counts.get(section) != \
                        len(inv_doc.get(section) or []):
                    problems.append(
                        f"counts.{section} is "
                        f"{counts.get(section)} but the "
                        f"section has "
                        f"{len(inv_doc.get(section) or [])}")
            record(
                "investigation counts reconcile",
                "fail" if problems else "pass",
                "; ".join(problems[:5]) if problems else
                "counts match the section arrays")
        else:
            record(
                "investigation counts reconcile", "warning",
                "investigation.json carries no counts "
                "block; nothing to reconcile (legacy shape)")
        hyp_bad = []
        for i, hyp in enumerate(
                inv_doc.get("hypotheses") or []):
            problems = _hypothesis_field_problems(hyp)
            if problems:
                ident = hyp.get("id") if isinstance(
                    hyp, dict) else None
                name = ident or f"hypotheses[{i}]"
                subject = hyp.get("subject") \
                    if isinstance(hyp, dict) else None
                hyp_bad.append(
                    f"{name} (subject={subject!r}): "
                    + "; ".join(problems))
        record(
            "investigation hypotheses carry basis + "
            "confirm + refute",
            ("fail" if hyp_bad and not inv_legacy else
             "warning" if hyp_bad else "pass"),
            "; ".join(hyp_bad[:5]) if hyp_bad else
            f"{len(inv_doc.get('hypotheses') or [])} "
            "hypotheses complete")
        for section in ("verified_facts",
                        "unverified_findings"):
            for item in inv_doc.get(section) or []:
                collect_refs(
                    f"investigation.json {section} item "
                    f"(subject="
                    f"{item.get('subject')!r})"
                    if isinstance(item, dict) else
                    f"investigation.json {section} item",
                    item)
        for item in inv_doc.get("paths") or []:
            collect_refs(
                f"investigation.json path "
                f"{item.get('rule_id') if isinstance(item, dict) else '?'}",
                item)
        for i, hyp in enumerate(
                inv_doc.get("hypotheses") or []):
            collect_refs(
                f"investigation.json hypotheses[{i}]", hyp)
        for item in inv_doc.get("unknowns") or []:
            collect_refs(
                "investigation.json unknown", item)

    # ---- correlations counts -------------------------------
    corr_doc = load("correlations.json") \
        if present("correlations.json") else None
    if present("correlations.json") and corr_doc is None:
        record("correlations.json parses", "fail",
               "correlations.json is not valid JSON")
    if isinstance(corr_doc, dict):
        counts = corr_doc.get("counts")
        mapping = {
            "jni_matched": ("jni_bindings", "matched"),
            "jni_declaration_only":
                ("jni_bindings", "declaration-only"),
            "jni_export_only": ("jni_bindings", "export-only"),
            "components_matched": ("components", "matched"),
            "components_declaration_only":
                ("components", "declaration-only"),
            "components_implementation_only":
                ("components", "implementation-only"),
            "endpoints_code_referenced":
                ("endpoints", "code-referenced"),
            "endpoints_no_code_reference":
                ("endpoints", "no-code-reference"),
            "network_libraries_matched":
                ("network_libraries", "matched"),
            "network_libraries_only":
                ("network_libraries", "library-only"),
        }
        if isinstance(counts, dict):
            problems = []
            for key, (section, status) in mapping.items():
                if key not in counts:
                    continue
                actual = sum(
                    1 for e in corr_doc.get(section) or []
                    if isinstance(e, dict)
                    and e.get("status") == status)
                if counts.get(key) != actual:
                    problems.append(
                        f"counts.{key} is {counts.get(key)} "
                        f"but {actual} {section} entries "
                        f"have status {status}")
            record(
                "correlations counts reconcile",
                "fail" if problems else "pass",
                "; ".join(problems[:5]) if problems else
                "counts match the correlation arrays")
        else:
            record(
                "correlations counts reconcile", "warning",
                "correlations.json carries no counts "
                "block; nothing to reconcile (legacy shape)")

    # ---- evidence reference resolution ---------------------
    if refs:
        doc_bad, path_bad = [], []
        for owner, ev in refs:
            doc_name = ev.get("document")
            field_path = ev.get("field_path")
            if not doc_name or not isinstance(
                    field_path, str):
                doc_bad.append(
                    f"{owner}: malformed evidence "
                    f"reference (document={doc_name!r}, "
                    f"field_path={field_path!r})")
                continue
            if not present(doc_name):
                doc_bad.append(
                    f"{owner}: cited document {doc_name} "
                    "is missing from the case")
                continue
            target = load(doc_name)
            if target is None:
                doc_bad.append(
                    f"{owner}: cited document {doc_name} "
                    "is not valid JSON")
            elif not _resolve_evidence_path(
                    target, field_path):
                path_bad.append(
                    f"{owner}: field path {field_path} "
                    f"does not resolve in {doc_name}")
        record(
            "evidence references name documents present "
            "in the case",
            ref_status if doc_bad else "pass",
            "; ".join(doc_bad[:5]) if doc_bad else
            f"{len(refs)} evidence references cite "
            "existing documents")
        record(
            "evidence field paths resolve in their "
            "documents",
            ref_status if path_bad else "pass",
            "; ".join(path_bad[:5]) if path_bad else
            f"{len(refs)} evidence field paths resolve")
    elif not present("graph.json") and not present(
            "investigation.json"):
        notes.append(
            "no graph.json / investigation.json in this "
            "case; evidence-integrity checks not "
            "applicable")

    return {"ok": not failures, "checks": checks,
            "failures": failures, "warnings": warnings,
            "notes": notes}


def verify_case(case_dir):
    """Verify a case directory's integrity: the recorded
    input hash (re-checked when the input file is still at
    its recorded path), the bundle manifest when present
    (every file's hash + size), and the stage-cache
    integrity keys (recomputed from the case's recorded
    input hash + its recorded NAR version + stage name),
    plus the evidence-integrity section (2.6.2,
    Workstream F): companion presence/schema/version
    against the report's companion list, graph structure,
    count reconciliation, hypothesis completeness, and
    evidence-reference resolution over graph.json /
    investigation.json / correlations.json when present.
    Returns {ok, checks, failures, notes, warnings,
    evidence_integrity} — a check that cannot run is a
    note, never a silent pass; warnings never affect ok
    (see the hard-failure vs warning policy above
    _verify_evidence_integrity)."""
    checks, failures, notes, warnings = [], [], [], []

    def check(name, ok, detail=""):
        checks.append({"check": name, "ok": bool(ok),
                       "detail": detail})
        if not ok:
            failures.append(f"{name}: {detail}")

    empty_section = {
        "ok": False, "checks": [], "failures": [],
        "warnings": [],
        "notes": ["evidence-integrity checks could not "
                  "run: no readable case.json"]}
    case_json = os.path.join(case_dir, "case.json")
    if not os.path.isfile(case_json):
        check("case.json present", False, "case.json missing")
        return {"ok": False, "checks": checks,
                "failures": failures, "notes": notes,
                "warnings": warnings,
                "evidence_integrity": empty_section}
    check("case.json present", True)
    try:
        with open(case_json, encoding="utf-8") as fh:
            case_doc = json.load(fh)
    except ValueError as e:
        check("case.json parses", False,
              f"case.json is not valid JSON: {e}")
        return {"ok": False, "checks": checks,
                "failures": failures, "notes": notes,
                "warnings": warnings,
                "evidence_integrity": empty_section}
    if not isinstance(case_doc, dict):
        # A case record that parses but is not an object
        # is a FAILED verification, not a traceback
        # (stability audit C-08 — verify itself crashed
        # on malformed case/manifest shapes).
        check("case.json parses", False,
              "case.json is not a JSON object")
        return {"ok": False, "checks": checks,
                "failures": failures, "notes": notes,
                "warnings": warnings,
                "evidence_integrity": empty_section}
    inp = case_doc.get("input") or {}
    if not isinstance(inp, dict):
        inp = {}
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
        try:
            with open(manifest_path, encoding="utf-8") as fh:
                manifest = json.load(fh)
            if not isinstance(manifest, dict):
                raise ValueError("manifest is not an object")
        except ValueError as e:
            check("bundle manifest parses", False, str(e))
            manifest = None
        if manifest is not None:
            check("bundle input hash matches case record",
                  manifest.get("input_sha256") == input_sha)
            bad = []
            listed_paths = set()
            entries = manifest.get("files", [])
            if not isinstance(entries, list):
                entries = []
                bad.append("manifest files is not a list")
            for entry in entries:
                if not isinstance(entry, dict) or \
                        not entry.get("path"):
                    bad.append("manifest entry without a "
                               "path")
                    continue
                listed_paths.add(entry["path"])
                try:
                    full = _contained_join(case_dir,
                                           entry["path"])
                except ValueError:
                    # A manifest path is data, not a
                    # trusted route: it must stay inside
                    # the case directory (C-18).
                    bad.append(
                        f"{entry['path']} escapes the case "
                        "directory")
                    continue
                if not os.path.isfile(full):
                    bad.append(f"{entry['path']} missing")
                elif sha256_of(full) != entry.get(
                        "sha256") or os.path.getsize(
                        full) != entry.get("size_bytes"):
                    bad.append(
                        f"{entry['path']} hash/size mismatch")
            check("bundle manifest: every file intact",
                  not bad,
                  "; ".join(bad[:5]) if bad else
                  f"{len(entries)} files verified")
            # Files present but NOT in the manifest were
            # previously invisible to verify (C-07: the
            # manifest check was one-directional). They
            # are a warning, not a failure — a case dir
            # can legitimately gain notes — but they are
            # never silent.
            on_disk = {rel for rel, _full in
                       _case_files(case_dir)}
            extra = sorted(on_disk - listed_paths
                           - {BUNDLE_MANIFEST})
            if extra:
                warnings.append(
                    "files present in the case but not "
                    "listed in the bundle manifest: "
                    + ", ".join(extra[:10])
                    + (" …" if len(extra) > 10 else ""))
    else:
        notes.append("no bundle manifest in this case "
                     "(not an imported bundle); manifest "
                     "checks not applicable")
    cache_dir = os.path.join(case_dir, "cache")
    if os.path.isdir(cache_dir) and input_sha:
        case_version = case_doc.get("nar_version") or NAR_VERSION
        # Legacy container era (stability audit S-01):
        # before the fix, stage cache keys for CONTAINER
        # targets (xapk/apks/aab) were derived from the
        # EXTRACTED base APK's hash, which the case does
        # not record. Those keys cannot be recomputed
        # from case data — a mismatch in that era proves
        # nothing either way, so it is a warning with the
        # reason stated, never a hard failure and never
        # silently passed. Unparsable cache JSON remains
        # a hard failure in every era.
        input_ext = os.path.splitext(
            (inp.get("path") or ""))[1].lower()
        legacy_container = _version_lt(
            case_version, "2.6.2") and input_ext in (
                ".xapk", ".apks", ".aab")
        bad = []
        legacy_key_notes = []
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
            # Era variants are derived from the case's own
            # record, the same discipline as the legacy
            # tolerances above: a merged-container case
            # (case.json carries the container block) binds
            # "|container-merged" into every stage key, and
            # a case recorded with dex_format "full" (3.0
            # Part 11) binds "|dex-full" into the dex
            # stage's key. Any of the recorded variants is
            # a valid key for its stage.
            key_bases = [f"{input_sha}|{case_version}"]
            if isinstance(case_doc.get("container"), dict):
                key_bases.append(
                    key_bases[0] + "|container-merged")
            expected_set = {
                hashlib.sha256(
                    f"{base}|{stage}".encode()).hexdigest()
                for base in key_bases}
            if stage == "dex" and (
                    (case_doc.get("config") or {})
                    .get("dex_format") == "full"):
                expected_set |= {
                    hashlib.sha256(
                        f"{base}|dex-full|{stage}".encode()
                    ).hexdigest()
                    for base in key_bases}
            checked += 1
            if recorded not in expected_set:
                if legacy_container:
                    legacy_key_notes.append(stage)
                else:
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
        if legacy_key_notes:
            warnings.append(
                "stage cache keys not recomputed for "
                + ", ".join(sorted(legacy_key_notes))
                + ": this pre-2.6.2 container case derived"
                " its keys from the extracted base APK's"
                " hash, which the case does not record"
                " (S-01); the keys are unverifiable from"
                " case data, neither passed nor failed")
    stages = case_doc.get("stages") or {}
    if not isinstance(stages, dict):
        stages = {}
    failed = [s for s, v in stages.items()
              if not isinstance(v, dict)
              or v.get("status") not in ("ok", "cached")]
    if failed:
        notes.append("stages recorded as not-ok in this "
                     f"case: {', '.join(sorted(failed))} "
                     "(integrity is unaffected; the case "
                     "records its own degraded stages)")
    section = _verify_evidence_integrity(case_dir, case_doc)
    for entry in section["checks"]:
        checks.append({
            "check": entry["check"],
            "ok": entry["status"] != "fail",
            "detail": entry["detail"],
            "status": entry["status"]})
    failures.extend(section["failures"])
    warnings.extend(section["warnings"])
    notes.extend(section["notes"])
    return {"ok": not failures, "checks": checks,
            "failures": failures, "notes": notes,
            "warnings": warnings,
            "evidence_integrity": section}


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
    p.add_argument("--budget-mb", type=float, metavar="MB",
                   help="peak-RSS budget in MiB for the whole "
                        "run (3.0 Part 11): crossing it aborts "
                        "the run at the named, resumable "
                        "boundary memory-budget:<stage>, "
                        "recorded in the case + execution log; "
                        "re-running the same --out directory "
                        "without the budget resumes from the "
                        "stage cache")
    p.add_argument("--dex-full", action="store_true",
                   help="write dex.json in the full 2.6.2 "
                        "shape instead of the compact 3.0 "
                        "shape (nar-dex --full; the shape is "
                        "recorded in case.json and bound into "
                        "the dex stage cache key)")
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
    p.add_argument("--no-merge-splits", action="store_true",
                   help="analyse only the base APK of a "
                        "container (pre-3.0 behaviour, "
                        "byte-identical output)")
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
            try:
                doc = _graph.query_graph(
                    doc, kind=args.kind,
                    edge_kind=args.edge_kind,
                    min_confidence=min_conf, text=args.text)
            except ValueError as e:
                # An unknown --min-confidence level name is
                # a usage error (exit 2), not a traceback
                # (C-18 companion to the graph.py fix).
                print(f"nar-analyze: {e}", file=sys.stderr)
                return 2
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
            try:
                summary = export_case(args.export, args.bundle)
            except (ValueError, OSError) as e:
                print(f"nar-analyze: export failed: {e}",
                      file=sys.stderr)
                return 1
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
                mark = "FAIL" if not c["ok"] else \
                    "warn" if c.get("status") == "warning" \
                    else "ok"
                print(f"  [{mark}] "
                      f"{c['check']} {c['detail']}")
            for w in result.get("warnings", []):
                print(f"  warning: {w}")
            for n in result["notes"]:
                print(f"  note: {n}")
        return 0 if result["ok"] else 1
    if not args.target:
        p.error("a target file is required (or use --export / "
                "--import / --verify)")
    set_budgets(args.stage_timeout, args.total_budget,
                budget_mb=args.budget_mb)
    set_dex_full(args.dex_full)
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
        report = analyze(args.target, work_dir, out_dir,
                         merge_splits=not args.no_merge_splits)
    except FileNotFoundError as e:
        print(f"nar-analyze: {e}", file=sys.stderr)
        return 2
    except _MemoryBudgetExceeded as e:
        # The budget was crossed before the stage section
        # (doctor / triage / engine deep dives): the abort
        # is still recorded as a resumable case state —
        # a minimal report carrying the named boundary —
        # never a traceback (3.0 Part 11).
        report = {
            "tool": "nar-analyze", "version": NAR_VERSION,
            "nar_version": NAR_VERSION,
            "target": os.path.abspath(args.target),
            "target_name": os.path.basename(args.target),
            "target_sha256": sha256_of(args.target),
            "target_size_bytes": os.path.getsize(args.target),
            "limitations": [
                f"run aborted at {e.boundary}: memory "
                f"budget of {e.budget_mb} MB exceeded "
                f"(peak RSS {e.peak_rss_bytes} bytes); "
                "the case is resumable from this boundary "
                "via the stage cache"],
            "budget_abort": {
                "boundary": e.boundary, "stage": e.stage,
                "budget_mb": e.budget_mb,
                "peak_rss_bytes": e.peak_rss_bytes,
                "resumable": True,
                "resume": "re-run the same command and "
                          "--out directory without "
                          "--budget-mb (or with a higher "
                          "budget); completed stages are "
                          "served from the case stage cache"},
        }
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, "report.json")
    md_path = os.path.join(out_dir, "report.md")
    _write_report_json(json_path, report)
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
                   "budgets": _budget_snapshot(),
                   "dex_format": ("full" if DEX_FULL["enabled"]
                                  else "compact")},
        "tool_versions": {"nar": NAR_VERSION,
                          "python": sys.version.split()[0]},
        "stages": stages,
    }
    if report.get("budget_abort"):
        # The named, resumable boundary (3.0 Part 11): a
        # later run of the same --out directory resumes
        # from the stage cache past this boundary.
        case_doc["resume_boundary"] = report["budget_abort"]
    if report.get("container"):
        # Split-merge provenance lands in case.json (3.0
        # Part 2): which splits were merged into the case's
        # stages and which were skipped, with reasons.
        case_doc["container"] = report["container"]
    _write_report_json(
        os.path.join(out_dir, "case.json"), case_doc)
    exec_doc = {"tool": "nar-analyze", "case_id": case_id,
                "input_sha256": report.get("target_sha256"),
                "entries": EXEC_LOG}
    _write_report_json(
        os.path.join(out_dir, "execution-log.json"), exec_doc)
    _write_report_json(json_path, report)
    if report.get("budget_abort"):
        abort = report["budget_abort"]
        print(f"nar-analyze: aborted at {abort['boundary']} "
              f"(memory budget {abort['budget_mb']} MB, "
              f"peak RSS {abort['peak_rss_bytes']} bytes); "
              f"case state recorded in {out_dir} — re-run "
              "without --budget-mb to resume from the "
              "stage cache", file=sys.stderr)
        return 1
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
