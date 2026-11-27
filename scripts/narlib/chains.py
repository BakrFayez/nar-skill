"""narlib.chains: fallback chains + the decompilation
chain (Part 10.5).

Every capability declares an ordered fallback chain. The
runner tries each rung once (plus at most one bounded
self-repair retry for OOM / TIMEOUT, brief 10.5.5), records
every attempt with its FailureKind classification and
duration, and returns the Fallback Record in exactly the
brief 10.5.0 shape::

    {capability, chain[], attempts[{rung, status, reason,
     duration_s, ...}], served_by, fidelity, caveats[]}

Fidelity ladder (high to low): source-equivalent >
source-approximate > bytecode-listing > structural-summary
> identified-only. A lower-fidelity result is never
presented as higher: the record's fidelity is the serving
rung's declared fidelity (or lower when the rung itself
reports lower).

The runner never downloads, installs, or reconfigures
anything. A rung that fails with INSTALLED_WONT_START is
abandoned with no retry (the adapters probe real start
before any long run, so it costs a probe, not a timeout).

CHAIN_REGISTRY declares every capability's chain with only
the rungs that genuinely exist today (a tool is a rung
only when the tool registry carries it as integrated, or
the rung is one of NAR's own parsers / a named floor).
It is plain JSON-shaped data: ``registry_as_dict()``
returns it verbatim so a later Part can aggregate
coverage gaps from it. Only the java-decompile chain is
wired end-to-end in this Part; the other capabilities are
declared, not re-wired.

Part of NAR (Nirous Android Reversing). MIT License.
See LICENSE in the repo root.
"""
import importlib.util
import json
import os
import sys
import time

from . import failures
from .failures import FailureKind

FIDELITY_LADDER = (
    "source-equivalent", "source-approximate",
    "bytecode-listing", "structural-summary",
    "identified-only",
)

# Bounded floor for rung 5: at most this many method
# listings are emitted per DEX (counts stay complete).
DISASM_LISTING_CAP = 500

_SCRIPTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)


def _cap(capability, chain, fidelity_by_rung, floor_rung,
         notes=""):
    return {
        "capability": capability,
        "chain": list(chain),
        "fidelity_by_rung": dict(fidelity_by_rung),
        "floor_rung": floor_rung,
        "notes": notes,
    }


# ------------------------------------------------------------------
# Chain registry (brief 10.5.2, existing rungs only).
#
# Rung names are tool/registry names or NAR's own module
# names. Tools the registry marks unavailable (kind
# "unavailable": dex2jar, cfr, procyon, Il2CppInspector,
# AssetRipper, UAssetAPI, FModel, UnrealPak) are NOT rungs
# of the other capabilities; the decompile chain is the
# exception the brief names explicitly — its dex2jar rungs
# exist in the chain and record NOT_INSTALLED when the
# tools are not resolvable.
# ------------------------------------------------------------------
CHAIN_REGISTRY = {c["capability"]: c for c in [
    _cap("java-decompile",
         ["jadx", "baksmali", "dex2jar+cfr",
          "dex2jar+procyon", "nar-dex-disasm"],
         {"jadx": "source-approximate",
          "baksmali": "bytecode-listing",
          "dex2jar+cfr": "source-approximate",
          "dex2jar+procyon": "source-approximate",
          "nar-dex-disasm": "bytecode-listing"},
         "nar-dex-disasm",
         "Wired end-to-end in nar-analyze (Part 10.5)."),
    _cap("manifest-decode",
         ["apktool", "aapt2", "nar-perms"],
         {"apktool": "source-approximate",
          "aapt2": "structural-summary",
          "nar-perms": "structural-summary"},
         "nar-perms",
         "Own parser is nar-perms' AXML reader; no raw-AXML "
         "module beyond it exists today."),
    _cap("resource-table",
         ["aapt2", "apktool"],
         {"aapt2": "structural-summary",
          "apktool": "source-approximate"},
         None,
         "No own ARSC parser exists today; two external "
         "rungs is the truth."),
    _cap("signature",
         ["apksigner", "meta-inf-v1"],
         {"apksigner": "structural-summary",
          "meta-inf-v1": "structural-summary"},
         "meta-inf-v1",
         "meta-inf-v1 is the own META-INF v1 reading in "
         "nar-triage; no standalone apksig module exists."),
    _cap("il2cpp-dump",
         ["il2cppdumper", "cpp2il", "metadata-only"],
         {"il2cppdumper": "structural-summary",
          "cpp2il": "structural-summary",
          "metadata-only": "structural-summary"},
         "metadata-only",
         "metadata-only is nar-il2cpp's own metadata "
         "parser. Il2CppInspector is registry-unavailable "
         "and is not a rung."),
    _cap("unity-assets",
         ["unitypy", "inventory-only"],
         {"unitypy": "structural-summary",
          "inventory-only": "identified-only"},
         "inventory-only",
         "inventory-only is nar-unity/nar-assets' own "
         "path-level bundle inventory. AssetRipper is "
         "registry-unavailable and is not a rung."),
    _cap("unreal-packages",
         ["nar-unreal", "nar-pak"],
         {"nar-unreal": "structural-summary",
          "nar-pak": "structural-summary"},
         "nar-unreal",
         "nar-unreal is the own uasset/zen parser. "
         "UAssetAPI and FModel are registry-unavailable "
         "and are not rungs."),
    _cap("unreal-pak",
         ["nar-pak"],
         {"nar-pak": "structural-summary"},
         "nar-pak",
         "Single-rung: nar-pak is the own pak reader. "
         "UnrealPak is registry-unavailable (pak creation "
         "only) and is not a rung."),
    _cap("godot",
         ["nar-godot", "godotpcktool", "gdre"],
         {"nar-godot": "structural-summary",
          "godotpcktool": "structural-summary",
          "gdre": "source-approximate"},
         "nar-godot",
         "nar-godot is the own pack parser and floor."),
    _cap("flutter",
         ["nar-flutter", "strings-only"],
         {"nar-flutter": "structural-summary",
          "strings-only": "identified-only"},
         "nar-flutter",
         "strings-only is the nar-strings floor. blutter "
         "is not in the tool registry and is not a rung."),
    _cap("hermes",
         ["hermes-dec", "nar-rn"],
         {"hermes-dec": "bytecode-listing",
          "nar-rn": "structural-summary"},
         "nar-rn",
         "nar-rn is the own Hermes header parser and "
         "floor; no standalone hbc module exists today."),
    _cap("native-decompile",
         ["ghidra", "kuna", "objdump", "narlib-elf"],
         {"ghidra": "source-approximate",
          "kuna": "source-approximate",
          "objdump": "bytecode-listing",
          "narlib-elf": "structural-summary"},
         "narlib-elf",
         "narlib-elf is narlib.elf (own ELF parser: "
         "symbols/sections), driven by nar-native."),
    _cap("networking-runtime",
         ["mitmproxy", "tshark", "nar-network"],
         {"mitmproxy": "structural-summary",
          "tshark": "structural-summary",
          "nar-network": "structural-summary"},
         "nar-network",
         "nar-network is the own static endpoint "
         "analysis and floor."),
    _cap("runtime-hooks",
         ["frida", "adb", "static-only"],
         {"frida": "structural-summary",
          "adb": "structural-summary",
          "static-only": "identified-only"},
         "static-only",
         "static-only is the named limitation floor in "
         "nar-runtime when no device tooling serves."),
    _cap("xamarin-dotnet",
         ["narlib-dotnetmeta"],
         {"narlib-dotnetmeta": "structural-summary"},
         "narlib-dotnetmeta",
         "Single-rung: narlib.dotnetmeta is the own "
         "ECMA-335 reader. ilspycmd/monodis are not in "
         "the tool registry and are not rungs."),
    _cap("audio-banks",
         ["nar-assets", "identified-only"],
         {"nar-assets": "structural-summary",
          "identified-only": "identified-only"},
         "identified-only",
         "nar-assets is the own header-level audio "
         "inventory. vgmstream is not in the tool "
         "registry and is not a rung."),
]}


def registry_as_dict():
    """The chain registry as plain JSON-shaped data."""
    return json.loads(json.dumps(CHAIN_REGISTRY))


def _lower_fidelity(a, b):
    """The lower of two fidelity ladder values."""
    if a not in FIDELITY_LADDER:
        return b
    if b not in FIDELITY_LADDER:
        return a
    return a if FIDELITY_LADDER.index(a) >= \
        FIDELITY_LADDER.index(b) else b


# ------------------------------------------------------------------
# Chain runner.
#
# A rung spec is {name, fidelity, budget_s, caveats, run}
# where run(ctx) returns one of:
#   {"status": "ok", "artifacts": int, ...}
#   {"status": "partial", "detail": str, "artifacts": int,
#    "decompile_errors": int, ...}   (usable evidence, with
#                                     a PARTIAL classification)
#   {"status": "failed", "kind": FailureKind|name,
#    "detail": str, "install_hint": str (optional), ...}
# or raises (classified: missing binary NOT_INSTALLED,
# timeout TIMEOUT, memory OOM, anything else BUG with the
# traceback recorded on the attempt).
# ctx is {repair: None|"oom-retry"|"timeout-retry",
#         budget_s: float, chain_remaining_s: float|None}.
# ------------------------------------------------------------------
def _attempt_from_raw(spec, raw, duration, repair=None):
    """Normalize one rung outcome into an attempt entry."""
    attempt = {"rung": spec["name"],
               "duration_s": round(duration, 3)}
    if repair:
        attempt["repair"] = repair
    if (raw or {}).get("tool_identity"):
        # The serving/failed tool's identity verdict (field
        # round F-04): the record states whether the tool
        # was validated as the tool it claims to be.
        attempt["tool_identity"] = raw["tool_identity"]
    if (raw or {}).get("identity_rejections"):
        # Candidates rejected before this one served (or
        # before the rung failed): the named record that a
        # wrapper / impostor / broken override was passed
        # over, with what it reported instead.
        attempt["identity_rejections"] = \
            raw["identity_rejections"]
    status = (raw or {}).get("status")
    if status == "ok":
        attempt["status"] = "ok"
        if raw.get("artifacts") is not None:
            attempt["artifacts"] = raw["artifacts"]
        if raw.get("output_dir"):
            attempt["output_dir"] = raw["output_dir"]
        return attempt, None
    if status == "partial":
        attempt["status"] = "partial"
        attempt["classification"] = FailureKind.PARTIAL.value
        attempt["reason"] = failures.format_reason(
            FailureKind.PARTIAL, raw.get("detail") or
            "partial output used")
        if raw.get("artifacts") is not None:
            attempt["artifacts"] = raw["artifacts"]
        if raw.get("decompile_errors") is not None:
            attempt["decompile_errors"] = \
                raw["decompile_errors"]
        if raw.get("output_dir"):
            attempt["output_dir"] = raw["output_dir"]
        return attempt, FailureKind.PARTIAL
    kind = failures.coerce_kind(
        (raw or {}).get("kind")
        or (raw or {}).get("classification"))
    attempt["status"] = "failed"
    attempt["classification"] = kind.value
    attempt["reason"] = failures.format_reason(
        kind, (raw or {}).get("detail") or "")
    label = failures.report_label_for(kind)
    if label:
        attempt["report_label"] = label
    if (raw or {}).get("install_hint"):
        attempt["install_hint"] = raw["install_hint"]
    if (raw or {}).get("traceback"):
        attempt["traceback"] = raw["traceback"]
    return attempt, kind


def _execute(spec, ctx):
    started = time.time()
    try:
        raw = spec["run"](ctx)
    except Exception as exc:  # a rung raising is data
        kind = failures.classify_exception(exc)
        raw = {"status": "failed", "kind": kind,
               "detail": f"{type(exc).__name__}: {exc}"}
        if kind is FailureKind.BUG:
            raw["traceback"] = failures.traceback_text(exc)
    duration = time.time() - started
    return _attempt_from_raw(spec, raw, duration,
                             repair=ctx.get("repair")), raw


def run_chain(capability, rung_specs, total_budget_s=None):
    """Run an ordered rung list; return the Fallback
    Record (exactly capability / chain / attempts /
    served_by / fidelity / caveats)."""
    started = time.time()
    attempts = []
    caveats = []
    served_by = None
    fidelity = "identified-only"

    def remaining():
        if total_budget_s is None:
            return None
        return total_budget_s - (time.time() - started)

    for spec in rung_specs:
        rem = remaining()
        if rem is not None and rem <= 0:
            kind = FailureKind.BUDGET_EXCEEDED
            attempts.append({
                "rung": spec["name"], "status": "failed",
                "classification": kind.value,
                "reason": failures.format_reason(
                    kind, "chain total budget exceeded "
                          "before this rung"),
                "duration_s": 0.0})
            caveats.append(
                "chain total budget exceeded; "
                f"{spec['name']} was not attempted")
            break
        budget = spec.get("budget_s")
        ctx = {"repair": None, "budget_s": budget,
               "chain_remaining_s": rem}
        (attempt, kind), raw = _execute(spec, ctx)
        # Bounded self-repair (10.5.5): exactly one retry,
        # only for OOM / TIMEOUT, only when the chain
        # budget still allows another attempt.
        repair = failures.repair_label_for(kind) \
            if kind in (FailureKind.OOM, FailureKind.TIMEOUT) \
            else None
        if repair and (remaining() is None
                       or remaining() > 0):
            attempts.append(attempt)
            retry_budget = budget
            if kind is FailureKind.TIMEOUT \
                    and budget is not None:
                retry_budget = budget * 2
            ctx = {"repair": repair,
                   "budget_s": retry_budget,
                   "chain_remaining_s": remaining()}
            (attempt, kind), raw = _execute(spec, ctx)
        attempts.append(attempt)
        if attempt["status"] in ("ok", "partial"):
            served_by = spec["name"]
            fidelity = spec.get("fidelity",
                                "identified-only")
            if raw and raw.get("fidelity"):
                fidelity = _lower_fidelity(
                    fidelity, raw["fidelity"])
            caveats.extend(spec.get("caveats") or [])
            caveats.extend((raw or {}).get("caveats") or [])
            if attempt["status"] == "partial":
                caveats.append(
                    f"{spec['name']} served partial output: "
                    + ((raw or {}).get("detail")
                       or "partial output used"))
            break
    if served_by is None:
        caveats.append(
            "no rung yielded usable evidence; "
            "identified-only")
    # De-duplicate caveats, preserving order.
    seen = set()
    uniq = []
    for c in caveats:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return {
        "capability": capability,
        "chain": [s["name"] for s in rung_specs],
        "attempts": attempts,
        "served_by": served_by,
        "fidelity": fidelity,
        "caveats": uniq,
    }


# ------------------------------------------------------------------
# Decompilation chain (capability "java-decompile").
#
# Rungs 1-2 wrap the EXISTING nar-dex adapters (registry-
# driven availability, install hints, jadx PARTIAL
# handling) — they are not reimplemented here. Rungs 3-4
# exist in the chain and record NOT_INSTALLED (with the
# registry install hint) unless dex2jar and the JVM
# decompiler are genuinely resolvable through the
# registry. Rung 5 is NAR's own disassembler, the floor.
# ------------------------------------------------------------------
_nar_dex_mod = None


def _load_nar_dex():
    global _nar_dex_mod
    if _nar_dex_mod is None:
        path = os.path.join(_SCRIPTS, "nar-dex.py")
        spec = importlib.util.spec_from_file_location(
            "nar_dex_for_chains", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _nar_dex_mod = mod
    return _nar_dex_mod


def _registry_entry(name):
    from . import registry as reg_mod
    registry = reg_mod.load_registry()
    entry = next((t for t in registry["tools"]
                  if t["name"] == name), None)
    return reg_mod, entry


def _probe_failure(name):
    """(FailureKind, detail, install_hint) for a tool the
    registry cannot serve, or None when it is available."""
    reg_mod, entry = _registry_entry(name)
    if entry is None:
        return FailureKind.BUG, f"{name} not in registry", None
    probe = reg_mod.probe(entry)
    if probe["available"]:
        return None
    kind = failures.classify_unavailable(probe.get("note"))
    detail = f"{name} not available: {probe.get('note')}"
    return kind, detail, entry.get("install_hint")


def _adapter_failure(result):
    kind, detail = failures.classify_adapter_error(
        result.get("error", ""),
        result.get("output_tail", ""))
    raw = {"status": "failed", "kind": kind,
           "detail": detail}
    if result.get("install_hint"):
        raw["install_hint"] = result["install_hint"]
    if result.get("tool_identity"):
        raw["tool_identity"] = result["tool_identity"]
    if result.get("identity_rejections"):
        raw["identity_rejections"] = \
            result["identity_rejections"]
    return raw


def _first_dex_path(nar_dex, target, work_dir):
    """Extract the first DEX of the target to a file the
    external disassembler rungs can read, or None."""
    out = os.path.join(work_dir, "first.dex")
    if os.path.isfile(out):
        return out
    for _name, data in nar_dex.load_dexes(target):
        if data:
            os.makedirs(work_dir, exist_ok=True)
            with open(out, "wb") as fh:
                fh.write(data)
            return out
    return None


def _rung_jadx(target, out_dir):
    def run(ctx):
        nar_dex = _load_nar_dex()
        result = nar_dex.jadx_index(target, out_dir)
        if "error" in result:
            return _adapter_failure(result)
        classes = result.get("class_files", 0)
        errors = result.get("decompile_errors", 0)
        exit_code = result.get("exit_code")
        identity = {}
        if result.get("tool_identity"):
            identity["tool_identity"] = result["tool_identity"]
        if result.get("identity_rejections"):
            identity["identity_rejections"] = \
                result["identity_rejections"]
        if classes and (errors or exit_code not in (0, None)):
            return {
                "status": "partial",
                "detail": "jadx finished with errors, "
                          f"count: {errors}; classes on "
                          "disk were used",
                "artifacts": classes,
                "decompile_errors": errors,
                "output_dir": out_dir,
                "caveats": [
                    f"jadx decompile errors: {errors}; "
                    "affected methods remain smali-only"],
                **identity,
            }
        if not classes:
            # The decompile-outcome check (field round F-04):
            # an identity-validated jadx that produced no
            # Java sources is a distinct record from a bare
            # no-classes failure — the tool was verified as
            # jadx, ran, and yielded nothing.
            if result.get("tool_identity") == "validated":
                detail = (
                    "jadx (identity validated, version "
                    f"{result.get('tool_version')}) ran but "
                    "produced no Java sources")
            else:
                detail = "jadx produced no classes"
            return {"status": "failed",
                    "kind": FailureKind.BUG,
                    "detail": detail,
                    **identity}
        return {"status": "ok", "artifacts": classes,
                "output_dir": out_dir,
                **identity}
    return run


def _rung_baksmali(target, work_dir, out_dir):
    def run(ctx):
        nar_dex = _load_nar_dex()
        dex_path = _first_dex_path(nar_dex, target, work_dir)
        if dex_path is None:
            return {"status": "failed",
                    "kind": FailureKind.UNSUPPORTED_INPUT,
                    "detail": "target carries no DEX to "
                              "disassemble"}
        result = nar_dex.baksmali_index(dex_path, out_dir)
        if "error" in result:
            return _adapter_failure(result)
        count = result.get("smali_files", 0)
        if not count:
            kind = failures.classify_output(
                result.get("output_tail", ""),
                result.get("exit_code"))
            return {"status": "failed", "kind": kind,
                    "detail": "baksmali produced no smali "
                              f"files (exit "
                              f"{result.get('exit_code')})"}
        return {"status": "ok", "artifacts": count,
                "output_dir": out_dir}
    return run


def _rung_jvm_decompiler(rung_name, decompiler):
    """dex2jar + a JVM decompiler (cfr / procyon)."""
    def run(ctx):
        for tool in ("dex2jar", decompiler):
            failure = _probe_failure(tool)
            if failure is not None:
                kind, detail, hint = failure
                raw = {"status": "failed", "kind": kind,
                       "detail": f"{rung_name}: {detail}"}
                if hint:
                    raw["install_hint"] = hint
                return raw
        # Both tools probe available: no integration in
        # this release converts DEX through them (the
        # registry carries them as unavailable, so this
        # branch is not reachable through the registry
        # today). Recorded as a bug rather than a fake run.
        return {"status": "failed", "kind": FailureKind.BUG,
                "detail": f"{rung_name}: tools probe "
                          "available but no conversion "
                          "integration exists in this "
                          "release"}
    return run


def _rung_disasm(target, out_dir):
    def run(ctx):
        from . import dexdis
        from .dex import Dex, DexError
        nar_dex = _load_nar_dex()
        dexes = nar_dex.load_dexes(target)
        if not dexes:
            return {"status": "failed",
                    "kind": FailureKind.UNSUPPORTED_INPUT,
                    "detail": "target carries no DEX"}
        per_dex = []
        total_classes = 0
        total_decoded = 0
        last_error = None
        for name, data in dexes:
            if data is None:
                last_error = "DEX exceeds the read cap"
                continue
            if data[:4] == b"cdex":
                per_dex.append({
                    "name": name, "format": "compact-dex",
                    "note": "compact DEX identified; the "
                            "built-in disassembler does not "
                            "decode cdex payloads"})
                continue
            try:
                dex_obj = Dex(data, name)
            except DexError as exc:
                last_error = str(exc)
                continue
            dis = dexdis.disassemble(
                dex_obj, want_all=True,
                limit=DISASM_LISTING_CAP)
            total_classes += dex_obj.class_defs_size
            total_decoded += dis["methods_decoded"]
            per_dex.append({
                "name": name,
                "class_count": dex_obj.class_defs_size,
                "method_count": dex_obj.method_ids_size,
                "field_count": dex_obj.field_ids_size,
                "disassembly": dis})
        if not per_dex:
            kind = failures.classify_output(last_error or "")
            return {"status": "failed", "kind": kind,
                    "detail": last_error or
                    "no DEX could be parsed"}
        os.makedirs(out_dir, exist_ok=True)
        doc = {
            "tool": "nar-dex-disasm",
            "listing_cap_per_dex": DISASM_LISTING_CAP,
            "total_classes": total_classes,
            "total_methods_decoded": total_decoded,
            "dex_files": per_dex,
        }
        with open(os.path.join(out_dir, "disassembly.json"),
                  "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1)
        raw = {"status": "ok",
               "artifacts": total_decoded,
               "output_dir": out_dir,
               "caveats": [
                   "built-in disassembly listing capped "
                   f"at {DISASM_LISTING_CAP} methods per "
                   "DEX; class/method/field counts are "
                   "complete"]}
        if not total_decoded:
            raw["fidelity"] = "structural-summary"
            raw["caveats"].append(
                "no method bytecode decoded; structural "
                "counts only")
        return raw
    return run


def decompile_rung_specs(target, work_dir):
    """The ordered rung specs for java-decompile."""
    reg = CHAIN_REGISTRY["java-decompile"]
    fid = reg["fidelity_by_rung"]
    return [
        {"name": "jadx", "fidelity": fid["jadx"],
         "budget_s": 900,
         "caveats": ["jadx output is decompiled Java "
                     "approximation, not original source"],
         "run": _rung_jadx(
             target, os.path.join(work_dir, "jadx"))},
        {"name": "baksmali", "fidelity": fid["baksmali"],
         "budget_s": 600,
         "caveats": ["smali is disassembly, not Java "
                     "source; control flow is explicit"],
         "run": _rung_baksmali(
             target, work_dir,
             os.path.join(work_dir, "baksmali"))},
        {"name": "dex2jar+cfr",
         "fidelity": fid["dex2jar+cfr"], "budget_s": 60,
         "caveats": ["cfr output is decompiled Java "
                     "approximation, not original source"],
         "run": _rung_jvm_decompiler("dex2jar+cfr", "cfr")},
        {"name": "dex2jar+procyon",
         "fidelity": fid["dex2jar+procyon"], "budget_s": 60,
         "caveats": ["procyon output is decompiled Java "
                     "approximation, not original "
                     "source"],
         "run": _rung_jvm_decompiler(
             "dex2jar+procyon", "procyon")},
        {"name": "nar-dex-disasm",
         "fidelity": fid["nar-dex-disasm"], "budget_s": 600,
         "caveats": ["built-in disassembly is a bytecode "
                     "listing, not Java source"],
         "run": _rung_disasm(
             target, os.path.join(work_dir, "nar-dex-disasm"))},
    ]


def run_decompile_chain(target, work_dir,
                        total_budget_s=1800):
    """Run the java-decompile chain against a target
    (APK or bare DEX). Returns the Fallback Record."""
    os.makedirs(work_dir, exist_ok=True)
    return run_chain(
        "java-decompile",
        decompile_rung_specs(target, work_dir),
        total_budget_s=total_budget_s)


def identified_only_record(capability, chain, caveat):
    """A Fallback Record for a capability that does not
    apply to the target (no rung attempted)."""
    return {
        "capability": capability,
        "chain": list(chain),
        "attempts": [],
        "served_by": None,
        "fidelity": "identified-only",
        "caveats": [caveat],
    }
