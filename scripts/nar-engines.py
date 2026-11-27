#!/usr/bin/env python3
"""nar-engines.py: multi-indicator engine/framework detection
with confidence (brief section 5).

Fuses independent evidence instead of trusting any single
signature:

- nar-triage path signatures (native libraries, payload files),
- triage binary-header version evidence,
- triage DEX content markers (corroboration),
- JNI / native dynamic-symbol evidence read directly from the
  dynamic export table of every lib/**/*.so (narlib.elf): a
  family JNI match is direct evidence — medium on its own,
  high with a corroborating DEX/path marker for the family;
  JNI evidence contributed SOLELY by a known third-party SDK
  bridge namespace (formats.json jni_bridge_prefixes) is
  recorded but weighed below the detection threshold, since
  an SDK built on an engine is not the app's engine,
- a direct layout pass of its own (IoStore containers, Unity
  Data layout, Flutter assets, Hermes bundles, Godot packs),
- native-strings evidence: a bounded raw byte-substring scan
  of every lib/**/*.so for the per-engine string signatures
  in formats.json (string_signatures) — the channel that
  survives static linking into a generically-named library,
  where filename and exported-symbol evidence are both gone,
- with --deep, the matching deep-dive tool's verdict
  (nar-il2cpp / nar-godot / nar-flutter / nar-rn / nar-unreal),
  which can raise a verdict to confirmed.

Every verdict lists its indicators; scores map to confidence
(>=70 high, >=40 medium, else low) and a candidate under the
medium bar is reported as detected=false with its evidence
kept, never silently dropped and never overstated. Known
ambiguities (embedded Python as a runtime component, bare
assets/www, IL2CPP+Mono doubles) are stated as ambiguities.

Usage:
    python3 nar-engines.py app.apk [--json] [--deep]

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import container as container_mod  # noqa: E402
from narlib import formats_registry as _formats  # noqa: E402
from narlib.elf import Elf, ElfError, SHT_DYNSYM  # noqa: E402
from narlib.hashing import sha256_of  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))

# Canonical engine -> the triage hint names that feed it, the
# deep-dive tool that confirms it, and version keys in triage's
# engine_versions block. Since Part 16 this table is a derived
# view of scripts/formats.json (the single source of truth,
# loaded via narlib.formats_registry); the marker data lives
# in the JSON, never as literals here.
ENGINES = _formats.engines_table()

STRONG_MARKERS = (".so", ".dat", ".pak", ".pck", "application.xml",
                  "capacitor.config", "cordova.js", "cordova-",
                  "phonegap", "assemblies/",
                  # Engine-unique payload names: a compiled Ren'Py
                  # script or an RPG Maker core runtime script is
                  # shipped by exactly one engine, so a single hit
                  # is strong evidence, not a weak path hint.
                  ".rpyc", "rpg_core.js", "rmmz_core.js")

# ------------------------------------------------------------------
# JNI / dynamic-symbol evidence (Part 3.1).
#
# nar-engines previously never read ELF exports, so a build
# whose game library carried a NON-canonical name scored only
# its DEX corroboration (+10) no matter how many family JNI
# symbols it exported \u2014 e.g. a Cocos2d-x build exporting the
# full Cocos2d-x JNI surface under libgame.so came
# back detected=false / low. The symbol half of the engine
# marker matrix \u2014 JNI package prefixes and named exported
# symbols, classed strong (one hit is family-specific) vs
# weak (generic runtime surface; needs JNI_WEAK_MIN_MATCHES
# distinct hits), with also_requires where a family needs a
# specific corroborating symbol (L\u00d6VE: luaL_* alone is the
# stock Lua C API exported by every Lua embedder) \u2014 lives in
# scripts/formats.json since Part 16 and is loaded here as a
# derived view. Markers that are file/path facts (libhermes*,
# .pak, .rpa, libpython*, application.xml, libCore.so) are NOT
# symbol evidence and stay with the path/DEX channels.
JNI_SYMBOL_MARKERS = _formats.jni_markers()
# Families whose symbol matches are excluded when they come
# from a named library (formats.json jni_excluded_from): the
# IL2CPP runtime derives from the Mono codebase and its
# library exports the mono_* API as Unity internals, so those
# matches are not Xamarin evidence; a real Xamarin runtime
# ships its own Mono libraries, which keep their matches.
JNI_EXCLUSIONS = _formats.jni_exclusions()
# JNI symbol prefixes belonging to known third-party SDK
# bridges built on an engine (formats.json
# jni_bridge_prefixes): the SDK is hosted under the engine's
# Java package root and ships as its own library inside apps
# that are not built on the engine, so its bridge exports are
# evidence of the SDK, not of the app's engine (M2-07).
JNI_BRIDGE_PREFIXES = _formats.jni_bridge_prefixes()
# Score for JNI evidence that comes solely from such a
# bridge namespace: the indicator is still recorded (the JNI
# channel measurement reads recorded indicators), but the
# contribution stays below the detection threshold and never
# raises a verdict to the high floor; any non-bridge JNI
# evidence, or any corroborating channel, restores the
# normal weighing.
JNI_BRIDGE_ONLY_SCORE = 20
# Weak-only families need this many distinct weak symbol hits
# before the surface counts as family evidence at all.
JNI_WEAK_MIN_MATCHES = 3
# Symbol score: a family JNI match is direct evidence, sized
# to land at medium (>= 40) entirely on its own; fuse() then
# raises a corroborated match (any DEX/path/layout/version
# indicator for the same family) to the high floor.
JNI_SCORE = 45
JNI_HIGH_FLOOR = 70
# Bounded scan, in the codebase's budget style: libraries are
# parsed one at a time and released, oversized members are
# skipped, and a corrupt library degrades to no evidence.
# Members are visited largest-first within the cap: engine
# runtime libraries are large, while the hundreds of tiny
# per-assembly stubs some frameworks ship would otherwise
# crowd the runtime out of the scan window.
JNI_MAX_LIBRARIES = 128
JNI_MAX_LIBRARY_BYTES = 256 * 1024 * 1024
JNI_MAX_SYMBOLS_PER_LIBRARY = 20000
JNI_SAMPLE_SIZE = 10

# ------------------------------------------------------------------
# Native-strings evidence (field round, Area 4).
#
# A statically-linked engine whose only trace is strings in a
# generically-named library previously scored nothing and was
# affirmatively labelled plain native. The string signatures
# live in formats.json (string_signatures per engine, exposed
# via ENGINES) and are matched as raw byte substrings, the
# same technique nar-cocos uses for its version evidence.
#
# Weights, deliberately conservative: a strong token (a
# version banner such as an engine's "name x.y" build string)
# scores 40 — it ties the detection threshold (40) exactly,
# so a banner alone is detected/medium, and it stays below
# the path-signature channel's typical 42 and the JNI
# channel's 45. Each distinct weak token scores 12, with the
# weak-only contribution capped at 35: weak strings alone
# therefore stay a recorded candidate (score < 40, detected
# = false), never a detection. Weak tokens on top of a strong
# banner corroborate (40 + up to 35).
STRING_STRONG_SCORE = 40
STRING_WEAK_SCORE = 12
STRING_WEAK_CAP = 35
# Bounded scan, in the spirit of nar-cocos's NATIVE_CAP:
# libraries are read one at a time, members over the cap are
# skipped, and the library count is capped largest-first
# (engine runtime libraries are large).
STRING_MAX_LIBRARIES = 128
STRING_MAX_LIBRARY_BYTES = 64 * 1024 * 1024

# Unknown / custom engine (field round, Area 4): when no
# engine is detected but the target carries substantial
# native code, the honest outcome is an explicit unknown
# record carrying the native evidence, not an affirmative
# "no engine" label. "Substantial" here means at least two
# export-carrying libraries: a single small library exporting
# ANativeActivity_onCreate plus its own package's JNI is the
# plain-native shape pinned by test_engines_jni_symbols.py
# (verdicts == [] and native_no_engine true), and that
# classification is preserved; a multi-library native payload
# with zero known signatures is where a custom or unknown
# engine can actually hide.
UNKNOWN_MIN_LIBRARIES_WITH_EXPORTS = 2


_ALPHA_RUN = re.compile(r"[A-Za-z]+")
_CAMEL_BOUNDARY = re.compile(
    r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _symbol_tokens(name):
    """Whole-word tokens of an exported symbol name.

    Alphabetic runs (digit runs — including the length
    prefixes of Itanium-mangled names — act as separators)
    are split further at CamelCase boundaries, so a mangled
    name yields the identifiers it was built from: e.g.
    ``_ZN4love7physics4stepEf`` yields {zn, love, physics,
    step, ef} and ``...CellOverlays...`` yields {cell,
    overlays} — never a fused token spanning the boundary.
    """
    tokens = set()
    for run in _ALPHA_RUN.findall(name):
        for word in _CAMEL_BOUNDARY.split(run):
            if word:
                tokens.add(word.lower())
    return tokens


def _classify_symbol(name, spec, tokens=None):
    """'strong' / 'weak' / None for one exported symbol name."""
    for prefix in spec["prefixes"]:
        if name.startswith(prefix):
            return "strong"
    if name in spec["exact"]:
        return "strong"
    for sub in spec["substrings"]:
        if sub in name:
            return "strong"
    for prefix in spec["weak_prefixes"]:
        if name.startswith(prefix):
            return "weak"
    if spec["weak_substrings"]:
        # Weak substrings are the fuzzy channel: matched as a
        # raw substring they fire on accidents inside mangled
        # C++ names, where a short pattern can span the seam
        # between two identifiers (the tail of one word plus
        # the head of the next). They therefore count only
        # as a WHOLE TOKEN of the demangle-aware tokenization
        # above (M2-08). Strong patterns (prefixes, exact
        # names, specific substrings) are long and specific
        # enough to keep substring semantics.
        if tokens is None:
            tokens = _symbol_tokens(name)
        for sub in spec["weak_substrings"]:
            if sub.lower() in tokens:
                return "weak"
    return None


def match_jni_symbols(symbol_names):
    """Family matches over a flat iterable of exported names.

    Returns {canonical: {"matched": [...], "count": int,
    "strong": int, "weak": int}} for the families whose bar is
    met: at least one strong hit, or JNI_WEAK_MIN_MATCHES
    distinct weak hits (plus the family's also_requires
    substring, when declared, among the matched names)."""
    hits = {}
    for name in symbol_names:
        if not name:
            continue
        tokens = None
        for canonical, spec in JNI_SYMBOL_MARKERS.items():
            if spec["weak_substrings"] and tokens is None:
                tokens = _symbol_tokens(name)
            kind = _classify_symbol(name, spec, tokens)
            if kind is None:
                continue
            entry = hits.setdefault(canonical, {
                "names": [], "strong": 0, "weak": 0,
                "strong_names": []})
            if name not in entry["names"]:
                entry["names"].append(name)
            if kind == "strong" and \
                    name not in entry["strong_names"]:
                entry["strong_names"].append(name)
            entry[kind] += 1
    out = {}
    for canonical, entry in hits.items():
        spec = JNI_SYMBOL_MARKERS[canonical]
        if entry["strong"] < 1 and \
                entry["weak"] < JNI_WEAK_MIN_MATCHES:
            continue
        required = spec.get("also_requires")
        if required:
            # The corroborating token is held to the same
            # token discipline as the weak substrings (a raw
            # substring check would re-admit the boundary
            # accidents the token rule excludes); a strong
            # match that literally contains it (e.g. a
            # luaopen_<family> entry point) also satisfies it.
            req = required.lower()
            if not any(req in _symbol_tokens(n)
                       or (n in entry["strong_names"]
                           and req in n.lower())
                       for n in entry["names"]):
                continue
        names = sorted(entry["names"])
        out[canonical] = {
            "matched": names[:JNI_SAMPLE_SIZE],
            "count": len(names),
            "strong": entry["strong"], "weak": entry["weak"]}
    return out


def jni_evidence(apk_path, extra_paths=None):
    """Dynamic-export evidence from every lib/**/*.so member.

    ``extra_paths`` are additional archives (the merged
    splits of a container, resolved through
    narlib.container) whose libraries are scanned with the
    same budget; library names are then qualified with the
    archive they came from. Returns {"per_engine":
    {canonical: {matched, count, strong, weak, libraries,
    bridge_only, bridge_symbols}}, "libraries_scanned": int,
    "libraries_with_exports": int, "anative_activity": bool,
    "libraries": [paths of libraries with exports, in scan
    order (largest first within each archive)]}.
    bridge_only is True when every contributing library's
    family matches sit under a known SDK bridge prefix.
    A member that is not a parseable ELF, or exceeds the
    size budget, contributes no evidence and never fails
    the scan.
    """
    result = {"per_engine": {}, "libraries_scanned": 0,
              "libraries_with_exports": 0,
              "anative_activity": False,
              "libraries": []}
    for path in [apk_path] + list(extra_paths or []):
        _jni_evidence_one(path, result,
                          qualify=bool(extra_paths))
    return result


def _jni_evidence_one(apk_path, result, qualify=False):
    try:
        zf = zipfile.ZipFile(apk_path)
    except (zipfile.BadZipFile, OSError):
        return
    with zf:
        members = [i for i in zf.infolist()
                   if i.filename.startswith("lib/")
                   and i.filename.endswith(".so")]
        members.sort(key=lambda i: (-i.file_size, i.filename))
        for info in members[:JNI_MAX_LIBRARIES]:
            if info.file_size > JNI_MAX_LIBRARY_BYTES:
                continue
            result["libraries_scanned"] += 1
            try:
                data = zf.read(info.filename)
                elf = Elf(data, info.filename)
                symbols = elf.symbols(SHT_DYNSYM)
            except ElfError:
                # Corrupt or non-ELF member: no evidence.
                continue
            except Exception:
                # A zip read failure or a struct error on a
                # hostile header degrades the same way; one
                # bad library never crashes the whole scan.
                continue
            exports = []
            for sym in symbols[:JNI_MAX_SYMBOLS_PER_LIBRARY]:
                if sym["defined"] and sym["name"] \
                        and sym["bind"] in (1, 2):
                    exports.append(sym["name"])
            if not exports:
                continue
            result["libraries_with_exports"] += 1
            lib_label = (
                f"{os.path.basename(apk_path)}:"
                f"{info.filename}") if qualify \
                else info.filename
            if lib_label not in result["libraries"]:
                result["libraries"].append(lib_label)
            if "ANativeActivity_onCreate" in exports:
                result["anative_activity"] = True
            matches = match_jni_symbols(exports)
            for excluded in JNI_EXCLUSIONS.get(
                    info.filename.rsplit("/", 1)[-1], []):
                matches.pop(excluded, None)
            for canonical, match in matches.items():
                slot = result["per_engine"].setdefault(
                    canonical, {"matched": [], "count": 0,
                                "strong": 0, "weak": 0,
                                "libraries": [],
                                "bridge_only": bool(
                                    JNI_BRIDGE_PREFIXES.get(
                                        canonical)),
                                "bridge_symbols": 0})
                for name in match["matched"]:
                    if name not in slot["matched"]:
                        slot["matched"].append(name)
                slot["matched"] = sorted(
                    slot["matched"])[:JNI_SAMPLE_SIZE]
                slot["count"] += match["count"]
                slot["strong"] += match["strong"]
                slot["weak"] += match["weak"]
                bridge_prefixes = JNI_BRIDGE_PREFIXES.get(
                    canonical) or []
                if bridge_prefixes:
                    # This library's contribution is
                    # bridge-only when every symbol it matched
                    # for the family sits under a known SDK
                    # bridge prefix.
                    spec = JNI_SYMBOL_MARKERS[canonical]
                    family_symbols = [
                        s for s in exports
                        if _classify_symbol(s, spec) is not None]
                    slot["bridge_symbols"] += sum(
                        1 for s in family_symbols
                        if any(s.startswith(p)
                               for p in bridge_prefixes))
                    if not family_symbols or not all(
                            any(s.startswith(p)
                                for p in bridge_prefixes)
                            for s in family_symbols):
                        slot["bridge_only"] = False
                lib_label = (
                    f"{os.path.basename(apk_path)}:"
                    f"{info.filename}") if qualify \
                    else info.filename
                if lib_label not in slot["libraries"]:
                    slot["libraries"].append(lib_label)


def native_strings_evidence(apk_path, extra_paths=None):
    """Raw string-signature evidence from every lib/**/*.so.

    Scans each archive once (scan_path plus merged splits,
    mirroring jni_evidence): every engine's string_signatures
    tokens are searched as raw byte substrings in each
    library's bytes. Returns {canonical: {"hits": [{"token",
    "strong", "library"}], "strong_tokens": [...],
    "weak_tokens": [...]}} with token lists distinct per
    engine (a token found in two libraries scores once, but
    every hit is recorded with the library that carried it).
    A member over the byte cap, an unreadable archive, or a
    read failure contributes no evidence and never fails the
    scan.
    """
    tokens = []
    for canonical, spec in ENGINES.items():
        for sig in spec.get("string_signatures") or []:
            try:
                raw = sig["token"].encode("ascii")
            except (UnicodeEncodeError, AttributeError):
                continue
            if raw:
                tokens.append((canonical, sig["token"],
                               bool(sig.get("strong")), raw))
    out = {}
    if not tokens:
        return out
    for path in [apk_path] + list(extra_paths or []):
        qualify = bool(extra_paths)
        try:
            zf = zipfile.ZipFile(path)
        except (zipfile.BadZipFile, OSError):
            continue
        with zf:
            members = [i for i in zf.infolist()
                       if i.filename.startswith("lib/")
                       and i.filename.endswith(".so")]
            members.sort(key=lambda i: (-i.file_size, i.filename))
            for info in members[:STRING_MAX_LIBRARIES]:
                if info.file_size > STRING_MAX_LIBRARY_BYTES:
                    continue
                try:
                    data = zf.read(info.filename)
                except Exception:
                    continue
                lib_label = (
                    f"{os.path.basename(path)}:"
                    f"{info.filename}") if qualify \
                    else info.filename
                for canonical, token, strong, raw in tokens:
                    if raw not in data:
                        continue
                    slot = out.setdefault(canonical, {
                        "hits": [], "strong_tokens": [],
                        "weak_tokens": []})
                    slot["hits"].append({
                        "token": token, "strong": strong,
                        "library": lib_label})
                    bucket = slot["strong_tokens"] if strong \
                        else slot["weak_tokens"]
                    if token not in bucket:
                        bucket.append(token)
    return out


def run_json_tool(script, args, timeout=1800):
    cmd = [sys.executable, os.path.join(HERE, script)] + args + ["--json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
        if proc.returncode != 0:
            # A failed tool's stdout is an error document,
            # not a result: returning it let a bad target
            # produce an empty-but-successful report
            # downstream (stability audit D-02).
            return None
        return json.loads(proc.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def layout_evidence(apk_path, extra_paths=None):
    """Direct ZIP-layout indicators computed by this tool.
    With ``extra_paths`` (merged container splits), names
    from every archive contribute; split members are
    qualified with their archive name."""
    ev = {}
    names = []
    for path in [apk_path] + list(extra_paths or []):
        try:
            with zipfile.ZipFile(path) as zf:
                names.extend(zf.namelist())
        except zipfile.BadZipFile:
            continue
    if not names and extra_paths is None:
        return ev
    lower = [n.lower() for n in names]
    ev["iostore_files"] = [n for n in names
                           if n.lower().endswith((".utoc", ".ucas"))]
    ev["pak_files"] = [n for n in names if n.lower().endswith(".pak")]
    ev["pck_files"] = [n for n in names if n.lower().endswith(".pck")]
    ev["unity_data_layout"] = any(
        n.startswith("assets/bin/Data/") for n in names)
    ev["unity_managed_dlls"] = [n for n in names
                                if n.endswith(".dll")
                                and "Managed" in n][:10]
    ev["flutter_assets"] = any(
        n.startswith("assets/flutter_assets/") for n in names)
    ev["hermes_bundles"] = [n for n in names
                            if n.endswith(".hbc")
                            or n.endswith("index.android.bundle")]
    ev["godot_project"] = [n for n in names
                           if n.endswith("project.binary")
                           or n.endswith("project.godot")]
    return ev


def confidence_for(score):
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def fuse(apk_path, deep=False, work_dir=None):
    # Container inputs resolve through narlib.container:
    # layout and JNI evidence scan the base APK plus every
    # merged split (the ABI split is where the engine's
    # native libraries usually live), deep dives run on the
    # base APK, and the resolution is recorded under the
    # report's `container` block — the container file itself
    # is never scanned as if it were an APK.
    resolved = None
    scan_path = apk_path
    extra_paths = []
    if container_mod.detect_container(apk_path) in \
            container_mod.CONTAINER_KINDS + ("apk",):
        # A plain APK resolves too, but the resolution is
        # adopted only when it actually assembled a set (a
        # container, or a loose split set merged by sibling
        # discovery — field round F-01); an ordinary lone
        # APK keeps the single-archive path unchanged.
        candidate = container_mod.resolve_target(apk_path)
        if candidate.is_container or candidate.splits:
            resolved = candidate
            scan_path = resolved.base
            extra_paths = [s["path"] for s in resolved.splits]
        else:
            candidate.cleanup()
    try:
        return _fuse_resolved(apk_path, scan_path, extra_paths,
                              resolved, deep, work_dir)
    finally:
        if resolved is not None:
            resolved.cleanup()


def _fuse_resolved(apk_path, scan_path, extra_paths, resolved,
                   deep=False, work_dir=None):
    triage = run_json_tool("nar-triage.py", [apk_path])
    if triage is None:
        raise RuntimeError("nar-triage failed on this input")
    if resolved is not None:
        # Container: the container-level triage sees no
        # payload (the engine's files live in the contained
        # APKs), so fuse the per-archive triage evidence of
        # the base and every merged split as well — hints by
        # engine (marker union), version evidence (first
        # wins) and DEX markers (union). The merged verdict
        # is then at least as strong as the strongest
        # single-archive verdict, never weaker.
        merged_hints = {}
        for hint in triage.get("engine_hints") or []:
            merged_hints[hint["engine"]] = {
                "engine": hint["engine"],
                "markers": list(hint.get("markers") or []),
                "marker_count": hint.get("marker_count", 0)}
        merged_versions = dict(triage.get("engine_versions")
                                 or {})
        merged_dex = {m["marker"]: m for m in
                      triage.get("dex_markers") or []}
        for path in [scan_path] + list(extra_paths):
            sub = run_json_tool("nar-triage.py", [path])
            if sub is None:
                continue
            for hint in sub.get("engine_hints") or []:
                slot = merged_hints.setdefault(
                    hint["engine"],
                    {"engine": hint["engine"], "markers": [],
                     "marker_count": 0})
                for marker in hint.get("markers") or []:
                    if marker not in slot["markers"]:
                        slot["markers"].append(marker)
                slot["marker_count"] = max(
                    slot["marker_count"],
                    hint.get("marker_count", 0))
            for key, value in (sub.get("engine_versions")
                               or {}).items():
                merged_versions.setdefault(key, value)
            for marker in sub.get("dex_markers") or []:
                merged_dex.setdefault(marker["marker"], marker)
        triage = dict(triage)
        triage["engine_hints"] = sorted(
            merged_hints.values(), key=lambda h: h["engine"])
        triage["engine_versions"] = merged_versions
        triage["dex_markers"] = sorted(
            merged_dex.values(), key=lambda m: m["marker"])
    layout = layout_evidence(scan_path, extra_paths)
    jni = jni_evidence(scan_path, extra_paths)
    native_strings = native_strings_evidence(scan_path,
                                             extra_paths)
    hints = {h["engine"]: h for h in triage.get("engine_hints") or []}
    versions = triage.get("engine_versions") or {}
    dex_markers = {m["marker"] for m in triage.get("dex_markers") or []
                   if m.get("total_hits", 0) > 0}
    verdicts = []
    ambiguities = []

    for canonical, spec in ENGINES.items():
        score = 0
        indicators = []
        for hint_name in spec["hints"]:
            hint = hints.get(hint_name)
            if not hint:
                continue
            markers = hint.get("markers") or []
            strong = [m for m in markers
                      if any(s in m.lower() for s in STRONG_MARKERS)]
            weight = 40 if strong else 25
            score += weight + min(10, 2 * len(markers))
            indicators.append({
                "kind": "path-signature",
                "detail": f"{hint_name}: {', '.join(markers[:5])}"})
        for key in spec["version_keys"]:
            if key in versions:
                score += 15
                indicators.append({
                    "kind": "version-evidence",
                    "detail": f"{key} = {versions[key]}"})
        # Layout corroboration computed by this tool.
        if canonical.startswith("Unreal") and layout.get("pak_files"):
            score += 20
            indicators.append({
                "kind": "payload-layout",
                "detail": f"{len(layout['pak_files'])} .pak file(s)"})
        if canonical.startswith("Unreal") and layout.get("iostore_files"):
            score += 25
            indicators.append({
                "kind": "payload-layout",
                "detail": "IoStore container present (.utoc/.ucas): "
                          "UE5-era packaging"})
        if canonical.startswith("Unity") and layout.get("unity_data_layout"):
            score += 15
            indicators.append({
                "kind": "payload-layout",
                "detail": "assets/bin/Data/ Unity layout"})
        if canonical == "Godot" and layout.get("pck_files"):
            score += 20
            indicators.append({
                "kind": "payload-layout",
                "detail": f"{len(layout['pck_files'])} .pck pack(s)"})
        if canonical == "Flutter" and layout.get("flutter_assets"):
            score += 15
            indicators.append({
                "kind": "payload-layout",
                "detail": "assets/flutter_assets/ present"})
        if canonical == "React Native" and layout.get("hermes_bundles"):
            score += 15
            indicators.append({
                "kind": "payload-layout",
                "detail": "Hermes/bundle payload: "
                          f"{layout['hermes_bundles'][:3]}"})
        token = canonical.split(" ")[0].split("(")[0].lower()
        for marker in dex_markers:
            if token in marker.lower() and len(token) > 3:
                score += 10
                indicators.append({
                    "kind": "dex-marker",
                    "detail": f"DEX marker: {marker}"})
                break
        # Native-strings evidence: raw byte substrings in
        # the target's libraries. A strong version banner
        # scores STRING_STRONG_SCORE on its own; distinct
        # weak tokens score STRING_WEAK_SCORE each, capped
        # at STRING_WEAK_CAP, so weak strings alone stay a
        # recorded candidate below the detection threshold.
        # Every hit is an indicator naming the token and
        # the library that carried it.
        strings_match = native_strings.get(canonical)
        if strings_match:
            if strings_match["strong_tokens"]:
                score += STRING_STRONG_SCORE
            score += min(
                STRING_WEAK_CAP,
                STRING_WEAK_SCORE
                * len(strings_match["weak_tokens"]))
            for hit in strings_match["hits"]:
                indicators.append({
                    "kind": "native-strings",
                    "detail": f"string {hit['token']!r} in "
                              f"{hit['library']}"})
        # JNI / dynamic-symbol evidence: direct evidence.
        # Alone it scores medium (JNI_SCORE >= 40); with any
        # corroborating indicator for the same family (path,
        # DEX, layout, version) the verdict is raised to the
        # high floor. Path evidence alone is unchanged.
        # Bridge-only JNI evidence (M2-07) — every matching
        # symbol sits in a known third-party SDK bridge
        # namespace — is the exception: it is recorded with
        # the same indicator, but weighed at
        # JNI_BRIDGE_ONLY_SCORE (below the detection
        # threshold) and never raised to the high floor,
        # because the SDK's presence does not make the app
        # an app of that engine.
        jni_match = jni["per_engine"].get(canonical)
        if jni_match:
            corroborated = bool(indicators)
            bridge_only = bool(jni_match.get("bridge_only"))
            if bridge_only:
                score += JNI_BRIDGE_ONLY_SCORE
            else:
                score += JNI_SCORE
                if corroborated:
                    score = max(score, JNI_HIGH_FLOOR)
            detail = (
                f"{jni_match['count']} exported "
                f"symbol(s) match {canonical} "
                f"(sample: "
                f"{', '.join(jni_match['matched'][:3])}) "
                f"in {', '.join(jni_match['libraries'][:3])}")
            if bridge_only:
                detail += (
                    " — all matching symbols are in a known "
                    "third-party SDK bridge namespace; weighed "
                    "as SDK evidence, not engine evidence")
            indicators.append({
                "kind": "jni-symbols",
                "detail": detail})
        if not indicators:
            continue
        version = None
        for key in spec["version_keys"]:
            if key in versions:
                version = str(versions[key])
                break
        verdict = {"engine": canonical,
                   "detected": score >= 40,
                   "confidence": confidence_for(score),
                   "score": min(score, 100),
                   "version": version,
                   "indicators": indicators,
                   "recommended_next": spec["deep"]}
        if jni_match:
            verdict["jni_symbols"] = {
                "matched_symbols": jni_match["matched"],
                "match_count": jni_match["count"],
                "strong_matches": jni_match["strong"],
                "weak_matches": jni_match["weak"],
                "libraries": jni_match["libraries"]}
            if jni_match.get("bridge_only"):
                verdict["jni_symbols"]["sdk_bridge_only"] = True
                verdict["jni_symbols"]["bridge_symbols"] = \
                    jni_match.get("bridge_symbols", 0)
        if deep and spec["deep"] and verdict["detected"]:
            deep_args = [scan_path]
            if work_dir and spec["deep"] == "nar-il2cpp.py":
                # The dumper output is large; keep it out of
                # the /tmp default location.
                deep_args += ["--out",
                              os.path.join(work_dir, "il2cpp")]
            elif work_dir and spec["deep"] == "nar-rn.py":
                deep_args += ["--work",
                              os.path.join(work_dir, "rn")]
            deep_out = run_json_tool(spec["deep"], deep_args)
            if deep_out is not None:
                confirmed = None
                for key in ("is_il2cpp", "is_godot", "is_flutter",
                            "is_react_native"):
                    if key in deep_out:
                        confirmed = bool(deep_out[key])
                if "verdict" in deep_out:
                    confirmed = deep_out["verdict"] not in (
                        "absent", None)
                verdict["deep_dive"] = {
                    "tool": spec["deep"], "confirmed": confirmed}
                if confirmed:
                    verdict["confidence"] = "high"
                    verdict["score"] = max(verdict["score"], 85)
                    indicators.append({
                        "kind": "deep-dive",
                        "detail": f"{spec['deep']} confirmed the "
                                  f"engine from its own evidence"})
            else:
                verdict["deep_dive"] = {"tool": spec["deep"],
                                        "error": "deep-dive tool "
                                                 "failed to run"}
        verdicts.append(verdict)

    names = {v["engine"] for v in verdicts if v["detected"]}
    if "Embedded Python" in names and "Ren'Py" in names:
        ambiguities.append(
            "Embedded Python is the Ren'Py runtime here, not a "
            "second engine.")
    if "Unity (IL2CPP)" in names and "Unity (Mono)" in names:
        ambiguities.append(
            "Both IL2CPP and Mono Unity signatures are present; "
            "one may be a leftover or an SDK payload — inspect "
            "the native libraries per ABI.")
    if names == {"Web assets (assets/www)"}:
        ambiguities.append(
            "assets/www alone cannot separate a hybrid framework, "
            "a WebView wrapper, and bundled web content.")
    if "React Native" in names and any(
            h.startswith("React Native (new")
            for h in hints):
        for v in verdicts:
            if v["engine"] == "React Native" and v["detected"]:
                v["variant"] = "new architecture (Fabric/TurboModules)"
    # Unknown / custom engine: no engine was detected, but
    # the target carries substantial native code (see
    # UNKNOWN_MIN_LIBRARIES_WITH_EXPORTS). The outcome is an
    # explicit unknown record carrying the native evidence —
    # the affirmative plain-native label below is replaced
    # by it, not duplicated alongside it. A target with no
    # (or only a single small) native library gets no such
    # record and its output is unchanged.
    unknown_engine = bool(
        not names
        and jni["libraries_with_exports"]
        >= UNKNOWN_MIN_LIBRARIES_WITH_EXPORTS)
    if unknown_engine:
        inventory = ", ".join(jni["libraries"][:5])
        verdicts.append({
            "engine": "Unknown / custom engine",
            "detected": False,
            "confidence": "low",
            "score": 0,
            "version": None,
            "recommended_next": None,
            "unknown_engine": True,
            "indicators": [
                {"kind": "native-inventory",
                 "detail": f"{jni['libraries_with_exports']} "
                           f"native libraries with exports "
                           f"(of {jni['libraries_scanned']} "
                           f"scanned): {inventory}"},
                {"kind": "native-exports",
                 "detail": "export-carrying native libraries "
                           "present, with no known engine "
                           "family signatures in any channel"},
                {"kind": "anative-activity",
                 "detail": "ANativeActivity_onCreate exported"
                           if jni["anative_activity"] else
                           "ANativeActivity_onCreate not "
                           "exported"},
            ]})
    verdicts.sort(key=lambda v: -v["score"])
    jni_scan = {
        "libraries_scanned": jni["libraries_scanned"],
        "libraries_with_exports":
            jni["libraries_with_exports"],
        "anative_activity_oncreate":
            jni["anative_activity"],
        # ANativeActivity_onCreate with no family JNI
        # match and no detected engine is a plain
        # native app: identified as native, never
        # scored as an engine. When the unknown-engine
        # record above fires, that label is replaced:
        # native_no_engine is false and unknown_engine
        # is true instead.
        "native_no_engine": bool(
            jni["anative_activity"] and not names
            and not unknown_engine)}
    if unknown_engine:
        jni_scan["unknown_engine"] = True
    report = {"tool": "nar-engines", "version": "3.0.3",
              "target": os.path.abspath(apk_path),
              "target_sha256": sha256_of(apk_path),
              "verdicts": verdicts, "ambiguities": ambiguities,
              "jni_scan": jni_scan}
    if resolved is not None:
        report["container"] = resolved.container_block()
    return report


def human(report):
    print(f"NAR engine detection: "
          f"{os.path.basename(report['target'])}")
    print("=" * 60)
    if not report["verdicts"]:
        print("No engine indicators found (native Android or an "
              "engine without known signatures).")
    for v in report["verdicts"]:
        if v.get("unknown_engine"):
            state = ("UNKNOWN — substantial native code with "
                     "no known engine signatures; a custom "
                     "or unknown engine is possible")
        elif v["detected"]:
            state = "DETECTED"
        else:
            state = "weak candidate"
        print(f"- {v['engine']}: {state} "
              f"(confidence {v['confidence']}, score {v['score']})")
        if v.get("version"):
            print(f"    version evidence: {v['version']}")
        if v.get("variant"):
            print(f"    variant: {v['variant']}")
        for ind in v["indicators"]:
            print(f"    [{ind['kind']}] {ind['detail']}")
        if v.get("recommended_next"):
            print(f"    next: {v['recommended_next']}")
    scan = report.get("jni_scan") or {}
    if scan.get("native_no_engine"):
        print("- Native (no engine): ANativeActivity_onCreate "
              "exported and no engine-family JNI symbols found")
    for amb in report["ambiguities"]:
        print(f"ambiguity: {amb}")


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Multi-indicator engine detection with "
                    "confidence scores and stated ambiguities.")
    p.add_argument("apk", help="path to the .apk file")
    p.add_argument("--json", action="store_true")
    p.add_argument("--deep", action="store_true",
                   help="also run the matching deep-dive tool "
                        "for each detected engine")
    p.add_argument("--work", metavar="DIR",
                   help="work dir for deep-dive outputs "
                        "(keeps large dumper output off /tmp)")
    args = p.parse_args(argv)
    try:
        report = fuse(args.apk, args.deep, args.work)
    except (FileNotFoundError, RuntimeError) as e:
        print(f"nar-engines: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        human(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
