#!/usr/bin/env python3
"""nar-engines.py: multi-indicator engine/framework detection
with confidence (brief section 5).

Fuses independent evidence instead of trusting any single
signature:

- nar-triage path signatures (native libraries, payload files),
- triage binary-header version evidence,
- triage DEX content markers (corroboration),
- a direct layout pass of its own (IoStore containers, Unity
  Data layout, Flutter assets, Hermes bundles, Godot packs),
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

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import subprocess
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib.hashing import sha256_of  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))

# Canonical engine -> the triage hint names that feed it, the
# deep-dive tool that confirms it, and version keys in triage's
# engine_versions block.
ENGINES = {
    "Unity (IL2CPP)": {
        "hints": ["Unity (IL2CPP)"], "deep": "nar-il2cpp.py",
        "version_keys": ["unity_metadata_version"]},
    "Unity (Mono)": {
        "hints": ["Unity (Mono)"], "deep": None,
        "version_keys": []},
    "Unreal Engine": {
        "hints": ["Unreal Engine"], "deep": "nar-unreal.py",
        "version_keys": ["unreal_version", "unreal_engine"]},
    "Godot": {
        "hints": ["Godot"], "deep": "nar-godot.py",
        "version_keys": ["godot_version"]},
    "Flutter": {
        "hints": ["Flutter"], "deep": "nar-flutter.py",
        "version_keys": []},
    "React Native": {
        "hints": ["React Native", "React Native (new architecture)"],
        "deep": "nar-rn.py", "version_keys": []},
    "Cocos2d-x": {"hints": ["Cocos2d-x"], "deep": None,
                  "version_keys": []},
    "libGDX": {"hints": ["libGDX"], "deep": None, "version_keys": []},
    "Adobe AIR": {"hints": ["Adobe AIR"], "deep": None,
                  "version_keys": []},
    "Xamarin / .NET": {"hints": ["Xamarin / .NET"], "deep": None,
                       "version_keys": []},
    "Cordova (hybrid)": {"hints": ["Cordova (hybrid)"], "deep": None,
                         "version_keys": []},
    "Capacitor (hybrid)": {"hints": ["Capacitor (hybrid)"],
                           "deep": None, "version_keys": []},
    "Qt for Android": {"hints": ["Qt for Android"], "deep": None,
                       "version_keys": []},
    "Defold": {"hints": ["Defold"], "deep": None, "version_keys": []},
    "Ren'Py": {"hints": ["Ren'Py"], "deep": None, "version_keys": []},
    "RPG Maker (web export)": {"hints": ["RPG Maker (web export)"],
                               "deep": None, "version_keys": []},
    "Embedded Python": {"hints": ["Embedded Python"], "deep": None,
                        "version_keys": []},
    "Web assets (assets/www)": {"hints": ["Web assets (assets/www)"],
                                "deep": None, "version_keys": []},
}
STRONG_MARKERS = (".so", ".dat", ".pak", ".pck", "application.xml",
                  "capacitor.config", "cordova.js", "cordova-",
                  "phonegap", "assemblies/",
                  # Engine-unique payload names: a compiled Ren'Py
                  # script or an RPG Maker core runtime script is
                  # shipped by exactly one engine, so a single hit
                  # is strong evidence, not a weak path hint.
                  ".rpyc", "rpg_core.js", "rmmz_core.js")


def run_json_tool(script, args, timeout=1800):
    cmd = [sys.executable, os.path.join(HERE, script)] + args + ["--json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
        return json.loads(proc.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def layout_evidence(apk_path):
    """Direct ZIP-layout indicators computed by this tool."""
    ev = {}
    try:
        with zipfile.ZipFile(apk_path) as zf:
            names = zf.namelist()
    except zipfile.BadZipFile:
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
    triage = run_json_tool("nar-triage.py", [apk_path])
    if triage is None:
        raise RuntimeError("nar-triage failed on this input")
    layout = layout_evidence(apk_path)
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
        if deep and spec["deep"] and verdict["detected"]:
            deep_args = [apk_path]
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
    verdicts.sort(key=lambda v: -v["score"])
    return {"tool": "nar-engines", "version": "2.5.2",
            "target": os.path.abspath(apk_path),
            "target_sha256": sha256_of(apk_path),
            "verdicts": verdicts, "ambiguities": ambiguities}


def human(report):
    print(f"NAR engine detection: "
          f"{os.path.basename(report['target'])}")
    print("=" * 60)
    if not report["verdicts"]:
        print("No engine indicators found (native Android or an "
              "engine without known signatures).")
    for v in report["verdicts"]:
        state = "DETECTED" if v["detected"] else "weak candidate"
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
