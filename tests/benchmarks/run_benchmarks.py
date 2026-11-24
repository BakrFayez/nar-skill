#!/usr/bin/env python3
"""run_benchmarks.py: measured module timings, accuracy
metrics, and peak memory on local fixtures.

Runs a fixed module set against the local fixture roles
(demo / app / game / engine samples bound through
$NAR_FIXTURES + manifest.env, the same pattern as the e2e
harness) and records wall-clock seconds per run. Numbers
are measured on the machine that runs this script and are
reported as-is; nothing is estimated or extrapolated.

Since evolution Phase 11 the runner also computes
accuracy metrics from the labeled fixture corpora that
actually exist locally (protection attribution, engine
detection, format identification — synthetic and real
corpora reported separately, role labels only, never
file names) and measures peak memory for a full
nar-analyze run on the largest local fixture. Any metric
whose labeled corpus is not bound locally is reported
NOT RUN with the reason, never estimated. Methodology:
references/benchmarks.md.

Usage:
    python3 tests/benchmarks/run_benchmarks.py [--out FILE]
        [--no-metrics] [--no-memory]

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import resource
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
SCRIPTS = os.path.join(ROOT, "scripts")
FIXTURES = os.environ.get("NAR_FIXTURES",
                          os.path.expanduser(
                              "~/workspace/nar-e2e-fixtures"))

MODULES = ["nar-triage.py", "nar-fingerprint.py",
           "nar-engines.py", "nar-dex.py", "nar-native.py",
           "nar-network.py", "nar-assets.py"]

# Labeled corpora (role labels only in the output).
ENGINE_LABELS_REAL = {
    "FIX_UNITY": {"Unity (IL2CPP)", "Unity (Mono)"},
    "FIX_UNITY_BUNDLES": {"Unity (IL2CPP)", "Unity (Mono)"},
    "FIX_FLUTTER": {"Flutter"},
    "FIX_RN": {"React Native"},
    "FIX_GAME_UNREAL": {"Unreal Engine"},
    "FIX_GODOT_LOOSE": {"Godot"},
}
ENGINE_LABELS_SYNTHETIC = {
    "xamarin": "Xamarin / .NET",
    "cordova": "Cordova (hybrid)",
    "capacitor": "Capacitor (hybrid)",
    "qt": "Qt for Android",
    "defold": "Defold",
    "renpy": "Ren'Py",
    "rpgmaker": "RPG Maker (web export)",
    "kivy": "Embedded Python",
}
FORMAT_LABELS_REAL = {
    "FIX_APP": "apk", "FIX_GAME": "apk", "FIX_UNITY": "apk",
    "FIX_UNITY_BUNDLES": "apk", "FIX_FLUTTER": "apk",
    "FIX_RN": "apk", "FIX_GAME_UNREAL": "apk",
    "FIX_GODOT_LOOSE": "apk", "FIX_XAPK": "xapk",
    "FIX_GODOT_PCK": "godot-pck",
}

# Synthetic format corpus (2.6.1 accuracy extension):
# files written by tests/synthetic_fixtures.py, labeled by
# the format each builder constructs. The uasset/Zen
# builders are excluded — nar-input has no uasset format
# id (those files are identified by nar-unreal, a
# different surface), so labeling them here would grade
# the wrong tool.
FORMAT_LABELS_SYNTHETIC = {
    "synthetic.dex": "dex",
    "libsynthetic.so": "elf",
    "synthetic.pck": "godot-pck",
    "synthetic.pak": "unreal-pak",
    "synthetic.utoc": "unreal-iostore",
}


def manifest_env():
    env = {}
    manifest = os.path.join(FIXTURES, "manifest.env")
    if os.path.isfile(manifest):
        for line in open(manifest, encoding="utf-8"):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'") \
                    .replace("${NAR_FIXTURES}", FIXTURES) \
                    .replace("$NAR_FIXTURES", FIXTURES)
    return env


def fixture_roles():
    roles = {}
    demo = os.path.join(FIXTURES, "demo", "NarDemo.apk")
    if os.path.isfile(demo):
        roles["demo (synthetic, ~29 KB)"] = demo
    env = manifest_env()
    for role, key in (("app (manifest FIX_APP)", "FIX_APP"),
                      ("game (manifest FIX_GAME)", "FIX_GAME"),
                      ("unity (manifest FIX_UNITY)", "FIX_UNITY")):
        path = env.get(key)
        if path and os.path.isfile(path):
            roles[role] = path
    return roles


def timed(script, target):
    started = time.time()
    proc = subprocess.run(
        [sys.executable, os.path.join(SCRIPTS, script), target],
        capture_output=True, text=True, timeout=3600)
    return round(time.time() - started, 2), proc.returncode


def run_json(script, args):
    proc = subprocess.run(
        [sys.executable, os.path.join(SCRIPTS, script)] + args,
        capture_output=True, text=True, timeout=3600)
    try:
        return json.loads(proc.stdout)
    except (ValueError, TypeError):
        return None


def measure_peak_memory(env):
    """Peak RSS of a full nar-analyze run on the largest
    locally bound fixture. MUST be called before any other
    child process runs: RUSAGE_CHILDREN ru_maxrss is the
    maximum over all terminated children of this process,
    so a first-run measurement attributes the peak to the
    nar-analyze child alone. The figure is the nar-analyze
    process's own peak; its stage subprocesses are
    grandchildren and are not included (see
    references/benchmarks.md)."""
    candidates = {}
    demo = os.path.join(FIXTURES, "demo", "NarDemo.apk")
    if os.path.isfile(demo):
        candidates["DEMO"] = demo
    for key, path in env.items():
        if path and os.path.isfile(path):
            candidates[key] = path
    if not candidates:
        return {"status": "not_run",
                "reason": "no fixture files bound locally"}
    role, target = max(candidates.items(),
                       key=lambda kv: os.path.getsize(kv[1]))
    out = tempfile.mkdtemp(prefix="nar-bench-case-")
    started = time.time()
    try:
        proc = subprocess.run(
            [sys.executable,
             os.path.join(SCRIPTS, "nar-analyze.py"),
             target, "--out", out],
            capture_output=True, text=True, timeout=3600)
        peak_kb = resource.getrusage(
            resource.RUSAGE_CHILDREN).ru_maxrss
        return {
            "status": "measured",
            "fixture_role": role,
            "size_bytes": os.path.getsize(target),
            "peak_rss_bytes": int(peak_kb) * 1024,
            "wall_seconds": round(time.time() - started, 2),
            "exit_code": proc.returncode,
            "scope": "peak RSS of the nar-analyze process "
                     "itself (RUSAGE_CHILDREN, measured "
                     "before any other child ran); stage "
                     "subprocess peaks are excluded",
        }
    finally:
        shutil.rmtree(out, ignore_errors=True)


def protection_metrics(env):
    """Attributed commercial-packer detection: the one
    protected fixture must be detected (recall side) and
    the clean set must stay at zero (precision side)."""
    protected = env.get("FIX_PAIRIP")
    clean = env.get("FIX_CLEAN_SET", "").split()
    if not protected or not os.path.isfile(protected) or not clean:
        return {"status": "not_run",
                "reason": "protection fixtures (protected + "
                          "clean set) not bound in the local "
                          "manifest"}
    doc = run_json("nar-triage.py", [protected, "--json"])
    detected = bool(doc and any(
        f.get("category") == "commercial_packer"
        and f.get("attributed")
        for f in doc.get("protections", [])))
    false_positives = 0
    checked = 0
    for path in clean:
        if not os.path.isfile(path):
            continue
        checked += 1
        doc = run_json("nar-triage.py", [path, "--json"])
        if doc and any(f.get("category") == "commercial_packer"
                       and f.get("attributed")
                       for f in doc.get("protections", [])):
            false_positives += 1
    tp = 1 if detected else 0
    return {
        "status": "measured", "corpus": "real",
        "definition": "an attributed commercial_packer "
                      "finding in nar-triage --json output",
        "protected_fixtures": 1, "protected_detected": tp,
        "clean_fixtures": checked,
        "clean_false_positives": false_positives,
        "precision": (tp / (tp + false_positives)
                      if tp + false_positives else None),
        "recall": tp / 1,
    }


def _engine_detected(path, expected):
    doc = run_json("nar-engines.py", [path, "--json"])
    if not doc:
        return False
    return any(v.get("detected") and v.get("engine") in expected
               for v in doc.get("verdicts", []))


def engine_metrics(env):
    real = {"labeled": 0, "detected": 0, "per_role": {}}
    for role, expected in ENGINE_LABELS_REAL.items():
        path = env.get(role)
        if path and os.path.isfile(path):
            hit = _engine_detected(path, expected)
            real["labeled"] += 1
            real["detected"] += 1 if hit else 0
            real["per_role"][role] = (
                "detected" if hit else "missed")
    if real["labeled"]:
        real["status"] = "measured"
        real["recall_on_labeled_positives"] = (
            real["detected"] / real["labeled"])
    else:
        real = {"status": "not_run",
                "reason": "no engine-labeled real fixtures "
                          "bound in the local manifest"}
    synth_dir = os.path.join(FIXTURES, "frameworks")
    synth = {"labeled": 0, "matched": 0, "per_label": {}}
    for stem, verdict in ENGINE_LABELS_SYNTHETIC.items():
        path = os.path.join(synth_dir, stem + ".apk")
        if os.path.isfile(path):
            hit = _engine_detected(path, {verdict})
            synth["labeled"] += 1
            synth["matched"] += 1 if hit else 0
            synth["per_label"][verdict] = (
                "detected" if hit else "missed")
    if synth["labeled"]:
        synth["status"] = "measured"
        synth["accuracy"] = synth["matched"] / synth["labeled"]
    else:
        synth = {"status": "not_run",
                 "reason": "synthetic framework corpus not "
                           "present locally"}
    return {
        "real": real, "synthetic": synth,
        "real_precision": "NOT RUN — no labeled "
                          "engine-negative real corpus exists "
                          "locally, so real-corpus precision "
                          "cannot be computed",
    }


def format_metrics(env):
    labeled = 0
    correct = 0
    per_role = {}
    for role, expected in FORMAT_LABELS_REAL.items():
        path = env.get(role)
        if path and os.path.isfile(path):
            doc = run_json("nar-input.py",
                           ["identify", path, "--json"])
            got = doc.get("format") if doc else None
            labeled += 1
            ok = got == expected
            correct += 1 if ok else 0
            per_role[role] = "correct" if ok else (
                f"identified as {got!r}, expected {expected!r}")
    if not labeled:
        return {"status": "not_run",
                "reason": "no format-labeled fixtures bound "
                          "in the local manifest"}
    return {"status": "measured", "corpus": "real",
            "labeled": labeled, "correct": correct,
            "accuracy": correct / labeled, "per_role": per_role}


def format_synthetic_metrics():
    """Format identification on the generated synthetic
    corpus (labels = the format each builder constructs)."""
    sys.path.insert(0, os.path.join(ROOT, "tests"))
    try:
        import synthetic_fixtures
    except ImportError as e:
        return {"status": "not_run",
                "reason": f"synthetic fixture builders not "
                          f"importable: {e}"}
    labeled = 0
    correct = 0
    per_file = {}
    with tempfile.TemporaryDirectory() as td:
        synthetic_fixtures.generate(td)
        for name, expected in FORMAT_LABELS_SYNTHETIC.items():
            path = os.path.join(td, name)
            if not os.path.isfile(path):
                per_file[name] = "not generated"
                continue
            doc = run_json("nar-input.py",
                           ["identify", path, "--json"])
            got = doc.get("format") if doc else None
            labeled += 1
            ok = got == expected
            correct += 1 if ok else 0
            per_file[name] = "correct" if ok else (
                f"identified as {got!r}, expected {expected!r}")
    if not labeled:
        return {"status": "not_run",
                "reason": "no synthetic format fixtures "
                          "were generated"}
    return {"status": "measured", "corpus": "synthetic",
            "labeled": labeled, "correct": correct,
            "accuracy": correct / labeled,
            "per_file": per_file}


def compute_metrics(env):
    return {
        "corpora_note": "role labels only; synthetic and "
                        "real corpora are always reported "
                        "separately",
        "protection_attribution": protection_metrics(env),
        "engine_detection": engine_metrics(env),
        "format_identification": format_metrics(env),
        "format_identification_synthetic":
            format_synthetic_metrics(),
        "endpoint_classification": {
            "status": "not_run",
            "reason": "no labeled endpoint corpus exists "
                      "locally: ground truth would require "
                      "hand-labeled URL classifications for "
                      "real apps, and none is recorded. The "
                      "network stage's classification is "
                      "rule-based; its per-case counts are "
                      "reported, but they are not measured "
                      "against ground truth and no accuracy "
                      "figure is claimed."},
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", metavar="FILE")
    p.add_argument("--no-metrics", action="store_true",
                   help="timings only (skip accuracy metrics)")
    p.add_argument("--no-memory", action="store_true",
                   help="skip the peak-memory measurement")
    args = p.parse_args(argv)
    env = manifest_env()
    results = {"machine": os.uname().sysname + " " +
               os.uname().machine,
               "python": sys.version.split()[0], "runs": []}
    # Memory first: RUSAGE_CHILDREN attribution (see the
    # measure_peak_memory docstring).
    if not args.no_memory:
        results["memory"] = measure_peak_memory(env)
        mem = results["memory"]
        if mem.get("status") == "measured":
            print(f"memory: nar-analyze on {mem['fixture_role']} "
                  f"({mem['size_bytes']:,} B): peak RSS "
                  f"{mem['peak_rss_bytes']:,} B, "
                  f"{mem['wall_seconds']}s")
        else:
            print(f"memory: NOT RUN ({mem.get('reason')})")
    roles = fixture_roles()
    for role, path in roles.items():
        size = os.path.getsize(path)
        for module in MODULES:
            seconds, rc = timed(module, path)
            results["runs"].append({
                "fixture_role": role, "size_bytes": size,
                "module": module, "seconds": seconds,
                "exit_code": rc})
            print(f"{role:28s} {module:22s} {seconds:8.2f}s "
                  f"(exit {rc})")
    if not args.no_metrics:
        results["metrics"] = compute_metrics(env)
        m = results["metrics"]
        prot = m["protection_attribution"]
        if prot.get("status") == "measured":
            print(f"metrics: protection (real): precision "
                  f"{prot['precision']}, recall {prot['recall']} "
                  f"({prot['clean_false_positives']} FP on "
                  f"{prot['clean_fixtures']} clean)")
        eng = m["engine_detection"]
        if eng["real"].get("status") == "measured":
            print(f"metrics: engines (real): recall "
                  f"{eng['real']['recall_on_labeled_positives']} "
                  f"on {eng['real']['labeled']} labeled")
        if eng["synthetic"].get("status") == "measured":
            print(f"metrics: engines (synthetic): accuracy "
                  f"{eng['synthetic']['accuracy']} on "
                  f"{eng['synthetic']['labeled']} labeled")
        fmt = m["format_identification"]
        if fmt.get("status") == "measured":
            print(f"metrics: formats (real): accuracy "
                  f"{fmt['accuracy']} on {fmt['labeled']} labeled")
        fmts = m["format_identification_synthetic"]
        if fmts.get("status") == "measured":
            print(f"metrics: formats (synthetic): accuracy "
                  f"{fmts['accuracy']} on {fmts['labeled']} "
                  "labeled")
        print("metrics: endpoint classification NOT RUN "
              "(no labeled endpoint corpus locally)")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
