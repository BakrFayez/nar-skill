#!/usr/bin/env python3
"""run_accuracy.py: per-analyzer accuracy metrics (2.6.2 WS-E2).

Computes, per analyzer, samples / positives / negatives /
TP / FP / FN / TN / unclassified + precision / recall / F1 /
accuracy / FPR / FNR, with a confusion matrix for the
multiclass format analyzer. Synthetic and real corpora are
ALWAYS reported separately. An analyzer without defensible
ground truth is reported NOT MEASURED with the reason —
no estimate is ever substituted.

Ground truth (tests/accuracy/corpus.py):
- synthetic: builder intent / construction;
- real: role bindings from prior verified analysis plus
  cross-labeling (a fixture of one engine family is a
  negative for the other families; clean fixtures are
  negatives for protection attribution).

The output JSON contains role labels and counts only —
never fixture file names, paths, or hashes.

Usage:
    python3 tests/accuracy/run_accuracy.py [--out FILE]

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
SCRIPTS = os.path.join(ROOT, "scripts")
FIXTURES = os.environ.get("NAR_FIXTURES",
                          os.path.expanduser(
                              "~/workspace/nar-e2e-fixtures"))
sys.path.insert(0, os.path.join(ROOT, "tests", "accuracy"))
sys.path.insert(0, os.path.join(ROOT, "tests"))
import corpus  # noqa: E402


def _load_module(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(SCRIPTS, filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def run_json(script, args):
    proc = subprocess.run(
        [sys.executable, os.path.join(SCRIPTS, script)] + args,
        capture_output=True, text=True, timeout=3600)
    try:
        return json.loads(proc.stdout)
    except (ValueError, TypeError):
        return None


def binary_block(counts):
    """counts: dict with tp/fp/fn/tn/unclassified/samples/
    positives/negatives. Adds the rate metrics; a rate with
    a zero denominator is None, never invented."""
    tp, fp = counts["tp"], counts["fp"]
    fn, tn = counts["fn"], counts["tn"]

    def rate(num, den):
        return round(num / den, 4) if den else None
    precision = rate(tp, tp + fp)
    recall = rate(tp, tp + fn)
    f1 = None
    if precision is not None and recall is not None and (
            precision + recall) > 0:
        f1 = round(2 * precision * recall / (precision + recall), 4)
    return {**counts, "precision": precision, "recall": recall,
            "f1": f1,
            "accuracy": rate(tp + tn, tp + fp + fn + tn),
            "fpr": rate(fp, fp + tn), "fnr": rate(fn, fn + tp)}


def _empty():
    return {"samples": 0, "positives": 0, "negatives": 0,
            "tp": 0, "fp": 0, "fn": 0, "tn": 0,
            "unclassified": 0}


def score_binary(samples, predict):
    """predict(sample) -> True (positive call), False
    (negative call), or None (unclassified / tool failure).
    Unclassified positives count as FN-side misses for
    recall honesty: they are reported separately AND as fn.
    (fn here = missed positives including unclassified.)"""
    counts = _empty()
    for s in samples:
        counts["samples"] += 1
        counts["positives" if s["polarity"] == "positive"
               else "negatives"] += 1
        got = predict(s)
        if got is None:
            counts["unclassified"] += 1
            if s["polarity"] == "positive":
                counts["fn"] += 1
            else:
                counts["tn"] += 1
        elif got and s["polarity"] == "positive":
            counts["tp"] += 1
        elif got and s["polarity"] == "negative":
            counts["fp"] += 1
        elif not got and s["polarity"] == "positive":
            counts["fn"] += 1
        else:
            counts["tn"] += 1
    return binary_block(counts)


def engine_section(env):
    roles = {r for r, p in env.items()
             if p and os.path.isfile(p)}
    samples = corpus.real_engine_samples(roles)
    if not samples:
        return {"status": "not_measured",
                "reason": "no engine-labeled real fixtures "
                          "bound in the local manifest"}
    verdict_cache = {}

    def detected(role):
        if role not in verdict_cache:
            doc = run_json("nar-engines.py",
                           [env[role], "--json"])
            verdict_cache[role] = (
                {v.get("engine") for v in doc.get("verdicts", [])
                 if v.get("detected")} if doc else None)
        return verdict_cache[role]

    def predict(sample):
        got = detected(sample["role"])
        if got is None:
            return None
        return bool(got & corpus.FAMILY_VERDICTS[
            sample["expected"]])
    block = score_binary(samples, predict)
    block.update({"status": "measured", "dataset": "real",
                  "definition": "per-family binary detection "
                                "(nar-engines detected verdict "
                                "in the family); negatives are "
                                "cross-labeled fixtures of "
                                "other families"})
    return block


def framework_section():
    synth_dir = os.path.join(FIXTURES, "frameworks")
    stems = set()
    if os.path.isdir(synth_dir):
        stems = {os.path.splitext(f)[0]
                 for f in os.listdir(synth_dir)
                 if f.endswith(".apk")}
    samples = corpus.synthetic_framework_samples(stems)
    if not samples:
        return {"status": "not_measured",
                "reason": "synthetic framework corpus not "
                          "present locally"}
    cache = {}

    def detected(stem):
        if stem not in cache:
            doc = run_json("nar-engines.py", [
                os.path.join(synth_dir, stem + ".apk"), "--json"])
            cache[stem] = (
                {v.get("engine") for v in doc.get("verdicts", [])
                 if v.get("detected")} if doc else None)
        return cache[stem]

    def predict(sample):
        got = detected(sample["role"])
        if got is None:
            return None
        return sample["expected"] in got
    block = score_binary(samples, predict)
    block.update({"status": "measured", "dataset": "synthetic",
                  "definition": "per-framework binary "
                                "detection; negatives are "
                                "cross-labeled fixtures of "
                                "other frameworks"})
    return block


def format_section(env):
    roles = {r for r, p in env.items()
             if p and os.path.isfile(p)}
    real_samples = corpus.real_format_samples(roles)
    sections = {}
    for dataset, samples, paths in (
            ("real", real_samples,
             {s["role"]: env.get(s["role"]) for s in real_samples}),
    ):
        if not samples:
            sections[dataset] = {
                "status": "not_measured",
                "reason": "no format-labeled fixtures bound"}
            continue
        confusion = {}
        correct = 0
        unclassified = 0
        for s in samples:
            doc = run_json("nar-input.py",
                           ["identify", paths[s["role"]], "--json"])
            got = doc.get("format") if doc else None
            if got is None:
                unclassified += 1
                got = "<unclassified>"
            if got == s["expected"]:
                correct += 1
            row = confusion.setdefault(s["expected"], {})
            row[got] = row.get(got, 0) + 1
        sections[dataset] = {
            "status": "measured", "dataset": dataset,
            "samples": len(samples), "correct": correct,
            "unclassified": unclassified,
            "accuracy": round(correct / len(samples), 4),
            "confusion_matrix": confusion}
    # Synthetic format corpus from the repo builders.
    try:
        import synthetic_fixtures
        with tempfile.TemporaryDirectory() as td:
            synthetic_fixtures.generate(td)
            present = {f for f in os.listdir(td)}
            samples = corpus.synthetic_format_samples(present)
            confusion = {}
            correct = 0
            unclassified = 0
            for s in samples:
                doc = run_json("nar-input.py", [
                    "identify", os.path.join(td, s["role"]),
                    "--json"])
                got = doc.get("format") if doc else None
                if got is None:
                    unclassified += 1
                    got = "<unclassified>"
                if got == s["expected"]:
                    correct += 1
                row = confusion.setdefault(s["expected"], {})
                row[got] = row.get(got, 0) + 1
            sections["synthetic"] = {
                "status": "measured", "dataset": "synthetic",
                "samples": len(samples), "correct": correct,
                "unclassified": unclassified,
                "accuracy": (round(correct / len(samples), 4)
                             if samples else None),
                "confusion_matrix": confusion}
    except ImportError as e:
        sections["synthetic"] = {
            "status": "not_measured",
            "reason": f"synthetic fixture builders not "
                      f"importable: {e}"}
    return sections


def protection_section(env):
    roles = {r for r, p in env.items()
             if p and os.path.isfile(p)}
    clean = [p for p in env.get("FIX_CLEAN_SET", "").split()
             if os.path.isfile(p)]
    # Clean-set entries are local paths; their role label is
    # the clean-set membership itself. They are scored via
    # paths, keyed by a synthetic role label.
    samples = corpus.real_protection_samples(roles, [])
    path_by_role = {r: env.get(r) for r in roles}
    extra = []
    for i, path in enumerate(clean):
        label = f"FIX_CLEAN_SET[{i}]"
        extra.append({"id": f"real-protection-clean-{i}",
                      "analyzer": "protection", "dataset": "real",
                      "role": label,
                      "expected": "attributed-commercial-packer",
                      "polarity": "negative",
                      "ground_truth_source": "cross-label",
                      "verification_status": "verified"})
        path_by_role[label] = path
    samples = samples + extra
    if not any(s["polarity"] == "positive" for s in samples):
        return {"status": "not_measured",
                "reason": "protected fixture not bound in "
                          "the local manifest"}

    def predict(sample):
        doc = run_json("nar-triage.py",
                       [path_by_role[sample["role"]], "--json"])
        if doc is None:
            return None
        return any(f.get("category") == "commercial_packer"
                   and f.get("attributed")
                   for f in doc.get("protections", []))
    block = score_binary(samples, predict)
    block.update({"status": "measured", "dataset": "real",
                  "definition": "an attributed commercial_packer "
                                "finding in nar-triage output; "
                                "negatives are the clean set "
                                "plus cross-labeled fixtures"})
    return block


def endpoint_section():
    net = _load_module("nar_network_accuracy", "nar-network.py")
    samples = corpus.synthetic_endpoint_samples()
    confusion = {}
    correct = 0
    for s in samples:
        got, _host, _kind = net.classify(s["url"], s["sources"])
        if got == s["expected"]:
            correct += 1
        row = confusion.setdefault(s["expected"], {})
        row[got] = row.get(got, 0) + 1
    return {
        "synthetic": {
            "status": "measured", "dataset": "synthetic",
            "samples": len(samples), "correct": correct,
            "accuracy": round(correct / len(samples), 4),
            "confusion_matrix": confusion,
            "definition": "nar-network classify() against "
                          "construction-defined labels; "
                          "measures rule consistency, weaker "
                          "than independent human labeling"},
        "real": {
            "status": "not_measured",
            "reason": "no independently labeled endpoint "
                      "corpus exists locally: ground truth "
                      "would require hand-labeled URL "
                      "classifications for real apps, and "
                      "none is recorded"}}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", metavar="FILE")
    args = p.parse_args(argv)
    env = manifest_env()
    local_samples, local_note = corpus.load_local_labeling(FIXTURES)
    results = {
        "methodology": (
            "Per-analyzer binary/multiclass scoring against "
            "labeled corpora (tests/accuracy/corpus.py). "
            "Synthetic and real corpora are reported "
            "separately and never pooled. Real labels: role "
            "bindings from prior verified analysis plus "
            "cross-labeling. Output carries role labels and "
            "counts only. " + local_note +
            (f"; local labeling file supplied "
             f"{len(local_samples)} samples (merged by the "
             "operator; derived bindings above are computed "
             "from the same role bindings)" if local_samples
             else "")),
        "analyzers": {
            "engine_identification": engine_section(env),
            "framework_detection": framework_section(),
            "format_identification": format_section(env),
            "protection_attribution": protection_section(env),
            "endpoint_classification": endpoint_section(),
            "native_library_identification": {
                "status": "not_measured",
                "reason": "no labeled native-library corpus "
                          "is recorded locally: ground truth "
                          "would require per-fixture verified "
                          "library inventories, and none is "
                          "recorded; library lists are reported "
                          "per case, unmeasured"},
            "security_finding_classification": {
                "status": "not_measured",
                "reason": "no labeled security-findings "
                          "corpus exists locally: findings "
                          "are deterministic rule outputs and "
                          "no independent ground-truth labels "
                          "(which findings SHOULD fire on which "
                          "fixture) are recorded; inventing "
                          "them from the rules themselves would "
                          "be circular"},
        },
    }
    text = json.dumps(results, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
