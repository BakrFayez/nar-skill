"""2.6.2 WS-E — accuracy corpus + scoring discipline.

Synthetic inputs only: cross-labeling must produce a
negative for every other family, scoring must count
unclassified positives as misses while reporting them
separately, and rates with zero denominators must be
null rather than invented.
"""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "accuracy"))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("accuracy_corpus", ROOT / "tests" / "accuracy" / "corpus.py")
runner = _load("accuracy_runner", ROOT / "tests" / "accuracy" / "run_accuracy.py")


def test_cross_labeling_produces_negatives():
    samples = corpus.real_engine_samples({"FIX_UNITY", "FIX_FLUTTER"})
    unity = [s for s in samples if s["role"] == "FIX_UNITY"]
    positives = [s for s in unity if s["polarity"] == "positive"]
    negatives = [s for s in unity if s["polarity"] == "negative"]
    assert len(positives) == 1 and positives[0]["expected"] == "Unity"
    assert {s["expected"] for s in negatives} == (
        set(corpus.ENGINE_FAMILIES) - {"Unity"})
    assert all(s["ground_truth_source"] == "cross-label"
               for s in negatives)


def test_unbound_roles_produce_no_samples():
    assert corpus.real_engine_samples(set()) == []
    assert corpus.real_format_samples(set()) == []


def test_scoring_counts_and_rates():
    samples = [
        {"polarity": "positive"}, {"polarity": "positive"},
        {"polarity": "negative"}, {"polarity": "negative"}]
    calls = iter([True, False, True, False])
    block = runner.score_binary(samples, lambda s: next(calls))
    assert (block["tp"], block["fn"], block["fp"], block["tn"]) == (1, 1, 1, 1)
    assert block["precision"] == 0.5 and block["recall"] == 0.5
    assert block["f1"] == 0.5 and block["accuracy"] == 0.5
    assert block["fpr"] == 0.5 and block["fnr"] == 0.5


def test_unclassified_positive_is_miss_and_reported():
    samples = [{"polarity": "positive"}, {"polarity": "negative"}]
    block = runner.score_binary(samples, lambda s: None)
    assert block["unclassified"] == 2
    assert block["fn"] == 1 and block["recall"] == 0.0


def test_zero_denominator_rates_are_null():
    block = runner.binary_block({"samples": 0, "positives": 0,
                                 "negatives": 0, "tp": 0, "fp": 0,
                                 "fn": 0, "tn": 0, "unclassified": 0})
    assert block["precision"] is None and block["recall"] is None
    assert block["accuracy"] is None and block["f1"] is None


def test_endpoint_samples_cover_every_class():
    samples = corpus.synthetic_endpoint_samples()
    assert {s["expected"] for s in samples} == {
        "sensitive", "third-party", "dex-string", "potential",
        "unused-candidate", "unverified"}
    assert all(s["dataset"] == "synthetic" for s in samples)
