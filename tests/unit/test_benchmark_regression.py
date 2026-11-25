"""2.6.2 WS-D3 — regression-gate comparison logic.

Synthetic baseline pairs only: a memory regression beyond
the threshold must be caught, noise within the threshold
must be tolerated, timing swings must warn but never fail,
and missing keys must be reported as skips, not crashes or
silent passes of the affected comparison.
"""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load():
    spec = importlib.util.spec_from_file_location(
        "check_regression",
        str(ROOT / "tests" / "benchmarks" / "check_regression.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cr = _load()


def _baseline(peak=1_500_000_000, role="FIX_BIG", wall=100.0,
              matrix_peak=None, runs_seconds=10.0):
    doc = {"memory": {"status": "measured",
                      "fixture_role": role,
                      "peak_rss_bytes": peak,
                      "wall_seconds": wall},
           "runs": [{"fixture_role": "app", "module": "nar-dex.py",
                     "seconds": runs_seconds, "exit_code": 0}]}
    if matrix_peak is not None:
        doc["benchmark_matrix"] = [{
            "fixture_role": role, "size_class": "large",
            "peak_rss_bytes": matrix_peak,
            "wall_seconds": wall, "status": "completed"}]
    return doc


def test_memory_regression_caught():
    report = cr.compare_baselines(
        _baseline(), _baseline(peak=1_700_000_000))
    assert report["verdict"] == "fail"
    assert any("regressed" in f for f in report["failures"])
    assert report["memory"]["delta_ratio"] > 0.05


def test_memory_noise_tolerated():
    report = cr.compare_baselines(
        _baseline(), _baseline(peak=1_530_000_000))  # +2%
    assert report["verdict"] == "pass"
    assert report["failures"] == []


def test_memory_improvement_passes():
    report = cr.compare_baselines(
        _baseline(), _baseline(peak=1_200_000_000))
    assert report["verdict"] == "pass"


def test_timing_swing_warns_never_fails():
    report = cr.compare_baselines(
        _baseline(wall=100.0, runs_seconds=10.0),
        _baseline(wall=400.0, runs_seconds=40.0))
    assert report["verdict"] == "pass"
    assert any("timing" in w or "wall time" in w
               for w in report["warnings"])


def test_missing_memory_block_is_skip_not_failure():
    report = cr.compare_baselines({"runs": []}, _baseline())
    assert report["verdict"] == "pass"
    assert any("memory" in s for s in report["skips"])


def test_unmeasured_memory_is_skip():
    ref = _baseline()
    ref["memory"] = {"status": "not_run", "reason": "x"}
    report = cr.compare_baselines(ref, _baseline())
    assert report["verdict"] == "pass"
    assert report["skips"]


def test_role_mismatch_is_skip_not_comparison():
    report = cr.compare_baselines(
        _baseline(role="FIX_A"), _baseline(role="FIX_B"))
    assert report["verdict"] == "pass"
    assert any("roles differ" in s for s in report["skips"])
    assert report["memory"]["delta_ratio"] is None


def test_matrix_case_memory_regression_caught():
    report = cr.compare_baselines(
        _baseline(matrix_peak=500_000_000),
        _baseline(matrix_peak=600_000_000))
    assert report["verdict"] == "fail"
    assert any("matrix case" in f for f in report["failures"])


def test_matrix_case_missing_on_one_side_skips():
    report = cr.compare_baselines(
        _baseline(matrix_peak=500_000_000), _baseline())
    assert report["verdict"] == "pass"
    assert any("matrix case" in s for s in report["skips"])


def test_threshold_is_configurable():
    report = cr.compare_baselines(
        _baseline(), _baseline(peak=1_620_000_000),  # +8%
        memory_threshold=0.10)
    assert report["verdict"] == "pass"
    report = cr.compare_baselines(
        _baseline(), _baseline(peak=1_620_000_000),
        memory_threshold=0.05)
    assert report["verdict"] == "fail"
