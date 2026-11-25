#!/usr/bin/env python3
"""check_regression.py: benchmark regression gate (2.6.2 WS-D3).

Compares a fresh benchmark baseline (produced by
run_benchmarks.py) against a reference baseline and decides
whether the fresh run regressed.

Gate discipline:
- Peak RSS is the headline metric. A memory regression on
  the headline fixture beyond the stated threshold
  (default >5%) FAILS the gate with an actionable message.
- Wall-time differences are reported as WARNINGS only.
  Wall time on a shared box is load-dependent, so a timing
  difference never fails the gate (no flaky failures).
- Missing keys on either side are reported as SKIP lines,
  never silently treated as zero and never as failures:
  a comparison that cannot be made is stated, not faked.

Usage:
    python3 tests/benchmarks/check_regression.py \
        --reference tests/benchmarks/baseline-2.6.1.json \
        --candidate tests/benchmarks/baseline-2.6.2.json \
        [--memory-threshold 0.05]

Exit code: 0 = gate passes (warnings allowed),
1 = gate fails (memory regression beyond threshold),
2 = inputs unreadable.

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import sys

DEFAULT_MEMORY_THRESHOLD = 0.05


def _memory_peak(baseline):
    """(role, peak_bytes) from a baseline's memory block,
    or (None, None) when the block is absent/unmeasured."""
    mem = (baseline or {}).get("memory") or {}
    if mem.get("status") != "measured":
        return None, None
    peak = mem.get("peak_rss_bytes")
    if not isinstance(peak, int) or peak <= 0:
        return None, None
    return mem.get("fixture_role"), peak


def _matrix_cases(baseline):
    """Map (fixture_role, size_class) -> case dict from a
    baseline's optional benchmark_matrix block (2.6.2)."""
    out = {}
    for case in (baseline or {}).get("benchmark_matrix") or []:
        key = (case.get("fixture_role"), case.get("size_class"))
        out[key] = case
    return out


def compare_baselines(reference, candidate,
                      memory_threshold=DEFAULT_MEMORY_THRESHOLD):
    """Compare two baseline dicts. Returns a report dict:
    {verdict: "pass"|"fail", failures: [...], warnings: [...],
     skips: [...], memory: {...}}.

    Pure function over plain dicts so the logic is unit-
    testable with synthetic baseline pairs."""
    failures, warnings, skips = [], [], []

    ref_role, ref_peak = _memory_peak(reference)
    cand_role, cand_peak = _memory_peak(candidate)
    memory = {"reference_role": ref_role,
              "reference_peak_rss_bytes": ref_peak,
              "candidate_role": cand_role,
              "candidate_peak_rss_bytes": cand_peak,
              "threshold": memory_threshold,
              "delta_ratio": None}
    if ref_peak is None or cand_peak is None:
        skips.append(
            "memory: peak RSS not measured on one side "
            "(reference peak "
            f"{'present' if ref_peak else 'missing'}, candidate "
            f"peak {'present' if cand_peak else 'missing'}); "
            "memory gate not applied")
    elif ref_role != cand_role:
        skips.append(
            f"memory: headline fixture roles differ "
            f"(reference {ref_role!r} vs candidate "
            f"{cand_role!r}); peaks are not comparable and "
            "the memory gate is not applied")
    else:
        delta = (cand_peak - ref_peak) / ref_peak
        memory["delta_ratio"] = round(delta, 4)
        if delta > memory_threshold:
            failures.append(
                f"memory: peak RSS on {ref_role} regressed "
                f"by {delta:.1%}: {ref_peak:,} B -> "
                f"{cand_peak:,} B (threshold "
                f"{memory_threshold:.0%}). Investigate the "
                "stage that sets the run peak before "
                "accepting this baseline; if the increase is "
                "intentional, record the reason with the new "
                "baseline instead of raising the threshold.")
        elif delta > 0:
            warnings.append(
                f"memory: peak RSS on {ref_role} grew "
                f"{delta:.1%} ({ref_peak:,} B -> "
                f"{cand_peak:,} B), within the "
                f"{memory_threshold:.0%} threshold")
        else:
            warnings.append(
                f"memory: peak RSS on {ref_role} changed "
                f"{delta:.1%} ({ref_peak:,} B -> "
                f"{cand_peak:,} B); no regression")

    # Per-case matrix comparison (2.6.2 baselines): memory
    # per case is gated the same way; wall time warns only.
    ref_cases = _matrix_cases(reference)
    cand_cases = _matrix_cases(candidate)
    for key in sorted(set(ref_cases) | set(cand_cases),
                      key=lambda k: str(k)):
        label = f"{key[0]} [{key[1]}]"
        if key not in ref_cases:
            skips.append(f"matrix case {label}: absent from "
                         "the reference baseline; not compared")
            continue
        if key not in cand_cases:
            skips.append(f"matrix case {label}: absent from "
                         "the candidate baseline; not compared")
            continue
        r, c = ref_cases[key], cand_cases[key]
        rp, cp = r.get("peak_rss_bytes"), c.get("peak_rss_bytes")
        if isinstance(rp, int) and isinstance(cp, int) and rp > 0:
            delta = (cp - rp) / rp
            if delta > memory_threshold:
                failures.append(
                    f"matrix case {label}: peak RSS regressed "
                    f"by {delta:.1%}: {rp:,} B -> {cp:,} B "
                    f"(threshold {memory_threshold:.0%})")
        rw, cw = r.get("wall_seconds"), c.get("wall_seconds")
        if isinstance(rw, (int, float)) and isinstance(
                cw, (int, float)) and rw > 0:
            delta = (cw - rw) / rw
            if abs(delta) > 0.25:
                warnings.append(
                    f"matrix case {label}: wall time changed "
                    f"{delta:+.1%} ({rw}s -> {cw}s); timing is "
                    "load-dependent and never gates")

    # Module timing runs: warnings only, by design.
    def _run_times(baseline):
        times = {}
        for run in (baseline or {}).get("runs") or []:
            key = (run.get("fixture_role"), run.get("module"))
            if isinstance(run.get("seconds"), (int, float)):
                times[key] = run["seconds"]
        return times
    ref_times, cand_times = _run_times(reference), _run_times(candidate)
    for key in sorted(set(ref_times) & set(cand_times), key=str):
        r, c = ref_times[key], cand_times[key]
        if r > 0 and abs((c - r) / r) > 0.5:
            warnings.append(
                f"timing: {key[0]} / {key[1]} changed "
                f"{(c - r) / r:+.1%} ({r}s -> {c}s); timing "
                "is load-dependent and never gates")

    return {"verdict": "fail" if failures else "pass",
            "failures": failures, "warnings": warnings,
            "skips": skips, "memory": memory}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--reference", required=True,
                   help="reference baseline JSON")
    p.add_argument("--candidate", required=True,
                   help="fresh baseline JSON to gate")
    p.add_argument("--memory-threshold", type=float,
                   default=DEFAULT_MEMORY_THRESHOLD,
                   help="peak-RSS regression fraction that "
                        "fails the gate (default 0.05)")
    args = p.parse_args(argv)
    try:
        with open(args.reference, encoding="utf-8") as fh:
            reference = json.load(fh)
        with open(args.candidate, encoding="utf-8") as fh:
            candidate = json.load(fh)
    except (OSError, ValueError) as e:
        print(f"check_regression: cannot read baselines: {e}")
        return 2
    report = compare_baselines(reference, candidate,
                               args.memory_threshold)
    for line in report["skips"]:
        print(f"SKIP {line}")
    for line in report["warnings"]:
        print(f"WARN {line}")
    for line in report["failures"]:
        print(f"FAIL {line}")
    print(f"gate: {report['verdict'].upper()}")
    return 1 if report["verdict"] == "fail" else 0


if __name__ == "__main__":
    sys.exit(main())
