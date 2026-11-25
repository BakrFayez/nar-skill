# NAR Performance Report — 2.6.2 Stability & Certification Campaign

Methodology: the shipped benchmark runner
(tests/benchmarks/run_benchmarks.py) and regression
gate (tests/benchmarks/check_regression.py), identical
to the methodology that produced baseline-2.6.1.json
and baseline-2.6.2.json. Environment for every number
below: this VM, 1.5 shared vCPU, ~6 GB RAM, Python
3.12.3, fixtures from the local role-labeled corpus.
Wall-clock timings on a shared-CPU VM are
load-dependent; the gate treats them as informational
warnings only, by design. Memory (peak RSS) is the
gating metric.

## Fresh full run on the final tree — gate PASS

Command: `run_benchmarks.py --out benchmark-final.json`
followed by `check_regression.py --reference
baseline-2.6.2.json --candidate benchmark-final.json`.

- **Gate verdict: PASS.**
- Memory headline (nar-analyze on the 273 MB fixture):
  peak RSS 1,545,367,552 B (2.6.2 baseline) →
  **1,562,361,856 B, +1.1%** — a WARN inside the 5%
  threshold, the same noise band as the
  2.6.1→2.6.2 comparison (+0.6%). No campaign change
  altered the analyze memory profile materially; the
  peak remains set by DEX parse transients and
  downstream stages (the documented R-006 limitation —
  the windowed reader removed whole-file DEX reads in
  2.6.2, and peak did not drop because the remaining
  consumers dominate).
- Matrix cases all completed; every timing warning in
  this run was an improvement (the machine was less
  loaded than during the baseline run): e.g. small
  fixture analyze 111.6 s → 62.1 s, medium container
  analyze 436.1 s → 237.2 s, demo analyze 24.7 s →
  14.6 s. These are reported, not claimed as
  optimizations — no timing optimization work was done
  or needed under the freeze.
- Module timings: no module regressed beyond noise;
  several improved under the lighter load (nar-dex on
  the small fixture 5.03 s → 2.34 s, informational).

## The one measured memory defect — D-05 (fixed)

The campaign's resource audit found unbounded
whole-member reads in nar-dex, nar-strings, nar-native
(ZIP path), nar-flutter, and nar-triage. Reproduction
on the pre-fix tree: a 598 KB APK carrying a 400 MB DEX
and a 200 MB native library drove **819 MB peak RSS**.
Fix: a shared capped reader (256 MiB member cap,
declared size checked before decompression, streamed
count checked during) in narlib.safearchive, applied at
every site; nar-triage's version-file reads became
streamed head reads. Post-fix reproduction on the same
hostile input: nar-dex peaks at **≈21 MB** child RSS
and refuses the over-cap member with a labeled error.
Correctness gate: the full unit battery (653 passed)
includes byte-identity coverage for the capped paths,
and the accuracy corpora reproduce their recorded
values exactly — outputs are unchanged for every input
under the cap.

## Other resource bounds verified

- IoStore chunk inflation is capped at the
  TOC-promised size (B-01); a decompression bomb now
  fails fast instead of expanding.
- Unity LZMA bundle decoding has a 256 MiB expected
  output ceiling (B-21).
- dotnetmeta refuses inputs over 512 MiB (A-09).
- formats identify/validate no longer decompresses
  every archive entry twice (A-08): a budgeted streamed
  CRC pass replaces the double full read; classes.jar
  reads are gated by the structural-read cap.
- Archive budgets (entries, ratio, aggregate bytes,
  per-member bytes) are enforced by the single
  ResourceBudget implementation; the security suites
  exercise exhaustion paths (122 passed in the CI
  security subset).

## Known remaining costs (documented, not defects)

- nar-analyze peak ≈1.56 GB on the 273 MB fixture
  (R-006): set by parse transients and downstream
  stages; reducing it further needs the deferred
  streaming work recorded in the repair matrix.
- Godot scene-relationship join is quadratic in section
  counts within one file, bounded by the 25-file /
  4 MiB caps (B-19, documented in
  references/native-libs-and-jni.md).
- dex strings() has a quadratic worst-case corner in
  its NUL scan (recorded in NAR_STABILITY_AUDIT.md).
- The full benchmark on this VM takes ~85 minutes wall
  because two phases each run a full analyze of the
  273 MB fixture; per-case timeout in the harness is
  3600 s.

## Reproduce

```
python tests/benchmarks/run_benchmarks.py \
  --out candidate.json
python tests/benchmarks/check_regression.py \
  --reference tests/benchmarks/baseline-2.6.2.json \
  --candidate candidate.json   # gate: PASS expected
```

Research by Bakr Fayez. MIT License.
