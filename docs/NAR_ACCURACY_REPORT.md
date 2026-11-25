# NAR Accuracy Report — 2.6.2 Stability & Certification Campaign

Scope: per-analyzer accuracy on the labeled corpora that
exist locally, re-measured on the final stabilized tree.
Real and synthetic corpora are always reported separately.
An analyzer without defensible ground truth is NOT
MEASURED, with the reason — no estimate is substituted.
Small samples are reported as small samples; a 100% score
on 30 samples is evidence about those 30 samples, not a
general claim.

Reproduction: `python3 tests/accuracy/run_accuracy.py
--out <file>` on the final tree reproduces
`tests/benchmarks/accuracy-2.6.2.json` exactly — every
analyzer's status, sample count, and rates are identical
to the recorded 2.6.2 values (verified by direct
comparison of the two documents during this campaign).

## Measured analyzers

| Analyzer | Corpus | Samples | Result |
|---|---|---|---|
| Engine identification | real (cross-labeled fixture roles: each engine-family fixture is a positive for its family and a negative for the others) | 30 (6 pos / 24 neg) | precision 1.0, recall 1.0, F1 1.0, FP 0 |
| Format identification | real | 10 | accuracy 1.0 (apk 8, godot-pck 1, xapk 1; 0 unclassified) |
| Format identification | synthetic | 5 | accuracy 1.0 (elf, dex, unreal-pak, godot-pck, unreal-iostore) |
| Framework detection | synthetic | 64 | precision 1.0, recall 1.0, F1 1.0 |
| Protection attribution | real (clean fixtures are negatives) | 26 | precision 1.0, recall 1.0, F1 1.0, FP 0 |
| Endpoint classification | synthetic (construction-defined labels; measures rule consistency, weaker than independent human labeling) | 8 | accuracy 1.0 (sensitive 2, unverified 2, third-party 1, dex-string 1, potential 1, unused-candidate 1) |

## NOT MEASURED — with reasons

| Analyzer | Status | Reason |
|---|---|---|
| Endpoint classification (real) | NOT MEASURED | No independently labeled endpoint corpus exists locally; ground truth would require human traffic judgments the static labels cannot supply. |
| Native-library identification | NOT MEASURED | No labeled corpus with defensible per-library ground truth exists locally. |
| Security-finding classification | NOT MEASURED | No labeled corpus of confirmed/refuted findings exists locally; findings carry per-finding verification_status instead (see NAR_SECURITY_AUDIT.md). |

## Calibration corrections shipped in this campaign

- The endpoint class formerly named `confirmed` was
  already renamed `dex-string` in 2.6.2 (a string
  reference was never confirmation of traffic); verify
  now validates pre-2.6.2 cases under the era mapping
  instead of hard-failing them (S-02).
- Investigation promoted any finding whose status was
  not literally `UNVERIFIED` into verified_facts —
  including CONTRADICTED and POTENTIAL findings (C-04).
  Promotion is now an allowlist: CONFIRMED and
  STRONGLY_INDICATED only.
- Triage protection records carry no per-record
  confidence or verification_status field; the reference
  documentation now states this explicitly so the records
  are read as UNVERIFIED static indicators (D-16).
- nar-security findings continue to be built exclusively
  through the validating evidence constructor (all 13
  fields, explicit verification_status at all 12 call
  sites — re-verified by code read in this campaign).

## False-positive / false-negative investigation

- The 2.6.2 cross-labeled engine corpus was re-run
  unchanged: no new false positives or negatives on the
  final tree.
- One accuracy-relevant defect was found by the
  campaign's regression phase, not by the corpora:
  correlations silently degraded on any target with a
  detected network library (S-03), which would have
  suppressed library-correlation evidence (a false
  negative by omission). Fixed; regression-tested.
- The capability matrix's stale claim that real-corpus
  engine precision had "never been measured" was
  corrected to the measured result above (E-01).

## Environment

Local VM (1.5 shared CPUs), Python 3.12.3, fixture corpus
bound through the standard manifest roles. The corpora
are small and local; results are reported as measured on
them and are not generalized beyond them.

MIT License.
