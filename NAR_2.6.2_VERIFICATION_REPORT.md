# NAR 2.6.2 — Verification Report

Research by Bakr Fayez. This report records what was
executed for the 2.6.2 verification, security and
integrity round, with the status of every workstream
in the round's vocabulary: IMPLEMENTED / TESTED /
REAL-TARGET VERIFIED / SYNTHETIC-ONLY / NOT RUN /
NOT IMPLEMENTED. Implementation is never presented
as validation. Nothing in this round was published:
no push, no tag, no merge to main, no release — the
tree is release-ready at 2.6.2 pending the owner's
separate authorization.

## 1. Scope and method

Eight workstreams (A–H) executed on branch
`upgrade-2.6.2` from the 2.6.1 code state. Ground
truth at the start: NAR_2.6.1_VERIFICATION_REPORT.md
and NAR_REPAIR_MATRIX.md. Baseline battery executed
on the untouched tree before any change: pytest 463
passed, e2e 67/67, doctor READY. Testing layers
follow the brief: unit → security → integration →
e2e (public/private separated) → real targets →
runtime (emulator-provable subset; physical NOT
RUN) → performance. Every defect found was fixed in
the same cycle with regression tests; no failing
test was removed or weakened.

## 2. WS-A — Archive security, fuzzing, ELF robustness: TESTED

- `narlib/budget.py` (new): a validated
  `ResourceBudget` (entry count, per-file and total
  bytes, per-entry and total compression ratios,
  nesting depth, optional elapsed seconds).
  Defaults are value-identical to the historical
  safearchive limits; invalid overrides raise a
  named `BudgetError`. `narlib/safearchive.py`
  consumes the budget with public behavior
  unchanged (every existing safearchive/analyze/
  regression test passes unmodified). The
  previously scattered caps are expressed as named
  budget instances: the analyzer extraction budget
  (4 GiB / 8 GiB), the React Native read budget
  (256 MiB), the IL2CPP pair budget (1 GiB). The
  analyzer's extraction helper now returns
  structured per-entry records and removes partial
  files when a stream fails mid-extraction.
- 25 new tests (tests/unit/test_archive_budget.py):
  ZIP Slip, absolute paths, backslash traversal,
  drive-letter paths, symlink entries, pre-existing
  symlink-directory escape, duplicate member names
  (pinned semantics: processed in order, second
  replaces first on the contained target, never an
  escape), malformed central directory, declared-
  size mismatches, truncated streams, compression
  bombs, nesting, budget exhaustion, elapsed budget.
- DEX fuzzing: `tests/fuzz/dex_fuzz.py` — a
  deterministic, stdlib-only mutation harness
  (seeded; per-case timeout; crash artifacts and
  repro files preserved; Atheris documented as
  optional, never a dependency). Pre-fix, seed 2 ×
  1,500 cases found one root-cause defect in four
  shapes: the class-annotation offset-table walk
  was unbounded and leaked `struct.error` on
  truncated inputs — now bounded, truncated tables
  flagged, failures surface as `DexError`.
  Encoded-value recursion is capped at depth 64 in
  both DEX readers (found by the audit pass; the
  fuzzer's recursion operator could not reach the
  path unaided — stated plainly). Post-fix sweep:
  12 seeds × 2,500 = 30,000 cases, 0 distinct
  failures. 10 regression tests.
- ELF robustness: `EI_DATA` outside (1, 2) now
  raises the named error; program/section header
  entry sizes are validated before use; symbol and
  relocation readers use checked entry sizes.
  18 robustness tests. GNU-hash parsing is NOT
  IMPLEMENTED by design: the section is carried as
  opaque bytes, pinned by test.
- Elapsed-time budgets are enforced by safearchive
  only when a caller sets one (default preserves
  historical behavior); the field is unit-tested
  with a fake clock. Recorded here so the limit of
  the mechanism is explicit.

## 3. WS-B — Runtime validation: IMPLEMENTED + TESTED (emulator); physical device NOT RUN

- Capability statuses: `capability_statuses()` maps
  the existing capability record onto exactly one
  status per field — detected / verified /
  unsupported / unavailable / not_tested.
  `device_capabilities()` also returns the device
  fingerprint and the status map. The emulator-
  detection discipline (multi-marker, manufacturer
  corroboration) is untouched.
- `nar-runtime validate`: a machine-readable
  validation surface — adb availability, device
  authorization (named reasons with remedies),
  Frida host/server presence, version and match,
  ABI match, process enumeration, attach
  capability, clean detach. Unrun probes report
  `skip`, never `pass`.
- Frida validation suite (tests/runtime_validation/,
  device-dependent test tooling): 7 checks × the 4
  bundled scripts (the brief's "SSL observation"
  script does not exist; the fourth script is
  java-api-trace — recorded as a brief correction).
- Live emulator run (API 26 AVD, software rendering):
  suite **28/28 PASS** — the first live pass for
  the JNI-trace and Java-API-trace scripts through
  this suite; validate ok=true (9 pass / 1 warn /
  0 fail; the warn is FRIDA_SERVER_ABI_UNKNOWN —
  the on-device server binary carries a bare
  filename, so its ABI cannot be proven from the
  listing; remedy printed); 87 processes enumerated;
  Frida host/server 17.27.4 match. Two live-found
  defects fixed in-cycle (an intermittently silent
  `pm` under emulation had gated the attach probe;
  a Frida-internal attach timeout on a healthy
  target — both now bounded timeout-only retries
  with fake-transport regression tests). No-device
  behavior proven live after shutdown: 4 PASS
  (syntax) / 0 FAIL / 24 NOT RUN. 41 new unit tests.
- **Physical device: NOT RUN.** No physical device
  is attached to this machine (`adb devices` empty
  before and after the run). Nothing physical is
  claimed anywhere; the owner's device run remains
  the outstanding item, as it has been since 2.6.0.

## 4. WS-C — Unreal Zen validation: REAL-TARGET VERIFIED

Executed on three real IoStore container sets
retained locally from earlier authorized testing
(no download was needed; no title name, package or
hash appears anywhere in the repo — role labels and
counts only):

| Set | Dir-index files | Zen parsed OK | Failed |
|---|---|---|---|
| TOC v5 set | 6,743 | 684 | 0 |
| TOC v8 subset | 2,184 | 525 | 0 |
| TOC v8 wider set | 13,494 | 1,435 | 0 |
| **Total** | | **2,644** | **0** |

- 7,736 relationship edges (class 3,460 / template
  3,460 / outer 721 / super 95 / depends 0),
  0 unresolved on real data; every total reconciled
  exactly against the independent oracles (chunk
  counts, directory file counts, per-set table
  totals). 13,911 Oodle extraction records all
  refused by name (proprietary SDK; named, never
  decoded).
- Graph cross-validation: the standalone route
  (nar-unreal → graph builder) reconciled exactly
  per set; the pipeline carrier route is exact but
  small (a capped window: 1 real Zen package,
  2 edges; case verify OK; the investigation
  contained zero fabricated Unreal claims).
- Real defect found and fixed: Zen export
  references that cannot resolve carried no
  `note`, so the graph join upgraded them to high
  confidence with no unresolved status. nar-unreal
  now emits the classic path's exact unresolved
  wording for them; regression tests added; post-fix
  real outputs byte-identical (the defect was
  latent on real data, live on synthetic probes).
- Classic relationships byte-compatible: the
  standalone classic-pak report SHA-256 is
  identical before and after the change.
- Boundary classification: package ids, name maps,
  export/import maps, object references and
  serialization paths are tested-on-real;
  out-of-map targets, recorded versioning info and
  pre-5.3/Early-Access layouts are SYNTHETIC-ONLY;
  dependency-bundle contents are not covered by
  design (counts only). Graph identity is per-case:
  a combined-titles probe merged 153 duplicate
  stock package records; no real single-app
  instance of that shape exists in these sets.

## 5. WS-D — Performance: TESTED (byte-identity gate PASS; peak unchanged, stated plainly)

- Windowed reader: the DEX stage document is now
  read through `_WindowedReader` (bounded 1 MiB
  window; identical `len`/index/slice interface)
  instead of a memory map; the stage file is never
  mapped or held whole; cache/companion bytes are
  unchanged by construction; the classic fallback
  is intact. 3 regression tests.
- Hard gate, control comparison first: two
  pre-change runs (peaks 1,541,869,568 B /
  1,537,503,232 B; 31/39 case files byte-identical
  including both DEX outputs) proved the
  nondeterministic set — the network-security-config
  subtree and its investigation/report cascade
  (an apktool decode that is flaky under load),
  `duration_s`, `created`. Post-change run: exit 0,
  peak 1,546,702,848 B; **the dex.json companion
  SHA-256 is identical across both control runs and
  the post-change run; cache/dex.json identical**;
  all remaining differences are confined to the
  control-proven fields plus the report's
  environment block, proven to record the launching
  shell's tool resolution, not a code effect.
- Benchmark matrix (tests/benchmarks/
  baseline-2.6.2.json): 8/8 cases completed with
  per-case peak RSS, per-stage durations, second-run
  cache counts (7 of 12–13 stages cached in every
  case) and output sizes; 2.6.0/2.6.1 figures
  carried in under the same harness discipline
  (2.6.0's file has no memory block; carried as
  null). Headline (273 MB multi-DEX fixture,
  RUSAGE_CHILDREN): 2.6.0 1,887,678,464 B ·
  2.6.1 1,536,069,632 B · **2.6.2 1,545,367,552 B
  (+0.6% vs 2.6.1 — run-to-run noise, NOT a claimed
  win)**. The windowed reader removes mmap page
  pressure, but the run peak is now set by
  per-element parse transients and downstream
  stages. Wall times are recorded but never
  headlined (load-dependent on a shared machine).
- Regression gate: tests/benchmarks/
  check_regression.py + 10 unit tests. Live run
  against baseline-2.6.1.json: PASS, exit 0
  (memory +0.6% → warning inside the 5% threshold;
  matrix cases SKIP against the older reference;
  timing differences are warnings only).

## 6. WS-E — Accuracy and calibration: TESTED where ground truth is defensible; NOT MEASURED where it is not

Corpus and runner in tests/accuracy/ (labeling
format schema 1; labeling data stays local);
results in tests/benchmarks/accuracy-2.6.2.json.
Synthetic and real results are always separate;
unclassified positives count as misses.

| Analyzer | Corpus | Result |
|---|---|---|
| Engine identification | real, 30 samples (6 pos / 24 cross-labeled neg) | P/R/F1/Acc 1.0, FP 0 — real precision measured for the first time (2.6.1: NOT RUN) |
| Framework detection | synthetic, 64 samples (8 pos / 56 neg) | P/R/F1/Acc 1.0 |
| Format identification | real 10 · synthetic 5 | accuracy 1.0 / 1.0, confusion matrices recorded |
| Protection attribution | real, 26 samples (1 pos / 25 neg) | P/R/F1/Acc 1.0, FP 0 |
| Endpoint classification | synthetic, 8 construction-labeled | 8/8 (rule consistency — weaker than independent labeling, stated) |
| Endpoint classification | real | **NOT MEASURED** — no independently labeled corpus exists |
| Native library identification | — | **NOT MEASURED** — no recorded per-fixture library ground truth |
| Security finding classification | — | **NOT MEASURED** — no independent labels; deriving them from the rules would be circular |

Calibration audit: one overstatement found and
fixed. nar-network's endpoint label `confirmed`
was documented as "referenced from DEX code" but
its rule is mere presence in DEX string data (and
narlib.correlations grades the same evidence more
weakly). Renamed to `dex-string` in nar-network,
the endpoints schema, the nar-security consumer
and the output-schema reference, with regression
tests pinning that `confirmed` is never emitted.
Every other audited label — engine scoring
(including the intentional, test-pinned
single-strong-marker detection), protection
attribution, security verification_status values,
correlation statuses, graph confidences,
investigation path confidences, format verdicts —
traced to its evidence rule and found calibrated.

## 7. WS-F — Evidence and case integrity: TESTED

- `nar case verify` now ships `_verify_evidence_
  integrity()`: every evidence reference in
  graph.json (primary and accumulated) and
  investigation.json (evidence / basis /
  triggering_evidence) is validated against the
  case's existing documents and resolvable field
  paths (the builders' real grammar, including
  hyphens and [int] segments); duplicate node/edge
  identities, missing endpoints and orphans are
  distinct checks; header and by-kind counts,
  correlation counts and hypothesis
  basis/confirm/refute presence are reconciled.
  Results land as a structured `evidence_integrity`
  section in --json output and [warn] marks in
  text; the exit code follows hard failures.
- Companion discipline: companion-list presence,
  companion schema validity (18 case documents),
  and version-field agreement are verified;
  unparsable case.json/report.json are check
  failures, not crashes; export → import → verify
  re-verifies fully.
- Era policy (documented in code): hard failure in
  every era for duplicates, missing endpoints,
  count errors, missing listed companions, schema
  failures and version disagreement; WARNINGS only
  for pre-2.6.1 cases on evidence-resolution gaps,
  missing unverified_findings and legacy hypothesis
  gaps — failing archived cases for the older
  pipeline's own known defects would make verify
  useless. Legacy count tampering still hard-fails
  (tested).
- Build-time gate: hypotheses are validated when
  the investigation is built; suppressions are
  recorded in the document notes; hypotheses are
  never merged into facts. No schema change — the
  schema already required the fields; the gap was
  enforcement. 28 unit tests (14 hand-corrupted
  negative cases with expected structured reasons)
  + 1 new e2e case (public-mode safe).

## 8. WS-G — CI expansion: IMPLEMENTED; every job verified locally from a clean extraction

`.github/workflows/ci.yml` expands from two jobs to
nine: unit, syntax, schema-validation, cli-smoke,
security-regression, docs-consistency, e2e-public,
fuzz-smoke, benchmark-smoke (informational,
continue-on-error: hosted-runner memory is not
comparable to the local baseline). Pytest jobs run
with `-ra` so skip reasons print in CI output.
Each job's exact commands were executed locally
from a clean `git archive` extraction of the final
tree: unit 607 passed / 4 skipped (fixture-
dependent, reasons printed); syntax clean;
26 schemas parse + schema tests 7 passed; CLI
smoke clean (every script answers --help);
security-regression 122 passed; docs-consistency
30 passed; e2e-public 15 passed / 0 failed /
48 skipped; fuzz-smoke 500 iterations, 0 failures;
benchmark-smoke gate PASS. **ci.yml is excluded
from push manifests** (the push channel cannot
carry workflow files) and will be applied via the
web UI at publication; its first hosted run after
publication is the proof for the new jobs — the
2.6.1 workflow it replaces is executed and passing
(run #14, both jobs).

## 9. WS-H — Documentation and version: TESTED

Version 2.6.2 in all 18 guarded locations plus the
graph/investigation builder defaults, verified with
the repo's own version collector. README What's-new,
CHANGELOG 2.6.2 section, capability matrix (Zen
real-verified, runtime validation, physical device
NOT RUN, ResourceBudget), architecture (budget
module, windowed reader, evidence integrity,
validate surface; narlib now 22 modules),
SECURITY.md, the benchmarks reference and SKILL.md
routing corrected to the actual state. This report
is the round's record.

## 10. Final battery (executed on the final tree)

| Layer | Result |
|---|---|
| Unit | 611 passed / 0 failed (worktree); 607 passed / 4 skipped from a clean extraction (fixture-dependent skips, reasons printed) |
| Security | 122 passed (dedicated suites, clean extraction); fuzz sweep 30,000 cases / 0 failures; CI fuzz smoke 500 / 0 |
| Integration | graph/investigation/case round-trips inside the unit suite; case verify evidence integrity on real-shape cases |
| E2E private | 68 passed / 0 failed / 0 skipped |
| E2E public | 15 passed / 0 failed / 48 skipped (worktree and clean extraction) |
| Real targets | Zen: 2,644 packages reconciled (§4); accuracy corpora measured (§6); benchmark matrix 8/8 (§5) |
| Runtime | emulator suite 28/28 PASS; validate ok (9/1/0); no-device run 4 PASS / 24 NOT RUN; **physical device NOT RUN** |
| Performance | headline peak 1,545,367,552 B vs 2.6.1's 1,536,069,632 B (+0.6%, noise); regression gate PASS |
| Doctor | READY |

Hygiene: banned-identifier grep over the tree —
zero real hits (two substring false positives in a
historical report: "measuring"); forbidden credit
lines — zero (the only credit is "Research by
Bakr Fayez").

## 11. §12 deliverables

- **Changed files**: 62 files (21 added, 41
  modified), +8,568 / −120 lines vs the 2.6.1 code
  state, plus this report. New: narlib/budget.py,
  tests/fuzz/ (harness + README), tests/accuracy/
  (corpus, runner, README), tests/runtime_
  validation/, tests/benchmarks/baseline-2.6.2.json
  + accuracy-2.6.2.json + check_regression.py, and
  nine new test modules. Full list: `git diff
  --stat` of the branch against the 2.6.1 state.
- **Exact test commands**: `~/workspace/nar2-venv/
  bin/python -m pytest tests/ -q` (unit);
  `bash tests/run_e2e.sh` and `NAR_E2E_PUBLIC=1
  bash tests/run_e2e.sh` (e2e); `python3
  scripts/nar.py doctor`; `python3
  tests/fuzz/dex_fuzz.py --seed <n> --iterations
  <n>`; `python3 tests/benchmarks/
  check_regression.py --reference <a> --candidate
  <b>`; `python3 tests/accuracy/run_accuracy.py`.
- **Actual results**: §10 table; per-workstream
  detail in §2–§9.
- **Open security findings**: none open. Two
  defects found and fixed in-cycle (annotation-
  table bound, encoded-value recursion cap) plus
  the Zen unresolved-note confidence defect (§4)
  and the endpoint calibration overstatement (§6).
- **Physical-device status**: NOT RUN — no device
  attached to this machine; never claimed.
- **Zen status**: REAL-TARGET VERIFIED (§4).
- **Performance comparison vs 2.6.1**: §5 —
  byte-identity held; headline peak unchanged
  within noise; stated without spin.
- **Release-readiness assessment**: the tree is
  release-ready at 2.6.2. All executed layers pass;
  every unexecuted item is labeled NOT RUN / NOT
  MEASURED / NOT IMPLEMENTED with its reason in
  §12. Publication (push, web-UI ci.yml, release)
  awaits the owner's explicit authorization.

## 12. NOT RUN / NOT MEASURED / NOT IMPLEMENTED register

- Physical-device runtime validation — NOT RUN
  (no device attached; owner's device only).
- Endpoint classification accuracy on real data —
  NOT MEASURED (no independently labeled corpus).
- Native-library identification accuracy — NOT
  MEASURED (no recorded per-fixture ground truth).
- Security-finding classification accuracy — NOT
  MEASURED (independent labels would be circular).
- GNU-hash parsing — NOT IMPLEMENTED by design
  (section carried as opaque bytes, test-pinned).
- Zen dependency-bundle contents — not covered by
  design (counts only); Zen versioning info and
  pre-5.3/EA layouts — SYNTHETIC-ONLY (no real
  sample exists in the retained sets).
- Elapsed-time archive budget — enforced only when
  a caller sets it (default preserves historical
  behavior); unit-tested with a fake clock.
- CI 2.6.2 workflow — first hosted run pending
  publication (all jobs verified locally from a
  clean extraction, §8).
- Carried from earlier rounds, unchanged: CDEX
  payload decoding, Kotlin d1 interpretation,
  OAT beyond API 26 on real files, Kismet/Blueprint
  graph decoding, Unity serialized-object parsing
  (all NOT IMPLEMENTED / SYNTHETIC-ONLY as recorded
  in NAR_CAPABILITY_MATRIX.md).
