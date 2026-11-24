# NAR 2.6.0 Update Report

Research by Bakr Fayez

Repository-wide repair and intelligence upgrade,
executed 2026-11-24 on branch `upgrade-2.6.0` from
the shipped 2.5.2 (42516f7). This tree is
release-ready and UNPUBLISHED: no push, tag, merge
to main, or release has been made — publication is
the owner's separate authorization. The complete
issue-by-issue record is NAR_REPAIR_MATRIX.md.

## Program shape

The owner's brief ordered: a complete audit and
issue inventory before any edit; a repair campaign
in which every discovered actionable issue is fixed
with a regression test or documented with its
technical reason; depth upgrades across DEX,
native, engines, frameworks, a unified application
graph, an evidence-bound investigation layer,
dynamic analysis, security, benchmarks, dashboard,
CLI and documentation; and a truthful release
record. The brief's subsystem-sized items (full
Unity serialized-file parsing, Kismet decoding,
Hermes disassembly) were scoped to their honest,
tested cores with the remainders documented — no
placeholders, no fabricated results.

Execution note: the first attempt at Phases 9–14
was stopped by an execution-risk check in the
worker sessions. The owner gave his explicit
go-ahead on 2026-11-24 ("complete Phases 9–14 and
run the project's code and its tests") and the
phases were then executed under that approval.

## Issue inventory totals (Phase 1: R-001–R-020)

- Fixed with regression tests: **14**
- Partially fixed, remainder documented: **3**
  (R-005 Kotlin d1, R-012 Unity object parsing,
  R-020 pipeline retry/cancellation). R-002 (CDEX)
  is counted as fixed at the header/section level
  it was inventoried for, with its payload
  limitation stated in the matrix
- Documented with technical reason, no code: **3**
  (R-006 analyze memory restructure, R-015 ci.yml
  channel limit, R-019 Python 3.9/3.10 evidence)
- Closed silently: **0**

## Per-phase outcomes

- **Phase 1 — IMPLEMENTED_AND_TESTED.** Full audit
  of all 161 tracked files; baseline executed on
  the untouched tree (pytest 332, e2e 65, doctor
  READY); static audit clean (compileall, schemas,
  CLI helps, no TODO/FIXME, no shell=True/eval/
  pickle); inventory seeded as R-001–R-020.
- **Phase 2 — IMPLEMENTED_AND_TESTED.** The 2.5.2
  test infrastructure carried the program; the
  suite grew 332 → 425 tests, every fix with a
  regression test; coverage measured for the first
  time (Phase 11).
- **Phase 3 — IMPLEMENTED_AND_TESTED.** CFG edges
  in the DEX disassembler (`nar-dex --cfg`,
  targeted-only; dexdump-oracle listings still
  byte-identical); resolved call graph + per-method
  xref (`nar-dex --xref`; real multi-DEX fixture:
  431,390/736,471 invoke edges resolved, second
  fixture 111,211/180,290); CDEX header/section
  parser (synthetic-verified; `payload_decoded:
  False` stated in output); Kotlin d2 cross-check
  measured on the real corpus (d2[0] = annotated
  class in 99.89% of 4,425 checked); obfuscation
  identifier-shape indicators (confidence-labeled,
  never verdicts).
- **Phase 4 — IMPLEMENTED_AND_TESTED.** Native
  library dependency graph (DT_NEEDED edges,
  external dependencies labeled, caps with
  truncation flags; previous shape preserved) and
  symbol-cluster behavior indicators (evidence +
  confidence, weak symbols suppressed, not-a-verdict
  wording). Native control-flow: UNSUPPORTED,
  documented (no stdlib disassembler; Ghidra is the
  registered escalation).
- **Phase 5 — IMPLEMENTED_AND_TESTED (labeled
  boundaries).** Unity first-party UnityFS bundle +
  blocks-info + serialized-file header parsing
  (stored/LZMA1 via stdlib; LZ4-family inventoried,
  never decoded — real-fixture verified boundary).
  Unreal classic + Zen relationship records
  (table-derived edges; classic real-verified, Zen
  synthetic-only — no Zen-bearing fixture bound).
  Godot text scene/resource reference extraction
  (Godot 3 + 4 id styles; the real pack's 36 scenes
  are all binary — 0 candidates is the correct
  result and the explanatory note fires).
- **Phase 6 — IMPLEMENTED_AND_TESTED (synthetic +
  real).** Flutter plugin inventory (registrant +
  plugin classes + channel string candidates
  labeled inference; minified-build zero-interface
  case explained in-report and regression-tested).
  RN bridge mapping (bridge/registrar/codegen
  evidence incl. 85 real Native*Spec classes;
  bundle↔DEX join for text bundles; Hermes join
  unavailable with reason). Two real-fixture
  defects fixed in-cycle.
- **Phase 7 — IMPLEMENTED_AND_TESTED (synthetic).**
  graph.json companion (12 node kinds, 11 edge
  kinds, provenance + evidence refs + source-derived
  confidence; one-sided joins preserved with
  explicit statuses, never upgraded; findings never
  invent target nodes); graph.schema.json (26
  schemas); `nar case graph` query with filters;
  correlations.json byte-compatible.
- **Phase 8 — IMPLEMENTED_AND_TESTED (synthetic).**
  investigation.json: deterministic, offline,
  rule-based, zero external calls; verified_facts /
  ranked rule paths (8 rules) / hypotheses (labeled,
  with confirm–refute conditions) / unknowns
  strictly separated; a dedicated test asserts every
  referenced entity exists in the case data;
  --no-investigation / --no-graph + env switches;
  builder failure degrades to a failed stage entry
  + limitation, analysis continues (planted-failure
  tested).
- **Phase 9 — IMPLEMENTED_AND_TESTED (synthetic +
  live emulator).** Device capability detection,
  emulator-vs-physical classification with evidence,
  structured environment diagnostics with named
  failure reasons (`nar-runtime diagnose`), Frida
  host/server compatibility checks, bounded
  connection recovery. Live on the local emulator
  (API 26, boot verified; only the project's own
  demo fixture exercised): diagnose all-pass,
  classification emulator with evidence, frida
  17.27.4 = 17.27.4 match proven by host process
  enumeration; one live-found defect (frida-server
  log sidecar suppressing the version probe) fixed
  with a regression test. Physical device NOT RUN
  (owner's device only).
- **Phase 10 — IMPLEMENTED_AND_TESTED.** Real P1
  gap: case-bundle import used raw extractall —
  now safearchive-only with hostile-archive
  regression tests; archive limits enforced on
  actual decompressed bytes, corrupt entries reject
  individually; predictable temp defaults replaced
  with mkdtemp and a temp-dir leak fixed; parser
  whole-file read caps (formats 512 MiB, Godot
  512/64 MiB) with named skip notes; subprocess
  inventory probed-OK and pinned by a standing AST
  test (one documented deliberate exception: the
  interactive dispatcher).
- **Phase 11 — IMPLEMENTED_AND_TESTED.**
  baseline-2.6.0.json on byte-identical inputs
  (table below); synthetic-corpus parser field
  completeness 85/85 across 11 fixtures; coverage
  measured (below).
- **Phase 12 — IMPLEMENTED_AND_TESTED.** Dashboard
  gains Unified graph and Investigation sections
  rendered only when the companions exist, absent
  gracefully otherwise; fully offline verified
  (0 external references); verified on a real full
  case from the Phase 11 analyze run (graph 69,241
  nodes / 88,666 edges; investigation 235 facts /
  606 paths / 166 hypotheses / 3 unknowns).
- **Phase 13 — IMPLEMENTED_AND_TESTED.** CLI audit
  (27 dispatcher verbs + case router + version; 24
  standalone scripts): --help exit 0 everywhere,
  bad input → exit 2, structured error, no
  traceback. Two defects fixed with regression
  tests (case-view exit codes/traceback; v11 pak
  identification via a bounded 4 KiB tail scan —
  found by the Phase 11 measurement). No breaking
  changes.
- **Phase 14 — IMPLEMENTED_AND_TESTED.**
  Architecture, capability matrix (Phase 9/10 rows
  finalized in Phase 15), test matrix, SKILL.md
  routing (nar-dex --cfg/--xref row added),
  references/benchmarks.md, and SECURITY.md (new;
  every claim grep-verified in code first).
- **Phase 15 — this record.** Version 2.6.0 in all
  18 guarded locations plus the two graph/
  investigation builder defaults (consistency +
  YAML tests green; `nar version` reads 2.6.0);
  CHANGELOG and README sections; repair matrix
  completed; coverage re-measured on the final
  tree; final battery + greps below.

## Final battery (merged tree, coordinator's runs)

- pytest: **425 passed, 0 failed** (baseline 332;
  +93 across the program: Phases 3+4 +18, 5+6 +28,
  7+8 +10, 9+10 +31, 11–14 +6)
- e2e: **65 passed, 0 failed, 0 skipped**
- doctor: **Core toolchain: READY**
- Version consistency + YAML validation tests:
  green; `nar version` → NAR 2.6.0
- Greps over the full program diff: banned
  identifiers 0, forbidden credits 0 — the only
  credit anywhere is "Research by Bakr Fayez"

## Benchmarks (identical inputs, 2.5.2 → 2.6.0)

| Run | 2.5.2 peak RSS | 2.6.0 peak RSS | Δ |
|---|---|---|---|
| nar-unreal, UE 5.3 IoStore set | 40,079,360 B | 40,132,608 B | +0.13% |
| nar-unreal, TOC v8 set | 28,352,512 B | 28,913,664 B | +1.98% |
| nar-native, largest local ELF | 46,964,736 B | 47,308,800 B | +0.73% |
| nar-analyze, 273 MB fixture | 1,885,212,672 B | 1,887,678,464 B | +0.13% |

No memory regression. The analyze peak stands as
diagnosed in R-006 (orchestrator stage-JSON
round-trip; restructure out of scope). Wall times
are recorded in baseline-2.6.0.json; the analyze
wall from the Phase 11 run is flagged
non-comparable there (shared box during the
measurement).

## Coverage (R-016, first measurement)

coverage.py 7.17.5 (test venv only), command
`coverage run --source=scripts -m pytest tests/ -q`,
scope = line coverage of scripts/ as executed
in-process by the unit suite. Final merged tree
(425 tests): **53.04%** (6,666 covered / 12,567
statements). E2e-only paths are not in this number.

## Remaining limitations

CDEX payload not decoded (no real CDEX corpus;
synthetic-only verification); Kotlin d1 not
interpreted (no verifiable subset without the
versioned kotlinx-metadata schema); nar-analyze
peak memory unchanged (R-006, diagnosed);
Unity full serialized-file object parsing and LZ4
decoding out of scope (stdlib boundary); Zen
relationships synthetic-only; Godot binary scenes
yield references only via the note path;
Flutter/RN name-based detection degrades honestly
on fully minified builds; Unreal package
relationships not joined into graph.json
(nar-unreal is a standalone deep-dive; the graph
consumes nar-analyze stage documents); native
control-flow unsupported (Ghidra escalation);
physical-device runtime IMPLEMENTED_BUT_UNVERIFIED
(owner's device only).

## NOT RUN (with reasons)

- Physical-device runtime session: owner's device
  only; no device is attached to this environment.
- Live destructive connection-recovery test: the
  only target was healthy; forcing a disconnect
  would have risked the verification session. The
  recovery loop is synthetic-verified.
- Live Frida version-mismatch: a deliberately
  mismatched server was not installed on the only
  target (would have replaced the working server);
  the mismatch path is synthetic-verified.
- CI execution of the YAML tests: ci.yml installs
  only pytest + the package; see the owner
  follow-up below.

## Owner follow-up (one item)

`.github/workflows/ci.yml` cannot be edited through
this program's push channel (the GitHub App lacks
the workflows permission — established in 2.1.0).
Required change, one line in the install step: add
`pyyaml` to the pip install (e.g.
`pip install pytest pyyaml` or install the
pyproject `test` extra) so the YAML validation
tests run in CI instead of skipping. Everything
repo-side is already in place; the tests SKIP
honestly where PyYAML is absent.

## Release readiness checklist

- [x] Full test suite green (pytest 425/425)
- [x] E2E green (65/65)
- [x] Doctor READY
- [x] All schemas parse and validate generated cases
- [x] SKILL.md / skill.yaml valid under a real YAML parser
- [x] CLI surface audited (help, exit codes, structured errors)
- [x] Benchmark regression run on identical inputs (no regression)
- [x] Backward compatibility: existing verbs/flags unchanged in meaning; correlations.json byte-compatible; pre-existing report shapes preserved
- [x] Git diff inspected; no generated/temp artifacts committed (worker staging record files folded into NAR_REPAIR_MATRIX.md and removed)
- [x] Version metadata synchronized (18 guarded locations + 2 builder defaults)
- [x] Release documentation complete (this report, CHANGELOG, repair matrix, capability matrix)
- [ ] Publication: NOT DONE — owner's separate authorization required

## Publication status (addendum, 2026-11-24)

This report was written before publication, and its
checklist above records that state. For the record, the
publication it waited for has since happened, on
2026-11-24: the `upgrade-2.6.0` branch was fast-forwarded
into `main` (ceb9d4d) and pushed (remote main 0ef1817c);
the GitHub Release "NAR 2.6.0" (tag v2.6.0) was published
and marked Latest; and nar-ci run #12 for that push
completed with conclusion Success. The unchecked
"Publication" box above is therefore historical, not a
pending item. (Appended by the 2.6.1 verification round;
the original report text is unchanged.)
