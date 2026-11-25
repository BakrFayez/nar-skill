# NAR Final Verification Report — 2.6.2 Stability & Certification Campaign

Branch: `stability-certification` (from the completed,
unpublished 2.6.2 tree). Version identity: **2.6.2** —
owner-confirmed, no bump; the campaign hardened the
unpublished 2.6.2 in place under a feature freeze.
Nothing was merged, tagged, pushed, or released.

Environment: this VM (1.5 shared vCPU, ~6 GB RAM),
Python 3.12.3, Temurin JDK 17.0.20.1, jadx 1.5.3,
apktool 2.11.1. Corpora are named by role label only.

## Test execution summary (final tree)

| Battery | Result |
|---|---|
| pytest, fixtures bound | **653 passed / 0 failed** (baseline 611 + 43 campaign regression tests − 1 net contract/stub correction) |
| pytest, clean extraction (empty fixture root) | **637 passed / 16 skipped**, every skip with a printed reason |
| e2e private | **68 passed / 0 failed / 0 skipped** |
| e2e public | **15 passed / 0 failed / 48 skipped** |
| doctor | **READY** (24 scripts + 22 narlib modules compile; Python 3.12.3) |
| DEX fuzz | smoke 500 iterations seed 1: **0 failures**; spot-checks 5,000 iterations seeds 7 and 99: **0 failures** |
| CI (all 9 jobs, clean extraction) | unit 637/16 · syntax OK · schema 27 parse, 2 passed/5 skipped · cli-smoke OK · security-regression **122 passed** · docs-consistency **30 passed** · e2e-public 15/0/48 · fuzz-smoke 500/0 · benchmark-smoke gate PASS |
| Benchmark gate (fresh full run vs baseline-2.6.2) | **PASS**; memory headline +1.1% (within 5% threshold); all timing warnings informational |
| Accuracy runner | reproduces accuracy-2.6.2.json **exactly** (see NAR_ACCURACY_REPORT.md) |
| Real-target Zen sweep | 2,644 packages parsed, 0 failed; 7,736 relationship edges by kind reconciling exactly; 0 unresolved; 13,911 Oodle refusals by name |
| Real-target classic pak | v11, 1,564 entries, supported — identical to the 2.6.2 record |
| Case compatibility sweep | 15 retained cases: **14 OK** (one designed legacy warning), 1 expected failure on a legacy harness artifact's own manifest inconsistency, correctly detected |
| Runtime (emulator) | nar-runtime validate PASS; Frida suite **28/28 PASS**; no-device validate exits 1 |

## Findings outcome

3 P0 — all fixed. 21 P1 — all fixed. ~50 P2/P3 —
fixed except three documented-only items (B-19 Godot
join complexity, C-16 exit-code split, D-16 triage
record shape), each with its reason recorded in
NAR_STABILITY_AUDIT.md. Five findings were discovered
by the campaign's own fix/regression phases (D-01b,
S-01, S-02, S-03, CI-01) and fixed in the same cycle.
No test was removed or weakened to reach green; one
test's second half was updated to assert the stricter,
documented parser contract (A-04), and three pre-schema
test stubs were corrected to the real producer shapes
with every assertion unchanged.

## NOT RUN / NOT MEASURED (with reasons)

- **PHYSICAL_DEVICE_VALIDATION: NOT RUN** — no
  physical device is attached to this VM; the emulator
  subset is the executed evidence.
- **Python 3.10 / 3.11: NOT RUN** — only Python 3.12.3
  exists on this VM (R-019 remains the documented
  position).
- **Endpoint-classification accuracy on real data:
  NOT MEASURED** — no independently labeled real
  endpoint corpus exists.
- **Native-library and security-finding classification
  accuracy: NOT MEASURED** — no defensible ground
  truth; finding shape and construction are verified
  instead.
- **Hosted CI: NOT RUN** — ci.yml is applied only via
  the GitHub web UI at an authorized publication;
  every job's commands were executed locally from a
  clean extraction instead.

## Definition of Done (brief §13), item by item

1. **All critical security issues resolved** — PASS.
   The 3 P0s (IoStore zlib bomb, extraction symlink
   escape, credential redaction leaks) are fixed with
   regression tests; the full register is in
   NAR_SECURITY_AUDIT.md.
2. **P1 findings resolved or explicitly justified** —
   PASS. All 21 P1s fixed; none carried as open.
3. **Core workflows pass** — PASS. Full analyze, case
   create/verify/export/import, compare, graph,
   investigation, and the engine pipelines are covered
   by the 653-test battery, the 68-case private e2e,
   and the real-target sweeps.
4. **Regression tests pass** — PASS. 653/653 bound,
   637/637 executed in clean extraction; every fix
   shipped with a regression test.
5. **Evidence provenance validated** — PASS. Verify
   enforces manifest hashes, companion schemas
   (19 documents, permissions.json included), graph
   reconciliation, and cache integrity with era
   handling; provenance drops are counted, not silent.
6. **Security protections tested** — PASS. Archive,
   traversal, symlink, bomb, budget, and redaction
   paths are exercised by the security suites
   (122 passed in the CI subset) and the new targeted
   regressions; no control was disabled.
7. **Performance baselines documented** — PASS.
   Fresh full benchmark run gated PASS against
   baseline-2.6.2 (memory +1.1%, within threshold);
   the D-05 hostile-input result (819 MB → ≈21 MB) is
   measured before/after. NAR_PERFORMANCE_REPORT.md.
8. **Accuracy measured where datasets exist** — PASS.
   Every analyzer with a defensible labeled corpus is
   measured and reproduces its recorded values; the
   rest are printed NOT MEASURED with reasons.
   NAR_ACCURACY_REPORT.md.
9. **Runtime limitations honestly documented** — PASS.
   Emulator evidence is executed and recorded; the
   physical-device line stands as NOT RUN.
   NAR_RUNTIME_VALIDATION_REPORT.md.
10. **Documentation matches implementation** — PASS.
    The documentation audit corrected the capability
    matrix, test matrix, architecture, benchmarks,
    output-schema reference, README, and CHANGELOG
    against the audited code; the docs-consistency
    guard (30 tests) now enumerates the real tests/
    tree and the nar-compare version.
11. **CI verified** — PASS (locally). All 9 jobs'
    commands executed from a clean `git archive`
    extraction with skip reasons printed; one job
    defect (CI-01) found and fixed. Hosted execution
    remains NOT RUN until publication.
12. **No placeholder-dependent critical
    functionality** — PASS. The audit found no critical
    path depending on placeholder data; the registry
    can no longer fake tool availability, and degraded
    paths report themselves.

**Verdict: the stability Definition of Done is met.**
The tree is ready for the owner's publication decision
as version 2.6.2.

## Deliverables in this tree

NAR_STABILITY_AUDIT.md · NAR_SECURITY_AUDIT.md ·
NAR_ACCURACY_REPORT.md · NAR_PERFORMANCE_REPORT.md ·
NAR_COMPATIBILITY_REPORT.md ·
NAR_RUNTIME_VALIDATION_REPORT.md · this report ·
updated CHANGELOG.md, README.md (incl. the
owner-requested Example prompts section),
references/example-prompts.md, NAR_CAPABILITY_MATRIX.md,
NAR_TEST_MATRIX.md.

Research by Bakr Fayez. MIT License.
