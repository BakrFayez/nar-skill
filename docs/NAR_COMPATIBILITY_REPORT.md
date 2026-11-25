# NAR Compatibility Report — 2.6.2 Stability & Certification Campaign

Scope: backward compatibility of the stabilized tree
with everything the earlier releases produced — retained
case directories, bundle round-trips, schemas, the CLI
surface, and the Python floor. No backward-compatibility
breaks were introduced; the two era defects found
(S-01, S-02) were defects *in* compatibility handling
and are fixed.

## Retained case verification (final tree)

Every retained case directory was re-verified with
`nar-analyze --verify` on the final tree. Re-verification
was required because the campaign registered
permissions.json in verify's companion schema map
(E-09), so every case's permissions document is now
schema-checked too.

| Set | Cases | Result |
|---|---|---|
| cases-pre (2.4–2.6.1-era builds) | bundles, demo, unity, unreal, unreal-carrier, xapk | 6/6 OK |
| cases-post (2.6.1-era rebuilds) | bundles, demo, unity, unreal-carrier | 4/4 OK |
| cases-prof (profiling builds) | bundles, bundles-post | 2/2 OK |
| e2e-live (harness-built) | case1, case2 | OK |
| e2e-live | case3 | FAIL — expected, see below |

Warnings: exactly one across the sweep — the xapk case
carries the S-01 legacy-container warning by design.

**e2e-live/case3** fails on one check only: "bundle
manifest: report.json hash/size mismatch". The case's
own recorded manifest disagrees with its report.json on
disk — a legacy harness artifact inconsistency that
predates the campaign (identified during the 2.6.1/2.6.2
work). Verify is correctly detecting a real inconsistency
in the artifact; this is not a code defect and not a
compatibility regression. Recorded as an observed
legacy-artifact inconsistency.

## Era handling fixed in this campaign

- **S-01 (P1):** before the fix, stage cache keys for
  container targets (XAPK/APKS/AAB) were derived from
  the extracted base APK's hash, but case.json records
  the container hash — every container-built case
  falsely failed cache integrity. Keys now derive from
  the case target hash. Legacy container cases (built
  before 2.6.2 from a container input) carry keys that
  cannot be recomputed from case data at all: verify
  reports them as a warning with the reason stated,
  never a hard failure and never a silent pass.
  Unparsable cache JSON remains a hard failure in every
  era (regression-tested).
- **S-02 (P1):** the endpoint classification rename
  (`confirmed` → `dex-string`, a 2.6.2 calibration
  correction) hard-failed every pre-2.6.2 case whose
  endpoints carried the old label. Verify now validates
  those cases under the era mapping, following the
  existing investigation-legacy pattern, and records a
  note. The retired label in a current-era case still
  fails (regression-tested both directions).

## Round-trips

- Case export/import round-trips pass in the e2e
  battery (private 68/68) and in unit tests, including
  tamper detection (a tampered bundle fails verify).
- Import is now staged: a bundle that fails verification
  never touches the destination directory (C-03,
  regression-tested with a sentinel destination).
- Export refuses non-case directories and bundle paths
  inside the case directory (C-10, regression-tested).

## Schema compatibility

- All 27 schemas parse; every schema is written in the
  bundled validator's subset — the validator now actually
  implements `const` (E-04), so the subset claim in
  references/output-schema.md is true as written.
- comparison.schema.json was rewritten: the old file
  described a pre-2.0 document shape and a real
  comparison.json failed it (E-03). The new schema
  describes the actual producer document; real identical
  and differing comparisons validate clean, and a unit
  test now validates comparison documents against it.
- permissions.schema.json is new (E-09): permissions.json
  was the only case document with no schema. It accepts
  both producer shapes (full document and error
  document); all 13 real on-disk permissions.json files
  in the retained cases validate against it.

## CLI surface

- No verb, flag, or exit-code contract was removed.
  Exit-code discipline was tightened where tools leaked
  tracebacks or exited 0 on failure (C-13, D-02, D-10,
  D-15): bad targets are exit 2, an extract that rejects
  every entry is exit 1, `nar-runtime` diagnose/validate
  exit 1 when NOT READY, the doctor honors --help with
  exit 0. Bare `nar` (help, exit 0) vs bare `nar case`
  (usage error, exit 2) is a deliberate-looking split and
  was left unchanged (C-16, documented as accepted).
- `nar compare` feature maps now stamp the current
  version (was hard-coded 2.4.0, D-14); nar-compare.py
  joined the version-guard test list.

## Python versions

- The floor inconsistency is resolved: pyproject,
  README, and the doctor now all say Python 3.10+, and
  the doctor enforces it (E-12).
- Tested: Python 3.12.3 (system python3 and the project
  venv) — the only interpreters on this VM.
- Python 3.10 / 3.11 execution: NOT RUN (no such
  interpreters installed; R-019 remains documented).

## Clean-extraction behavior

From a `git archive` extraction with an empty fixture
root (the hosted-CI shape): unit suite 637 passed /
16 skipped, every skip printing its reason; the fixture
-gated tests skip, they never silently pass. See
NAR_FINAL_VERIFICATION_REPORT.md for the full CI table.

MIT License.
