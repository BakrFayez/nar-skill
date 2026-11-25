# NAR 2.6.1 — Verification Report

Round type: **verification and security remediation**.
No new features, beyond the two integration items the
owner named (Unreal relationships into the unified
graph; per-analyzer accuracy measurement). Everything
below was executed on this tree; anything not executed
is labeled NOT RUN with the reason. This release is
prepared locally and is **not published** — publication
is the owner's separate authorization.

Trigger: an external review of the published 2.6.0,
followed by the owner's code-level deep audit of the
same code. The review's central claim (version files
disagreeing; the live README still at an older version)
was checked against the live remote before any work:
it does not hold (see §1). The deep audit's claims were
verified one by one against the code and by execution;
their verdicts are in §2.

## 1. Release reconciliation (W1)

- All 18 version-bearing locations guarded by the
  repo's own consistency tests were read with the
  repo's own collector: **uniform at 2.6.0** before
  this round's bump (skill.yaml, SKILL.md,
  pyproject.toml, README version line, plugin.json,
  registry.json, the CLI version constants, and the
  nine stage tools' report fields).
- The live remote was re-read through the connector:
  skill.yaml, pyproject.toml, README, CHANGELOG (top
  entry) and SKILL.md all read 2.6.0.
- SKILL.md finding (the review claimed its
  metadata.version still read 2.5.2): the file,
  locally and on the remote, contains **exactly one**
  version string and it was 2.6.0. The remaining
  "2.5.2" strings in the tree are historical records
  (older changelogs, reports, matrices, baselines), a
  test comment marking a 2.5.2-era fix, and a
  test-fixture parameter in one graph test — none of
  them is release metadata.
- Verdict on the review's desync claim: **not
  reproduced** — the review was written against a
  stale snapshot (it also quotes the 2.5.2-era test
  count, 303; the tree it reviewed runs 425+). No
  version churn was performed; the uniformity is
  recorded here instead.
- One genuine staleness the owner spotted is fixed:
  NAR_2.6.0_UPDATE_REPORT.md still described its
  release as unpublished after it had shipped. A
  dated "Publication status" addendum is appended
  (original text untouched): on 2026-11-24 the 2.6.0
  branch was fast-forwarded into main (ceb9d4d),
  pushed as remote 0ef1817c, the GitHub Release
  "NAR 2.6.0" (tag v2.6.0) was published and marked
  Latest, and nar-ci run #12 succeeded.

## 2. Deep-audit remediation (W0-S)

Per-claim verdicts; each fix carries regression tests
(tests/unit/test_deep_audit_remediation.py, 16 tests).

1. **ZIP path traversal in nar-analyze — CONFIRMED,
   FIXED.** `extract_entry()` wrote archive members to
   destinations built from the raw entry name with no
   containment check; the base-APK call site passed
   the entry name itself as the path. All four call
   sites (base APK, OBB, pak, utoc) now route through
   a contained-destination helper (absolute paths and
   `..` escapes raise) plus a per-entry (4 GiB) and
   per-run total (8 GiB) extraction budget. Defense in
   depth: nar-triage no longer records traversal
   member names as contained APKs/OBBs; they are
   listed under `contained_apks_rejected` /
   `contained_obbs_rejected` with the reason.
   Regression proof includes a hostile container end
   to end (traversal and absolute entry names): the
   pipeline refuses, records the rejection, and writes
   nothing outside the case work directory.
2. **DEX LEB128 hardening — CONFIRMED, FIXED.**
   `_uleb128`/`_sleb128` looped unbounded (a crafted
   encoding leaked IndexError and could spin). Both
   now enforce the buffer bound and the DEX spec's
   5-byte cap, raising DexError. The class-def
   interface list and the proto parameter list —
   offsets the header extent check cannot cover — are
   extent-validated to the same standard. The mutation
   corpus is extended to class-data offsets,
   interfaces_off and proto parameter offsets; all
   raise DexError, never a leaked IndexError or
   struct.error.
3. **Unified archive resource budget — CONFIRMED in
   part, FIXED.** Genuinely unbounded reads found and
   capped with named constants and refusal notes in
   the output: the React Native stage's JS bundle and
   DEX member reads (256 MiB each), the IL2CPP pair
   extraction (1 GiB per file, declared-size and
   streamed-count enforcement, partial files removed),
   and nar-analyze's container extraction (item 1).
   Verified already bounded, no change: nar-godot
   (declared-size precheck before any read), nar-pak
   (capped decompression), nar-unreal (memory-mapped
   parsing; APK-member entries are materialized by zip
   necessity and are inventoried, not extracted
   wholesale). Whole-file parser inputs that are read
   by design (DEX/ELF/ARSC analysis targets) are
   unchanged. No behavior change under the caps;
   outputs for existing fixtures are unchanged.
4. **Graph provenance — CONFIRMED by execution,
   FIXED.** The audit's claim was settled by running
   the builder, not by reading it: with no input data,
   `build_graph()` did create the application node
   citing fingerprint.json → properties although no
   fingerprint data existed; when the package came
   from the permissions data alone, the node still
   cited fingerprint.json. Both reproduced. And
   duplicate node/edge merges kept only the first
   evidence reference, silently dropping the rest —
   also reproduced. Fixes: the application node's
   evidence now follows its actual source
   (fingerprint document, permissions document, or —
   for the generic anchor — the graph document
   itself); merges accumulate up to 8 further distinct
   references in a new `evidence_also` list (schema
   documents the field); provenance is never silently
   discarded now.
5. **Investigation fact separation — CONFIRMED,
   FIXED.** Findings with verification_status
   UNVERIFIED (including findings with no status,
   which default to UNVERIFIED) landed in
   verified_facts. They now land in a new top-level
   **unverified_findings** section; verified_facts
   holds the remaining statuses with the status still
   recorded on each item. The investigation schema
   requires the new section (the builder always emits
   it), the summary view carries it, and the dashboard
   renders it as its own table ("Unverified findings
   (reported, not verified)") only when non-empty;
   dashboards render pre-separation cases unchanged.
6. **Doc freshness — CONFIRMED, FIXED.**
   NAR_CAPABILITY_MATRIX.md framed itself around the
   2.5.2 reconciliation and a 303-test battery. Its
   intro now records the 2.6.0 state (425 tests at
   compilation) and points here for this round's
   numbers.

## 3. Graph + investigation verification on real targets (W2)

Method: nar-analyze was run end to end on six real
targets; each produced case was validated
programmatically (19 checks): graph/investigation/
correlations schema validity against the repo
schemas; every graph edge endpoint exists as a node;
node/edge counts recompute exactly; **every evidence
reference — graph and investigation — names a
document that exists in the case and a field path
that resolves inside it**; DEX classes, endpoints,
JNI bindings, matched components and Unreal edges
reconcile with the stage documents they were built
from; investigation counts recompute; hypotheses are
labeled with basis and confirm/refute; every fact
subject exists in the case data.

| Target (role) | Size | Graph | Investigation (verified / unverified / paths / hypotheses / unknowns) | Result |
|---|---|---|---|---|
| Real Unreal title (shell APK) | 28,430,131 B | 4,156 nodes / 4,344 edges | 65 / 0 / 47 / 9 / 3 | ALL PASS |
| Unity fixture | 63,764,627 B | 1,075 / 1,181 | 8 / 0 / 92 / 52 / 3 | ALL PASS |
| The 273 MB fixture | 273,366,540 B | 69,241 / 88,666 | 235 / 0 / 606 / 166 / 3 | ALL PASS |
| Real XAPK container | 53,826,448 B | 23,651 / 27,706 | 148 / 0 / 653 / 504 / 3 | ALL PASS |
| Project demo APK | 29,297 B | 18 / 22 | 5 / 0 / 3 / 0 / 2 | ALL PASS |
| Carrier APK holding the Unreal title's real pak | 52,507,474 B | 23 / 17 | 0 / 0 / 0 / 0 / 1 | ALL PASS |

Notes:

- unverified_findings is 0 on these cases because
  their security findings carry CONFIRMED,
  STRONGLY_INDICATED or POTENTIAL statuses — none is
  UNVERIFIED. The separation itself is proven by the
  unit tests (UNVERIFIED and status-less findings
  route to the new section; schema validates).
- The Unreal shell APK produces no Unreal package
  relationships: the title ships its Unreal content
  in its OBB, and the package-lifting run covers the
  target APK's own entries (OBB-resident paks are
  inventoried by the pak stage). The carrier case
  exists to verify the relationship path on the same
  title's real pak bytes, unmodified (§5).
- One checker-side defect was found and fixed during
  validation (not a repo defect): the local validator's
  field-path tokenizer rejected hyphens, while the
  permissions document's component keys are the
  manifest tag names verbatim (one contains a hyphen).
  The cited paths resolve correctly; the checker's
  grammar was narrower than the evidence-path grammar
  the builders emit.
- The permissions.json defect in §4 was found by this
  workstream's evidence-resolution design before the
  fix; after the fix, all evidence references resolve
  on all six cases.

## 4. Integration audit (W3)

- **Defect found and fixed: permissions.json was
  cited but never written.** The graph and
  investigation builders cite the permissions
  document (package, permissions, components) as
  evidence, but no stage wrote it into the case — on
  every real case those references dangled. nar-analyze
  now writes the raw permissions document verbatim as
  the `permissions.json` companion (registered in the
  report's companion list). The e2e harness gained an
  evidence-integrity assertion on both analyze cases:
  permissions.json present, and every document
  graph.json cites (primary or accumulated evidence)
  exists in the case.
- **Companion projections: no silent loss.** On all
  six cases, the projections reconcile exactly with
  their source documents: component totals and
  permission counts (manifest projection vs the
  permissions document), library counts
  (native-inventory vs the native document), endpoint
  and host counts (network-analysis vs the endpoints
  document), API host profiles vs endpoint hosts, and
  the application package (application projection vs
  the fingerprint document). (The carrier case has no
  manifest; both sides agree on empty, as expected.)
- **CLI surface exercised on produced cases:**
  `nar case verify` passes (input hash re-verified,
  stage-cache integrity verified); `nar case graph`
  filters return the right subsets (e.g. 4,034 class
  nodes on the Unreal case); `nar case investigation`
  prints the summary including the new
  unverified_findings count; `nar case export` →
  `import` → `verify` round-trips a real case (39
  files, bundle manifest intact), and the imported
  case re-passes all 19 validation checks.
- Correlations ↔ graph reconciliation is part of the
  19 checks in §3 (JNI nodes equal correlation
  bindings; implements edges equal matched
  components; counts recompute internally).

## 5. Unreal → graph integration (named integration item)

nar-unreal's relationship records (classic
table-derived and Zen) now join the unified graph when
a case includes Unreal analysis: `unreal_package` and
`unreal_object` nodes (14 node kinds total) and
`unreal_class` / `unreal_super` / `unreal_outer` /
`unreal_template` / `unreal_depends` edges, under the
graph's discipline — table-resolved relationships are
high confidence, Zen cross-package resolution text is
medium, unresolvable targets are kept explicitly with
status "unresolved" at low confidence, and the
upstream record caps are noted in the graph's notes.
Evidence cites the report's engine sections by field
path. Standalone nar-unreal output is unchanged, and
cases without Unreal analysis are byte-identical to
before (guarded by tests).

Verification on the carrier case (the real title's
real 53.7 MB pak, unmodified, carried in a minimal
APK so the pipeline routes it): nar-unreal inspected
**5 packages**; the graph gained exactly **5
unreal_package nodes, 15 unreal_object nodes and 10
unreal edges** (5 unreal_class, 5 unreal_template),
and the validator's reconciliation — graph Unreal
edges equal nar-unreal's shown edges, package counts
equal — passes. This pak's packages carry no
super/outer/depends records, so those edge kinds are
covered by the synthetic regression tests
(tests/unit/test_graph_unreal.py) rather than by this
case. Zen relationships on a real IoStore title were
not re-run this round: no real IoStore-bearing APK
remains in the local fixture tree (the 2.6.0 Zen
verification corpus is not on this machine anymore);
the Zen path is covered by the same builder code and
the synthetic tests. Recorded as a limitation, not
papered over.

## 6. Accuracy / false-positive measurement (named item)

Measured with the benchmark harness on this tree
(tests/benchmarks/run_benchmarks.py; figures recorded
in tests/benchmarks/baseline-2.6.1.json). Synthetic
and real corpora are always reported separately; role
labels only.

| Analyzer | Corpus | Measure | Result |
|---|---|---|---|
| Protection attribution (attributed commercial packer) | real: 1 protected + 9 clean | precision / recall | **1.0 / 1.0** (1/1 detected, 0 false positives) |
| Engine identification | real: 6 labeled positives | recall on labeled positives | **1.0** (6/6) |
| Engine identification | real | precision | **NOT RUN** — no labeled engine-negative real corpus exists locally |
| Engine identification | synthetic: 8 labeled framework fixtures | accuracy | **1.0** (8/8) |
| Format identification | real: 10 labeled | accuracy | **1.0** (10/10) |
| Format identification | synthetic: 5 builder-labeled files (DEX, ELF, Godot pack, Unreal pak, IoStore TOC) — new this round | accuracy | **1.0** (5/5) |
| Endpoint classification | — | — | **NOT RUN** — no labeled endpoint corpus exists locally; ground truth would require hand-labeled URL classifications for real apps and none is recorded. The network stage's counts are reported per case, unmeasured; no figure is claimed. |

The two NOT RUN entries are the honest state of the
local corpora, stated in the baseline file itself —
no accuracy figure is invented for an analyzer
without labels.

## 7. Performance — R-006 (W4)

Profile first (VmHWM sampled every 0.5 s, stage
boundaries from the case's cache timestamps, 273 MB
fixture): before the DEX stage the process sat at
488 MB; **the peak was reached inside the DEX stage
window and never grew afterwards** — the documented
diagnosis (the orchestrator's DEX JSON round-trip)
is confirmed as the peak-setter, and the downstream
builders were never the problem.

Restructure (stdlib only, DEX stage only): the tool's
stdout is spooled to a file instead of captured as a
string; the spool is promoted verbatim to the stage
cache (byte-identical to the classic cache write);
the projection the builders consume is extracted
element by element over a memory map — each dex_files
element is parsed, projected to exactly the fields
the correlation/graph builders read, and discarded;
the indent=1 companion is written by a token-level
re-serializer that copies scalar/string tokens
verbatim and regenerates only whitespace
(byte-identical to the classic companion write,
property-tested against the stdlib encoder). Any
failure in the streaming machinery removes its
partial artifacts and falls back to the classic stage
path unchanged.

| Measurement (identical input, harness discipline) | Peak RSS |
|---|---|
| 2.6.0 baseline (baseline-2.6.0.json) | 1,887,678,464 B |
| This tree before W4 (reference run) | 1,887,891,456 B |
| This tree after W4 (case run) | 1,532,669,952 B |
| This tree after W4 (benchmark harness's own run, baseline-2.6.1.json) | 1,536,069,632 B |
| After W4, VmHWM sampled under memory pressure | 919,683,072 B |

Reduction under the harness discipline: **−18.8%**.
The quiet-run figure includes reclaimable file-backed
pages from memory-mapping the 312 MB stage document
twice (extraction, then companion writing); under
memory pressure those pages are reclaimed and the
sampled peak roughly halves versus 2.6.0. Remaining
footprint: per-element parse transients (elements are
26–47 MB of text), the retained slim projection, mmap
pages, and allocator retention. A windowed
(non-mmap) reader is the documented next step; it was
not taken in a verification round.

**Hard correctness gate: PASS.** On the 273 MB
fixture every case file is byte-identical to the
pre-change run, except the three network-derived
files (endpoints document, its cache copy, and the
report), which differ only in (a) per-run temporary
work-directory names embedded in path values and
(b) one list ordering. A control comparison — two
runs of the identical pre-change code — differs in
the same three files the same way, proving both are
pre-existing run-to-run variance, not effects of this
change. The demo, Unity and carrier cases are
identical modulo the same work-directory paths.
Wall time on this shared box is load-dependent and is
not reported as a result.

## 8. CI expansion (W5)

Prepared in the repo; **the workflow file is applied
through the GitHub web UI at publication time** (the
push channel cannot carry workflow files — it is
excluded from push manifests, as before).

- Install step: `pip install pytest pyyaml` — the
  YAML validity tests now run in CI instead of
  skipping.
- New `e2e-public` job: generates the public synthetic
  fixtures (tests/generate_fixtures.py) and runs the
  harness in its new public mode (NAR_E2E_PUBLIC=1).
  Public mode never consults the private fixture tree
  or its manifest; fixture-bound cases SKIP through
  their existing guards; the doctor case SKIPs rather
  than FAILs when the host lacks the full core
  toolchain (hosted runners do not preinstall apktool,
  jadx or the Android build-tools).
- Local verification of the exact CI commands from a
  clean `git archive` extraction with no private
  fixtures: unit-and-syntax job — **459 passed, 4
  skipped** (the 4 skips are private-fixture-dependent
  tests, absent by design on a bare clone; with PyYAML
  importable the YAML tests run and pass); fixture
  generation succeeds; public e2e — **14 passed, 0
  failed, 48 skipped**, exit 0. Public mode was also
  run with the fixture variable deliberately pointed
  at the private tree to prove isolation (same
  result). A unit test (test_e2e_public_mode.py)
  guards the switch. First hosted run after
  publication remains the proof for the hosted
  runner's exact behavior.

## 9. Final battery (this tree, 2.6.1)

- pytest: **459 passed, 4 skipped** (skips =
  private-fixture-dependent tests with fixtures
  unbound in that run; with PyYAML present the YAML
  tests are among the passed).
- e2e (private fixtures bound): **67 passed, 0
  failed, 0 skipped** — including the new
  evidence-integrity assertions on both analyze cases.
- e2e public mode: **14 passed, 0 failed, 48
  skipped**, exit 0.
- doctor: **READY**.
- Version uniformity: all 18 guarded locations at
  2.6.1 (repo's own collector), plus the graph and
  investigation builder defaults.
- Hygiene greps: no fixture-identifying names,
  packages or hashes anywhere in the tree; the only
  credit line is the project credit line.

## 10. NOT RUN — and the owner's device checklist

**Physical-device runtime testing: NOT RUN by
design.** No device is attached to this machine; the
emulator verification of the runtime module was done
in 2.6.0 and is not repeated here. Owner checklist
against a physical device (the Poco-class ARM64
handset used previously):

1. Connect the device (USB debugging authorized) and
   run `python3 scripts/nar.py doctor` — adb must see
   the device.
2. `python3 scripts/nar-runtime.py diagnose` (or
   `nar runtime diagnose`): confirm the device is
   classified physical (not emulator), its ABI and API
   level are read correctly, and the Frida
   compatibility verdict matches the installed
   frida-tools version.
3. `nar runtime status` with frida-server of the
   **same** version as the host frida-tools running
   on the device: the version match must be reported,
   not worked around.
4. Attach-mode runs of the four bundled scripts
   (network monitor, file-io monitor, JNI trace, SSL
   observation) against a test app the owner controls:
   `frida -U -p <pid> -l scripts/frida/<script>.js` —
   each must attach, emit its banner events, and
   detach cleanly.
5. Record the outcome against this report; any
   mismatch is a defect for the next round.

Also NOT RUN / open, stated plainly:

- The hosted-CI first run of the new e2e-public job
  (only possible after publication; §8).
- Zen relationships on a real IoStore title (§5 —
  no such APK remains locally; synthetic coverage
  only this round).
- Kotlin d1 interpretation, CDEX payload decoding,
  Unity full object parsing: unchanged documented
  limitations from 2.6.0, out of this round's scope.
- Publication itself: no push, no tag, no merge, no
  release was performed. Remaining steps at the
  owner's authorization: merge the branch, push
  (manifest excludes workflow files), apply ci.yml
  via the web UI, create the release titled exactly
  "NAR 2.6.1", append the sync record, rebuild the
  distribution ZIP, and refresh the installed skill
  copy.
