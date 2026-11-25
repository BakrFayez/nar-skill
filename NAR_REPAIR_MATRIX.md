# NAR Repository-Wide Repair Matrix

This matrix is the record of the 2.6.0 repository-wide
repair and upgrade program (branch `upgrade-2.6.0`). It was
seeded by the Phase 1 audit (2026-11-24) and is completed
phase by phase: every inventoried issue is either fixed
(with a regression test and a verification result) or
documented here with the technical reason it cannot
currently be resolved. Statuses use the project
vocabulary: IMPLEMENTED_AND_TESTED,
IMPLEMENTED_BUT_UNVERIFIED, PARTIALLY_IMPLEMENTED,
PLANNED, MISSING, BROKEN, UNSUPPORTED, NOT_APPLICABLE.
Corpora are named by role label only, as everywhere in
this repo.

## Phase 1 baseline (untouched tree, 42516f7 == 2.5.2)

- pytest: **332 passed, 0 failed** (executed on this
  worktree before any edit).
- doctor: **Core toolchain: READY** (22 checks, including
  skill-yaml OK).
- e2e: 65 passed / 0 failed at the 2.5.2 release battery
  on this identical tree; re-executed for this program's
  baseline record (result appended when the run lands).
- Static audit: all 161 tracked files inventoried
  (24 scripts + nar.py + nar-doctor.sh, 18 narlib modules,
  24 schemas, 37 unit test files + e2e harness + synthetic
  fixture system, 24 reference guides, plugin/pyproject/
  registry configs). `compileall` clean; all 24 schemas
  parse; registry.json and protection-signatures.json
  parse; every script CLI answers `--help` with exit 0;
  narlib cross-imports all resolve; no TODO/FIXME/XXX
  markers anywhere; no `shell=True`, `os.system`, `eval`
  or `pickle` in shipped code (the one `__import__` is
  narlib/registry.py probing module names declared in the
  repo's own registry.json — by design, checked OK).
- Version state: 2.5.2 in all 18 version-bearing
  locations (guarded by test_docs_consistency); git has
  no tags; release branches from earlier programs remain
  as worktree branches (history, not defects).

## Issue inventory (Phase 1 seed)

Severity: P0 = wrong/absent core behaviour, P1 = missing
advertised capability or real defect, P2 = hardening /
consistency, P3 = cosmetic / dead code.

| ID | Component | Issue | Severity | Root cause | Disposition |
|---|---|---|---|---|---|
| R-001 | scripts/nar-unity.py | Unused `io` import (line 25) | P3 | Leftover from an earlier refactor | Fix in repair pass |
| R-002 | narlib/oat.py, formats | CDEX is identified and carved but no header/structure parsing exists; capability matrix lists payload decoding Unsupported | P1 | Never implemented; no real CDEX corpus locally | Phase 3: header + section-table parsing per the public compact-DEX layout, synthetic-verified, honest labels |
| R-003 | narlib/dexdis.py | Only a block summary exists; no control-flow graph edges | P1 | block_summary was the scoped increment in 2.5.0 | Phase 3: CFG edges from block leaders / terminators / try ranges |
| R-004 | nar-dex / narlib/dex.py | Call edges are emitted per-DEX but there is no resolved cross-reference / call-graph artifact (callers, callees, unresolved split) | P1 | Edges never assembled into a graph product | Phase 3 + Phase 7 |
| R-005 | narlib/dex.py (Kotlin) | Kotlin `@Metadata` d1/d2 payloads not interpreted (header fields only) | P2 | kotlinx-metadata protobuf schema subset never implemented | Phase 3: implement a genuinely tested subset or document the boundary |
| R-006 | scripts/nar-analyze.py | Peak memory ~1.9 GB on the 273 MB fixture: stage JSON is captured whole, parsed, re-serialized twice and retained (diagnosed in 2.5.2 W4) | P1 | Orchestrator stage plumbing passes JSON on stdout | Documented limitation unless a low-risk fix lands; restructure would break the stage-cache format |
| R-007 | scripts/nar-runtime.py | No device capability detection, no emulator-vs-physical identification, no Frida compatibility diagnostics, no connection recovery | P1 | Runtime module grew around session records only | Phase 9 |
| R-008 | narlib/correlations.py | Correlations are flat join lists, not a graph: no nodes/edges artifact with provenance, confidence, evidence references, export or search | P1 | Correlations predate the graph requirement | Phase 7: graph.json companion |
| R-009 | (absent) | No investigation layer: findings are never synthesized into prioritized, evidence-cited investigation paths | P1 | Never built | Phase 8: deterministic offline investigation.json companion |
| R-010 | scripts/nar-flutter.py | No plugin registration or platform-channel inventory | P1 | Flutter module stops at versions + AOT markers + assets | Phase 6: evidence-based inventory from manifest/DEX/native artifacts, inference labeled |
| R-011 | scripts/nar-rn.py | Native-module / bridge mapping is partial (bundle-side only) | P2 | DEX-side bridge evidence never joined | Phase 6 |
| R-012 | scripts/nar-unity.py | Serialized-file inspection is census-only via the optional UnityPy module; no first-party bundle/serialized-file header parse | P2 | Own parser never written; UnityPy optional covers census when present | Phase 5: first-party header-level parse where genuinely implementable + tested; boundary documented |
| R-013 | scripts/nar-unreal.py / narlib/uasset.py, zen.py | Import/export/depends maps exist per package but no UObject relationship extraction across them | P2 | Never assembled | Phase 5: relationship records from existing maps, joined into the Phase 7 graph |
| R-014 | scripts/nar-godot.py | Scene/resource relationships inside packs are not extracted (listing + per-entry types only) | P2 | Text scene/resource reference parsing never implemented | Phase 5: ext_resource-style reference extraction where the format exposes it |
| R-015 | .github/workflows/ci.yml | CI installs only pytest; the PyYAML-guarded tests SKIP in CI instead of running | P2 | Workflow predates the YAML validation work | Cannot be edited through this program's push channel (documented in 2.5.2 W1): exact required change recorded as an owner follow-up in the 2.6.0 update report |
| R-016 | tests | Code coverage has never been measured | P2 | No coverage tooling in the test environment | Phase 2/11: measure with available tooling (coverage.py in the test venv, else stdlib trace) or state unmeasured with the reason |
| R-017 | scripts/nar-report.py | Dashboard has no sections for graph / investigation / engine-depth data (the data did not exist) | P2 | Data products absent | Phase 12, after Phases 5–8 land their data |
| R-018 | docs | No SECURITY.md (responsible-use / analysis-boundary statement as a standalone file) | P3 | Boundaries live inside guides, never a root file | Phase 14: create only with real, repo-specific content |
| R-019 | pyproject.toml vs guides | `requires-python >=3.10` while guides say the scripts run on Python 3.9+; neither side correctable on evidence (no 3.9 runtime exists here; only a 3.9-grammar parse check) | P3 | Packaging metadata and guide text written at different times | Documented: left unchanged, reason recorded (carried from 2.5.2 W6) |
| R-020 | scripts/nar-analyze.py | No adaptive planning, stage retry or cancellation policy (capability matrix records this) | P2 | Orchestrator is a fixed pipeline by design | Phase 8 covers retry/cancellation at the investigation layer; pipeline-level policy documented as a limitation |

## Repair record

(Filled per phase group as the program runs; the final
table at the end of this file is the completed matrix:
component / issue / severity / root cause / fix / test /
verification / remaining limitations.)

### Phases 3 + 4 — DEX and native (branch worker A)

- **R-003 FIXED — IMPLEMENTED_AND_TESTED (synthetic).**
  `narlib/dexdis.py` gained `control_flow_graph()` +
  `cfg_batch()`: blocks with code-unit and
  instruction-index ranges; edges typed fallthrough /
  branch / switch / goto / return-exit / try-handler
  (handler exception type carried). Exposed as
  `nar-dex --cfg` under the existing targeted-selection
  rules (unscoped refused). Tests: hand-computed exact
  edge sets for branch, switch and try/catch-all
  methods; disassembly listings asserted unchanged
  (the dexdump-oracle listings still pass
  byte-identical).
- **R-004 FIXED — IMPLEMENTED_AND_TESTED (synthetic +
  real).** `narlib/dex.py assemble_call_graph()`:
  nodes are defined methods, invoke edges resolved
  against the defining DEX or across the DEX set of
  one APK (cross-DEX resolutions counted and labeled),
  external targets counted with a capped sample and
  truncation flag, top caller/callee lists capped,
  per-method xref via `nar-dex --xref`. Real
  verification on a large multi-DEX corpus fixture
  through the shipped CLI: 431,390 of 736,471 invoke
  edges resolved; a second real fixture: 111,211 of
  180,290.
- **R-002 FIXED (header level) — IMPLEMENTED_AND_TESTED
  (synthetic).** New `narlib/cdex.py` parses the
  136-byte compact-DEX header per the public AOSP
  layout (standard header + feature flags, debug-info
  offsets, owned-data bounds) and the six-entry
  section table, with named errors on malformed input.
  Wired into `formats.identify` (bare CDEX gains
  `details.cdex_header`) and into `narlib/oat.py`
  carving (cdex hits gain header facts and a
  trustworthy file size used to bound the carve).
  **Remaining limitation:** string contents and the
  compact payload are NOT decoded — stated in the
  module (`payload_decoded: False`); no real CDEX
  corpus exists locally, so verification is synthetic.
- **R-005 PARTIALLY FIXED — PARTIALLY_IMPLEMENTED.**
  Implemented and verified: `dex.kotlin_d2_stats()` +
  the nar-dex `kotlin.metadata.d2_cross_check` —
  descriptor-shaped d2 strings cross-checked against
  the DEX's own type table. Measured on the real
  Kotlin corpus fixture (10,213 annotations):
  d2[0] equals the annotated class in 4,420/4,425
  checked (99.89%); descriptor entries present in the
  type table 26,252/28,550 (91.95% — the residual is
  cross-DEX/library types, which is why this is a
  cross-check, not a decode); signature-embedded types
  20,325/20,420 (99.53%). **Not implemented, with
  reason:** the d1 payload is a kotlinx-metadata
  protobuf stream; without the full versioned schema
  no subset of d1 can be verified against ground
  truth in this repo (d2 worked precisely because its
  strings are plain and independently checkable). d1
  stays decoded-as-values only; the boundary is
  stated in the nar-dex report.
- **Obfuscation indicators (Phase 3 addition) —
  IMPLEMENTED_AND_TESTED (synthetic).**
  `dex.identifier_shape_stats()` + per-DEX
  `obfuscation_indicators` in nar-dex: short-name
  ratio indicators with sample-count floors and
  confidence labels, plus an explicit low-confidence
  no-pattern record; never a binary verdict. Tests:
  short-named synthetic DEX scores medium/high,
  long-named control scores low only.
- **Native dependency graph (Phase 4) —
  IMPLEMENTED_AND_TESTED (synthetic + real).**
  nar-native gained `library_dependency_graph`:
  bundled-library nodes + external dependencies
  labeled external, every DT_NEEDED edge with
  to-kind, caps (500 nodes / 5,000 edges) with
  truncation flags. The pre-existing bundled-only
  `dependency_graph` shape is preserved.
- **Native behavior indicators (Phase 4) —
  IMPLEMENTED_AND_TESTED (synthetic).**
  `nar-native.behavior_indicators()`: symbol-cluster
  pattern indicators (process manipulation, dynamic
  code loading, network access, and the combined
  cluster), each with matched-symbol evidence and
  confidence, weak single symbols suppressed, and
  wording that states these are pattern indicators,
  not behavior verdicts.
- **Native control-flow analysis — UNSUPPORTED
  (documented).** No disassembler exists in the
  stdlib-only toolchain; Ghidra is the registered
  escalation path. No code written.
- Defects found in-cycle by Worker A (all in its own
  new code, all fixed with regression coverage): a
  CDEX header field-offset error caught by the
  round-trip test; an f-string syntax error in new
  human output caught by the doctor compile check;
  misleading wording in the low-confidence
  obfuscation record, corrected.

### Phases 5 + 6 — engines and frameworks (Worker B)

- **R-001 FIXED.** Unused `io` import removed from
  `scripts/nar-unity.py` (zero references verified).
- **R-012 PARTIALLY FIXED — IMPLEMENTED_AND_TESTED
  (header level).** nar-unity gained first-party
  UnityFS parsing: bundle header, blocks-info (block
  + node tables), decompression for stored and
  Unity LZMA1 payloads via stdlib lzma, and
  serialized-file header parsing (classic + format-9+
  endianness + format-22 extended header), with
  named errors and `bundle_inspections` wired into
  the report. Synthetic round-trips (v22 stored,
  v17 LZMA, boundary cases, malformed) + real
  fixtures by role. **Remaining limitations (stated
  in the report output itself):** LZ4/LZ4HC/LZHAM
  blocks are inventoried, never decoded (no stdlib
  decoder exists); UnityWeb/UnityRaw get header
  strings only; full serialized-file object/type-tree
  parsing remains out of scope (multi-week
  subsystem).
- **R-013 FIXED — IMPLEMENTED_AND_TESTED (synthetic;
  real for classic).** nar-unreal gained
  `classic_relationships()` and `zen_relationships()`:
  export class/super/outer/template references
  resolved through the import/export tables by
  package index, plus depends-map edges; bounded at
  250 edges with accounting; every edge labeled with
  its source field and the record labeled
  table-derived. Synthetic builders assert exact
  edge sets (3 classic, 2 Zen); real classic
  packages from the pak fixture role carry correct
  edges (387 packages, the 5 under the cap checked).
  **Remaining limitation:** Zen relationships are
  synthetic-verified only — no Zen-bearing package
  fixture is bound in the local corpus. Integration
  boundary: these relationships live in nar-unreal's
  standalone reports; the Phase 7 graph consumes
  nar-analyze stage documents, so Unreal package
  edges are not joined into graph.json (recorded
  under R-008).
- **R-014 FIXED — IMPLEMENTED_AND_TESTED
  (synthetic); real boundary verified.** nar-godot
  gained `parse_text_scene()` + `scene_relationships()`:
  ext_resource (id/path/type/uid), sub_resource ids,
  node counts, instance references joined to external
  paths, for Godot 4 string ids and Godot 3 integer
  ids; caps with accounting; encrypted entries
  counted, never decoded; bare .tscn/.tres accepted;
  binary content rejected honestly. Real pack
  fixture: all 36 scenes are binary .scn exports, so
  0 text candidates is the correct result and the
  new explanatory note fires. **Remaining
  limitation:** node properties and hierarchy
  semantics are not reconstructed — header-declared
  references only.
- **R-010 FIXED — IMPLEMENTED_AND_TESTED (synthetic
  + real).** nar-flutter gained `plugin_inventory`:
  DEX class-table evidence (generated plugin
  registrant presence + location, plugin-namespace
  classes, FlutterPlugin interface implementers),
  platform-channel string candidates from DEX and
  native-library strings (each labeled string
  evidence with its source artifact; list-level
  confidence "candidate"; presence ≠ registration
  stated), and the manifest `flutterEmbedding`
  value via a minimal binary-AXML walk. Real
  fixture: registrant present, embedding 2, 7
  framework-namespace classes, 92 channel
  candidates. **Documented behaviour on minified
  builds:** when the framework's own types are
  renamed (R8), the interface count is legitimately
  0 and the report now carries an explanatory note
  in exactly that case (regression-tested).
- **R-011 FIXED — IMPLEMENTED_AND_TESTED (synthetic
  + real).** nar-rn gained `bridge_mapping`: bridge
  class presence per DEX, registrar classes from
  the class table, codegen markers (view-manager
  namespace classes, *ManagerDelegate /
  *ManagerInterface classes, Native<Module>Spec
  classes), and the bundle↔DEX module-name join
  (matched vs bundle-only, string evidence). For
  Hermes bundles the join is recorded unavailable
  with the reason (names not attributable from the
  bytecode string table) and the DEX evidence
  stands alone. Real Hermes fixture: 2/4 bridge
  classes present, 85 Native*Spec codegen classes.
  Two defects fixed in-cycle with regression tests:
  TurboModuleManagerDelegate was miscounted as a
  Fabric view-manager delegate by the suffix rule
  (now excluded by name, stated in the evidence);
  Native<Module>Spec codegen classes were not
  inventoried at all (added).

### Phases 7 + 8 — graph and investigation (Worker C)

- **R-008 FIXED — IMPLEMENTED_AND_TESTED
  (synthetic).** New `narlib/graph.py` + the
  `graph.json` case companion: nodes (application,
  dex_file, class, native_library, jni_function,
  network_endpoint, component, permission, engine,
  security_finding, asset, network_library) and
  edges (contains, declares, implements,
  exports_jni, references_endpoint, uses_library,
  declares_component, requests_permission,
  detected_as, finding_about, depends_on), every
  node/edge carrying source stage, provenance
  (stage + field path) and an evidence reference;
  edge confidence derived only from the source
  data's own verification status / detection
  confidence. One-sided joins are preserved with
  explicit statuses (declaration-only, export-only,
  implementation-only, no-code-reference, external,
  unmatched) — never dropped, never upgraded.
  Security findings link only to an existing node
  or the application node — no target is invented
  from free text. `schemas/graph.schema.json`
  added (26 schemas total); graph.json is validated
  through the existing companion path before
  writing. `correlations.json` is byte-compatible
  (builder and writing path untouched). Query
  surface: `nar case graph CASE_DIR` with
  --kind/--edge-kind/--min-confidence/--text
  filters, routed through the existing `nar case`
  verb (no new top-level verb). Incremental
  behaviour is the stage cache: graph.json records
  `contributing_stages` and rebuilds from cached
  stage outputs. **Documented boundaries:** the
  schema also admits `binds_jni` / `references_class`
  edge kinds that no builder emits (no stage data
  supports a distinct edge); Unreal package
  relationships (R-013) live in nar-unreal's
  standalone reports, not in nar-analyze stage
  documents, and are therefore not joined into
  graph.json.
- **R-009 FIXED — IMPLEMENTED_AND_TESTED
  (synthetic).** New `narlib/investigation.py` + the
  `investigation.json` companion: deterministic,
  offline, rule-based, stdlib-only, no external
  calls. Sections: verified_facts (lifted from
  findings/correlations with stage + document +
  field-path evidence), paths (ranked rules:
  INV-EXPORTED-NO-PERMISSION, INV-FINDING-FOLLOWUP,
  INV-CLEARTEXT, INV-JNI-DECL-ONLY,
  INV-COMPONENT-ONE-SIDED, INV-ENDPOINT-NO-CODE-REF,
  INV-JNI-EXPORT-ONLY, INV-NETLIB-LIBRARY-ONLY —
  each with rule id, triggering evidence,
  confidence), hypotheses (separate section, each
  labeled hypothesis with basis + confirm/refute
  conditions), unknowns (runtime behaviour, dynamic
  JNI binding, actual endpoint use). A dedicated
  test asserts every referenced entity exists in
  the case data (fabricated case + generated case).
  Optional: --no-investigation / --no-graph flags
  and NAR_NO_* / NAR_DISABLE_* env switches; with a
  layer disabled, all other outputs are produced as
  before. CLI view: `nar case investigation`.
### Phases 9 + 10 — runtime and security (Worker D)

(First attempt blocked by an execution-risk check;
the owner gave his explicit go-ahead on 2026-11-24
to complete Phases 9–14 and run the project's code
and tests, and the work below was executed under
that approval.)

- **R-007 FIXED — IMPLEMENTED_AND_TESTED (synthetic
  + live emulator).** nar-runtime gained:
  `device_capabilities()` (one getprop dump per
  device: ABI/abilist, API level, boot state; adbd
  root state via `id`; frida-server presence +
  version probe); `classify_device()`
  (emulator-vs-physical: strong markers decide
  alone, weak markers need two, empty property set
  = unknown — never guessed; every verdict carries
  its evidence); structured environment diagnostics
  (`nar-runtime diagnose [--serial] [--package]
  [--recover]`, also embedded in `status()`): seven
  checks with named failure reasons (ADB_NOT_FOUND,
  NO_DEVICE_ATTACHED, DEVICE_NOT_READY,
  BOOT_NOT_COMPLETED, APP_NOT_INSTALLED,
  FRIDA_SERVER_NOT_ON_DEVICE, FRIDA_VERSION_MISMATCH,
  FRIDA_VERSION_UNKNOWN, …) and an actionable fix
  per failure; `frida_compatibility()` (major.minor
  match, patch tolerated and reported, mismatch
  message names both versions and the remedy);
  `recover_connection()` (bounded: hard cap of 5
  attempts, clamped, full history — no infinite
  loops). Tests: 19 in
  tests/unit/test_phase9_runtime_hardening.py
  (recorded fake-runner outputs). **Live evidence**
  (local emulator, API 26 google_apis x86_64, QEMU
  TCG, boot_completed verified first; ONLY the
  project's own demo fixture, its x86_64 rebuild,
  was exercised): diagnose ok with zero failure
  reasons and all seven checks passing with the
  demo package check; classification = emulator
  with property evidence; frida-server 17.27.4 =
  host 17.27.4 match, proven by use (host process
  enumeration through the server); status =
  verified-live. A live-found defect was fixed
  in-cycle: a `frida-server.log` sidecar shared the
  server name prefix and silently suppressed the
  version probe (candidate filter fixed +
  regression test). **NOT RUN:** physical device
  (owner's device only); live destructive recovery
  test (the only target was healthy — the recovery
  loop is synthetic-verified); a deliberately
  mismatched frida-server was not installed live
  (mismatch path synthetic-verified).
- **Phase 10 — IMPLEMENTED_AND_TESTED.**
  (a) REAL GAP (P1): `nar-analyze import_case` used
  raw `ZipFile.extractall` with only a name check —
  no entry-count/size/ratio/symlink limits on
  case-bundle imports. It now extracts exclusively
  through safearchive and aborts on any rejected
  entry (regression tests: symlink bundle refused
  with no link created, traversal refused,
  pre-existing-symlink-dir escape refused, FIFO
  refused; ZIP hardlinks probed — no such entry
  type exists, nothing invented). (b) safearchive
  limits are now enforced on ACTUAL decompressed
  bytes, and a corrupt/CRC-lying entry rejects
  alone with its partial file removed instead of
  aborting the whole extraction (crafted-archive
  regression test). (c) Subprocess inventory
  PROBED-OK: AST-verified list-form calls, no
  shell=True/os.system/eval/pickle, every
  subprocess.run timed except nar.py's interactive
  dispatcher (documented deliberate exception) —
  encoded as a standing regression test, no fix
  invented. (d) Temp files: predictable
  `gettempdir()/nar-<tool>-<stem>` defaults in
  nar-analyze/nar-il2cpp/nar-rn replaced with
  mkdtemp (unpredictable, 0700); nar-godot's
  mkdtemp leak on parse-error runs removed in a
  finally block. (e) Parser read caps: formats
  whole-file structural reads (vdex/odex/cdex/art)
  capped at 512 MiB with a named skip note;
  nar-godot bare pack (512 MiB) / bare scene
  (64 MiB) caps and a declared-size check before
  embedded-pack decompression. Probed-OK with
  evidence: dex.py header-extent validation,
  Godot directory count cap, the 2.5.2 mmap
  readers, dotnetmeta, nar-input→safearchive.
  Tests: 12 in tests/unit/test_phase10_hardening.py.

### Phases 11–14 — benchmarks, dashboard, CLI, docs (Worker E)

- **R-016 FIXED — MEASURED.** Coverage tooling was
  absent from the test environment (verified);
  coverage.py was installed into the test venv only
  (test-side; shipped code stays stdlib-only) and
  line coverage of the shipped code over the unit
  suite was measured. The figure, tool version,
  command and scope are recorded in
  tests/benchmarks/baseline-2.6.0.json (re-measured
  on the final merged tree in Phase 15).
  Limitation: line coverage of in-process
  executions; e2e-only paths are not in the number.
- **Phase 11 — IMPLEMENTED_AND_TESTED.**
  tests/benchmarks/baseline-2.6.0.json re-measures
  the four 2.5.2 reference commands on
  byte-identical inputs with the same harness:
  peak RSS within +0.13% / +1.98% / +0.73% / +0.13%
  of the 2.5.2 after-values (no regression; the
  analyze peak stands — R-006); the analyze wall
  time is flagged non-comparable in the file (the
  run shared the box with this phase's coverage and
  suite runs). Synthetic-corpus parser field
  completeness: 85/85 asserted fields across 11
  fixtures; format identification per generated
  file recorded (the measurement exposed the v11
  pak defect fixed under Phase 13).
- **R-017 FIXED — IMPLEMENTED_AND_TESTED.**
  scripts/nar-report.py (the authoritative
  dashboard generator) renders a Unified graph
  section (totals + counts by kind + contributing
  stages) and an Investigation section (verified
  facts / ranked paths / hypotheses labeled
  unverified / unknowns in four separate tables,
  50-row caps with companion pointers) only when
  the companions exist; absent/empty companions
  produce no sections. Fully offline verified
  (0 external references); regression tests cover
  rendered/absent/empty cases, and the sections
  were verified on a real full case produced by
  the Phase 11 analyze run.
- **Phase 13 — IMPLEMENTED_AND_TESTED.** Audit of
  the unified CLI (27 dispatcher verbs + case
  router + version) and all 24 standalone scripts:
  --help exit 0 everywhere; nonexistent targets
  rejected with exit 2, structured error, no
  traceback. Two real defects fixed with
  regression tests: (1) `nar case graph` /
  `nar case investigation` exited 1 for a missing
  companion and raised a traceback on malformed
  JSON — now exit 2 with a structured error;
  (2) v11 pak identification — the footer magic
  sits 204 B from EOF, outside the 64 B tail scan;
  the pak scan now reads a bounded 4 KiB tail.
  nar-runtime.py was audited and needed no CLI
  change (recorded). No breaking changes.
- **R-018 FIXED.** SECURITY.md created at the repo
  root with repo-specific content only, every
  mechanism grep-verified in the shipped code
  first: the analysis-only boundary (encrypted
  containers inventoried, never decrypted; Oodle
  refused by name; no signature/license/payment
  bypass), untrusted-sample handling (static
  analysis never executes the sample; safearchive
  guards with their actual limits; parser caps),
  report redaction of credential-shaped strings,
  responsible use.
- **Phase 14 — IMPLEMENTED_AND_TESTED.**
  NAR_ARCHITECTURE.md (cdex/graph/investigation
  modules, CFG + call-graph facts, 21 narlib
  modules, 26 schemas), NAR_CAPABILITY_MATRIX.md
  (rows for all Phase 3–8 and 11–13 outcomes;
  Phase 9/10 rows finalized by the coordinator in
  Phase 15), NAR_TEST_MATRIX.md (2.6.0 benchmark /
  coverage records), SKILL.md (the missing
  nar-dex --cfg/--xref routing row, verified
  against the real CLI), README (SECURITY.md in
  the structure block), references/benchmarks.md
  (completeness + coverage methodology).

## Final repair matrix (completed, Phase 15)

| ID | Disposition | Remaining limitation |
|---|---|---|
| R-001 | FIXED (unused import removed) | — |
| R-002 | FIXED at header/section level, synthetic-verified | CDEX payload (strings, compact data) not decoded; no real CDEX corpus exists locally |
| R-003 | FIXED — CFG edges, synthetic-verified, oracle listings unchanged | — |
| R-004 | FIXED — resolved call graph + xref, synthetic + real fixtures | External targets counted/sampled, not resolved (they are not in the file) |
| R-005 | PARTIALLY FIXED — d2 cross-check implemented and measured on the real corpus | d1 not interpreted: no verifiable subset exists without the full versioned kotlinx-metadata schema |
| R-006 | DOCUMENTED, not fixed | nar-analyze peak ~1.9 GB on the 273 MB fixture: stage JSON is captured whole, parsed, re-serialized and retained; the fix is a stage-plumbing restructure that would break the stage-cache format — out of this program's scope |
| R-007 | FIXED — synthetic + live emulator verified | Physical device NOT RUN (owner's device); live destructive recovery and live version-mismatch NOT RUN (reasons recorded) |
| R-008 | FIXED — graph.json + `nar case graph`, synthetic-verified | Unreal package relationships (R-013) are not joined into graph.json (nar-unreal is a standalone deep-dive; the graph consumes nar-analyze stage documents); schema admits binds_jni/references_class kinds no builder emits (no stage data supports them) |
| R-009 | FIXED — investigation.json, deterministic/offline, synthetic-verified | Rule-based synthesis only; no external AI service by design |
| R-010 | FIXED — synthetic + real fixtures | Name-based detection degrades honestly on fully minified builds (explanatory note fires) |
| R-011 | FIXED — synthetic + real fixtures | Hermes bundle↔DEX name join unavailable (names not attributable from the bytecode string table); DEX evidence stands alone |
| R-012 | PARTIALLY FIXED — first-party header-level parse, synthetic + real fixtures | Full serialized-file object/type-tree parsing out of scope (multi-week subsystem); LZ4/LZ4HC/LZHAM inventoried, never decoded (no stdlib decoder) |
| R-013 | FIXED — synthetic exact edge sets; real for classic packages | Zen relationships synthetic-verified only (no Zen-bearing fixture bound in the local corpus) |
| R-014 | FIXED — synthetic; real boundary verified | Binary scenes yield no text references (correct result; note fires); node hierarchy semantics not reconstructed |
| R-015 | DOCUMENTED — owner follow-up | ci.yml cannot be edited through this program's push channel; the exact required change (add pyyaml to the CI install step so the YAML tests run instead of skipping) is recorded in NAR_2.6.0_UPDATE_REPORT.md |
| R-016 | FIXED — coverage measured (figure + methodology in baseline-2.6.0.json) | Line coverage of in-process executions only; e2e-only paths excluded |
| R-017 | FIXED — dashboard graph/investigation sections | Graph section is a tabular summary by design; node browsing stays with `nar case graph` |
| R-018 | FIXED — SECURITY.md created, claims verified in code | — |
| R-019 | DOCUMENTED, left unchanged | pyproject requires-python >=3.10 vs guides' 3.9+: no 3.9 runtime exists here to settle either side on evidence |
| R-020 | PARTIALLY FIXED — optional-layer failure degradation implemented and tested | Pipeline-level adaptive planning / stage retry / cancellation for core stages unimplemented: the orchestrator is a fixed pipeline by design |

Program totals: 20 inventoried issues — 14 fixed,
3 partially fixed with documented remainders,
3 documented with technical reasons (R-006, R-015,
R-019). No issue was closed silently.

### R-020 — optional-layer failure handling (Phases 7 + 8 record)
  investigation builders run through a shared
  optional-layer path under the existing budget
  machinery: a builder exception or validation
  failure records a failed stage entry (case.json +
  execution log), appends a limitation, writes no
  file, and the analysis continues (tested with a
  planted raising builder). **Remaining
  limitation:** pipeline-level adaptive planning,
  stage retry and cancellation policy for the core
  stages remain unimplemented — the orchestrator is
  a fixed pipeline by design; recorded here as the
  documented R-020 remainder.
