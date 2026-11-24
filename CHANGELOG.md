# Changelog

## Unreleased

## 2.6.0 (2026-11-24)

Repository-wide repair and intelligence upgrade driven
by a full audit (issue inventory R-001–R-020). Full
record: NAR_2.6.0_UPDATE_REPORT.md and
NAR_REPAIR_MATRIX.md. Research by Bakr Fayez.

- DEX intelligence: control-flow graph edges from the
  disassembler's block model (`nar-dex --cfg`,
  listings still byte-identical to the dexdump
  oracle); a resolved call graph with per-method
  cross-references (`nar-dex --xref`; on a real
  multi-DEX fixture 431,390 of 736,471 invoke edges
  resolved); a compact-DEX (CDEX) header/section
  parser (payload not decoded, stated in the
  output); a Kotlin metadata d2 cross-check against
  the DEX type table (d1 documented as not
  interpreted, with the reason); confidence-labeled
  obfuscation identifier-shape indicators — never
  verdicts.
- Native intelligence: a library dependency graph
  (bundled + external DT_NEEDED edges, caps with
  truncation flags) and symbol-cluster behavior
  indicators with matched-symbol evidence and an
  explicit not-a-verdict wording. Native
  control-flow analysis remains unsupported
  (documented; Ghidra is the registered escalation).
- Engines and frameworks: Unity gains first-party
  UnityFS bundle and serialized-file header parsing
  (stored/LZMA decompression; LZ4-family blocks
  inventoried, never decoded); Unreal classic and
  Zen packages gain table-derived relationship
  records; Godot gains text scene/resource reference
  extraction; Flutter gains a plugin and
  platform-channel inventory from DEX/manifest/native
  evidence (inference labeled); React Native gains
  bridge/codegen mapping joined between bundle and
  DEX where the format allows.
- Unified graph and investigation: every analysis
  case gains graph.json (typed nodes/edges with
  provenance, evidence references and source-derived
  confidence; one-sided joins preserved, never
  upgraded) with a `nar case graph` query surface,
  and investigation.json — a deterministic, offline,
  rule-based investigation plan separating verified
  facts, ranked paths, labeled hypotheses and
  unknowns. Both layers are optional
  (--no-graph / --no-investigation) and degrade to a
  recorded limitation on failure instead of failing
  the analysis.
- Runtime (R-007): device capability detection,
  emulator-vs-physical identification with evidence,
  structured environment diagnostics with named
  failure reasons and fixes (`nar-runtime diagnose`),
  Frida host/server compatibility checks, and
  bounded connection recovery. Verified live on a
  local emulator with the project's own demo
  fixture; physical-device verification remains the
  owner's device test.
- Security and reliability: case-bundle import
  (nar-analyze import) now extracts only through the
  guarded archive path (a crafted bundle could
  previously plant symlinks / act as an archive
  bomb); archive limits are enforced on actual
  decompressed bytes and a corrupt entry no longer
  aborts the whole extraction; predictable default
  temp paths replaced with mkdtemp and a temp-dir
  leak fixed; whole-file parser reads capped
  (formats, Godot) with named skip notes; a standing
  subprocess-inventory test pins list-form,
  timeout-carrying calls. A v11 pak identification
  gap (footer magic outside the scanned tail) and
  the case-view exit-code inconsistency were found
  by the new measurements and fixed.
- Reporting and measurement: the offline dashboard
  renders the graph and investigation companions
  when present; tests/benchmarks/baseline-2.6.0.json
  re-measures the 2.5.2 reference commands on
  byte-identical inputs (peak memory within ~2% on
  every run; the analyze peak is unchanged — the
  R-006 stage-plumbing diagnosis stands, documented
  in the repair matrix); synthetic-corpus parser
  field completeness is 85/85 asserted fields; line
  coverage of the shipped code was measured for the
  first time (coverage.py over the unit suite;
  figure and methodology in the baseline file).
  SECURITY.md added at the repo root.

## 2.5.2 (2026-11-24)

Reliability, performance and consistency update driven
by a repository audit. Full record:
NAR_2.5.2_UPDATE_REPORT.md. Research by Bakr Fayez.

- Skill YAML is valid YAML now. skill.yaml and the
  SKILL.md frontmatter both failed a real YAML parser
  (unquoted colons in the title/description values) in
  every shipped 2.x release; the values are quoted,
  the metadata text is unchanged, and validation is
  parser-based (tests/unit/test_yaml_validation.py,
  with malformed-YAML regression cases) instead of
  regex-only. nar-doctor gained an optional skill-yaml
  check that reports honestly when no YAML parser is
  available. Correction to the 2.5.0 entry below: its
  Phase 10 line "programmatic frontmatter validation"
  overstated the check — validation was regex-level
  and the frontmatter was in fact invalid YAML until
  this release.
- Unreal capability reporting is generated from the
  parsers' own capability facts (narlib uasset/zen/
  iostore `capabilities()`), so reporting cannot drift
  from the parser again: the UE5 property tag
  extensions (object version 1011 and 1012+) are
  reported as implemented (synthetic-verified), not
  unsupported. A consistency test pins report text to
  the capability source.
- Unreal analysis limits are configurable:
  nar-unreal --max-packages / --max-containers /
  --max-chunks / --max-names and --all-packages /
  --all-containers / --all-details, with the previous
  hardcoded values kept as defaults. Every capped
  collection now reports total / processed / skipped /
  failed counts; nothing truncates silently.
- Memory and speed: nar-unreal, nar-native and
  nar-pak read large files through memory mapping
  (new narlib.mmapio) instead of loading them whole,
  nar-native processes APK libraries one at a time,
  and the ELF relocation summary streams instead of
  materializing every relocation. Measured on
  identical inputs: peak RSS on the local IoStore
  sets fell 84.5% and 77.3%, on the largest local ELF
  84.7%, with wall times roughly halved; parser
  outputs are byte-identical. A full nar-analyze run
  on the 273 MB reference fixture did not improve
  (its peak is the orchestrator's DEX-stage JSON
  round-trip; see the update report).
- Defects fixed: narlib.elf no longer leaks bare
  struct.error or silently tolerates out-of-bounds
  program/section header offsets; nar-analyze now
  records a fatal and exits nonzero on a non-container
  target instead of exiting 0; nar-pak bounds
  decompression at the index-promised size per entry
  instead of inflating fully before checking;
  nar-doctor's nar-scripts check now compiles every
  bundled script (24), not a hand-listed 10.
- Reproducible testing: tests/synthetic_fixtures.py
  + tests/generate_fixtures.py generate the public
  synthetic fixture set (DEX, ELF, pak, IoStore, Zen,
  classic/1011/1012 UAsset variants, Godot pack) with
  a committed expected-output manifest
  (tests/expected_outputs.json, builder intent);
  NAR_TEST_MATRIX.md documents the five test
  categories. A clean clone runs the public suite:
  private-corpus tests SKIP, never fail or fake-pass
  (clean-extraction proof: 295 passed, 8 skipped,
  0 failed).
- Consistency: NAR_CAPABILITY_MATRIX.md (new, 47
  capabilities with status + evidence) and 14
  documentation corrections across
  NAR_ARCHITECTURE.md, NAR_GAP_ANALYSIS.md,
  references and README, reconciling docs with the
  code (module/schema inventories, registry facts,
  doctor checks).
- Security/regression tests: 29 new tests
  (tests/unit/test_security_regression.py) covering
  invalid offsets, hostile archives, absurd-count
  memory guards, invalid container metadata,
  per-entry extraction failures and path traversal.

## 2.5.1 (2026-11-24)

Schema-layer patch, found by an end-to-end validation run
against a real case produced by 2.5.0 (a 28.4 MB Unreal
game case, 26 JSON documents). No tool behavior changes.

- report.schema.json rewritten to the report shape
  nar-analyze actually writes (target / target_sha256 /
  target_size_bytes / environment / triage / identity /
  stage summaries); the 2.0-era schema required an
  `input` object the shipped report no longer carries,
  so every real report.json failed validation.
- engine.schema.json and timeline.schema.json were not
  parseable JSON (unbalanced braces) and could not
  validate anything; both are repaired and aligned to
  the real documents (nar-engines verdicts incl. score
  and recommended_next; the runtime timeline template
  shape).
- New schemas for the case documents that had none:
  dex.schema.json and native.schema.json (root case
  documents and their cache copies), plus
  dex-classes.schema.json and dex-methods.schema.json
  for the nar-dex sidecar inventories. The schema set
  is now 24; every one of the 26 documents of the
  reference case validates or is a non-JSON artifact.
- Regression guards (tests/unit/test_schemas.py): a
  parse-all test loads every file in schemas/, and
  generated-case tests validate a real demo-fixture
  report / engines / dex / native document set and
  the DEX sidecars against their schemas, so a stale
  or unparseable schema fails the battery.
- Documentation: `@Metadata` is written as a code span
  in the markdown guides and records, so it no longer
  renders as a user mention.

## 2.5.0 (2026-11-24)

- Release preparation (evolution Phase 12): version
  bumped to 2.5.0 in all 18 version-bearing locations
  (consistency-tested); the Unreleased evolution
  entries consolidated into this section; a release
  guide (references/release-guide.md) now documents
  the 2.x release practice end to end — battery, the
  18-location bump, changelog discipline, pre-push
  greps, the push manifest excluding
  .github/workflows, the sync record, the ZIP, and
  the web-UI release step. This section is the
  complete record of the TOTAL INTELLIGENCE EVOLUTION
  program (Phases 0–12) over the 2.4.0 baseline.
  Publication remains the owner's explicit decision.
- Testing + benchmarks (evolution Phase 11): the
  benchmark runner now computes accuracy metrics from
  the labeled local corpora and measures peak memory,
  with methodology in the new benchmarks guide
  (references/benchmarks.md). Measured on the local
  corpora (role labels only): protection attribution
  precision 1.0 / recall 1.0 with zero false positives
  on the 9-app clean set (real corpus); engine-detection
  recall 1.0 on 6 labeled real fixtures and accuracy
  1.0 on the 8-fixture synthetic framework corpus
  (reported separately); format-identification accuracy
  1.0 on 10 labeled fixtures; real-corpus engine
  precision is NOT RUN (no labeled engine-negative real
  corpus exists). Peak memory, measured: a full
  nar-analyze run on the largest local fixture
  (273,366,540 bytes) peaked at 1,887,338,496 bytes RSS
  for the nar-analyze process (stage subprocess peaks
  excluded), 304.69 s wall. A new parser mutation corpus
  (truncated / corrupted DEX, ELF, PAK, IoStore TOC and
  Zen inputs) proves each parser fails with its named
  error type; the corpus caught two real defects, fixed
  in this phase: narlib.dex let an inflated header table
  leak a bare struct.error from the string-table reader
  (header table extents are now validated at
  construction), and narlib.elf silently treated an
  invalid EI_CLASS as 32-bit (now an ElfError).
- Skill + integrations (evolution Phase 10): SKILL.md
  routing now covers the Phase 1–9 surface (companions
  incl. correlations.json, network redaction, the
  versioned protection-signature database, the
  `nar tools` / `identify` / `validate` / `benchmark` /
  `case` verbs, orchestration budgets, case
  export/import/verify, runtime session records, audio
  metadata, compare artifacts, Addressables catalogs,
  RN source maps, Flutter asset inventories, Godot
  resource types, DEX try/catch + Kotlin `@Metadata`, ELF
  relocations). The deferred full guide-vs-code audit
  ran over all 22 guides + SKILL.md: zero missing link
  targets, zero missing script files, zero
  misattributed nar flags, zero unknown nar verbs; the
  51 flags no nar script defines are all external-tool
  flags in named-tool contexts. One stale capability
  claim fixed (the DEX guide's scope limit now reflects
  try/catch tables, debug-info presence and the block
  summary); the dynamic-analysis guide documents
  session records and the tool-registry guide documents
  `nar tools`. The audit's durable checks are encoded
  as unit tests, including programmatic SKILL.md
  frontmatter + plugin.json validation. The capability
  registry needed no entry changes in Phases 9–10
  (verified by its consistency tests).
- Reporting + CLI (evolution Phase 9): the offline
  dashboard renders the native dependency graph from
  native.json as an inline SVG section (deterministic
  layered layout, escaped labels, zero external
  references; oversized graphs truncate with a note).
  The unified CLI gains five verbs over existing
  capability, with all existing verbs untouched:
  `nar tools` (tool-registry view with live probes,
  via the new nar-tools.py), `nar identify` and
  `nar validate` (nar-input aliases), `nar benchmark`
  (the fixture-corpus benchmark runner), and `nar case`
  (export / import / verify routing to nar-analyze's
  case operations).
- Evidence + orchestration (evolution Phase 8):
  verification_status is now carried by fingerprint
  properties (mapped from fact class) and by the new
  correlations.json case companion — explicit
  cross-module joins (DEX native declarations ↔ ELF
  JNI exports, manifest components ↔ DEX entry
  points, endpoints ↔ referencing classes, network
  libraries ↔ DEX presence) with same-evidence
  deduplication; JNI entries are also embedded in
  native.json. nar-analyze gains orchestration budgets
  (--stage-timeout / --total-budget, recorded as
  budget-exceeded stops in the execution log) and case
  export / import / verify: a case directory travels
  as one archive with a per-file hash manifest, and
  verify re-checks the input hash, the manifest, and
  the stage-cache integrity keys.
- Assets + comparison (evolution Phase 7): nar-assets
  reads audio metadata from WAV / OGG (Vorbis, Opus) /
  MP3 headers — channels, sample rate, and duration
  where the header makes it computable (MP3 estimates
  are labeled as estimates); other formats report
  unmeasured instead of guessing. nar-compare --out DIR
  now writes comparison.json, feature-map.json (a
  schema-validated per-dimension projection) and
  version-diff.md, with signing-file churn separated
  from content changes under a labeled build-noise
  heuristic. The phase also fixed the extended endpoint
  diff, which had silently reported 0/0 on every pair.
- Runtime + security intelligence (evolution Phase 6):
  nar-runtime plan/status can persist structured session
  records (runtime-session.json: device identity, tool
  probes, start/stop, events, errors) into a case
  workspace via --session-out. The jni-trace
  RegisterNatives event path is verified live on the
  API 26 emulator (attach + spawn) against a
  dynamic-registration fixture — the live run also caught
  and fixed a Frida 17 API removal in the script's
  per-method read. Security findings now carry a
  verification_status (CONFIRMED / STRONGLY_INDICATED /
  POTENTIAL / UNVERIFIED / CONTRADICTED); findings
  written before the field existed still validate.
- Protection + network intelligence (evolution Phase 5):
  the protection signatures moved from code into a
  versioned database (scripts/protection-signatures.json,
  database v1.0.0) with a validating loader and doctor
  visibility — detection behavior is unchanged (pinned
  by a canonical digest and byte-identical triage output
  on the protection fixtures). nar-network now redacts
  credential values in endpoint URLs before any output
  (counts reported, raw values never written), and case
  runs emit two new schema-validated companions:
  network-analysis.json and api-architecture.json.
- Engine intelligence depth (evolution Phase 4): Unity
  Addressables catalogs parse into a full inventory
  (locations, providers, resource types, decoded entry
  table — verified on a real catalog with thousands of
  locations); React Native reports shipped source maps
  and a native-module inventory (TurboModule / Fabric /
  NativeModules names for text bundles, architecture
  markers for Hermes bytecode); Flutter inventories
  flutter_assets with typed entries instead of a
  presence flag; Godot pack listings classify every
  entry's resource type with labeled evidence (content
  header over extension; encrypted entries never typed);
  Unreal classic-package parsing adds the UE5
  tag-extension property layouts (object versions 1011
  and 1012+), verified on synthetic packages and labeled
  synthetic, as no real sample records those versions.
- Android intelligence depth (evolution Phase 3): DEX
  analysis now parses try/catch handler tables and
  debug-info presence (cross-checked exactly against the
  SDK's dexdump), the disassembler adds a control-flow
  block summary without changing its verified listings,
  ELF analysis parses relocation tables (cross-checked
  against readelf) and reports compiler fingerprints from
  the .comment section as observed evidence, and Kotlin
  `@Metadata` payloads are parsed — metadata version and
  declaration kind per class — on real-world Kotlin apps.
- Case companions completed (evolution Phase 2): the
  orchestrated case now also emits application.json,
  manifest.json, native-inventory.json and frameworks.json,
  projected from the same run's stage data and validated
  against new shipped schemas (a degraded source stage is
  reported explicitly, never as an empty success).
  Fingerprints report the compile SDK when the badging
  reader exposes it, and input validation adds structural
  summaries for AAR and JAR archives (entry and class
  counts, manifest presence, library layout facts).
- Documentation truth guards (evolution Phase 1): the
  README repository-structure block now matches the real
  tree (22 reference guides, all current modules and the
  shared library, unit + benchmark test suites), and new
  automated checks keep it that way — a unit test asserts
  every script, library module, guide and schema is named
  in the block, that skill routing targets exist, and
  that all version-bearing files agree (a planted
  mismatch is caught). The toolchain check no longer
  leaves bytecode caches in the tree, and the brand
  headline no longer embeds a version number.

## 2.4.0 (2026-11-24)

- Unreal Zen packages: Zen (IoStore-native) package
  chunks are now parsed, not just identified — the Zen
  header (current, pre-5.3 and Early Access legacy
  layouts, accepted only when every section validates),
  versioning info when the writer recorded it, the
  per-package name map, the bulk data map, imported
  public export hashes, the import/export maps and the
  export bundle entries, with names and references
  resolved through the package's own name map. Sections
  no public reader decodes (dependency bundles,
  imported package names) are located and measured,
  and export property streams follow the same honesty
  rules as classic packages. Verified on byte-exact
  synthetic fixtures with regression tests and on
  the real Zen set inventoried earlier: all 684
  stored chunks parse in full (the sweep found one
  forward-export-reference defect, since fixed; an
  independent byte-walk oracle agrees 45/45 on one
  real package — see NAR_TEST_MATRIX.md).
- Runtime completion (emulator scope): the two Frida
  scripts that had never executed live (jni-trace,
  java-api-trace) have now run against a live process —
  hooks installed in attach mode and, for jni-trace, in
  a Frida-spawned process via the resume-first recipe.
  Event accounting stays honest: one REPL-triggered
  call/return pair for java-api-trace; no RegisterNatives
  events, because the demo fixture binds its native
  method statically (the event path remains labeled
  unverified).
- Compiled-artifact support: narlib now parses OAT
  (header + key-value store), VDEX (fields + byte-exact
  DEX carving), Dalvik ODEX, and ART image headers, and
  nar-dex accepts .vdex/.odex/.oat/.cdex as first-class
  targets. Verified on real API 26 artifacts pulled
  from a device (OAT 124, VDEX 006, ART 043), including
  full parsing of the DEX carried by a real VDEX.
  Dalvik ODEX and CDEX remain synthetic-fixture level;
  compact-DEX payloads are identified, not decoded.
- Mega sweep fixes (full pipeline over 75 local
  targets): native-stage crash on ZIP payloads named
  as libraries; IL2CPP split-pair reporting and a
  silent split-base skip in the case workflow; legacy
  versioned Cordova/PhoneGap runtimes now detected;
  Ren'Py / RPG Maker unique payloads now reach the
  detection threshold; bundletool .apks sets are
  classified as containers and routed to the canonical
  base split instead of producing hollow reports.
- Godot: encrypted-pack detection verified on a real
  engine-written encrypted pack (reported as encrypted,
  listing honestly unavailable, no decryption added);
  format 3 (Godot 4.5+) directory-at-end parsing fixed
  (previously reported "Files: 0"); format 4 headers
  report facts with the listing marked unsupported;
  individually encrypted entries are marked in listings.
- Unreal IoStore: the directory index parser now also
  reads the pooled name-index layout written by current
  (UE 5.3-era) packagers — fixed-size rows over a shared
  string pool — after a real UE5 game's full container
  set showed its index being silently dropped; a layout
  is accepted only on exact buffer consumption plus a
  complete tree walk. IoStore container reports now
  identify Zen-format package chunks (the IoStore-
  native package format, magic as trailer) as such
  instead of misreporting them as corrupt classic
  packages. The same real set verified TOC parsing,
  directory naming, and stored-chunk extraction end to
  end at full-game scale; Oodle chunks remain refused
  by name.
- Unreal IoStore (TOC v8): containers of the newest
  TOC generation ship the pooled directory-index
  layout unchanged, but their trees are wider — the
  directory-index flattening walk counted sibling
  hops against its depth bound and dropped a real
  v8 container's index (674 directories, 13,494
  files) as unreadable. Sibling chains are now
  walked iteratively and the bound applies to true
  nesting depth only; the v8 index flattens
  completely, verified path-for-path against an
  independent byte-walk oracle, and the UE 5.3 set's
  flattened map is unchanged.
- Unreal Zen packages (newer writers): a second real
  Zen corpus — an indie UE5 horror title of the
  newest engine generation (TOC v8 containers,
  unsealed) — showed a writer variant the parser had
  never seen: a count-prefixed byte array serialized
  between the name batch and the bulk data map,
  which made all 525 of the title's stored packages
  fail to parse. The variant is now accepted under
  the same rule as every other layout (the classic
  map behind the array must land exactly on the
  imported-public-export-hashes section), the array
  itself is reported located-and-measured rather
  than decoded, and the corpus parses 525/525 with
  regression tests; an independent byte-walk oracle
  agrees with the parser on 20/20 field checks on
  one real package. The same title's classic pak
  (index unencrypted, SHA-verified) holds no
  packages at all, and none of its packages records
  versioning info — the hunt for a real
  classic-format UE5 package with a recorded
  FileVersionUE5 remains open (see
  NAR_TEST_MATRIX.md).

## 2.3.0 (2026-11-23)

- Real-UE5 verification rung executed on an unsealed
  title: nar-pak now parses the v10/v11 encoded pak
  index (path-hash + full directory index) with SHA-1
  verification of both index regions, and extracts
  stored/zlib/gzip entries from it (entries using a
  method with no stdlib decoder are refused by name).
  narlib.uasset now reads unversioned packages whose
  legacy summary version is -8 — the variant that
  carries the UE5 version field — under the UE5 layout
  assumption instead of the UE4-only one; all 220
  stored packages of the test title parsed, cross-
  checked by an independent byte-walk oracle and an
  independent pak header-chaining walk. Full record in
  NAR_TEST_MATRIX.md.

## 2.2.0 (2026-11-23)

Verification-and-depth release: the runtime layer was
verified live on an emulator (attach mode, then spawn
mode), Unreal support gained UAsset-level package
inspection verified on real cooked UE4 packages, nar-dex
gained an own DEX bytecode disassembler cross-checked
against the Android SDK disassembler with full agreement,
and nar-pak now diagnoses AES-sealed pak indexes
explicitly. The full evidence is recorded in
NAR_TEST_MATRIX.md (post-2.1.0 and unreleased addenda).

- Runtime layer verified live: against an Android emulator
  (API 26 / Android 8.0.0, google_apis x86_64, QEMU TCG
  on a KVM-less host), the adb adapter, package install
  and launch, nar-runtime's verified-live status, and
  Frida attach-mode observation (bundled network-observe
  and file-io-observe scripts, frida-server 17.27.4)
  all ran against a real target. This supersedes the
  2.1.0 entry's runtime note for emulator scope. At this
  stage Frida spawn mode still failed repeatedly under
  TCG (closed by the follow-up directly below), and a
  physical device remains IMPLEMENTED_BUT_UNVERIFIED.
  Full record in NAR_TEST_MATRIX.md (post-2.1.0 runtime
  addendum) and references/troubleshooting.md.
- Frida spawn mode verified live: the spawn failures above were
  root-caused (ActivityManager's ~10 s process-start
  timeout kills the Frida-gated child under TCG) and a
  resume-first recipe — spawn via the Frida API, resume
  immediately, settle, then load via the CLI against the
  spawned pid — ran both bundled observation scripts
  live in Frida-spawned processes on the same emulator.
  Spawn mode is now IMPLEMENTED_AND_TESTED for emulator
  scope with that recipe; the one-command gated form
  remains unusable under TCG, and a physical device
  remains IMPLEMENTED_BUT_UNVERIFIED. Full record in
  NAR_TEST_MATRIX.md (spawn-mode addendum) and
  references/frida-scripts.md.
- DEX bytecode disassembler (new narlib/dexdis): nar-dex
  gains a targeted disassembly mode (`--disassemble` with
  `--disasm-class` / `--disasm-method` selection, or
  `--disasm-all` for an explicit full decode). Method code
  items are decoded instruction by instruction with operands
  resolved through the DEX's own tables (strings, types,
  fields, methods, prototypes, call sites, method handles),
  covering every documented format family and the switch /
  fill-array payloads, with DEX 038+ forms gated on the file
  header version. A method that cannot be decoded fails its
  own listing with the precise reason and code-unit offset —
  never a guessed instruction. Cross-checked against the
  Android SDK disassembler on the demo fixture and real-world
  DEX files from the local test corpus (773,166 instructions
  compared, full agreement) and against an independent smali
  disassembler for the gated DEX 038/039 forms.
- UAsset-level inspection (new narlib/uasset): Unreal
  packages (.uasset / .umap) are parsed in full at the
  header and table level — FPackageFileSummary with UE4
  (object versions 434–522) and UE5 (1000+) version
  gating, name / import / export / depends tables with
  package indices and FNames resolved to readable
  references, soft package references, the UE5 soft
  object path list, and searchable names. Cooked layout
  is honoured: export serial ranges are located in the
  package or its sibling .uexp, and bulk data is reported
  against the .ubulk. A best-effort FPropertyTag reader
  decodes primitive values and recurses into struct
  values under an explicit per-export confidence note;
  unversioned-property packages and the UE5 tag-extension
  layouts are reported as unparsed, with the reason.
  nar-unreal parses packages loose in an APK, inside
  IoStore containers, and inside .pak files under --work
  extraction, and accepts a bare package as a target;
  nar-analyze lifts the summaries into its engine
  companions. Verified on synthetic byte-exact fixtures
  (UE4-era, UE5-era, and unversioned layouts) in the unit
  suite and the end-to-end harness, and on real cooked
  packages from a locally held UE4-era corpus checked
  against independent manual spec accounting; that
  real-asset rung also caught and fixed the property-tag
  reader skipping the documented array-inner-type and
  property-GUID tag-header fields (UE4 object versions
  500 / 503).
- Real-asset verification, UE5: a lawfully obtained
  free UE5 title's containers were inspected — all of
  its pak archives (format version 11) seal their
  indexes with AES encryption and register Oodle as
  the sole compression method, so no package could be
  extracted under the skill's no-key-extraction
  boundary and the UAsset parser remains unverified
  on real UE5 packages. nar-pak now surfaces the
  footer index-encryption flag for v7+ paks (passed
  through by nar-unreal), so a sealed modern pak
  reports both of its blockers plainly.

## 2.1.0 (2026-11-23)

Gap-closure release. Every item below was verified by
execution in the reference environment; the full evidence
is recorded in NAR_TEST_MATRIX.md (2.1.0 addendum).

- CI truth: the nar-ci workflow has executed on GitHub
  Actions (3 runs, all successful). Documentation that
  called it "authored, not executed" was corrected.
- IoStore entry-level parsing (new narlib/iostore):
  .utoc containers are parsed end to end — header, chunk
  IDs / offsets / lengths, compression blocks and method
  names, directory index (chunk -> file path), per-chunk
  meta — across the current and legacy layout eras, with
  a layout accepted only when its section walk consumes
  the file exactly. nar-unreal inventories containers for
  APK and bare .utoc targets; nar-analyze embeds counts
  as engines.unreal_iostore. Chunk extraction supports
  the None and Zlib methods; other methods (e.g. Oodle)
  are named, not decoded, and encrypted containers are
  inventoried, never decrypted.
- Cpp2IL is now an optional second IL2CPP backend in
  nar-il2cpp (--backend cpp2il or $NAR_IL2CPP_BACKEND);
  Il2CppDumper remains the default. Its registry entry
  flips from unavailable to a probed CLI entry, the
  doctor probes it, and its dummy-DLL output is
  summarized by a new ECMA-335-lite reader
  (narlib/dotnetmeta: TypeDef / MethodDef counts and
  namespaces). Extracted-pair targets refuse with the
  precise reason (Cpp2IL's force-path options require a
  Unity version a bare pair does not carry).
- nar-dex performance on very large targets (~1.9x on a
  273 MB multi-DEX fixture): --json emission uses the
  compact C encoder (an indent argument forces CPython's
  pure-Python encoder; the parsed document is
  field-identical), and the code scan unpacks the
  instruction stream in one pass.
- Fixed: narlib field enumeration started its class_data
  walk two ULEB128s early (it never skipped the header's
  two method counts), shifting every field list onto
  wrong field ids. The corrected walk is verified
  against the Android SDK's dexdump (9,949 classes,
  0 mismatches).
- Runtime verification was attempted on an emulator and
  remains IMPLEMENTED_BUT_UNVERIFIED: with no /dev/kvm
  on the reference host, the API-34 image never reached
  boot completion under QEMU TCG within the time box.
  The precise blocker is recorded in the test matrix and
  the troubleshooting guide.

## 2.0.0 (2026-11-23)

NAR 2.0 — NIROUS ANDROID INTELLIGENCE. Everything from 1.x is
preserved (same script CLIs, same report sections); 2.0 adds a
platform layer underneath and around it.

Post-release fix: the Kuna credit link pointed to a repository
that does not exist; corrected to Kuna's real home
(Noelo-Lab/kuna) in the README credits, the setup guide, the
doctor hint, and the tool registry.

- Input layer (nar-input, narlib): magic + structure
  identification for APK/APKS/XAPK/AAB/AAR/JAR/DEX/ODEX/VDEX/
  OBB/ELF and engine containers, duplicate detection by hash,
  and guarded extraction — traversal, absolute-path, symlink,
  and archive-bomb entries are rejected per entry and
  reported.
- narlib: shared library with a full DEX parser (tables,
  class data, bounded code scan), a full ELF parser (headers,
  dynamic entries incl. a PT_DYNAMIC fallback for
  section-less binaries, symbol tables), the evidence
  envelope + §9.5 finding builder, a structural JSON-Schema
  validator, and the capability-registry client.
- Capability registry (scripts/registry.json): every
  orchestrated tool declared with kind, requirements,
  discovery order, and limitations; unavailable tools are
  registered as unavailable, never faked.
- nar-fingerprint: normalized identity where every property
  carries provenance, confidence, and fact class.
- nar-engines: multi-indicator engine fusion with scores
  and stated ambiguities across 18 families; --deep confirms
  verdicts through the matching deep-dive tool. New deep
  dives: nar-unity (backend, editor-version evidence,
  bundle inventory, optional UnityPy object census) and
  nar-unreal (generation evidence, pak inventory/encryption,
  IoStore inventory with its parsing limit stated).
- nar-dex: class/method/field enumeration, call edges,
  string-reference mapping, reflection and dynamic-loading
  evidence, entry points, Kotlin inventory, and
  version-checked jadx/baksmali adapters.
- nar-native: ELF facts per library, JNI export map,
  bundled-library dependency graph, readelf cross-check.
- nar-network: classified static endpoint inventory
  (confirmed/potential/third-party/unused-candidate/
  sensitive/unverified), backend-service detection, and
  network-security-config parsing. Nothing is contacted.
- nar-security: structured findings (NAR-SEC-NNN) with
  severity, confidence, evidence, impact, remediation, and
  false-positive considerations, plus positive observations.
- nar-assets: asset inventory with magic-first typing,
  categories, image dimensions, and duplicate grouping.
- nar-runtime: adb/Frida adapters, session plans, and the
  timeline schema. Device-dependent parts are labeled
  IMPLEMENTED_BUT_UNVERIFIED (no device in the build
  environment).
- nar-analyze is now the orchestrator: case workspace
  (case.json), execution log, stage caching/resume keyed by
  input hash, standardized companions (fingerprint, engines,
  endpoints, security-findings, assets, dex, native), and an
  offline single-file HTML dashboard via nar-report
  (dark/light, filterable, zero external references).
- nar-compare: extended comparison — class and endpoint
  diffs, asset diffs, per-change severity with reasons, and
  an entry-level similarity score. 1.x output unchanged.
- nar.py: unified CLI over every module; each module script
  keeps working standalone.
- Schemas for all standardized outputs in schemas/;
  pytest unit suite in tests/unit/ (synthetic DEX/ELF/format
  builders, no binary fixtures); benchmark runner in
  tests/benchmarks/; pyproject.toml; CI workflow for
  GitHub Actions (executed there since the 2.0.0 release —
  runs #1–#3 all passed; see the 2.1.0 addendum in
  NAR_TEST_MATRIX.md).
- Fix carried from the audit: nar-analyze Markdown no longer
  renders structured string hits as raw JSON blobs.
- The five 1.1.1 wide-sweep fixes are included (they landed
  during the 2.0 Phase 2 commit).

## 1.1.1 (2026-11-23)

Fixes from a wide real-world sweep: sixteen additional free apps
and games across engines, frameworks, and eras, each run through
the full nar-analyze workup, with every misdetection fixed and
re-proven on the target that exposed it.

- nar-rn: `*.bundle` assets are content-validated before any
  React Native claim. Unity Addressables bundles (UnityFS magic)
  are rejected and named as Unity asset bundles instead of being
  reported as a JSC bundle, and a bundle at the contract path
  that is neither Hermes bytecode nor JavaScript text reports an
  unknown binary format instead of a guessed engine.
  nar-analyze's React Native routing flag and report rendering
  follow the same rule.
- nar-triage: Adobe AIR is attributed only on its descriptor
  (`META-INF/AIR/application.xml`). The bare `.swf` substring
  pattern misattributed apps that bundle Flash files as
  web-content fallbacks; it is removed.
- nar-triage: Widevine DRM is also identified in compiled form —
  the scheme UUID as raw bytes, or as the pair of 64-bit long
  constants a `new UUID(msb, lsb)` compiles to in the same DEX —
  not only as a dashed string constant.
- nar-godot: loose exports (no `.pck`) are counted properly.
  The counter anchors on `project.binary` / `project.godot` and
  covers the exported assets tree (dexopt profiles excluded)
  instead of reporting 0 project files for real loose-layout
  games; `.import/` subtrees also count without an anchor.
- nar-analyze: the Markdown report prints the form factors
  triage already collects (for example Android TV), and renders
  absent `android:debuggable` / `android:allowBackup` with the
  platform defaults nar-perms reports instead of "unknown".
  String hits in the report render as clean one-line values
  instead of raw JSON blobs.
- Test harness: four new end-to-end cases (loose Godot layout,
  compiled-UUID Widevine, `.swf` content without AIR, Unity
  Addressables rejection) over local fixtures; 38 cases total.

## 1.1.0 (2026-11-23)

The automation update: one-command analysis, engine deep-dive
scripts, pak extraction, wider framework coverage, and a permanent
end-to-end test harness.

- New `nar-analyze.py`: runs the full static workup on an
  APK/AAB/XAPK/OBB (triage, permission audit, strings scan,
  protections, and the engine deep dives the target routes to) and
  writes one evidence report (`report.md` + `report.json`) with an
  explicit limitations section.
- New engine scripts, all stdlib-only: `nar-il2cpp.py` (locates
  the metadata/library pair in a Unity IL2CPP build, reads the
  metadata format version, runs Il2CppDumper when available, and
  summarizes types, methods, and top namespaces),
  `nar-flutter.py` (Dart/Flutter versions and AOT snapshot markers
  from the engine and app libraries, with a clean negative on
  non-Flutter builds), `nar-godot.py` (Godot pack header, format,
  engine version, encryption flag, and file listing for a bare
  `.pck` or an APK), and `nar-rn.py` (extracts the React Native
  bundle, decides Hermes vs JSC from the magic, and reports the
  Hermes bytecode version with function/string/identifier counts,
  cross-checked against hermes-dec when installed).
- `nar-pak.py` gained `--extract`: entries can be pulled out of an
  unencrypted pak (Zlib entries decompressed, stored entries copied
  byte for byte); encrypted entries refuse plainly.
- Triage coverage audit additions: framework/engine markers for
  Xamarin / .NET (incl. MAUI), Cordova, Capacitor, Qt for Android,
  Defold, Ren'Py, RPG Maker web exports, EasyRPG Player, Kivy /
  embedded CPython, and generic web-asset bundles; form-factor
  surfacing from badging (Wear OS, Android TV); and a 16 KB
  page-alignment verdict in the native-hardening finding (every
  `PT_LOAD` segment's `p_align`, weakest segment reported).
- Guides: an "Unpacking: the full chain" section in the triage
  guide (delivery containers → APK → expansion files → asset
  containers → packed DEX, with staged-DEX recovery labeled as
  runtime work); instant apps in the app-bundles guide; APEX
  format notes with the system apps; Android 16 (API 36) notes in
  the modern guide; and the signatures guide now carries the full
  own-build signing workflow (what each scheme protects, the
  align → sign → verify order, keystore/certificate analysis, v3
  rotation lineage, source stamp, and signature continuity across
  versions) with the analysis-only boundary stated inside it.
- `tests/run_e2e.sh`: a permanent end-to-end harness that runs
  every bundled script against a local fixture corpus (bound
  through `$NAR_FIXTURES` and an uncommitted manifest, so no
  fixture names live in the repo) and prints a pass/fail matrix.
  Current matrix: 34 passed, 0 failed.
- `nar-doctor.sh`'s bundled-script self-check now covers all ten
  Python scripts.

## 1.0.4 (2026-11-23)

Protection-systems detection in triage, covering the full Android
protection taxonomy. Detection and reporting only.

- `nar-triage.py`: new "Protection systems" section (plain and
  JSON), organized by category. Findings are attributed to a named
  product only when a dedicated marker attributes them; anything
  else is reported at category level or as unattributed.
- Commercial packers / VM protectors, named: Pairip (Google),
  Tencent Legu, Qihoo 360 Jiagu, Bangcle SecShell, Alibaba
  SecurityGuard, Baidu Protect, NetEase YiDun, iJiami,
  DexProtector, LIAPP, AppSealing — via dedicated runtime
  libraries, stub application classes, wrapper packages, and
  payload files. A StubApp-shaped class with no vendor marker is
  reported as an unattributed packer stub, never guessed.
- Obfuscation: DEX string-table statistics (share of class
  descriptors with <= 2-char simple names) and R8 annotation
  stripping residue (Kotlin referenced, `kotlin/Metadata` absent).
- Anti-tamper / RASP: RootBeer, su / Magisk / Superuser markers,
  emulator and debugger markers, Frida / Xposed / Substrate
  markers, SafetyNet (legacy), and Play Integrity API — the last
  two labeled client-side presence only, since their verdicts are
  server-side.
- Network protection: SSL pinning from compiled-in `sha256/...`
  pin constants and from pin-sets in a network security config.
  The OkHttp `CertificatePinner` class alone is not treated as
  evidence: it ships with the library whether or not pins are
  configured.
- Licensing / DRM: Play License Verification classes, the
  `CHECK_LICENSE` permission (folded into the LVL finding when
  both are present), and Widevine via its MediaDrm scheme UUID.
- Code / asset encryption: DEX entries without a valid header,
  the shell / stub DEX shape (tiny DEX, bulk native or asset
  payload), IL2CPP metadata with an unreadable header, the Godot
  PCK encryption flag (now also surfaced in `engine_versions`),
  and the Unreal pak index-encryption flag read from the footer.
- Native hardening: per-library posture from ELF headers —
  `ET_DYN`, `PT_GNU_RELRO`, `BIND_NOW`, and symbol-table absence
  (stripped) — aggregated in the report, with per-library detail
  in JSON.
- Guides: the triage guide gains a Protection systems section
  with the taxonomy, the attribution discipline, and the honest
  list of protection kinds that have no reliable static marker
  (DexGuard-style string encryption, in-code signature checks,
  OLLVM-style native obfuscation, injected commercial RASP
  runtimes, encrypted string pools). `SKILL.md` gains a routing
  row for "Is this app protected? Which packer / protector?".

## 1.0.3 (2026-11-23)

Small fixes from a real-use simulation pass.

- `nar-pak.py`: per-entry encryption flags are now read from the
  pak index trailer instead of being skipped, and reported in
  plain output ("Encryption: none", or AES with the flagged count)
  and as a count in JSON. Plain output also adds grouped stats:
  entries by file extension and by top-level folder (top 10 by
  count), each with packed and uncompressed totals.
- `nar-perms.py`: an absent `android:debuggable` now prints the
  platform default, "false (platform default; attribute absent)",
  instead of "?". An absent `android:allowBackup` likewise states
  the default for the app's target SDK, labeled as a default.
  Split stub manifests still print "?": their values live in the
  base APK and are not invented here.
- `nar-doctor.sh`: the jadx check runs `jadx --version` for real.
  A jadx that exists but will not start (its launcher needs a JDK)
  is reported as a warning with the fix (set JAVA_HOME to a
  JDK 17+) instead of OK, and counts against the core verdict.
- `references/manifest-and-resources.md`: note that some system
  apktool builds garble fragments of decoded manifest XML, and
  that `nar-perms.py`'s own parser plus `aapt2 dump xmltree` are
  the cross-check; when the three disagree, trust the two that
  agree.

## 1.0.2 (2026-11-23)

Fixes and one new tool, all found by running the skill end to end on
real-world apps and games of every shape (native-heavy, legacy,
split sets, containers, engine games, modern Compose apps).

- `nar-triage.py`: Kotlin is now detected from DEX type evidence
  (`Lkotlin/`, `kotlinx/coroutines`) instead of only the
  `kotlin/Metadata` string, which R8 strips from release builds.
  Framework markers for AndroidX (`androidx/`) and the legacy
  support library (`android/support/`) added.
- `nar-triage.py`: `.xapk` / `.apkm` containers are understood:
  identity comes from the container `manifest.json`, contained APKs
  and OBBs are listed, and the misleading "pure DEX app" line is
  never printed for a container. The same line is also suppressed
  for a split base whose native libs live in config splits, whether
  the tell is engine evidence or bundle artifacts
  (`stamp-cert-sha256`, `res/xml/splits*.xml`).
- `nar-triage.py`: platform-implied permissions from badging are
  labeled separately instead of being counted as declared.
  Duplicate `<uses-sdk>` elements are detected (via xmltree) and
  the first occurrence wins, in agreement with `nar-perms.py` and
  `nar-compare.py`. apksigner warnings are no longer dropped, and
  the source-stamp flag is shown in plain output. A v2/v3-only APK
  now explains why it has no META-INF signing files.
- `nar-triage.py`: library versions from `META-INF/*.version`
  files are surfaced (`library_versions`), and the Unreal engine
  version is extracted from the build string inside the engine
  library (`++UE4+Release-X.Y`) into `engine_versions`.
- `nar-strings.py`: the key-pattern matcher no longer floods on
  binary-heavy apps. Hex runs are bounded and must mix digits with
  a-f letters, assigned values must look like values, identifier
  floods (mangled symbols, dotted theme/class names, hex constant
  table chunks) are rejected, the email pattern requires a real
  domain, and IP matches inside longer dotted-numeric sequences are
  dropped. On the test corpus, key-pattern hits fell from 191,895
  to 55 on an Unreal game and from 18,331 to 1,106 on a
  native-heavy app, while planted test tokens are still caught.
- `nar-perms.py`: duplicate `<uses-sdk>` handled first-wins with a
  warning; split manifests are recognized (split name reported,
  stub app-level flags suppressed, no raw `None` values printed).
  Permission table extended: Play billing and license, ads ID and
  ad-services permissions, push receive, foreground-service media
  projection/health/file-management, screen capture/recording
  detection, and Health Connect (`health.*`) permissions.
- New: `nar-pak.py`, a stdlib-only Unreal `.pak` lister (pak
  format versions 1-7). Parses the footer and index, lists entries
  with sizes and compression, and accepts a layout only when it
  consumes the index exactly. Versions 8+ and encrypted indexes are
  reported as unsupported, plainly, never guessed.
- `nar-doctor.sh`: also verifies the bundled NAR scripts exist and
  compile.
- Guides: the Unreal section of the native-libs guide documents
  the `nar-pak.py` workflow and build-string version extraction;
  the Unity IL2CPP guide notes that Il2CppDumper may ignore its
  output-directory argument and write next to its own DLL; the
  triage guide explains containers, implied permissions, duplicate
  `<uses-sdk>`, library versions, and the split-base native note.

## 1.0.1 (2026-11-23)

- `nar-strings.py`: the key-pattern matcher now catches lowercase hex
  tokens (32+ hex characters, e.g. MD5-style API keys) and
  keyword-prefixed tokens (`token_<hex>`, `api_key_<...>`). Found by
  the demo run: the previous matcher required mixed case and missed
  a planted lowercase hex token.
- `nar-triage.py`: `.aab` bundles now report package, version, and SDK
  levels from `bundletool dump manifest`. Previously triage reported
  those fields as unreadable for bundles.

## 1.0.0 (2026-11-23)

First release. NAR (Nirous Android Reversing) is an AI-agent skill for
Android APK reverse engineering, CLI-first, no MCP server required. It
covers all Android apps and games, old and new.

### Skill core

- `SKILL.md`: routing table, method, report format, and legitimate-use
  boundary (analysis only: no signature-kill, no VIP/paid unlocks, no
  unlimited currency, no DRM bypass).
- `skill.yaml` and `.claude-plugin/plugin.json`: skill metadata and
  Claude Code plugin manifest.

### Reference guides (17)

- Setup and doctor, triage and inventory, manifest and resources, DEX
  and smali with jadx decompile, native libraries and JNI, signatures
  and integrity, version compare and feature maps, dynamic analysis,
  evidence workflows.
- Unity IL2CPP deep analysis: Il2CppDumper workflow, metadata dump
  reading, Ghidra method mapping.
- Flutter/Dart analysis: `libapp.so`, AOT snapshots, strings and
  symbol recovery.
- React Native analysis: Hermes bytecode bundle parsing,
  disassembly, and decompilation with hermes-dec.
- Godot deep analysis: `.pck` pack extraction with GodotPckTool,
  GDScript decompile and full project recovery with GDRE Tools.
- App bundles and split APKs: AAB structure, bundletool build-apks,
  XAPK/APKM containers, Play Asset Delivery.
- Network traffic analysis: mitmproxy capture, tshark pcap reading.
- Frida script library: running the bundled observation scripts.
- Legacy analysis: ODEX/OAT, old DEX versions, v1/v2 signing, ARMv7,
  Eclipse-era builds, old Unity Mono, Cocos2d-x, libGDX, Adobe AIR,
  Android 4.x-7 behavior.
- Modern analysis: Android 14/15, 16KB page size, Kotlin
  Multiplatform, Jetpack Compose, Rust NDK, Play Integrity, v3/v3.1/v4
  signatures, fs-verity, R8 full mode, baseline profiles, Unity 6,
  Unreal 5, Godot 4, Flutter 3.x, React Native new architecture,
  scoped storage.
- System apps: pulling from firmware partitions, platform signature
  comparison, sharedUserId, priv-app permissions.
- App data: reading on-device databases and preferences with adb
  and sqlite3 (own test device only).
- WebView: JavaScript bridge analysis (`addJavascriptInterface`,
  `@JavascriptInterface`, URL interception).

### Scripts

- `nar-doctor.sh`: toolchain check, plain and `--json` output.
- `nar-triage.py`: first-5-minutes APK/AAB/OBB triage, plain and
  `--json` output. Reports DEX versions and method counts, native
  inventory, signature schemes, engine and framework markers.
- `nar-strings.py`: ranked string extraction (URLs, endpoints,
  key-like patterns, package names).
- `nar-compare.py`: two-version diff without apktool or jadx.
- `nar-perms.py`: permission, component, and intent-filter audit.
  Reports `sharedUserId` and decodes protection levels, including
  the `privileged` flag.
- `scripts/frida/`: four observation scripts (Java API tracing, JNI
  tracing, file I/O, network). Observation only.

### Examples

- `quick-triage.md`: example command session.
- `sample-report.md`: filled example report.
- `unity-il2cpp-triage.md`: Unity IL2CPP worked example with measured
  values from a test game.
- `godot-triage.md`: Godot 4 worked example with measured values
  from a test game.
