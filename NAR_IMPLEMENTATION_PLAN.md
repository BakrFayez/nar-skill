# NAR Implementation Plan — 2.0 program

Execution order follows the brief's 12 phases. Each phase ends
with: new/updated tests green, the full e2e harness green, and
a local commit. Statuses are updated as phases land.

## TOTAL INTELLIGENCE EVOLUTION — Phase 0 baseline and phase plan (2026-11-24)

Phase 0 (reconciliation) is complete. Executed baseline on
this branch at the v2.4.0 tree: pytest 144/144, e2e harness
47/47 (0 skipped), doctor READY, 23/23 unified-CLI
subcommands help-clean, one orchestrated case executed end
to end (10/10 stages ok) with the stage cache verified on
re-run (7 cached / 3 ok). The capability baseline with
per-area statuses and evidence is in NAR_GAP_ANALYSIS.md
("Evolution Phase 0 reconciliation", 2026-11-24); audit
findings are in NAR_AUDIT.md §7.

Already done — do NOT re-plan or re-build: universal input
identification + guarded extraction; provenance fingerprint;
18-family engine fusion; DEX enumeration + full
disassembler (oracle-verified); OAT/VDEX/ODEX/ART parsing;
pak incl. encoded indexes; IoStore TOC v5 + v8 with both
directory-index layouts; the Zen package parser; classic
UAsset inspection; emulator-verified runtime (attach +
spawn); case workspace with hash-keyed cache + resume;
offline HTML dashboard; the 35-tool capability registry;
11 output schemas; executed CI for the current workflow
scope. The phases below target only the verified residual
gaps, ordered by dependency and value. Every item names
its acceptance test; a phase is complete only when its
acceptance tests pass and the full battery stays green
(pytest + e2e + doctor). No phase pushes, tags, or
releases: publication is the owner's explicit call.

### Phase 1 — Core reliability (docs truth + consistency guards)

- Fix the README repo-structure block (BROKEN at audit):
  22 reference guides, all 2.0 modules + narlib, tests/unit
  + tests/benchmarks. Acceptance: a new e2e/docs check
  asserts every file in scripts/ and references/ appears
  in the README structure block.
- Add a version-consistency unit test: skill.yaml,
  SKILL.md, plugin.json, pyproject.toml, README version
  line, nar.py, narlib, nar-analyze, registry.json must
  agree. Acceptance: test passes on the tree and fails on
  a planted mismatch in a temp copy.
- Doctor compile check stops leaving `__pycache__` in the
  tree (compile into the case/temp dir). Acceptance:
  `git status` clean after a doctor run.

**Phase 1 record (2026-11-24): COMPLETE.** Implemented:
README repo-structure block rewritten to the real 2.4.0
layout (22 reference guides, all 2.0 modules + narlib's
14 modules, schemas, tests/unit + tests/benchmarks);
tests/unit/test_docs_consistency.py added (10 tests: every
scripts/ + narlib/ + frida/ + references/ + schemas/ file
named in the block, guide count asserted, SKILL.md routing
targets exist, version consistency across all 18
version-bearing locations, planted-mismatch detection in a
temp copy); nar-doctor.sh compiles bundled scripts into a
throwaway temp dir instead of the tree (verified: zero
`__pycache__` under scripts/ after a doctor run, doctor
still READY). Headline resolution: the brand headline no
longer embeds a version number — README and pyproject now
read "NAR — NIROUS ANDROID INTELLIGENCE" — so the headline
cannot diverge from the release version again; the version
lives only in the guarded version-bearing files. Tests:
pytest 154/154 (144 baseline + 10 new), e2e 47/47, doctor
READY. Known failures: none. Remaining limitations: the
docs check asserts file-name presence, not prose accuracy
of each one-line description.

### Phase 2 — Input and fingerprinting

- nar-analyze emits the brief-named companion set —
  application.json, manifest.json, native-inventory.json,
  frameworks.json — projected from data the stages already
  compute (fingerprint properties, perms manifest facts,
  native.json, engines/fingerprint markers), each
  schema-validated like the existing companions.
  Acceptance: case run on the demo fixture emits and
  validates all four; output-schema.md updated to match.
- nar-fingerprint gains compile_sdk when the badging
  reader exposes it (parse the compileSdkVersion line
  instead of noting its absence). Acceptance: fingerprint
  on an SDK-built fixture reports compile_sdk with
  provenance; absence stays an explicit note.
- nar-input `validate` gains a structural summary for
  AAR/JAR (entry classes, manifest presence) instead of
  identification only. Acceptance: unit tests on synthetic
  AAR/JAR fixtures.

**Phase 2 record (2026-11-24): COMPLETE.** Implemented:
nar-analyze now emits the brief-named companion set —
application.json, manifest.json, native-inventory.json,
frameworks.json — projected by the new narlib/companions.py
from stage data the same run already computed (no stage
re-runs), each validated against a new shipped schema
(schemas/application|manifest|native-inventory|frameworks
.schema.json) before being written; a degraded source
stage yields an explicit "unavailable" field, and a
projection failing validation is not written (limitation
recorded instead). Existing companions unchanged.
nar-fingerprint gains compile_sdk: nar-triage's badging
parser now reads compileSdkVersion off the aapt2 package
line (the Codename field is not matched); the fingerprint
reports it with provenance when present and keeps an
explicit absence note otherwise (verified live: the
SDK-built demo fixture reports compile_sdk 34).
nar-input validate gains a structural summary for AAR/JAR
(narlib.formats.archive_structure_summary: entry/class
counts, MANIFEST.MF presence; for AAR also AndroidManifest
presence, classes.jar presence + its class count, R.txt,
res/ entries, jni/ libraries). Tests: pytest 165/165
(+11: projection/schema validation incl. degraded paths,
planted AAR/JAR summaries, planted-stub-aapt2 compile_sdk
parse); e2e analyze cases assert the four companions in
both case runs; a manual full case on the demo fixture
emitted all four, schema-valid, with compile_sdk flowing
into application.json. references/output-schema.md updated
to match. Battery: pytest 165/165, e2e 49/49 (47 baseline
+ 2 companion assertions), doctor READY. Known failures:
the first e2e run of this phase failed the four nar-input
cases — a syntax error in the new human-readable validate
output (a conditional split across two f-strings), which
no unit test imported; fixed in-phase and the re-run is
green. Remaining limitations:
projections cover the stages' summary-level data by
design (full detail stays in the stage documents);
compile_sdk depends on aapt2 badging, so AAB/container
identity paths still record its absence explicitly.

### Phase 3 — Android intelligence (DEX / ELF / JNI depth)

- narlib/dex.py: parse try/catch handler tables
  (try_items + encoded catch handlers) and report
  debug-info presence per method. Acceptance: unit tests
  on a synthetic DEX with known try ranges + a dexdump
  cross-check over corpus DEX files (handler counts
  agree).
- narlib/dexdis.py: optional control-flow block summary
  per method (block boundaries from branch targets; no
  full graph rendering). Acceptance: unit test on a
  method with known branches; the 40,837-method oracle
  comparison stays 0-mismatch.
- narlib/elf.py: relocation parsing (DT_RELA/DT_REL,
  PLT/GOT summary). Acceptance: `readelf -r` cross-check
  on the demo native library + one corpus library.
- Compiler fingerprints: .comment section parsing
  (Clang/GCC) beside the existing Rust markers.
  Acceptance: unit fixtures with planted .comment
  strings; no fingerprint claimed when the section is
  stripped.
- Kotlin: parse @Metadata annotation payloads (metadata
  version, kind) when present. Acceptance: fixture with
  known metadata version; stripped-metadata fixtures
  keep the existing marker-level verdict.

**Phase 3 record (2026-11-24): COMPLETE.** Implemented:
narlib/dex.py code_item_info (try/catch handler tables —
try items, typed handlers resolved through the DEX's own
type table, catch-all addresses — plus debug-info presence
per method), surfaced by nar-dex as a per-DEX try_catch
summary; narlib/dexdis.py block_summary (block boundaries
from branch/switch targets, fallthrough, and try ranges;
the listing path is untouched); narlib/elf.py relocation
parsing (SHT_REL/SHT_RELA with symbol resolution, per-type
names, PLT/GOT subset) and .comment compiler fingerprints
(Clang/GCC banners as OBSERVED evidence, nothing claimed
when stripped), both surfaced in nar-native facts;
narlib/dex.py annotation decoding (encoded values +
class-level annotation sets) with Kotlin @Metadata
extraction in nar-dex (metadata version + declaration
kind per class, capped samples). Two real defects found
and fixed in-phase: (1) index-carrying encoded values are
fixed-width little-endian (value_arg+1 bytes), not ULEB128
— the ULEB reading desynchronized annotation streams on
indices >= 256 (proven on a real corpus class whose
@Metadata elements decode garbled before the fix and
exactly after it; a synthetic regression case with a
string index of 300 placed before mv/k pins it);
(2) nar-dex gated @Metadata extraction on the bare string
"kotlin/Metadata" in the string table, which release
builds do not carry — the gate is now the type-table
descriptor, and metadata_annotation_present uses the same
check (on the Kotlin corpus fixture the count moved from
0 to 10,213 classes). Cross-checks executed: SDK dexdump
on a corpus DEX — methods with tries 484 = 484, try items
1,178 = 1,178, handler entries 1,357 = 1,357; readelf -r
on the demo native library — section counts 3 + 2 = 5
agree, and readelf's type names corrected the AArch64
JUMP_SLOT number in the name map (1026, not 282); the
dexdis oracle harness re-run on the corpus DEX — FULL
AGREEMENT (230,836 instructions, 0 mismatches), so the
block summary did not disturb listing equivalence.
@Metadata on the Kotlin corpus fixture: 10,213 annotations,
metadata versions 1.8.0 / 2.2.0 dominant, legacy bv
element present on older annotations. Tests: pytest
171/171 (+6 synthetic: known try ranges, block layout,
planted .rela.plt + .comment ELF, @Metadata incl. the
desync regression); e2e and doctor in the phase battery.
Known failures: none outstanding. Remaining limitations:
debug-info is presence-only (no line/local decoding);
block summary is boundaries + edges, not a rendered
graph; relocation output is a summary in facts (full
entries available via Elf.relocations()); @Metadata
d1/d2 payloads are decoded as values but not interpreted
as Kotlin declaration models.

### Phase 4 — Game engine intelligence

- Unity: parse the Addressables catalog.json into an
  addressables inventory (locations, resource types,
  providers) in nar-unity. Acceptance: synthetic catalog
  fixture + the Unity fixture case asserts the inventory.
- React Native: source-map detection and native-module /
  TurboModule / Fabric indicator inventory in nar-rn
  (bundle assets + DEX markers). Acceptance: planted
  fixture with a source map + module markers; clean
  fixtures stay negative.
- Flutter: real asset inventory for flutter_assets
  (entries typed via nar-assets rules) in nar-flutter.
  Acceptance: Flutter fixture case lists assets, not
  just a presence flag.
- Godot: resource-type classification in nar-godot
  listings (scene/script/texture/audio/font by header +
  extension, labeled by evidence kind). Acceptance:
  Godot fixture listings carry types; encrypted entries
  stay marked, never typed by guess.
- Unreal: UE5 tag-extension property layouts (object
  version >= 1011) — synthetic fixtures only, labeled as
  such; Kismet/Blueprint graph decoding stays PLANNED
  and out of scope until a versioned real corpus exists
  (see environment-blocked list). Acceptance: synthetic
  byte-exact fixtures; docs state the synthetic level.

**Phase 4 record (2026-11-24): COMPLETE.** Implemented:
(1) Unity Addressables: nar-unity parses catalog.json
into a real inventory (locations, providers, resource
types, entry table). The entry blob layout (int32 count
+ 28-byte entries) and its field roles were established
by range validation against a real catalog's own tables
(6,798 locations / 159 types / 24,820 entries on the
bundles fixture; per-type and per-provider counts
cross-validate: 6,308 bundle resources = 6,308
AssetBundleProvider entries). A defect was caught and
fixed in-phase: the bundle walk's scan cap could exit
before a late-listed catalog was read — the catalog now
reads in its own pass. (2) React Native: source-map
detection (*.map entries + the bundle's sourceMappingURL
reference) and a native-module inventory — full name
extraction (TurboModule / Fabric / NativeModules) for
text bundles; for Hermes bytecode the names are
standalone string-table entries and cannot be attributed
to call sites without bytecode reference analysis, so
the report gives architecture-marker counts and says
names were not extracted (verified on the real Hermes
fixture: all four markers present). (3) Flutter:
nar-flutter inventories flutter_assets for real (370
typed entries on the fixture: 262 images, 8 fonts, 2
shaders, ...; AssetManifest.bin presence reported, its
keys not decoded; the JSON manifest's declared keys are
counted when that form ships). (4) Godot: pack entries
carry resource types with labeled evidence — header
magic wins (text scenes/resources, RSRC binary resources
with the embedded type name read out, texture/audio/font
magic), extension is the labeled fallback, and encrypted
entries are NEVER typed (fixture pack: 36 scenes, 58
textures, 89 compiled scripts, 1 RSRC 'PackedScene').
(5) Unreal UE5 tag extensions: narlib.uasset now parses
the 1011 extension tail and the 1012+ complete-type-name
layout (FPropertyTypeName node tree, flags byte carrying
array index / GUID / extensions, bool value in the
flags), replacing the previous "unsupported" refusal.
The layouts were grounded in the publicly documented
format (the open-source reference reader's published
sources) and are verified on SYNTHETIC packages only —
no real package with a recorded UE5 version >= 1011
exists (shipped titles strip versions or use Zen) — and
the parser output labels them synthetic wherever they
are reported. Tests: pytest 178/178 (+5 engine-intel, +2
uasset synthetic-layout; the real-fixture catalog test
makes the unit suite slower, ~70 s total, dominated by
the IL2CPP path on the bundles fixture), doctor READY
(one transient INCOMPLETE during the phase was an
environment artifact — scratch filled the VM's small
/tmp tmpfs and the JVM could not create its
shared-memory file; cleaning scratch restored READY; no
code involvement). Known failures: none outstanding.
Remaining limitations: Hermes module-name attribution
needs bytecode reference analysis (markers only);
AssetManifest.bin keys not decoded; Godot entries whose
content and extension both lack signal stay "unknown";
UE5 1011/1012 layouts are IMPLEMENTED_BUT_UNVERIFIED
against real samples (synthetic verification only, by
corpus evidence); Kismet/Blueprint graph decoding stays
PLANNED (Phase 7 area), out of this phase's scope.

### Phase 5 — Protection and network intelligence

- Extract the packer/protection signatures from
  nar-triage code into a versioned data artifact
  (signatures database with its own version field +
  loader + doctor visibility). Acceptance: unit tests
  load the DB; the protection e2e cases (named on
  doctored, zero false positives on the clean set) pass
  unchanged.
- nar-network: credential/token redaction pass over all
  emitted documents (endpoints, hosts, services) with
  redaction counts reported. Acceptance: planted-token
  fixture is redacted in JSON output; counts match the
  planted number.
- nar-analyze emits network-analysis.json and
  api-architecture.json companions projected from the
  endpoints document, schema-validated. Acceptance:
  case run emits + validates both.

**Phase 5 record (2026-11-24): COMPLETE.** Implemented:
(1) The protection signatures moved out of nar-triage
code into the versioned data artifact
scripts/protection-signatures.json (database_version
1.0.0, schema 1: categories, 11 named packers with
attribution notes, RASP + licensing DEX markers, the four
Widevine UUID forms, pin/stub patterns, stub thresholds),
loaded and structurally validated by the new
narlib/signatures.py; a missing or malformed database is
a hard error, never a silent fallback. Equivalence is
pinned two ways: a canonical digest of the loaded
structures equals the digest computed from the
pre-extraction code literals (test_signatures.py pins
it), and nar-triage --json output is byte-identical to
the pre-change tool on all three protection fixtures and
the demo (the new protection_signatures provenance field
aside). nar-doctor gained a core protection-signatures
check reporting the DB version + counts; triage reports
carry the database version. (2) nar-network redaction:
credential values in endpoint URLs (sensitive query
parameters + userinfo) are replaced with REDACTED before
any output; classification still runs on the original
URL; the report counts redactions and no raw value
reaches any case output (nar-security evidence strings
included, since they quote the redacted document).
Acceptance: planted fixture with exactly 5 credential
values → count 5, zero secret substrings in the
serialized report, 3 sensitive classifications preserved.
(3) network-analysis.json + api-architecture.json
companions (narlib.companions projections, two new
schemas), schema-validated in case runs like the Phase 2
set; the architecture projection keeps paths only (query
strings dropped). Tests: pytest 194/194 (178 baseline +
9 signatures + 7 network), e2e 52/52 (protection cases
unchanged: Pairip named, zero named packers on the
9-file clean set, Widevine compiled-UUID; both analyze
cases assert all six companions), doctor READY.
Known failures: none. Remaining limitations: redaction
covers endpoint URLs (the only credential carrier in the
network documents); google-services evidence stays
value-free by design as before. The signature database
is versioned but its update workflow is manual (edit
JSON + bump database_version + update the digest pin).

### Phase 6 — Runtime and security

- nar-runtime: persisted session records (session id,
  device facts, tool versions, start/stop, event paths,
  errors) written by plan/status flows. Acceptance:
  offline unit tests over recorded session inputs;
  device paths keep their honest labels.
- jni-trace RegisterNatives event path: build a demo
  fixture variant whose native library registers via
  RegisterNatives (the current fixture binds statically)
  and run it on the API 26 emulator with the verified
  attach + spawn recipes. Acceptance: a live
  [jni-register] event captured, or the row stays
  labeled unverified with the attempt recorded.
  Physical-device rows are NOT part of this phase
  (environment-blocked).
- nar-security: findings gain the verification-status
  field (with Phase 8's vocabulary). Acceptance: schema
  validation + the known-findings/clean fixture cases.

**Phase 6 record (2026-11-24): COMPLETE, including the
live jni event capture.** Implemented: (1) Runtime
session records — nar-runtime plan/status accept
--session-out DIR and persist runtime-session.json
(new schema): session id, flow kind, device identity
with its verification label carried unchanged, adb/frida
probes, target path + SHA-256, start/stop, the events
the flow produced (session-started, one step-planned
per plan step / status-probe), evidence paths, errors.
Offline unit tests validate records built from recorded
status snapshots; a live run into a scratch case dir
recorded the attached emulator truthfully
(verified-live). (2) The jni-trace event path is
CLOSED with genuine live events. A demo-fixture variant
was built whose second library exports only JNI_OnLoad
and binds dynGreeting via RegisterNatives, loading
lazily when the details screen opens (demo source copy
outside the repo; built x86_64 with the demo's own test
keystore; evidence + attempt log in the runtime-test
workspace). Attach mode captured the FULL chain:
"[jni-register] class=…DetailsActivity methods=1 via
JNIEnv table", the per-method line resolving the
variant library's registered function symbol, and a
[jni-entry] call
trace; logcat confirms the registered method ran and
returned its string. Spawn mode (spawn → immediate
resume → 50 s settle → CLI load) captured the
class-level event the same way. The live run caught a
real defect: the per-method read used
Memory.readPointer/readUtf8String statics removed in
Frida 17 — fixed to NativePointer instance methods
(the other four scripts audited: no other removed
statics). First attempts failed honestly (CLI attach
timeout under host contention; a transient empty pidof)
and are recorded in the attempt log with the driver
hardening they produced. (3) verification_status: the
vocabulary (CONFIRMED / STRONGLY_INDICATED / POTENTIAL /
UNVERIFIED / CONTRADICTED) landed in narlib;
make_finding validates and carries it (default
UNVERIFIED); nar-security assigns it per finding —
CONFIRMED for facts read directly off the target
(manifest attributes, signer verdict, config),
STRONGLY_INDICATED for conclusions from classified
patterns, POTENTIAL for the permission-surface review
prompt; the schema lists it in properties but NOT in
required, so pre-field findings still validate (pinned
by test). Tests: pytest 202/202 (194 + 8), e2e 52/52,
doctor READY. Known failures: none outstanding.
Remaining limitations: physical-device runtime is
still untested (owner's device only); the spawn-mode
capture holds the class-level event (the method-line
rendering is proven by the attach capture on the same
script build); session records cover the plan/status
flows — a live device session's own events are still
the operator's timeline to fill.

### Phase 7 — Assets and comparison

- nar-assets: audio metadata from headers (WAV/OGG/MP3:
  duration where computable, channels, sample rate),
  labeled by format support. Acceptance: synthetic audio
  fixtures with known headers; unsupported formats are
  reported as unmeasured, never guessed.
- nar-compare: emit feature-map.json and version-diff.md
  as named artifacts beside the comparison JSON.
  Acceptance: planted-pair e2e asserts both files and
  their key deltas (added permission, endpoint change,
  asset change).

**Phase 7 record (2026-11-24): COMPLETE.** Implemented:
(1) nar-assets audio metadata — stdlib header parsers
for WAV (fmt/data chunks: channels, sample rate,
duration = data size / byte rate), OGG Vorbis + Opus
(ID header + final-page granule duration), and MP3
(frame header: channels, sample rate; duration from the
Xing/Info frame count when present, otherwise a
constant-bitrate estimate LABELED as an estimate).
Audio entries gain an "audio" block; formats outside
the measured set (FLAC, M4A, truncated files) report
measured: false with the reason — never guessed.
Acceptance: synthetic fixtures with known headers
(WAV exactly 2.0 s, Vorbis granule exactly 3.0 s,
Xing-counted MP3 2.612 s, CBR estimate 2.0 s labeled)
plus an inventory-level test. (2) nar-compare --out DIR
writes comparison.json (the full report), feature-
map.json (per-dimension added/removed/modified
projection, new compare-feature-map schema), and
version-diff.md rendered from the same projection so
the two cannot disagree. The build-noise block
separates signing-file churn from content changes and
labels the separation a heuristic; unfiltered counts
stay in comparison.json. The phase also caught a real
latent defect: the extended endpoint diff iterated the
nar-strings group DICTS (yielding their keys) instead
of their hit lists, so both sides produced identical
sets and every endpoint diff silently reported 0/0 —
fixed; the planted pair now shows its real endpoint
change (one added, one removed). Acceptance: the new
e2e case asserts all three artifacts and the planted
deltas (added permission, method-count delta +2,
endpoint change) on the demo pair; unit tests pin the
projection + the signing/content separation. Tests:
pytest 213/213 (202 + 7 audio + 4 compare), e2e 53/53
(52 + 1), doctor READY. Known failures: none.
Remaining limitations: MP3 duration without a Xing
header is an estimate by construction (labeled);
WAV/OGG durations depend on header honesty (a file
whose data chunk lies about its size reports the
header's claim — the basis string says exactly what
was computed); the planted pair has no asset delta, so
the assets dimension is asserted at unit level with a
fabricated report rather than on the pair.

### Phase 8 — Evidence and orchestration

- narlib/evidence.py: verification-status vocabulary
  (CONFIRMED / STRONGLY_INDICATED / POTENTIAL /
  UNVERIFIED / CONTRADICTED) as a first-class field +
  schema updates in schemas/. Acceptance: unit tests +
  schema validation of a full case's outputs.
- Correlation records: join nar-dex native declarations
  with nar-native JNI exports and emit explicit
  correlation entries (matched / declaration-only /
  export-only) in native.json and the report.
  Acceptance: the demo fixture's known JNI pair appears
  as matched; a planted unmatched declaration appears
  as declaration-only.
- Orchestration budgets: per-stage timeout + total
  budget in the case config, enforced and recorded in
  the execution log. Acceptance: unit test with a forced
  slow stage records a budget stop, not a hang.
- Case export / import / verify in nar-analyze
  (portable case bundle; verify re-checks input hash +
  cache integrity). Acceptance: round-trip e2e —
  export, import elsewhere, verify passes; a tampered
  bundle fails verify.

**Phase 8 record (2026-11-24): COMPLETE.** Implemented:
(1) The verification-status vocabulary is now
first-class across the evidence layer: narlib carries
VERIFICATION_STATUSES (Phase 6), evidence.py adds
verification_for_fact_class (observed → CONFIRMED,
derived → STRONGLY_INDICATED, inferred/hypothesis →
POTENTIAL, unknown → UNVERIFIED; CONTRADICTED is only
ever set explicitly), nar-fingerprint properties carry
verification_status via that mapping (schema updated,
field not required so older fingerprints validate),
and correlation entries carry it per entry. A full
case's thirteen schema-bound documents were validated
as a sweep — all valid. (2) Correlations:
narlib/correlations.py joins DEX native declarations ↔
ELF JNI exports (JNI symbol mangling; matched /
declaration-only / export-only; exports are unioned
from jni_map and per-library jni_exports), manifest
components ↔ DEX entry points (matched /
declaration-only / implementation-only), endpoints ↔
DEX string-reference classes (code-referenced /
no-code-reference), and network libraries ↔ DEX class
prefixes. Emitted as the schema-validated
correlations.json companion in every case run; the JNI
entries are also embedded into native.json and counted
in the report. Same-evidence deduplication is stated
in the document and implemented (multi-DEX
declarations merge). Acceptance on the demo fixture:
the known JNI pair is matched/CONFIRMED, both
components matched, the app's API host code-referenced
while a native-only toolchain URL is not; a fabricated
document set pins the planted declaration-only and
export-only paths. (3) Orchestration budgets:
--stage-timeout / --total-budget on nar-analyze,
enforced centrally in the tool runner (effective
timeout = min of cap, remaining budget) and as a
pre-stage total-budget check; stops are recorded in
execution-log.json + case.json stage states with
status "budget-exceeded" (schema enum extended) and
the budgets are recorded in the case config. Unit
tests: an exhausted total budget stops a stage without
running it; a 1 ms stage cap against a real tool
records budget-exceeded in well under a second.
(4) Case export/import/verify: --export/--bundle
writes a single zip with a per-file SHA-256 manifest;
--import extracts with path guards and verifies;
--verify re-checks the recorded input hash (re-hashed
when the input file is present), the bundle manifest
(every file's hash + size), and the stage-cache
integrity keys (recomputed from the case's recorded
input hash + its recorded NAR version + stage name).
Round-trip e2e on a real case: export → import
elsewhere → verify OK; a tampered report.json fails
verify with the mismatch named. Tests: pytest 220/220
(213 + 7), e2e 55/55 (53 + correlations + bundle
cases), doctor READY, full-case schema sweep 13/13.
Known failures: none. Remaining limitations: budgets
bound tool subprocesses; a stage already past its
subprocess (projection/companion work in-process) is
not preemptible, and cached stages consume no budget
by design; verify's input-hash re-check needs the
input file at its recorded path (an imported case
notes the skip rather than passing silently);
correlations inherit their stages' limits (e.g.
endpoint referencing classes come from the DEX
string-reference samples).

### Phase 9 — Reporting and CLI

- Dashboard renders the native dependency graph from
  native.json (offline, stdlib-generated SVG, no
  external requests). Acceptance: dashboard e2e asserts
  the graph section and the zero-external-reference
  property.
- New CLI verbs without changing existing ones:
  `nar tools` (registry view), `nar identify` /
  `nar validate` (aliases of nar input subcommands),
  `nar benchmark` (wraps tests/benchmarks runner),
  `nar case` (export/import/verify routing).
  Acceptance: the --help sweep covers the new verbs;
  smoke e2e runs each once.

**Phase 9 record (2026-11-24): COMPLETE.** Implemented:
(1) Dashboard dependency graph: nar-report.py loads
native.json and renders its dependency_graph as an
inline SVG section (nar-report.py dep_graph_svg):
deterministic longest-path layered layout (bounded
relaxation, so cyclic graphs terminate), per-layer
widths, theme-variable colors, HTML-escaped labels,
arrow markers via internal fragment references only.
Graphs over 120 libraries truncate to the first 120
(sorted) with a note pointing at native.json; an
absent or empty graph renders no section. The page
keeps the zero-external-reference property (asserted
in unit tests and e2e: no http(s)://, src=, href=).
(2) CLI verbs: nar.py's dispatch table gains a fixed
prefix-args element; new verbs are `nar tools` (new
scripts/nar-tools.py: registry view over
narlib.registry probe_all, --json / --available, a
view not a gate), `nar identify` / `nar validate`
(prefix aliases into nar-input's subcommands),
`nar benchmark` (routes to
tests/benchmarks/run_benchmarks.py), and `nar case`
(a small router translating export/import/verify to
nar-analyze's --export/--import/--verify flags, with
its own usage text). All 23 pre-existing verbs are
untouched pass-throughs; `nar --help` documents the
new set. Tests: tests/unit/test_phase9_reporting_cli.py
(9 tests: graph render/escape/cycle/truncation,
no-section cases, help listing, per-verb --help,
tools JSON shape, identify/validate on a synthetic
APK, a full case export→import→verify round-trip
through the CLI, unknown case subcommand rejected);
e2e gains 10 cases (tools JSON, five --help sweeps,
identify/validate on the demo, case verify/export on
the app case, dashboard graph on a synthetic case,
benchmark smoke on a demo-only corpus). Battery:
pytest 229/229 (220 + 9), e2e 65/65 (55 + 10),
doctor READY. Known failures: none. Remaining
limitations: the graph layout is a layered drawing,
not a force-directed one — dense real-world graphs
(hundreds of libraries) truncate at 120 nodes in the
dashboard by design, with the complete graph always
available in native.json; `nar benchmark` measures
the local fixture corpus only (Phase 11 extends the
runner with accuracy metrics and peak memory).

### Phase 10 — AI skill and integrations

- SKILL.md routing rows for the Phase 9 verbs and the
  Phase 2/5 companion documents; references updated in
  the same commits as the code they describe.
  Acceptance: docs-vs-CLI consistency check (Phase 1)
  covers SKILL.md routing targets — every routed script
  path exists.
- Registry: any tool whose status changes in Phases 3–9
  is updated in registry.json in the same commit.
  Acceptance: test_registry.py green.

**Phase 10 record (2026-11-24): COMPLETE.** Implemented:
(1) SKILL.md routing updated for the Phase 1–9 surface:
the analyze row names correlations.json and the
budgets; the unified-CLI row names the five Phase 9
verbs; new rows route `nar tools` and `nar case`;
module rows now state try/catch + Kotlin @Metadata
(DEX), relocations + compiler fingerprints (native),
source redaction (network), verification status
(security), audio metadata (assets), session records
+ live-verified jni-trace (runtime), the versioned
signature database (protection), compare artifacts,
Addressables catalogs, RN source maps + module
inventory, the Flutter asset inventory, and Godot
resource types; the helper-scripts paragraph names
nar-tools.py. (2) The deferred full guide-vs-code
audit ran over all 22 references + SKILL.md with a
scripted extraction: link targets 0 missing; script
filenames 0 missing; flags attributed to a nar script
on the same line 0 mismatches; block-level attribution
0 mismatches; backticked `nar <verb>` mentions 0
unknown. The 51 flag tokens no nar script defines were
each dispositioned in context: all belong to named
external tools in the guides' own command examples
(bundletool, apksigner, jadx, frida-tools, oatdump,
GDRE, mitmproxy, dotnet-install, pip, node) — no guide
change needed; one of them (--jvm-args) is a guide's
explicit correction note that jadx has no such flag.
One stale capability claim found and fixed: the DEX
guide's scope limit denied try/catch decoding and any
control-flow structure; it now states what nar-dex /
narlib actually do (try/catch tables + debug-info
presence reported; library block summary; rendered
CFG and debug line/local decoding still unimplemented).
Two discoverability gaps closed: the dynamic-analysis
guide documents runtime session records, and the
tool-registry guide documents `nar tools`. (3) The
audit's durable checks are encoded in
tests/unit/test_phase10_guide_audit.py (5 tests),
including programmatic SKILL.md frontmatter parsing
(name, version == library version) and plugin.json
parsing (version match). (4) Registry: no tool's
status changed in Phases 9–10, so registry.json is
unchanged; test_registry.py green. Battery: pytest
234/234 (229 + 5), e2e 65/65, doctor READY. Known
failures: none. Remaining limitations: flag checking
covers nar-attributed flags only — external-tool flags
in guides are verified by context, not against the
tools; the dedicated `nar benchmark` routing row lands
with its methodology guide in Phase 11.

### Phase 11 — Testing and benchmarks

- Benchmark runner gains accuracy metrics over the
  labeled fixture corpus: format-identification accuracy,
  engine-verdict accuracy, packer false-positive /
  false-negative counts — computed from the corpus,
  reported with methodology; synthetic and real-target
  numbers reported separately. Acceptance: runner emits
  a metrics JSON; numbers reproduce on re-run.
- Mutation corpus: truncated/mutated DEX, ELF, PAK and
  IoStore headers must fail cleanly (structured error,
  no traceback) across narlib parsers. Acceptance: unit
  tests over the mutation set.
- Performance: record wall-time + peak memory for the
  largest local fixture in the benchmark run.
  Acceptance: measured values in the benchmark report;
  nothing estimated.

**Phase 11 record (2026-11-24): COMPLETE.** Implemented:
(1) Benchmark metrics: run_benchmarks.py gains a
metrics section computed from the labeled corpora bound
in the local fixture manifest (role labels only in the
output; synthetic and real always separate) and a
peak-memory measurement (nar-analyze on the largest
bound fixture, RUSAGE_CHILDREN of the runner measured
before any other child runs; the scope — nar-analyze
process peak, stage subprocess peaks excluded — is
stated in the output and the guide). Methodology:
references/benchmarks.md (new guide; README guide count
22 → 23; SKILL.md gains the benchmark routing row).
Measured results (this machine, this corpus): timings
28/28 runs exit 0. Protection attribution (real:
1 protected + 9 clean): precision 1.0, recall 1.0,
0 false positives. Engine detection (real): recall
1.0 on 6 labeled positives (Unity ×2, Flutter, React
Native, Unreal, Godot). Engine detection (synthetic
framework corpus): accuracy 1.0 on 8 — the first full
run showed 0.875 because the runner's expected label
"Xamarin /.NET" did not match the canonical verdict
name "Xamarin / .NET" (the engine itself detected the
fixture at score 44); the label was corrected and the
metrics re-run reproduces 8/8. Format identification
(real): accuracy 1.0 on 10 labeled (8 APK, 1 XAPK,
1 Godot pack). NOT RUN, stated in the output: real-
corpus engine precision (no labeled engine-negative
real corpus exists). Peak memory (measured): fixture
273,366,540 bytes → nar-analyze peak RSS 1,887,338,496
bytes, wall 304.69 s, exit 0. (2) Mutation corpus:
tests/unit/test_phase11_mutations.py (5 tests) drives
truncated / corrupted / empty inputs through the DEX,
ELF, PAK, IoStore and Zen parsers (construct +
materialize) and requires each parser's named error
type — no leaked struct.error / IndexError / TypeError.
The corpus caught two genuine defects, fixed in-cycle:
narlib.dex validated no header-table extents, so an
inflated string_ids count leaked a bare struct.error
from strings() — __init__ now validates all six tables'
extents and raises DexError; narlib.elf treated any
EI_CLASS ≠ 2 as 32-bit — an invalid class byte now
raises ElfError. (3) Battery: pytest 239/239 (234 + 5),
e2e 65/65, doctor READY. Known failures: none.
Remaining limitations: the protection corpus has a
single positive, so its recall is 1.0-or-0.0 by
construction (the informative figure is the clean-set
FP count); the peak-memory figure excludes stage
subprocess peaks by the stated method; timings vary
by machine and load.

### Phase 12 — Release preparation (no publication)

- Release guide reference (version-bump checklist across
  the nine version-bearing files, battery, greps, ZIP,
  sync) written from the 2.x release practice.
- README compatibility/install sections refreshed
  against the final tree; CHANGELOG Unreleased entries
  consolidated per release discipline.
- Final battery + banned-identifier and credit greps;
  the tree is left release-ready for the owner's
  explicit publication decision.

**Phase 12 record (2026-11-24): COMPLETE — release
prepared, NOT published.** Implemented: (1) Version
2.5.0 in all 18 version-bearing locations (the Phase 1
consistency test enumerates them; nar-runtime carries
the field in three report builders, all bumped);
`nar version` reports 2.5.0 and the docs-consistency +
guide-audit tests pass at the new version. Historical
2.4.0 mentions in CHANGELOG/plan/gap/matrix stay
untouched, as do version strings carried as fixture
data. (2) CHANGELOG: the 12 evolution bullets
(Phases 1–12) consolidated under "## 2.5.0
(2026-11-24)" with a fresh empty Unreleased above.
(3) Release guide: references/release-guide.md (new;
README guide count 23 → 24) documents the 2.x practice
end to end — battery, the 18-location bump, changelog
discipline, pre-push greps, push manifest excluding
.github/workflows, sync record, ZIP via git archive,
the web-UI release step, skill-copy sync. (4) README:
Version line 2.5.0, a "What's new in 2.5.0" summary
section, structure block current (24 guides,
benchmarks + release-guide listed). (5) Final battery:
pytest 239/239, e2e 65/65 (0 skipped), doctor READY,
CLI smoke of all 28 verbs + version (29 invocations,
every --help exits 0). (6) Greps over the whole
evolution diff (Phase 0 commit ba2ad2e..HEAD): banned
identifiers 0 hits, forbidden credits 0 hits (the only
credit anywhere is the allowed one). Tree left clean
on branch `evolution`, release-ready. Merging to main,
pushing, tagging, and publishing were NOT done — they
remain the owner's explicit decision. Known failures:
none. Remaining limitations (unchanged, honestly
labeled in the baseline): physical-device runtime
verification (owner's device only), Zen pre-5.3/EA
layouts and recorded Zen versioning (synthetic-only),
OAT beyond API 26 x86_64 (synthetic-only), Kismet /
Blueprint graph decoding (PLANNED), CI execution
(GitHub-only), real-corpus engine precision (NOT RUN —
no labeled engine-negative real corpus).

### Environment-blocked (not schedulable in this environment)

- Physical-device runtime verification — no device is
  attached to this VM; the owner's device test is the
  only path. Rows stay IMPLEMENTED_BUT_UNVERIFIED.
- CI workflow changes and CI execution — the release
  push path lacks the GitHub workflows permission
  (workflow edits route through the web UI), and CI
  runs on GitHub only when pushed; this program does
  not push.
- Oodle decompression — proprietary SDK with no open
  implementation; UNSUPPORTED by design, refused by
  name.
- A real classic-format UE5 package with recorded
  FileVersionUE5 — evidence-negative across five
  examined UE5 titles; the verification row stays open
  by evidence and cannot be scheduled against a sample
  that has not been found.
- Zen pre-5.3 / Early Access layouts and recorded Zen
  versioning on real data; OAT beyond API 26 x86_64;
  real Dalvik-ODEX / CDEX files; Wear OS / APEX /
  instant-app samples — no obtainable samples; each
  stays at its labeled synthetic or unexercised level
  until a sample exists.
- Play Integrity server-side verdict — not completable
  from any client; client-presence reporting only.

## Completion record (2.0.0, 2026-11-23)

- Phase 1 ✅ audit document set (commit 9d1e958).
- Phase 2 ✅ narlib + registry + schemas + nar-input + MD fix
  (commit fc6b22e; the five 1.1.1 wide-sweep fixes landed in
  the same commit).
- Phase 3 ✅ nar-fingerprint, nar-dex, nar-native,
  nar-compare extended; narlib ELF gained a PT_DYNAMIC
  fallback found by the new unit tests.
- Phase 4 ✅ nar-engines (fusion + --deep), nar-unity
  (incl. optional UnityPy census), nar-unreal.
- Phase 5 ✅ nar-network (classified endpoints, services,
  NSC parsing; malformed-URL hardening from real string data).
- Phase 6 ✅ nar-runtime (adapters + plans + timeline
  schema); device parts IMPLEMENTED_BUT_UNVERIFIED.
- Phase 7 ✅ nar-security (§9.5 findings, schema-validated).
- Phase 8 ✅ inside Phase 3 (nar-compare extended section).
- Phase 9 ✅ nar-assets.
- Phase 10 ✅ nar-analyze orchestrator (case workspace,
  execution log, stage cache/resume), nar-report offline
  dashboard, nar.py unified CLI.
- Phase 11 ✅ five new reference guides, SKILL.md routing,
  README identity block, pyproject.toml, CI workflow
  (authored; executed locally in equivalent steps, not on
  GitHub Actions).
- Phase 12 ✅ final QA: pytest 33/33, py_compile sweep clean,
  benchmarks measured on four fixture roles (28 runs),
  banned-identifier grep clean, version 2.0.0 everywhere.
  Remaining honest limits: runtime-on-device unverified;
  IoStore entry parsing not integrated; the e2e harness
  gained no new cases this cycle for the 2.0 modules (their
  coverage lives in tests/unit + direct fixture runs
  recorded in NAR_TEST_MATRIX.md).

## Phase 1 — Repository audit ✅ (this document set)

Deliverables: `NAR_AUDIT.md`, `NAR_GAP_ANALYSIS.md`,
`NAR_IMPLEMENTATION_PLAN.md`, `NAR_TEST_MATRIX.md`,
`NAR_ARCHITECTURE.md`. Wide-sweep findings folded in (one
cosmetic Markdown-rendering defect recorded as BROKEN).

## Phase 2 — Core reliability

- `scripts/narlib/` package: hashing, format identification
  (§3.1 magic + structure for APK/APKS/XAPK/AAB/AAR/JAR/DEX/
  ODEX/VDEX/ELF/PCK/PAK/IoStore/ZIP/OBB), safe archive layer
  (zip-slip, traversal, symlink, bomb ratio, nesting, size
  caps — all reported), evidence schema + stdlib validator,
  registry reader.
- `scripts/registry.json`: every orchestrated tool declared
  (name, probe, platforms, formats, engines, required,
  limitations, validation). Absent tools (Cpp2IL,
  Il2CppInspector, AssetRipper, UABEA, FModel, UAssetAPI,
  UnrealPak, CFR, Procyon, dex2jar) are registered as
  unavailable with reasons — never faked.
- `schemas/` for the 2.0 outputs.
- `scripts/nar-input.py`: identify / validate / duplicates /
  safe-extract CLI over the core.
- Fix the nar-analyze Markdown raw-JSON rendering defect.
- Unit tests: `tests/unit/` (pytest, stdlib-style tests) for
  formats, safe archive (planted slip/bomb/traversal cases),
  evidence validation.
- Acceptance: unit tests pass; e2e harness green; new e2e
  cases for nar-input on synthetic fixtures.

## Phase 3 — Android intelligence

- `scripts/nar-fingerprint.py`: normalized application +
  fingerprint JSON with provenance/confidence, from triage +
  perms outputs.
- `scripts/nar-dex.py`: DEX enumeration (classes, methods,
  fields, hierarchy edges, string-ref mapping at class level,
  reflection + dynamic-loading + native-method evidence,
  entry points, invoke-based call edges with bounds), plus
  version-checked jadx/apktool/baksmali adapters producing
  class/method indexes; Kotlin feature inventory from DEX
  evidence (coroutines, Flow/StateFlow, serialization,
  data/sealed/companion inference labeled as inferred).
- `scripts/nar-native.py`: ELF imports/exports/dependencies/
  sections/segments/build-id/JNI export mapping + dependency
  graph, readelf cross-check when available.
- nar-compare extension: class/method/string/endpoint/asset
  diff categories + change severity + similarity metrics +
  noise notes.
- Acceptance: unit + e2e cases for each module on fixtures
  with known ground truth (demo pair, engine fixtures).

## Phase 4 — Game engine intelligence

- `scripts/nar-engines.py`: fused multi-indicator detection
  with confidence + ambiguity (consumes triage + fingerprint
  + container evidence).
- `scripts/nar-unity.py`: Mono/IL2CPP routing, Unity version,
  metadata inspection (via nar-il2cpp), AssetBundle +
  Addressables inventory; UnityPy optional deep inventory
  (object-type counts) with graceful absence.
- `scripts/nar-unreal.py`: UE4/UE5 routing, version evidence,
  pak inventory (via nar-pak), IoStore detection + container
  header facts with honest limits, config inventory.
- Godot/Flutter/RN adapters formalized around the 1.x
  scripts (declared stages/limits in the registry; Flutter
  asset inventory; RN source-map + native-module discovery).
- Acceptance: e2e engine cases extended (confidence present,
  no single-weak-signature verdicts).

## Phase 5 — Network intelligence

- `scripts/nar-network.py`: static discovery with the brief
  taxonomy (confirmed/potential/third-party/unused/sensitive/
  unverified), host + base-URL inventory, WebSocket/GraphQL
  identification, Firebase/Supabase config detection,
  Retrofit/OkHttp/Ktor client evidence, NSC structured parse;
  emits endpoints.json, network-analysis.json,
  api-architecture.json.
- Dynamic observation stays guide + tshark/mitmproxy based;
  redaction guidance enforced in the module's pcap summary
  helper where implementable without a device.
- Acceptance: e2e case on a fixture with known endpoints +
  a planted-config synthetic fixture.

## Phase 6 — Runtime intelligence

- `scripts/nar-runtime.py`: adb adapter (discovery, device
  facts, package/process inspection, logcat capture),
  frida adapter (availability, version match, template
  runner in observe-only mode), behavior timeline builder
  (logcat text → timeline JSON schema).
- All device paths labeled `IMPLEMENTED_BUT_UNVERIFIED`
  (no device in this environment); offline paths (timeline
  from a recorded log, discovery with zero devices) are
  tested for real.
- Acceptance: unit tests for the timeline parser; e2e case
  for zero-device discovery behavior.

## Phase 7 — Security intelligence

- `scripts/nar-security.py`: findings engine over manifest,
  storage, crypto, and WebView evidence, emitting the brief
  §9.5 finding schema (id, title, severity, confidence,
  component, path, evidence, explanation, impact,
  reproduction, remediation, false-positive notes).
  References are never auto-promoted to vulnerabilities:
  crypto/string evidence lands as informational unless a
  concrete weak configuration is observed.
- Acceptance: e2e cases — a purpose-built fixture with known
  findings (debuggable/exported/no-NSC demo build) and a
  clean fixture with no high findings.

## Phase 8 — Comparison engine

Covered inside Phase 3 (nar-compare extension) and verified
against the demo pair + a cross-version fixture pair with
planted endpoint/asset changes.

## Phase 9 — Reporting

- Orchestrator output set: report.json + application.json,
  fingerprint.json, engine.json, dependencies.json,
  classes.json, methods.json, endpoints.json,
  permissions.json, security-findings.json, assets.json,
  comparison.json (compare mode), execution-log.json —
  each emitted when its data exists, each schema-validated.
- `scripts/nar-assets.py`: typed asset inventory (type by
  signature, size, hash, image dimensions from headers,
  duplicates, large assets) feeding assets.json.
- `scripts/nar-report.py`: offline single-file HTML
  dashboard (dark + light themes, search/filter/sort,
  expandable evidence, severity visualization, JSON/MD
  export buttons that work offline via embedded data).
- Acceptance: e2e case generating the dashboard from a real
  case directory and asserting section presence + offline
  (no external URLs) property.

## Phase 10 — Benchmarking

- `tests/benchmarks/` runner over the fixture corpus:
  format-detection accuracy, engine-detection accuracy,
  metadata accuracy, false-positive/negative rates for
  packer attribution, execution success rate, wall time.
  Results written to a local report with methodology +
  corpus limitations; numbers are measured, never invented.
  (Benchmark report is a local artifact; the methodology
  ships in the repo.)

## Phase 11 — Documentation and CI/CD

- SKILL.md 2.0: registry/case/CLI-aware routing, resume
  guidance; new references: architecture.md,
  tool-registry.md, output-schema.md,
  safety-and-authorization.md, troubleshooting.md.
- `pyproject.toml` (metadata + ruff/mypy/bandit/pytest
  config), `.github/workflows/ci.yml` (pytest, lint, schema
  validation, docs checks) — authored here, executed in CI;
  labeled as such in the QA report.
- README 2.0 identity block + compatibility matrix +
  install profiles in the doctor guide.
- Doctor gains installation profiles (minimal/standard/
  full/game/security) as grouped verdicts.

## Phase 12 — Final QA

- Full battery: unit tests, e2e harness, benchmark run,
  schema validation of every emitted file, docs-vs-CLI
  consistency check, banned-identifier grep, regression
  diff of 1.x script outputs on the fixture corpus.
- Version 2.0.0 in SKILL.md, skill.yaml, plugin.json,
  README; generic CHANGELOG 2.0.0 entry; release notes +
  QA summary in the final report to the parent agent.
- Local commits per phase; no push (parent reviews and
  pushes).

## Standing constraints (all phases)

- No application names, package names, file names, or
  identifying hashes of tested apps anywhere in the repo.
- Analysis-only boundary: no signature-kill, no paid/VIP
  unlocks, no currency grants, no DRM/license bypass, no
  credential theft — in code, guides, and examples.
- All scripts original to this workspace; external tools are
  orchestrated, never copied.
- Runtime/device features are labeled
  `IMPLEMENTED_BUT_UNVERIFIED` where no device exists.
