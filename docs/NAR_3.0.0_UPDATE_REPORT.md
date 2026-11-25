# NAR 3.0.0 Update Report

The 3.0 round: an explicit feature round ordered by the owner,
executed on branch `3.0.0` over the published 2.6.2 tree, one
commit per Part. Goal, in the brief's words: answer anything
about any app or game, with evidence — never a bare
"I don't know".

Status vocabulary used throughout: IMPLEMENTED / TESTED /
REAL-TARGET VERIFIED / SYNTHETIC-ONLY / NOT RUN /
NOT IMPLEMENTED. Nothing in this report upgrades a label: what
was not executed says NOT RUN and why. No app or game is named
anywhere in this report — real-target evidence is described by
shape and measured counts only; the identifying records stay in
the local audit trail, outside the repository.

**Publication state: NOT PUBLISHED.** This report records the
completed round and its acceptance results. Merge, tag, release
and any public-status change remain the owner's decision.

## Round summary

- New verbs: `ask`, `blueprint`, `atlas`, `anim`, `coverage`,
  `script`, `app` (dispatcher verbs 28 → 34); 21 engine deep-dive
  modules behind `nar-engines --deep`; a decompile stage inside
  `nar analyze`.
- New foundations: a shared container layer (splits merged by
  default), a single data registry (`scripts/formats.json`)
  driving detection, triage, analysis, graph and coverage, a
  failure-classification enum with fallback chains, and the
  Answer Contract as the Q&A layer's only output shape.
- Final battery (final tree, after the acceptance fixes):
  recorded in the last section of this report.

## Part 0 — The Contract

- **Defect:** answers could end at a bare unknown; no output
  shape forced evidence, confidence, or a named reason.
- **Fix:** the Answer Contract (ANSWER / EVIDENCE / CONFIDENCE /
  WHY / CHAIN / BOUNDARY, plus REASON / PROBE / COST when
  unknown) is the only output shape of `nar ask`, and the
  citation discipline of `nar blueprint` (every claim cited or
  marked inferred; evidence-free sections render
  NOT RECOVERABLE, never skipped).
- **Test:** contract-completeness and forbidden-phrasing pins in
  `tests/unit/test_ask.py` / `test_blueprint.py`; the acceptance
  checker scans every ANSWER field.
- **Measured:** Part 7 acceptance — 120 answers, 0 contract
  violations. Part 15 (below) — 1,445 answers, 0 bare unknowns.

## Part 1 — Coverage doctrine

- **Defect:** coverage claims lived in prose; nothing
  machine-readable enumerated what is unsupported, or why.
- **Fix:** `scripts/coverage.json`, generated from
  `scripts/formats.json`; `nar coverage [--gap]` enumerates
  every non-supported entry with reason + cheapest probe. The
  registry loader hard-fails on a `supported` entry without a
  test reference and on a non-supported entry without
  reason + probe.
- **Measured:** at round close the gap list holds **50 entries**
  (input types 7, engines 14, asset formats 1, script formats
  11, animation systems 5, app frameworks 11, protection kinds
  1), every one programmatically verified to carry a non-empty
  reason and probe (Part 13, item 2). The generated matrix is in
  `docs/NAR_COVERAGE_REPORT.md`.

## Part 2 — Input & container universe

- **Defect (verified by execution on 2.6.2):** containers were
  not opened by every module — `nar-assets` returned 0 assets
  on an XAPK, and splits were never merged, so a target whose
  libraries live in an ABI split reported
  `native_library_count: 0`.
- **Fix:** `scripts/narlib/container.py` — content-first
  container detection (APK/AAB/APKS/XAPK/APKM/OBB/plain-ZIP
  wrapper), one shared base-APK rule, `ResolvedTarget`
  {base, splits[], obbs[], assets_roots[], native_roots[]}
  consumed by every module; split merge is default-on with
  per-item `source_split` provenance, `splits_merged[]` /
  `split_skipped[]` (named reasons) in the case, nesting to
  depth 3, and duplicate detection across the set. All
  extraction stays inside the existing safearchive +
  ResourceBudget machinery. `--no-merge-splits` reproduces
  2.6.2 behaviour.
- **Test:** 19 container tests incl. a 3-level nesting fixture
  and hostile-container regressions from the stability
  campaign.
- **Measured:** retained real XAPK — assets 0 → 95 with
  per-split provenance, native libraries 0 → 18 (all in the
  config split); `--no-merge-splits` byte-identical to the
  2.6.2 baselines (6/6 empty diffs). Re-measured in Part 13 on
  a second real XAPK: 2,413 assets, 7 native libraries,
  `splits_merged` = 3 splits.

## Part 3.1 — Engine detection reads JNI symbols

- **Defect (verified):** `nar-engines` never read ELF exports;
  a Cocos-family build whose library carried a non-canonical
  name scored 10 / low / not detected on its DEX marker alone,
  regardless of its exported `Java_org_cocos2dx_lib_*` symbols.
- **Fix:** `jni_symbols` evidence — dynamic exports of every
  `lib/**/*.so` read through the existing `narlib/elf.py`,
  scored as direct evidence (JNI alone → medium; JNI + a
  corroborating marker → high; path marker alone → low),
  data-driven from the registry marker table.
- **Test:** 13 unit tests with hermetic byte-built ELF
  fixtures; a negative control (plain native app) never
  reaches high.
- **Measured:** the defect fixture goes 10/low/not-detected →
  medium on JNI alone, high with a DEX marker. No-regression
  sweep over 44 retained targets: 8 verdict changes, all
  JNI-attributable improvements, zero losses; the sweep caught
  one false-positive mechanism (an IL2CPP runtime library
  embedding `mono_*` exports), fixed with a documented
  exclusion and pinned by a test. Part 13 item 7 re-verified
  on a real split target: merged run detected:true / high,
  15 matched JNI symbols; the same tool on the bare base APK
  alone reports not-detected because that base carries zero
  native libraries (all live in the ABI split) — an artifact
  property, recorded as such.

## Part 3.2 — Engine deep dives breadth

- **Defect:** 21 of 26 engine families were `identified_only`
  with no deep-dive module (`"deep": None`).
- **Fix:** 21 deep-dive modules wired through the existing
  `nar-engines --deep` mechanism under one contract
  (ResolvedTarget scan, bounded reads, top-level `verdict`,
  exit 0 when absent): Cocos, libGDX, Defold, GameMaker,
  Ren'Py, Construct/Cordova, Capacitor, Solar2D, Heaps,
  LÖVE, Ebitengine, Bevy, Xamarin/.NET, MonoGame/FNA,
  Adobe AIR, Qt, embedded Python/Kivy, SDL, RPG Maker,
  web-assets, Unity-Mono — plus Unreal gap-fill (`.locres`
  string tables, Wwise bank facts).
- **Test:** 54 golden tests; every family raised above
  identified_only carries a fixture + golden output.
- **Measured:** 11 families reach `supported`, 10 reach
  `partial` with the boundary written into their registry
  reason (e.g. Xamarin held at partial by review: the default
  XALZ assembly store is not stdlib-decodable). Unreal
  `.locres` decode is REAL-TARGET VERIFIED: real samples
  reconcile exactly (largest: 482 namespaces / 4,806 entries /
  3,791 strings). Detection no-regression: corrected sweep
  over 43 targets, 0 verdict diffs. Most breadth families
  have no real local corpus — their layouts come from public
  format documentation and are SYNTHETIC-ONLY; each family's
  registry reason says so.

## Part 4 — Asset & animation universe

- **Defect (verified):** the asset extension table missed 27
  brief-listed extensions; support for Spine, DragonBones,
  Lottie, Rive, Aseprite and SpriteAtlas was zero; no
  composition answer existed for "how is X animated?".
- **Fix:** `nar atlas` and `nar anim` verbs; compressed-texture
  header decode (ASTC/KTX/KTX2/PVR/DDS/ETC — dimensions, block
  geometry, mip counts; headers only, never pixel decoding);
  atlas parsers (Cocos XML + binary plist, libGDX, TexturePacker,
  Starling/Phaser, Godot AtlasTexture, Unity SpriteAtlas at its
  honest fidelity) emitting frames[] / frame_count /
  packed_area / rotated_count with generalised part grouping
  and inferred composition labels; animation-system parsers
  (Spine JSON decoded, `.skel` header-level; DragonBones,
  Lottie, Aseprite, Godot AnimationPlayer, Spriter, Creature
  decoded; Rive header-level; Unity Animator textual for loose
  files, identified-only in bundles; Cocos `.ccb` decoded,
  `.csb` identified-only); physics-rig detection requiring both
  a symbol cluster and part naming; the Composition Report
  (parts → naming pattern → attachment points → driver →
  evidence → confidence), discovered generally, never
  hardcoded to a target. Wwise bank headers, video
  codec/profile facts, font glyph/name facts and model counts
  added at header level.
- **Test:** 73 new tests across textures/media, atlas, anim
  and the ask integration.
- **Measured (real container target):** 30 atlases, 672
  frames, 41 particle systems; cross-checked against the raw
  member inventory — the target ships exactly 71 plist
  members, parser reach 71/71. **The brief's numeric
  thresholds (≥ 40 atlases / ≥ 2,000 frames) are NOT MET:
  this build simply ships fewer, and the code was not tuned
  to the number.** The vehicle composition case holds
  (vehicle, inferred, with chassis/wheel-role frames named
  exactly as in the plist). The same target ships no
  animation-system files and its game library is stripped, so
  `nar anim` claims 0 systems and 0 physics rigs and states
  the limitation — the honesty path working as designed.

## Part 5 — Script & bytecode universe

- **Defect (verified):** beyond DEX, no structural parsers
  existed for Lua, GDScript, Wasm or `.pyc`; Hermes and .NET
  had partial implementations that nothing wired together.
- **Fix:** `nar script` verb + `scripts/narlib/scriptparse.py`:
  Lua/LuaJIT chunk walk, GDScript GDSC walk, Wasm full
  structural parse, `.pyc` structural marshal census (never
  executes, never `marshal.loads`), JavaScript bundle census,
  AngelScript/Squirrel/Pawn identification with counts,
  custom-VM bytecode detected + named, never decoded. Hermes
  counts are wired from the existing React Native parser and
  Dart facts from the existing Flutter parser — wiring and
  generalisation, not recreation. Undecoded bytecode is never
  presented as source.
- **Test:** 38 tests; fixtures produced honestly per format
  (a real `.pyc` compiled in-test, a real `.wasm` built with
  a local WABT toolchain, hand-constructed Lua/GDScript
  streams from the documented layouts where no compiler
  exists on this machine — stated in the test docstrings).
- **Measured:** Wasm reaches `supported` (every count asserted
  exactly on the toolchain-built module). On retained real
  fixtures the wired counts are identical to the source
  parsers' own output (Hermes bundle: bytecode version 98,
  20,566 functions, 164,372 strings; Dart: VM 3.12.2 /
  Flutter 3.44.8, counts null by design with the reason
  stated). Hostile `.pyc` streams (tuple-count bomb, nesting
  bomb) are refused with named failures in < 5 s, no
  execution.

## Part 6 — Non-game app universe

- **Defect (verified):** app frameworks were marker-only in
  triage; no SQLite parser existed anywhere; no app-level
  screen, storage or auth intelligence existed.
- **Fix:** `nar app` verb + an `app.json` case companion +
  `scripts/narlib/sqlite.py` (read-only sqlite_master byte
  parser; never writes, never opens a target database with
  the sqlite3 module): Compose `@Composable` census, layout
  roots, WebView JS-bridge surface, Activity/Fragment graph +
  deep-link route map, SharedPreferences candidates,
  Room/SQLite schemas of shipped databases, encrypted-storage
  detection (named, never decrypted), OAuth + JWT structure
  only (claim names, never values; a scrub pass plus a
  planted-token leak scan), background-work inventory,
  declared-vs-referenced permission over-request report, SDK
  inventory with versions from `META-INF/*.version`, and a
  compliance surface — emitted as an evidence-cited
  screen/module map and data-flow map, consumed by `nar ask`
  and `nar blueprint`.
- **Test:** 21 tests incl. the JWT leak scan (planted token
  appears in zero outputs across app/ask/blueprint) and a
  real sqlite3-built fixture database read exactly.
- **Measured (real targets, local):** a native utility
  container — 33,838 DEX classes, 89 activities, 373 layouts,
  200 screen-map entries, 52 data-flow edges, 23 declared
  permissions / 15 over-request candidates; a commercial
  hybrid container — 273 layouts, 2 `addJavascriptInterface`
  call sites, 11 `@JavascriptInterface` methods, SDK versions
  read from shipped `.version` files. **No local target ships
  a database member** (all non-game corpus targets and every
  retained-fixture archive inventoried, incl. nested APKs:
  0 found) — the real-asset-database leg is measured
  NOT FOUND; the parser is synthetic-fixture-verified only.
- **Measured limitation (final group):** the Compose census
  reads DEX annotation directories. On a genuinely
  Compose-architected real target (full Compose library
  stack, composable-shaped method signatures) the census
  returns 0, independently verified with a full third-party
  decompilation: that build's DEX annotation directories
  carry no `@Composable` annotations. The census is exact
  for what it reads; composable functions whose annotations
  are not DEX-visible are outside its reach. Recorded for
  the owner; the census was not redesigned mid-acceptance.

## Part 7 — The Q&A layer (`nar ask`)

- **Defect:** no Q&A layer existed; knowledge was spread
  across tool outputs with no answer discipline.
- **Fix:** `nar ask "<question>" <target> [--json] [--case
  DIR]` — deterministic keyword+structural intent
  classification (14 intents; no LLM, no network), evidence
  gathered only from the modules the intent needs, case
  cache reused, every answer assembled in the Part 0
  contract. `references/question-library.json` holds 289
  canonical questions, each mapped to its serving modules;
  a test asserts every library question maps to ≥ 1 module
  and its recorded intent matches the classifier.
- **Test:** 26 unit tests at landing (schema/intent parity
  extended in the final group, below).
- **Measured:** brief acceptance — 40 canonical questions ×
  3 fixtures (engine game, native app, hybrid app): 120
  answers, 0 checker problems; the 3 unknowns were true
  absences (no settings-named activity in any fixture),
  each with REASON + PROBE + COST. An in-cycle defect —
  storage evidence living in DEX superclasses that a
  name-only scan missed — was found by the acceptance run,
  fixed, and the corpus re-run clean. The full-library run
  is Part 15, below.

## Part 8 — The rebuild layer (`nar blueprint`)

- **Defect:** no rebuild-specification layer existed;
  rebuild answers had no evidence-cited emitter.
- **Fix:** `nar blueprint <target> --out spec/` emits the 9
  files (features, architecture, data-model, flows, assets,
  network, build-order, unrecoverable, unknowns) from
  verified case evidence only; every feature claim carries a
  machine-checkable citation or an `inferred` marker; the
  Part 0.3 boundary line appears verbatim exactly once per
  spec; network values are redacted; `unknowns.json`
  validates against `schemas/blueprint.schema.json`.
- **Test:** 18 tests incl. NOT RECOVERABLE rendering on
  constructed evidence-free cases and a planted-secret scan.
- **Measured:** fixture — 9 files, 48 feature bullets,
  0 uncited; real container target — 9 files, 51 bullets,
  0 uncited, network leak scan 0 unredacted values,
  `unrecoverable.md` spot-checked exact against the case
  companions (including stating a category's absence rather
  than inventing an instance). An in-cycle crash on
  malformed harvested URLs was fixed with a regression test.

## Part 9 — Knowledge base

- **Defect:** the registry claimed support with no knowledge
  base behind it.
- **Fix:** 26 per-family engine guides under
  `references/engines/` (packaging, serialisation, common
  protections, rebuild pitfalls) plus asset-formats,
  animation-systems, script-formats, app-patterns,
  protection-playbook, rebuild-playbook and glossary guides.
- **Test:** a docs-consistency guard pins that every
  registry entry claiming `supported` (114/114) has its
  guide section showing a real command producing a real
  output shape.

## Part 10 — Cross-platform & CI

- **Defect (verified):** the doctor resolved only `python3`
  (line 171), so on a python-only system (stock Windows) the
  core self-checks reported missing and `core_ok` was false
  with a working Python present.
- **Fix:** interpreter resolution `$NAR_PYTHON → python3 →
  python → py -3`, each candidate probed and required
  ≥ 3.10, the resolved binary used for every internal
  self-check, `python_resolved` added to `--json`; MSYS /
  Git-Bash portability fixes; CI matrix prepared in-tree
  (ubuntu/windows/macos × doctor, unit, CLI smoke, public
  e2e; Windows uses `python`), applied via the web UI at
  publication as before.
- **Test:** 6 regression-guard tests, incl. one that fires
  on the literal pre-fix line.
- **Measured:** Linux `--json` identical to 2.6.2 modulo
  `python_resolved`, human output byte-identical. PATH
  simulations prove both sides: python-only shim → new
  doctor `core_ok: true` with both self-checks ok, the
  2.6.2 doctor under the identical shim reproduces
  `core_ok: false`; too-old-python and `py`-only branches
  also verified. **Windows and macOS real execution:
  NOT RUN** (no such hosts here; the hosted CI run at
  publication is the proof).

## Part 10.5 — Failure tolerance & fallback chains

- **Defect (verified):** the DEX adapter took one tool and
  returned an error on failure — a failing jadx meant no
  Java code at all — and `nar analyze` never ran
  decompilation.
- **Fix:** `scripts/narlib/failures.py` (one 11-name
  classification enum used everywhere; free-form failure
  strings forbidden in new paths) and `scripts/narlib/
  chains.py` (ordered fallback chains emitting the brief's
  Fallback Record: attempts with classified reasons,
  served_by, the fidelity ladder — a lower-fidelity result
  is never presented as higher — and bounded one-shot
  self-repair for OOM/TIMEOUT; nothing is ever downloaded
  or installed). The decompilation chain (jadx → baksmali →
  dex2jar+cfr → dex2jar+procyon → built-in disassembler) is
  wired into `nar analyze` as a cached stage; the
  pre-existing jadx PARTIAL behaviour (exit 1 + errors
  marker → use the output, record the error count) is wired
  in, not reimplemented. The remaining capability chains
  are declared in the chain registry with only genuinely
  existing rungs.
- **Test:** 25 tests incl. the kill-switch and broken-JDK
  acceptances and enum-exactness.
- **Measured:** kill-switch (PATH stripped of the external
  tools) — complete case, decompile served by the built-in
  disassembler at bytecode-listing fidelity, every failure
  enum-classified; broken-JDK — 0.90 s, served by baksmali.
  Re-verified on a real container target in Part 13 item 8
  (served_by the built-in disassembler; NOT_INSTALLED × 8,
  zero unclassified). The dex2jar+cfr / dex2jar+procyon
  rungs are NOT RUN (tools absent here; they record
  NOT_INSTALLED with an install hint).

## Part 11 — Performance & size

- **Defect (verified, and larger than the brief's figure):**
  on the largest retained fixture (273 MB input) the 2.6.2
  `dex.json` companion measured **390,522,756 B** — 1.43×
  the input.
- **Fix:** compact DEX shape by default (per-method rows
  de-duplicated against the method table; class→method as
  index arrays), streaming writers for every large
  companion, and `nar analyze --budget-mb N` aborting at a
  named, resumable boundary instead of an OOM kill.
- **Measured:** `dex.json` 390,522,756 → **153,375,252 B**
  (−60.7%); nar-dex peak RSS 1,583,865,856 →
  1,000,869,888 B (−36.8%); `--full` restores the 2.6.2
  shape byte-identically; graph.json / investigation.json
  byte-identical across shapes; a budget-aborted run resumes
  to a complete, verified case. Recorded in
  `tests/benchmarks/baseline-3.0.0.json`. The full benchmark
  matrix (all roles) was NOT RUN for the baseline; the
  module timings and the headline memory measurement were.
  Whole-analyze peak on the largest target remains dominated
  by the decompile stage's JVM on this machine class; the
  orchestrator's own peak measured 590,151,680 B, and a
  fully-cached re-run's subtree peak (1,194,188,800 B) sits
  below the 2.6.2 headline figure.

## Part 12 — Schemas & docs

- **Fix:** new schemas — atlas, animation, coverage,
  blueprint, ask, composition, question, fallback-chain
  (38 total); the capability matrix gains a
  one-row-per-coverage-entry appendix (177 entries)
  generated from coverage.json; SKILL.md routing covers
  every new verb; `references/example-prompts.md` extended
  with the new verbs.
- **Measured:** docs-consistency guards green (structure
  block, guide pinning, coverage appendix freshness,
  credit-line placement).

## Part 13 — Verification protocol (executed by the final group)

Run on the brief's audit target — a real Cocos-family split
container held locally (named only in the local audit trail).

| # | Item | Result |
|---|---|---|
| 1 | Doctor on Linux | PASS — exit 0, Core toolchain READY, 22/22 checks ok, `python_resolved` reported. Windows/Git Bash leg NOT RUN (no host); the Part 10 PATH-simulation evidence stands in, labelled simulation |
| 2 | `nar coverage --gap` | PASS — 50 entries; programmatic check: every entry carries a non-empty reason and probe, 0 missing |
| 3 | `nar analyze` on the audit container | PASS — exit 0; native_library_count 7; splits_merged 3; total assets 2,413; all 14 stages ok; decompile served by jadx PARTIAL at source-approximate fidelity |
| 4 | `nar ask "how is the car animated?"` | PASS — full Answer Contract; composition content present (30 atlases, 672 frames, 41 particle systems, 94 compositions; the vehicle group at inferred confidence) |
| 5 | `nar ask "what can you not tell me?"` | PASS — named gaps enumerated: 50 coverage entries across 7 sections with reason + probe, 3 investigation unknowns, 3 report limitations |
| 6 | `nar blueprint` | PASS — exactly 9 files; features.md 52 bullets, 0 uncited; unknowns.json 22 entries |
| 7 | `nar engines --deep` | PASS on the merged target — Cocos family detected:true / high, 15 matched JNI symbols, deep dive confirmed. On the bare base APK alone: not detected, because that base carries zero native libraries (all 7 live in the ABI split) — artifact property, not a defect |
| 8 | Kill-switch run | PASS — stripped PATH (python3 + java + core utilities only): analyze exit 0, complete case, verify OK; decompile served by the built-in disassembler at bytecode-listing fidelity; failure classifications NOT_INSTALLED × 8, zero unclassified |
| 9 | pytest + public e2e | PASS — recorded in the final battery below |
| 10 | DEX size + peak RSS | CITED from Part 11 (not re-measured; no fix in this group touched the DEX path): dex.json 390,522,756 → 153,375,252 B; nar-dex peak RSS 1,583,865,856 → 1,000,869,888 B |
| 11 | `nar case verify` | PASS on both cases built for this protocol (audit case: 19 companions, 76,033 evidence references resolve; kill-switch case: 76,032 resolve) |

## Part 14 — Non-goals (held)

Analysis only: no app modification, patching, repackaging,
signature bypass, IAP manipulation, currency granting, or DRM
circumvention — verified by the standing guard tests and the
round's own reviews. `dependencies = []` unchanged (pyproject).
No LLM/API call at runtime; `nar ask` is deterministic. No
emulator or device requirement in the static path. The 1.x
compatibility surface is unchanged (Part 2's byte-identity
proofs; the stability campaign's era handling untouched).

## Part 15 — Final acceptance (executed by the final group)

The entire 289-question library was run through `nar ask`
against five lawfully held targets of different shapes, with
an automated checker over every answer. Per-target results:

| Target shape | Case verify | Bare unknowns | Contract blocks | Non-unknown EVIDENCE | Unknown REASON+PROBE+COST | Blueprint (9 files, citations) |
|---|---|---|---|---|---|---|
| Engine game (Unreal fixture) | PASS | 0 | PASS (after the fix below) | 100% | PASS | PASS (48 bullets, 0 uncited) |
| Native app (retained fixture) | PASS | 0 | PASS | 100% | PASS | PASS (43, 0 uncited) |
| Hybrid app (React Native fixture) | PASS | 0 | PASS | 100% | PASS | PASS (47, 0 uncited) |
| Legacy app (DEX 035, minSdk 19) | PASS | 0 | PASS | 100% | PASS | PASS (10, 0 uncited) |
| Modern app (substitution — see below) | PASS | 0 | PASS | 100% | PASS | PASS (51, 0 uncited) |

- **Totals:** 1,445 answers; confidence split across targets —
  confirmed 474, strongly-indicated 478, inferred 273,
  unknown 220. Every unknown is contract-complete.
- **Unknowns:** all 220 carry reason `absent` (the artifact
  genuinely lacks the asked-about thing); `encrypted`,
  `unsupported-codec`, `server-side`, `stripped` × 0. The 12
  compare-intent questions per target (60 total) were run
  verbatim against the single target and are contract-PASS as
  unknown + `absent` (a comparison needs a second artifact),
  counted separately. Coverage cross-check: the capability-gap
  unknown set is empty, so unknowns mapping to no
  `coverage --gap` entry = 0.
- **Defect found and fixed in this cycle:** exactly 3 answers
  (the three script questions on the engine-game target)
  failed validation — the classifier's first-class `scripts`
  intent was missing from the answer schema's intent enum, so
  scripts answers failed the repository's own schema. Fixed
  (schema enum + two regression tests pinning enum parity and
  scripts-answer validation); the affected questions were
  re-executed and the target's full check re-run clean
  (failures 3 → 0) before the remaining targets ran.
- **The Compose shape — substitution, stated plainly:** the
  fifth slot asks for a modern Compose app. Neither local
  candidate produces a genuine `@Composable` census > 0 under
  the Part 6 census: the retained Compose-architected fixture
  (full Compose library stack, verified independently — see
  Part 6's measured limitation) and a modern corpus app's
  base both census 0. The protocol's substitution branch was
  followed: the fifth target is the modern corpus app's base
  (5 DEX, 33,838 classes, 373 layouts), run in full and
  **not labelled Compose anywhere**. The acceptance criteria
  pass on it; the shape qualification is this paragraph, not
  a relabel.

## Part 16 — Generality & extensibility

- **Fix:** `scripts/formats.json` is the single source of
  truth (7 sections, 177 coverage entries at close);
  detection, triage, analysis, graph and coverage all read
  it — adding an engine or format is one registry row + one
  deep module + one fixture, no duplicated marker lists in
  Python (grep-pinned).
- **Test:** the generality test injects a synthetic engine
  row + fixture and asserts detection, triage, coverage and
  a complete analysis case with zero code changes, and that
  removing the row removes it everywhere (5/5 assertions).
  `tests/unit/test_no_hardcoded_targets.py` greps scripts/
  and references/ for real package/game identifiers — zero
  hits. Per-entry fidelity is declared in the registry and
  `nar ask` never claims above it.

## Part 17 — Delivery

- One commit per Part on branch `3.0.0`, each naming the
  defect and its pinning test; two further commits from the
  final group (the Part 15 schema fix, the sweep's ask fix —
  below) and this close-out.
- Deliverables: this report; `scripts/formats.json` +
  `scripts/coverage.json`; `docs/NAR_COVERAGE_REPORT.md`
  (generated from the coverage commands on the final tree);
  updated README block, SKILL.md routing, capability matrix,
  CHANGELOG. `dependencies = []` unchanged.

## Final-group corpus sweep (real targets, local evidence)

The full pipeline (analyze + case verify; engines, atlas,
anim, script, app spot outputs; three `nar ask` questions per
target including one animation and one gaps question) ran
serially over 12 real targets held locally — games and apps
of diverse shapes, 31 MB to 1.48 GB, plain APKs and split
containers. **12 of 12 completed end-to-end** (analyze exit 0,
verify OK, all spot verbs exit 0, 36/36 ask answers
contract-complete, zero forbidden bare-unknown phrases).
Headline range across the sweep: assets 92 → 44,728 per
target; atlases up to 5,710 (9,641 frames); Spine systems
decoded on four targets; one target's 68 animation records
all identified-only (its format is not decoded — stated, not
upgraded).

- **Defect found and fixed in this cycle:** the ask
  animation answer unconditionally led with "Animation
  systems decoded by nar-anim" and a WHY claiming decoding,
  even when every system was identified_only — contradicting
  the same answer's per-system status and its own BOUNDARY.
  Fixed to a status-accurate lead with regression test; the
  affected target's answer re-run ("identified by nar-anim
  (none decoded)").
- **Findings recorded (target properties, not defects):**
  one shooter's IL2CPP stage reports `degraded` because the
  metadata/library pair is split across base + ABI split —
  the merged-container evidence still covers it (engines
  high, the split's library inventoried) and the case
  verifies; `native_library_count` is present on the merged
  path and absent on the single-archive path (documented
  pre-3.0 byte-identical behaviour; counts agree everywhere);
  three targets honestly produce no engine verdict (two ship
  zero native libraries — verified by direct archive
  listing); one Unreal target's loose-asset count reflects
  pak-packed content, not missing inventory.
- **Infrastructure interruptions, recorded:** a driver
  SIGTERM during one target's verify phase and a transient
  storage write-failure window during another's analyze —
  both recovered through the stage cache on resume and
  completed fully; neither is a product defect.

## NOT RUN / limits

- Windows and macOS real execution (doctor + CI legs):
  NOT RUN at the time of writing — no such hosts; PATH
  simulations cover the Windows defect class, and the
  hosted CI run at publication is the proof.
  **Superseded by the post-publication addendum at the end
  of this report: hosted runs #39–#42 executed the full
  matrix for real; run #42 is fully green.**
- Physical-device runtime validation: NOT RUN — no device
  attached (standing label since 2.6.2; the owner's checklist
  stands).
- Accuracy: NOT MEASURED for the new JNI channel, the script
  formats, and the app-intelligence areas — no labeled
  corpora exist for them; the sweeps recorded are verdict
  diffs and contract checks, not accuracy measurements. The
  2.6.2 labeled-corpus figures stand for the areas they
  measured.
- Part 4 numeric thresholds (≥ 40 atlases / ≥ 2,000 frames
  on the audit target): NOT MET — measured 30 / 672 with
  parser reach 71/71 over the target's plist members; the
  build ships fewer. Reported, not tuned for.
- Real-app SQLite database parse: NOT RUN — no local target
  ships a database member (measured across all local
  targets); the parser is synthetic-fixture-verified.
- Compose census on release builds: measured limitation
  (Part 6) — a genuinely Compose-architected target censuses
  0 because its DEX annotation directories carry no
  `@Composable` annotations.
- dex2jar+cfr / dex2jar+procyon chain rungs: NOT RUN —
  tools absent here; the rungs record NOT_INSTALLED with an
  install hint.
- Full benchmark matrix for baseline-3.0.0.json: NOT RUN —
  module timings and the headline memory measurement were
  run and recorded in the baseline itself.
- Carried limits from earlier rounds, unchanged: CDEX
  payload not decoded; Kotlin d1 not interpreted; Unity
  serialized-object/TypeTree parsing and LZ4 bundle decoding
  out of stdlib scope; Unreal tag-extension layouts 1011 /
  1012+ synthetic-verified only; Zen pre-5.3/EA layouts
  synthetic-only; Oodle refused by name; endpoint
  classification accuracy (real) NOT MEASURED.

## Definition of Done (brief Part 17.3), as measured

1. **Part 15 passes on five targets** — PASS, with the
   Compose-shape substitution recorded in the Part 15
   section (all acceptance criteria pass on the five
   targets run; no local target yields a genuine
   `@Composable` census, measured).
2. **Part 10.5 kill-switch passes** — PASS (Part 13 item 8).
3. **Part 16 generality test passes** — PASS (5/5
   assertions, in the unit suite).
4. **`nar doctor` is honest on Windows/Linux/macOS** —
   Linux PASS (executed, Part 13 item 1); Windows/macOS
   NOT RUN (no hosts) with the Windows defect class proven
   by simulation — this item is therefore PARTIAL as
   measured, and stays so until the hosted CI run at
   publication.
5. **`nar coverage --gap` enumerates every gap with reason
   + probe** — PASS (50 entries, programmatically verified).
6. **No hardcoded target names; no silent truncation; no
   invented figures** — PASS (guard test in the suite;
   unmet thresholds reported as unmet).
7. **`dependencies = []`; 1.x CLIs unchanged** — PASS
   (pyproject; byte-identity proofs in Part 2).

## Final battery (final tree)

Run by the final group on the closing tree (after both
in-cycle acceptance fixes):

- `pytest tests/ -q`: **971 passed, 1 skipped, 12 subtests
  passed**, 0 failed (the 1 skip is the designed ask
  blueprint-fallback skip). The count reconciles exactly:
  968 at the version bump + 2 regression tests from the
  Part 15 schema fix + 1 from the sweep's ask fix.
- `bash tests/run_e2e.sh` (private fixtures): **68 passed,
  0 failed, 0 skipped**.
- `bash tests/run_e2e.sh` (public mode): **15 passed,
  0 failed, 48 skipped** (fixture-bound cases skip by
  design in public mode).
- `nar doctor`: **Core toolchain: READY**, exit 0.
- Credit line: exactly once in the tree (README Author
  section), enforced by the docs-consistency guard in the
  suite above.
- Version: every guarded location reads the single value
  **3.0.0**; `nar version` prints "NAR 3.0.0".
- No-hardcoded-targets guard: in the suite, green.

The branch is left clean at the close-out commit. Nothing
has been pushed, merged, tagged or released.


## Post-publication addendum (2026-11-26) — hosted CI proof

At publication the Windows/macOS legs were NOT RUN locally
(DoD item 4 PARTIAL). The hosted runs then executed the
full matrix for real, and every failure they exposed was
fixed on `main` in the same cycle (stability rules; the
v3.0.0 tag itself is unchanged and predates these fixes):

- Run #39 (the 3.0.0 tree): Linux and macOS legs all PASS;
  three Windows legs failed (doctor, unit, e2e-public) —
  bare-`bash` dispatch hitting the WSL stub, normalised
  instead of raw hostile archive names in reports, an
  import-time `resource` crash, Windows RSS and probe gaps.
- Fix round 1 (7 commits): Git Bash discovery in the CLI
  dispatcher, raw-name report keying, guarded imports,
  ctypes RSS, PATHEXT probing, explicit directory checks.
  Run #40: doctor and e2e-public Windows legs PASS; unit
  (Windows) down to 9 failures.
- Fix round 2 (3 commits): the remaining 9 were five
  fixture-truthfulness defects (Python's zipfile sanitises
  hostile names at write time on Windows, so the stored
  names were never the asserted ones), three tests invoking
  bare `bash`, one environment-dependent expectation, and
  one real product bug — the win32 RSS ctypes prototypes
  truncated the 64-bit process handle, so the memory budget
  never engaged on Windows. Run #41: unit (Windows) PASS;
  one new failure in security-regression (Ubuntu) — the
  doctor-compile test's own bash-resolution import polluted
  its pycache snapshot on cold-cache subset runs.
- Snapshot fix (1 commit): resolve bash before the
  snapshot. **Run #42: FULLY GREEN — all 17 jobs PASS
  (syntax, schema, fuzz, benchmark and docs smokes,
  security-regression, and cli-smoke / doctor / e2e-public
  / unit on Linux, macOS and Windows).**

DoD item 4 therefore closes as PASS by hosted execution.
Physical-device runtime validation remains NOT RUN (the
owner's device; the standing checklist applies). Local
battery on the final tree: pytest 1007 passed / 1 skipped,
e2e 68/68 private + 15/0/48 public, doctor READY.

On the owner's decision (2026-11-26) these fixes shipped
as the patch release **3.0.1** (tag v3.0.1); the
3.0.1 tree is the final tree measured above.
