# NAR Implementation Plan — 2.0 program

Execution order follows the brief's 12 phases. Each phase ends
with: new/updated tests green, the full e2e harness green, and
a local commit. Statuses are updated as phases land.

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
