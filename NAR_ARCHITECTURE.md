# NAR Architecture — 2.0

> Inventory addendum (2.5.2 W6, 2026-11-24): the design
> below is the 2.0 architecture, unchanged in shape. The
> module, schema, registry, and CLI inventories in this
> document were re-audited against the shipped 2.5.1 tree
> (plus the 2.5.2 workstreams W1–W5) and corrected in
> place: the `narlib` list now names all 18 modules, the
> schema count is 24, the registry count is 35 tools /
> (2.6.0 Phases 3–8 addendum: narlib grows to 21 modules —
> `cdex.py`, `graph.py`, `investigation.py` — and schemas
> to 26 with `graph.schema.json` and
> `investigation.schema.json`; the benchmark/coverage
> record is `tests/benchmarks/baseline-2.6.0.json` and the
> dashboard gained graph/investigation sections in
> Phase 12.)
> 9 unavailable, and the runtime subsystem also persists
> structured session records (`runtime-session.json`,
> Evolution Phase 6). The per-capability status record
> lives in `NAR_CAPABILITY_MATRIX.md`.

NAR 2.0 keeps the 1.x layout that works (standalone scripts in
`scripts/`, guides in `references/`, the repo root as the skill)
and adds a shared core plus new intelligence modules beside the
existing scripts. Nothing working is moved or renamed: every
1.1.0 command line keeps working unchanged (brief rules 3, 4, 7).

## Layers

```
                ┌────────────────────────────────────────────┐
   Agent / user │  SKILL.md routing  ·  unified CLI (nar.py) │
                └───────────────┬────────────────────────────┘
                                │
                ┌───────────────▼────────────────────────────┐
   Orchestration│  nar-analyze.py 2.0: planner over the tool │
                │  registry, case workspace, stage cache,    │
                │  execution log, report assembly            │
                └───────────────┬────────────────────────────┘
        ┌───────────────┬───────┴────────┬───────────────────┐
        ▼               ▼                ▼                   ▼
  Input + identity  Intelligence    Engine adapters     Reporting
  nar-input.py      nar-dex.py      nar-il2cpp.py (1.x) nar-report.py
  nar-fingerprint   nar-native.py   nar-unity.py        (HTML + JSON
  nar-triage.py     nar-network.py  nar-unreal.py        companions)
  (1.x, unchanged)  nar-security.py nar-flutter.py (1.x)
                    nar-assets.py   nar-godot.py (1.x)
                    nar-compare.py  nar-rn.py (1.x)
                    (1.x, extended) nar-pak.py (1.x)
                                │
                ┌───────────────▼────────────────────────────┐
   Core (new)   │  scripts/narlib/: input detection, safe    │
                │  archive handling, evidence schema, tool   │
                │  registry access, DEX/ELF primitives       │
                └───────────────┬────────────────────────────┘
                                ▼
   External tools (orchestrated, never copied): apktool, jadx,
   aapt2, apksigner, bundletool, baksmali/smali, Il2CppDumper,
   Cpp2IL, hermes-dec, GodotPckTool, GDRE, Ghidra, Kuna,
   readelf/nm/objdump, mitmproxy, tshark, adb, frida — each
   declared in scripts/registry.json with version checks and
   limitations (35 tools declared; 9 registered unavailable).
```

## Core library (`scripts/narlib/`)

New 2.0 code shares one package instead of a twelfth copy of
each helper (audit debt #17). The 1.x scripts stay standalone
on purpose: they are the compatibility surface and are imported
by nothing.

- `narlib/__init__.py` — version, shared constants.
- `narlib/hashing.py` — streaming SHA-256 (moved pattern from
  the 1.x scripts).
- `narlib/formats.py` — magic-byte + structural format
  identification for the brief §3.1 input list.
- `narlib/budget.py` — the ResourceBudget abstraction
  (2.6.2): validated archive/resource limits (entries,
  per-file and total bytes, per-entry and total ratios,
  nesting depth, elapsed seconds) shared by the
  extraction paths; invalid overrides raise a named
  BudgetError.
- `narlib/safearchive.py` — extraction with zip-slip, path
  traversal, symlink, bomb-ratio, nesting-depth, and
  total-size guards; every rejection is reported, never silent.
- `narlib/evidence.py` — the common result/finding schema
  (source, module, tool + version, evidence location,
  timestamp, confidence, status; fact class:
  observed/derived/inferred/hypothesis/unknown) and a stdlib
  structural validator for the schemas in `schemas/`.
- `narlib/registry.py` — loads `scripts/registry.json`,
  resolves tool paths using the same discovery rules as
  `nar-doctor.sh`, verifies versions before execution.
- `narlib/dex.py` — DEX parser primitives (header, string/type/
  proto/field/method tables, class defs, code-item scan for
  invoke/reflection/native evidence) with streaming bounds.
  Since 2.6.0 Phase 3 it also assembles the resolved
  call graph (`assemble_call_graph()`: defined-method nodes,
  invoke edges resolved within one DEX or across an APK's
  DEX set, external targets counted with a capped sample;
  per-method cross-reference via `nar-dex --xref`), Kotlin
  `@Metadata` d2 cross-checks against the DEX type table, and
  identifier-shape obfuscation indicators (confidence-labeled,
  never a binary verdict).
- `narlib/dexdis.py` — DEX bytecode disassembler (instruction
  listings with operands resolved through the DEX's own tables,
  plus a control-flow block summary; since 2.6.0 Phase 3 also
  `control_flow_graph()` / `cfg_batch()`: per-method CFG edges
  typed fallthrough / branch / switch / goto / return-exit /
  try-handler, exposed as `nar-dex --cfg`).
- `narlib/cdex.py` — compact-DEX (CDEX) header + section-table
  parser (2.6.0 Phase 3, R-002): parses the 136-byte header and
  six-entry section table per the public AOSP layout and
  reports `payload_decoded: False` — string contents and the
  compact payload are not decoded. Wired into
  `narlib/formats.py` identification and `narlib/oat.py`
  carving.
- `narlib/graph.py` — unified application intelligence graph
  (2.6.0 Phase 7, R-008): builds the `graph.json` case
  companion (14 node kinds, edge kinds with provenance,
  evidence references and source-derived confidence) from the
  stage documents + correlations; since 2.6.1 the analyze
  report's Unreal package relationship records join as
  unreal_package / unreal_object nodes with unreal_* edges;
  queried via `nar case graph`.
- `narlib/investigation.py` — deterministic offline
  investigation layer (2.6.0 Phase 8, R-009): builds the
  `investigation.json` companion (verified facts / ranked
  rule paths / hypotheses / unknowns, kept separate) with no
  external calls; viewed via `nar case investigation`;
  disableable via `--no-investigation` / `--no-graph` and the
  `NAR_NO_*` / `NAR_DISABLE_*` env switches, as is the graph
  layer.
- `narlib/elf.py` — ELF parser primitives (headers, sections,
  segments, dynamic table, symbol tables, relocations) for
  ELF32/64 on all four Android architectures.
- `narlib/dotnetmeta.py` — ECMA-335-lite reader for Cpp2IL
  dummy-DLL output (TypeDef / MethodDef counts, namespaces).
- `narlib/oat.py` — ART compiled-artifact parser (OAT header +
  key-value store, VDEX fields + DEX carving, Dalvik ODEX,
  ART image header; CDEX payloads identified, not decoded).
- `narlib/iostore.py` — Unreal IoStore (UTOC/UCAS) parser:
  TOC versions 0–10, classic + pooled directory-index layouts,
  chunk inventory, None/Zlib extraction; owns the module's
  `capabilities()` facts.
- `narlib/uasset.py` — classic Unreal package parser
  (FPackageFileSummary, name/import/export/depends tables,
  best-effort property tags incl. the UE5 1011 / 1012+
  tag-extension layouts); owns its `capabilities()` facts.
- `narlib/zen.py` — Unreal Zen package parser (current,
  pre-5.3 and Early Access layouts); owns its
  `capabilities()` facts.
- `narlib/signatures.py` — validating loader for the
  versioned protection-signature database
  (`scripts/protection-signatures.json`).
- `narlib/companions.py` — brief-named case companion
  projections (application / manifest / native-inventory /
  frameworks / network-analysis / api-architecture),
  schema-validated before writing.
- `narlib/correlations.py` — cross-module correlation
  records (DEX/ELF/manifest/network joins) for the
  `correlations.json` companion.
- `narlib/mmapio.py` — read-only file mapping (`mmap`)
  helper so the parsers can run over large files without
  whole-file reads (added in 2.5.2).

## Data flow (one analysis)

1. **Intake** — `nar-input.py` identifies the format by
   signature + structure, hashes it, validates it, and (only
   on request) extracts it through the safe-archive layer.
2. **Fingerprint** — triage + perms outputs are normalized by
   `nar-fingerprint.py` into `application.json` /
   `fingerprint.json` with per-property provenance + confidence.
3. **Engine detection** — `nar-engines.py` fuses path
   signatures, DEX markers, native evidence, and container
   contents into one verdict per engine family with
   confidence and ambiguity notes (never one weak signature).
4. **Intelligence modules** — dex, native, network, security,
   assets run over the same opened target; each emits
   schema-shaped JSON and registers its evidence.
5. **Engine adapters** — the 1.x deep-dive scripts plus the
   new Unity and Unreal adapters run when detection routes to
   them.
6. **Comparison** — `nar-compare.py` keeps its 1.x output and
   gains the extended diff categories.
7. **Reporting** — the orchestrator assembles `report.json`
   plus the companion files that have data (including the
   brief-named projections from `narlib/companions.py` and
   `correlations.json` from `narlib/correlations.py`),
   `report.md`, and (via `nar-report.py`) the offline HTML
   dashboard. Since 2.6.0 the case also gains `graph.json`
   (`narlib/graph.py`, from the stage documents +
   correlations) and `investigation.json`
   (`narlib/investigation.py`); engine adapters feed
   relationship records into their own reports (Unreal
   classic/Zen UObject relationships, Godot text-scene
   references). Since 2.6.1 the Unreal relationship
   records ALSO join graph.json as unreal_package /
   unreal_object nodes and unreal_* edges under the
   graph's provenance/confidence discipline (closing the
   R-008 remainder; an earlier sentence here said they
   live only in the standalone reports — that was the
   2.6.0 state, reversed in 2.6.1), and the dashboard renders Unified graph and
   Investigation sections when those companions exist
   (Phase 12), staying fully offline. `nar-report.py` is the
   authoritative dashboard generator; nar-analyze invokes it
   for `report.html`.
8. **Case workspace** — every run lives in a case directory:
   `case.json` (id, input hash, config, stage states, tool
   versions, history). Completed stages are cached by
   (input hash, stage, tool versions) and skipped on resume.

## Registries

`scripts/registry.json` is the single machine-readable
declaration of tools and capabilities: name, kind, version
probe, platforms, input formats, engines, required/optional,
limitations, validation strategy (35 tools declared at
2.5.1; 9 with kind `unavailable`). `nar-doctor.sh` stays the
human-facing checker (bash, unchanged interface): a flat
core/optional check list (22 checks at 2.5.2, including the
bundled-scripts compile check, the protection-signatures
database check, and the optional skill-YAML check) — it has
no profile groupings. `narlib/registry.py` is the
programmatic reader. The two are kept consistent by unit
tests (`tests/unit/test_registry.py`) and the doctor's own
checks, not by construction.

## Schemas

`schemas/` holds JSON Schema documents for the structured
outputs — 26 schemas at 2.6.0 (24 at 2.5.1, plus graph and
investigation): report, fingerprint, engine,
endpoints, security findings, assets, comparison,
compare-feature-map, execution log, case, input, timeline,
runtime-session, correlations, and the case companions and
DEX/native documents (application, manifest, frameworks,
native-inventory, network-analysis, api-architecture, dex,
dex-classes, dex-methods, native, permissions).
Validation uses a
small stdlib structural validator (the project stays
dependency-free at runtime); the schemas are written to
that validator's documented subset (see
references/output-schema.md), and the CI schema job
parses every schema as JSON and runs the schema tests —
no standard-validator step runs in CI (an earlier
sentence here claimed otherwise; corrected in the
2.6.2 stability campaign). A parse-all regression test
(`tests/unit/test_schemas.py`) loads every schema file.

## Runtime subsystem

`nar-runtime.py` wraps adb and frida through the registry:
device discovery, version/compatibility checks, package and
process inspection, logcat capture, and a behavior-timeline
builder that turns captured logcat/Frida observation output
into the timeline schema. All device-touching verbs require
an explicit `--device` target and print the authorization
reminder from `references/safety-and-authorization.md`.
In an environment with no device, the module reports its
device paths as `IMPLEMENTED_BUT_UNVERIFIED`. Those paths
were exercised live on 2026-11-23 against an emulator
(API 26, QEMU TCG): adb discovery and inspection, package
install/launch, Frida attach-mode observation, and Frida
spawn-mode observation (resume-first recipe; the gated
one-command form loses ActivityManager's process-start-
timeout race under TCG) all ran; physical-device paths
remain unverified.

## Compatibility contract

- Every 1.1.0 script path and CLI flag keeps working.
- `scripts/nar.py` (the unified `nar` CLI) is a wrapper: it
  delegates to the same scripts, one verb per module (27
  dispatcher verbs plus the `case` router and `version`,
  at 2.5.1). It has no profile or `--module`/`--engine`
  selection flags; module selection is the choice of verb,
  and stage budgets live on `nar-analyze` itself
  (`--stage-timeout` / `--total-budget`).

## 2.6.2 addendum

- The DEX stage document is consumed through a bounded
  windowed reader (1 MiB window) instead of a memory map;
  cache and companion bytes are unchanged (hard
  byte-identity gate, NAR_2.6.2_VERIFICATION_REPORT.md).
- `nar case verify` enforces evidence integrity: graph
  and investigation evidence references (primary and
  accumulated) resolve to existing documents and fields,
  endpoints exist, identifiers are unique, counts
  reconcile, and hypotheses carry basis/confirm/refute.
  Investigation hypotheses are also gated at build time.
  Pre-2.6.1 cases verify with warnings for that era's
  known citation defects; tampering fails in every era.
- The runtime module reports every device capability
  with a status (detected / verified / unsupported /
  unavailable / not_tested) and offers a `validate`
  surface; the Frida validation suite lives in
  `tests/runtime_validation/` as device-dependent test
  tooling.
- narlib grows to 22 modules (budget.py added).
- New JSON outputs are additive; 1.x JSON keys are not
  renamed or removed.
