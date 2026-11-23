# NAR Architecture — 2.0

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
   aapt2, apksigner, bundletool, baksmali, Il2CppDumper,
   hermes-dec, GodotPckTool, GDRE, Ghidra, Kuna, readelf/nm,
   mitmproxy, tshark, adb, frida — each declared in
   scripts/registry.json with version checks and limitations.
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
- `narlib/elf.py` — ELF parser primitives (headers, sections,
  segments, dynamic table, symbol tables) for ELF32/64 on all
  four Android architectures.

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
   plus the companion files that have data, `report.md`, and
   (via `nar-report.py`) the offline HTML dashboard.
8. **Case workspace** — every run lives in a case directory:
   `case.json` (id, input hash, config, stage states, tool
   versions, history). Completed stages are cached by
   (input hash, stage, tool versions) and skipped on resume.

## Registries

`scripts/registry.json` is the single machine-readable
declaration of tools and capabilities: name, kind, version
probe, platforms, input formats, engines, required/optional,
limitations, validation strategy. `nar-doctor.sh` stays the
human-facing checker (bash, unchanged interface) and gains
profile groupings; `narlib/registry.py` is the programmatic
reader. The two are kept consistent by an e2e case.

## Schemas

`schemas/` holds JSON Schema documents for the 2.0 outputs
(report, fingerprint, engine, endpoints, security findings,
assets, comparison, execution log, case). Validation uses a
small stdlib structural validator (the project stays
dependency-free at runtime); schemas are also valid inputs
for standard validators in CI.

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
  delegates to the same scripts and adds profiles, module
  selection, and the report/doctor/tools verbs.
- New JSON outputs are additive; 1.x JSON keys are not
  renamed or removed.
