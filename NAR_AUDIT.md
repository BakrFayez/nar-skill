# NAR Repository Audit — Phase Zero (2.0 program)

Audit of the complete NAR repository as it stood at v1.1.0 (commit
`30e89f0`), performed before any 2.0 modification. Every file in the
repository was inspected: skill manifests, all Python and shell
scripts, all Frida scripts, all reference documentation, all
examples, the test harness, and the plugin manifest. No CI/CD
configuration, dependency file, `pyproject.toml`, or `schemas/`
directory existed at audit time.

Statuses used throughout the 2.0 program documents:

- `IMPLEMENTED_AND_TESTED` — implemented, and a real test executed
  against it in this environment.
- `IMPLEMENTED_BUT_UNVERIFIED` — implemented, but the executing
  environment cannot exercise it here (for example, no Android
  device is attached to this machine).
- `PARTIALLY_IMPLEMENTED` — some of the capability exists; named
  parts are missing.
- `MISSING` — not present.
- `BROKEN` — present but defective in a reproduced case.
- `NOT_APPLICABLE` — the requirement does not apply to this project.

## 1. Repository inventory (v1.1.0 baseline)

| Path | Lines | Role |
|---|---|---|
| `SKILL.md` | 229 | Agent skill entry: routing table, workflows, legitimate-use boundary |
| `skill.yaml` | 5 | Skill manifest (name, title, version, description) |
| `.claude-plugin/plugin.json` | — | Claude Code plugin manifest |
| `README.md` | 250 | Human-facing overview, install, tool table |
| `CHANGELOG.md` | 268 | Release history (generic entries, no fixture identities) |
| `CONTRIBUTING.md` | — | Contribution notes |
| `LICENSE` | — | MIT |
| `.gitignore` | — | Excludes binaries, work output, caches |
| `scripts/nar-doctor.sh` | 337 | Toolchain check (core + optional), `--json`, real-start verification for jadx |
| `scripts/nar-triage.py` | 1958 | First-pass triage: identity, inventory, DEX versions, engine hints, DEX markers, protections (7 categories), signatures, containers, AAB via bundletool |
| `scripts/nar-perms.py` | 936 | Permission + component audit; own binary-AXML parser with aapt2 xmltree cross-check; platform-default labeling |
| `scripts/nar-analyze.py` | 567 | One-command static workup; orchestrates the other scripts' `--json` output into `report.md` + `report.json` |
| `scripts/nar-compare.py` | 488 | Two-version diff (identity, permissions, DEX header counts, hashes, methods via header counts) |
| `scripts/nar-strings.py` | 356 | Ranked string scan with classified groups (URLs, endpoints, IPs, emails, key patterns) |
| `scripts/nar-pak.py` | 494 | Unreal `.pak` lister + extractor (stdlib index parse, per-entry encryption flags, grouped stats) |
| `scripts/nar-il2cpp.py` | 303 | Unity IL2CPP locator + Il2CppDumper runner + dump summary |
| `scripts/nar-flutter.py` | 145 | Flutter/Dart fingerprint from engine + app libraries |
| `scripts/nar-godot.py` | 271 | Godot `.pck` header/directory parse (stdlib), encryption flag, GodotPckTool cross-check |
| `scripts/nar-rn.py` | 203 | React Native bundle locator, Hermes/JSC decision, Hermes header parse, hermes-dec cross-check |
| `scripts/frida/*.js` (4) | 771 | Observation-only Frida templates: Java API trace, JNI trace, file I/O, network |
| `references/` (17 guides) | ~4,900 | setup/doctor, triage, manifest/resources, DEX/smali, native/JNI, Unity IL2CPP, Flutter, React Native, bundles, network traffic, Frida, legacy, modern, signatures, version compare, dynamic analysis, evidence workflows |
| `examples/` (4) | ~880 | Quick triage, Unity IL2CPP triage, Godot triage, filled sample report |
| `tests/run_e2e.sh` | 400 | Shell end-to-end harness, 34 cases, fixtures bound via `$NAR_FIXTURES` + local uncommitted manifest |

## 2. Environment verified at audit time

Host: Linux VM, Python 3.12, Node available. Verified present and
startable: JDK 17/21/25, .NET runtime (for Il2CppDumper), apktool,
aapt2 + apksigner + zipalign (SDK build-tools 34/35), adb
(platform-tools; **no device or emulator attached**), jadx CLI,
bundletool (jar), Il2CppDumper, hermes-dec, GodotPckTool, GDRE
Tools, Ghidra 12.2 headless, Kuna, mitmproxy, tshark, frida (host
CLI in a venv), baksmali/smali, GNU binutils (readelf/nm/objdump).
Installed during the audit as OPTIONAL Python dependencies in a
workspace virtualenv: pytest (test runner) and UnityPy (Unity asset
parsing). Verified absent: Cpp2IL, Il2CppInspector, AssetRipper,
UABEA, FModel, UAssetAPI, UnrealPak, CFR, Procyon, dex2jar.

## 3. Existing strengths

1. **Triage depth.** `nar-triage.py` already covers identity,
   inventory, DEX format versions, multi-indicator engine hints,
   DEX content markers, library versions from `META-INF`, Rust
   markers, 16 KB alignment evidence, form factors, container
   handling (XAPK/APKM/AAB/OBB/splits), and a seven-category
   protection-systems taxonomy with attribution discipline
   (a packer is named only on a dedicated marker; otherwise the
   finding stays unattributed).
2. **Honesty mechanics are structural, not cosmetic.** Implied
   permissions are labeled as implied; platform defaults are
   labeled as defaults; key-pattern string hits carry an explicit
   "looks like, not proof" caveat; encrypted pak entries are
   counted, not opened; every analyze report ends with a
   limitations section.
3. **Real test discipline.** A 34-case end-to-end harness runs
   every script against purpose-built and real-world fixtures,
   including byte-verified pak extraction against an independent
   from-scratch parse, positive and negative engine cases, and a
   zero-false-positive packer discipline check on a clean set.
4. **Wide-sweep evidence (v1.1.0).** A 16-target sweep of free
   apps and games across kinds (native C/C++ game, Java/libGDX
   game, Godot game, Flutter app, Capacitor app, Cordova hybrid
   game, Xamarin/.NET MAUI app, a second .NET-framework game, a
   large Kotlin app, a WebView wrapper, two Android TV apps, a
   2018-era app, a large popular messenger, a Widevine media app,
   a large Unity IL2CPP game) completed with exit code 0 on every
   finished target, and the engine/framework verdicts were
   verified correct on each kind — including the Xamarin/MAUI and
   Capacitor markers on real (not doctored) apps.
5. **Tool adapters verify before trusting.** The doctor actually
   starts jadx rather than trusting its presence; nar-godot
   cross-checks its own parse against GodotPckTool; nar-rn
   cross-checks against hermes-dec; nar-perms cross-checks its
   own AXML parser against aapt2.

## 4. Defects and weaknesses found

1. **Report rendering robustness (`BROKEN`, cosmetic).** In the
   wide sweep, one large-app `nar-analyze` Markdown report
   rendered some string findings as raw unescaped JSON blobs
   instead of clean truncated lines. The JSON report was correct;
   the Markdown summarizer truncates by character count but does
   not flatten structured hits. **FIXED in 2.0** (Phase 2:
   summarize_strings flattens structured hits; verified in the
   harness analyze cases).
2. **No unified CLI.** Twelve separate script entry points; no
   `nar` command, no profiles (`quick`/`full`), no module
   selection. (`MISSING` per brief §14.)
3. **No capability/tool registry.** Tool knowledge is embedded
   per-script (doctor's bash tables, each script's own finder
   functions). No machine-readable registry declares versions,
   formats, engines, limitations, or validation strategies.
   (`MISSING` per brief §12/§19.)
4. **No case workspace / resume.** nar-analyze writes a report
   but keeps no case state; re-running repeats every stage,
   including expensive ones. (`MISSING` per brief §17.)
5. **No standardized evidence schema.** Each script emits its
   own JSON shape; there is no common finding schema, no
   `schemas/` directory, no validation of outputs.
   (`PARTIALLY_IMPLEMENTED` per brief §13.)
6. **Engine detection is hint-based, single-layer.** Triage
   emits hints and markers but there is no dedicated detection
   layer that fuses multiple independent indicators into a
   verdict with confidence and ambiguity reporting.
   (`PARTIALLY_IMPLEMENTED` per brief §3.3.)
7. **DEX intelligence is header-level.** Method/field counts
   come from DEX headers; there is no class/method/field
   enumeration, hierarchy, string-reference mapping, reflection
   or dynamic-loading detection, native-method mapping, or call
   graph in any script. jadx/apktool usage is documented in
   guides but not wrapped in version-checked adapters.
   (`PARTIALLY_IMPLEMENTED` per brief §4.)
8. **Native intelligence is posture-level.** Triage reads ELF
   headers for hardening posture and alignment; there is no
   symbol import/export inventory, dependency (DT_NEEDED)
   listing, JNI export mapping, or native dependency graph in
   any script. (`PARTIALLY_IMPLEMENTED` per brief §6.)
9. **Network intelligence is strings-level.** nar-strings
   classifies URLs/endpoints, but there is no endpoint
   inventory with the brief's classification taxonomy, no host
   inventory, no Firebase/Supabase configuration detection, no
   network-security-config parsing, no API architecture output.
   (`PARTIALLY_IMPLEMENTED` per brief §7.)
10. **No security findings engine.** Permission/component audit
    exists; there is no finding schema (severity, confidence,
    evidence, impact, remediation), no storage/crypto/WebView
    checks. (`MISSING` per brief §9.)
11. **No asset inventory engine.** Triage counts assets and
    bundles; there is no typed asset inventory with dimensions,
    hashes, duplicate detection, or export. (`MISSING` per
    brief §10.)
12. **Comparison is summary-level.** nar-compare covers
    identity, permissions, DEX header counts, and file hashes;
    it does not diff classes/methods/strings/endpoints/assets
    or classify change severity. (`PARTIALLY_IMPLEMENTED` per
    brief §11.)
13. **Runtime subsystem is guides + templates only.** Four
    Frida templates and two guides exist; there is no adb
    adapter module, no device discovery code, no behavior
    timeline tooling. No device exists in this environment, so
    device-dependent parts can only ever be
    `IMPLEMENTED_BUT_UNVERIFIED` here. (`PARTIALLY_IMPLEMENTED`
    per brief §8.)
14. **No HTML reporting.** Reports are Markdown + JSON only.
    (`MISSING` per brief §15.)
15. **No unit tests, no CI, no packaging metadata.** Only the
    shell e2e harness exists. No `tests/unit/`, no pytest
    configuration, no `pyproject.toml`, no GitHub workflows.
    (`MISSING` per brief §21/§22.)
16. **Input handling is extension-driven.** Triage decides
    AAB/OBB/XAPK by filename suffix and ZIP readability; there
    is no signature-based format identification across the
    brief's full input list (AAR, JAR, bare DEX/ODEX/VDEX,
    ELF, IoStore, resource archives), and no safe-extraction
    layer with zip-slip/bomb/traversal protections.
    (`PARTIALLY_IMPLEMENTED` per brief §3.1.)
17. **Duplicated helper code.** `sha256_of`, tool finders
    (aapt2/apksigner/bundletool), and ZIP helpers are
    re-implemented in most scripts. Acceptable for standalone
    scripts, but new 2.0 modules must share one library instead
    of adding a twelfth copy. (Technical debt; brief rule 6.)
18. **`__pycache__` artifacts in the working tree.** The
    doctor's compile check leaves `scripts/__pycache__/` in
    the tree (gitignored, but untidy). (Minor debt.)

## 5. Documentation state

The 17 reference guides are accurate against the 1.1.0
implementation (verified by spot-reading the routing table
against actual script CLIs during this audit). Missing per
brief §16: an architecture reference, a tool-registry
reference, an output-schema reference, a safety/authorization
reference, and a troubleshooting reference. The brief's §16
filename list largely renames topics the existing guides
already cover under established names; per brief §16's own
"avoid duplicating" rule, the existing filenames are kept and
only the genuinely missing references are added.

## 6. Audit conclusion

The 1.1.0 baseline is a working, tested, honest static-analysis
skill with deep triage and four engine deep-dives. The 2.0
program's work is therefore additive: a shared core library,
input/fingerprint/engine-detection layers, DEX and native
intelligence modules, network and security engines, an asset
inventory, a stronger comparison engine, an orchestrator with
registry + case workspace, standardized evidence outputs, an
HTML dashboard, a unified CLI, unit tests, and CI — without
rewriting or breaking any existing script.

## 7. Reconciliation (2026-11-24) — Evolution Phase 0

This audit was written against v1.1.0 before the 2.0
program. The TOTAL INTELLIGENCE EVOLUTION program's
Phase 0 re-audited the shipped v2.4.0 tree (local main
c31c072; executed baseline: pytest 144/144, e2e harness
47/47 with 0 skipped, doctor READY, all 23 unified-CLI
subcommands help-clean, one orchestrated case executed
end to end with its stage cache verified on re-run).
Sections 1–6 above stand as the historical v1.1.0 audit;
this section reconciles them.

### 7.1 Disposition of the §4 defect list

- #1 Markdown raw-JSON rendering — FIXED in 2.0
  (recorded in place above); no recurrence in the
  2.1.0–2.4.0 sweeps.
- #2 unified CLI, #3 capability registry, #4 case
  workspace/resume, #5 evidence schema + `schemas/`,
  #10 security findings engine, #11 asset inventory,
  #14 HTML dashboard, #15 unit tests + CI + pyproject —
  all CLOSED by the 2.0 program and still present and
  green at 2.4.0.
- #6 engine detection, #7 DEX intelligence, #8 native
  intelligence, #9 network intelligence, #12 comparison,
  #16 signature-based input + safe extraction — CLOSED
  as designed in 2.0; residual sub-gaps found by this
  reconciliation are listed in §7.2.
- #13 runtime subsystem — CLOSED beyond the audit's
  expectation: the module exists and its device paths
  were verified live on an emulator (API 26) in
  2.1.0–2.4.0, attach and spawn; physical-device paths
  remain IMPLEMENTED_BUT_UNVERIFIED.
- #17 duplicated helpers — contained as designed:
  2.0+ modules share narlib; the 1.x scripts remain
  standalone on purpose (compatibility surface).
- #18 `__pycache__` in tree — still occurs after doctor
  runs; gitignored. Cosmetic; carried into the
  evolution plan (Phase 1) as a tidy item, not a defect.

### 7.2 New findings of this reconciliation

Documentation defects (docs claim more, or other, than
the code ships):

1. README "Repo structure" block still describes the
   1.x layout: it lists 17 reference guides (the tree
   has 22; architecture, output-schema,
   safety-and-authorization, tool-registry and
   troubleshooting are missing from the list) and its
   scripts listing omits every 2.0 module (nar.py,
   nar-input, nar-fingerprint, nar-engines, nar-unity,
   nar-unreal, nar-dex, nar-native, nar-network,
   nar-security, nar-assets, nar-runtime, nar-report)
   and narlib; its tests listing omits tests/unit and
   tests/benchmarks. Status: BROKEN (documentation).
2. The 2.0 implementation plan promised case companions
   named application.json, permissions.json,
   dependencies.json, classes.json and methods.json at
   the case root. The shipped orchestrator emits a
   different, documented set (references/output-schema.md
   matches the code): classes/methods live under dex/,
   permission data lives in report.json, and no
   application.json exists (fingerprint.json covers the
   role). A naming divergence between plan and product,
   not a functional gap; the evolution plan (Phase 2)
   closes it by emitting the brief-named set.
3. README and pyproject carry the headline "NAR 2.0 —
   NIROUS ANDROID INTELLIGENCE" at version 2.4.0.
   Cosmetic identity staleness, shipped unchanged
   through 2.1.0–2.4.0; recorded, not silently edited.

Code-verified gaps (each reproduced or grep-proven in
this pass; all are carried into the evolution plan with
acceptance tests):

4. No cross-module correlation engine: the string
   "correlat" appears nowhere in scripts/. Correlation
   exists only as merged summaries in report.json and
   as joins inside single modules (nar-native's JNI map,
   nar-dex's native declarations). The evidence
   envelope (narlib/evidence.py) carries fact classes
   and confidence, but no verification-status field
   with the CONFIRMED / STRONGLY_INDICATED / POTENTIAL /
   UNVERIFIED / CONTRADICTED vocabulary.
5. narlib/dex.py parses no try/catch handler tables
   and no debug info; narlib/dexdis.py produces
   listings without a control-flow graph.
6. narlib/elf.py parses no relocation tables; compiler
   fingerprints beyond Rust markers (triage) do not
   exist.
7. nar-network applies no credential/token redaction
   pass to its output (redaction is guide-level only);
   its three brief-named documents ship as one
   endpoints document.
8. nar-assets extracts no audio metadata (duration,
   channels, sample rate); image dimensions only.
   Asset dependency relationships are container
   cross-references, not graphs.
9. nar-rn has no source-map, native-module,
   TurboModule or Fabric inventory. nar-unity treats
   Addressables as a catalog-presence flag (no catalog
   parse); nar-flutter's asset handling is a presence
   flag. nar-godot classifies pack contents at listing
   level; GDScript bytecode and scene/resource parsing
   are orchestrated external tools, not narlib parsers.
10. Protection signatures are embedded in nar-triage
    code; there is no versioned signature-database
    artifact.
11. The case workspace has resume + hash-keyed stage
    cache, but no case export / import / verify
    commands, no execution budgets, and no retry or
    cancellation policy; the stage pipeline is fixed,
    not adaptive.
12. tests/benchmarks/run_benchmarks.py measures module
    wall-times on fixture roles only; it computes no
    accuracy, precision/recall or false-positive/
    negative metrics (accuracy evidence lives in this
    matrix instead).
13. The unified CLI has 23 working subcommands, but
    the brief's target families `tools`, `benchmark`,
    `case`, `validate`, `identify` and `info` are not
    commands (their functions are reachable through
    doctor, `nar input identify/validate`, and the
    tests/benchmarks runner).

Environment-blocked (unchanged by any code work):
physical-device runtime verification (no device is
attached to this VM); CI workflow changes (the release
push path lacks the workflows permission — workflow
edits route through the GitHub web UI) and CI
execution itself (runs on GitHub only, on push);
Oodle decompression (proprietary SDK — UNSUPPORTED by
design); a real classic-format UE5 package with a
recorded FileVersionUE5 (evidence-negative across five
examined UE5 titles; the row stays open by evidence,
not by omission); Zen pre-5.3 / Early Access layouts
and recorded Zen versioning on real data (no obtainable
sample; synthetic-verified only); OAT beyond API 26
x86_64 and real Dalvik-ODEX / CDEX files (synthetic
level; CDEX payloads are identified, not decoded);
Wear OS / APEX / instant-app samples (none obtainable;
rows stay labeled unexercised).
