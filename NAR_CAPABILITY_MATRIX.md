# NAR Capability Matrix

Research by Bakr Fayez

One row per capability area. The skeleton is the area list
of `NAR_GAP_ANALYSIS.md` (Phase-Zero baseline §§3–22, as
reconciled by its dated addenda through the 2.5.2 W6
reconciliation), refined where 2.5.x workstreams split an
area. This matrix was compiled in 2.5.2 W6 (2026-11-24)
from the repo's own tests, the executed records in
`NAR_TEST_MATRIX.md` and `NAR_2.5.2_UPDATE_REPORT.md`,
and the parsers' own `capabilities()` facts — it makes
no claim that is not backed by one of those.

Status vocabulary (exactly one status per row — the
strongest honest one; the Evidence column carries the
nuance):

- **Implemented** — the code exists and runs; verification
  is limited to the level named in Evidence (for example
  synthetic fixtures only).
- **Tested** — automated tests in this repo pass against
  it (unit suite, e2e harness, or both).
- **Independently verified** — an external oracle or tool
  (SDK dexdump, readelf, aapt2, an independent byte-walk,
  or a real engine-written file) agrees with NAR's output.
- **Partially supported** — a real subset works and is
  tested; a named remainder does not.
- **Unsupported** — not implemented, by design or by
  plan; the tooling names it instead of guessing.

Corpora are named by role label only, as everywhere in
this repo. Battery at compilation: pytest 303 passed,
e2e 65 passed, doctor READY (2.5.2 W5 end; W6 numbers in
the update report).

| Capability | Status | Evidence |
|---|---|---|
| Universal input identification (APK/AAB/splits/OBB, AAR/JAR, bare DEX/ODEX/VDEX, ELF, engine containers) | Tested | tests/unit/test_formats.py (magic + structure verdicts per format); benchmark format-identification accuracy 1.0 on 10 labeled fixtures (Phase 11 record, NAR_TEST_MATRIX.md) |
| Safe archive extraction (zip-slip, traversal, symlink, bomb ratio, nesting, total size) | Tested | tests/unit/test_safearchive.py — every planted guard case rejected and reported, never silent |
| Application fingerprinting with provenance + confidence + fact class | Tested | nar-fingerprint.py + brief-named companions projected by narlib/companions.py and schema-validated before writing; generated-case validation in tests/unit/test_schemas.py |
| Manifest, permissions, components, signing inventory | Independently verified | nar-perms.py own AXML parser cross-checked against aapt2 xmltree; signature schemes v1–v4 inventoried via apksigner itself; e2e perms cases |
| DEX parsing and enumeration (tables, hierarchies, call edges, reflection/dynamic-loading/native evidence, try/catch, debug-info presence) | Independently verified | Field enumeration vs SDK dexdump: 9,949 classes, 0 mismatches (2.1.0 record); try/catch vs dexdump on a real corpus DEX: 484 methods with tries, 1,178 try items, 1,357 handler entries — all agree (Phase 3 record); tests/unit/test_dex_elf.py |
| DEX bytecode disassembler | Independently verified | Disassembly agrees with SDK dexdump: 40,837 methods / 773,166 instructions, full agreement (tests/unit/test_dexdis.py + NAR_TEST_MATRIX.md oracle record); control-flow block summary added Phase 3 with listings unchanged |
| Java / Kotlin intelligence | Partially supported | Kotlin inventory + `@Metadata` payload parsing Tested on a real Kotlin corpus fixture (10,213 annotations; versions 1.8.0 / 2.2.0 dominant, Phase 3 record). Not implemented: semantic rename suggestions, debug line/local decoding, full CFG rendering; CFR / Procyon / dex2jar are registered unavailable, never integrated |
| Compiled artifacts (OAT / VDEX / ODEX / ART) | Partially supported | Real API 26 files verified (app .odex = OAT 124, companion .vdex = VDEX 006 with its DEX 037 fully parsed, boot .oat/.art; tests/unit/test_oat.py). Synthetic-only: OAT beyond API 26, Dalvik-era ODEX on a real file, VDEX versions beyond 006 field parsing |
| CDEX (compact DEX) payload decoding | Unsupported | CDEX files are identified and reported honestly; the payload is not decoded (narlib/oat.py; NAR_GAP_ANALYSIS.md close-all-gaps addendum) |
| Native ELF analysis (headers, sections, segments, dynamic, symbols, DT_NEEDED, Build ID, hardening, dependency graph, relocations, compiler fingerprints) | Independently verified | readelf cross-check: relocation section counts and PLT/GOT subset agree, symbol/dependency output compared (tests/unit/test_native.py, test_dex_elf.py); .comment Clang/GCC fingerprints reported as observed evidence only, stripped binaries claim neither |
| JNI intelligence (static) | Tested | nar-native JNI export map joined with nar-dex native-method declarations; correlations.json JNI pairs (demo fixture: known pair matched/CONFIRMED; fabricated set pins declaration-only + export-only); tests/unit/test_phase8_orchestration.py |
| Engine / framework detection (18 families, fused verdicts with confidence + ambiguity) | Tested | Benchmarks on labeled corpora, synthetic and real reported separately: recall 1.0 on 6 labeled real fixtures, accuracy 1.0 on the 8-fixture synthetic framework corpus (Phase 11 record); e2e framework cases |
| Real-corpus engine precision | Unsupported | NOT RUN — no labeled engine-negative real corpus exists, so precision on real data has never been measured (benchmark runner states this; Phase 11 record). This row is a measurement gap, not a code claim |
| Unity analysis | Partially supported | IL2CPP location + Il2CppDumper summary and the optional Cpp2IL backend Tested (e2e IL2CPP case; narlib/dotnetmeta summary); Addressables catalog inventory Tested on a real catalog (6,798 locations, 24,820 entries) plus a synthetic catalog. Partial: Mono is inventory-level; AssetBundle object census only via optional UnityPy; no scene/prefab/material semantic inventory |
| Unreal `.pak` archives (v1–7 classic index, v10/v11 encoded index) | Independently verified | E2e: 1,598 entries listed, extraction byte-verified against an independent parse; v10+ index regions SHA-1-verified. Versions 8/9 (FName-based index) are reported unsupported, plainly (tests/unit/test_pak.py) |
| Unreal IoStore (.utoc/.ucas) | Independently verified | TOC versions 0–10 declared by narlib/iostore.py `capabilities()`; both directory-index layouts (classic, pooled) agree with an independent byte-walk oracle on all 6,743 named files of the UE 5.3 real set, and path-for-path on the historical TOC v8 set; chunk extraction for None/Zlib only (tests/unit/test_iostore.py) |
| Unreal classic packages (.uasset/.umap) | Partially supported | Summary + name/import/export/depends tables verified on synthetic byte-exact fixtures and a real UE4-era corpus incl. independent manual spec accounting on one small package (tests/unit/test_uasset.py). Best-effort property tags only; a real classic package with a recorded FileVersionUE5 is still absent from the corpus (evidence-negative over five titles) |
| UE5 property tag extensions (object versions 1011 / 1012+) | Implemented | Implemented in narlib/uasset.py (1011 `ue5-tag-extension` tail; 1012+ `ue5-complete-type-name`), synthetic-verified only: tests/unit/test_uasset.py builders + a synthetic 1011 package run through nar-unreal in tests/unit/test_unreal.py. No real package recording >= 1011 is in the corpus |
| Unreal Zen packages | Independently verified | Current (UE 5.3+) layout: 1,209 real stored packages parsed across two real corpora (684 + 525), independent byte-walk oracles agree 45/45 and 20/20 field checks on sampled packages (tests/unit/test_zen.py + sweeps in NAR_TEST_MATRIX.md) |
| Zen pre-5.3 / Early Access layouts, recorded Zen versioning info | Implemented | Implemented in narlib/zen.py, synthetic-verified only (tests/unit/test_zen.py builders); all 1,209 real packages use the current layout and record no versioning info, so no real sample exists for these paths |
| Unreal capability reporting + configurable limits (2.5.2 W2/W3) | Tested | Reports carry `limits` + `capabilities` composed from the narlib `capabilities()` facts; limitations text is generated, never hand-written; `--max-*` / `--all-*` caps carry total/processed/skipped/failed accounting on every capped collection (tests/unit/test_unreal.py, 12 tests) |
| Kismet / Blueprint graph decoding | Unsupported | PLANNED in NAR_GAP_ANALYSIS.md; narlib/uasset.py `capabilities()` lists it as not decoded. Class-specific export data is located and measured, not decoded |
| Oodle decompression | Unsupported | By design (proprietary SDK, refused by name): Oodle chunks in IoStore and pak entries are named, never decoded (narlib/iostore.py `capabilities()`; nar-pak refusal) |
| AES decryption of encrypted containers / pak indexes | Unsupported | By design: encrypted containers (including AES-sealed indexes) and encrypted packs are inventoried and diagnosed, never decrypted (narlib/iostore.py `capabilities()`; nar-pak footer index-encryption diagnosis) |
| Godot packs (.pck formats 2/3/4) | Tested | tests/unit/test_godot.py + e2e: listing, encryption flag, per-entry resource-type classification. Encrypted-pack detection Independently verified on a real engine-written encrypted pack (detection only, listing honestly unavailable); format 4 headers report facts with the listing marked unsupported |
| Flutter / Dart analysis | Partially supported | Versions + AOT markers Tested (e2e positive/negative); flutter_assets inventory Tested on a real fixture (370 typed entries). Not implemented: snapshot/VM structure parsing, symbol recovery, plugin/native-channel inventory |
| React Native analysis | Partially supported | Hermes vs JSC decision + Hermes header parse Tested, cross-checked with hermes-dec; source-map detection + native-module inventory Tested for text bundles (planted call sites) and architecture markers on a real Hermes fixture. Hermes module NAME attribution is partial by design boundary (string-table entries cannot be attributed to call sites without bytecode reference analysis; the report states this) |
| Deep dives for other detected frameworks (Cordova, Xamarin/.NET, Qt, Defold, Ren'Py, RPG Maker, Kivy, …) | Unsupported | Detection only, by design: nar-engines detects these families (row above), and no deep-dive module exists for them (NAR_GAP_ANALYSIS.md Phase 0 reconciliation, "Other frameworks" row) |
| Protection / obfuscation detection | Tested | Benchmark on labeled real corpus: attribution precision 1.0 / recall 1.0, 0 false positives on the 9-fixture clean set (single-positive-corpus caveat recorded in Phase 11); signatures ship as a versioned database (scripts/protection-signatures.json v1.0.0) with a validating loader (tests/unit/test_signatures.py) |
| Network intelligence (static) | Tested | Classified endpoint taxonomy, hosts, services, NSC structured parse, client-library evidence; credential/token redaction at the source Tested with a planted fixture (5 planted values, count 5, no secret substring in the report; tests/unit/test_network_phase5.py); endpoints + network-analysis + api-architecture companions schema-validated |
| Network capture (dynamic, mitmproxy / tshark) | Partially supported | Guides + registered tooling orchestrate capture on the user's own device/emulator only; capture needs a device and a CA the target trusts, and pinning may block it — that outcome is a finding, not an error (registry limitations; references/network-traffic.md) |
| Runtime / dynamic analysis — emulator | Tested | Live on an API 26 emulator (2026-11-23): adb discovery/inspection, install/launch, all four bundled Frida scripts in attach mode and spawn mode (resume-first recipe), jni-trace RegisterNatives events captured live against a dynamic-registration fixture (Phase 6 record); session records persisted and schema-validated (tests/unit/test_runtime_sessions.py) |
| Runtime / dynamic analysis — physical device | Implemented | Emulator-verified only: every physical-device path is implemented (same adb/Frida adapters) but remains IMPLEMENTED_BUT_UNVERIFIED — no physical-device session has been run (owner's device only) |
| Security intelligence (NAR-SEC findings) | Tested | Findings carry severity/confidence/evidence/impact/remediation/false-positive notes + verification_status, schema-validated; known-findings fixture + clean fixture e2e cases (tests/unit/test_runtime_sessions.py findings case; e2e security cases). CVSS deliberately not computed (documented) |
| Asset intelligence | Tested | Typed inventory, hashes, image dimensions, duplicates, large assets, container cross-reference; audio header metadata (WAV / OGG / MP3) Tested on synthetic known-header fixtures (tests/unit/test_assets_audio.py); formats outside the measured set report unmeasured with the reason |
| Version comparison | Tested | Extended diffs (classes/methods/strings/endpoints/assets/security/engine) + severity + similarity on a planted pair (e2e); `--out` emits comparison.json + schema-validated feature-map.json + version-diff.md with labeled build-noise separation. Not supported: comparisons of more than two versions |
| Evidence model, JSON schemas, correlations | Tested | 24 schemas in schemas/, all parse-checked and used by generated-case validation (tests/unit/test_schemas.py); evidence envelope carries tool+version, source, location, timestamp, confidence, fact class, verification status; correlations.json joins are Tested on demo + fabricated sets. The built-in validator is a structural subset of JSON Schema and says so in its docstring |
| Orchestration (case workspace, stage cache/resume, budgets, case bundles) | Partially supported | Tested: hash-keyed cache + resume, per-stage/total budgets recorded as budget-exceeded stops, export/import/verify with hash manifest and tamper failure (tests/unit/test_phase8_orchestration.py; e2e case cases). Not implemented: adaptive planning, retry/cancellation policy |
| Tool registry + doctor | Tested | scripts/registry.json declares 35 tools (9 kind `unavailable`, probing unavailable, never faked — tests/unit/test_registry.py); `nar tools --json` reports the same 35; doctor READY. Known defect found in 2.5.2 W6: the doctor's bundled-scripts check compiles only 10 of the 24 Python scripts while reporting "all bundled scripts compile" (see the W6 record in NAR_2.5.2_UPDATE_REPORT.md) |
| Reporting (report.md/json + offline HTML dashboard) | Tested | Dashboard renders the native dependency graph as inline SVG (deterministic layout, escaped labels, truncation over 120 libraries labeled); zero external references asserted by unit test and e2e (tests/unit/test_phase9_reporting_cli.py) |
| Unified CLI (`nar`) | Tested | 27 dispatcher verbs + `case` router + `version`, all `--help`-clean (Phase 12 smoke: 29/29 invocations); 1.x standalone script CLIs unchanged (tests/unit/test_phase9_reporting_cli.py, test_phase10_guide_audit.py verb guard) |
| Skill interface (SKILL.md routing, skill.yaml, plugin manifest) | Tested | Routing covers every module (link/verb/flag guards in tests/unit/test_phase10_guide_audit.py + test_docs_consistency.py); skill.yaml + SKILL.md frontmatter parse with a real YAML parser and are guarded by tests/unit/test_yaml_validation.py (18 tests) since 2.5.2 W1 — before W1 both files were invalid YAML despite regex-level checks |
| Testing infrastructure + reproducibility | Tested | Documented test categories (NAR_TEST_MATRIX.md) + synthetic fixture library/generator/manifest (tests/synthetic_fixtures.py, tests/generate_fixtures.py, tests/expected_outputs.json); clean-extraction proof: 295 passed / 8 skipped / 0 failed with an empty $NAR_FIXTURES (W5 record); parser mutation corpus guards DEX/ELF/PAK/IoStore/Zen clean failure (tests/unit/test_phase11_mutations.py) |
| Benchmarks + performance | Tested | Labeled-corpus accuracy metrics + measured peak memory (references/benchmarks.md methodology); 2.5.2 W0/W4 baselines on identical inputs (tests/benchmarks/baseline-2.5.2.json): nar-unreal peaks −84.5%/−77.3% and nar-native −84.7% after the mmap work; the nar-analyze peak is diagnosed (stage-JSON round-trip in the orchestrator) and unchanged |
| Play Integrity verdict | Unsupported | From the client: triage detects the Play Integrity API's presence and labels it client-side presence only — the verdict is server-side and cannot be obtained from the shipped app (references/triage-and-inventory.md; CHANGELOG 1.0.4 record) |
| Documentation | Tested | 24 reference guides + program documents; automated guards assert every script/narlib/frida/reference/schema file is named in the README structure block, every SKILL.md routing target exists, and all version-bearing files agree (tests/unit/test_docs_consistency.py, test_phase10_guide_audit.py) |
| Packaging / distribution | Implemented | pyproject (stdlib-only runtime core, optional extras incl. the test-only PyYAML extra), .claude-plugin/plugin.json, per-release ZIP practice in references/release-guide.md. CI workflow execution is GitHub-only and cannot be verified from this repo state |
