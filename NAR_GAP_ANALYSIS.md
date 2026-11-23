# NAR Gap Analysis — Phase Zero (2.0 program)

Every requirement area of the NAR 2.0 master brief (§§3–22)
mapped against the audited v1.1.0 implementation. Statuses:
`IMPLEMENTED_AND_TESTED` (IT), `IMPLEMENTED_BUT_UNVERIFIED`
(IU), `PARTIALLY_IMPLEMENTED` (PI), `MISSING` (M), `BROKEN` (B),
`NOT_APPLICABLE` (NA). "Where" names the exact files.

## §3.1 Universal input formats

| Requirement | Status | Where / gap |
|---|---|---|
| APK, XAPK/APKM, APKS, AAB, OBB, split sets | IT | `nar-triage.py` `triage()`, `container_manifest_of()`, `bundletool_manifest()`; e2e cases |
| AAR, JAR identification | M | No signature-based identifier exists |
| Bare DEX / ODEX / VDEX identification | M | DEX version read only inside containers (`dex_version_of`) |
| ELF shared library as input | M | ELF parsed only inside containers (`elf_hardening_of`) |
| Unity AssetBundle as input | PI | Bundles inventoried inside APKs; no standalone bundle parser (UnityPy optional in 2.0) |
| Unreal PAK as input | IT | `nar-pak.py` full list/extract, byte-verified |
| Unreal IoStore (.utoc/.ucas) | M | Not detected at all in 1.1.0 |
| Godot PCK as input | IT | `nar-godot.py` stdlib parse + tool cross-check |
| File signature detection | PI | Extension + ZIP readability only; no magic-byte layer |
| Structural validation, corruption detection | PI | Bad ZIP reported; no per-format structural validation |
| Safe extraction (zip-slip, traversal, symlink, bombs, nesting, exhaustion) | M | Extractions in `nar-analyze.py`/`nar-rn.py` write entry names without a dedicated guard layer |
| Split package discovery | IT | Triage split detection + container manifests |
| SHA-256 identification | IT | Every script hashes its target |
| Duplicate detection (inputs) | M | No cross-input duplicate registry |
| Encrypted container identification | IT | Pak index flag, PCK flag, IL2CPP metadata magic in triage protections |

## §3.2 Application fingerprinting

| Requirement | Status | Where / gap |
|---|---|---|
| Package, label, versions, SDK levels | IT | aapt2 badging in triage; AAB via bundletool |
| ABIs, native libraries | IT | Triage `native_libs_by_abi` |
| Activities/services/receivers/providers | IT | `nar-perms.py` `analyze()` full component inventory |
| Permissions + intent filters | IT | `nar-perms.py` incl. protection levels, implied labeling |
| Signing certificates + schemes | IT | `apksigner_verify()` in triage; signatures guide |
| Embedded SDKs / library versions | IT | `META-INF/*.version` harvesting in triage |
| Frameworks / build metadata | PI | DEX markers + form factors; no single fingerprint document |
| `application.json` / `fingerprint.json` / `manifest.json` outputs | M | No normalized fingerprint artifact is emitted |
| Provenance + confidence per property | M | Values are reported without provenance records |

## §3.3 Engine detection

| Requirement | Status | Where / gap |
|---|---|---|
| Unity Mono / IL2CPP | IT | Path signatures + metadata version; `nar-il2cpp.py` |
| Unreal UE4 | IT | lib/build-string version; pak tooling |
| Unreal UE5 | PI | UE5 ships IoStore + `libUnreal.so`; build-string path exists, IoStore unrecognized |
| Godot 3 / 4 | IT | PCK format + engine version in `nar-godot.py` |
| Flutter / Dart | IT | `nar-flutter.py` versions + AOT markers |
| React Native / Hermes | IT | `nar-rn.py` magic decision + header parse |
| Cocos2d-x, libGDX, Defold | IT | Path + DEX markers, e2e framework cases |
| Native Java / Kotlin distinction | IT | DEX markers (Kotlin evidence independent of stripped metadata) |
| Xamarin / .NET MAUI | IT | Markers verified on real apps in the wide sweep |
| Cordova / Capacitor | IT | Markers verified on real apps in the wide sweep |
| Qt, Kivy/Python, Ren'Py, RPG Maker | IT | Markers + e2e doctored-fixture cases |
| Confidence scoring, multi-indicator rule, ambiguity reporting | M | Hints are listed; no fused verdict with confidence exists |

## §4 DEX / Java / Kotlin intelligence

| Requirement | Status | Where / gap |
|---|---|---|
| Multi-DEX discovery | IT | Triage DEX inventory |
| Class/method/field enumeration | PI | Header counts only (compare); no enumeration |
| Hierarchy, interfaces, invocation map, call graph | M | No DEX parser beyond headers |
| Annotation extraction | PI | Marker-level only (e.g. metadata presence) |
| String/resource reference mapping | M | Strings scanned globally, not mapped to referencing classes |
| Reflection + dynamic loading detection | M | Not implemented |
| Native method mapping (DEX side) | M | Not implemented |
| Entry-point discovery | PI | Manifest entry points via perms; no DEX-level entry analysis |
| jadx / apktool adapters with version checks | PI | Doctor verifies jadx starts; scripts do not wrap jadx/apktool |
| baksmali/smali integration | M | Present on host, unused by the skill |
| CFR / Procyon / dex2jar | M | Absent on host; no adapter |
| Kotlin intelligence (coroutines, Flow, serialization…) | PI | Coroutines marker exists; no structured Kotlin feature inventory |
| Obfuscation intelligence (R8/ProGuard, renaming stats) | IT | Triage obfuscation category (short-name share, stripping residue) |
| String encryption / control-flow obfuscation detection | PI | Labeled no-reliable-marker in guide; heuristics not implemented |
| Semantic rename suggestions (inferred) | M | Not implemented |

## §5 Game engine adapters

| Requirement | Status | Where / gap |
|---|---|---|
| Unity: version, Mono/IL2CPP, metadata, dump summary | IT | `nar-il2cpp.py` + triage |
| Unity: AssetBundle/Addressables inventory | PI | Bundle files counted; no per-bundle object inventory (UnityPy optional in 2.0) |
| Unity: texture/audio/scene/prefab discovery | M | Not implemented (depends on asset parsing) |
| Unreal: version, pak inventory, config | IT | Triage + `nar-pak.py` |
| Unreal: IoStore, UAsset/UExport inspection | M | No IoStore support; UAssetAPI/FModel absent on host |
| Godot: PCK, versions, file inventory, encryption | IT | `nar-godot.py` |
| Godot: GDScript/scene/texture/audio categorization | PI | File listing exists; categorization by type partial in guide only |
| Flutter: AOT, assets, symbols, metadata | PI | Versions + markers; no asset inventory or symbol pass |
| React Native: Hermes, bundle, source maps, native modules | PI | Hermes deep parse exists; source-map and native-module discovery missing |
| Adapter interface (versions/formats/deps/stages/schema/limits/tests declared) | M | Scripts are uniform by convention, not by a declared adapter contract |

## §6 Native / ELF intelligence

| Requirement | Status | Where / gap |
|---|---|---|
| ELF32/64, ARM/ARM64/x86/x86_64 headers | IT | `elf_hardening_of()` header + program-header parse |
| Hardening posture, 16 KB alignment | IT | Triage native-hardening category, readelf-cross-verified |
| Imports/exports/dynamic symbols | M | Not implemented in any script |
| Sections/segments/dependencies (DT_NEEDED) | M | Not implemented |
| Build ID, debug symbols presence | PI | Stripped-ness via SHT_SYMTAB only |
| JNI exports + RegisterNatives mapping | M | Guide documents manual Ghidra flow; no script output |
| Compiler fingerprints | PI | Rust markers only |
| Ghidra/binutils integration | PI | Guides + doctor checks; no adapter producing normalized output |

## §7 Network intelligence

| Requirement | Status | Where / gap |
|---|---|---|
| URL/endpoint/IP/email extraction + ranking | IT | `nar-strings.py` classified groups |
| Endpoint classification taxonomy (confirmed/potential/third-party/unused/sensitive/unverified) | M | Groups exist; brief taxonomy not applied |
| Host inventory, API base URLs, WebSocket/GraphQL identification | M | Not separated from raw URL group |
| Firebase/Supabase configuration detection | M | Not implemented |
| Retrofit/OkHttp/Ktor client discovery | M | Not implemented |
| Network security config parsing (pinning, cleartext) | PI | Pin constants + NSC pin-sets detected as protections; no structured NSC report |
| `endpoints.json` / `network-analysis.json` / `api-architecture.json` | M | Not emitted |
| Dynamic observation (mitmproxy/tshark) | IU | Guides + tooling verified present; capture needs a device the lab lacks |
| Credential redaction by default | PI | Guide instructs; no tooling enforces |

## §8 Runtime / dynamic analysis

| Requirement | Status | Where / gap |
|---|---|---|
| Frida observation templates (Java/JNI/file/network) | IT | 4 scripts, syntax-checked in e2e; observation-only by construction |
| ADB adapter (discovery, versions, launch, logs) | M | Guide only; no module |
| Frida availability/version/device compatibility checks | PI | Doctor checks host CLI presence/version only |
| Behavior timeline generation | M | Not implemented |
| Runtime protection presence reporting | PI | Static RASP detection exists (triage); runtime confirmation needs a device |
| Device-dependent execution | IU | No device/emulator exists in this environment — cannot be tested here |

## §9 Security intelligence

| Requirement | Status | Where / gap |
|---|---|---|
| Manifest security (exported, debuggable, backup, cleartext, NSC) | PI | Facts audited by `nar-perms.py`; not expressed as findings |
| Storage security (prefs/SQLite/Room/WebView storage) | M | Guide-level only (dynamic guide) |
| Cryptography inventory (algorithms, weak configs, hardcoded keys) | PI | Key-pattern strings exist with not-proof caveat; no crypto inventory |
| WebView security checks | M | Not implemented |
| Finding schema (id/severity/confidence/evidence/impact/remediation…) | M | Not implemented |
| Severity scale + CVSS discipline | M | Not implemented |

## §10 Resource / asset intelligence

| Requirement | Status | Where / gap |
|---|---|---|
| Asset/res counting + bundle inventory | IT | Triage inventory |
| Typed inventory (image/audio/font/code…) with size + hash | M | Not implemented |
| Image dimensions metadata | M | Not implemented |
| Duplicate detection, large-asset detection | M | Not implemented |
| `assets.json` + export | M | Not implemented |

## §11 Version comparison

| Requirement | Status | Where / gap |
|---|---|---|
| Identity, versions, permissions, certs, DEX counts, hashes | IT | `nar-compare.py`, e2e-verified deltas |
| Class/method/string/resource/asset diffs | PI | Method totals only; no per-item diffs beyond files |
| Change categories + severity + similarity metrics | M | Not implemented |
| Endpoint/engine-version diffs | M | Not implemented |
| Build-noise filtering + limitations | PI | Limitations implicit; no noise model |

## §12 Orchestration

| Requirement | Status | Where / gap |
|---|---|---|
| One-command workup | IT | `nar-analyze.py` |
| Capability + tool registry (declared metadata) | M | Knowledge embedded per script |
| Execution planner / module selection | PI | Fixed pipeline in nar-analyze; engine routing is content-driven |
| Result normalization + evidence collection | PI | Per-script JSON; analyze merges ad hoc |
| Timeout handling | IT | Per-tool timeouts in analyze |
| Retry / recovery / partial execution | PI | Sections degrade with explicit errors; no retry policy |
| Resume / stage caching / cancellation | M | Not implemented |
| Execution logs | PI | stderr notes only; no structured execution log |

## §13 Evidence and reporting

| Requirement | Status | Where / gap |
|---|---|---|
| report.md + report.json | IT | nar-analyze |
| Companion JSON files (application/fingerprint/engine/dependencies/classes/methods/endpoints/permissions/security-findings/assets/comparison/execution-log) | M | Only the single merged report.json exists |
| Common finding schema with provenance/confidence/status | M | Not implemented |
| Observed vs derived vs inferred vs hypothesis separation | PI | Done in prose discipline + limitations; not in data schema |
| Schema validation of outputs | M | No schemas exist |
| Markdown rendering robustness | B | Raw JSON blobs observed in one wide-sweep report's strings section |

## §14 Unified CLI

| Requirement | Status | Where / gap |
|---|---|---|
| `nar info/analyze/compare/permissions/endpoints/assets/security/runtime/tools/doctor/report` | M | No `nar` entry point; twelve script CLIs instead |
| Profiles (quick/full), `--engine`, `--module` selection | M | Not implemented |
| Help, validation, exit codes, JSON output | PI | True per-script; not unified |
| Backward compatibility | IT | Existing script CLIs are the compatibility surface to preserve |

## §15 HTML dashboard

| Requirement | Status | Where / gap |
|---|---|---|
| Offline single-purpose dashboard (15 sections, themes, search/filter/sort, exports) | M | Not implemented |

## §16 Skill intelligence / references

| Requirement | Status | Where / gap |
|---|---|---|
| SKILL.md routing, evidence discipline, resume guidance | IT | SKILL.md (229 lines) |
| Reference set | PI | 17 guides cover most §16 topics under established names; architecture, tool-registry, output-schema, safety-and-authorization, troubleshooting references are missing |
| Docs match implementation | IT | Verified at audit; must be re-verified after 2.0 changes |

## §17 Case workspace

| Requirement | Status | Where / gap |
|---|---|---|
| Case ID, hashes, config, stage states, tool versions, history | M | Not implemented |
| Resume + unchanged-input skipping | M | Not implemented |

## §18 Multi-agent architecture

| Requirement | Status | Where / gap |
|---|---|---|
| Model-agnostic, subagent-friendly decomposition | PI | Scripts are independently invocable (de facto); roles not documented as an architecture |

## §19 Dependency management

| Requirement | Status | Where / gap |
|---|---|---|
| Doctor: OS/Python/Java/SDK/tools with version + compatibility + required/optional + path + guidance | IT | `nar-doctor.sh` incl. real-start jadx verification |
| Engine-specific tool checks (Unity/Unreal/Godot) | PI | il2cppdumper/godotpcktool/gdre/hermes-dec checked; no per-engine grouping |
| Installation profiles (minimal/standard/full/game/security) | M | Not implemented |
| No unverified auto-downloads | IT | Doctor never downloads anything |

## §20 Performance / scalability

| Requirement | Status | Where / gap |
|---|---|---|
| Streaming reads, scan budgets | IT | Rust scan budget, chunked hashing, DEX parse caps in triage |
| Concurrency, caching, progress, cleanup | PI | Sequential by design; temp work dirs are caller-managed |

## §21 Testing / benchmarking

| Requirement | Status | Where / gap |
|---|---|---|
| E2E harness over real + purpose-built fixtures | IT | `tests/run_e2e.sh`, 34 cases green at audit |
| Unit tests | M | None |
| Integration tests with real external tools | PI | Inside e2e cases (dumper, hermes-dec, GodotPckTool cross-checks) |
| Benchmark metrics + methodology | M | No benchmark suite or published metrics |
| Invalid/corrupt input cases | PI | Bad-ZIP path exists in triage; not in the harness |

## §22 CI/CD / release engineering

| Requirement | Status | Where / gap |
|---|---|---|
| GitHub Actions (test/lint/type/security/schema/docs) | M | No workflows exist |
| pyproject.toml / lock strategy | M | Absent (scripts are intentionally stdlib-only; packaging metadata still required by the brief) |
| Versioned releases + changelog + compatibility matrix | PI | Changelog disciplined; no compatibility matrix document |

## 2.1.0 status addendum (2026-11-23)

The tables above remain the Phase-Zero audit of v1.1.0 —
a historical baseline, not edited. The 2.0 program closed
most rows (see NAR_IMPLEMENTATION_PLAN.md and the 2.0.0
test matrix). The 2.1.0 gap-closure cycle moved these
further; evidence in NAR_TEST_MATRIX.md (2.1.0 addendum):

- §22 GitHub Actions: the workflow exists (added with
  2.0.0) and has EXECUTED on GitHub Actions — 3 runs,
  all successful. Row status now IT.
- §3.1 Unreal IoStore: entry-level parsing shipped
  (narlib/iostore, two layout eras, directory index,
  chunk inventory + None/Zlib extraction in nar-unreal
  and nar-analyze). Row status now IT for chunk-level
  inventory; UAsset/UExport-level inspection (§13)
  remains PI — FModel/UAssetAPI are still absent on the
  host, registered unavailable, never faked.
- §11 IL2CPP tooling: Cpp2IL integrated as an optional
  second backend (probed registry entry, doctor probe,
  ECMA-335-lite summary); Il2CppDumper remains default.
- §20 Performance: nar-dex ~1.9x on the 273 MB fixture
  (emission + scan); the same cycle fixed a field
  enumeration defect the equivalence proof exposed.
- Runtime rows (§16): UNCHANGED at
  IMPLEMENTED_BUT_UNVERIFIED. The 2.1.0 emulator attempt
  was blocked by the host (no /dev/kvm; the API-34 image
  never reached boot completion under QEMU TCG inside
  the time box). A KVM-capable host or a physical device
  is required to move these rows.
