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

### Post-2.1.0 addendum — runtime verification (2026-11-23)

The §16 runtime rows moved, on emulator evidence only:
a lean API 26 (Android 8.0.0) google_apis x86_64 image
booted to completion under the same QEMU TCG conditions
that defeated the API-34 image, and the full runtime
workflow ran against it — adb discovery/inspection,
install and launch of the demo fixture, nar-runtime
status reporting verified-live, frida-server 17.27.4 as
root, and the bundled network-observe and file-io-observe
scripts attached to the live demo process with all hooks
installed. The adb and Frida-attach rows are therefore
IMPLEMENTED_AND_TESTED (emulator scope). Still
IMPLEMENTED_BUT_UNVERIFIED at that point: every
physical-device row, and Frida spawn mode, which
repeatedly lost its session during script load under TCG.

A follow-up attempt the same day (2026-11-23) closed the
spawn row as well. The failures were root-caused from
logcat: Android's ActivityManager kills a started process
that does not attach within its ~10 s process-start
timeout, and a Frida-gated spawn child cannot attach
while gated — under TCG the load-before-resume sequence
always loses that race. With the verified recipe —
spawn via the Frida API, resume in the very next call,
let the process settle, then load the bundled script
with the standard CLI path against the spawned pid —
both observation scripts ran live in Frida-spawned
processes, so the spawn row is also
IMPLEMENTED_AND_TESTED (emulator scope, hybrid recipe;
the one-command load-while-gated form remains unusable
under TCG). Every physical-device row stays
IMPLEMENTED_BUT_UNVERIFIED. Evidence is summarized in
the matching NAR_TEST_MATRIX.md addenda.

## Unreleased status addendum (2026-11-23)

- §3.1 / §13 Unreal UAsset-level inspection: SHIPPED as
  narlib/uasset (original implementation of the public
  package layout) — FPackageFileSummary with UE4/UE5
  version gating, name / import / export / depends
  tables with resolved references, soft package
  references, UE5 soft object paths, searchable names,
  cooked .uexp/.ubulk awareness, and a best-effort
  FPropertyTag reader (primitive values, struct
  recursion, per-export confidence note). nar-unreal
  parses packages loose, in IoStore containers, and in
  .pak files under --work; nar-analyze lifts summaries
  into the engine companions. FModel/UAssetAPI remain
  registered unavailable — they are no longer the
  blocker for package inspection. What remains out of
  scope, stated plainly: class-specific export data
  decoding (meshes, textures, Blueprints as object
  graphs), property reading for PKG_UnversionedProperties
  packages (needs a .usmap), and the UE5 tag-extension
  layouts (object version >= 1011). Verification:
  synthetic byte-exact fixtures (unit suite + harness)
  plus a real-asset rung over a locally held cooked
  UE4-era corpus, including independent manual spec
  accounting on one small package — see
  NAR_TEST_MATRIX.md (unreleased addendum).

### Close-all-gaps addendum (2026-11-23)

- Runtime rows (§8/§16): all four bundled Frida scripts
  have now executed live (emulator scope) — jni-trace.js
  and java-api-trace.js joined network-observe.js and
  file-io-observe.js. jni-trace installed its
  RegisterNatives hook in both attach mode and a
  Frida-spawned process (resume-first recipe); no
  registration/entry events were recorded because the
  demo fixture's native library binds its method
  statically, so the RegisterNatives event path remains
  the one runtime sub-path without a live event, and it
  is labeled as such. java-api-trace installed both
  URL.openConnection hooks and captured one genuine
  call/return pair, recorded honestly as REPL-triggered
  (the fixture's own code never calls the traced
  method). Physical-device rows remain
  IMPLEMENTED_BUT_UNVERIFIED.
- Compiled artifacts (§1 bare-container row): OAT, VDEX,
  ODEX, CDEX, and ART identification and parsing are now
  implemented in narlib (OatHeader + key-value store,
  VDEX field parse and byte-exact DEX carving, Dalvik
  ODEX parse/carve, ART image header) and nar-dex takes
  compiled artifacts as first-class targets. Verified on
  real API 26 files (app .odex = OAT 124, companion
  .vdex = VDEX 006 with its DEX 037 fully parsed, boot
  .oat/.art). Still labeled synthetic-only: Dalvik-era
  ODEX on a real file, CDEX on a real file (compact-DEX
  decoding remains unimplemented and is reported
  honestly), VDEX versions beyond 006 field parsing,
  and OAT from other releases/instruction sets.
- Godot encrypted packs: CLOSED at REAL level. An
  encrypted pack written by a real engine pack writer
  with a 256-bit key is detected and reported as
  encrypted with the listing honestly unavailable
  (detection only — no decryption capability exists
  anywhere in the skill). The same cycle fixed format 3
  (Godot 4.5+) directory-at-end parsing, which had
  silently reported "Files: 0", and made format 4
  headers report facts + encryption flag with the
  listing marked unsupported. Regression coverage in
  tests/unit/test_godot.py.
- Mega sweep (close-all-gaps): the full pipeline ran
  over 75 local targets; six defects were found and
  fixed in-cycle (native-stage crash on ZIP payloads
  named as libraries, IL2CPP split-pair reporting and
  a silent split-base skip, legacy versioned Cordova
  runtime detection, Ren'Py/RPG Maker scoring, .apks
  container routing). Engine-detection rows for
  Cordova/PhoneGap and Ren'Py/RPG Maker move from
  partial to implemented-and-tested at the fixture +
  real-target level recorded in NAR_TEST_MATRIX.md.
  Wear OS / APEX / instant-app rows are unchanged: no
  sample was obtainable, and they stay labeled
  unexercised rather than claimed.
- Unreal IoStore (§3.1): now IMPLEMENTED_AND_TESTED at
  real-set level — a complete, unsealed UE 5.3 game's
  container set (global container + one chunk container,
  TOC v5, 7,171 chunks) parses end to end: TOC,
  directory index, stored-chunk extraction, and the
  nar-unreal / nar-analyze routes. The rung found and
  fixed a real defect: the directory index exists in a
  second, pooled name-index layout (UE 5.3-era
  packagers) that the parser silently dropped; both
  layouts are now read under exact-consumption +
  complete-walk validation, with an independent
  byte-walk oracle agreeing on all 6,743 named files.
  A second real set, from a TOC v8 container (the
  newest TOC generation, 14,867 chunks), is now also
  parsed end to end including its directory index
  (674 directories, 13,494 files): the v8 writers
  kept the pooled layout unchanged, but the
  flattening walk itself had to be fixed — it
  counted sibling hops against its depth bound and
  dropped wide trees as unreadable. Sibling chains
  are now walked iteratively with the bound on true
  nesting depth only; the v8 result is verified
  path-for-path against an independent oracle, and
  the UE 5.3 set's flattened map is unchanged.
- Unreal packages (§13): the same set's cooked
  packages are Zen-format (the IoStore-native package
  format), not classic FPackageFileSummary packages —
  identified and inventoried as such (684 of 684
  stored package chunks carry the Zen trailer trait).
  Zen package parsing is now IMPLEMENTED (narlib.zen):
  the Zen header in its current, pre-5.3 and Early
  Access legacy layouts, versioning info when the
  writer recorded it, the per-package name map, the
  bulk data map, imported public export hashes, the
  import/export maps and the export bundle entries,
  with references resolved through the package's own
  name map; sections no public reader decodes are
  located and measured, and export payloads are
  located and measured under the same honesty rules
  as classic packages. Verification status: the
  parser is verified on byte-exact synthetic
  fixtures with regression tests
  (tests/unit/test_zen.py) AND on the real set —
  the sweep over all 684 stored chunks (run with
  the owner's explicit go-ahead after an
  execution-risk flag had stopped corpus processing
  in the implementing session) parses 684/684 in
  full, and an independent byte-walk oracle on one
  real package agrees on 45/45 field checks. The
  sweep found and fixed one defect the fixtures had
  hidden (a forward export reference crashed the
  reference pass with a raw KeyError; the export
  parse is now two-pass, with a regression test).
  All 684 chunks use the current header layout and
  record no versioning info, so the pre-5.3 and
  Early Access layouts and recorded versioning info
  remain synthetic-verified only. Zen headers record no
  UE4/UE5 object version unless versioning info was
  recorded, so the one remaining Unreal row is
  unchanged in substance and sharper in definition: a
  real classic-format UE5 package whose summary
  records FileVersionUE5 1000+ is still unproven —
  every real UE5 title examined so far ships either
  sealed containers or Zen packages.
  A second real Zen corpus (a 2025-era indie UE5
  horror title, TOC v8 containers) has since been
  swept: all 525 stored package chunks are Zen, the
  title's classic pak holds no packages at all, and
  the sweep exposed a newer-writer Zen variant the
  parser had never seen — a count-prefixed byte array
  ahead of the bulk data map — which had made every
  one of the 525 fail; it is now parsed under the
  same exact-landing acceptance rule, with the array
  located and measured, and the corpus parses
  525/525 with an independent byte-walk oracle
  agreeing 20/20 on one real package (full record
  in NAR_TEST_MATRIX.md). The versioned-classic row
  stands exactly as defined above: across five real
  UE5 titles examined in this program — one sealed,
  one classic-but-version-stripped, three Zen-native
  — no shipped title has yet provided a classic
  package with a recorded FileVersionUE5.

## Evolution Phase 0 reconciliation (2026-11-24)

The tables at the top of this document are the v1.1.0
Phase-Zero audit and the dated addenda below them track
each release; several addenda supersede each other (the
2.1.0 addendum's runtime paragraph is superseded by the
post-2.1.0 runtime addenda; its §13 "UAsset remains PI"
note is superseded by the unreleased UAsset addendum).
This reconciliation supersedes all of them where they
conflict. It was produced by re-reading the shipped
v2.4.0 tree and executing the baseline (pytest 144/144,
e2e 47/47 with 0 skipped, doctor READY, 23/23 CLI
`--help` exit 0, one full orchestrated case + cache
re-run). Statuses use the exact evolution vocabulary:
IMPLEMENTED_AND_TESTED (IT), IMPLEMENTED_BUT_UNVERIFIED
(IU), PARTIALLY_IMPLEMENTED (PI), PLANNED (PL), MISSING
(M), BROKEN (B), UNSUPPORTED (US), NOT_APPLICABLE (NA).

| Area | Status | Evidence (executed or grep-verified, 2026-11-24) |
|---|---|---|
| Universal input intelligence | IT | narlib/formats.py magic+structure ID over the full input list; nar-input identify/validate/extract/duplicates; narlib/safearchive.py guards (slip/traversal/symlink/bomb/nesting/size) with planted-case unit tests; OAT/VDEX/ODEX/ART are first-class inputs since 2.4.0 |
| Application fingerprinting | IT | nar-fingerprint.py: normalized properties each with provenance + confidence + fact class; fingerprint.json schema-validated in case runs. Named-file divergence: the brief's five files (application/manifest/native-inventory/frameworks + fingerprint) ship as one fingerprint.json + report sections — content present, names differ (plan Phase 2) |
| Android internals (manifest, resources, permissions, signing) | IT | nar-perms.py own AXML parser with aapt2 cross-check; triage signature-scheme inventory (v1–v4), form factors, split/container handling; e2e cases green |
| DEX / bytecode | PI | IT core: narlib/dex.py enumeration, hierarchies, call edges, reflection/dynamic-loading/native evidence; narlib/dexdis.py full disassembler (oracle: 40,837 methods, 0 mismatches). Missing: try/catch handler tables, debug info, control-flow graphs |
| Java / Kotlin intelligence | PI | nar-dex Kotlin inventory (coroutines, Flow/StateFlow, serialization, data/sealed/companion labeled inferred); jadx + baksmali adapters version-checked. CFR/Procyon/dex2jar registered unavailable, never integrated; no Kotlin-metadata (@Metadata) parse; no rename suggestions |
| Native binary analysis | PI | IT core: narlib/elf.py headers/sections/segments/dynamic/symbols/DT_NEEDED/Build ID/hardening + dependency graph, readelf cross-check. Missing: relocation tables; compiler fingerprints beyond Rust markers |
| JNI intelligence (static) | IT | nar-native JNI export map joined with nar-dex native-method declarations; unit + e2e coverage. The runtime RegisterNatives event path is counted under Runtime, not here |
| Unity | PI | IT core: IL2CPP location + Il2CppDumper summary, Cpp2IL optional second backend, metadata versions. Partial: Mono is inventory-level; AssetBundle object census only via optional UnityPy; Addressables is a catalog-presence flag, no catalog parse; no scene/prefab/material semantic inventory |
| Unreal | PI | IT core: nar-pak incl. v10/v11 encoded index; narlib/iostore TOC v5 + v8, both directory-index layouts, real-set verified (7,171 chunks; 13,494 files); narlib/zen on 1,209 real packages; narlib/uasset summary/tables + best-effort property tags on a real UE4 corpus. Missing/unproven: Kismet/Blueprint graph decoding; UE5 tag-extension layouts (object version >= 1011); a real classic package with recorded FileVersionUE5 (evidence-negative over five titles — open by evidence) |
| Godot | PI | IT core: nar-godot pack formats 3/4, encrypted-pack detection verified on a real encrypted pack, per-file encrypted marks, GodotPckTool cross-check. Partial: resource/scene classification is listing-level; GDScript bytecode is GDRE-orchestrated, not parsed |
| Flutter / Dart | PI | nar-flutter versions + AOT markers, e2e positive/negative. Missing: snapshot/VM structure parsing, symbol recovery, plugin/native-channel inventory; assets are a presence flag |
| React Native | PI | nar-rn Hermes/JSC decision + Hermes header parse, hermes-dec cross-check. Missing: source maps, native-module / TurboModule / Fabric inventory |
| Other frameworks (detection) | IT | nar-engines fusion over 18 families with confidence + ambiguity reporting; Cordova/PhoneGap and Ren'Py/RPG Maker rows moved to tested by the 2.4.0 mega-sweep; Xamarin/.NET via narlib/dotnetmeta. Deep dives beyond detection do not exist for these families, by design |
| Protection / obfuscation detection | PI | IT core: triage 7-category taxonomy, named packers under attribution discipline, zero false positives on clean sets (e2e + protection fixtures), RASP/pinning/DRM/encryption categories. Missing: a versioned signature-database artifact (signatures are code-embedded) |
| Network intelligence | PI | IT core: nar-network classified endpoint taxonomy, hosts, services, NSC structured parse, client-library evidence. Missing: credential/token redaction pass in tooling (guide-level only); the three brief-named documents ship as one endpoints document; dynamic capture IU (device) |
| Runtime / dynamic analysis | PI | Emulator scope IT: adb + install/launch + all four Frida scripts executed live, attach and spawn (API 26, 2026-11-23). IU: every physical-device row; the jni-trace RegisterNatives event path (hooks install live; no event — the fixture binds statically); java-api-trace app-triggered events (one REPL-triggered pair only). Session persistence is plan/timeline level, not a stored session record |
| Security intelligence | IT | nar-security NAR-SEC findings (id/severity/confidence/evidence/impact/remediation/false-positive notes), schema-validated; known-findings fixture + clean fixture e2e cases. CVSS deliberately not computed (facts rarely support it; documented) |
| Asset intelligence | PI | IT core: nar-assets typed inventory, hashes, image dimensions, duplicates, large assets, container cross-reference. Missing: audio metadata; dependency graphs (relationships are cross-references) |
| Version comparison | PI | IT core: nar-compare extended diffs (classes/methods/strings/endpoints/assets/security/engine) + severity + similarity, planted-pair verified. Missing: feature-map.json / version-diff.md as named artifacts; >2-version comparison |
| Evidence + correlation | PI | IT core: narlib/evidence.py envelope (tool+version, source, offset/location, timestamp, confidence, fact class) + 11 schemas + stdlib validator. Missing: verification-status vocabulary as a field; a correlation engine/records; derived-evidence de-duplication |
| Orchestration | PI | IT core: nar-analyze case workspace, registry-driven stages, hash-keyed cache + resume (verified in this pass: 7 cached / 3 ok on re-run), execution log, partial-result degradation. Missing: adaptive planning, execution budgets, retry/cancellation policy |
| Tool registry | IT | scripts/registry.json: 35 tools declared with probes + limitations; 9 registered unavailable (il2cppinspector, assetripper, uabea, unrealpak, fmodel, uassetapi, cfr, procyon, dex2jar), never faked; test_registry.py + doctor consistency. Noted risk: nar-doctor.sh is a parallel bash implementation kept consistent by test, not by construction |
| Reporting | PI | IT core: report.md/json + offline HTML dashboard (zero external references asserted by e2e), companion set as documented in references/output-schema.md. Missing: dependency-graph rendering in the dashboard (graph data ships in native.json only) |
| Unified CLI | PI | 23 subcommands, all help-clean with consistent exit codes (verified in this pass); 1.x standalone CLIs unchanged. Missing as commands: tools, benchmark, case, validate, identify, info (functions reachable via doctor / nar input / tests runner) |
| AI skill interface | IT | SKILL.md routing covers every module; frontmatter valid; version consistent across skill.yaml / SKILL.md / plugin.json / pyproject / README (grep-verified 2.4.0); install routes documented for Claude Code, Codex, Cursor, Muse; no MCP dependency |
| Testing / benchmarks | PI | IT core: pytest 144 + e2e 47 executed in this pass; security-guard unit tests (planted archives, malformed inputs). Partial: benchmarks runner measures wall-times only — no accuracy / precision / recall / FP / FN metrics; no memory metrics; no fuzz corpus |
| Documentation | PI | 22 reference guides + 5 program documents; architecture/registry/schema/safety/troubleshooting guides exist and match code. BROKEN item: README repo-structure block describes the 1.x layout (17 guides, no 2.0 modules). Minor: "NAR 2.0" headline branding at version 2.4.0 in README + pyproject |
| Packaging / distribution | IT | pyproject (stdlib-only core, optional extras), plugin manifest, per-release ZIP, GitHub Release v2.4.0 published; CI executed green on GitHub for the current workflow scope |
| Extensibility | PI | narlib shared core + registry-declared tools + uniform script conventions. Missing: a formal adapter/plugin contract, capability negotiation, a versioned signature database |

Environment-blocked rows (no code change moves them):
physical-device runtime (IU — no device attached);
CI workflow edits + execution (workflows permission is
absent on the release push path; execution happens on
GitHub, on push, and this program does not push);
Oodle (US — proprietary SDK, refused by name);
versioned classic UE5 package on real data (open by
evidence over five titles); Zen pre-5.3/EA layouts and
recorded Zen versioning on real data (no obtainable
sample); OAT beyond API 26 x86_64, real Dalvik-ODEX and
CDEX files (synthetic level; CDEX payload identified,
not decoded); Wear OS / APEX / instant-app samples
(unexercised, labeled as such in-product).

## Evolution Phase 1 addendum (2026-11-24) — core reliability

Documentation row moves from PARTIALLY_IMPLEMENTED (with
a BROKEN item) to IMPLEMENTED_AND_TESTED for the audited
defects: the README repo-structure block now describes the
real 2.4.0 layout (22 guides, all 2.0 modules + narlib,
tests/unit + tests/benchmarks), and a new automated guard
(tests/unit/test_docs_consistency.py) asserts the block
names every file in scripts/, scripts/narlib/,
scripts/frida/, references/ and schemas/, that the stated
guide count equals the tree, and that every SKILL.md
routing target exists. Version consistency is now guarded
by unit test across all 18 version-bearing locations,
including a planted-mismatch case. The README/pyproject
"NAR 2.0" headline divergence is resolved by removing the
version number from the brand headline entirely (recorded
in NAR_IMPLEMENTATION_PLAN.md, Phase 1 record). The
nar-doctor compile check no longer leaves `__pycache__`
in the tree (compiles into a temp dir; verified clean
after a run). Battery after this phase: pytest 154/154,
e2e 47/47, doctor READY.

## Evolution Phase 2 addendum (2026-11-24) — input + fingerprinting

Application fingerprinting stays IMPLEMENTED_AND_TESTED
and gains compile_sdk (parsed from the aapt2 badging
package line by nar-triage, reported by nar-fingerprint
with provenance; absence remains an explicit note — the
AAB/container identity paths do not expose it). The
named-file divergence recorded in Phase 0 is closed:
nar-analyze emits application.json, manifest.json,
native-inventory.json and frameworks.json beside the
existing companions, projected from the same run's stage
data by narlib/companions.py and schema-validated before
writing (four new schemas ship in schemas/); the existing
companion set is unchanged. Universal input intelligence
stays IMPLEMENTED_AND_TESTED and gains AAR/JAR structural
summaries in nar-input validate (entry/class counts,
manifest presence; AAR layout facts incl. the classes.jar
class count), covered by planted-fixture unit tests.
Battery after this phase: pytest 165/165, e2e 49/49, doctor READY;
e2e analyze cases assert the companion set in both runs.

## Evolution Phase 3 addendum (2026-11-24) — Android intelligence

DEX / bytecode moves from PARTIALLY_IMPLEMENTED toward
IMPLEMENTED_AND_TESTED for the audited sub-gaps: try/catch
handler tables and debug-info presence are parsed
(narlib.dex.code_item_info) and reported per DEX by
nar-dex, cross-checked exactly against SDK dexdump on a
real corpus DEX (484 methods with tries, 1,178 try items,
1,357 handler entries — all three counts agree);
narlib.dexdis gains a control-flow block summary
(boundaries + branch edges + try ranges) with the
disassembler oracle re-run at FULL AGREEMENT (230,836
instructions, 0 mismatches), so listings are unchanged.
Full control-flow graph rendering and debug line/local
decoding remain unimplemented (presence and boundaries
only). Java / Kotlin intelligence gains @Metadata payload
parsing (metadata version + declaration kind per class)
on top of the existing inventory: verified on a real
Kotlin corpus fixture (10,213 annotations; versions
1.8.0 / 2.2.0 dominant). Two defects were found and fixed
in-phase (encoded-value index encoding; the @Metadata
string-table gate) — see the Phase 3 record in
NAR_IMPLEMENTATION_PLAN.md. Native binary analysis gains
relocation parsing (cross-checked against readelf -r:
section counts and PLT/GOT subset agree; one AArch64
type number corrected from readelf's evidence) and
.comment-based Clang/GCC compiler fingerprints as
OBSERVED evidence; stripped binaries claim neither.
Battery after this phase: pytest 171/171, doctor READY.

## Evolution Phase 4 addendum (2026-11-24) — engine intelligence

Unity intelligence gains the Addressables catalog
inventory in nar-unity (locations / providers / resource
types / decoded entry table, fields claimed only where
range-validated against the catalog's own tables) —
IMPLEMENTED_AND_TESTED on a real catalog (6,798
locations, 24,820 entries) plus a synthetic catalog.
React Native gains source-map detection and a
native-module inventory: IMPLEMENTED_AND_TESTED for
text bundles (planted call sites) and for Hermes
architecture markers on a real fixture; Hermes module
NAME attribution is PARTIALLY_IMPLEMENTED by design
boundary (string-table entries cannot be attributed to
call sites without bytecode reference analysis — the
report states this). Flutter gains the real
flutter_assets inventory (IMPLEMENTED_AND_TESTED: 370
typed entries on the fixture; JSON AssetManifest keys
counted, the binary manifest reported as present only).
Godot listings gain resource-type classification with
labeled evidence (header > extension; encrypted entries
never typed) — IMPLEMENTED_AND_TESTED on the real pack
plus synthetic packs. Unreal classic-package property
parsing gains the UE5 tag-extension layouts: 1011
extension tail and 1012+ complete type names are
IMPLEMENTED_BUT_UNVERIFIED against real samples —
verified on synthetic packages built to the documented
format and labeled synthetic in parser output and docs,
because no real package with a recorded UE5 version
>= 1011 exists in the corpus (evidence-negative for
real samples, same finding as 2.4.0). Kismet/Blueprint
graph decoding remains PLANNED. Battery after this
phase: pytest 178/178, doctor READY.

## Evolution Phase 5 addendum (2026-11-24) — protection + network

Protection / obfuscation detection: the "missing"
item from Phase 0 is closed — the signatures now ship
as a versioned database artifact
(scripts/protection-signatures.json, database_version
1.0.0, schema 1) with a validating loader
(narlib/signatures.py) and doctor visibility (a core
protection-signatures check). Behavioral equivalence
with the code-embedded set is proven by a pinned
canonical digest and byte-identical triage output on
the protection fixtures; the e2e protection cases
(named-on-doctored, zero false positives on the clean
set, Widevine compiled-UUID) pass unchanged. The row
moves to IMPLEMENTED_AND_TESTED for the database
artifact; detection coverage itself is unchanged.
Network intelligence: the credential/token redaction
pass is implemented in nar-network (endpoint URLs
redacted at the source, counts reported, raw values
never written to case outputs) — IMPLEMENTED_AND_TESTED
with a planted-fixture acceptance (5 planted values,
count 5, no secret substring in the report). The three
brief-named network documents now ship: endpoints.json
plus the network-analysis.json and api-architecture.json
companions, schema-validated in case runs. Battery
after this phase: pytest 194/194, e2e 52/52, doctor READY.

## Evolution Phase 6 addendum (2026-11-24) — runtime + security

Dynamic analysis: the last unverified Frida event path
is closed. jni-trace's RegisterNatives events were
captured LIVE on the API 26 emulator (Frida 17.27.4)
against a purpose-built demo variant whose library
registers dynamically via RegisterNatives in JNI_OnLoad:
attach mode produced the full chain (class line,
per-method line with resolved symbol, [jni-entry] call
trace, logcat corroboration that the registered method
ran); spawn mode produced the class-level event. The
row moves to IMPLEMENTED_AND_TESTED for the emulator
environment; a physical-device session remains NOT RUN
(owner's device only). The live run found and fixed a
real defect (Frida 17 removed the Memory.readPointer /
readUtf8String statics the per-method read used).
Runtime sessions: plan/status flows now persist
structured session records (runtime-session.json,
schema-validated; device identity, tool probes,
start/stop, events, evidence paths, errors) with the
honest verification label carried unchanged —
IMPLEMENTED_AND_TESTED offline + one live-recorded
session. Security intelligence: findings carry
verification_status from the Phase 8 vocabulary
(schema + make_finding + per-rule assignment in
nar-security); legacy findings without the field still
validate — IMPLEMENTED_AND_TESTED. Battery after this
phase: pytest 202/202, e2e 52/52, doctor READY.

## Evolution Phase 7 addendum (2026-11-24) — assets + comparison

Asset inventory: audio entries now carry header-parsed
metadata (WAV / OGG Vorbis+Opus / MP3: channels, sample
rate, duration where the header makes it computable —
Xing frame count or a labeled CBR estimate for MP3,
final-page granule for OGG); formats outside the
measured set report unmeasured with the reason. The
Phase 0 "no audio metadata" gap is closed —
IMPLEMENTED_AND_TESTED on synthetic known-header
fixtures. Version comparison: nar-compare --out emits
the three named artifacts (comparison.json,
feature-map.json schema-validated projection,
version-diff.md) with a labeled-heuristic build-noise
separation of signing churn from content changes —
IMPLEMENTED_AND_TESTED (planted-pair e2e asserts the
files + key deltas). The phase also fixed a latent
defect that made the extended endpoint diff report
0/0 unconditionally (group dicts iterated instead of
their hit lists); the planted pair's real endpoint
change now surfaces. Battery after this phase:
pytest 213/213, e2e 53/53, doctor READY.

## Evolution Phase 8 addendum (2026-11-24) — evidence + orchestration

Evidence model: the verification-status vocabulary is
now wired through findings (Phase 6), fingerprint
properties (fact-class mapping in narlib.evidence), and
correlation entries, with schemas updated and legacy
documents still validating — IMPLEMENTED_AND_TESTED,
including a 13-document full-case schema sweep.
Cross-module correlation records (the Phase 0 "no
explicit correlation" gap) now ship as the
correlations.json companion in every case run: JNI
declarations↔exports, components↔entry points,
endpoints↔referencing classes, network libraries↔DEX
presence, with same-evidence deduplication stated and
implemented — IMPLEMENTED_AND_TESTED (demo fixture:
known JNI pair matched/CONFIRMED; fabricated set pins
declaration-only + export-only). Orchestration: the
previously hardcoded-timeout runner now enforces
configurable per-stage + total budgets, recorded as
budget-exceeded stops in the execution log and case
config — IMPLEMENTED_AND_TESTED. Case portability:
export/import/verify with a hash manifest and cache
integrity keys — IMPLEMENTED_AND_TESTED (round-trip +
tamper e2e). Battery after this phase: pytest 220/220,
e2e 55/55, doctor READY. Phases 5–8 of the evolution
program are complete; the branch remains local and
unpublished per the program rule.

## Evolution Phase 9 addendum (2026-11-24) — reporting + CLI

Reporting: the Phase 0 "no dependency-graph rendering"
gap is closed — the offline dashboard renders
native.json's dependency graph as an inline SVG
section (deterministic layered layout, escaped
labels, internal fragment references only, zero
external references asserted by unit test and e2e;
graphs over 120 libraries truncate with a note, the
full graph stays in native.json). The row moves to
IMPLEMENTED_AND_TESTED for the audited gap. Unified
CLI: the Phase 0 "missing as commands" list is
closed — `nar tools` (registry view, new
nar-tools.py over narlib.registry probes),
`nar identify` / `nar validate` (nar-input prefix
aliases), `nar benchmark` (the benchmark runner),
and `nar case` (export/import/verify routing) ship
with --help, JSON where the family has it, unit
tests, and e2e smokes; the 23 existing verbs are
untouched pass-throughs. (`nar info` from the
Phase 0 list was not added: no distinct capability
backs it — identity is `nar version` + triage —
and the program rule is no verb without a real
implementation behind it.) The row moves to
IMPLEMENTED_AND_TESTED. Battery after this phase:
pytest 229/229, e2e 65/65, doctor READY.

## Evolution Phase 10 addendum (2026-11-24) — skill + integrations

Skill quality: SKILL.md routing now covers everything
Phases 1–9 added (companions incl. correlations.json,
redaction, signature DB, the five new CLI verbs,
budgets, case ops, session records, audio metadata,
compare artifacts, Addressables, RN source maps,
Flutter assets, Godot resource types, DEX try/catch +
@Metadata, ELF relocations). The Phase 0-deferred full
guide-vs-code audit is executed: 0 missing link
targets, 0 missing script files, 0 misattributed nar
flags (line- and block-level), 0 unknown nar verbs;
51 unattributed flag tokens all dispositioned as
external-tool flags in named-tool contexts; 1 stale
capability claim fixed (DEX guide scope limit); 2
discoverability gaps closed (session records in the
dynamic-analysis guide, `nar tools` in the
tool-registry guide). The audit's durable checks are
unit tests now, including programmatic frontmatter +
plugin.json validation. The row moves to
IMPLEMENTED_AND_TESTED. Registry: unchanged in
Phases 9–10 (no tool status changed); consistency
tests green. Battery after this phase: pytest
234/234, e2e 65/65, doctor READY.

## Evolution Phase 11 addendum (2026-11-24) — testing + benchmarks

Testing: the Phase 0 "no accuracy metrics, no
benchmarks beyond wall-times, no mutation corpus" gap
is closed. The benchmark runner computes, from the
labeled local corpora (role labels only; synthetic
and real separate): protection attribution precision
1.0 / recall 1.0, 0 FP on the 9-fixture clean set
(real); engine-detection recall 1.0 on 6 labeled real
fixtures; engine accuracy 1.0 on the 8-fixture
synthetic framework corpus; format-identification
accuracy 1.0 on 10 labeled fixtures. NOT RUN (stated
in the runner output): real-corpus engine precision —
no labeled engine-negative real corpus exists.
Peak memory measured on the largest fixture
(273,366,540 B): nar-analyze process peak RSS
1,887,338,496 B (stage subprocess peaks excluded by
the stated method), 304.69 s wall. The parser
mutation corpus (DEX/ELF/PAK/IoStore/Zen) passes with
named error types only, after two in-cycle parser
fixes (DEX header-extent validation; ELF EI_CLASS
validation). Methodology: references/benchmarks.md.
The Testing row moves to IMPLEMENTED_AND_TESTED for
the audited gaps; the single-positive protection
corpus caveat stands (recall there is 1.0-or-0.0 by
construction). Battery after this phase: pytest
239/239, e2e 65/65, doctor READY.

## Evolution Phase 12 addendum (2026-11-24) — END STATE, v2.5.0 prepared

The TOTAL INTELLIGENCE EVOLUTION program is complete
on this branch. Version 2.5.0 is prepared (18/18
version locations, consistency-tested) and NOT
published: merge / push / tag / release remain the
owner's explicit decision.

End-state capability deltas from Phases 9–12 (the
earlier addenda record Phases 1–8):

- Reporting: dependency-graph rendering MISSING →
  IMPLEMENTED_AND_TESTED (offline inline SVG from
  native.json; truncation labeled; zero external
  references asserted).
- Unified CLI: five capability areas reachable only
  as scripts/flags → IMPLEMENTED_AND_TESTED as verbs
  (`tools`, `identify`, `validate`, `benchmark`,
  `case`); 28 verbs + version, all --help-clean; the
  23 original verbs untouched.
- Skill quality / guide accuracy: deferred audit →
  IMPLEMENTED_AND_TESTED (full guide-vs-code audit
  executed; durable checks encoded as tests;
  frontmatter + plugin.json validated
  programmatically).
- Testing: wall-times only → IMPLEMENTED_AND_TESTED
  (labeled-corpus accuracy metrics, parser mutation
  corpus, measured peak memory), with one explicit
  NOT RUN: real-corpus engine precision (no labeled
  engine-negative real corpus exists).
- Parser robustness: mutation corpus now guards DEX,
  ELF, PAK, IoStore, Zen clean-failure; two defects
  it caught (DEX header extents, ELF EI_CLASS) are
  fixed and covered.
- Release readiness: IMPLEMENTED_AND_TESTED as
  preparation (release guide written from 2.x
  practice; final battery pytest 239/239, e2e 65/65,
  doctor READY; whole-evolution-diff greps clean).

Standing limitations, unchanged and still labeled as
before: physical-device runtime verification is
IMPLEMENTED_BUT_UNVERIFIED (owner's device only);
Zen pre-5.3/EA layouts and recorded Zen versioning
remain synthetic-verified only; OAT beyond API 26
x86_64 remains synthetic-only; Kismet / Blueprint
graph decoding remains PLANNED; CI execution is
GitHub-only (no push this cycle).
