# Changelog

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
  tests/benchmarks/; pyproject.toml; CI workflow authored
  for GitHub Actions (not executed in the build
  environment).
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
