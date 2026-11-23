# Changelog

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
