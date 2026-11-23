# Modern Android analysis

This guide covers current Android apps: Android 14 and 15 behavior,
current engines and frameworks, current signing and integrity
schemes, and current delivery through App Bundles. It assumes the
triage and DEX guides for the basics.

## Android 14 and 15

### The 16 KB page-size requirement

Android has always used 4 KB memory pages. Android 15 added support
for devices whose kernel runs with 16 KB pages, and Google Play
requires apps that target Android 15 or higher to support them.
A native library built for 4 KB pages cannot load on a 16 KB device:
the dynamic linker maps each `LOAD` segment at a page boundary, and
a 4 KB-aligned library fails that mapping.

Two separate alignments must be right:

1. ELF alignment. Every `LOAD` segment of every 64-bit `.so` must
   declare `p_align` of at least `0x4000` (16 KB). This is set by
   the linker when the library is built (NDK r27 and later default
   to it; older builds need `-Wl,-z,max-page-size=16384`). Only
   the library's author can change it.
2. ZIP alignment. Uncompressed `.so` files are mapped straight out
   of the APK, so each one must start at a ZIP offset that is a
   multiple of 16,384. This is set at packaging time (`zipalign
   -P 16`).

How to check the ELF side:

```bash
unzip -p app.apk lib/arm64-v8a/libexample.so > work/libexample.so
readelf -lW work/libexample.so | grep LOAD
```

Every `LOAD` line must show an alignment of `0x4000` or higher.
`0x1000` means the library was built for 4 KB pages and will not
load on a 16 KB device. Only 64-bit ABIs (`arm64-v8a`, `x86_64`)
count for this rule.

How to check the ZIP side:

```bash
zipalign -c -P 16 -v 4 app.apk
```

Observed on a test sample: all 13 native libraries in a
native-heavy test app (browser engine) report `p_align 0x4000`
on every `LOAD` segment, including the 154 MB `libxul.so`. That
build is 16 KB ready.

The Play enforcement date has moved more than once (extensions
were granted past the original dates). Check the app's policy
status in Play Console for the date that applies to it; do not
quote a deadline from memory.

### Other Android 14 and 15 behavior that changes analysis

- Android 14: apps must declare foreground service types,
  `targetSdkVersion` 23 or higher is required to install,
  per-app language settings, partial photo and video access, and
  the photo picker replaces broad media permission for most apps.
- Android 15: edge-to-edge layout is enforced for apps targeting
  API 35, predictive back is on by default, partial screen
  sharing, and private space. 16 KB page-size support is the
  biggest analysis-relevant change, covered above.
- `targetSdkVersion` decides which of these apply. Triage reports
  it from badging; always read it before assuming behavior.

## Kotlin Multiplatform and Jetpack Compose

### Jetpack Compose

Compose is Android's declarative UI toolkit. A Compose app has no
XML layouts for its Compose screens; the UI is Kotlin code that
builds a tree at runtime. For analysis this means:

- There is no `res/layout/` file to read for a Compose screen.
  The layout is in DEX, in `@Composable` functions.
- Compose version and compiler info live in DEX strings and in
  `META-INF/` version files. Search DEX for `androidx/compose`
  to confirm Compose, and for `androidx.compose.compiler` strings
  for the compiler version.
- Recomposition and state hoisting make control flow harder to
  follow than in a View-based app: a `@Composable` function can
  run many times, and state lives in `remember` blocks and
  ViewModels, not in fields you can read once.

Detection markers:

- DEX strings under `androidx/compose/` (runtime, UI, foundation,
  material3). Triage scans DEX for `androidx/compose` and reports
  it as the "Jetpack Compose" marker.
- `kotlin/Metadata` annotations on the composable classes, same
  as any Kotlin code.

Real samples: none of the seven DEX files examined here contain
`androidx/compose` references. The marker's positive detection
was verified on a synthetic DEX.

### Kotlin Multiplatform (KMP)

KMP shares Kotlin code between Android, iOS, desktop, and web.
On Android, shared KMP code compiles to ordinary DEX, so there is
no reliable APK-level marker that says "this module is shared".
What you can look for:

- `org/jetbrains/compose/` DEX paths: Compose Multiplatform, the
  multiplatform version of Compose. Triage scans for this marker.
  It is the strongest KMP signal in an APK.
- A shared module's package shape: KMP projects usually keep
  shared code in a module named `shared`, `common`, or similar,
  with `expect`/`actual` declarations compiled into platform
  classes. Package names are a hint, not proof.
- `kotlinx` libraries (`kotlinx.coroutines`, `kotlinx.serialization`,
  `kotlinx.datetime`) appear in pure Android Kotlin apps too, so
  they do not prove KMP on their own.

Be honest about KMP: without the source tree, "shared code" is
often a guess. Report the markers you found and say what they do
and do not prove.

## Rust NDK libraries

Rust is increasingly common in Android native code, both in
first-party libraries and in large engines (Gecko, Chromium
components). A Rust `.so` is still an ELF file; what changes is
what is inside it.

Detection markers, strongest first:

- `.rustc` section in the ELF section headers (unstripped builds
  only). Check with `readelf -SW libexample.so | grep rustc`.
- `rustc version` strings, from the compiler version embedded in
  the binary.
- `panicked at` strings: Rust panic messages. A library with
  several of these almost certainly contains Rust code.
- `rust_begin_unwind` symbols: the Rust panic runtime entry point.
- Mangled Rust symbols: legacy mangling starts with `_ZN`, and
  v0 mangling starts with `_R`. Both look different from C++
  mangling once you know the shape.

```bash
readelf -SW work/libexample.so | grep -i rust
strings work/libexample.so | grep -E "panicked at|rustc version|rust_begin_unwind"
nm -D work/libexample.so | grep -E "_ZN|_R" | head
```

Triage scans every `.so` for the string markers (`panicked at`,
`rustc version`, `rust_begin_unwind`, `.rustc`) and reports hits
per library. The scan is bounded at 512 MB of `.so` bytes total;
beyond that it stops and says so.

Observed on a test sample: a native-heavy test app has Rust
markers in three of its 13 libraries. `libxul.so` contains 2 `panicked
at` strings and a `.rustc` substring inside a mangled `uniffi_core`
symbol. `libcrashhelper.so` contains 4 `panicked at` strings and a
`rust_begin_unwind` symbol. `libcrashtools.so` contains 4
`panicked at` strings, a `rust_begin_unwind` symbol, and the same
`uniffi_core` mangled name. No `.rustc` section exists in any of
them: these are stripped release builds, so the section check
finds nothing and the string markers do the work. Absence of all
markers proves nothing; a stripped library can hide every one.

Rust analysis notes: Rust code decompiles in Ghidra like any
native code, but the standard library is large and inlined
generics make functions long. Rust symbols demangle with
`rustfilt` (or `c++filt` with Rust support). Panic paths and
`Result` handling are visible in the control flow; `unwrap` calls
show up as panic branches.

## Play Integrity and app integrity checks

Play Integrity is Google's API for asking Play whether an app
install and device look genuine. This section describes the API
surface as an observed feature, for analysis only. It does not
cover bypassing, spoofing, or weakening any integrity check.

What the API surface looks like in DEX:

- `com/google/android/play/core/integrity/` classes:
  `IntegrityManager`, `IntegrityManagerFactory`,
  `IntegrityTokenRequest`, `IntegrityTokenResponse`.
- The newer standard API: `StandardIntegrityManager`,
  `StandardIntegrityTokenRequest`, and the prepare-then-request
  flow (`prepareIntegrityToken` followed by `requestIntegrityToken`).
- The app calls the API, receives an integrity token (an
  encrypted verdict), and sends it to its own server, which
  decrypts it with Google's server API. The verdict covers app
  integrity (is this the genuine Play install), device integrity
  (does the device pass checks), and account details.

What to record when you find it:

- Which API the app uses (classic or standard) and which methods
  it calls. Triage scans DEX for
  `com/google/android/play/core/integrity` and reports it as the
  "Play Integrity API" marker.
- Where the token goes: search for the network call that sends
  the token to the app's server. The server-side verdict handling
  is not visible in the APK.
- Whether the app also uses SafetyNet Attestation
  (`com/google/android/gms/safetynet/`), the older API that Play
  Integrity replaced. Both can coexist during migration.

Real samples: none of the seven DEX files examined here contain
Play Integrity references. The marker's positive detection was
verified on a synthetic DEX.

Other integrity checks you may meet: root detection (searches for
`su` binaries, Magisk paths, or `test-keys` builds), emulator
detection (Build properties, sensor checks), debugger detection
(`Debug.isDebuggerConnected`, `TracerPid` in `/proc/self/status`),
and tamper checks (comparing the signing certificate at runtime).
Record each as an observed feature with its location. Do not
defeat any of them.

## APK Signature Scheme v3, v3.1, and v4, and fs-verity

The [signatures guide](signatures-and-integrity.md) has the full
scheme table. The modern schemes:

- v3 (Android 9.0): like v2, plus key-rotation lineage. The signer
  can prove a new signing key descends from the old one, so an
  app can rotate keys and still update over old installs. The
  lineage is a chain of signed statements in the signing block
  (block ID `0xf05368c0`).
- v3.1 (Android 13): rotation that targets Android 13 and later
  only (block ID `0x1b93ad61`). Old devices keep trusting the old
  key; new devices accept the rotated key. An APK can carry both
  v3 and v3.1 blocks with different lineages.
- v4 (Android 11): fs-verity for streaming installs. The v4
  signature lives in a separate `.idsig` file beside the APK, not
  in the APK itself. It holds a Merkle hash tree (fs-verity) over
  the APK bytes, so the system can verify pages as they stream in
  during an incremental install. Without the `.idsig` file there
  is nothing to check; the APK alone does not carry v4.

Observed on test samples: the signed test APKs report v3 yes
and v3.1 no, v4 no. That is the common shape for apps signed with
current build tools and no key rotation.

## R8 full mode and current obfuscators

R8 is the standard Android shrinker and obfuscator (it replaced
ProGuard). R8 full mode is a more aggressive mode, enabled with
`android.enableR8.fullMode=true` in older AGP versions and default
in newer ones. What full mode changes:

- Class merging: small classes get merged into their callers,
  which removes classes entirely rather than just renaming them.
- More aggressive shrinking of unused code, fields, and methods.
- Stricter assumptions about the code (for example, that
  `-keep` rules are complete), which can break reflection if the
  rules are wrong.

Markers that suggest R8 full mode (all heuristics, none decisive):

- Very few classes left in DEX relative to the app's size, with
  single-letter names (`a`, `b`, `c`) in flat packages.
- Missing `SourceFile` attributes and line-number tables.
- Merged classes: one class doing work that clearly belonged to
  several (mixed responsibilities, odd field groupings).
- A `mapping.txt` file in the build output (not in the APK)
  showing merged class entries.

Other current obfuscators:

- DexGuard (commercial, from the ProGuard makers): adds string
  encryption, class encryption, and tamper detection on top of
  R8-style renaming. Markers include encrypted string blobs,
  decryptor helper classes, and resource encryption. DexGuard
  output is deliberately hard to read; budget more time for it.
- Allatori, DashO, and similar Java obfuscators: less common on
  Android, but they appear in apps that share code with desktop
  Java. Markers are similar (renamed classes, control-flow
  changes, string encryption).

Honest limits: no R8 full-mode or DexGuard sample was on this
machine, so these markers are UNTESTED here. Obfuscation
detection is always heuristic. Report what you observed (name
patterns, missing attributes, string blobs) and name the
obfuscator only when the evidence supports it.

## Baseline profiles

Baseline profiles tell ART which code paths matter, so the system
can compile them ahead of time instead of waiting for JIT
profiling. They ship in the APK:

- `assets/dexopt/baseline.prof`: the profile, in a human-readable
  text format (class and method names, one per line, with flags).
- `assets/dexopt/baseline.profm`: the same profile in binary
  form, used on newer releases.
- `*.dm` (DEX metadata) files: the older delivery form, placed
  beside the DEX files.

Why they matter for analysis: a baseline profile is a list of the
app's hot code paths, written by the developer. It names the
classes and methods the developer considered important, which is
a useful map when deciding where to start reading. Read it with
any text editor (`.prof`) or with `profgen` tooling (`.profm`).

Triage lists baseline profiles and `.dm` files when present.
Real samples: none of the three test APKs ship a baseline
profile or a `.dm` file. Detection of both was verified on a
synthetic ZIP.

## Unity 6

Unity 6 is Unity's current major line (version numbers start with
`6000.`). Detection:

- `libil2cpp.so` plus `global-metadata.dat`, same as any IL2CPP
  build. The difference is the metadata format version: Unity 6
  writes version 39. Triage reads the version from the metadata
  header and maps it to an era. Checked example builds: 2019.4
  wrote 24, 2020.3 wrote 27, 2022.3.30 wrote 29, 2022.3.62 wrote
  31, 6000.4 wrote 39. The mapping is by example build, not a
  strict rule; always report the raw version number.
- Version strings inside `libunity.so` and `libil2cpp.so` start
  with `6000.` for Unity 6 builds.
- The original Il2CppDumper supports metadata up to version 29.
  Version 39 needs a newer fork (for example, the v39 fork of
  Il2CppDumper) or REA's `inspect-il2cpp-metadata`, which
  supports 24, 27, 29, 31, and 39.

What changed in Unity 6 that matters for analysis: unified
versioning (no more separate LTS/TECH streams in the same way),
render pipeline changes, and the metadata format bump to 39 with
variable-width indexing. Game logic analysis is unchanged:
metadata plus `libil2cpp.so`, as in the
[native guide](native-libs-and-jni.md).

Metadata version detection was verified on synthetic files only
(versions 29 and 39). No real Unity 6 sample was on this machine.

## Unreal Engine 5

Unreal 5 detection:

- `libUE4.so` (the library keeps the UE4 name in UE5 builds) or
  `libUnreal.so`, plus `.pak` asset packs. Path markers do not
  distinguish UE4 from UE5.
- Version strings inside `libUE4.so`: search for `++UE5+Release-`
  followed by the version (`5.3`, `5.4`, and so on). UE4 builds
  show `++UE4+Release-4.x` instead.

```bash
strings lib/arm64-v8a/libUE4.so | grep -E "\+\+UE[45]\+Release-" | head -5
```

- `.pak` files are versioned containers. The pack version is in
  the footer; use a `.pak` reader for the matching engine version
  rather than guessing at bytes.

Game logic is C++ in the `.so`, as in UE4. Nanite and Lumen are
rendering features; they change what the engine does, not how you
analyze the game code.

No Unreal sample of any version was on this machine. The version
string check is UNTESTED here.

## Godot 4

Godot 4 detection:

- `libgodot_android.so` (the name varies by export template).
- A `.pck` data pack in `assets/`, or a pack embedded in the
  binary. The PCK header carries both the pack format version and
  the engine version that wrote it: magic `GDPC`, then a uint32
  pack format version (1 for Godot 3.x, 2 for Godot 4.0-4.4, 3
  for Godot 4.5 and later, 4 seen with Godot 4.7), then uint32
  engine major, minor, and patch. Triage reads the header and
  reports both numbers.

```bash
xxd -l 20 assets/game.pck
# GDPC, pack format, engine major/minor/patch, little-endian
```

What changed from Godot 3:

- GDScript compiles to `.gdc` bytecode (magic `GDSC`) as before,
  but the bytecode version changed, so decompilers must match the
  engine version. Godot 4.3 and later also use an intermediate
  `.gdir` format (magic `GDIR`) with type information.
- GDExtension replaces GDNative for native modules. GDExtension
  code is a native `.so` analyzed like any other native code.
- The export template and the pack are versioned together; a
  version mismatch between template and pack is a finding.

PCK header detection was verified on synthetic files only (pack
format 1 with engine 3.5.1, pack format 2 with engine 4.3.0). No
real Godot sample was on this machine.

## Flutter 3.x

Flutter 3.x detection:

- `libflutter.so` (the engine) plus `libapp.so` (the Dart AOT
  snapshot with the app's code). Both are path markers triage
  already reports.
- The Dart version and Flutter version appear as strings inside
  `libflutter.so` (search for `Flutter 3.`). The snapshot in
  `libapp.so` is AOT-compiled Dart, not DEX; jadx sees only the
  thin Android wrapper (`io/flutter/embedding/` classes in DEX).
- Impeller is the current default renderer (it replaced Skia).
  It changes rendering internals, not the APK layout or the
  analysis approach.

Analysis: Dart AOT code needs Dart-aware tooling (for example,
`reflutter` for snapshots that allow it, or Ghidra on `libapp.so`
with Dart symbols). The wrapper DEX is small; the app logic is
in the snapshot.

No Flutter sample was on this machine. The path markers were
verified on a synthetic ZIP; version-string detection is UNTESTED
here.

## React Native new architecture

React Native's new architecture (available from 0.68, default
from 0.76) replaces the old bridge with three pieces:

- Fabric: the new renderer, replacing the old UI manager.
- TurboModules: the new native module system, with lazy loading
  and direct JSI calls instead of bridge messages.
- JSI (JavaScript Interface): direct C++ calls between JavaScript
  and native code, replacing serialized bridge traffic.

What changed for analysis: the old bridge (`CatalystInstance`,
`RCTBridge`, bridge modules) is gone in a new-arch app. Native
modules are TurboModules with codegen-generated specs, and the
JS bundle loads through Hermes with JSI bindings. The JS bundle
(`assets/index.android.bundle`) is still Hermes bytecode and
still readable with Hermes tooling.

Detection markers:

- Native libraries: `libfabricjni.so` (Fabric),
  `libturbomodulejsijni.so` (TurboModules),
  `libreact_nativemodule_core.so`, `libreact_render_core.so`.
  Newer releases consolidate these into `libreactnative.so` plus
  an app-specific `libappmodules.so`.
- The deciding check is the build flag in `BuildConfig.smali`
  (from apktool output): `IS_NEW_ARCHITECTURE_ENABLED` true or
  false. Library presence alone is not decisive, because the
  libraries can ship in an APK whose flag is off. Triage scans
  DEX for the flag string and reports it; read the value in
  smali to decide.

All new-architecture markers were verified on synthetic ZIPs
only. No React Native sample was on this machine.

## Current AAB and Play delivery

Play delivery today is bundle-based:

- AAB (Android App Bundle): the publishing format. One bundle
  holds all languages, screen densities, and ABIs in modules
  (`base/` plus feature modules). Triage reads AABs directly
  (`base/dex/`, `base/manifest/`, `base/res/`, `base/assets/`).
  `aapt2 dump badging` cannot read an AAB; use `bundletool dump
  manifest` or `bundletool build-apks` to turn it into APKs.
- Split APKs: what a device actually installs. One base APK plus
  config splits (`config.arm64_v8a`, `config.en`,
  `config.xxxhdpi`) and feature splits. Triage a set as a set;
  see the [triage guide](triage-and-inventory.md).
- Play Asset Delivery (PAD): large game assets ship as asset
  packs, not in the APK. Three modes: install-time (delivered
  with the install), fast-follow (delivered right after install),
  and on-demand (downloaded when the game asks). Asset packs
  appear as modules in the AAB and as separate split APKs on the
  device. An APK without its asset packs is an incomplete game.
- Play Feature Delivery: on-demand feature modules, delivered
  when the app requests them through the Play Core library
  (`com.google.android.play.core.splitinstall`). The split
  install API surface in DEX shows which modules are on-demand.
- `.apks` files are ZIP archives of split APKs (from bundletool
  or third-party tools). Unzip first, then triage each APK.

Observed on a test sample: a test bundle triages cleanly
(DEX 037 in `base/dex/`). `apksigner` cannot verify an AAB (it throws
`ApkFormatException: Missing AndroidManifest.xml`); triage
reports signature schemes as not applicable for bundles.

## Storage: scoped storage and app-specific directories

Android 10 introduced scoped storage; Android 11 enforces it for
apps targeting API 30 and later. What changes for analysis:

- An app's own files live in its app-specific directories:
  internal (`/data/data/<package>/`) and external
  (`/sdcard/Android/data/<package>/`). No permission is needed for
  its own directories, and other apps cannot read them.
- Shared media goes through MediaStore (`MediaStore.Images`,
  `MediaStore.Video`, `MediaStore.Audio`, `MediaStore.Downloads`).
  An app reads only its own media plus media the user grants; it
  cannot list the whole shared storage.
- `WRITE_EXTERNAL_STORAGE` no longer grants broad write access on
  Android 11 and later. `READ_EXTERNAL_STORAGE` is narrowed to
  media the app owns or the user picks.
- File picking goes through the Storage Access Framework (SAF):
  `ACTION_OPEN_DOCUMENT`, `ACTION_CREATE_DOCUMENT`. The app gets a
  URI for the picked file, not a filesystem path.
- `MANAGE_EXTERNAL_STORAGE` (all-files access) is the exception:
  an app that holds it can read and write shared storage broadly.
  It needs a Play policy declaration, so its presence in a manifest
  is a finding by itself. `nar-perms.py` reports it like any other
  permission.
- `requestLegacyExternalStorage="true"` opted an app out of scoped
  storage, but only on Android 10 and only for apps targeting API
  29. It has no effect on Android 11 and later. Its presence in an
  old manifest explains old behavior, not current behavior.

For analysis: when a feature touches files, check which storage
route it uses (app-specific dir, MediaStore, SAF, or all-files
access) before assuming where the data lands. The data-extraction
commands in the [dynamic guide](dynamic-analysis.md) start from
the app-specific directories.

Verification note: this section describes documented Android
behavior (AOSP storage docs). No storage behavior was observed on a
device here.

## Verification notes

Observed on test samples:

- 16 KB page-size alignment: observed. All 13 native libraries
  in a native-heavy test app report `p_align 0x4000` on every
  `LOAD` segment.
- Kotlin DEX marker: observed. A native-heavy test app has 3
  `kotlin/Metadata` occurrences (1 in `classes.dex`, 2 in
  `classes2.dex`).
- Rust markers: observed. The test app's `libxul.so` (2
  `panicked at`), `libcrashhelper.so` (4 `panicked at`,
  `rust_begin_unwind`), `libcrashtools.so` (4 `panicked at`,
  `rust_begin_unwind`). No `.rustc` section in any of them.
- v3/v3.1/v4 scheme reporting: observed. The signed test APKs
  report v3 yes, v3.1 no, v4 no.
- AAB triage: observed. A test bundle reads correctly
  (DEX 037, signature schemes not applicable).
- Compose, Play Integrity, and baseline profiles: real negative
  on all test APKs (zero hits). Positive detection is SYNTHETIC.

SYNTHETIC (verified only on small ZIPs built for this guide):

- Unity metadata versions 29 and 39, Godot PCK versions 1 and 2.
- React Native new-architecture libraries, Flutter path markers,
  baseline profile and `.dm` detection.
- Compose, Compose Multiplatform, and Play Integrity DEX markers.

UNTESTED (no sample on this machine; documented from specs and
docs, not from a file examined here):

- Unreal 5 version strings, Flutter 3.x version strings.
- R8 full-mode and DexGuard markers.
- Android 14/15 device behavior beyond the 16 KB ELF check.
- Play Asset Delivery packs and on-demand modules.
- Scoped storage behavior: documented from AOSP storage docs; no
  device test was run.
