# Legacy Android analysis

This guide covers Android apps and games from the Dalvik era and the
early ART era, roughly Android 4.x through 7.x, plus the old toolchains
and libraries that still show up in APKs built long ago. A legacy app
is usually one DEX file, one or two ABIs, and a build system that
predates Gradle or the Android App Bundle.

## Dalvik, ODEX, OAT, VDEX, and CDEX

Dalvik was the runtime before ART (Android 4.4 and older). ART
replaced it from Android 5.0. The two runtimes leave different
artifacts on a device, and you meet them when pulling files from a
phone rather than from an APK.

### ODEX (Dalvik, Android 2.2 to 4.4)

An `.odex` file is an optimized DEX: the original DEX plus Dalvik
optimizations applied at install time by `dexopt`. The optimizations
replace some instructions with quickened forms (`iget-quick`,
`invoke-virtual-quick`) that assume resolved classes and fields.

Where they live: `/data/dalvik-cache/` on the device, or beside the
APK in `/system/app/` and `/system/priv-app/` for system apps. An
`.odex` file is tied to the exact framework it was optimized against,
so you need the matching boot classpath to read it.

How to read one:

```bash
baksmali deodex -b framework/core.jar:framework/framework.jar app.odex -o out/smali
dexdump -d app.odex                                 # raw dump, quickened opcodes visible
```

`baksmali` in deodex mode reverses the quickening. The `-b` value
is the device's boot classpath: for a Dalvik `.odex` it is the
colon-separated list of framework jars (`core.jar`, `framework.jar`,
and the rest, from `/system/framework/`). Without the right
framework files it fails, so collect the device's framework first.
`oat2dex` is another tool that handles `.odex` files.

### OAT (ART, Android 5.0 and later)

An `.oat` file is ART ahead-of-time compiled output: an ELF shared
object holding compiled native code for the app's methods, plus (on
older releases) the original DEX embedded in its `.rodata` section.
`dex2oat` produces it at install time or on first boot.

Where they live: `/data/dalvik-cache/<abi>/` (system apps),
`/data/app/<package>/oat/<abi>/` (user apps), and
`/system/framework/<abi>/boot.oat` (the boot image).

The OAT header starts with the magic `oat\n` and a three-digit
version that changes with almost every Android release.
Per-release tables in older references are unreliable: one
widely copied table lists 052 for Android 8.0, but a real
API 26 (Android 8.0) OAT header examined here reads 124,
and its ART image reads 043. Read the version from the
header of your own file; newer releases use higher numbers.

How to read one:

```bash
oatdump --oat-file=app.oat --header-only     # header and method list
oatdump --oat-file=app.oat                   # full dump, including disassembly
baksmali deodex -b boot.oat app.oat -o out/smali   # smali output; -b is the boot.oat here
```

`oatdump` comes from AOSP and is version-sensitive: the oatdump
build must match the OAT version. A mismatch produces garbage or an
error, not a clean failure message. When oatdump is unavailable,
`readelf` still shows the ELF structure, and the embedded DEX (when
present) can be carved out by searching for the `dex\n` magic.

### VDEX and CDEX (Android 8.0 and later)

From Android 8.0, OAT files no longer embed the DEX. The DEX moves
into a companion `.vdex` (verified DEX) file that sits beside the
`.oat` file. VDEX versions: 006 (API 26), 010 (API 27), 019 (API 28),
021 (API 29). From Android 9.0, VDEX files may hold Compact DEX
instead of standard DEX. Compact DEX has the magic `cdex` and version
`001`; it compresses DEX structures and deduplicates shared data
across multi-DEX apps.

How to read one:

```bash
vdexExtractor -i app.vdex -o out/     # extracts standard .dex (or .cdex) files
```

`vdexExtractor` (anestisb/vdexExtractor, MIT) reverses the
quickening and writes plain `.dex` files you can feed to jadx or
apktool. Its backend is per-VDEX-version, so a newer VDEX than 021
needs a newer tool.

Sample status, updated: real API 26 OAT and VDEX files have
since been examined on this machine — an app `.odex` (OAT
version 124) and its companion `.vdex` (VDEX 006) pulled
from a device, plus the boot image's `.oat` and `.art`
(043). NAR's own parser reads these formats directly
(`nar-dex` accepts `.vdex`/`.odex`/`.oat`/`.cdex` targets
and parses the DEX a VDEX carries), verified against those
files. Dalvik ODEX and CDEX still have no real sample here;
for those two, the layouts above come from the format
documentation and synthetic fixtures only, and they stay
labeled as such. See the verification notes at the end.

## DEX versions 035, 037, and 038

The DEX header magic carries a three-digit version. The differences
between the old versions are small but real, and they decide which
bytecodes a file can contain. (Version 036 was skipped on purpose:
an old Dalvik bug accepted 036 files, so ART refuses them.)

| Version | Android | What it added |
|---|---|---|
| 035 | up to 6.x | The original format. |
| 037 | 7.0 | Default and static interface methods, with changes to `invoke` rules for them. First version to enforce class definition ordering. |
| 038 | 8.0 | `invoke-polymorphic` and `invoke-custom`, with the call-site and method-handle tables. |
| 039 | 9.0 | `const-method-handle` and `const-method-type`. |
| 040 | 10 | More characters allowed in simple names, including spaces. |
| 041 | 16 (experimental) | Container format: several DEX files in one container, header grows to 120 bytes. Not for production use. |

`triage` reports the DEX version of every DEX file it finds, read
from the header magic. Observed on test samples: an unsigned test
APK is DEX 035, ten builds of a test Java app are DEX 037, and a
native-heavy test app is DEX 038 on both DEX files.

What this means in practice:

- A 035 file cannot contain default methods, `invoke-custom`, or
  method handles. If a tool reports them in a 035 file, the tool is
  wrong or the file is corrupt.
- A 037 file can contain default methods but no `invoke-custom`.
  Lambdas in a 037 file are compiled to synthetic classes and
  `invoke-static` calls, not to `invokedynamic` style call sites.
- A 038 file can contain `invoke-custom` (lambdas, method-handle
  call sites). Smali for these files shows `invoke-custom` and
  `const-method-handle` instructions that older parsers do not know.

Parse by the header version, never by assumption. See the
[DEX guide](dex-smali-and-decompile.md) for structure and smali.

## APK Signature Scheme v1 (JAR signing) and v2

Both schemes can coexist on one APK. The
[signatures guide](signatures-and-integrity.md) has the full scheme
table; this section goes deeper on the two oldest schemes.

### v1 (JAR signing)

v1 is the original JAR signing scheme, from Java. It signs each ZIP
entry separately and stores the result in `META-INF/`:

- `MANIFEST.MF`: lists every signed entry with its SHA-1 (or
  SHA-256) digest.
- `<NAME>.SF`: the signature file. It holds digests of the manifest
  sections, plus a digest of the whole manifest.
- `<NAME>.RSA`, `<NAME>.DSA`, or `<NAME>.EC`: the PKCS#7 signature
  block over the `.SF` file, containing the signer's certificate.

Verification walks the chain backwards: the `.RSA` block signs the
`.SF` file, the `.SF` file signs the manifest, the manifest signs
each entry. An entry whose bytes changed fails its manifest digest.

What v1 does not cover: ZIP metadata (entry names, compression
method, extra fields), the ZIP central directory, and any entry not
listed in the manifest. An attacker can add unsigned entries, or
reorder entries, without breaking v1. That is why v1 alone is weak
and why Android 7.0 made v2 the norm.

What v1 still tells you: the signer certificate (read it with
`keytool -printcert -jarfile app.apk` or `apksigner verify
--print-certs`), and whether the APK predates v2 (v1-only signing is
a strong sign of a build from before 2017, or a build that
deliberately kept v1 for old devices).

Observed on test samples: the signed test APKs all report
`v1: false` from `apksigner verify --verbose`. Their `META-INF/`
files exist but carry no v1 signature; the signing block holds v2
and v3 only. An unsigned test build has no `META-INF/` at all and
fails verification with `Missing META-INF/MANIFEST.MF`.

### v2 (APK Signature Scheme v2)

v2 signs the whole APK as one blob, except for the signing block
itself. The signature lives in the APK Signing Block, a structure
inserted between the ZIP entries and the central directory, with
block ID `0x7109871a`. The scheme hashes the APK in 1 MB chunks
(SHA-256 digests) and signs the digest list.

What v2 covers that v1 does not: everything. ZIP metadata, entry
order, the central directory, and any added entry all break the
signature, because the signature covers the full byte range of the
APK outside the signing block. That is the whole point of v2.

Practical notes:

- `zipalign` must run before signing with v2. Aligning after
  signing changes bytes and breaks the signature.
- v2 requires Android 7.0 or later to verify. An APK that must
  install on Android 6.x or older needs v1 as well.
- `apksigner verify --verbose` reports each scheme separately.
  Triage runs it when apksigner is available and records the result.

## armeabi, ARMv7, and old NDK ABIs

Old apps ship native libraries for ABIs that modern builds dropped:

| ABI | What it is | Notes |
|---|---|---|
| `armeabi` | ARMv5TE, soft-float | Removed from the NDK in r17. Any APK with `lib/armeabi/` is an old build or ships a very old third-party lib. |
| `armeabi-v7a` | ARMv7-A, hard-float, optional NEON | The workhorse ABI of the 2012-2018 era. Still common in games for 32-bit device coverage. |
| `mips`, `mips64` | MIPS | Removed from the NDK in r17. Rare; mostly very old builds. |
| `x86` | 32-bit Intel | Old emulators and a few Intel phones. |
| `arm64-v8a`, `x86_64` | 64-bit | Modern norm. |

How to tell what a `.so` really is (do not trust the directory name
alone):

```bash
readelf -h lib/armeabi-v7a/libexample.so | grep -E "Machine|Flags"
file lib/armeabi-v7a/libexample.so
```

`readelf` reports the machine (`ARM`, `AArch64`, `Intel 80386`) and,
for ARM, the flags (hard-float ABI, NEON). A 32-bit ARM library in an
`arm64-v8a` directory is a packaging bug worth recording.

Old NDK notes:

- Old NDK builds link against low platform levels (`android-3`,
  `android-9`, `android-14`). The platform level shows in the
  `.note.android.ident` section or in `readelf -n` output.
- `armeabi` libraries use soft-float calling conventions; mixing
  them with hard-float `armeabi-v7a` code in one process is not
  possible, which is why old APKs shipped both.
- 32-bit-only apps cannot install on devices that dropped 32-bit
  support. An `armeabi-v7a`-only APK is a finding on its own.

No ARMv7-only real sample was on this machine. The triage ABI
listing for `armeabi` and `armeabi-v7a` was verified on a synthetic
ZIP (see verification notes).

## Eclipse and Ant-era builds

Before Gradle became the standard (roughly before 2014-2015), Android
apps were built with Eclipse and Ant. Their APKs look different:

- One `classes.dex`, built by the `dx` tool (not `d8`). The DEX is
  usually version 035.
- No AAB, no splits, no feature modules. One APK, all ABIs inside.
- `META-INF/` with v1 JAR signing only (v2 did not exist yet).
- `project.properties` and `build.xml` in the source tree, not in
  the APK. Inside the APK the signs are indirect: old `aapt`
  resource packaging, `R.java`-era resource IDs, and ProGuard
  (not R8) obfuscation.
- Multidex, when present, comes from the support library
  (`android.support.multidex.MultiDexApplication` in DEX), not
  from native multidex, because native multidex needs Android 5.0.

How to spot one from the APK alone: DEX 035, v1-only signing,
`android.support.v4` classes in DEX, and no `base/` module layout.
None of these alone proves an Ant build, but together they are a
strong signal.

## Legacy libraries

Old libraries leave package-path fingerprints in DEX. Search the
jadx output or the raw DEX strings for them.

| Library | DEX marker | Notes |
|---|---|---|
| Apache HttpClient | `org/apache/http` | Removed from the Android SDK in API 23. Apps that still need it bundle `org.apache.http.legacy.jar` or ship the classes directly. Its presence dates the networking code. |
| Apache Commons (Lang, IO, Codec) | `org/apache/commons` | Common in old apps. Harmless on its own; useful for dating. |
| Android Support Library | `android/support/v4`, `android/support/v7` | Pre-AndroidX. AndroidX (`androidx/`) replaced it from 2018. |
| ActionBarSherlock | `com/actionbarsherlock` | Pre-AppCompat action bar backport. Dates the UI code to 2012-2014. |
| Old Google Play Services | `com/google/android/gms` (old versions) | Version strings in `res/values` or in the DEX strings date the build. |
| Volley | `com/android/volley` | Google's old HTTP library. Still maintained, but its presence in an old APK is typical. |
| Old OkHttp / Retrofit | `com/squareup/okhttp`, `retrofit` | Version 2.x and older. Check the version string. |

Triage scans DEX for `org/apache/http` and reports it as the
"Apache HttpClient (legacy)" marker. Observed on test samples:
all seven DEX files examined here contain zero `org/apache/http`
references.
The marker's positive detection was verified on a synthetic DEX
(see verification notes).

## Old Unity Mono builds

Unity games from the Unity 4 and Unity 5 era (and Unity 2017-2018
builds that kept Mono) run C# on the Mono runtime instead of
compiling it to native code with IL2CPP:

- `assets/bin/Data/Managed/Assembly-CSharp.dll`: the game's own
  managed code, plus `Assembly-UnityScript.dll` and
  `Assembly-Boo.dll` when the game used UnityScript or Boo.
- `libmono.so`: the Mono runtime.
- `libunity.so`: the engine itself, same as in IL2CPP builds.

Analysis is .NET analysis, not native analysis: decompile the
assemblies with ILSpy, dnSpyEx, or `ilspycmd`. The assemblies carry
full type and method names unless the build stripped them. Mono
builds also ship `mscorlib.dll` and the Unity engine assemblies
(`UnityEngine.dll`, `UnityEngine.CoreModule.dll` in newer Mono
builds) in the same `Managed/` directory.

The Unity version shows in strings inside `libunity.so` (for
example `2018.4.36f1`). Mono builds cannot be told apart from
IL2CPP builds by `libunity.so` alone; the presence of
`Assembly-CSharp.dll` is what decides it.

No old Unity Mono sample was on this machine. The triage path
markers (`assembly-csharp.dll`, `libmono.so`) were verified on a
synthetic ZIP.

## Cocos2d-x and libGDX games

### Cocos2d-x

Cocos2d-x is a C++ game framework. Detection:

- `libcocos2dcpp.so` (C++ games) or `libcocos2djs.so` (JavaScript
  games built with Cocos Creator's JS runtime).
- DEX wrapper classes under `org/cocos2dx/lib/` (`Cocos2dxActivity`,
  `Cocos2dxGLSurfaceView`).
- Game scripts and scenes in `assets/` (`.js` files for Cocos
  Creator JS games, `.json` scene files).

Game logic for C++ Cocos games is native code in the `.so`, analyzed
with Ghidra or Kuna. For JS games, the `.js` files in `assets/` are
the game code and are readable directly.

### libGDX

libGDX is a Java game framework with a thin native layer:

- `libgdx.so` (plus `libgdx-freetype.so` and `libgdx-bullet.so`
  when those extensions are used).
- DEX classes under `com/badlogic/gdx/` (`AndroidApplication`,
  `AndroidGraphics`).
- Game assets in `assets/`: texture atlases (`.atlas`), particle
  files (`.p`), skins (`.json`), and Tiled maps (`.tmx`).

Game logic is Java in DEX, so jadx is the main tool. The native
layer is small and mostly handles OpenGL and input.

Both engines' triage markers were verified on synthetic ZIPs only
(see verification notes).

## Adobe AIR apps

Adobe AIR (now maintained by HARMAN) lets ActionScript and Flash
content run as an Android app. Two deployment models exist:

- Shared runtime (old): the app needs the separate AIR runtime app
  installed. Rare now.
- Captive runtime (current): the app bundles its own private copy
  of the runtime, adding roughly 9-12 MB.

Detection markers:

- `assets/META-INF/AIR/application.xml`: the app descriptor. This
  is the strong marker. It declares the app ID, version, and
  initial content (usually a `.swf` file).
- `.swf` files in `assets/`: the app content itself.
- `assets/META-INF/AIR/extensions/`: unpacked AIR Native
  Extensions (ANEs), which call platform native code.
- DEX classes under `com/adobe/air/` (the AIR activity and runtime
  bridge).

Analysis: the game or app logic is ActionScript inside the SWF.
Decompile SWF files with a Flash decompiler (for example, JPEXS
Free Flash Decompiler). ANEs are native `.so` files analyzed like
any other native code. The AIR runtime itself is a large binary;
analyze the app's SWF and ANEs first, not the runtime.

All AIR markers were verified on synthetic ZIPs only.

## Old WebView

Before Android 4.4, WebView was built on the old WebKit engine.
From 4.4 it is Chromium-based, and from Android 5.0 it updates
through the Play Store as a separate component. For analysis:

- Old WebView apps often load local HTML from `assets/` and bridge
  to Java with `addJavascriptInterface`. On Android 4.1 and older,
  every public Java method on the bridged object was reachable from
  JavaScript; from 4.2 only `@JavascriptInterface` methods are.
  A bridged object in an old app is worth reading carefully.
- WebView cache, databases, and local storage live in the app's
  data directory (`app_webview/`, `app_database/`). Those paths
  matter for dynamic analysis on old devices.
- `shouldOverrideUrlLoading` and `WebViewClient` overrides in DEX
  show how the app handles links and what it intercepts.

## Legacy storage and permission models

Android 6.0 changed permissions from install-time to runtime. Apps
built for the old model behave differently:

- Pre-6.0: all permissions granted at install. The manifest lists
  them and the user accepts them as a group. There is no runtime
  permission code in DEX.
- Android 6.0 and later: dangerous permissions need a runtime
  request (`requestPermissions`). An old app running on a new
  device still gets its permissions at install time if its
  `targetSdkVersion` is below 23, because the system grants them
  for compatibility. Check `targetSdkVersion` in badging before
  assuming runtime permission behavior.
- External storage: old apps read and write freely under
  `/sdcard/` with `WRITE_EXTERNAL_STORAGE`. Scoped storage
  (Android 10+) restricts this, but old apps targeting low SDK
  levels keep broad access through compatibility modes.
- `MODE_WORLD_READABLE` and `MODE_WORLD_WRITEABLE` shared
  preferences and files: deprecated in API 17, removed later.
  Their presence in old DEX is a finding, not a modern pattern.
- No Storage Access Framework (SAF) in old apps: file picking is
  done with direct paths and intents, not document providers.

## Android 4.x to 7.x behavior that changes analysis

- Android 4.4: SELinux enforcing, Dalvik still default. ART
  available as an experimental option.
- Android 5.0: ART default, AOT compilation, 64-bit support,
  material design. OAT files appear.
- Android 6.0: runtime permissions, Doze mode, App Standby,
  fingerprint API. Apps that assume always-on background work
  behave differently.
- Android 7.0: multi-window, direct boot, file-based encryption,
  `file://` URIs banned between apps (must use FileProvider).
  An old app that shares `file://` URIs crashes on 7.0+.
  Nougat also introduced DEX 037 and the v2 signature scheme.

When analyzing an old app, check `minSdkVersion` and
`targetSdkVersion` first (triage reports both from badging). They
decide which of these behaviors apply, and they date the build.

## Verification notes

Observed on test samples:

- DEX versions 035, 037, 038: observed. An unsigned test APK is
  035, ten builds of a test Java app are 037, a native-heavy test
  app is 038.
- v1/v2/v3 scheme reporting: observed. The signed test APKs
  report v1 no, v2 yes, v3 yes, v3.1 no, v4 no, 1 signer,
  verifies. An unsigned test build reports DOES NOT VERIFY.
- Apache HttpClient marker: real negative. Zero `org/apache/http`
  references in all seven DEX files examined. Positive detection
  is SYNTHETIC (fake DEX with the marker string).
- All other DEX markers in triage (Compose, Play Integrity,
  libGDX, AIR, Flutter, Unity, Godot, Cocos wrappers): real
  negative on the same seven DEX files; positive detection
  SYNTHETIC.

SYNTHETIC (verified only on small ZIPs built for this guide, each
containing just the marker paths or headers):

- Cocos2d-x, libGDX, Adobe AIR, Unity Mono path markers.
- `armeabi` and `armeabi-v7a` ABI listing.
- DEX 039 and 041 version reporting.
- Unity metadata versions 29 and 39, Godot PCK versions 1 and 2.

UNTESTED (no sample on this machine; documented from format specs
and tool docs, not from a file examined here):

- ODEX, OAT, VDEX, and CDEX files and their tools (oatdump,
  vdexExtractor, baksmali deodex).
- Old Unity Mono builds, old WebView behavior, Eclipse/Ant-era
  APK layout, and Android 4.x to 7.x device behavior.
