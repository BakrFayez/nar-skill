# Triage and inventory

Triage is the first five minutes on any APK, AAB, split set, or OBB: get
identity, shape, and engine before opening any decompiler. It answers
"what is this?" with hashes and counts, not guesses.

## nar-triage.py

Stdlib-only Python 3, no pip dependencies. Reads the file as a ZIP and
never executes anything inside it.

```bash
python3 scripts/nar-triage.py app.apk            # human-readable
python3 scripts/nar-triage.py app.apk --json     # machine-readable
python3 scripts/nar-triage.py app.aab            # bundles work too
python3 scripts/nar-triage.py main.123.com.game.obb
```

Output: SHA-256, size, package / version / SDK levels (via `aapt2 dump
badging` when available), ZIP entry count, DEX files with sizes, native
libraries per ABI, `META-INF` and signing files, assets / `res/` counts,
game-engine hints, and asset-bundle inventory.

When `aapt2` cannot read badging (missing binary), the
package fields report why instead of inventing values. For `.aab` files
triage reads the manifest with `bundletool dump manifest` instead. Fall back to
`apktool d` and read the decoded `AndroidManifest.xml` directly.

## What to read from a triage

- SHA-256 and size: the identity of the artifact. Record both in every
  report; re-triage after any re-download.
- DEX count and sizes: 1 small DEX means a small app; multi-DEX or tens
  of megabytes means a large app or a game with heavy Java/Kotlin code.
  DEX size is uncompressed bytes, so it reflects real code size.
- Native libraries per ABI: `arm64-v8a` only is the modern norm.
  `armeabi-v7a` / `x86_64` alongside it means wider device coverage.
  A single huge `.so` (tens to hundreds of MB) is usually a game engine
  or a browser engine.
- `META-INF` entries: `*.RSA` / `*.DSA` / `*.EC` plus `*.SF` and
  `MANIFEST.MF` are the v1 JAR signature files. Their presence says
  nothing about v2/v3. See the signatures guide.
- Assets vs `res/`: games carry most content in `assets/` (levels,
  audio, bundles); apps carry most UI in `res/`.

## Game-engine hints

Triage matches ZIP entry paths against engine signatures. A hint is a
starting point, not proof: confirm with the
[native libs and JNI](native-libs-and-jni.md) guide.

| Engine | Markers |
|---|---|
| Unity (IL2CPP) | `lib/arm64-v8a/libil2cpp.so`, `assets/bin/Data/Managed/Metadata/global-metadata.dat` |
| Unity (Mono) | `assets/bin/Data/Managed/Assembly-CSharp.dll`, `libmono.so` |
| Unity 6 | Same IL2CPP markers; metadata format version 39 in `global-metadata.dat` (triage reports it) |
| Unreal Engine | `libUE4.so`, `libUnreal.so`, `*.pak` asset packs |
| Unreal Engine 5 | Same markers; version comes from `++UE5+Release-` strings in `libUE4.so` |
| Godot | `libgodot_android.so` (name varies by export template) |
| Godot 4 | Same marker; `.pck` pack format 2+ and engine version in the PCK header (triage reports both) |
| Cocos2d-x | `libcocos2dcpp.so`, `libcocos2djs.so` |
| Flutter | `libflutter.so`, `libapp.so` |
| Flutter 3.x | Same markers; version comes from `Flutter 3.` strings in `libflutter.so` |
| React Native | `libreactnativejni.so`, `libhermes.so` |
| React Native (new architecture) | `libfabricjni.so`, `libturbomodulejsijni.so`, `libreact_nativemodule_core.so`, `libreactnative.so` |
| libGDX | `libgdx.so` (+ `libgdx-freetype.so`, `libgdx-bullet.so`), `com/badlogic/gdx` in DEX |
| Adobe AIR | `assets/META-INF/AIR/application.xml`, `.swf` in `assets/`, `com/adobe/air` in DEX |

Notes:

- `libunity.so` appears in both Mono and IL2CPP Unity builds; it does
  not distinguish them. `libil2cpp.so` plus `global-metadata.dat`
  means IL2CPP. `Assembly-CSharp.dll` means Mono. The Unity version
  comes from the metadata format version (39 means Unity 6 era) or
  from version strings in `libunity.so`, not from paths.
- `.pak` alone is weak evidence for Unreal: confirm with `libUE4.so`
  or Unreal directory layout before claiming Unreal. UE4 and UE5
  share the `libUE4.so` name; only the version strings inside
  separate them.
- Godot 3 and Godot 4 share the `libgodot` name. The `.pck` header
  decides: pack format 1 is Godot 3.x, 2 is Godot 4.0-4.4, 3 is
  Godot 4.5 and later.
- React Native new-architecture libraries can ship in an APK whose
  new-arch flag is off. The deciding check is
  `IS_NEW_ARCHITECTURE_ENABLED` in `BuildConfig.smali` (apktool
  output). Triage reports the flag string when DEX contains it.
- A bare `.swf` alone is weak evidence for Adobe AIR: confirm with
  `META-INF/AIR/application.xml`, the descriptor.
- A game with no engine markers is usually a custom native engine or a
  pure-Java game. Check the `.so` list and the DEX package names.

## Game asset bundles

Triage lists asset-bundle files (`.pak`, `.bundle`, `.unity3d`, `.obb`,
`.assets`, `.resource`) with sizes. What they mean:

- `.pak` (Unreal): cooked content packs. Inventory them; do not assume
  contents from names.
- `.bundle` / `.unity3d` (Unity): AssetBundles, often downloaded after
  install or shipped in `assets/`.
- `.assets` (Unity): serialized asset files inside the APK or OBB.
- Embedded `.obb` files are unusual; OBBs normally ship beside the APK
  (see below).

For the full asset picture, decode with apktool and inventory `assets/`
and `res/raw/` by extension and size. See
[manifest and resources](manifest-and-resources.md).

## Reading the triage report

Details that are easy to misread:

- **Containers (.xapk/.apkm)** are ZIPs of APKs plus a `manifest.json`.
  Triage takes the container's identity (package, version, SDK,
  permissions) from that manifest and lists the contained APKs and
  OBBs. There is no code at container level; triage each contained
  APK for code-level detail. The app-bundles guide covers the format.
- **Implied permissions.** `aapt2 dump badging` lists not only the
  permissions declared in the manifest but also ones the platform
  implies (for example `READ_EXTERNAL_STORAGE` implied by
  `WRITE_EXTERNAL_STORAGE`, and several implied for apps with very
  old target SDKs). Triage separates them into their own labeled
  line; never report an implied permission as declared.
- **Duplicate `<uses-sdk>`.** Old manifests sometimes declare
  `<uses-sdk>` twice (occasionally nested inside a component, where
  the platform ignores it). Both NAR tools use the FIRST occurrence
  and warn. If triage and nar-perms ever disagree on SDK levels,
  that agreement rule is the tiebreaker to check.
- **Library versions.** Java/AndroidX libraries stamp
  `META-INF/<group>_<artifact>.version` files with their exact
  version. Triage surfaces them as `library_versions` — measured
  version evidence, better than guessing from class names. Kotlin's
  own version is the exception: kotlin-stdlib ships no `.version`
  file, and its version lives in `kotlin.Metadata`, which R8 strips
  from release builds. Detect Kotlin by DEX type evidence
  (`Lkotlin/`, `kotlinx/coroutines`) instead; that survives
  stripping.
- **A base APK with no native libs is not always a pure-DEX app.**
  When engine evidence (Unity/Unreal/Godot/Flutter) is present but
  the file holds no `.so`, the native libs live in a config split of
  the same bundle. The same applies to any APK generated from a
  bundle, engine or not: bundletool leaves a `stamp-cert-sha256`
  file in every APK of the set and a splits manifest
  (`res/xml/splits*.xml`) in the base. Triage reports the evidence
  instead of printing the pure-DEX line; triage the splits before
  concluding anything about native code.
- **No META-INF signing files is normal for v2/v3-only APKs**: the
  APK Signing Block carries the signature, so there are no `.RSA` /
  `.SF` files to find. Triage's signing line says which case applies.

## Split APKs, APKS, and AAB

Modern Play installs are often split: one base APK plus config splits
(`config.arm64_v8a`, `config.en`, `config.xxxhdpi`, ...). An `.apks` file
is a ZIP of those APKs. An `.aab` is the bundle they are generated from.

Triage a set as a set:

1. Run `nar-triage.py` on the base APK and on every split. Record each
   file's SHA-256. A single split alone is an incomplete app: its DEX
   and manifest are partial by design.
2. Confirm the splits belong together: the base APK and every split
   must share the same package name and version code. Triage reports
   both from badging. A split whose version code differs from the
   base does not belong to that install set.
3. For an `.apks` file, unzip it first (it is a plain ZIP), then triage
   each contained APK.
4. For an `.aab`, triage works directly: NAR reads `base/dex/`,
   `base/manifest/`, `base/res/`, and `base/assets/`, and takes the
   package, version, and SDK levels from the bundle manifest with
   `bundletool dump manifest` (`aapt2 dump badging` cannot read an
   AAB). Use `bundletool build-apks` to convert it to APKs.
5. Version comparison across a set means comparing base-to-base and
   split-to-split with matching split names. See the
   [version compare guide](version-compare-and-feature-map.md).

## OBB expansion files

Large games ship expansion files beside the APK on the device at
`Android/obb/<package>/`:

- `main.<versionCode>.<package>.obb`: required content.
- `patch.<versionCode>.<package>.obb`: updates to the main file.

OBBs are ZIP containers (usually stored uncompressed). Triage reads them
directly and reports the kind, version code, and package parsed from the
filename. Inventory the OBB's entries the same way as an APK's assets:
they are usually the game's bulk content (levels, audio, video). An OBB
without its matching APK version is orphaned content; record the version
code and match it against the APK's `versionCode`.

## System apps

System apps ship in the firmware image instead of coming from a
store. They live in read-only partitions on the device:

- `/system/app/`: ordinary system apps.
- `/system/priv-app/`: privileged system apps, which can hold
  `signature|privileged` permissions.
- `/system_ext/app/` and `/system_ext/priv-app/`, `/product/app/`,
  `/vendor/app/`: the same split on newer partition layouts.

Pull one from a device you own or are authorized to test. No root
is needed to read the APK itself:

```bash
adb shell pm path <package>
adb pull /system/priv-app/Example/Example.apk
```

Then triage it like any other APK: `nar-triage.py` and
`nar-perms.py` work the same way. What differs from a store app:

- Signature: system apps are signed with the platform key (or a
  vendor key). Compare the signer fingerprint against the device's
  platform certificate, not against a store listing. See the
  [signatures guide](signatures-and-integrity.md).
- `sharedUserId`: system apps often share a UID
  (`android.uid.system`, `android.uid.shared`). `nar-perms.py`
  reports it and flags it; apps that share a UID share a data
  directory and must be analyzed together.
- Permissions: `signature|privileged` permissions only work for
  apps in `priv-app/` (or a matching partition) signed with the
  platform key. `nar-perms.py` decodes the protection flags,
  including `privileged`.
- Old devices: system apps on Android 4.x-7 may be ODEXed, with
  the DEX stripped into `.odex`/`.oat` files beside the APK. See
  the [legacy guide](legacy-analysis.md).

Verification note: no system APK was on this machine. The pull
commands above are standard adb and were not run against a device
here; the triage and permission checks were verified on test APKs,
including a synthetic APK carrying `android.uid.system`.

## Fallbacks when the script is unavailable

```bash
sha256sum app.apk
unzip -l app.apk | head -50
aapt2 dump badging app.apk | head -30
```

These three commands give identity, inventory, and package info without
any NAR file. Use them when triaging on a machine where the repo is not
checked out.
