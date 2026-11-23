# App bundles and split APKs

An Android App Bundle (`.aab`) is a publishing format, not an
installable file. You cannot install an `.aab` on a phone. Google
Play (or bundletool, locally) turns it into split APKs, and the
device installs the splits that match its configuration. Reversing
work therefore starts by either reading the bundle directly or
generating APKs from it with bundletool.

All commands in this guide were run against bundletool 1.18.1 and a
real test bundle: 14,095,721 bytes, package `com.example.game`,
version 1.0, code 1.
Anything not run here is marked untested.

## AAB structure

An `.aab` is a ZIP. List it before doing anything else:

```bash
unzip -l app.aab
```

The test bundle has 142 entries in a single `base/` module:

| Path | What it is |
|---|---|
| `BundleConfig.pb` | Bundle metadata. Here it holds only the builder version string (`1.17.2`), 10 bytes. |
| `META-INF/` | JAR signature of the bundle itself (`MANIFEST.MF`, `CERT.SF`, `CERT.RSA`). |
| `base/manifest/AndroidManifest.xml` | The base module manifest, in binary XML. |
| `base/dex/classes.dex` | The base module code, 132,808 bytes. |
| `base/res/` | Resources, 17 entries (icons in 5 densities, 12 raw audio files). |
| `base/assets/` | Game assets, 117 entries. |
| `base/resources.pb` | Resource table describing the resources and their targets. |
| `base/assets.pb` | Asset table describing the assets and their targets. |

This bundle has no `native.pb` (no native libraries), no
`BUNDLE-METADATA/` directory, and no extra modules. A larger app
typically adds feature modules (`feature1/`, `feature2/`, ...),
asset packs, and a `BUNDLE-METADATA/` directory with items such as
ProGuard mappings. Those are not packaged into the APKs.

Note the layout differences from an APK: the manifest lives under
`manifest/`, the DEX files under `dex/`, and the resource table is
`resources.pb` instead of `resources.arsc`. Tools that expect APK
layout will not read a bundle directly.

## bundletool: validate and dump

bundletool is the reference tool for bundles. This skill was verified
with bundletool 1.18.1:

```bash
java -jar bundletool-all-1.18.1.jar validate --bundle=app.aab
java -jar bundletool-all-1.18.1.jar dump manifest --bundle=app.aab
java -jar bundletool-all-1.18.1.jar dump manifest --bundle=app.aab --xpath=/manifest/@package
```

`validate` exits 0 on a well-formed bundle and prints the module
list with every file. `dump manifest` prints the merged manifest
as readable XML. The test manifest reads: package `com.example.game`,
versionCode 1, versionName 1.0, minSdk 24,
targetSdk 34, one launcher activity (`.MainActivity`), no
permissions declared.

## bundletool: build-apks

`build-apks` generates APKs from a bundle. It signs the output, so
it needs a keystore. Use a throwaway key for analysis, never a
release key:

```bash
keytool -genkeypair -keystore test-debug.keystore -storepass android \
  -keypass android -alias testkey -keyalg RSA -keysize 2048 \
  -validity 30 -dname "CN=NAR Test, O=NAR, C=EG"
```

Default mode generates every split the bundle can produce:

```bash
java -jar bundletool-all-1.18.1.jar build-apks --bundle=app.aab \
  --output=app.apks --ks=test-debug.keystore --ks-pass=pass:android \
  --ks-key-alias=testkey --key-pass=pass:android
```

On the test bundle this produced a 28,240,452 byte `.apks`
containing two APKs and a table of contents:

```text
toc.pb                      196 bytes
splits/base-master.apk      14,087,183 bytes
splits/base-master_2.apk    14,152,719 bytes
```

Two master APKs and no config splits. The split is by SDK version:
one variant targets SDK 24-28, the other SDK 29 and up. The 29+
variant stores `classes.dex` uncompressed (132,808 bytes stored)
so the runtime can map it directly; the 24-28 variant deflates it
(68,868 bytes compressed). Both APKs contain the same 143 ZIP
entries. There are no density, ABI, or language splits here because
the bundle has no native libraries and its minimal `BundleConfig.pb`
does not request them.

Universal mode generates one APK that runs on any device:

```bash
java -jar bundletool-all-1.18.1.jar build-apks --mode=universal \
  --bundle=app.aab --output=app-universal.apks \
  --ks=test-debug.keystore --ks-pass=pass:android \
  --ks-key-alias=testkey --key-pass=pass:android
```

On the test bundle this produced a 14,087,488 byte `.apks`
holding a single `universal.apk` of 14,087,183 bytes. Use universal
mode when you want one file to decompile; use default mode when you
want to see how the app splits.

An `.apks` file is itself a ZIP: `toc.pb` (a protobuf describing
which APK suits which device) plus the APKs under `splits/`.
Unzip it and triage each APK with
[nar-triage.py](../scripts/nar-triage.py) as usual.

## bundletool: get-size and extract-apks

`get-size` works on an `.apks`, not on an `.aab`. Passing `--aab`
fails with `Missing the required --apks flag`:

```bash
java -jar bundletool-all-1.18.1.jar get-size total --apks=app.apks
java -jar bundletool-all-1.18.1.jar get-size total --apks=app.apks \
  --dimensions=SDK,ABI,SCREEN_DENSITY,LANGUAGE
```

On the test APKS this reported MIN,MAX of 14,073,374 and
14,074,230 bytes, and the dimension breakdown confirmed the SDK
split: SDK 24-28 is 14,073,374 bytes, SDK 29+ is 14,074,230 bytes.
The universal APKS reported a single size of 14,073,394 bytes.

`extract-apks` pulls out the APKs one device would receive, given a
device spec file:

```bash
java -jar bundletool-all-1.18.1.jar extract-apks --apks=app.apks \
  --output-dir=extracted --device-spec=device-spec.json
```

With a device spec of SDK 34, arm64-v8a, 480 dpi, locale `en`,
extraction returned only `base-master_2.apk` (14,152,719 bytes),
the SDK 29+ variant. Installing the extracted set on a device
(`adb install-multiple`, or `bundletool install-apks`) is untested
here: no device was attached.

## XAPK and APKM containers

Third-party stores distribute split APKs in their own ZIP
containers. Both are plain ZIPs, so the analysis flow is the same:
unzip, read the metadata file, triage every APK inside.

### XAPK (APKPure)

An `.xapk` holds APKs, optional OBB expansion files, and a
`manifest.json` describing the package and its splits. A test XAPK
was built here from two test APKs (one as `base.apk`,
one as `split_config.en.apk`) with this manifest:

```json
{
  "xapk_version": 1,
  "package_name": "com.example.app",
  "name": "Sample App",
  "version_code": 1,
  "version_name": "1.0",
  "min_sdk_version": 24,
  "target_sdk_version": 34,
  "total_size": 3264982,
  "split_apks": [
    {"id": "base", "file": "base.apk", "size": 1632491},
    {"id": "config.en", "file": "split_config.en.apk", "size": 1632491}
  ],
  "expansions": []
}
```

The resulting file is 3,246,555 bytes.
Unzip and triage verified the flow end to end:

```bash
unzip -l app.xapk
unzip app.xapk -d extracted
python3 scripts/nar-triage.py extracted/base.apk
python3 scripts/nar-triage.py extracted/split_config.en.apk
```

The extracted `base.apk` hashed identically to the original
test APK,
and the triage script flagged the second file as a split APK by
name. Note the test XAPK reuses two full APKs as container
contents; a real XAPK holds a base APK plus true config splits
that complement it, not two standalone builds.

### APKM (APKMirror)

An `.apkm` is also a ZIP. Per the published APKM format spec, it
holds `info.json` (package metadata), `icon.png`, `base.apk`, and
`split_config.*.apk` files (ABI, density, and language splits),
plus a JAR signature of the archive itself under `META-INF/`
(`APKMIRRO.SF`, `APKMIRRO.RSA`). No real `.apkm` file was
available here, so this layout is taken from the spec, not verified
against a sample. Treat `info.json` as the metadata source; some
secondary write-ups call it `manifest.json`, but the spec and real
listings use `info.json`.

## Play Asset Delivery

Play Asset Delivery (PAD) is how Google Play delivers large game
assets that live in an AAB as asset packs. It is a delivery
mechanism, not a file format: there is no separate PAD file to
triage. The asset packs sit inside the bundle as top-level
directories next to `base/`, and Play serves them in one of three
modes:

- Install-time: delivered with the app install.
- Fast-follow: delivered shortly after install, while the app can
  already run.
- On-demand: delivered only when the app requests the pack.

PAD replaced OBB expansion files for new Play apps: since August
2021 new apps must use Play Asset Delivery or Play Feature Delivery
for content over the download size limit instead of OBBs. When you
triage a bundle with asset packs, list each pack directory, note
its delivery mode from its manifest, and remember that on-demand
packs may never reach a given device. No bundle with asset packs
was available here, so pack-level commands are untested.

## A note on "PBA"

No Android delivery format called PBA exists in the Android
developer documentation, in bundletool 1.18.1, or in web sources
checked for this guide. The `.pba` extension belongs to unrelated
desktop formats (OpenOffice Basic protected modules, CyberLink
PowerBackup archives). If a source mentions PBA delivery for
Android, treat it as unverified and ask for the exact format
definition; the likely intended term is PAD (Play Asset Delivery),
covered above.

## What this guide does not cover

- Installing split APKs on a device: untested, no device attached.
- Multi-module bundles with dynamic feature modules: the test
  bundle has one module only, so feature-module behavior (delivery
  conditions, on-demand install) is described from the format docs,
  not from a run.
- Asset packs: no sample bundle with asset packs was available.
