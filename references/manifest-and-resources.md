# Manifest and resources

The manifest declares what the app is and what it may do; the resources
carry its strings, layouts, and bundled content. Decode both before
reading code: they frame every later question.

## Decoding

```bash
apktool d app.apk -o out/apktool
```

This produces a readable `AndroidManifest.xml`, `res/` (layouts,
drawables, values), `assets/`, `lib/`, and smali under `smali*/`.
Useful flags:

- `apktool d -r app.apk`: skip resources, decode DEX/smali only. Use
  this when resource decoding fails or when you only need code.
- `apktool d -s app.apk`: skip sources, decode resources only.
- `apktool d -f app.apk`: overwrite an existing output directory.
- `apktool d --no-src app.apk`: the long form of `-s`.

When apktool fails on resources (framework errors), fall back to aapt2
without decoding:

```bash
aapt2 dump xmltree app.apk --file AndroidManifest.xml
aapt2 dump resources app.apk
aapt2 dump badging app.apk
```

`aapt2 dump xmltree` prints the binary XML as readable text, including
attribute resource IDs. It never writes a tree, so it is the fastest
route to one manifest answer.

One caution on decoded output: some system apktool builds garble
fragments of the decoded manifest XML (attributes merged into one
another, stray entities), so a decoded manifest can look subtly wrong
even when the APK is fine. Cross-check before trusting it:
`nar-perms.py` parses the binary manifest with its own parser, and
`aapt2 dump xmltree` reads it independently. When the three disagree,
trust the two that agree.

## AndroidManifest.xml: what to extract

- Identity: `package`, `android:versionCode`, `android:versionName`.
- SDK: `uses-sdk` (`minSdkVersion`, `targetSdkVersion`).
  `minSdkVersion` bounds the Android APIs the code can rely on;
  `targetSdkVersion` bounds runtime behavior. `compileSdkVersion`
  is a manifest attribute, not part of `uses-sdk`.
- Permissions: every `uses-permission`. Group them: normal, dangerous
  (runtime-granted), signature. Note dangerous ones and whether the
  code actually uses them. A declared permission the code never
  exercises is a finding, not a behavior.
- Components: `activity` (note `exported` and intent filters; the
  `MAIN`/`LAUNCHER` activity is the entry point), `service`,
  `receiver`, `provider` (note `authorities` and `exported`).
- Intent filters: actions, categories, data schemes. Deep links
  (`VIEW` + `data android:scheme`) are part of the app's interface.
- `application` attributes: `android:name` (custom Application class, the first code that runs), `allowBackup`, `debuggable`,
  `networkSecurityConfig`, `usesCleartextTraffic`, `extractNativeLibs`.
- Meta-data: `meta-data` entries often carry SDK keys and flags.
  Record them; never publish secrets found here.
- Split markers: a split APK's own badging lists its split name,
  and dynamic-feature splits carry `android:isFeatureSplit`.

Report components as observed declarations. A declared component that
is never reached from code is still part of the attack surface; a
component reached only by reflection stays an unknown until runtime
evidence confirms it.

## resources.arsc structure

`resources.arsc` is a chunked binary table: string pool, package chunks,
type chunks, and entry values. You normally read it through apktool or
`aapt2 dump resources`, not by hand. When you must parse it by hand
(for example, in your own tooling), know these facts:

- Every chunk starts with a 16-bit type, a 16-bit header size, and a
  32-bit chunk size. Walk by chunk size; never assume a fixed layout
  beyond the header.
- A package chunk (`ResTable_package`, type `0x0200`) carries its
  fields at fixed offsets from the chunk start: the package name
  (UTF-16, 128 chars) at +12, the `typeStrings` string-pool offset at
  +268, and the `keyStrings` string-pool offset at +276. (NAR
  hard-won note: these offsets are stable across `resources.arsc`
  writers; do not re-derive them from the header size.)
- Resource IDs are `0xPPTTEEEE`: package byte, type byte, entry
  index. The `R` class in decompiled code maps names to these IDs.
- Type chunks hold entry offsets; entries hold values (strings,
  references, dimensions, colors) or a reference to another entry.
  A value of type `TYPE_REFERENCE` must be followed to its target.
- String pools are UTF-8 or UTF-16; the pool header flags say which.
  Binary XML files (layouts, manifest) carry their own string pools
  with the same encoding rules.

Common pitfall: string values in `aapt2 dump resources` are resolved
references, while raw ARSC entries may be references to other entries.
When a value matters, follow the reference chain to the literal.

## Strings and assets inventory

After decoding, inventory strings and assets by size and type:

```bash
grep -r "http" out/apktool/res/values/strings.xml | head -20
find out/apktool/assets -type f -printf '%s %p\n' | sort -nr | head -30
find out/apktool/res/raw -type f -printf '%s %p\n' | sort -nr | head -20
```

What to look for:

- URLs, API hosts, and endpoint paths in strings: map them to the
  code that uses them before claiming any network behavior.
- Game content in `assets/`: level data, audio, video, JSON configs.
  Record sizes and formats; large opaque blobs are content, not code.
- `res/raw/` audio and video: note formats and sizes.
- Asset bundles (`.pak`, `.bundle`, `.unity3d`, `.assets`): inventory
  with `nar-triage.py` first, then list contents per bundle if the
  question needs it. Unity AssetBundles and Unreal `.pak` files have
  their own container formats; use dedicated extractors rather than
  guessing at bytes.
- Native libraries shipped in `assets/` instead of `lib/` (some games
  and SDKs do this): they are loaded at runtime, so the triage `.so`
  list understates native code. Note them explicitly.

## Binary XML string pools

Binary XML (`AndroidManifest.xml` in the APK, compiled layouts) stores
all strings in a pool at the top of the file, then references them by
index. When hand-parsing: read the pool first, then resolve attribute
values by index. Attribute names are resource IDs resolved against the
framework (`android:` namespace) or the app's own `R` class. Never
infer an attribute's meaning from its raw integer value.
