# Version compare and feature map

Comparing two versions of the same app answers "what changed?" with
evidence instead of release-note guesses. A feature map turns that
evidence into a durable document: feature, where it lives, how sure
you are.

## Setup: decode both versions the same way

Use identical tool versions and flags for both APKs, or the diff will
be full of tool noise:

```bash
apktool d app-v1.apk -o work/v1/apktool
apktool d app-v2.apk -o work/v2/apktool
jadx -d work/v1/jadx app-v1.apk
jadx -d work/v2/jadx app-v2.apk
```

For split sets, compare base-to-base and split-to-split with matching
split names. For AABs, compare the same module (`base`) in both.

## Manifest diff

```bash
diff -u work/v1/apktool/AndroidManifest.xml work/v2/apktool/AndroidManifest.xml
```

Read for: version bump, SDK changes, added or removed permissions,
added or removed components, changed intent filters, changed
`application` attributes (`debuggable` flipping on is a red flag),
provider authority changes. A permission added without a matching
code change is a finding; a component removed while code still
references it is a bug.

## DEX / code diff

```bash
diff -rq work/v1/jadx/sources work/v2/jadx/sources
diff -u work/v1/jadx/sources/com/example/Foo.java work/v2/jadx/sources/com/example/Foo.java
```

Work in layers:

1. Added and removed classes (`diff -rq`): new features, removed
   features, new SDKs (a whole new package tree usually means a new
   library, not new app code).
2. Changed classes: read the method-level diff. Focus on behavior
   changes, not formatting.
3. Obfuscation trap: if both versions are obfuscated with different
   mappings, class names will differ everywhere and a textual diff is
   useless. Compare by structure instead: method counts, string
   literals, API call sets. With both `mapping.txt` files,
   deobfuscate both sides first with a tool that accepts ProGuard
   mappings (REA's Android tools do; plain jadx CLI does not, see
   the DEX guide).
4. String diff: `diff` the sorted string lists from both DEX files.
   New strings reveal new features, endpoints, and UI text.

## Resource diff

```bash
diff -rq work/v1/apktool/res work/v2/apktool/res
diff -u work/v1/apktool/res/values/strings.xml work/v2/apktool/res/values/strings.xml
```

New layouts and drawables track UI changes. New `res/raw` audio or
`assets/` content tracks game content changes. Compare `assets/` by
file list and sizes; hash large files instead of diffing bytes.

## Native diff

For each `.so` present in both versions:

```bash
sha256sum work/v1/lib/arm64-v8a/libexample.so work/v2/lib/arm64-v8a/libexample.so
nm -D work/v1/lib/arm64-v8a/libexample.so > work/v1/exports.txt
nm -D work/v2/lib/arm64-v8a/libexample.so > work/v2/exports.txt
diff -u work/v1/exports.txt work/v2/exports.txt
```

Identical hash means unchanged: skip it. Changed exports mean a
changed interface; decompile only the changed functions. For Unity
IL2CPP games, also dump both `global-metadata.dat` files and diff
the dumps (method and type additions are the game's changelog).

## Signature check across versions

Run `apksigner verify --print-certs` on both. The certificate
fingerprint must match (or a v3 lineage must connect them). A changed
signer without lineage means users cannot upgrade in place. Record
the fingerprints in the comparison report.

## Building a feature map

A feature map is a document, not a dump. One row per feature:

| Feature | Evidence | Confidence |
|---|---|---|
| Login with email | `com.example.auth.LoginActivity`, `POST /v1/login` in `strings.xml`, `OkHttp` call in `ApiClient.login()` | High |
| Offline cache | `Room` database `cache.db`, `CacheDao` class | Medium (schema seen, eviction logic not traced) |

Rules:

- One feature per row. Evidence is a file, class, method, or resource
  cite. Never "somewhere in the app".
- Confidence is High (code read end to end), Medium (entry points
  seen, internals partial), or Low (inferred from strings or layout
  only). Unknowns get their own row, not a confident guess.
- Include a "not found" section: features the user asked about that
  no evidence supports, with the search boundary (which DEX files,
  which string searches) so the negative result is checkable.
- Date the map and record both APK digests. A map without digests
  rots the moment the app updates.

## Reconstruction guidance

A feature map often feeds a rebuild. The rule is simple: rebuild from
understanding, not from copying.

- Write original code from the feature map's behavior description.
  Never copy decompiled code verbatim into a shipping product:
  decompiled output is derived from someone else's binary, and
  copying it wholesale is both a legal risk and a quality risk
  (decompiler artifacts become your bugs).
- Reimplement protocols and file formats from observed behavior and
  documented specs, not from pasted disassembly.
- Keep the map and the new code separate: the map is evidence, the
  code is yours. When a behavior is unclear, mark it unknown in the
  map and design your own behavior rather than guessing at theirs.
