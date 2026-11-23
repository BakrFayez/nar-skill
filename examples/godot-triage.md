# Worked example: Godot 4 triage and pack recovery

A full Godot 4 session on a real, legal test APK. Every value below
was recorded from the actual run on 2026-11-23. The workflow is
documented in `references/native-libs-and-jni.md` (Godot section);
this file is the evidence that the workflow runs end to end.

## Test APK

The test file is a Godot 4 game from an open-source project. App
identity is left out of this example on purpose: the numbers below
are the evidence, not the game.

- File: `example.apk`
- Size: 32,510,067 bytes
- Package: `com.example.app`, version 1.5.2 (code 10502)
- Label: Sample App
- SDK: min 21 / target 34
- Engine: Godot 4.4.1 (pack header and template strings agree)

## 1. Triage

```bash
python3 ~/workspace/nar-skill/scripts/nar-triage.py example.apk
```

Full output (identity fields replaced with the generic labels above):

```text
NAR triage: example.apk
============================================================
SHA-256: <64-hex digest of the file>
Size:    32,510,067 bytes
Package: com.example.app  v1.5.2 (code 10502)
SDK:     min 21 / target 34  label: Sample App
ZIP entries: 505  |  AndroidManifest.xml: yes  |  resources.arsc: yes
DEX: 1 file(s), 5,138,996 bytes total  |  format version(s): 035
  - classes.dex  (DEX 035, 5,138,996 bytes)
DEX markers (string fingerprints inside DEX; a hit means the framework's classes are referenced):
  - Godot wrapper: 224 hit(s) in classes.dex x224
  - Kotlin: 2 hit(s) in classes.dex x2
Native libs: 2 file(s)
  - [arm64-v8a] libc++_shared.so  (6,933,952 bytes)
  - [arm64-v8a] libgodot_android.so  (69,115,784 bytes)
Signing files: META-INF/MANIFEST.MF, META-INF/CERT.RSA, META-INF/CERT.SF
Signature schemes (apksigner): v1 yes, v2 yes, v3 yes, v3.1 no, v4 no  |  signers: 1  |  verifies
Assets: 392 file(s)  |  res/: 71 file(s)  |  other: 11 file(s)
Engine hints (path signatures; confirm with the native guide):
  - Godot: 1 marker(s), e.g. lib/arm64-v8a/libgodot_android.so
Baseline profiles: assets/dexopt/baseline.prof, assets/dexopt/baseline.profm
```

Only one ABI is shipped (`arm64-v8a`), so there was no ABI choice
to make. The DEX is the Godot Android wrapper plus AndroidX and
Kotlin support code; the game logic is not in DEX.

## 2. Layout: loose assets, no .pck in the APK

Godot Android exports come in two layouts. This sample uses the
loose-assets layout: the project files sit directly under
`assets/`, and there is no `.pck` file in the APK. Do not treat a
missing `.pck` as a failed export. Inventory what is there:

```bash
unzip -l example.apk | grep -i "\.pck"
# no matches: this export has no pack
mkdir -p x && cd x && unzip -q -o ../example.apk 'assets/*'
find assets -type f | sed 's/.*\.//' | sort | uniq -c | sort -rn
```

File counts by extension under `assets/` (392 files, 7.9 MB):

| Extension | Count | What it is |
| --- | --- | --- |
| `.remap` | 123 | Path remaps from source name to exported name |
| `.gdc` | 89 | Compiled GDScript (bytecode) |
| `.import` | 68 | Import settings for textures, models, fonts |
| `.ctex` | 49 | Compressed textures (ETC2 on this Android export) |
| `.scn` | 36 | Binary scenes |
| `.fontdata` | 13 | Font data |
| `.res` | 4 | Binary resources |
| `.gdshader` | 1 | Shader source (plain text) |
| `.cfg`, `.binary`, `.bin`, `.json`, `.svg`, `.prof`, `.profm`, `_cl_` | 9 | Project config, UID cache, profiles, misc |

The project config is `assets/project.binary` (magic `ECFG`).
It is a binary config file, but `strings` reads most of it: the
app name, version, main scene path, enabled editor plugins, the
physics engine, and the rendering method are all plain strings
in the file. Read it before opening any other file; it names the
main scene, which is where analysis of the game flow starts.

## 3. The .pck pack (from the same project, web export)

The same open-source project also ships a web export, which does
use a pack. That pack is the same project content in pack form,
so it is a valid test of the `.pck` workflow. The pack is
12,308,656 bytes.

Read the header first. The layout is magic `GDPC`, then four
little-endian uint32 values: pack format version, engine major,
minor, and patch.

```bash
python3 -c "
import struct
d = open('game.pck', 'rb').read(64)
print('magic:', d[:4])
fmt, maj, minor, patch = struct.unpack('<IIII', d[4:20])
print('pack format:', fmt, '| engine:', f'{maj}.{minor}.{patch}')
"
```

Output on the test pack:

```text
magic: b'GDPC'
pack format: 2 | engine: 4.4.1
```

Pack format 2 is Godot 4.0 to 4.4; format 1 is Godot 3.x.
(See `references/modern-analysis.md` for the full version map.)

List and extract with GodotPckTool (v2.3, Linux binary from its
GitHub releases):

```bash
godotpcktool -p game.pck -a list
godotpcktool -p game.pck -a extract -o pck-out -q
```

Output:

```text
Pck version: 2, Godot: 4.4.1
Contents of 'game.pck':
...
end of contents.
```

The pack holds 392 files, the same count as the APK assets. The
two sets are not byte-identical: the web pack uses S3TC texture
variants where the APK uses ETC2, and each export carries its own
platform-only files (the APK has the DEX baseline profiles and
web service-worker files the pack does not). The scripts, scenes,
and resources are the same files in both.

## 4. Template version check

The export template and the pack are versioned together. Confirm
the template matches the pack before trusting deeper results:

```bash
unzip -p example.apk lib/arm64-v8a/libgodot_android.so > libgodot_android.so
strings libgodot_android.so | grep -m 2 "4.4.1.stable"
```

Output:

```text
4.4.1.stable.official
Godot Engine v4.4.1.stable.official
```

Template 4.4.1 matches pack engine 4.4.1: no version mismatch.
The library is a 69,115,784-byte AArch64 shared object with 62
`Java_` exports (the Android wrapper JNI bindings) and 87 lines
matching `GDScript` in its strings.

## 5. Scripts: compiled, compressed, not readable with strings

Every `.gdc` file starts with magic `GDSC`, then a uint32
bytecode version, then a uint32 uncompressed size:

```bash
python3 -c "
import struct, glob, os
for f in sorted(glob.glob('pck-out/**/*.gdc', recursive=True))[:3]:
    d = open(f, 'rb').read(12)
    print(os.path.basename(f), 'size', os.path.getsize(f),
          'bytecode version:', struct.unpack('<I', d[4:8])[0],
          'uncompressed size:', struct.unpack('<I', d[8:12])[0])
"
```

On the test sample every `.gdc` reports bytecode version 100
(Godot 4.3 and 4.4; version 101 is Godot 4.5). A 2,575-byte file
reports an uncompressed size of 8,016, so the token stream is
compressed. That matches the export setting
`script_export_mode=2` (compressed binary tokens) in the
project's public export preset.

Consequence, measured: `strings -n 8` on a `.gdc` file returns
nothing, and the file entropy is 7.9 out of 8.0. Do not expect
`strings` to recover script content from a Godot 4 export that
uses compressed tokens. The scripts are recoverable only with a
decompiler built for the matching bytecode version.

## 6. Scenes and resources: binary, but strings still work

Binary scene and resource files use magic `RSRC` (`.scn`,
`.res`); compressed textures use `GST2` (`.ctex`); font data
uses `RSCC` (`.fontdata`). Unlike the scripts, scenes are not
compressed, so `strings` on a `.scn` file recovers the scene
structure: the `PackedScene` type, node names, and the
`res://` paths of attached scripts and resources. That is enough
to map which script belongs to which scene before decompiling
anything.

## 7. GDScript decompile with GDRE Tools

GDRE Tools (v2.7.1, Linux binary from its GitHub releases)
decompiles `.gdc` files headlessly. The bytecode version must
match the engine version; pass the engine version and the tool
picks the matching bytecode revision.

Single file:

```bash
gdre_tools.x86_64 --headless \
  --decompile="pck-out/<path>/script.gdc" \
  --bytecode=4.4.1 --output=gdre-out
```

Output:

```text
Decompiling from bytecode version 77af6ca (4.3.0-stable)
Decompiling pck-out/<path>/script.gdc
Output file: gdre-out/script.gd
Decompilation complete
```

The decompiled file is readable GDScript: class declaration,
exported variables, constants, and functions, matching the
original source structure (comments and original formatting are
not preserved). Note the tool maps engine 4.4.1 to bytecode
revision `77af6ca`, labeled 4.3.0-stable: bytecode version 100
covers both 4.3 and 4.4, so this is the correct revision, not a
mismatch.

Without `--bytecode` the tool prints its options and decompiles
nothing. That is the first error to check for when a decompile
run produces no output.

## 8. Full project recovery from the APK

GDRE Tools can recover the whole project straight from the APK,
decompiling scripts and converting binary scenes to text:

```bash
gdre_tools.x86_64 --headless --recover=example.apk --output=recovered
```

Output (tail):

```text
Use Godot editor version 4.4.1.stable to edit the project.
Recovery finished in 00m10s
```

Results on the test APK:

- 620 files recovered in 10 seconds
- 89 `.gd` scripts decompiled (all of the `.gdc` files)
- 30 `.tscn` scenes converted to text (format 3, with
  `ext_resource` entries naming scripts, textures, and shapes)
- `project.godot` recovered as a text config file
- 2 error lines in the log, both the same non-fatal font issue
  (`Font has no textures` during a bitmap font export); nothing
  else failed

The recovered `.tscn` files are the fastest way to read the
game structure: each one lists its external resources by
`res://` path, so the scene-to-script map falls out of a plain
text search.

## Findings summary

- Godot 4.4.1, template and pack versions match.
- Loose-assets Android layout: 392 files under `assets/`, no
  `.pck` in the APK. The `.pck` workflow was verified on the
  same project's web export pack (pack format 2, 392 files).
- 89 compiled scripts, bytecode version 100, compressed tokens:
  `strings` recovers nothing from them; GDRE Tools decompiles
  all 89.
- 36 binary scenes; `strings` recovers node names and script
  paths, and full recovery converts 30 of them to readable
  `.tscn`.
- No GDExtension native modules in this sample: the only native
  libraries are the engine template and `libc++_shared.so`.
