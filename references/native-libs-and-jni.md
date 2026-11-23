# Native libraries and JNI

Native code (`.so` files under `lib/<abi>/`) carries game engines,
crypto, media codecs, and performance-critical logic. Analyze it when
triage shows significant `.so` content, when DEX declares `native`
methods, or when the question is about a game engine.

## Inventory first

List libraries per ABI from triage, then extract one for inspection:

```bash
unzip -p app.apk lib/arm64-v8a/libexample.so > work/libexample.so
file work/libexample.so
```

Record the ABI (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`), the
architecture (AArch64 vs ARM vs x86), and whether the library is
stripped (no symbol table). Stripped libraries need more work: names
are gone, so analysis proceeds from strings, exports, and structure.

Quick signals before any decompiler:

```bash
strings work/libexample.so | grep -i -E "unity|unreal|godot|ssl|key|http" | head -30
nm -D work/libexample.so | head -40        # dynamic symbols (exports)
readelf -h work/libexample.so              # ELF header: machine, type
```

`strings` output is evidence of presence, not of behavior. A string
such as `https://api.example.com` proves the bytes exist; it does not
prove the library contacts that host.

## JNI bindings

Java `native` methods are implemented in `.so` files two ways:

### Static registration

The native function name encodes the Java declaration:

```
Java_<package>_<Class>_<method>
```

Underscores in names are escaped as `_1`. Find them with:

```bash
nm -D lib/arm64-v8a/*.so | grep " Java_"
```

Match each `Java_*` export against the `native` declarations in the
decompiled DEX. A declared native method with no matching export is
either dynamically registered or missing. A missing binding would crash at runtime, so note it as a finding.

### Dynamic registration (RegisterNatives)

The library calls `RegisterNatives` at load time (`JNI_OnLoad`) with a
table of `{name, signature, function pointer}` entries. These bindings
are invisible to `nm`: find them by decompiling `JNI_OnLoad` in Ghidra
or Kuna and reading the registration table. The table entries are the
evidence; record each `{class, method, signature}` triple.

Rules:

- A matched binding means the candidate implementation was observed.
  It does not prove the method is ever called.
- Runtime registration and class loading remain unknown from static
  analysis alone. If `JNI_OnLoad` is obfuscated or the table is built
  dynamically, say so and mark the bindings as partially unknown.
- `System.loadLibrary("name")` calls in DEX name the libraries the app
  loads. A `.so` with no loader call may be loaded by another `.so`
  or not at all.

## Game engines

### Unity

Detect: `libil2cpp.so` + `assets/bin/Data/Managed/Metadata/global-metadata.dat`
(IL2CPP), or `Assembly-CSharp.dll` + `libmono.so` (Mono). Confirm with
triage engine hints, then:

- IL2CPP: `global-metadata.dat` holds every managed type, method, and
  string literal. It is the key to the whole game: method names,
  field layouts, and string constants live there, while the code
  lives in `libil2cpp.so`. Metadata format versions 24, 27, 29, 31,
  and 39 are the commonly supported ones; other versions or encrypted
  metadata are unsupported by most tooling. Say so when you meet
  them. Use Il2CppDumper-style tooling (or REA's
  `inspect_il2cpp_metadata` when available) to dump the metadata,
  then resolve method addresses in `libil2cpp.so` with Ghidra.
  Without a linked binary, native addresses stay unknown.
- Mono: decompile `Assembly-CSharp.dll` with a .NET decompiler
  (ILSpy, dnSpyEx, or `ilspycmd`). This is managed code again, not
  native analysis.
- `libunity.so` is the engine itself. Analyzing it answers engine
  questions, not game questions; game logic lives in IL2CPP metadata
  or the Mono assemblies.
- Unity games also ship AssetBundles (`.bundle`, `.unity3d`) and
  `.assets` files. Inventory them from triage; extract with
  Unity-asset tooling when the question needs contents.

### Unreal Engine

Detect: `libUE4.so` (or `libUnreal.so`) plus `.pak` asset packs.
Unreal game logic is C++ in the `.so`; there is no managed metadata
to dump. Analysis is native decompilation (Ghidra/Kuna) guided by
exported symbols when present, plus `.pak` inventory for content
questions.

The engine version is not in any header. Triage extracts it from the
build string embedded in the engine library
(`++UE4+Release-4.16+Compile...` becomes `unreal_version: 4.16` in
the triage report); believe that string over any store listing.

Listing a `.pak`: extract the `.pak` from the APK or OBB, then use
the bundled stdlib-only lister:

```bash
python3 scripts/nar-pak.py game.pak            # first 50 entries
python3 scripts/nar-pak.py game.pak --limit 0  # all entries
python3 scripts/nar-pak.py game.pak --json     # machine-readable
```

It parses the FPakInfo footer and the index for pak format versions
1-7 and for the v10/v11 encoded index (path-hash + full directory
index), and prints each entry with packed/unpacked sizes and its
compression method (for v10+, resolved from the footer's
compression-method slots). Entries can also be pulled out of an
unencrypted pak (Zlib/Gzip entries are decompressed, stored entries
copied byte for byte; entries using a method with no decoder in the
Python standard library, such as Oodle, and encrypted entries
refuse plainly):

```bash
python3 scripts/nar-pak.py game.pak --extract "Content/Maps/*" --out work/pak-out
python3 scripts/nar-pak.py game.pak --extract "Engine/Config/Base.ini" --out work/pak-out
``` A layout is only accepted
when it consumes the index exactly (for v10+, both index regions
are also verified against their recorded SHA-1s), so a wrong guess
never produces plausible-looking garbage. Versions 8/9 use a
different FName-based index and are reported as unsupported,
plainly. An index whose footer flags it as AES-encrypted cannot be
read without the key; that is diagnosed explicitly instead of
inventing entries. Listing is inventory only:
names and sizes answer content questions, and entries can be matched
against the classes and assets the code references.

### Godot

Detect: `libgodot_android.so` (name varies by export template).
Godot games export in two layouts: a template binary plus a `.pck`
data pack, or a template binary with the project files loose under
`assets/`. A missing `.pck` is not an error; check which layout the
APK uses before choosing a tool. Worked example with measured
values: `examples/godot-triage.md`.

Loose-assets layout: inventory `assets/` by extension. The files
that matter are `.gdc` (compiled GDScript), `.scn` (binary
scenes), `.res` (binary resources), `.ctex` (compressed
textures), `.remap` (path remaps), and `project.binary` (magic
`ECFG`, readable with `strings`: it names the main scene, the
app version, enabled plugins, and the physics engine).

`.pck` layout: the bundled inspector reads the header and the file
directory for you, on an APK (embedded pack or loose layout) or a
bare `.pck`:

```bash
python3 scripts/nar-godot.py game.apk     # or: python3 scripts/nar-godot.py game.pck
python3 scripts/nar-godot.py game.pck --json
```

It reports the pack format, the engine version, the encryption flag,
and every contained file with its size, using a stdlib directory
parse (GodotPckTool is the fallback for layouts it cannot read).
For manual header work: the layout is magic `GDPC`, then four
little-endian uint32 values: pack format version, engine major,
minor, and patch.

```bash
python3 -c "
import struct
d = open('game.pck', 'rb').read(64)
fmt, maj, minor, patch = struct.unpack('<IIII', d[4:20])
print('magic:', d[:4])
print('pack format:', fmt, '| engine:', f'{maj}.{minor}.{patch}')
"
```

Pack format 1 is Godot 3.x, 2 is Godot 4.0 to 4.4, 3 is Godot
4.5 and later. List and extract the pack with GodotPckTool
(v2.3 verified here; Linux binary from its GitHub releases):

```bash
godotpcktool -p game.pck -a list
godotpcktool -p game.pck -a extract -o pck-out -q
```

Check the template version against the pack engine version.
The template carries its version as a string:

```bash
unzip -p app.apk lib/arm64-v8a/libgodot_android.so > libgodot_android.so
strings libgodot_android.so | grep -m 2 "stable"
```

A mismatch between template and pack is a finding; a match
means the pack was written by the template in the APK.

File magics inside the pack or the loose assets:

| Extension | Magic | Notes |
| --- | --- | --- |
| `.gdc` | `GDSC` | Compiled GDScript; uint32 bytecode version at offset 4, uint32 uncompressed size at offset 8 |
| `.scn`, `.res` | `RSRC` | Binary scene/resource; `strings` recovers node names and `res://` script paths |
| `.ctex` | `GST2` | Compressed texture |
| `.fontdata` | `RSCC` | Compressed font data |

GDScript bytecode versions: 12 to 13 for Godot 3, 100 for
Godot 4.3 and 4.4, 101 for Godot 4.5. A decompiler must be built
for the exact bytecode revision.

Scripts exported with compressed binary tokens
(`script_export_mode=2`) do not yield to `strings`: on the test
sample the `.gdc` files measured entropy 7.9 out of 8.0 and
`strings -n 8` returned nothing. Decompile them with GDRE Tools
(v2.7.1 verified here; Linux binary from its GitHub releases).
Pass the engine version; the tool maps it to the matching
bytecode revision. Without `--bytecode` the tool prints its
options and decompiles nothing.

```bash
# One script
gdre_tools.x86_64 --headless \
  --decompile="pck-out/<path>/script.gdc" \
  --bytecode=4.4.1 --output=gdre-out
# Whole project, straight from the APK
gdre_tools.x86_64 --headless --recover=app.apk --output=recovered
```

On the test APK, full recovery took 10 seconds and produced
620 files: all 89 scripts decompiled to `.gd`, 30 scenes
converted to readable `.tscn`, and `project.godot` recovered
as text, with one non-fatal font export error in the log.
The recovered `.tscn` files list their external resources by
`res://` path, which gives the scene-to-script map directly.

GDExtension code is native: a `.so` shipped alongside the
template is analyzed like any other native library. If the APK
ships no extra `.so` beyond the template and `libc++_shared.so`,
there is no GDExtension code to analyze.

### Custom engines

No engine markers means a custom native engine or a pure-Java game.
Work from the `.so` export list and strings, and from DEX package
names. Do not force-fit a game into an engine category it shows no
evidence for.

## Ghidra and Kuna on .so files

For deep native analysis, use Ghidra (headless) or Kuna:

```bash
# Ghidra headless: import and auto-analyze one library
# (create the project directory first: analyzeHeadless will not make it)
mkdir -p work/ghidra-proj
analyzeHeadless work/ghidra-proj NAR -import work/libexample.so
# Kuna: list functions, then decompile all or one function
kuna functions work/libexample.so
kuna decompile-all work/libexample.so
kuna decompile work/libexample.so Java_com_example_Native_doWork
```

Ghidra headless import runs auto-analysis and stores the project under
`work/ghidra-proj`. Read the decompilation in the Ghidra GUI by opening
that project, or drive it with your own GhidraScript. Note: Ghidra
12.2 ships no script named `Decompile`, so `-postScript Decompile`
fails. Do not copy that flag from older tutorials without checking.

Practical rules:

- Analyze one library at a time. A 150 MB `libxul.so` or `libUE4.so`
  needs a large heap and a long analysis; start with `nm -D` and
  strings, and decompile only the functions the question names.
- Keep Ghidra project directories under your workspace, not `/tmp`:
  project databases grow large.
- Pseudocode is an approximation. Verify critical claims against the
  disassembly, especially around arithmetic and control flow.
- Indirect calls and virtual calls stay unknown unless the analysis
  resolves them. Record unresolved call targets as unknowns.
