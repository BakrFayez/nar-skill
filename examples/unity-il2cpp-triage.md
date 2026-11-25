# Worked example: Unity IL2CPP triage and dump

A full IL2CPP session on a real, legal test APK. Every value below was
recorded from the actual run on 2026-11-23. The workflow is documented
in `references/unity-il2cpp.md`; this file is the evidence that the
workflow runs end to end.

## Test APK

The test file is a Unity game built with IL2CPP (64-bit), from an
open-source project. App identity is left out of this example on
purpose: the numbers below are the evidence, not the game.

- File: `example.apk`
- Size: 63,764,627 bytes
- Package: `com.example.game`, version 1.0 (code 1)
- Label: Sample Game
- SDK: min 23 / target 36
- Unity version: 2022.3.62f3 (from build paths in `libil2cpp.so` strings)

## 1. Triage

```bash
python3 ~/workspace/nar-skill/scripts/nar-triage.py example.apk
```

Full output:

```text
NAR triage: example.apk
============================================================
SHA-256: <64-hex digest of the file>
Size:    63,764,627 bytes
Package: com.example.game  v1.0 (code 1)
SDK:     min 23 / target 36  label: Sample Game
Permissions (4): android.permission.INTERNET, android.permission.MANAGE_EXTERNAL_STORAGE, android.permission.READ_EXTERNAL_STORAGE, android.permission.WRITE_EXTERNAL_STORAGE
ZIP entries: 800  |  AndroidManifest.xml: yes  |  resources.arsc: yes
DEX: 1 file(s), 177,168 bytes total
  - classes.dex  (177,168 bytes)
Native libs: 4 file(s)
  - [arm64-v8a] lib_burst_generated.so  (103,064 bytes)
  - [arm64-v8a] libil2cpp.so  (73,037,032 bytes)
  - [arm64-v8a] libmain.so  (6,728 bytes)
  - [arm64-v8a] libunity.so  (18,023,304 bytes)
META-INF (5): META-INF/CERT.RSA, META-INF/CERT.SF, META-INF/MANIFEST.MF, META-INF/com.android.games.engine.build_fingerprint, META-INF/com/android/build/gradle/app-metadata.properties
Signing files: META-INF/CERT.RSA, META-INF/CERT.SF, META-INF/MANIFEST.MF
Assets: 758 file(s)  |  res/: 30 file(s)  |  other: 2 file(s)
Asset bundles (3, 228,966 bytes):
  - assets/aa/Android/localization-assets-shared_assets_all.bundle  (34,098 bytes)
  - assets/aa/Android/localization-locales_assets_all.bundle  (2,395 bytes)
  - assets/aa/Android/localization-string-tables-english_assets_all.bundle  (192,473 bytes)
Engine hints (path signatures; confirm with the native guide):
  - Unity (IL2CPP): 2 marker(s), e.g. assets/bin/Data/Managed/Metadata/global-metadata.dat
```

The DEX is tiny (177,168 bytes): it is only the Unity player stub. All
game logic is in the native library. Only one ABI is shipped
(`arm64-v8a`), so there was no ABI choice to make.

## 2. Extraction and metadata header

```bash
unzip -o -q example.apk \
  "assets/bin/Data/Managed/Metadata/global-metadata.dat" \
  "lib/arm64-v8a/libil2cpp.so" -d extract
file extract/lib/arm64-v8a/libil2cpp.so
```

Extracted files:

- `assets/bin/Data/Managed/Metadata/global-metadata.dat`: 12,840,952 bytes
- `lib/arm64-v8a/libil2cpp.so`: 73,037,032 bytes, ELF 64-bit LSB shared
  object, ARM aarch64, dynamically linked, stripped,
  BuildID `<build-id>`

Header check:

```text
magic: 0xfab11baf  version: 31
magic OK (0xFAB11BAF): True
```

Metadata format version 31, plain (not encrypted).

## 3. Tool install

Il2CppDumper was not installed (`which il2cppdumper` found nothing), and
no .NET runtime was on the machine. Installed for this run:

- Il2CppDumper v6.7.46, net6 build, from
  https://github.com/Perfare/Il2CppDumper/releases/download/v6.7.46/Il2CppDumper-net6-v6.7.46.zip
- Zip SHA-256:
  `db9bbbc538e33abfb057c7757ae5d6c1f16a05fdc0d13af8a5a67ea31faaba0c`
- Installed to `~/workspace/tools/il2cppdumper/`
- .NET runtime 6.0.36, installed with the official install script to
  `~/workspace/tools/dotnet/`

Config change before the run: `GenerateDummyDll` and `RequireAnyKey`
both set to `false` in `~/workspace/tools/il2cppdumper/config.json`.
See section 5 for why.

## 4. The dump

```bash
~/workspace/tools/dotnet/dotnet ~/workspace/tools/il2cppdumper/Il2CppDumper.dll \
  extract/lib/arm64-v8a/libil2cpp.so \
  extract/assets/bin/Data/Managed/Metadata/global-metadata.dat \
  il2cpp-dump < /dev/null
```

Run time was about 17 seconds, exit code 0. Log:

```text
Initializing metadata...
Metadata Version: 31
Initializing il2cpp file...
Applying relocations...
WARNING: find JNI_OnLoad
ERROR: This file may be protected.
Il2Cpp Version: 31
Searching...
CodeRegistration : 4098538
MetadataRegistration : 41f0538
Dumping...
ERROR: Some errors in dumping
Done!
Generate struct...
Done!
```

Output files:

| File | Bytes | Lines |
| --- | --- | --- |
| dump.cs | 29,152,061 | 820,961 |
| il2cpp.h | 73,001,461 | 2,593,219 |
| script.json | 82,314,188 | 1,615,225 |
| stringliteral.json | 1,883,592 | 88,197 |

Counts:

| What | Count | Source |
| --- | --- | --- |
| Types | 12,555 | `TypeDefIndex:` lines in dump.cs |
| Types | 12,553 | `ScriptMetadata` in script.json |
| Methods with RVA | 188,699 | `RVA: 0x` lines in dump.cs |
| Methods with RVA | 188,702 | `ScriptMethod` in script.json |
| String literals | 22,049 | `ScriptString` in script.json |
| Metadata methods | 24,381 | `ScriptMetadataMethod` in script.json |
| Function addresses | 210,136 | `Addresses` in script.json |
| Assemblies (images) | 60 | `// Image` lines in dump.cs |
| Types in GameCode namespaces | 1,084 | namespace lines in dump.cs |
| Methods in GameCode namespaces | 15,415 | `ScriptMethod` names |

The 3-method and 2-type gaps between `dump.cs` and `script.json` are
the visible trace of the "Some errors in dumping" line. The dump is
accurate within a few entries, not exact to one.

## 5. Errors hit and fixed

**Dummy DLL crash.** The first run used the default config and crashed
while generating dummy DLLs: `System.Exception: Invalid compressed
integer format` in `GetConstantValueFromBlob`. This is a bug in
Il2CppDumper's constant-blob reader on this metadata. Fix: set
`GenerateDummyDll` to `false` in `config.json` and rerun. The rerun
produced byte-identical `dump.cs`, `il2cpp.h`, `script.json`, and
`stringliteral.json`.

**ReadKey crash.** The same first run ended with an unhandled
`System.InvalidOperationException` from `Console.ReadKey`, because stdin
was redirected and `RequireAnyKey` was `true`. Fix: set `RequireAnyKey`
to `false`. First run exit code was 134; the clean rerun exited 0.

**"This file may be protected."** This warning printed on every run,
including the clean one. The tool still found `CodeRegistration`
(0x4098538) and `MetadataRegistration` (0x41f0538) and dumped normally.
On this APK it is a false alarm.

**Ghidra 1-byte function.** The first version of the resolve script
called `createFunction` without disassembling first. With `-noanalysis`
the listing holds no disassembly, and the result was a function with a
1-byte body and 0 instructions. Fix: call `disassemble(target)` before
`createFunction`. See section 6.

## 6. Ghidra resolution

Target method: `GameEntry.Start`, from `dump.cs` line 15089:

```text
// RVA: 0x2129B7C Offset: 0x2125B7C VA: 0x2129B7C
private void Start() { }
```

The same method in `script.json`:

```json
{
  "Address": 34773884,
  "Name": "GameCode.GameEntry$$Start",
  "Signature": "void GameCode_GameEntry__Start (GameCode_GameEntry_o* __this, const MethodInfo* method);",
  "TypeSignature": "vii"
}
```

Ghidra 12.2 (JDK Temurin 25.0.5.1+2) imported `libil2cpp.so` with
`-noanalysis` in about 40 seconds, language `AARCH64:LE:64:v8A`, image
base `0x00100000`. The resolve script disassembled at image base plus
RVA and created the function. Verified result:

- Function: `GameEntry_Start`
- Address: `0x02229b7c` (image base 0x00100000 + RVA 0x2129B7C)
- Body: `0x02229b7c` to `0x02229ba3`, 40 bytes, 10 instructions
- The 40-byte body matches the dump: the next method,
  `GameEntry.Update` at RVA 0x2129BA4, starts exactly 40 bytes
  later.

Disassembly:

```text
02229b7c  stp x30,x19,[sp, #-0x10]!
02229b80  ldr x8,[x0]
02229b84  mov x19,x0
02229b88  ldp x9,x1,[x8, #0x198]
02229b8c  blr x9
02229b90  ldr x8,[x19]
02229b94  mov x0,x19
02229b98  ldp x2,x1,[x8, #0x1a8]
02229b9c  ldp x30,x19,[sp], #0x10
02229ba0  br x2
```

A standard AArch64 prologue, two virtual calls, and a tail call. The
address resolves to a real function. The Ghidra project directory is
116 MB.

Related entry points from the same class, for further work:
`GameEntry.Awake` at RVA 0x21293B4, `GameEntry.Update` at
RVA 0x2129BA4.

## 7. What was not tested

- Full Ghidra auto-analysis of `libil2cpp.so` (73 MB, about 188,000
  methods). The targeted workflow in section 6 is what ran. A full pass
  needs a lot of RAM and a long run, and it was not attempted here.
- The shipped `ghidra.py` bulk-labeling script. It uses `askFile`, so
  it needs the Ghidra GUI. Only the single-method headless script ran.
- Dummy DLL generation. It crashes on this metadata (section 5), so no
  dummy DLLs exist for this APK.
- Encrypted metadata. This APK uses plain version 31 metadata. No
  decryption workflow was tested.
- Other metadata versions. Only version 31 was tested. The commonly
  supported set (24, 27, 29, 31, 39) comes from the native libraries
  guide, not from runs here.
- Runtime behavior. Nothing in this session ran the game. The dump
  shows what methods exist and where they sit, not which ones run.

