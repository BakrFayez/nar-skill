# Unity IL2CPP deep analysis

IL2CPP is Unity's ahead-of-time scripting backend. The game code, written
in C#, is compiled to native machine code in `libil2cpp.so`. The names of
every type and method, the field layouts, and the string literals are kept
separately in `global-metadata.dat`. Neither file alone tells the full
story. The metadata gives names and addresses. The library holds the code.

This guide covers the full static workflow: detect IL2CPP, extract the two
files, dump the metadata with Il2CppDumper, and resolve a dumped method
address to a real function in Ghidra. Every command here was run against
the test APK in `examples/unity-il2cpp-triage.md` (a test Unity
game, IL2CPP 64-bit, metadata version 31). Where a step was
not tested, the guide says so.

## 1. Detecting IL2CPP

Run triage first. IL2CPP shows up as two markers plus a large
`libil2cpp.so`:

```bash
python3 ~/workspace/nar-skill/scripts/nar-triage.py app.apk
```

On the test APK, triage reported:

```text
Native libs: 4 file(s)
  - [arm64-v8a] lib_burst_generated.so  (103,064 bytes)
  - [arm64-v8a] libil2cpp.so  (73,037,032 bytes)
  - [arm64-v8a] libmain.so  (6,728 bytes)
  - [arm64-v8a] libunity.so  (18,023,304 bytes)
Engine hints (path signatures; confirm with the native guide):
  - Unity (IL2CPP): 2 marker(s), e.g. assets/bin/Data/Managed/Metadata/global-metadata.dat
```

The two markers are `libil2cpp.so` and
`assets/bin/Data/Managed/Metadata/global-metadata.dat`. If the APK ships
`Assembly-CSharp.dll` and `libmono.so` instead, it is a Mono build, not
IL2CPP. Mono assemblies are managed code again, and this guide does not
apply. See `references/native-libs-and-jni.md` for the Mono path.

If the APK ships more than one ABI, pick one library and stay with it.
All addresses in this guide are relative to that one `libil2cpp.so`.

## 2. Extracting the metadata and the library

Extract the two files from the APK. Keep them in a work directory, not in
the repo:

```bash
mkdir -p work
unzip -o -q app.apk \
  "assets/bin/Data/Managed/Metadata/global-metadata.dat" \
  "lib/arm64-v8a/libil2cpp.so" \
  -d work/extract
file work/extract/lib/arm64-v8a/libil2cpp.so
```

On the test APK this gave a 12,840,952 byte metadata file and a
73,037,032 byte library:

```text
work/extract/lib/arm64-v8a/libil2cpp.so: ELF 64-bit LSB shared object,
ARM aarch64, version 1 (SYSV), dynamically linked,
BuildID[sha1]=<build-id>, stripped
```

The library is stripped. No symbol table survives, so the metadata dump
is the only source of method names.

## 3. Reading the metadata header

Before running any tool, read the first bytes of the metadata file. The
magic must be `0xFAB11BAF` and the second word is the format version:

```bash
od -A d -t x1 -N 32 work/extract/assets/bin/Data/Managed/Metadata/global-metadata.dat
```

```text
0000000 af 1b b1 fa 1f 00 00 00 00 01 00 00 40 b1 02 00
0000016 40 b2 02 00 f4 10 0a 00 34 c3 0c 00 3c 8f 1b 00
```

The same check in Python:

```bash
python3 -c "
import struct
d=open('work/extract/assets/bin/Data/Managed/Metadata/global-metadata.dat','rb').read(16)
magic,ver=struct.unpack('<II',d[:8])
print('magic: 0x%08x  version: %d' % (magic,ver))
print('magic OK (0xFAB11BAF):', magic==0xFAB11BAF)
"
```

On the test APK this printed magic `0xfab11baf` and version `31`. Version
31 is Unity 2022.3. The Unity version was confirmed from strings in the
library, which contain build paths such as
`C:/Program Files/Unity/Hub/Editor/2022.3.62f3/Editor/Data/il2cpp/...`.

If the magic is wrong, the metadata is encrypted or packed, and the dump
in section 5 will fail. See section 10.

## 4. Installing Il2CppDumper

Il2CppDumper (Perfare) is the dumper used here. Check whether it is
already installed:

```bash
which il2cppdumper
```

On the test machine it was missing. Il2CppDumper is a .NET app, so it
needs a .NET runtime first. The net6 build needs .NET 6. Install the
runtime with the official install script, into the workspace tools
directory:

```bash
curl -sSL -o /tmp/dotnet-install.sh https://dot.net/v1/dotnet-install.sh
chmod +x /tmp/dotnet-install.sh
/tmp/dotnet-install.sh --channel 6.0 --runtime dotnet --install-dir ~/workspace/tools/dotnet
~/workspace/tools/dotnet/dotnet --list-runtimes
```

This installed runtime `6.0.36`. Then download the Il2CppDumper release
and unpack it under `~/workspace/tools/il2cppdumper/`:

```bash
mkdir -p ~/workspace/tools/il2cppdumper
cd ~/workspace/tools/il2cppdumper
curl -sL -o Il2CppDumper-net6-v6.7.46.zip \
  "https://github.com/Perfare/Il2CppDumper/releases/download/v6.7.46/Il2CppDumper-net6-v6.7.46.zip"
unzip -o -q Il2CppDumper-net6-v6.7.46.zip
sha256sum Il2CppDumper-net6-v6.7.46.zip
```

Tool versions used for the test run:

- Il2CppDumper v6.7.46, net6 build, released 2024-07-06. Source:
  https://github.com/Perfare/Il2CppDumper/releases/tag/v6.7.46
- Zip SHA-256:
  `db9bbbc538e33abfb057c7757ae5d6c1f16a05fdc0d13af8a5a67ea31faaba0c`
- .NET runtime 6.0.36, from the install script above.

The release zip also ships `ghidra.py`, `ida.py`, and struct variants for
bulk labeling in those tools. They were not run here: `ghidra.py` uses
`askFile`, so it needs the Ghidra GUI. Section 8 uses a small headless
script instead.

### Config fix before the first run

The default `config.json` in the Il2CppDumper directory has two settings
that break a headless run on this metadata. Set both to `false`:

```json
{
  "GenerateDummyDll": false,
  "RequireAnyKey": false
}
```

`GenerateDummyDll` crashed on the test APK (see section 6). Dummy DLLs
are optional for this workflow, so turning them off loses nothing the
guide needs. `RequireAnyKey` makes the tool wait for a key press at the
end, which crashes when stdin is redirected. Everything else in the
default config stays as shipped: method, field, property, attribute,
field-offset, method-offset, and type-index dumping all on, struct
generation on.

## 5. Running the dump

Shortcut: `python3 scripts/nar-il2cpp.py game.apk` does the whole
locate-and-dump flow — it finds `global-metadata.dat` and the
matching `libil2cpp.so` inside the APK, reads the metadata format
version from the header, runs Il2CppDumper when the doctor finds it,
and summarizes the dump (type count, method count, top namespaces).
Run it first; do the manual steps below when you need control over
the pair or the dumper flags.

Run the dumper with the library, the metadata, and an output directory.
All three arguments are given, so the tool asks no questions:

```bash
~/workspace/tools/dotnet/dotnet ~/workspace/tools/il2cppdumper/Il2CppDumper.dll \
  work/extract/lib/arm64-v8a/libil2cpp.so \
  work/extract/assets/bin/Data/Managed/Metadata/global-metadata.dat \
  work/il2cpp-dump < /dev/null
```

The run took about 17 seconds on the test APK. The log:

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

Exit code was 0. The two `ERROR` lines look bad but the dump still
completed; section 6 explains both.

One practical quirk: Il2CppDumper may ignore the output-directory
argument and write `dump.cs`, `il2cpp.h`, `script.json`, and
`stringliteral.json` next to its own DLL instead. If the output
directory is empty after a successful run, look in the dumper's
install directory before re-running or blaming the metadata. The output directory held four
files:

```text
dump.cs            29,152,061 bytes   820,961 lines
il2cpp.h           73,001,461 bytes 2,593,219 lines
script.json        82,314,188 bytes 1,615,225 lines
stringliteral.json  1,883,592 bytes    88,197 lines
```

Counts from the dump:

```bash
grep -c "TypeDefIndex:" work/il2cpp-dump/dump.cs
grep -c "RVA: 0x" work/il2cpp-dump/dump.cs
grep -c "^// Image" work/il2cpp-dump/dump.cs
```

```text
12555
188699
60
```

That is 12,555 types, 188,699 methods with an RVA, and 60 assemblies
(images). `script.json` reports nearly the same numbers: 12,553
`ScriptMetadata` entries and 188,702 `ScriptMethod` entries. The small
difference is the visible trace of the "Some errors in dumping" line.
Treat the counts as accurate within a few entries, not exact to one.

## 6. Errors seen on the test APK, and the fixes

Three problems appeared. All three are recorded here so the next run does
not have to rediscover them.

**"ERROR: This file may be protected."** This printed on every run,
including the clean one. The tool still found `CodeRegistration` and
`MetadataRegistration` and dumped normally. On this APK the warning is a
false alarm. If the dump fails after this line, the file may really be
protected or the version unsupported. Here it was not.

**"ERROR: Some errors in dumping."** The tool prints this line but gives
no detail. The dump still completed, and the counts in section 5 show the
damage is small: `dump.cs` and `script.json` differ by 3 methods and 2
types out of about 188,000 and 12,500. A few entries failed to dump. Which
ones is not recorded anywhere. Do not claim the dump is complete to the
last method.

**Dummy DLL crash (first run only).** With the default config, the run
crashed while generating dummy DLLs:

```text
Generate dummy dll...
System.Exception: Invalid compressed integer format
   at Il2CppDumper.BinaryReaderExtensions.ReadCompressedUInt32(...)
   at Il2CppDumper.Il2CppExecutor.GetConstantValueFromBlob(...)
   at Il2CppDumper.DummyAssemblyGenerator..ctor(...)
```

This is a bug in Il2CppDumper's constant-blob reader on this metadata.
The fix is the config change in section 4: set `GenerateDummyDll` to
`false` and rerun. The second run exited 0 and produced byte-identical
`dump.cs`, `il2cpp.h`, `script.json`, and `stringliteral.json`.

The same first run also ended with an unhandled exception from
`Console.ReadKey`, because stdin was redirected and `RequireAnyKey` was
`true`. Setting `RequireAnyKey` to `false` fixed that too. The exit code
of the first run was 134; the clean rerun exited 0.

## 7. Reading the dump

### dump.cs

`dump.cs` is a C# skeleton of every type in the game. It starts with one
comment line per assembly image:

```text
// Image 0: Assembly-CSharp.dll - 0
// Image 1: mscorlib.dll - 2379
// Image 2: mcs.dll - 4103
```

Image 0, `Assembly-CSharp.dll`, is the game code. The rest are framework,
Unity engine modules, and third-party libraries. Each type carries its
index, and each method carries its address:

```text
public class GameEntry : MonoBehaviour // TypeDefIndex: 449
{
	// RVA: 0x2129B7C Offset: 0x2125B7C VA: 0x2129B7C
	private void Start() { }
```

The three numbers on the RVA line are different views of the same method:

- RVA: the address relative to the start of `libil2cpp.so` in memory.
  This is the number Ghidra needs, added to the image base.
- Offset: the byte offset inside the `libil2cpp.so` file. Use this to
  read raw bytes or check the file directly.
- VA: the virtual address, which here equals the RVA because the library
  loads at base 0 in its own address space.

Method bodies in `dump.cs` are always empty braces. The C# source is
gone. The real code is native AArch64 in `libil2cpp.so` at the RVA.

### script.json

`script.json` is the machine-readable form of the same dump. Its
top-level keys, with the test APK counts:

```bash
python3 -c "
import json
d=json.load(open('work/il2cpp-dump/script.json'))
print('top-level keys:', list(d.keys()))
for k,v in d.items():
    if isinstance(v,list): print(k, 'list len', len(v))
    elif isinstance(v,dict): print(k, 'dict len', len(v))
    else: print(k, type(v), v)
"
```

```text
top-level keys: ['ScriptMethod', 'ScriptString', 'ScriptMetadata', 'ScriptMetadataMethod', 'Addresses']
ScriptMethod list len 188702
ScriptString list len 22049
ScriptMetadata list len 12553
ScriptMetadataMethod list len 24381
Addresses list len 210136
```

A `ScriptMethod` entry holds the address as a decimal RVA, the name with
`$$` separating class and method, and a C signature for the native
function:

```json
{
  "Address": 34773884,
  "Name": "GameCode.GameEntry$$Start",
  "Signature": "void GameCode_GameEntry__Start (GameCode_GameEntry_o* __this, const MethodInfo* method);",
  "TypeSignature": "vii"
}
```

34773884 decimal is 0x2129B7C, the same RVA as in `dump.cs`.
`ScriptString` holds string literals with their addresses.
`ScriptMetadata` holds type metadata addresses. `Addresses` is the sorted
list of function start addresses, used by the bulk-labeling scripts to
create functions.

### stringliteral.json

A list of 22,049 entries, each a value and a hex address:

```json
{"value": "", "address": "0x4409378"}
```

Search it for the literal strings the game uses: UI text, file paths,
URLs, error messages. A string proves the bytes exist in the binary. It
does not prove the game shows or uses that string.

### il2cpp.h

A C header with a struct for every dumped type. It is 73 MB on the test
APK. Use it when you need field offsets for a type you are reading in
native code, or when feeding struct definitions to Ghidra. It is not
needed for the basic workflow in this guide.

## 8. Mapping a method address into Ghidra

The goal is to take one RVA from the dump and confirm it lands on a real
function in `libil2cpp.so`. The example here is
`GameEntry.Start`, RVA 0x2129B7C.

Import the library without auto-analysis. Full auto-analysis of a 73 MB
stripped library with about 188,000 methods needs a lot of RAM and a long
run. The targeted workflow below is the one this guide uses and tests.
Ghidra 12.2 is used, with JDK 25, from the REA engines directory:

```bash
source ~/workspace/tools/rea-engines/rea-env.sh
mkdir -p work/ghidra-proj
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" work/ghidra-proj NAR \
  -import work/extract/lib/arm64-v8a/libil2cpp.so -noanalysis
```

The import took about 40 seconds and reported language
`AARCH64:LE:64:v8A`. It also reported 293 unresolved external symbols
(`liblog.so`, `libm.so`, `libdl.so`, `libc.so` not in the project). That
is expected: the Android system libraries are not imported, and they are
not needed for this check.

Ghidra loads this shared object at image base `0x00100000`. The target
address is image base plus RVA: `0x00100000 + 0x2129B7C = 0x02229B7C`.

Run a GhidraScript that disassembles at the target and creates the
function. Save it as `NAR_ResolveIl2CppMethod.java` in a script
directory:

```java
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class NAR_ResolveIl2CppMethod extends GhidraScript {

	@Override
	public void run() throws Exception {
		Address imageBase = currentProgram.getImageBase();
		println("NAR image base: " + imageBase);

		long rva = 0x2129B7CL;
		String methodName = "GameEntry_Start";
		Address target = imageBase.add(rva);
		println("NAR target: " + target + " (image base + RVA 0x2129B7C)");

		FunctionManager fm = currentProgram.getFunctionManager();
		Function f = fm.getFunctionAt(target);
		if (f != null) {
			println("NAR function already present, body size: " +
				f.getBody().getNumAddresses() + " bytes");
		}
		else {
			// With -noanalysis nothing is disassembled yet, and
			// createFunction alone makes a 1-byte body. Disassemble
			// first so the function body covers the real code.
			println("NAR disassembling at target");
			disassemble(target);
			f = createFunction(target, methodName);
		}
		if (f == null) {
			println("NAR FAILED to create function at " + target);
			return;
		}
		println("NAR function: " + f.getName());
		println("NAR entry point: " + f.getEntryPoint());
		println("NAR body min: " + f.getBody().getMinAddress());
		println("NAR body max: " + f.getBody().getMaxAddress());
		println("NAR body size: " + f.getBody().getNumAddresses() + " bytes");
		println("NAR instruction count: " + countInstructions(f));

		println("NAR first instructions:");
		InstructionIterator it =
			currentProgram.getListing().getInstructions(f.getBody(), true);
		int n = 0;
		while (it.hasNext() && n < 10) {
			Instruction ins = it.next();
			println("NAR   " + ins.getAddress() + "  " + ins.toString());
			n++;
		}
	}

	private int countInstructions(Function f) {
		int n = 0;
		InstructionIterator it =
			currentProgram.getListing().getInstructions(f.getBody(), true);
		while (it.hasNext()) {
			it.next();
			n++;
		}
		return n;
	}
}
```

Run it headless against the imported program:

```bash
source ~/workspace/tools/rea-engines/rea-env.sh
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" work/ghidra-proj NAR \
  -process libil2cpp.so -noanalysis -scriptPath work/ghidra-scripts \
  -postScript NAR_ResolveIl2CppMethod
```

The disassemble-first step matters. The first version of this script
called `createFunction` without disassembling, and the result was a
function with a 1-byte body and 0 instructions. With `-noanalysis` the
listing holds no disassembly, and `createFunction` does not disassemble
on its own. Disassembling first fixed it.

The verified result on the test APK:

```text
NAR image base: 00100000
NAR target: 02229b7c (image base + RVA 0x2129B7C)
NAR function: GameEntry_Start
NAR entry point: 02229b7c
NAR body min: 02229b7c
NAR body max: 02229ba3
NAR body size: 40 bytes
NAR instruction count: 10
NAR   02229b7c  stp x30,x19,[sp, #-0x10]!
NAR   02229b80  ldr x8,[x0]
NAR   02229b84  mov x19,x0
NAR   02229b88  ldp x9,x1,[x8, #0x198]
NAR   02229b8c  blr x9
NAR   02229b90  ldr x8,[x19]
NAR   02229b94  mov x0,x19
NAR   02229b98  ldp x2,x1,[x8, #0x1a8]
NAR   02229b9c  ldp x30,x19,[sp], #0x10
NAR   02229ba0  br x2
```

The address resolves to a real function: a standard AArch64 prologue,
two virtual calls, and a tail call. The 40-byte body matches the dump
exactly, since the next method (`GameEntry.Update`, RVA
0x2129BA4) starts 40 bytes later. The Ghidra project directory for the
imported library is 116 MB.

To resolve more methods, change the `rva` and `methodName` values in the
script and rerun it. For bulk labeling of all 188,702 methods, the
shipped `ghidra.py` does that work in the GUI; it was not run headless
here.

## 9. Finding game logic functions

Game logic lives in the game's own namespaces, not in the engine or
framework assemblies. Start from the namespace list in `dump.cs`:

```bash
grep "^// Namespace: GameCode" work/il2cpp-dump/dump.cs | sort -u
```

On the test APK this lists the game's namespaces, including
`GameCode.Game`, `GameCode.Game.Entity`,
`GameCode.Game.Items`, `GameCode.Game.Questing`, and
`GameCode.Game.Formulas`. 1,084 types sit under
`GameCode` namespaces, and 15,415 of the 188,702
`ScriptMethod` entries belong to them. The rest are engine, framework,
and third-party code.

Useful starting points in any Unity game:

- `Awake`, `Start`, and `Update` on the main `MonoBehaviour` classes.
  They are the entry points the engine calls. On the test APK:
  `GameEntry.Awake` at RVA 0x21293B4, `GameEntry.Start`
  at RVA 0x2129B7C, `GameEntry.Update` at RVA 0x2129BA4.
  `Start` sits 1,992 bytes after `Awake` and 40 bytes before `Update`,
  which matches the 40-byte body Ghidra measured for `Start`.
- Save and load methods, usually named `Save`, `Load`, or
  `Serialize`. Search `dump.cs` for the name and read the RVA.
- Formula and rules code, often in a namespace like `Game.Formulas`.
  These are pure logic methods with no engine calls, so they decompile
  cleanly.
- Anything that reads a string literal from `stringliteral.json`. A
  distinctive literal, such as an error message, points at the method
  that uses it.

Work from the dump outward. Find the method by name, take its RVA,
resolve it in Ghidra as in section 8, and read the disassembly. Do not
start by browsing the native binary: with 188,000 methods and no
symbols, the binary alone gives no names.

## 10. Metadata versions and encrypted metadata

Il2CppDumper supports the common metadata format versions. The test APK
used version 31 (Unity 2022.3) and dumped cleanly. Versions 24, 27, 29,
31, and 39 are the commonly supported ones. Other versions may fail or
dump garbage. If the version is outside that set, check the Il2CppDumper
release notes for the version you have before trusting the output.

Encrypted metadata is a separate problem. Some games encrypt or pack
`global-metadata.dat`. The signs are: the magic bytes are not
`0xFAB11BAF` (section 3), or Il2CppDumper fails at "Initializing
metadata". No decryption workflow was tested for this guide. Do not
guess at a decryption key or a custom unpacker. Record the metadata as
encrypted and stop the IL2CPP path there.

A related case: Il2CppDumper finds `CodeRegistration` and
`MetadataRegistration` by scanning the library. If it cannot find them,
it prints the "may be protected" error from section 6 and the dump
fails. On the test APK that warning was a false alarm and the scan
succeeded, but a failed dump after that line is a real stop. Record it
and do not force the dump with `ForceDump` unless you can verify the
output another way.

## 11. What static IL2CPP analysis cannot prove

The dump gives names, addresses, and string literals. It does not give
behavior. Keep these limits in mind when writing a report:

- A dumped method may never run. Static analysis cannot show which
  methods the game actually calls, or in what order.
- The C# source is gone. `dump.cs` bodies are empty. Only the native
  disassembly shows what a method does, and decompilation is an
  approximation.
- String literals prove bytes exist, not that the game displays or uses
  them.
- Values computed at runtime, such as keys derived at startup or data
  fetched from a server, are not in the dump.
- Server-side logic is out of reach. If a game rule is enforced by a
  server, the client code only shows the request, not the decision.
- A few entries may be missing from the dump. The test run showed a
  small gap between `dump.cs` and `script.json` counts. Do not claim
  the dump is complete to the last method.
- Obfuscated builds rename methods and types. The dump still works, but
  the names no longer describe what the code does.

Research by Bakr Fayez.

## Addressables catalogs

When a build ships Addressables, `nar-unity` parses the
content catalog (`assets/aa/catalog.json`) into an
inventory (`addressables_catalog` in the JSON report):
locations (the catalog's internal ids), the provider
ids, the declared resource types, and the entry table.
The entry table is a base64 blob — an int32 count plus
28-byte entries — whose index fields are claimed only
where they validate against the catalog's own tables
(internal-id, provider, and resource-type indices), so
the per-type and per-provider entry counts are evidence,
not guesses. A catalog whose entry blob does not match
that validated layout is reported by size, undecoded.
