# React Native analysis

A React Native app keeps its JavaScript in a single bundle file,
`assets/index.android.bundle`, and the JavaScript engine in native
libraries. The DEX files hold only the Android shell: the React
activity, the bridge or JSI glue, and native module wrappers. If
you decompile the DEX expecting the app logic, you will not find
it. All values marked "observed on a test sample" below were
recorded from a real open-source React Native app on 2026-11-23.

## Detecting React Native

Triage reports React Native markers when it finds them. Confirm
by listing the APK:

```bash
unzip -l app.apk | grep -E "index.android.bundle|libhermes|libreactnative|libjsi|libfbjni"
```

A Hermes-based React Native APK has all of these:

- `assets/index.android.bundle`, the compiled JavaScript.
- `lib/<abi>/libhermesvm.so`, the Hermes JavaScript engine.
- `lib/<abi>/libreactnative.so`, the React Native core.
- `lib/<abi>/libfbjni.so`, the Java-to-native bridge.
- `lib/<abi>/libjsi.so` and `libreact_codegen_<module>.so`
  files on a new-architecture app (Fabric and TurboModules):
  `libjsi.so` is the JavaScript interface, and the codegen
  libraries are the generated TurboModule specs. On the test
  sample, triage also reported a `React Native new-arch flag`
  DEX marker.

An older JavaScriptCore app ships `libjsc.so` instead of
`libhermesvm.so`, and its bundle is minified JavaScript rather
than Hermes bytecode. The JSC path was not exercised on a sample
here; the rest of this guide covers Hermes.

## Extracting the bundle

```bash
unzip -p app.apk assets/index.android.bundle > index.android.bundle
file index.android.bundle
ls -l index.android.bundle
```

On the test sample the bundle is 9,006,680 bytes and `file`
reports it directly:

```text
index.android.bundle: Hermes JavaScript bytecode, version 98
```

The Hermes bytecode version is the number to record. It tracks
the React Native release, and decompiler support depends on it.
The React Native version itself is not reliably readable from
the native libraries: on the test sample, `strings` on
`libreactnative.so` shows only the symbol name
`reactNativeVersion`, not a version number. Record the Hermes
bytecode version instead.

## Reading the header

Shortcut: `python3 scripts/nar-rn.py app.apk` extracts the bundle,
decides Hermes vs JSC from the magic, reports the Hermes bytecode
version with function / string / identifier counts, and cross-checks
against hermes-dec when it is installed. A clean "not React Native"
verdict comes back when the APK ships no JS bundle asset.

The first bytes are an 8-byte magic, a uint32 bytecode version,
and a 20-byte source hash:

```bash
od -A d -t x1 -N 32 index.android.bundle
python3 -c "
import struct
d = open('index.android.bundle', 'rb').read(64)
print('magic:', d[:8].hex(), '| version:', struct.unpack('<I', d[8:12])[0])
"
```

On the test sample:

```text
magic: c61fbc03c103191f | version: 98
```

## Strings: what is recoverable

`strings` on the bundle recovers identifiers, module names,
URLs, and API hosts, but the string table is stored packed, so
results run together into long lines with no separators. Count
first, then search with `grep -o` for the needle you want
instead of reading the raw output:

```bash
strings -n 6 index.android.bundle | wc -l
strings -n 6 index.android.bundle | grep -c -m 1 "AppRegistry"
strings -n 6 index.android.bundle | grep -m 2 -o -E "[A-Za-z0-9_.-]*example[A-Za-z0-9_./-]*"
```

On the test sample, `strings -n 6` produced 3,712 lines, and
needles such as `AppRegistry`, `TurboModule`, `NativeModules`,
and app domains were all present. Strings prove that a name or
host exists in the bundle; they do not prove it is used, and
they say nothing about the logic around it.

## Parsing the bundle with hermes-dec

hermes-dec (0.1.8 verified here) parses, disassembles, and
decompiles Hermes bytecode. It needs only the Python standard
library. Install it into a local directory and run its tools
with that directory on `PYTHONPATH`; without it, the tools
fail with `ModuleNotFoundError: No module named 'hermes_dec'`.

```bash
pip install --target hermes-dec-pkg hermes-dec
PYTHONPATH=$PWD/hermes-dec-pkg ./hermes-dec-pkg/bin/hbc-file-parser index.android.bundle
```

Header fields on the test sample (bytecode version 98):

| Field | Value |
| --- | --- |
| Version | 98 |
| FileLength | 0x896e58 (9,006,680 bytes) |
| FunctionCount | 20,566 |
| IdentifierCount | 25,401 |
| StringCount | 0x28214 (164,884) |
| OverflowStringCount | 441 |
| StringStorageSize | 0x33dd30 |
| RegExpCount | 352 |
| FunctionSourceCount | 326 |

hermes-dec 0.1.8 warns that bytecode version 98 "is not
formally supported by the current tool". On the test sample the
parser, disassembler, and decompiler all still ran and produced
sane output. Treat the warning as a reason to spot-check
results, not as a hard stop, and re-check support when the
bytecode version moves again.

## Disassembly

```bash
PYTHONPATH=$PWD/hermes-dec-pkg ./hermes-dec-pkg/bin/hbc-disassembler index.android.bundle disasm.hasm
```

On the test sample this produced a 62,687,217-byte `.hasm` file
with all 20,566 functions. Each function header gives its name
(when present), byte size, parameter count, frame size, and
offset; each instruction line carries the resolved string for
its string operand:

```text
=> [Function #0 "global" of 62607 bytes]: 1 params, frame size=29, strict=0, exc handler=0, debug info=0  @ offset 0x004e66f8

==> 00000000: <DeclareGlobalVar>: <string_id: 52864>  # String: '__BUNDLE_START_TIME__' (Identifier)
==> 00000005: <DeclareGlobalVar>: <string_id: 62324>  # String: '__DEV__' (Identifier)
```

Use the disassembly to find a function by name or by the
strings it references, then read that function in isolation.
Do not read the whole file top to bottom; at tens of megabytes
it is a search target, not a document.

## Decompilation

```bash
PYTHONPATH=$PWD/hermes-dec-pkg ./hermes-dec-pkg/bin/hbc-decompiler index.android.bundle decompiled.js
```

On the test sample this produced a 35,781,193-byte
`decompiled.js` in about 34 seconds, with one warning
(`pass4: LoadFromEnvironment references unknown register 13`).
The output is readable pseudo-JavaScript with register names
(`r5`, `r6`) and a switch-based control-flow reconstruction:

```js
_fun0: for(var _fun0_ip = 0; ; ) switch(_fun0_ip) {
case 0:
    __BUNDLE_START_TIME__ = undefined;
    __DEV__ = undefined;
    process = undefined;
```

The decompiler recovers structure and string constants, not
the original source: comments and original formatting are gone,
and minified identifiers stay minified. Verify any claim that
matters against the disassembly, especially where the
decompiler printed a warning.

## The native side

The bundle is only half the app. Native modules (camera,
storage, sensors, push) live in `.so` files and in the DEX
wrappers that call them. After the bundle work:

- List the native libraries from triage and note which are
  React Native framework (`libreactnative.so`,
  `libhermesvm.so`, `libjsi.so`, `libfbjni.so`,
  `libreact_codegen_*.so`) and which belong to third-party
  modules.
- Match TurboModule codegen libraries to the modules the
  bundle references.
- Analyze a module's `.so` with the native guide
  (`references/native-libs-and-jni.md`) when the question is
  about what that module does at the OS level.

## Limits

- No public tool returns the original JavaScript source.
  Disassembly and decompilation are approximations; the
  disassembly is the closer record.
- Hermes bytecode versions move with React Native releases.
  A newer version than the one verified here (98) may need a
  newer hermes-dec, and the tools may warn or fail. Record
  the version first, then pick the tool.
- Dynamic behavior (network calls, storage writes, native
  module calls at runtime) is not visible from the bundle
  alone. Pair static bundle work with the dynamic guide
  (`references/dynamic-analysis.md`) when the question is
  about what the app does when it runs.

## Source maps and the native-module inventory

`nar-rn` reports any `*.map` entries shipped in the APK
(`source_maps`) and the bundle's own
`//# sourceMappingURL=` reference. Its `native_modules`
block inventories the new-architecture surface: for text
bundles, module names are extracted from the call sites
themselves (TurboModuleRegistry.get/.getEnforcing,
codegenNativeComponent, NativeModules.<name>). For
Hermes bytecode the same names sit in the string table
as standalone entries and cannot be attributed to call
sites without bytecode reference analysis, so the report
gives architecture-marker counts (TurboModuleRegistry,
codegenNativeComponent, NativeModules,
__turboModuleProxy) and states that names were not
extracted — marker presence proves the architecture is
used, not which modules exist.
