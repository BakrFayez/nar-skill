# Flutter and Dart analysis

A Flutter app does not keep its Dart code in DEX. The Dart code is
compiled ahead of time (AOT) into a native library, `libapp.so`, and
the Flutter engine ships as a second native library, `libflutter.so`.
The DEX files in a Flutter APK hold only the Android shell: the
Flutter activity, plugin glue, and the embedding code. If you decompile
the DEX expecting the app logic, you will not find it.

## Detecting Flutter

Triage reports Flutter markers when it finds them. For the worked
example below it reported 4 markers. Confirm by listing the APK:

```bash
unzip -l app.apk | grep -i -E "flutter|dart|snapshot|isolate"
```

A Flutter APK has all of these:

- `lib/<abi>/libapp.so`, the compiled Dart code.
- `lib/<abi>/libflutter.so`, the Flutter engine.
- `assets/flutter_assets/`, with `AssetManifest.bin`,
  `FontManifest.json`, and usually `NativeAssetsManifest.json`
  and `NOTICES.Z`.
- `lib/<abi>/libdartjni.so` when the app uses Dart FFI or JNI bindings.

The absence of `libapp.so` for one ABI does not mean the app is not
Flutter. The worked example ships `libapp.so` and `libflutter.so`
for `arm64-v8a` and `armeabi-v7a` only; its `x86_64` folder holds
plugin libraries but no Flutter engine.

## libapp.so vs libflutter.so

`libapp.so` is the app. It contains the AOT-compiled Dart code for
the app and its Dart packages, plus the Dart VM snapshot data the
code runs against. Its size tracks the size of the Dart codebase.

`libflutter.so` is the engine. It contains the Dart VM, the Skia
and Impeller rendering code, the platform channel plumbing, and the
embedder that talks to Android. It is roughly the same for every app
built with the same Flutter version. Do not waste time searching it
for app logic; search it for engine and Dart version strings instead.

Extract the arm64 copies for inspection:

```bash
unzip -o -q app.apk "lib/arm64-v8a/libapp.so" "lib/arm64-v8a/libflutter.so" -d extracted
file extracted/lib/arm64-v8a/libapp.so
file extracted/lib/arm64-v8a/libflutter.so
```

Both are stripped ELF shared objects in a release build. `file`
reports `stripped` for each, and `nm` reports `no symbols` for both.
What remains is the dynamic symbol table, which is small for
`libapp.so` and larger for `libflutter.so`.

## Dart AOT snapshot layout

A release `libapp.so` is not ordinary compiled code with functions
and symbols. It is a Dart AOT snapshot: two data blobs and two
instruction blobs, exposed through exactly five dynamic symbols.

```bash
nm -D extracted/lib/arm64-v8a/libapp.so
```

On the worked example this returns:

```
00000000000045c0 R _kDartIsolateSnapshotData
0000000000ff6a80 T _kDartIsolateSnapshotInstructions
00000000000001c8 R _kDartSnapshotBuildId
0000000000000340 R _kDartVmSnapshotData
0000000000fe0000 T _kDartVmSnapshotInstructions
```

The roles:

- `_kDartVmSnapshotData` and `_kDartVmSnapshotInstructions`: the VM
  snapshot, holding core Dart library code shared by every isolate.
- `_kDartIsolateSnapshotData` and
  `_kDartIsolateSnapshotInstructions`: the isolate snapshot, holding
  the app code and its data.
- `_kDartSnapshotBuildId`: a build identifier string.

The section table shows where these live:

```bash
readelf -S extracted/lib/arm64-v8a/libapp.so
```

On the worked example, `.rodata` starts at file offset `0x340`
and holds the snapshot data (about 16 MB), and `.text` starts at
`0xfe0000` and holds the snapshot instructions (about 12 MB). The
file has 11 section headers. There is no per-function symbol table
to read; the snapshot is a flat blob of Dart objects and machine
code, and the VM finds things by offsets recorded inside the blob.

## What strings and symbols survive in a release AOT build

More survives than in a stripped C library, because the snapshot
embeds Dart metadata. Run the counts first:

```bash
strings extracted/lib/arm64-v8a/libapp.so | wc -l
strings extracted/lib/arm64-v8a/libapp.so | grep -c "\.dart"
strings extracted/lib/arm64-v8a/libapp.so | grep -c "package:"
strings extracted/lib/arm64-v8a/libapp.so | grep -c "^dart:"
strings extracted/lib/arm64-v8a/libapp.so | grep -c "https://"
```

On the worked example, `libapp.so` (29,295,504 bytes) yields
177,475 strings, including 3,030 strings ending in `.dart`,
2,819 `package:` URIs, 236 `dart:` URIs, and 605 strings containing
`https://`. Readable Dart identifiers survive: class names such as
`HomeScreenWidget` and `SettingsWidget`, and method names
such as `initState` and `didChangeDependencies`. Source paths
survive too:

```bash
strings extracted/lib/arm64-v8a/libapp.so | grep "package:" | head -8
```

```
package:flutter_widget_from_html_core/src/data/image.dart
package:example_app/pages/home/home_page.dart
package:example_app/widgets/app_button.dart
```

That tells you which Dart packages the app uses and how its own
source tree is laid out. It does not give you the source code.

This worked example was built without obfuscation: no single-letter
class names appear, and the identifiers above are intact. An
obfuscated build (`--obfuscate`) renames classes, methods, and
fields to short meaningless names, and the readable identifiers in
this section mostly disappear. The `package:` URIs and string
literals still survive obfuscation, because the VM needs the URIs
and the literals are data, not names.

What survives in `libflutter.so` is different. Its 531 dynamic
symbols are mostly imports from Android system libraries. It exports
`JNI_OnLoad` and no `Java_*` methods, which means its JNI bindings
are registered dynamically. Its 64,009 strings hold engine messages,
error text, and the Dart version string (see below).

## Symbol recovery options and their limits

No tool recovers Dart source from a release AOT snapshot. The
available tools recover structure: function boundaries, names when
they survive, and disassembly. All of the following are untested in
this environment; they are documented here so you know what exists,
not as verified procedure.

- Blutter parses `libapp.so` and dumps the snapshot's function
  table with names and offsets. It needs a Dart SDK matching the
  snapshot's Dart version for disassembly, and it recovers nothing
  useful from an obfuscated build beyond offsets.
- ReFlutter patches `libflutter.so` so the engine dumps the Dart
  objects at runtime. It needs a device or emulator, and it modifies
  the engine library, so the result is no longer the original binary.
- Darter disassembles the AOT snapshot into Dart-like output. It is
  a research tool with narrow version support.

Limits that apply to all of them: obfuscation removes the names
they rely on, version mismatches break parsing, and the output is
disassembly or recovered structure, never the original source.
Record which tool and version you used, and treat recovered names
as leads to verify, not as proven behavior.

## Dart and Flutter version detection

The Dart version string lives in `libflutter.so`:

```bash
strings extracted/lib/arm64-v8a/libflutter.so | grep -E "^3\.[0-9]+\.[0-9]+ \(stable\)"
```

On the worked example this returns:

```
3.12.2 (stable) (Tue Jun 9 01:11:39 2026 -0700) on "android_arm64"
```

The Flutter version string lives in `libapp.so`:

```bash
strings extracted/lib/arm64-v8a/libapp.so | grep -E "^3\.[0-9]+\.[0-9]+"
```

On the worked example this returns:

```
3.44.8 (stable) - Git hash 058e0af2c2 - Git URL https://github.com/flutter/flutter.git
```

Both version strings are needed. Snapshot parsers and disassemblers
are version-sensitive, so record both before reaching for one.
If the version strings are absent, the build was stripped harder
than usual; fall back to matching `libflutter.so` size and behavior
against known releases, and say so in your notes.

## What static Flutter analysis cannot prove

Strings prove bytes exist. A URL string in `libapp.so` proves the
literal is in the binary; it does not prove the app contacts that
host, and it does not prove when or why. A package URI proves a
package was linked; it does not prove its code runs. A readable
class name proves the identifier survived; it does not prove what
the class does.

Static analysis of a Flutter app cannot prove runtime behavior:
network calls, permission use at runtime, or what the app shows on
screen. For network behavior, capture traffic from a running app
(see the network traffic guide). For UI behavior, run the app on a
device or emulator. Keep every static claim at the level of
"present in the binary" unless a runtime check backs it.

## Worked example

App: a test Flutter app (open source, Apache License 2.0), F-Droid
flavor APK. Size: 130,304,708 bytes. Min SDK 24, target SDK 36.
Triage: 2 DEX files (5,617,324 bytes total), 30 native libraries,
Flutter: 4 markers. All values below were measured on that test app.

Measured values (arm64-v8a):

| Item | Value |
| --- | --- |
| `libapp.so` size | 29,295,504 bytes |
| `libapp.so` dynamic symbols | 5 (the `_kDart*` snapshot symbols) |
| `libapp.so` strings | 177,475 |
| `libflutter.so` size | 11,581,856 bytes |
| `libflutter.so` dynamic symbols | 531 (mostly imports) |
| `libflutter.so` strings | 64,009 |
| `libapp.so` (armeabi-v7a) | 33,014,348 bytes |
| `libflutter.so` (armeabi-v7a) | 8,453,804 bytes |
| Dart version | 3.12.2 (stable) |
| Flutter version | 3.44.8 (stable), git hash 058e0af2c2 |
| Obfuscation | None detected |
