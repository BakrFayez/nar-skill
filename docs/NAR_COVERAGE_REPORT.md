# NAR Coverage Report

Generated from `scripts/coverage.json` (itself generated from
`scripts/formats.json`, the single source of truth) by running
`nar coverage` and `nar coverage --gap` on the 3.0.0 tree.
Regenerate with: `python3 scripts/nar-coverage.py --write` for the
JSON, and re-capture the two commands below for this document.
Every non-`supported` entry carries a reason and the cheapest
probe that would close it; statuses are never inflated — an entry
is `supported` only when a test reference pins it.

## Coverage matrix

## Input types (partial: 6, supported: 13, unsupported: 1)
- apk: supported (fidelity structural-summary)
- apks: supported (fidelity structural-summary)
- xapk: supported (fidelity structural-summary)
- aab: supported (fidelity structural-summary)
- aar: supported (fidelity structural-summary)
- jar: supported (fidelity structural-summary)
- dex: supported (fidelity structural-summary)
- elf: supported (fidelity structural-summary)
- obb: supported (fidelity structural-summary)
- zip: supported (fidelity structural-summary)
- odex: partial (fidelity structural-summary)
    reason: Dalvik-era ODEX payload is identified and its embedded DEX located; deep parse rides the DEX path only.
    probe: Add a real Dalvik ODEX corpus file and pin field-level parsing.
- vdex: partial (fidelity structural-summary)
    reason: Header fields parsed for version 006; later versions are identified with limited field parsing.
    probe: Add VDEX samples beyond 006 and extend field parsing.
- oat: partial (fidelity structural-summary)
    reason: Verified on API 26 files; OAT beyond API 26 is synthetic-only (capability matrix).
    probe: Add real OAT files from newer API levels and pin parsing.
- cdex: partial (fidelity structural-summary)
    reason: Header + section table parsed; payload is NOT decoded (payload_decoded stays false).
    probe: Add a real CDEX corpus and a payload decoder.
- art: partial (fidelity structural-summary)
    reason: Header parsed on a real API 26 boot image; other versions are untested.
    probe: Add ART images from other API levels and pin parsing.
- unity-assetbundle: partial (fidelity structural-summary)
    reason: Bundle header + blocks-info parsed; LZ4/LZHAM blocks are inventoried, never decoded (no stdlib decoder).
    probe: Add an LZ4 block decoder path with a fixture.
- unreal-pak: supported (fidelity structural-summary)
- unreal-iostore: supported (fidelity structural-summary)
- godot-pck: supported (fidelity structural-summary)
- unknown: unsupported (fidelity identified-only)
    reason: No known signature matched; reported as unknown, never guessed.
    probe: Add a signature + structural verdict for the new format with a fixture.

## Engines (partial: 14, supported: 12)
- Unity (IL2CPP): partial (fidelity structural-summary)
    reason: Deep dive locates the IL2CPP pair and summarizes metadata; Mono-side inventory and scene/prefab semantics are not reconstructed (capability matrix: Unity analysis is partially supported).
    probe: Extend nar-il2cpp/nar-unity object-level parsing and pin it with a labeled fixture.
- Unity (Mono): supported (fidelity structural-summary)
- Unreal Engine: partial (fidelity structural-summary)
    reason: Deep dive parses pak/IoStore/Zen/classic packages at structural level, decodes .locres string tables (v1 EntryMetaData layout verified end-to-end on real samples; v0 Initial layout implemented from the public format, synthetic-verified only) and attaches Wwise bank header facts for readable .bnk/.wem members (Oodle/encrypted members are named, never decoded). Kismet/Blueprint decoding, Oodle and AES decryption are unsupported by design (capability matrix).
    probe: Add Kismet bytecode decoding to narlib/uasset.py with synthetic packages pinning it.
- Godot: supported (fidelity structural-summary)
- Flutter: partial (fidelity structural-summary)
    reason: Fingerprint + flutter_assets inventory only; Dart snapshot/VM structure parsing and symbol recovery are not implemented (capability matrix).
    probe: Add a Dart snapshot structure parser to nar-flutter with a labeled fixture.
- React Native: partial (fidelity structural-summary)
    reason: Hermes header parse and bundle inventory exist; Hermes module-name attribution and bytecode decompilation are not built in (capability matrix).
    probe: Wire a Hermes bytecode rung (hermes-dec) into nar-rn and pin module attribution on a fixture.
- Cocos2d-x: supported (fidelity structural-summary)
- libGDX: supported (fidelity structural-summary)
- Adobe AIR: partial (fidelity structural-summary)
    reason: Descriptor and SWF structure are parsed (header, tag census, ExportAssets/SymbolClass symbol names), but DoABC tags are counted and sized only: ABC bytecode is not decoded, so ActionScript semantics are not reconstructed.
    probe: Add an ABC (ActionScript bytecode) parser to nar-air.py to lift symbol-level facts (classes, methods) from DoABC bodies, pinned with a synthetic SWF fixture.
- Xamarin / .NET: partial (fidelity structural-summary)
    reason: Deep dive parses loose *.dll members and assemblies carved from uncompressed assemblies.blob spans through narlib.dotnetmeta (typedef/methoddef counts, Module-table names) and censuses the native runtime libraries and AssemblyStore markers. XALZ blocks — the default AssemblyStore compression in current Xamarin/MAUI builds — are counted by magic only: they are LZ4-compressed payloads and the stdlib has no LZ4 decoder, so assemblies inside XALZ stores are identified, not parsed.
    probe: XALZ blocks are counted by magic only: they are LZ4-compressed assembly payloads and the stdlib has no LZ4 decoder, so compressed assemblies are identified, not decoded. A blob over the 32 MiB member-read cap is skipped whole.
- Cordova (hybrid): supported (fidelity structural-summary)
- Capacitor (hybrid): supported (fidelity structural-summary)
- Qt for Android: partial (fidelity structural-summary)
    reason: Deep dive parses Qt RCC v1/v2 headers and walks the 22-byte tree-node records recursively (bounded nodes/depth, every offset validated) reconstructing resource paths with sizes and compression flags (zlib payloads), plus .qmlc/.jsc identification. No real Qt corpus locally; layout from public format documentation, synthetic-fixture verified.
    probe: Validate the tree walk against a real .rcc (including v2 and locale/country node variants) when a labeled corpus target is available.
- Defold: partial (fidelity structural-summary)
    reason: Deep dive parses the .arci index (public Defold engine source layout) with a fully validated entry walk (count/offset/size/hash checks) and reports entry counts, payload totals, compressed/encrypted flag counts and largest entries by hash; entry paths are NOT recoverable from the index (MurmurHash64 hashes only) — that is the family's structural boundary, stated in the report. No real Defold corpus locally; layout from public format documentation, synthetic-fixture verified.
    probe: Validate the .arci entry walk and flag-bit meanings (compressed=0x1, encrypted=0x2 assumed from public source) against a real Defold archive when a labeled corpus target is available.
- Ren'Py: partial (fidelity structural-summary)
    reason: Deep dive parses RPA-1.0/2.0/3.0 headers and index listings (file count, total bytes, by-extension census, sample names) with RPA-3.0 key XOR deobfuscation. SECURITY: the index pickle is never loaded with plain pickle.loads — a pickletools pre-scan refuses GLOBAL/STACK_GLOBAL/REDUCE/OBJ/INST/NEWOBJ (and NEWOBJ_EX/EXT) opcodes and the load uses a RestrictedUnpickler whose find_class always raises; a hostile reduce-based fixture is refused and never executes (test-pinned). Consequence: indexes whose bytes objects are encoded via a reduce (protocol < 3 style) are refused by design rather than executed. .rpyc is identification + length-prefixed zlib slot census only, no decompilation. No real Ren'Py corpus locally; layout from public format documentation, synthetic-fixture verified.
    probe: Validate the RPA-2.0/1.0 header shapes and the RPC2 slot walk against a real Ren'Py build when a labeled corpus target is available.
- RPG Maker (web export): supported (fidelity structural-summary)
- Embedded Python: supported (fidelity structural-summary)
- Web assets (assets/www): supported (fidelity structural-summary)
- SDL: supported (fidelity structural-summary)
- GameMaker: partial (fidelity structural-summary)
    reason: Deep dive walks the data.win FORM chunk table with validated sizes, resolves the GEN8 game name via candidate string-offset fields (+4/+8/+12, basis reported), censuses the STRG string table (count, sample, total chars) and reads TXTR/AUDO/SPRT count fields. No real GameMaker corpus locally; layout from public format documentation, synthetic-fixture verified.
    probe: Confirm the GEN8 name-field position and chunk count-field semantics against a real data.win when a labeled corpus target is available; extend to room/object chunk censuses only after that validation.
- Solar2D: partial (fidelity structural-summary)
    reason: Deep dive lists resource.car when it is a plain ZIP (count, by-extension census, total bytes), extracts labelled textual facts from config.lua/build.settings (orientation.default, content scale/fps via bounded regex) and censuses compiled Lua (.luac + extensionless Lua-magic members); non-ZIP car variants degrade to identification + header facts. Corona markers (assets/*.luac, libcorona.so paths) are censused in the surrounding APK. No real Solar2D corpus locally; behaviour from public format documentation, synthetic-fixture verified.
    probe: Identify the non-ZIP resource.car variant layout from a real Solar2D build when a labeled corpus target is available.
- Heaps / Haxe: partial (fidelity identified-only)
    reason: Deep dive verifies the HLB magic and decodes the version and flags uindex values (documented HashLink uindex encoding, including multi-byte values) plus a sibling .hl/.dat census. Section counts after version/flags are deliberately NOT named: the deeper header walk could not be validated, so section_counts is null with the reason recorded — no counts are invented. No real HashLink corpus locally; layout from public format documentation, synthetic-fixture verified.
    probe: Validate the full header count sequence (types/functions/globals/constants order) against a real hlboot.dat and only then name section counts.
- LÖVE: supported (fidelity structural-summary)
- Ebitengine: supported (fidelity structural-summary)
- Bevy / Rust: partial (fidelity structural-summary)
    reason: The assets census is structural (member count, by-extension census, .ron and .scn.ron counts) and the rustc version is extracted from the 'rustc version ' string in the largest native library when present; Bevy crate presence is occurrence counts of the bevy_ecs / bevy_render / bevy_asset / bevy_winit / winit name strings, labelled string evidence, with the verdict requiring RON assets or at least two distinct crate strings.
    probe: RON facts are a labelled textual approximation (identifiers at bracket depth 1 followed by ':'), not a RON parse — a real RON parser would be needed for typed scene data; crate string counts cannot distinguish linked Bevy crates from coincidental string content, which is why the status is partial.
- MonoGame / FNA: partial (fidelity structural-summary)
    reason: MonoGame.Framework.dll is found loose or carved from assemblies.blob (identified by its Module-table name) and summarized via narlib.dotnetmeta; FNA markers (FNA.dll, FAudio, libtheorafile) are a presence list. XNB headers parse fully (platform byte, version, HiDef/compressed flags, declared size validated against the member size) and uncompressed XNBs get their whole type-reader table parsed, with the census grouped by primary reader short name.
    probe: Compressed XNBs (flag 0x80) are LZX-compressed: counted, never decoded — no stdlib LZX decoder exists; that is why the status is partial rather than supported.

## Asset formats (partial: 1, supported: 87)
- binary: supported (fidelity structural-summary)
- bmp-image: supported (fidelity structural-summary)
- bundle: supported (fidelity structural-summary)
- css: supported (fidelity structural-summary)
- csv: supported (fidelity structural-summary)
- dex: supported (fidelity structural-summary)
- elf: supported (fidelity structural-summary)
- fbx-model: supported (fidelity structural-summary)
- flac-audio: supported (fidelity structural-summary)
- gif-image: supported (fidelity structural-summary)
- glb-model: supported (fidelity structural-summary)
- gltf-model: supported (fidelity structural-summary)
- godot-pck: supported (fidelity structural-summary)
- hermes-bytecode: supported (fidelity structural-summary)
- html: supported (fidelity structural-summary)
- ini-config: supported (fidelity structural-summary)
- javascript: supported (fidelity structural-summary)
- jpeg-image: supported (fidelity structural-summary)
- json: supported (fidelity structural-summary)
- m4a-audio: supported (fidelity structural-summary)
- mkv-video: supported (fidelity structural-summary)
- mp3-audio: supported (fidelity structural-summary)
- mp4-video: supported (fidelity structural-summary)
- obj-model: supported (fidelity structural-summary)
- ogg-audio: supported (fidelity structural-summary)
- otf-font: supported (fidelity structural-summary)
- png-image: supported (fidelity structural-summary)
- properties: supported (fidelity structural-summary)
- protobuf-schema: supported (fidelity structural-summary)
- text: supported (fidelity structural-summary)
- ttf-font: supported (fidelity structural-summary)
- unityfs: supported (fidelity structural-summary)
- unreal-iostore: supported (fidelity structural-summary)
- unreal-pak: supported (fidelity structural-summary)
- wav-audio: supported (fidelity structural-summary)
- webm-video: supported (fidelity structural-summary)
- webp-image: supported (fidelity structural-summary)
- xml: supported (fidelity structural-summary)
- yaml: supported (fidelity structural-summary)
- plist: supported (fidelity structural-summary)
- spine-skeleton: supported (fidelity structural-summary)
- godot-resource: supported (fidelity structural-summary)
- godot-scene: supported (fidelity structural-summary)
- godot-project: supported (fidelity structural-summary)
- godot-import: supported (fidelity structural-summary)
- unreal-asset: supported (fidelity structural-summary)
- unreal-map: supported (fidelity structural-summary)
- wwise-audio: supported (fidelity structural-summary)
- wwise-bank: supported (fidelity structural-summary)
- fmod-bank: supported (fidelity structural-summary)
- astc-texture: supported (fidelity structural-summary)
- ktx-texture: supported (fidelity structural-summary)
- ktx2-texture: supported (fidelity structural-summary)
- pvr-texture: supported (fidelity structural-summary)
- dds-texture: supported (fidelity structural-summary)
- pkm-texture: supported (fidelity structural-summary)
- tga-image: supported (fidelity structural-summary)
- psd-image: supported (fidelity structural-summary)
- lua-script: supported (fidelity structural-summary)
- gdscript: supported (fidelity structural-summary)
- dart-source: supported (fidelity structural-summary)
- wasm: supported (fidelity structural-summary)
- obb: supported (fidelity structural-summary)
- zip: supported (fidelity structural-summary)
- 7z-archive: supported (fidelity structural-summary)
- aseprite: supported (fidelity structural-summary)
- rive-animation: supported (fidelity structural-summary)
- spriter: supported (fidelity structural-summary)
- javascript-compiled: supported (fidelity structural-summary)
- python-bytecode: supported (fidelity structural-summary)
- cocos-ccb: supported (fidelity structural-summary)
- cocos-csb: supported (fidelity structural-summary)
- unreal-locres: supported (fidelity structural-summary)
- ron-data: supported (fidelity structural-summary)
- kivy-layout: supported (fidelity structural-summary)
- renpy-archive: supported (fidelity structural-summary)
- love-package: supported (fidelity structural-summary)
- qt-resource: supported (fidelity structural-summary)
- solar2d-car: supported (fidelity structural-summary)
- cocos-particle-plist: supported (fidelity structural-summary)
- cocos-plist-atlas: supported (fidelity structural-summary)
- godot-atlas-texture: supported (fidelity structural-summary)
- libgdx-atlas: supported (fidelity structural-summary)
- phaser-json: supported (fidelity structural-summary)
- starling-xml: supported (fidelity structural-summary)
- texturepacker-json: supported (fidelity structural-summary)
- texturepacker-xml: supported (fidelity structural-summary)
- unity-spriteatlas: partial (fidelity identified-only)
    reason: Text YAML references packed sprites by GUID only: nar-atlas recovers the atlas name and packed-sprite count; frame names and rects are not recoverable from the .spriteatlas file alone.
    probe: Add a UnityPy rung to resolve the packed sprites inside the project's serialized data.

## Script formats (identified_only: 4, partial: 7, supported: 2)
- dex: supported (fidelity bytecode-listing)
- hermes: partial (fidelity structural-summary)
    reason: Header parse (bytecode version, function/string/identifier counts) lives in nar-rn.parse_hermes_header and is wired per-file by nar-script; no bytecode disassembly or module attribution.
    probe: Add a Hermes bytecode listing rung (hermes-dec) and pin module attribution on a fixture.
- dotnet-cil: partial (fidelity structural-summary)
    reason: ECMA-335 metadata reader (narlib/dotnetmeta) is wired standalone by nar-script over every .dll member (TypeDef/MethodDef counts, namespaces, heuristic obfuscation markers) and by the IL2CPP/Mono/Xamarin deep dives; no IL disassembly.
    probe: Add an IL disassembly rung over MethodDef RVAs with a fixture.
- javascript: partial (fidelity structural-summary)
    reason: Text bundles get minified/bundled detection, source-map presence and a webpack module-count estimate, all labelled heuristic; no AST or module-graph parse.
    probe: Add a stdlib JS tokenizer-based module census and pin it against the heuristic estimate on a fixture.
- gdscript: partial (fidelity structural-summary)
    reason: GDSC token-stream header parses (tokenizer version, identifier/constant/token counts, identifier sample) for Godot 3 and uncompressed Godot 4 streams; Zstd-compressed Godot 4 streams (no stdlib Zstd decoder) and GDEC-encrypted scripts are identified_only per file, named and never decoded; constants are counted, not decoded (Variant encodings).
    probe: Add a Godot Variant binary decoder for constant values and a Zstd decoder path, pinned with fixtures.
- dart-snapshot: identified_only (fidelity identified-only)
    reason: nar-script wires nar-flutter's extraction per member (Dart VM + Flutter version strings, snapshot markers, kernel_blob presence + kernel format version); the AOT snapshot is a serialized object graph, so class and string-pool counts are not derivable with the stdlib and are reported null.
    probe: Add a Dart snapshot object-graph parser with a labeled fixture to derive class/string counts.
- lua: partial (fidelity structural-summary)
    reason: Lua 5.x chunks get a header + prototype walk (function count, string-constant pool) and LuaJIT dumps a BCDump framing walk (function count, chunk name); opcode streams are counted and sized, not disassembled, and chunks failing validation (the encrypted/obfuscated presentation) are identified_only per file.
    probe: Add an opcode disassembly rung for one Lua version and pin it with a compiled fixture.
- wasm: supported (fidelity structural-summary)
- pyc: partial (fidelity structural-summary)
    reason: Magic maps to the CPython version and a structural marshal walker censuses code objects (count, function count, name sample) without executing, importing or marshal.loads-ing the payload; hostile marshal streams are refused with a named failure. No bytecode disassembly or decompilation.
    probe: Add a disassembly rung over the walked code objects' bytecode bytes with a fixture.
- angelscript: identified_only (fidelity identified-only)
    reason: Source (.as) census only (line count + heuristic function-pattern count): AngelScript has no standard compiled file format - scripts compile in memory and saved bytecode streams are engine-specific, so no structural parse exists to wire.
    probe: Identify a documented saved-bytecode stream layout from a real AngelScript target and add a header parser with a fixture.
- squirrel: identified_only (fidelity identified-only)
    reason: Compiled streams are identified by the 0xFAFA tag + RIQS signature with a PART-marker census; the closure serialization has no documented entry-count header, so no function count is claimed. Source (.nut) gets a labelled heuristic function census.
    probe: Implement the Squirrel closure serialization walk (literals/functions per closure) against a compiler-produced fixture.
- Pawn (AMX): partial (fidelity structural-summary)
    reason: The .amx header (Pawn Implementer's Guide) parses fully - public/native/library/pubvar/tag entry counts derive from the table offsets; the AMX instruction stream is not disassembled.
    probe: Add an AMX disassembly rung with a compiler-produced fixture.
- Custom VM bytecode: identified_only (fidelity identified-only)
    reason: Custom VM bytecode (for example SpiderMonkey .jsc in protected targets) is detected and named, never decoded by design.
    probe: Name additional custom-VM signatures only when a labeled target documents them; decoding stays out of scope by design.

## Animation systems (partial: 5, supported: 6)
- spine: partial (fidelity structural-summary)
    reason: Spine JSON exports decode fully (bones, slots with slot-to-bone attachment data, skins, constraint counts, events, per-animation timeline groups and duration estimates). The .skel binary is header-only: hash, version and skeleton dimensions are emitted when the guarded header walk stays consistent; binary timeline decode is version-sensitive and not implemented.
    probe: Export the skeleton as Spine JSON from the Spine editor for full timeline decode, or add a version-pinned .skel timeline decoder.
- dragonbones: supported (fidelity structural-summary)
- lottie: supported (fidelity structural-summary)
- rive: partial (fidelity identified-only)
    reason: Header facts only: RIVE magic, major/minor version varints and the file id varint are parsed; the property-stream decode is not implemented.
    probe: Add a Rive property-stream decoder (varint property keys and the core object table), or inspect the file in the Rive editor/runtime.
- aseprite: supported (fidelity structural-summary)
- unity-animator: partial (fidelity structural-summary)
    reason: Loose .anim/.controller/.overrideController files are Unity YAML text and decode textually (document class ids 74/91/221/1107/1102, m_Name, clip m_Legacy/m_StopTime/m_SampleRate, curve-block counts labelled as a bounded textual count, controller parameters with types, state-machine child-state names resolved through AnimatorState documents, AnyStateTransitions count). Clips/controllers embedded inside Unity bundles/.assets members are identification only (bounded member content scan for AnimationClip/AnimatorController type names).
    probe: Add a UnityPy rung to enumerate serialized objects inside UnityFS bundles and .assets files.
- godot-animationplayer: supported (fidelity structural-summary)
- spriteatlas: partial (fidelity identified-only)
    reason: nar-atlas recovers the atlas name and packed-sprite count from the .spriteatlas text YAML; packed sprites are referenced by GUID only, so frame names and rects are not recoverable from the file alone.
    probe: Add a UnityPy rung to resolve packed sprites inside the project's serialized data.
- cocos-ccb: partial (fidelity structural-summary)
    reason: .ccb decodes when it is a plist (binary or XML, via plistlib): recursive nodeGraph node count (capped), sequence names and lengths, resolutions count; a non-plist .ccb degrades to identified_only. .csb is identification plus first-bytes facts only: it is a custom FlatBuffers-based binary (Cocos Studio) and its node-graph decode is not implemented.
    probe: Add a CSB FlatBuffers reader (timeline/node tables) with a labeled fixture; convert non-plist .ccb files to their XML plist form for decode.
- creature: supported (fidelity structural-summary)
- spriter: supported (fidelity structural-summary)

## App frameworks (identified_only: 5, partial: 5, server_side: 1)
- kotlin: identified_only (fidelity identified-only)
    reason: DEX marker detection in nar-triage only; Kotlin intelligence beyond inventory is partial (capability matrix).
    probe: Pin the marker in formats-driven triage tests and extend the Kotlin @Metadata path.
- jetpack-compose: partial (fidelity structural-summary)
    reason: nar-app (Part 6) censuses @Composable-annotated classes and methods from DEX annotation directories (types only) and lists them as screens; Compose semantics beyond the annotation census (recomposition, state flow, navigation-compose routes) are not decoded.
    probe: Decode navigation-compose route strings and Compose runtime metadata on a real Compose corpus app.
- compose-multiplatform: identified_only (fidelity identified-only)
    reason: DEX marker detection in nar-triage only.
    probe: Add a fixture-backed marker test.
- androidx: partial (fidelity structural-summary)
    reason: nar-app (Part 6) censuses defined AndroidX classes, reads versions from shipped META-INF/*.version files where present, and inventories the AndroidX subsystems it covers (Room, WorkManager, DataStore, Security, Custom Tabs, UMP); other AndroidX libraries are counted, not deep-dived.
    probe: Extend the subsystem census (Navigation, Paging, Benchmark) on a real corpus app.
- jetpack-room: partial (fidelity structural-summary)
    reason: nar-app (Part 6) censuses RoomDatabase subclasses and parses shipped .db/.sqlite assets read-only via narlib.sqlite (sqlite_master page walk: tables, columns, indexes); Room entity/DAO semantics and runtime-created databases are not in the artifact.
    probe: Census @Entity/@Dao annotations on a real Room corpus app.
- jetpack-workmanager: partial (fidelity structural-summary)
    reason: nar-app (Part 6) inventories Worker/ListenableWorker subclasses, JobService subclasses, AlarmManager references and manifest foreground services; work chains, constraints and schedules are runtime configuration, not decoded.
    probe: Decode WorkSpec rows from a shipped WorkManager database on a corpus app.
- android-webview-hybrid: partial (fidelity structural-summary)
    reason: nar-app (Part 6) counts addJavascriptInterface call sites in DEX code and censuses @JavascriptInterface-annotated methods (the JS bridge surface); the JavaScript side of the bridge inside web assets is inventoried by nar-webassets, not traced call-by-call.
    probe: Correlate bridge method names with JS-side call sites in a hybrid corpus app.
- android-support-legacy: identified_only (fidelity identified-only)
    reason: DEX marker detection in nar-triage only.
    probe: Add a fixture-backed marker test.
- play-integrity: server_side (fidelity identified-only)
    reason: Client-side presence is detected, but the Play Integrity verdict is made server-side and cannot be obtained from the shipped app (capability matrix).
    probe: No client-side probe exists; the verdict requires the developer's server integration.
- apache-httpclient-legacy: identified_only (fidelity identified-only)
    reason: DEX marker detection in nar-triage only.
    probe: Add a fixture-backed marker test.
- easyrpg: identified_only (fidelity identified-only)
    reason: DEX marker detection in nar-triage only; EasyRPG has no engine family entry (no path/JNI/deep evidence) so its marker stays with triage's framework markers.
    probe: Add path/JNI evidence for EasyRPG and promote it to a full engine row.

## Protection kinds (server_side: 1, supported: 7)
- commercial_packer: supported (fidelity structural-summary)
- obfuscation: supported (fidelity structural-summary)
- anti_tamper_rasp: supported (fidelity structural-summary)
- network_protection: supported (fidelity structural-summary)
- licensing_drm: supported (fidelity structural-summary)
- code_asset_encryption: supported (fidelity structural-summary)
- native_hardening: supported (fidelity structural-summary)
- play-integrity-verdict: server_side (fidelity identified-only)
    reason: The verdict is server-side; only client-side presence markers are detectable statically.
    probe: No client-side probe exists; the verdict requires the developer's server integration.

## Gaps — every non-supported entry, with reason and probe

NAR coverage matrix (from formats.json)
============================================================

## Input types (partial: 6, supported: 13, unsupported: 1)
- odex: partial (fidelity structural-summary)
    reason: Dalvik-era ODEX payload is identified and its embedded DEX located; deep parse rides the DEX path only.
    probe: Add a real Dalvik ODEX corpus file and pin field-level parsing.
- vdex: partial (fidelity structural-summary)
    reason: Header fields parsed for version 006; later versions are identified with limited field parsing.
    probe: Add VDEX samples beyond 006 and extend field parsing.
- oat: partial (fidelity structural-summary)
    reason: Verified on API 26 files; OAT beyond API 26 is synthetic-only (capability matrix).
    probe: Add real OAT files from newer API levels and pin parsing.
- cdex: partial (fidelity structural-summary)
    reason: Header + section table parsed; payload is NOT decoded (payload_decoded stays false).
    probe: Add a real CDEX corpus and a payload decoder.
- art: partial (fidelity structural-summary)
    reason: Header parsed on a real API 26 boot image; other versions are untested.
    probe: Add ART images from other API levels and pin parsing.
- unity-assetbundle: partial (fidelity structural-summary)
    reason: Bundle header + blocks-info parsed; LZ4/LZHAM blocks are inventoried, never decoded (no stdlib decoder).
    probe: Add an LZ4 block decoder path with a fixture.
- unknown: unsupported (fidelity identified-only)
    reason: No known signature matched; reported as unknown, never guessed.
    probe: Add a signature + structural verdict for the new format with a fixture.

## Engines (partial: 14, supported: 12)
- Unity (IL2CPP): partial (fidelity structural-summary)
    reason: Deep dive locates the IL2CPP pair and summarizes metadata; Mono-side inventory and scene/prefab semantics are not reconstructed (capability matrix: Unity analysis is partially supported).
    probe: Extend nar-il2cpp/nar-unity object-level parsing and pin it with a labeled fixture.
- Unreal Engine: partial (fidelity structural-summary)
    reason: Deep dive parses pak/IoStore/Zen/classic packages at structural level, decodes .locres string tables (v1 EntryMetaData layout verified end-to-end on real samples; v0 Initial layout implemented from the public format, synthetic-verified only) and attaches Wwise bank header facts for readable .bnk/.wem members (Oodle/encrypted members are named, never decoded). Kismet/Blueprint decoding, Oodle and AES decryption are unsupported by design (capability matrix).
    probe: Add Kismet bytecode decoding to narlib/uasset.py with synthetic packages pinning it.
- Flutter: partial (fidelity structural-summary)
    reason: Fingerprint + flutter_assets inventory only; Dart snapshot/VM structure parsing and symbol recovery are not implemented (capability matrix).
    probe: Add a Dart snapshot structure parser to nar-flutter with a labeled fixture.
- React Native: partial (fidelity structural-summary)
    reason: Hermes header parse and bundle inventory exist; Hermes module-name attribution and bytecode decompilation are not built in (capability matrix).
    probe: Wire a Hermes bytecode rung (hermes-dec) into nar-rn and pin module attribution on a fixture.
- Adobe AIR: partial (fidelity structural-summary)
    reason: Descriptor and SWF structure are parsed (header, tag census, ExportAssets/SymbolClass symbol names), but DoABC tags are counted and sized only: ABC bytecode is not decoded, so ActionScript semantics are not reconstructed.
    probe: Add an ABC (ActionScript bytecode) parser to nar-air.py to lift symbol-level facts (classes, methods) from DoABC bodies, pinned with a synthetic SWF fixture.
- Xamarin / .NET: partial (fidelity structural-summary)
    reason: Deep dive parses loose *.dll members and assemblies carved from uncompressed assemblies.blob spans through narlib.dotnetmeta (typedef/methoddef counts, Module-table names) and censuses the native runtime libraries and AssemblyStore markers. XALZ blocks — the default AssemblyStore compression in current Xamarin/MAUI builds — are counted by magic only: they are LZ4-compressed payloads and the stdlib has no LZ4 decoder, so assemblies inside XALZ stores are identified, not parsed.
    probe: XALZ blocks are counted by magic only: they are LZ4-compressed assembly payloads and the stdlib has no LZ4 decoder, so compressed assemblies are identified, not decoded. A blob over the 32 MiB member-read cap is skipped whole.
- Qt for Android: partial (fidelity structural-summary)
    reason: Deep dive parses Qt RCC v1/v2 headers and walks the 22-byte tree-node records recursively (bounded nodes/depth, every offset validated) reconstructing resource paths with sizes and compression flags (zlib payloads), plus .qmlc/.jsc identification. No real Qt corpus locally; layout from public format documentation, synthetic-fixture verified.
    probe: Validate the tree walk against a real .rcc (including v2 and locale/country node variants) when a labeled corpus target is available.
- Defold: partial (fidelity structural-summary)
    reason: Deep dive parses the .arci index (public Defold engine source layout) with a fully validated entry walk (count/offset/size/hash checks) and reports entry counts, payload totals, compressed/encrypted flag counts and largest entries by hash; entry paths are NOT recoverable from the index (MurmurHash64 hashes only) — that is the family's structural boundary, stated in the report. No real Defold corpus locally; layout from public format documentation, synthetic-fixture verified.
    probe: Validate the .arci entry walk and flag-bit meanings (compressed=0x1, encrypted=0x2 assumed from public source) against a real Defold archive when a labeled corpus target is available.
- Ren'Py: partial (fidelity structural-summary)
    reason: Deep dive parses RPA-1.0/2.0/3.0 headers and index listings (file count, total bytes, by-extension census, sample names) with RPA-3.0 key XOR deobfuscation. SECURITY: the index pickle is never loaded with plain pickle.loads — a pickletools pre-scan refuses GLOBAL/STACK_GLOBAL/REDUCE/OBJ/INST/NEWOBJ (and NEWOBJ_EX/EXT) opcodes and the load uses a RestrictedUnpickler whose find_class always raises; a hostile reduce-based fixture is refused and never executes (test-pinned). Consequence: indexes whose bytes objects are encoded via a reduce (protocol < 3 style) are refused by design rather than executed. .rpyc is identification + length-prefixed zlib slot census only, no decompilation. No real Ren'Py corpus locally; layout from public format documentation, synthetic-fixture verified.
    probe: Validate the RPA-2.0/1.0 header shapes and the RPC2 slot walk against a real Ren'Py build when a labeled corpus target is available.
- GameMaker: partial (fidelity structural-summary)
    reason: Deep dive walks the data.win FORM chunk table with validated sizes, resolves the GEN8 game name via candidate string-offset fields (+4/+8/+12, basis reported), censuses the STRG string table (count, sample, total chars) and reads TXTR/AUDO/SPRT count fields. No real GameMaker corpus locally; layout from public format documentation, synthetic-fixture verified.
    probe: Confirm the GEN8 name-field position and chunk count-field semantics against a real data.win when a labeled corpus target is available; extend to room/object chunk censuses only after that validation.
- Solar2D: partial (fidelity structural-summary)
    reason: Deep dive lists resource.car when it is a plain ZIP (count, by-extension census, total bytes), extracts labelled textual facts from config.lua/build.settings (orientation.default, content scale/fps via bounded regex) and censuses compiled Lua (.luac + extensionless Lua-magic members); non-ZIP car variants degrade to identification + header facts. Corona markers (assets/*.luac, libcorona.so paths) are censused in the surrounding APK. No real Solar2D corpus locally; behaviour from public format documentation, synthetic-fixture verified.
    probe: Identify the non-ZIP resource.car variant layout from a real Solar2D build when a labeled corpus target is available.
- Heaps / Haxe: partial (fidelity identified-only)
    reason: Deep dive verifies the HLB magic and decodes the version and flags uindex values (documented HashLink uindex encoding, including multi-byte values) plus a sibling .hl/.dat census. Section counts after version/flags are deliberately NOT named: the deeper header walk could not be validated, so section_counts is null with the reason recorded — no counts are invented. No real HashLink corpus locally; layout from public format documentation, synthetic-fixture verified.
    probe: Validate the full header count sequence (types/functions/globals/constants order) against a real hlboot.dat and only then name section counts.
- Bevy / Rust: partial (fidelity structural-summary)
    reason: The assets census is structural (member count, by-extension census, .ron and .scn.ron counts) and the rustc version is extracted from the 'rustc version ' string in the largest native library when present; Bevy crate presence is occurrence counts of the bevy_ecs / bevy_render / bevy_asset / bevy_winit / winit name strings, labelled string evidence, with the verdict requiring RON assets or at least two distinct crate strings.
    probe: RON facts are a labelled textual approximation (identifiers at bracket depth 1 followed by ':'), not a RON parse — a real RON parser would be needed for typed scene data; crate string counts cannot distinguish linked Bevy crates from coincidental string content, which is why the status is partial.
- MonoGame / FNA: partial (fidelity structural-summary)
    reason: MonoGame.Framework.dll is found loose or carved from assemblies.blob (identified by its Module-table name) and summarized via narlib.dotnetmeta; FNA markers (FNA.dll, FAudio, libtheorafile) are a presence list. XNB headers parse fully (platform byte, version, HiDef/compressed flags, declared size validated against the member size) and uncompressed XNBs get their whole type-reader table parsed, with the census grouped by primary reader short name.
    probe: Compressed XNBs (flag 0x80) are LZX-compressed: counted, never decoded — no stdlib LZX decoder exists; that is why the status is partial rather than supported.

## Asset formats (partial: 1, supported: 87)
- unity-spriteatlas: partial (fidelity identified-only)
    reason: Text YAML references packed sprites by GUID only: nar-atlas recovers the atlas name and packed-sprite count; frame names and rects are not recoverable from the .spriteatlas file alone.
    probe: Add a UnityPy rung to resolve the packed sprites inside the project's serialized data.

## Script formats (identified_only: 4, partial: 7, supported: 2)
- hermes: partial (fidelity structural-summary)
    reason: Header parse (bytecode version, function/string/identifier counts) lives in nar-rn.parse_hermes_header and is wired per-file by nar-script; no bytecode disassembly or module attribution.
    probe: Add a Hermes bytecode listing rung (hermes-dec) and pin module attribution on a fixture.
- dotnet-cil: partial (fidelity structural-summary)
    reason: ECMA-335 metadata reader (narlib/dotnetmeta) is wired standalone by nar-script over every .dll member (TypeDef/MethodDef counts, namespaces, heuristic obfuscation markers) and by the IL2CPP/Mono/Xamarin deep dives; no IL disassembly.
    probe: Add an IL disassembly rung over MethodDef RVAs with a fixture.
- javascript: partial (fidelity structural-summary)
    reason: Text bundles get minified/bundled detection, source-map presence and a webpack module-count estimate, all labelled heuristic; no AST or module-graph parse.
    probe: Add a stdlib JS tokenizer-based module census and pin it against the heuristic estimate on a fixture.
- gdscript: partial (fidelity structural-summary)
    reason: GDSC token-stream header parses (tokenizer version, identifier/constant/token counts, identifier sample) for Godot 3 and uncompressed Godot 4 streams; Zstd-compressed Godot 4 streams (no stdlib Zstd decoder) and GDEC-encrypted scripts are identified_only per file, named and never decoded; constants are counted, not decoded (Variant encodings).
    probe: Add a Godot Variant binary decoder for constant values and a Zstd decoder path, pinned with fixtures.
- dart-snapshot: identified_only (fidelity identified-only)
    reason: nar-script wires nar-flutter's extraction per member (Dart VM + Flutter version strings, snapshot markers, kernel_blob presence + kernel format version); the AOT snapshot is a serialized object graph, so class and string-pool counts are not derivable with the stdlib and are reported null.
    probe: Add a Dart snapshot object-graph parser with a labeled fixture to derive class/string counts.
- lua: partial (fidelity structural-summary)
    reason: Lua 5.x chunks get a header + prototype walk (function count, string-constant pool) and LuaJIT dumps a BCDump framing walk (function count, chunk name); opcode streams are counted and sized, not disassembled, and chunks failing validation (the encrypted/obfuscated presentation) are identified_only per file.
    probe: Add an opcode disassembly rung for one Lua version and pin it with a compiled fixture.
- pyc: partial (fidelity structural-summary)
    reason: Magic maps to the CPython version and a structural marshal walker censuses code objects (count, function count, name sample) without executing, importing or marshal.loads-ing the payload; hostile marshal streams are refused with a named failure. No bytecode disassembly or decompilation.
    probe: Add a disassembly rung over the walked code objects' bytecode bytes with a fixture.
- angelscript: identified_only (fidelity identified-only)
    reason: Source (.as) census only (line count + heuristic function-pattern count): AngelScript has no standard compiled file format - scripts compile in memory and saved bytecode streams are engine-specific, so no structural parse exists to wire.
    probe: Identify a documented saved-bytecode stream layout from a real AngelScript target and add a header parser with a fixture.
- squirrel: identified_only (fidelity identified-only)
    reason: Compiled streams are identified by the 0xFAFA tag + RIQS signature with a PART-marker census; the closure serialization has no documented entry-count header, so no function count is claimed. Source (.nut) gets a labelled heuristic function census.
    probe: Implement the Squirrel closure serialization walk (literals/functions per closure) against a compiler-produced fixture.
- Pawn (AMX): partial (fidelity structural-summary)
    reason: The .amx header (Pawn Implementer's Guide) parses fully - public/native/library/pubvar/tag entry counts derive from the table offsets; the AMX instruction stream is not disassembled.
    probe: Add an AMX disassembly rung with a compiler-produced fixture.
- Custom VM bytecode: identified_only (fidelity identified-only)
    reason: Custom VM bytecode (for example SpiderMonkey .jsc in protected targets) is detected and named, never decoded by design.
    probe: Name additional custom-VM signatures only when a labeled target documents them; decoding stays out of scope by design.

## Animation systems (partial: 5, supported: 6)
- spine: partial (fidelity structural-summary)
    reason: Spine JSON exports decode fully (bones, slots with slot-to-bone attachment data, skins, constraint counts, events, per-animation timeline groups and duration estimates). The .skel binary is header-only: hash, version and skeleton dimensions are emitted when the guarded header walk stays consistent; binary timeline decode is version-sensitive and not implemented.
    probe: Export the skeleton as Spine JSON from the Spine editor for full timeline decode, or add a version-pinned .skel timeline decoder.
- rive: partial (fidelity identified-only)
    reason: Header facts only: RIVE magic, major/minor version varints and the file id varint are parsed; the property-stream decode is not implemented.
    probe: Add a Rive property-stream decoder (varint property keys and the core object table), or inspect the file in the Rive editor/runtime.
- unity-animator: partial (fidelity structural-summary)
    reason: Loose .anim/.controller/.overrideController files are Unity YAML text and decode textually (document class ids 74/91/221/1107/1102, m_Name, clip m_Legacy/m_StopTime/m_SampleRate, curve-block counts labelled as a bounded textual count, controller parameters with types, state-machine child-state names resolved through AnimatorState documents, AnyStateTransitions count). Clips/controllers embedded inside Unity bundles/.assets members are identification only (bounded member content scan for AnimationClip/AnimatorController type names).
    probe: Add a UnityPy rung to enumerate serialized objects inside UnityFS bundles and .assets files.
- spriteatlas: partial (fidelity identified-only)
    reason: nar-atlas recovers the atlas name and packed-sprite count from the .spriteatlas text YAML; packed sprites are referenced by GUID only, so frame names and rects are not recoverable from the file alone.
    probe: Add a UnityPy rung to resolve packed sprites inside the project's serialized data.
- cocos-ccb: partial (fidelity structural-summary)
    reason: .ccb decodes when it is a plist (binary or XML, via plistlib): recursive nodeGraph node count (capped), sequence names and lengths, resolutions count; a non-plist .ccb degrades to identified_only. .csb is identification plus first-bytes facts only: it is a custom FlatBuffers-based binary (Cocos Studio) and its node-graph decode is not implemented.
    probe: Add a CSB FlatBuffers reader (timeline/node tables) with a labeled fixture; convert non-plist .ccb files to their XML plist form for decode.

## App frameworks (identified_only: 5, partial: 5, server_side: 1)
- kotlin: identified_only (fidelity identified-only)
    reason: DEX marker detection in nar-triage only; Kotlin intelligence beyond inventory is partial (capability matrix).
    probe: Pin the marker in formats-driven triage tests and extend the Kotlin @Metadata path.
- jetpack-compose: partial (fidelity structural-summary)
    reason: nar-app (Part 6) censuses @Composable-annotated classes and methods from DEX annotation directories (types only) and lists them as screens; Compose semantics beyond the annotation census (recomposition, state flow, navigation-compose routes) are not decoded.
    probe: Decode navigation-compose route strings and Compose runtime metadata on a real Compose corpus app.
- compose-multiplatform: identified_only (fidelity identified-only)
    reason: DEX marker detection in nar-triage only.
    probe: Add a fixture-backed marker test.
- androidx: partial (fidelity structural-summary)
    reason: nar-app (Part 6) censuses defined AndroidX classes, reads versions from shipped META-INF/*.version files where present, and inventories the AndroidX subsystems it covers (Room, WorkManager, DataStore, Security, Custom Tabs, UMP); other AndroidX libraries are counted, not deep-dived.
    probe: Extend the subsystem census (Navigation, Paging, Benchmark) on a real corpus app.
- jetpack-room: partial (fidelity structural-summary)
    reason: nar-app (Part 6) censuses RoomDatabase subclasses and parses shipped .db/.sqlite assets read-only via narlib.sqlite (sqlite_master page walk: tables, columns, indexes); Room entity/DAO semantics and runtime-created databases are not in the artifact.
    probe: Census @Entity/@Dao annotations on a real Room corpus app.
- jetpack-workmanager: partial (fidelity structural-summary)
    reason: nar-app (Part 6) inventories Worker/ListenableWorker subclasses, JobService subclasses, AlarmManager references and manifest foreground services; work chains, constraints and schedules are runtime configuration, not decoded.
    probe: Decode WorkSpec rows from a shipped WorkManager database on a corpus app.
- android-webview-hybrid: partial (fidelity structural-summary)
    reason: nar-app (Part 6) counts addJavascriptInterface call sites in DEX code and censuses @JavascriptInterface-annotated methods (the JS bridge surface); the JavaScript side of the bridge inside web assets is inventoried by nar-webassets, not traced call-by-call.
    probe: Correlate bridge method names with JS-side call sites in a hybrid corpus app.
- android-support-legacy: identified_only (fidelity identified-only)
    reason: DEX marker detection in nar-triage only.
    probe: Add a fixture-backed marker test.
- play-integrity: server_side (fidelity identified-only)
    reason: Client-side presence is detected, but the Play Integrity verdict is made server-side and cannot be obtained from the shipped app (capability matrix).
    probe: No client-side probe exists; the verdict requires the developer's server integration.
- apache-httpclient-legacy: identified_only (fidelity identified-only)
    reason: DEX marker detection in nar-triage only.
    probe: Add a fixture-backed marker test.
- easyrpg: identified_only (fidelity identified-only)
    reason: DEX marker detection in nar-triage only; EasyRPG has no engine family entry (no path/JNI/deep evidence) so its marker stays with triage's framework markers.
    probe: Add path/JNI evidence for EasyRPG and promote it to a full engine row.

## Protection kinds (server_side: 1, supported: 7)
- play-integrity-verdict: server_side (fidelity identified-only)
    reason: The verdict is server-side; only client-side presence markers are detectable statically.
    probe: No client-side probe exists; the verdict requires the developer's server integration.
