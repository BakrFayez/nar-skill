# Script & bytecode formats

Every format in `scripts/formats.json` `script_formats`. Parser: `nar-script` unless stated.

## dex — dex

Status: **supported** · Fidelity: bytecode-listing · Parser: `narlib/dex + narlib/dexdis` · Test: `tests/unit/test_dex_elf.py`

```bash
python3 scripts/nar-dex.py <fixture:demo/NarDemo.apk>
```

```text
NAR DEX intelligence: NarDemo.apk
============================================================
- classes.dex (DEX 037): 7 classes, 13 methods, 14 fields (header: 33 method ids)
    call edges: 36; native methods: 1; entry points: 2
    try/catch: 0 of 12 coded methods, 0 try items, 0 handler entries; debug info on 12 methods
```

## hermes — hermes

Status: **partial** · Fidelity: structural-summary · Parser: `nar-rn + nar-script` · Test: `tests/unit/test_script.py::test_hermes_header_via_wired_parser`

Header parse (bytecode version, function/string/identifier counts) lives in nar-rn.parse_hermes_header and is wired per-file by nar-script; no bytecode disassembly or module attribution.

```bash
python3 scripts/nar-script.py <target>
```

## dotnet-cil — dotnet-cil

Status: **partial** · Fidelity: structural-summary · Parser: `narlib/dotnetmeta + nar-script` · Test: `tests/unit/test_script.py::test_dotnet_cil_via_dotnetmeta`

ECMA-335 metadata reader (narlib/dotnetmeta) is wired standalone by nar-script over every .dll member (TypeDef/MethodDef counts, namespaces, heuristic obfuscation markers) and by the IL2CPP/Mono/Xamarin deep dives; no IL disassembly.

```bash
python3 scripts/nar-script.py <target>
```

## javascript — javascript

Status: **partial** · Fidelity: structural-summary · Parser: `nar-script` · Test: `tests/unit/test_script.py::test_javascript_webpack_bundle_facts`

Text bundles get minified/bundled detection, source-map presence and a webpack module-count estimate, all labelled heuristic; no AST or module-graph parse.

```bash
python3 scripts/nar-script.py <target>
```

## gdscript — gdscript

Status: **partial** · Fidelity: structural-summary · Parser: `nar-script` · Test: `tests/unit/test_script.py::test_gdscript_godot3_counts_and_identifiers`

GDSC token-stream header parses (tokenizer version, identifier/constant/token counts, identifier sample) for Godot 3 and uncompressed Godot 4 streams; Zstd-compressed Godot 4 streams (no stdlib Zstd decoder) and GDEC-encrypted scripts are identified_only per file, named and never decoded; constants are counted, not decoded (Variant encodings).

```bash
python3 scripts/nar-script.py <target>
```

## dart-snapshot — dart-snapshot

Status: **identified_only** · Fidelity: identified-only · Parser: `nar-script` · Test: `tests/unit/test_script.py::test_kernel_blob_header_facts`

nar-script wires nar-flutter's extraction per member (Dart VM + Flutter version strings, snapshot markers, kernel_blob presence + kernel format version); the AOT snapshot is a serialized object graph, so class and string-pool counts are not derivable with the stdlib and are reported null.

```bash
python3 scripts/nar-script.py <target>
```

## lua — lua

Status: **partial** · Fidelity: structural-summary · Parser: `nar-script` · Test: `tests/unit/test_script.py::test_lua51_chunk_walk_counts_and_strings`

Lua 5.x chunks get a header + prototype walk (function count, string-constant pool) and LuaJIT dumps a BCDump framing walk (function count, chunk name); opcode streams are counted and sized, not disassembled, and chunks failing validation (the encrypted/obfuscated presentation) are identified_only per file.

```bash
python3 scripts/nar-script.py <target>
```

## wasm — wasm

Status: **supported** · Fidelity: structural-summary · Parser: `nar-script` · Test: `tests/unit/test_script.py::test_wasm_real_module_from_wat`

```bash
python3 scripts/nar-script.py <synthetic-fixture.apk>
```

```text
  [wasm] assets/mod.wasm (supported) — version=1, function_count=0, total_functions=0
```

## pyc — pyc

Status: **partial** · Fidelity: structural-summary · Parser: `nar-script` · Test: `tests/unit/test_script.py::test_pyc_real_compile_census`

Magic maps to the CPython version and a structural marshal walker censuses code objects (count, function count, name sample) without executing, importing or marshal.loads-ing the payload; hostile marshal streams are refused with a named failure. No bytecode disassembly or decompilation.

```bash
python3 scripts/nar-script.py <target>
```

## angelscript — angelscript

Status: **identified_only** · Fidelity: identified-only · Parser: `nar-script` · Test: `tests/unit/test_script.py::test_angelscript_source_identified_only`

Source (.as) census only (line count + heuristic function-pattern count): AngelScript has no standard compiled file format - scripts compile in memory and saved bytecode streams are engine-specific, so no structural parse exists to wire.

```bash
python3 scripts/nar-script.py <target>
```

## squirrel — squirrel

Status: **identified_only** · Fidelity: identified-only · Parser: `nar-script` · Test: `tests/unit/test_script.py::test_squirrel_compiled_stream_identified`

Compiled streams are identified by the 0xFAFA tag + RIQS signature with a PART-marker census; the closure serialization has no documented entry-count header, so no function count is claimed. Source (.nut) gets a labelled heuristic function census.

```bash
python3 scripts/nar-script.py <target>
```

## pawn — Pawn (AMX)

Status: **partial** · Fidelity: structural-summary · Parser: `nar-script` · Test: `tests/unit/test_script.py::test_pawn_amx_table_counts`

The .amx header (Pawn Implementer's Guide) parses fully - public/native/library/pubvar/tag entry counts derive from the table offsets; the AMX instruction stream is not disassembled.

```bash
python3 scripts/nar-script.py <target>
```

## custom-vm — Custom VM bytecode

Status: **identified_only** · Fidelity: identified-only · Parser: `nar-script` · Test: `tests/unit/test_script.py::test_custom_vm_named_never_decoded`

Custom VM bytecode (for example SpiderMonkey .jsc in protected targets) is detected and named, never decoded by design.

```bash
python3 scripts/nar-script.py <target>
```
