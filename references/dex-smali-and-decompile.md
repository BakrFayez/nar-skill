# DEX, smali, and decompile

DEX is where app and game logic lives, except in engine-native games, where
most logic is in `.so` files. For those games, see the native guide. This guide covers
DEX structure, smali, jadx decompilation, and searching code.

## DEX file structure

A DEX file starts with a 112-byte header (`dex\n039\0` magic, checksum,
SHA-1 signature, file size, offsets and sizes of each section), followed
by string IDs, type IDs, proto IDs, field IDs, method IDs, class
definitions, call-site IDs, and the data section (code, strings, debug
info, annotations).

Sections that matter for analysis:

- `string_ids`: every string literal, in order. Searching here is the
  fastest way to find a feature's footprint.
- `type_ids`: type descriptors (`Lcom/example/Foo;`, `I`, `[B`).
- `method_ids`: class + proto + name for every referenced method.
- `class_defs`: per-class access flags, superclass, interfaces, and
  offsets to fields and methods.
- `code`: Dalvik bytecode per method, with registers, instructions,
  try/catch, and debug info.

Hard-won NAR notes (from building DEX parsers by hand):

- `type_list` entries are `uint16`, not `uint32`. Each entry is a
  2-byte index into `type_ids`, and the list is padded to a 4-byte
  boundary. Reading them as 4-byte values silently corrupts every
  interface list and multi-type proto after the first entry.
- Multi-DEX apps (`classes.dex`, `classes2.dex`, ...) split classes
  across files. A class or method search must cover every DEX file,
  not just `classes.dex`. jadx and apktool handle this; hand-rolled
  searches must not stop at the first file.
- DEX 039 is the current version; older DEX 035/037/038 files differ
  in small ways (for example, hidden-API flags). Parse by the header
  version, not by assumption.

## Instruction-level disassembly (built in)

nar-dex can decode method bytecode itself
(`scripts/narlib/dexdis.py`, pure Python, no external tool) for the
cases where the orchestrated decompilers are the wrong instrument:
a jadx failure on one obfuscated or protected method, a quick
instruction-level check while triaging, or a DEX whose structure
the structural parser already reads but that no decompiler run has
covered yet.

```bash
python3 scripts/nar-dex.py app.apk --disassemble \
    --disasm-class 'Lcom/example/Pay;' --disasm-method 'verify'
python3 scripts/nar-dex.py app.apk --disassemble --disasm-all
```

Discipline, by design:

- **Targeted, not a dump.** A selection is required: a class
  and/or method substring pattern, or `--disasm-all` to request
  the full corpus explicitly. Unscoped `--disassemble` is
  refused. Listings are capped (`--disasm-limit`, default 500);
  selection and decode counts always stay complete.
- **Resolved operands.** Every reference is rendered through the
  DEX's own tables: string contents, type names, field and
  method signatures, prototypes (parameter descriptors
  concatenated with no separator, per DEX convention),
  call sites in full smali form
  (`call_site_N("name", proto, args...)@bootstrap`), and method
  handles as `kind@target`.
- **Full format coverage.** All documented instruction formats
  and the switch / fill-array payload pseudo-instructions
  (payloads are consumed in-stream and reported as payloads,
  never mistaken for opcodes). DEX 038+ forms (invoke-custom,
  invoke-polymorphic, const-method-handle, const-method-type)
  decode only in files whose header version allows them.
- **Clean failure, never a guess.** An unknown opcode, an
  out-of-range reference index, a truncated stream, or a gated
  opcode in an older file fails THAT method's listing with the
  precise reason and code-unit offset; the rest of the file is
  unaffected. Switch/fill target mismatches are warnings, not
  failures. A single wrong operand width would corrupt every
  following instruction, so width correctness is treated as
  the core risk and is oracle-verified (see below).
- **Scope limit.** The listing covers instructions and
  payloads. It does not build a control-flow graph, does not
  decode try/catch handler tables or debug info, and is not a
  decompiler — for Java-level reading, jadx stays the tool.

Verification: the decoder was cross-checked instruction by
instruction against the Android SDK disassembler over the demo
fixture DEX and three real-world DEX files from the local test
corpus (DEX 035/037; 40,837 methods, 773,166 instructions and
2,363 payloads compared on address, mnemonic, resolved
reference, branch target, and literal — full agreement, zero
failures), against a toolchain-built DEX 038 file carrying a
real invoke-polymorphic (full agreement), and against an
independent smali disassembler for the DEX 038/039 gated forms
on a spec-built file (rendering identical). A full-corpus
decode of the largest corpus DEX (56,073 methods, 1,217,078
instructions) completes in about 6 seconds. No local real-world
file uses invoke-custom, so that form's real-file coverage
rests on the spec-built file plus its unit tests.

## smali

apktool decodes DEX to smali (one `.smali` file per class), the
human-readable form of Dalvik bytecode. Read smali when jadx output is
unclear, when you need exact control flow, or when you are tracing a
single method.

Smali essentials:

- Registers are `v0`, `v1`, ... (locals) and `p0`, `p1`, ... (parameters;
  `p0` is `this` for instance methods).
- `invoke-virtual`, `invoke-direct`, `invoke-static`, `invoke-interface`,
  `invoke-super` call methods; `invoke-custom` is a lambda or
  method-handle call site.
- `const-string` loads a string literal; `sget-object` / `sput-object`
  read and write static fields.
- `if-*` / `goto` are branches; `packed-switch` / `sparse-switch` are
  switch tables; `try` / `catch` blocks are explicit.

Smali round-trip rules (for your own tooling, when re-assembling):

- Never hand-edit smali and expect a working APK without re-signing;
  see the signatures guide for why the signature breaks.
- `d8` does not accept a bare classes directory: jar the `.class`
  files first, then run `d8` on the jar. Passing a directory fails.
- When rebuilding a ZIP with Java's `ZipOutputStream`, `STORED`
  (uncompressed) entries require `size`, `compressedSize`, and `CRC`
  set before writing the entry. Buffer the entry bytes first, compute
  all three, then write. `DEFLATED` entries do not need this.

## jadx decompilation

jadx turns DEX into readable Java. It is the main code-reading tool.

```bash
jadx -d out/jadx app.apk                    # decompile everything
jadx --show-bad-code -d out/jadx app.apk    # include code jadx could not decompile cleanly
jadx -d out/jadx --comments-level error app.apk   # quieter output
```

Useful flags:

- `--no-res`: skip resources (faster when you only need code).
- `--no-imports`: keep fully qualified names (useful for grepping).
- `--deobf`: rename obfuscated identifiers to readable placeholders.
  Names are guesses; never treat a deobfuscated name as the original.
- `--single-class com.example.Foo`: decompile one class only.
- Heap for large games: jadx has no `--jvm-args` flag. Set the heap
  through the environment instead: `JADX_OPTS="-Xmx8g" jadx ...`.
  The launcher also honors `JAVA_OPTS`.

jadx output is an approximation of the original source, not the
original source. Limits to respect:

- Deobfuscated names are invented. Control flow may be restructured.
  Some methods decompile to `// $FF: Couldn't be decompiled`. Read
  those in smali instead.
- jadx does not recover comments, original local names, or generics
  that were erased.
- Never copy jadx output verbatim into a shipping product. It is
  evidence for understanding, not source to reuse. See the
  version-compare guide for reconstruction rules.

### Mapping files (R8 / ProGuard)

A release build is usually obfuscated with R8 or ProGuard: class and
method names become `a`, `b`, `c`. If you have the build's `mapping.txt`
(your own app's build output), note what jadx can and cannot do with
it. The jadx CLI does not apply ProGuard `mapping.txt` files. Its
`--mappings-path` flag takes Tiny and Tiny v2 (`.tiny`) or Enigma
(`.mapping`) files only. Do not pass a ProGuard `mapping.txt` to it
and expect renamed output. REA's Android tools do accept a
`mapping.txt` path when you use REA instead of plain jadx.

Without a usable mapping, work from string literals, Android API
calls, and structure: package shapes, class sizes, and string
constants identify features even when names are gone. Never guess
that an obfuscated name maps to a specific original name; say
`a.b.c` (obfuscated) and describe what it does from its body.

## Searching classes and methods

Start from a question, not from browsing:

1. Search strings first: `grep -r "some literal" out/jadx/sources/`
   finds the class that uses a feature's text, URL, or key.
2. Search API calls: `grep -r "getSystemService\|HttpURLConnection" ...`
   finds platform usage.
3. Search class names by keyword: `find out/jadx/sources -iname "*login*"`.
4. Read one class fully before expanding. Understand its fields and
   methods, then follow the calls that matter.

Find callers (incoming references) with grep over the jadx tree, or
with `grep -r "methodName" out/jadx/sources/` scoped to the owning
class name. There is no exact xref index in jadx output; a textual
search is the working method, and it misses reflection and dynamic
calls. Record that as a coverage limit.

## WebView and JavaScript bridges

Apps that embed web content use `android.webkit.WebView`. The
interesting analysis surface is the bridge between JavaScript and
Java, and the URLs the WebView loads. Search jadx output:

```bash
grep -rn "addJavascriptInterface" out/jadx/sources/
grep -rn "JavascriptInterface" out/jadx/sources/
grep -rn "setJavaScriptEnabled" out/jadx/sources/
grep -rn "shouldOverrideUrlLoading\|WebViewClient\|loadUrl" out/jadx/sources/
grep -rln "android.webkit.WebView" out/jadx/sources/
```

What each hit means:

- `addJavascriptInterface(obj, "name")`: exposes a Java object to
  JavaScript under `name`. Read the object's class: every method
  annotated `@JavascriptInterface` is callable from any page the
  WebView loads. An unannotated method is not reachable from
  JavaScript on Android 4.2 and later, but is reachable on 4.1 and
  older (see the legacy guide).
- `setJavaScriptEnabled(true)`: JavaScript runs in the WebView.
  Without it, the bridge is dead even if it is registered.
- `shouldOverrideUrlLoading`: the app intercepts URL loads. Read
  it to see which URLs stay in the WebView and which open elsewhere
  or trigger native actions.
- `loadUrl("javascript:...")`: the app injects JavaScript into the
  loaded page. Read the injected strings; they are part of the
  app's behavior.
- Local HTML: WebView apps often load pages from `assets/`
  (`file:///android_asset/`). Read those files too; the bridge
  contract lives in them as much as in the Java code.

Verification note: these grep commands were run against jadx output
of a test APK (0 WebView hits; the test app has no WebView). The
commands execute cleanly; a positive hit on a WebView app was not
observed on this machine.

## Reflection and dynamic loading

Static analysis cannot see through reflection (`Class.forName`,
`Method.invoke`), dynamic class loading (`DexClassLoader`,
`PathClassLoader`), or native-called Java methods. When a feature's
entry point is reflective:

- Say so explicitly: "entry point reached via reflection; static
  callers unknown."
- Search for the reflective string constants (class and method names
  as literals). They are often visible even when the call is not.
- Use dynamic analysis to confirm the runtime target. See the
  dynamic-analysis guide.

## When DEX is not the story

In Unity IL2CPP games, `classes.dex` is mostly a thin launcher; the
game logic is compiled into `libil2cpp.so` plus `global-metadata.dat`.
In Unreal games, most logic is in `libUE4.so`. If triage shows a tiny
DEX and a huge `.so`, go to the native guide first and treat DEX as
the wrapper, not the app.
