---
name: nar
description: "Reverse engineer any Android APK or AAB (apps and games) with CLI tools: triage and inventory, manifest and resources, DEX/smali analysis, jadx decompilation, native libraries and JNI, game engines (Unity/Unreal/Godot), Unity IL2CPP deep analysis, Flutter/Dart, app bundles, network traffic, Frida scripts, signatures, version comparison, feature maps, and legacy (Android 4.x-7) and modern (Android 14/15/16) analysis."
metadata:
  version: "3.0.3"
---

# NAR: Nirous Android Reversing

NAR is an AI-agent skill for Android APK reverse engineering, in the style of
REA (reverse-engineer-anything) but specialized ONLY on Android APKs, AABs,
split APKs, and OBB expansion files. It covers **all Android apps and games,
old and new**: regular apps, Unity / Unreal / Godot / Flutter games and apps,
native-heavy apps, and legacy builds back to Android 4.x.

Use NAR when a claim depends on a shipped APK: what the app does, how a
feature is implemented, what changed between two versions, what a game is
built with, or what to rebuild from scratch as an original implementation.
For ordinary analysis of a complete source repository you already own, use
normal repository tools and do not run NAR.

NAR is CLI-first. No MCP server is required: it works in Muse, Claude Code,
Codex, Cursor, and any agent with a shell, using apktool, jadx, aapt2,
apksigner, and optional Ghidra / Kuna / Frida. The APK is never launched by
static analysis; dynamic analysis is a separate, opt-in guide.

## Legitimate use

NAR is for analyzing your own apps, authorized security research,
compatibility and interoperability work, and learning. It teaches ANALYSIS:
inspect, decompile, map, and compare.

NAR does not teach, and you must not use it for: bypassing or killing
signature verification, unlocking VIP or paid features, granting unlimited
paid currency or items, bypassing DRM, or repackaging someone else's app as
your own. Signature tooling here is verification and analysis only
(`apksigner verify`, certificate fingerprints, scheme inventory). The same
boundary applies to games: analyzing how a game stores progress is fine;
modifying it to grant paid items is not. If a request crosses this line,
decline that part and offer a legitimate alternative (analyze your own build,
or build the feature in your own original app).

## Check tools first

Before any investigation, run the doctor once per session:

```bash
bash scripts/nar-doctor.sh
```

It checks java, apktool, jadx, aapt2, apksigner, zipalign, and python3
(core), plus adb, frida, ghidra, kuna, bundletool, il2cppdumper,
cpp2il, mitmproxy, tshark, godotpcktool, gdre, and hermes-dec
(optional), and three self-checks: the bundled scripts compile
and the protection-signature database loads (both core), and
skill YAML validity (optional, when a YAML parser is present).
Exit 0 means the core toolchain is ready. If a core tool is missing, read
[setup and doctor](references/setup-and-doctor.md) and fix that one tool;
do not repeat the whole setup for every question. `--json` gives
machine-readable output. If tools are already known good in this session,
proceed directly to the target.

Work under a project directory (for example `~/workspace/nar-work/<app>/`),
never in `/tmp` for large outputs: decode and decompile output can be
hundreds of megabytes, and `/tmp` may be a small tmpfs. Keep the original
APK untouched; all work happens on copies and extracted output.

## Route the target first

Choose the first step from the question, not from habit. Start every
investigation with triage unless the question already names a deeper target.

Interpreter note: the table's commands are written as `python3 …`; on
Windows machines where `python3` is the Microsoft Store stub, run them
with `python` or `py -3` instead — see
[setup and doctor](references/setup-and-doctor.md).

| Question | First step | Guide |
|---|---|---|
| What is this APK? Package, version, size, DEX/.so inventory | `python3 scripts/nar-triage.py app.apk` | [triage and inventory](references/triage-and-inventory.md) |
| Give me the full workup in one shot (report file) | `python3 scripts/nar-analyze.py app.apk` (1.x workup + 2.0 stages → case dir with report.md / report.json / report.html + companions incl. correlations.json, graph.json, investigation.json, case.json, execution-log.json; stage results are cached per input hash; `--stage-timeout` / `--total-budget` bound the run; `--no-graph` / `--no-investigation` skip the optional layers) | [triage and inventory](references/triage-and-inventory.md), [evidence workflows](references/evidence-workflows.md), [output schema](references/output-schema.md) |
| Query a case's entity graph / prioritized investigation paths | `python3 scripts/nar.py case graph CASE_DIR` and `python3 scripts/nar.py case investigation CASE_DIR` (JSON views over the case's graph.json / investigation.json; the graph view filters by node kind, edge kind, minimum confidence and free text) | [evidence workflows](references/evidence-workflows.md), [output schema](references/output-schema.md) |
| One command for everything? | `python3 scripts/nar.py <command> …` — unified CLI over every module (`nar analyze`, `nar dex`, `nar security`, …; also `nar tools`, `nar identify`, `nar validate`, `nar benchmark`, `nar case`); each module script also works standalone | [architecture](references/architecture.md) |
| What does NAR support, and where are the coverage gaps? | `python3 scripts/nar.py coverage [--gap] [--json]` (matrix generated from `scripts/formats.json`, the single source of truth for engines/formats; `--gap` lists every non-supported entry with reason + cheapest probe) | [architecture](references/architecture.md) |
| Decompilation when jadx is missing, broken, or only partial | `nar analyze` runs the java-decompile fallback chain (jadx → baksmali → dex2jar+cfr → dex2jar+procyon → the built-in disassembler); every attempt is classified (no free-form failures) and the Fallback Record — chain, attempts, served_by, fidelity, caveats — lands in the case's decompile.json (schema: fallback-chain.schema.json / decompile.schema.json); a lower-fidelity result is never presented as higher | [DEX, smali, and decompile](references/dex-smali-and-decompile.md) |
| Ask a question about an app or game and get an evidence-cited answer | `python3 scripts/nar.py ask "<question>" app.apk [--json] [--case DIR]` (deterministic intent classification, no LLM; always the full Answer Contract — ANSWER / EVIDENCE / CONFIDENCE / WHY / CHAIN / BOUNDARY, plus REASON / PROBE / COST when unknown; case built or reused via nar-analyze) | [question library](references/question-library.md) |
| Rebuild specification from verified evidence (features, architecture, data model, flows, assets, network, build order, unrecoverable) | `python3 scripts/nar.py blueprint app.apk --out spec/ [--case DIR]` (9 files from the case companions; every features.md claim evidence-cited or marked inferred; evidence-free sections render NOT RECOVERABLE; unknowns.json validates against blueprint.schema.json) | [question library](references/question-library.md) |
| Sprite atlases: frames, part grouping, composition classification | `python3 scripts/nar.py atlas app.apk [--json]` (Cocos plist XML+binary, TexturePacker/Phaser/Starling, libGDX, Godot AtlasTexture, Unity SpriteAtlas at GUID-level fidelity; part groups classified vehicle/character/ui/environment, always inferred) | [output schema](references/output-schema.md) |
| Animation systems: what animates, with what driver | `python3 scripts/nar.py anim app.apk [--json]` (Spine, DragonBones, Lottie, Aseprite, Godot AnimationPlayer/Tree, Spriter, Creature decoded; Rive and Spine .skel header-level; Unity clips/controllers textual for loose files; physics-rig detection from native symbols + part naming; composition report with attachment points and drivers) | [output schema](references/output-schema.md) |
| App intelligence: screens, navigation, storage, SDKs, permissions actually used | `python3 scripts/nar.py app app.apk [--json]` (Compose @Composable census, res/layout roots, WebView JS-bridge surface, Activity/Fragment graph + deep-link route map, SharedPreferences candidates, Room/SQLite schemas of shipped databases read from sqlite_master bytes, encrypted-storage detection, OAuth + JWT structure only — values always redacted, WorkManager/JobScheduler/AlarmManager, declared-vs-referenced permissions over-request report, SDK inventory with META-INF .version versions, tracking/ad-ID/consent compliance surface; screen map + data-flow map; also runs as the app.json stage of `nar analyze`) | [output schema](references/output-schema.md) |
| Script & bytecode content: Lua, GDScript, Dart, Hermes, JS bundles, Wasm, .NET CIL, .pyc, AngelScript, Squirrel, Pawn, custom VM | `python3 scripts/nar.py script app.apk [--json]` (structural parsers per format at honest fidelity: Wasm full section parse; Lua chunk walk; GDSC header counts; Hermes header via nar-rn; Dart facts via nar-flutter with class/string counts null; .pyc structural marshal census, never executed; encrypted/custom-VM content named, never decoded) | [output schema](references/output-schema.md) |
| Which of NAR's tools are installed on this machine? | `python3 scripts/nar.py tools [--json]` (registry view with live probes; the doctor stays the readiness gate) | [tool registry](references/tool-registry.md) |
| How fast / how accurate is NAR on the fixture corpus? | `python3 scripts/nar.py benchmark [--out metrics.json]` (measured timings, labeled-corpus accuracy metrics, peak memory; synthetic and real corpora reported separately) | [benchmarks](references/benchmarks.md) |
| Move a case directory / verify its integrity | `python3 scripts/nar.py case export case/ --bundle case.zip`, then `case import case.zip --out dir/` / `case verify dir/` (per-file hash manifest; tampering fails verify; since 2.6.2 verify also enforces evidence integrity — every graph/investigation evidence reference resolves, endpoints exist, no duplicates/orphans, counts reconcile, hypotheses carry basis/confirm/refute — with structured failure reasons) | [output schema](references/output-schema.md) |
| What file is this really? Is extraction safe? | `python3 scripts/nar-input.py identify file` / `extract` / `duplicates` (magic-based identification, zip-slip/bomb-guarded extraction) | [architecture](references/architecture.md) |
| A fingerprint I can diff/track, with provenance | `python3 scripts/nar-fingerprint.py app.apk` (every property carries source tool + confidence) | [output schema](references/output-schema.md) |
| Engine verdict with a confidence score | `python3 scripts/nar-engines.py game.apk [--deep]` (multi-indicator fusion; --deep confirms with the engine's own deep-dive tool) | [triage and inventory](references/triage-and-inventory.md) |
| Deep DEX facts: classes, call edges, reflection, dynamic loading | `python3 scripts/nar-dex.py app.apk` (own DEX parser: try/catch tables, debug-info presence, Kotlin `@Metadata` inventory; `--jadx` / `--baksmali` adapters) | [DEX, smali, and decompile](references/dex-smali-and-decompile.md) |
| Instruction-level bytecode listing for one class/method (jadx failed, obfuscated or protected method) | `python3 scripts/nar-dex.py app.apk --disassemble --disasm-class '<substr>'` (own disassembler; `--disasm-all` for an explicit full decode) | [DEX, smali, and decompile](references/dex-smali-and-decompile.md) |
| Control-flow graph / who calls this method (call graph, cross-references) | `python3 scripts/nar-dex.py app.apk --cfg --disasm-class '<substr>'` (per-method CFG edges under the targeted-selection rules) and `python3 scripts/nar-dex.py app.apk --xref '<method-substr>'` (resolved call-graph callers/callees, cross-DEX resolutions labeled) | [DEX, smali, and decompile](references/dex-smali-and-decompile.md) |
| Deep native facts: dependencies, JNI exports, hardening | `python3 scripts/nar-native.py app.apk` (own ELF parser: dependency graph, relocations, compiler fingerprints; readelf cross-check with `--work`) | [native libs and JNI](references/native-libs-and-jni.md) |
| Which endpoints does it talk to (statically)? | `python3 scripts/nar-network.py app.apk` (classified endpoint inventory, services, network security config; credential/token values redacted at the source, counts reported) | [network traffic](references/network-traffic.md) |
| Security review with severities and fixes | `python3 scripts/nar-security.py app.apk [--deep]` (findings in the NAR-SEC schema: evidence, impact, remediation, verification status) | [output schema](references/output-schema.md), [safety and authorization](references/safety-and-authorization.md) |
| Full asset inventory (types, sizes, duplicates) | `python3 scripts/nar-assets.py app.apk` (audio header metadata for WAV/OGG/MP3; other formats report unmeasured) | [manifest and resources](references/manifest-and-resources.md) |
| Runtime observation on my own device | `python3 scripts/nar-runtime.py status` / `plan app.apk` (adb + Frida adapters, session plans, persisted session records with `--session-out`; jni-trace RegisterNatives events verified live on the emulator, attach + spawn). For device/toolchain validation: `nar-runtime.py validate` (capability statuses detected / verified / unsupported / unavailable / not_tested, actionable diagnostics) and the Frida validation suite in `tests/runtime_validation/` — emulator-verified; physical-device validation is NOT RUN until a device is attached | [dynamic analysis](references/dynamic-analysis.md) |
| What engine is this game? Unity / Unreal / Godot? | Triage engine hints, then confirm markers | [triage](references/triage-and-inventory.md), [native libs and JNI](references/native-libs-and-jni.md) |
| Is this app protected? Which packer / protector? | Triage Protection systems section (named packers, obfuscation, RASP, pinning, DRM, encryption, native hardening; signatures ship as a versioned database, `scripts/protection-signatures.json`) | [triage and inventory](references/triage-and-inventory.md) |
| Permissions, components, intent filters, SDK levels | `apktool d` or `aapt2 dump xmltree` | [manifest and resources](references/manifest-and-resources.md) |
| Strings, layouts, drawables, asset bundles (.pak/.bundle/.obb) | `apktool d` + inventory | [manifest and resources](references/manifest-and-resources.md) |
| Which classes/methods exist? Where is feature X? | Grep jadx output, then read one class | [DEX, smali, and decompile](references/dex-smali-and-decompile.md) |
| How does this method work? | jadx decompile of one class/method | [DEX, smali, and decompile](references/dex-smali-and-decompile.md) |
| What does the native library do? JNI bindings? | `.so` inventory, strings, Ghidra/Kuna | [native libs and JNI](references/native-libs-and-jni.md) |
| Unity IL2CPP game: what is the game logic? | `python3 scripts/nar-il2cpp.py game.apk` (locates the pair, runs Il2CppDumper, summarizes), then Ghidra; Addressables content: `python3 scripts/nar-unity.py` parses catalog.json into a location inventory | [Unity IL2CPP](references/unity-il2cpp.md) |
| Godot game: what is in the `.pck` and the scripts? | `python3 scripts/nar-godot.py game.apk` (pack listing + encryption flag, per-entry resource-type classification), GodotPckTool extract, GDRE Tools decompile | [native libs and JNI](references/native-libs-and-jni.md) |
| Unreal game: what is inside the `.pak` packs? | Extract the `.pak`, then `python3 scripts/nar-pak.py game.pak` (list, or `--extract` entries) | [native libs and JNI](references/native-libs-and-jni.md) |
| Unreal game: what is inside a `.uasset` / `.umap` package? | `python3 scripts/nar-unreal.py asset.uasset` (summary + name/import/export tables, resolved references, best-effort property tags; the report carries `limits` + generated `capabilities`, and `--max-packages` / `--max-containers` / `--max-chunks` / `--max-names` / `--all-packages` / `--all-containers` / `--all-details` lift the detail caps with total/processed/skipped/failed accounting), or the APK / `.utoc` / `.pak` holding it | [native libs and JNI](references/native-libs-and-jni.md) |
| React Native app: what is in the JS bundle? | `python3 scripts/nar-rn.py app.apk` (Hermes vs JSC, bytecode version, counts, source-map detection, native-module inventory), then hermes-dec decompile | [React Native](references/react-native.md) |
| Flutter/Dart app: what is in `libapp.so`? | `python3 scripts/nar-flutter.py app.apk` (Dart/Flutter versions, AOT markers, flutter_assets inventory), then Dart AOT strings and symbols | [Flutter and Dart](references/flutter-dart.md) |
| What does it do on the network? | mitmproxy capture, tshark pcap reading | [network traffic](references/network-traffic.md) |
| What does it do at runtime? (Frida scripts) | `scripts/frida/*.js` on a rooted device or emulator | [Frida scripts](references/frida-scripts.md) |
| Interesting strings, URLs, endpoints | `python3 scripts/nar-strings.py app.apk` | [nar-strings.py](scripts/nar-strings.py) |
| Permissions, components, intent filters | `python3 scripts/nar-perms.py app.apk` | [manifest and resources](references/manifest-and-resources.md) |
| What changed between v1 and v2? | `python3 scripts/nar-compare.py old.apk new.apk [--out DIR]` (`--out` also writes feature-map.json + version-diff.md beside comparison.json) | [version compare and feature map](references/version-compare-and-feature-map.md) |
| Legacy app: Android 4.x-7, ODEX, v1 signing, ARMv7 | DEX version, signing schemes, legacy markers | [legacy analysis](references/legacy-analysis.md) |
| Modern app: Android 14/15/16, 16KB pages, Compose, Rust | ELF alignment, DEX markers, Play Integrity | [modern analysis](references/modern-analysis.md) |
| Is it signed? Which schemes? Whose certificate? How do I sign my own build? | `apksigner verify --verbose --print-certs`; own-build workflow (align → sign → verify, rotation, continuity) in the same guide | [signatures and integrity](references/signatures-and-integrity.md) |
| What does it do at runtime? | adb/logcat, Frida on an authorized device | [dynamic analysis](references/dynamic-analysis.md) |
| Split APKs / APKS / AAB / OBB set | Triage every file in the set together | [triage and inventory](references/triage-and-inventory.md), [app bundles](references/app-bundles.md) |
| How do I open this file at all? (unpack chain) | Work outermost-first: delivery container → APK → asset containers → staged DEX | [triage and inventory](references/triage-and-inventory.md) (Unpacking section) |
| System app from `/system` or `/system/priv-app`? | `adb pull`, then triage + `nar-perms.py` (sharedUserId, platform signature) | [triage and inventory](references/triage-and-inventory.md) |
| What data does it store on the device? | `run-as` pull, sqlite3 read-only, shared_prefs XML | [dynamic analysis](references/dynamic-analysis.md) |

Split sets under `nar analyze`: the target is resolved before any
stage runs, and splits are merged by default in every hand-over
shape — a container (`.apks` / `.xapk` / `.apkm` / `.zip`)
contributes its contained splits; a lone base APK discovers its
sibling splits in the same directory (membership is proven, never
assumed: a sibling's manifest package must match the base's, and
it must declare itself a split, carry a split-shaped name, or the
base must carry bundle split evidence); a directory target is
taken as the set itself, with the base picked by the shared rule.
Opt out with `--no-merge-splits` or `NAR_NO_MERGE_SPLITS=1`. When
a set is detected but not fully merged, the report's limitations
say so — "split set incomplete — native layer may be
under-reported … engine and native verdicts cover the base APK
only" — and the case record's `split_set` block lists what was
merged and what was skipped, with reasons. The fingerprint and
decompile stages always run on the base APK, merged or not.

If the user says only "my app" without a name, path, or target already
selected for this task, ask which app before searching for artifacts. Paths
in unrelated saved reports do not select the user's target. Never choose an
example app on the user's behalf.

## Work summary-first

Start with the smallest useful overview, then drill into exactly what the
question needs. Triage first, then one focused decode or decompile, then
one method or resource at a time. Do not dump a whole jadx output into the
conversation: search it, read the relevant class, and cite it.

Every conclusion must distinguish observations, inferences, and unknowns.
Cite evidence precisely: `classes.dex` offsets, `class:method` names,
`AndroidManifest.xml` entries, file paths with SHA-256 digests. Preserve
limitations and incomplete coverage. Never imply that static analysis
observed execution: manifest entries and decompiled text are static
observations, not runtime behavior. Reflection, dynamic loading, and
obfuscated calls remain unknown unless runtime evidence proves them.

Do not repeat an identical analysis or a rejected command without a changed
input or a resolved blocker. Reuse existing decode/decompile output when
the APK digest matches; re-decode only when the file changed.

## Plan broader investigations

For requests that span multiple features or subsystems, use a staged
workflow:

1. Turn the request into a checklist of questions and the evidence each
   answer needs. Resolve target identity and constraints from the
   conversation and workspace before asking for information again.
2. Inspect existing state: prior triage output, decoded trees, jadx output,
   saved reports. Reuse matching state; do not open duplicate work or
   repeat identical analysis.
3. Start with the smallest useful overview or inventory. Follow each
   question from its entry point through relevant data and state changes
   to its result. Batch related operations around a specific hypothesis,
   then expand only when the returned evidence leaves a concrete gap.
4. Inspect packaged resources and configuration alongside code when they
   affect the question. Use format-aware inventory and parsers; do not
   infer behavior from filenames, strings, or layout alone.
5. Corroborate a conclusion with the evidence type it requires. Use
   runtime observation only when static evidence cannot answer the
   question and an authorized device or emulator is available.
6. Decompose work into independent questions. When parallel workers are
   available and the questions do not depend on one another, assign
   distinct scopes, point workers to existing evidence, and ask them to
   return sources, conclusions, and unresolved gaps. Otherwise, work
   sequentially.
7. Keep a concise finding ledger linking each conclusion to evidence,
   confidence, search boundary, and remaining unknowns. Update the shared
   report so later passes can reuse results.

Before finishing, revisit the original checklist. Mark each question as
answered, partially answered, or unresolved based on its evidence; keep
bounded negative searches bounded, and do not describe a broad
investigation as complete while required questions remain open.

## Read only the relevant guide

- Installing engines, environment variables, doctor failures:
  [references/setup-and-doctor.md](references/setup-and-doctor.md)
- First-5-minutes triage, inventory, engines, splits, AAB, OBB:
  [references/triage-and-inventory.md](references/triage-and-inventory.md)
- Manifest, permissions, components, resources.arsc, strings, assets:
  [references/manifest-and-resources.md](references/manifest-and-resources.md)
- DEX structure, smali, jadx decompile, obfuscation, callers:
  [references/dex-smali-and-decompile.md](references/dex-smali-and-decompile.md)
- Native libraries, JNI, Unity/Unreal/Godot, Ghidra/Kuna:
  [references/native-libs-and-jni.md](references/native-libs-and-jni.md)
- Unity IL2CPP deep analysis, Il2CppDumper, Ghidra method mapping:
  [references/unity-il2cpp.md](references/unity-il2cpp.md)
- Flutter/Dart: libapp.so, AOT snapshots, strings and symbols:
  [references/flutter-dart.md](references/flutter-dart.md)
- React Native: Hermes bytecode bundle, hermes-dec parse/disassemble/decompile:
  [references/react-native.md](references/react-native.md)
- App bundles, split APKs, XAPK/APKM, bundletool build-apks:
  [references/app-bundles.md](references/app-bundles.md)
- Network traffic: mitmproxy capture, tshark pcap reading:
  [references/network-traffic.md](references/network-traffic.md)
- Frida script library: Java/JNI/file/network observation scripts:
  [references/frida-scripts.md](references/frida-scripts.md)
- Legacy analysis: ODEX/OAT, old DEX, v1/v2 signing, ARMv7, old engines:
  [references/legacy-analysis.md](references/legacy-analysis.md)
- Modern analysis: Android 14/15/16, 16KB pages, Compose, Rust, Play Integrity:
  [references/modern-analysis.md](references/modern-analysis.md)
- v1/v2/v3/v3.1 signatures, certificates, zipalign:
  [references/signatures-and-integrity.md](references/signatures-and-integrity.md)
- Diffing versions, building a feature map, reconstruction rules:
  [references/version-compare-and-feature-map.md](references/version-compare-and-feature-map.md)
- adb, logcat, Frida, runtime vs static:
  [references/dynamic-analysis.md](references/dynamic-analysis.md)
- Evidence ledger, report template, confidence levels:
  [references/evidence-workflows.md](references/evidence-workflows.md)

Helper scripts (run with `--help`): `scripts/nar.py` (unified CLI
over all modules), `scripts/nar-analyze.py`
(one-command full workup → case dir: report.md + report.json +
report.html + companions + case.json + execution-log.json),
`scripts/nar-triage.py` (first-5-minutes triage),
`scripts/nar-strings.py` (ranked strings), `scripts/nar-compare.py`
(two-version diff, extended in 2.0 with class/endpoint/asset
diffs, severity, similarity), `scripts/nar-perms.py` (permission and component
audit), `scripts/nar-pak.py` (Unreal .pak lister/extractor),
`scripts/nar-il2cpp.py` (Unity IL2CPP locator + dumper summary),
`scripts/nar-flutter.py` (Flutter/Dart fingerprint),
`scripts/nar-godot.py` (Godot .pck inspector), `scripts/nar-rn.py`
(React Native bundle inspector), the engine deep-dive modules
(`scripts/nar-cocos.py`, `scripts/nar-libgdx.py`,
`scripts/nar-defold.py`, `scripts/nar-gamemaker.py`,
`scripts/nar-renpy.py`, `scripts/nar-solar2d.py`,
`scripts/nar-heaps.py`, `scripts/nar-qt.py`,
`scripts/nar-cordova.py`, `scripts/nar-capacitor.py`,
`scripts/nar-air.py`, `scripts/nar-love.py`,
`scripts/nar-rpgmaker.py`, `scripts/nar-webassets.py`,
`scripts/nar-xamarin.py`, `scripts/nar-monogame.py`,
`scripts/nar-mono.py`, `scripts/nar-python.py`,
`scripts/nar-sdl.py`, `scripts/nar-ebiten.py`,
`scripts/nar-bevy.py` — each run by `nar-engines.py`
in its deep mode), `scripts/nar-tools.py`
(registry view behind `nar tools`), the 2.0 modules
`scripts/nar-input.py` (format identification + safe extraction),
`scripts/nar-fingerprint.py`, `scripts/nar-engines.py`,
`scripts/nar-unity.py` (incl. Addressables catalog inventory),
`scripts/nar-unreal.py`,
`scripts/nar-dex.py`, `scripts/nar-native.py`,
`scripts/nar-network.py`, `scripts/nar-security.py`,
`scripts/nar-assets.py`, `scripts/nar-runtime.py`,
`scripts/nar-report.py`, the shared library in `scripts/narlib/`,
the capability registry in `scripts/registry.json`, the output
schemas in `schemas/`, and the Frida observation scripts
in `scripts/frida/` (see the Frida guide). Architecture:
[references/architecture.md](references/architecture.md);
tool registry: [references/tool-registry.md](references/tool-registry.md);
troubleshooting: [references/troubleshooting.md](references/troubleshooting.md).

## Finish the task

Explain findings in plain language and tie them to evidence. End every
investigation with a short report:

- Identity: file name, SHA-256, package, version, SDK levels, size.
- Findings: each with its evidence cite (file, class:method, or offset).
- Limitations and unknowns: what was not checked, what static analysis
  cannot prove, where coverage is partial.
- Next steps: the concrete follow-up (a deeper guide, a runtime check, or
  a rebuild decision).

See [evidence workflows](references/evidence-workflows.md) for the full
report template and a filled example in
[examples/sample-report.md](examples/sample-report.md). When the user asks
to build something from the findings, use normal coding tools, write
original code, and separate observed behavior from design choices. Never
copy decompiled code verbatim into a shipping product.

