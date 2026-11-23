---
name: nar
description: Reverse engineer any Android APK or AAB (apps and games) with CLI tools: triage and inventory, manifest and resources, DEX/smali analysis, jadx decompilation, native libraries and JNI, game engines (Unity/Unreal/Godot), Unity IL2CPP deep analysis, Flutter/Dart, app bundles, network traffic, Frida scripts, signatures, version comparison, feature maps, and legacy (Android 4.x-7) and modern (Android 14/15) analysis.
metadata:
  version: "1.0.3"
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
mitmproxy, tshark, godotpcktool, gdre, and hermes-dec (optional).
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

| Question | First step | Guide |
|---|---|---|
| What is this APK? Package, version, size, DEX/.so inventory | `python3 scripts/nar-triage.py app.apk` | [triage and inventory](references/triage-and-inventory.md) |
| What engine is this game? Unity / Unreal / Godot? | Triage engine hints, then confirm markers | [triage](references/triage-and-inventory.md), [native libs and JNI](references/native-libs-and-jni.md) |
| Permissions, components, intent filters, SDK levels | `apktool d` or `aapt2 dump xmltree` | [manifest and resources](references/manifest-and-resources.md) |
| Strings, layouts, drawables, asset bundles (.pak/.bundle/.obb) | `apktool d` + inventory | [manifest and resources](references/manifest-and-resources.md) |
| Which classes/methods exist? Where is feature X? | Grep jadx output, then read one class | [DEX, smali, and decompile](references/dex-smali-and-decompile.md) |
| How does this method work? | jadx decompile of one class/method | [DEX, smali, and decompile](references/dex-smali-and-decompile.md) |
| What does the native library do? JNI bindings? | `.so` inventory, strings, Ghidra/Kuna | [native libs and JNI](references/native-libs-and-jni.md) |
| Unity IL2CPP game: what is the game logic? | Il2CppDumper on `global-metadata.dat` + `libil2cpp.so`, then Ghidra | [Unity IL2CPP](references/unity-il2cpp.md) |
| Godot game: what is in the `.pck` and the scripts? | GodotPckTool list/extract, GDRE Tools decompile | [native libs and JNI](references/native-libs-and-jni.md) |
| Unreal game: what is inside the `.pak` packs? | Extract the `.pak`, then `python3 scripts/nar-pak.py game.pak` | [native libs and JNI](references/native-libs-and-jni.md) |
| React Native app: what is in the JS bundle? | Extract `index.android.bundle`, hermes-dec parse/decompile | [React Native](references/react-native.md) |
| Flutter/Dart app: what is in `libapp.so`? | Dart AOT strings and symbols, version detection | [Flutter and Dart](references/flutter-dart.md) |
| What does it do on the network? | mitmproxy capture, tshark pcap reading | [network traffic](references/network-traffic.md) |
| What does it do at runtime? (Frida scripts) | `scripts/frida/*.js` on a rooted device or emulator | [Frida scripts](references/frida-scripts.md) |
| Interesting strings, URLs, endpoints | `python3 scripts/nar-strings.py app.apk` | [nar-strings.py](scripts/nar-strings.py) |
| Permissions, components, intent filters | `python3 scripts/nar-perms.py app.apk` | [manifest and resources](references/manifest-and-resources.md) |
| What changed between v1 and v2? | `python3 scripts/nar-compare.py old.apk new.apk` | [version compare and feature map](references/version-compare-and-feature-map.md) |
| Legacy app: Android 4.x-7, ODEX, v1 signing, ARMv7 | DEX version, signing schemes, legacy markers | [legacy analysis](references/legacy-analysis.md) |
| Modern app: Android 14/15, 16KB pages, Compose, Rust | ELF alignment, DEX markers, Play Integrity | [modern analysis](references/modern-analysis.md) |
| Is it signed? Which schemes? Whose certificate? | `apksigner verify --verbose --print-certs` | [signatures and integrity](references/signatures-and-integrity.md) |
| What does it do at runtime? | adb/logcat, Frida on an authorized device | [dynamic analysis](references/dynamic-analysis.md) |
| Split APKs / APKS / AAB / OBB set | Triage every file in the set together | [triage and inventory](references/triage-and-inventory.md), [app bundles](references/app-bundles.md) |
| System app from `/system` or `/system/priv-app`? | `adb pull`, then triage + `nar-perms.py` (sharedUserId, platform signature) | [triage and inventory](references/triage-and-inventory.md) |
| What data does it store on the device? | `run-as` pull, sqlite3 read-only, shared_prefs XML | [dynamic analysis](references/dynamic-analysis.md) |

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
- Modern analysis: Android 14/15, 16KB pages, Compose, Rust, Play Integrity:
  [references/modern-analysis.md](references/modern-analysis.md)
- v1/v2/v3/v3.1 signatures, certificates, zipalign:
  [references/signatures-and-integrity.md](references/signatures-and-integrity.md)
- Diffing versions, building a feature map, reconstruction rules:
  [references/version-compare-and-feature-map.md](references/version-compare-and-feature-map.md)
- adb, logcat, Frida, runtime vs static:
  [references/dynamic-analysis.md](references/dynamic-analysis.md)
- Evidence ledger, report template, confidence levels:
  [references/evidence-workflows.md](references/evidence-workflows.md)

Helper scripts (run with `--help`): `scripts/nar-strings.py` (ranked
strings), `scripts/nar-compare.py` (two-version diff),
`scripts/nar-perms.py` (permission and component audit),
`scripts/nar-pak.py` (Unreal .pak lister), and the Frida
observation scripts in `scripts/frida/` (see the Frida guide).

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

---

Research by Bakr Fayez.
