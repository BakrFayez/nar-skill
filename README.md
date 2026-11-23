# NAR Skill: Nirous Android Reversing

# NAR 2.0 — NIROUS ANDROID INTELLIGENCE

**Understand Every Layer. Follow Every Evidence.**

Version 2.3.0

Research by Bakr Fayez

NAR is an AI agent skill for Android APK reverse engineering. It covers all Android apps and games, old and new: regular apps, Unity, Unreal, Godot, and Flutter games and apps, native-heavy apps, and legacy builds back to Android 4.x. It works with CLI tools you already know: apktool, jadx, aapt2, apksigner, Ghidra, Kuna, Il2CppDumper, mitmproxy, and bundletool. No MCP server required.

Clone this repo and you have a working skill. Drop it into your agent's skills folder and start triaging APKs.

## NAR vs REA

REA (reverse-engineer-anything) covers everything: native binaries, Electron apps, firmware, browsers, and more. NAR covers one thing in depth: Android APKs. If your target is an APK, an AAB, a split APK set, or an OBB file, NAR goes deeper than REA on that target. If your target is anything else, use REA.

## What it does

- Triage any APK, AAB, split set, or OBB in under a minute: identity, hashes, DEX versions and method counts, native inventory, permissions, signature schemes, form factors (Wear OS, Android TV), game-engine and framework detection (Unity, Unreal, Godot, Flutter, Cocos2d-x, libGDX, React Native, Compose, Rust, Xamarin / .NET, Cordova, Capacitor, Qt, Defold, Ren'Py, RPG Maker, Kivy / embedded Python).
- Detect protection systems and report them by category: named commercial packers and VM protectors (Pairip, Tencent Legu, 360 Jiagu, Bangcle SecShell, Alibaba SecurityGuard, Baidu Protect, NetEase YiDun, iJiami, DexProtector, LIAPP, AppSealing), obfuscation evidence, anti-tamper / RASP markers, SSL pinning, licensing and DRM, code and asset encryption, and native hardening posture from ELF headers. Detection and reporting only.
- Decode manifests and resources with apktool and aapt2, including `resources.arsc` structure and string pools.
- Read DEX and smali, and decompile with jadx, including obfuscated builds.
- Map native libraries and JNI bindings, static and dynamic.
- Identify game engines: Unity IL2CPP and Mono, Unreal, Godot, Cocos2d-x, libGDX, Adobe AIR. Deep IL2CPP analysis with Il2CppDumper and Ghidra method mapping. Deep Godot analysis with GodotPckTool pack extraction and GDRE Tools script decompile.
- Analyze Flutter/Dart apps: `libapp.so`, AOT snapshots, strings and symbol recovery.
- Analyze React Native apps: Hermes bytecode bundle parsing, disassembly, and decompilation with hermes-dec.
- Verify signatures: v1, v2, v3, v3.1, v4 inventory, certificate fingerprints, key rotation, fs-verity. Analysis only.
- Diff two versions and build a feature map: feature, evidence, confidence.
- Analyze app bundles and split APKs with bundletool, including XAPK/APKM containers and Play Asset Delivery.
- Capture and read network traffic with mitmproxy and tshark, on your own devices only.
- Run dynamic analysis with adb and Frida on a device you own, with a ready script library for Java, JNI, file, and network observation.
- Cover old and new Android: legacy Dalvik/ODEX/OAT, ARMv7, Eclipse-era builds, and Android 14/15/16 with 16KB page size, Kotlin Multiplatform, Jetpack Compose, Rust NDK, Play Integrity, and R8 full mode.
- Handle system apps and app data: platform signatures, sharedUserId, priv-app permissions, and on-device data extraction (SQLite databases, shared_prefs).

## Quick start

```bash
git clone https://github.com/BakrFayez/nar-skill.git
cd nar-skill
bash scripts/nar-doctor.sh
python3 scripts/nar-triage.py app.apk
```

One command for the full 2.0 workup (case directory with
report.md + report.json + offline report.html, companion
evidence files, execution log, and a resumable stage cache):

```bash
python3 scripts/nar.py analyze app.apk --out case/
```

Every module also runs through the unified CLI
(`python3 scripts/nar.py dex|native|network|security|engines …`)
or standalone, exactly as in 1.x.

## What's new in 2.0

- **Universal input layer**: magic + structure identification
  for every container NAR meets, and guarded extraction
  (zip-slip, symlink, and archive-bomb entries rejected and
  reported).
- **Fingerprint with provenance**: every identity property
  carries the tool that produced it, a confidence, and a
  fact class (observed / derived / inferred).
- **Engine verdicts with confidence**: multi-indicator fusion
  across 18 engine/framework families, with optional deep-dive
  confirmation (`nar-engines.py --deep`), plus dedicated
  Unity (`nar-unity.py`, optional UnityPy census) and Unreal
  (`nar-unreal.py`, IoStore entry-level parsing and
  UAsset-level package inspection) deep dives.
- **DEX and native intelligence**: a built-in DEX parser
  (classes, methods, fields, call edges, reflection and
  dynamic-loading evidence, Kotlin inventory, jadx/baksmali
  adapters) and a built-in ELF parser (dependencies, JNI
  exports, hardening, dependency graph, readelf cross-check).
- **Static network intelligence**: classified endpoint
  inventory (confirmed / potential / third-party /
  unused-candidate / sensitive / unverified), backend
  services, and network-security-config parsing.
- **Structured security findings**: the NAR-SEC schema —
  severity, confidence, evidence, impact, remediation, and
  false-positive notes for every finding.
- **Asset inventory**: types, categories, image dimensions,
  duplicate detection, engine-container cross-reference.
- **Orchestrated cases**: `nar-analyze` is now a case
  workspace (case.json, execution-log.json, stage caching
  and resume) with standardized companion documents
  (schemas in `schemas/`) and a single-file offline HTML
  dashboard (dark/light, filterable, zero external requests).
- **Runtime subsystem**: adb/Frida adapters, session plans,
  and a timeline schema — device paths verified live on an
  emulator (API 26, QEMU TCG) on 2026-11-23: adb, install/
  launch, and Frida observation in both attach mode and
  spawn mode (hybrid resume-first recipe; see
  references/frida-scripts.md) all ran against a real
  target; a physical device is still unverified.
- **Capability registry**: every orchestrated tool declared
  in `scripts/registry.json` with availability probing and
  honest limitations; unavailable tools are registered as
  unavailable, never faked.

`nar-doctor.sh` checks your toolchain and tells you what is missing. `nar-triage.py` gives you the first five minutes on any APK: SHA-256, package, version, DEX versions, native libs, signature schemes, engine hints. `nar-analyze.py` runs the whole static workup in one command and writes a single evidence report (`report.md` + `report.json`). `nar-strings.py`, `nar-compare.py`, and `nar-perms.py` cover strings, version diffs, and permission audits. `nar-pak.py` lists and extracts Unreal `.pak` archives. `nar-il2cpp.py` (Il2CppDumper by default, Cpp2IL as an optional second backend), `nar-flutter.py`, `nar-godot.py`, and `nar-rn.py` handle the Unity IL2CPP, Flutter/Dart, Godot, and React Native deep dives.

Then open `SKILL.md` and follow the routing table for your question.

## Install for your agent

NAR is a plain skill directory. The repo root is the skill. Install it where your agent reads skills from.

Claude Code:

```bash
cp -r nar-skill ~/.claude/skills/nar
```

Codex:

```bash
cp -r nar-skill ~/.codex/skills/nar
```

Cursor:

```bash
cp -r nar-skill ~/.cursor/skills/nar
```

Muse:

```bash
cp -r nar-skill ~/workspace/custom-skills/nar
```

Claude Code plugin users: the repo ships `.claude-plugin/plugin.json`, so you can also install it as a plugin from the repo path.

Manual CLI use (no agent): the scripts work on their own. `nar-doctor.sh` and `nar-triage.py` need nothing but bash and Python 3. The guides in `references/` are plain Markdown. Read them directly.

## Tools

| Tool | Version | Needed for |
|---|---|---|
| Java (full JDK) | 17 or newer | apktool, jadx |
| apktool | 2.7.0 or newer | Manifest, resources, smali |
| jadx | 1.5.x CLI or a jadx jar | Decompilation |
| aapt2, apksigner, zipalign | Android SDK build-tools 34 or newer | Badging, signatures, alignment |
| Python | 3.9 or newer | `nar-triage.py` |
| adb | SDK platform-tools | Dynamic analysis (optional) |
| Frida | Matching client and server versions | Runtime hooks (optional) |
| Ghidra | 12.2 or newer | Deep native analysis (optional) |
| Kuna | 1.833 or newer | Fast native decompile (optional) |
| bundletool | 1.18.x | AAB inspection, APK generation (optional) |
| Il2CppDumper | 6.7.x | Unity IL2CPP metadata dumps (optional) |
| mitmproxy | 12.x | Network capture (optional) |
| tshark | 4.x | pcap reading (optional) |
| GodotPckTool | 2.3.x | Godot `.pck` list/extract (optional) |
| GDRE Tools | 2.7.x | Godot project recovery, GDScript decompile (optional) |
| hermes-dec | 0.1.8 | Hermes bytecode tools (optional) |

See `references/setup-and-doctor.md` for install steps and environment variables.

## Usage examples

Triage an APK:

```bash
python3 scripts/nar-triage.py example.apk
```

Decode the manifest and resources:

```bash
apktool d app.apk -o work/apktool
```

Decompile the code:

```bash
jadx -d work/jadx app.apk
```

Check the signature:

```bash
apksigner verify --verbose --print-certs app.apk
```

Compare two versions:

```bash
python3 scripts/nar-compare.py old.apk new.apk
```

Rank the interesting strings:

```bash
python3 scripts/nar-strings.py app.apk
```

Audit permissions and components:

```bash
python3 scripts/nar-perms.py app.apk
```

List an Unreal `.pak` (extract it from the APK or OBB first), or extract entries from an unencrypted one:

```bash
python3 scripts/nar-pak.py game.pak
python3 scripts/nar-pak.py --extract "Content/*" --out work/pak-out game.pak
```

Run the full workup and write one evidence report:

```bash
python3 scripts/nar-analyze.py app.apk
```

Deep-dive a game engine build:

```bash
python3 scripts/nar-il2cpp.py game.apk     # Unity IL2CPP: locate pair, dump, summarize
python3 scripts/nar-flutter.py app.apk     # Flutter/Dart fingerprint
python3 scripts/nar-godot.py game.apk      # Godot pack listing + encryption flag
python3 scripts/nar-rn.py app.apk          # React Native bundle (Hermes vs JSC)
```

A full example session is in `examples/quick-triage.md`. A filled report is in `examples/sample-report.md`. A Unity IL2CPP session is in `examples/unity-il2cpp-triage.md`. A Godot session is in `examples/godot-triage.md`.

## Repo structure

```text
nar-skill/
  SKILL.md                  Main skill: routing, method, report format
  skill.yaml                Skill metadata
  README.md                 This file
  CHANGELOG.md              Release history
  LICENSE                   MIT
  CONTRIBUTING.md           How to contribute
  .gitignore                Keeps APKs and decoded output out of git
  references/               One guide per topic (17 guides)
    setup-and-doctor.md
    triage-and-inventory.md
    manifest-and-resources.md
    dex-smali-and-decompile.md
    native-libs-and-jni.md
    unity-il2cpp.md
    flutter-dart.md
    react-native.md
    app-bundles.md
    network-traffic.md
    frida-scripts.md
    legacy-analysis.md
    modern-analysis.md
    signatures-and-integrity.md
    version-compare-and-feature-map.md
    dynamic-analysis.md
    evidence-workflows.md
  scripts/
    nar-doctor.sh           Toolchain check (plain and --json)
    nar-analyze.py          One-command full workup (report.md + report.json)
    nar-triage.py           First-5-minutes APK triage (plain and --json)
    nar-strings.py          Ranked string extraction (plain and --json)
    nar-compare.py          Two-version diff (plain and --json)
    nar-perms.py            Permission and component audit (plain and --json)
    nar-pak.py              Unreal .pak lister/extractor, pak format v1-7 + v10/v11 encoded index (plain and --json)
    nar-il2cpp.py           Unity IL2CPP locator + Il2CppDumper summary (plain and --json)
    nar-flutter.py          Flutter/Dart fingerprint (plain and --json)
    nar-godot.py            Godot .pck inspector (plain and --json)
    nar-rn.py               React Native bundle inspector (plain and --json)
    frida/                  Frida observation scripts (Java, JNI, file, network)
  tests/
    run_e2e.sh              End-to-end script test harness (fixtures via $NAR_FIXTURES)
  examples/
    sample-report.md        Filled report from a real triage run
    quick-triage.md         Example command session
    unity-il2cpp-triage.md  Unity IL2CPP worked example
    godot-triage.md         Godot 4 worked example
  .claude-plugin/
    plugin.json             Claude Code plugin manifest
```

## Legitimate use

NAR is for analyzing your own apps, authorized security research, compatibility and interoperability work, and learning. It teaches analysis: inspect, decompile, map, and compare.

NAR does not teach, and you must not use it for: bypassing or killing signature verification, unlocking VIP or paid features, granting unlimited paid currency or items, bypassing DRM, or repackaging someone else's app as your own. Signature tooling here is verification and analysis only. The same boundary applies to games.

## Credits

NAR stands on open source tools built by others:

- [apktool](https://apktool.org/) by Connor Tumbleson and Ryszard Wiśniewski
- [jadx](https://github.com/skylot/jadx) by skylot
- [Ghidra](https://ghidra-sre.org/) by the NSA
- [Kuna](https://github.com/Noelo-Lab/kuna)
- [Android SDK](https://developer.android.com/tools) by Google (aapt2, apksigner, zipalign, adb, bundletool)
- [Frida](https://frida.re/)
- [Il2CppDumper](https://github.com/Perfare/Il2CppDumper) by Perfare
- [mitmproxy](https://mitmproxy.org/)
- [Wireshark / tshark](https://www.wireshark.org/)
- [GodotPckTool](https://github.com/hhyyrylainen/GodotPckTool) by hhyyrylainen
- [GDRE Tools](https://github.com/GDRETools/gdsdecomp) by GDRETools
- [hermes-dec](https://github.com/P1sec/hermes-dec) by P1sec
- [REA](https://github.com/morluto/rea) by morluto, whose skill structure NAR follows

## Author

Bakr Fayez

NAR Skill is MIT licensed. See LICENSE.
