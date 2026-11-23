# NAR Skill: Nirous Android Reversing

Version 1.0.1

Research by Bakr Fayez

NAR is an AI agent skill for Android APK reverse engineering. It covers all Android apps and games, old and new: regular apps, Unity, Unreal, Godot, and Flutter games and apps, native-heavy apps, and legacy builds back to Android 4.x. It works with CLI tools you already know: apktool, jadx, aapt2, apksigner, Ghidra, Kuna, Il2CppDumper, mitmproxy, and bundletool. No MCP server required.

Clone this repo and you have a working skill. Drop it into your agent's skills folder and start triaging APKs.

## NAR vs REA

REA (reverse-engineer-anything) covers everything: native binaries, Electron apps, firmware, browsers, and more. NAR covers one thing in depth: Android APKs. If your target is an APK, an AAB, a split APK set, or an OBB file, NAR goes deeper than REA on that target. If your target is anything else, use REA.

## What it does

- Triage any APK, AAB, split set, or OBB in under a minute: identity, hashes, DEX versions and method counts, native inventory, permissions, signature schemes, game-engine and framework detection (Unity, Unreal, Godot, Flutter, Cocos2d-x, libGDX, React Native, Compose, Rust).
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
- Cover old and new Android: legacy Dalvik/ODEX/OAT, ARMv7, Eclipse-era builds, and Android 14/15 with 16KB page size, Kotlin Multiplatform, Jetpack Compose, Rust NDK, Play Integrity, and R8 full mode.
- Handle system apps and app data: platform signatures, sharedUserId, priv-app permissions, and on-device data extraction (SQLite databases, shared_prefs).

## Quick start

```bash
git clone https://github.com/BakrFayez/nar-skill.git
cd nar-skill
bash scripts/nar-doctor.sh
python3 scripts/nar-triage.py app.apk
```

`nar-doctor.sh` checks your toolchain and tells you what is missing. `nar-triage.py` gives you the first five minutes on any APK: SHA-256, package, version, DEX versions, native libs, signature schemes, engine hints. `nar-strings.py`, `nar-compare.py`, and `nar-perms.py` cover strings, version diffs, and permission audits.

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
    nar-triage.py           First-5-minutes APK triage (plain and --json)
    nar-strings.py          Ranked string extraction (plain and --json)
    nar-compare.py          Two-version diff (plain and --json)
    nar-perms.py            Permission and component audit (plain and --json)
    frida/                  Frida observation scripts (Java, JNI, file, network)
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
- [Kuna](https://github.com/ScepticCute/kuna)
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
