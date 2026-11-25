# NAR — NIROUS ANDROID INTELLIGENCE

**Understand Every Layer. Follow Every Evidence.**

[![CI](https://github.com/BakrFayez/nar-skill/actions/workflows/ci.yml/badge.svg)](https://github.com/BakrFayez/nar-skill/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An AI agent skill for Android APK reverse engineering — all apps and games, old and new.

Version 3.0.1

NAR covers regular apps, Unity, Unreal, Godot, and Flutter games and apps, native-heavy apps, and legacy builds back to Android 4.x. It works with CLI tools you already know: apktool, jadx, aapt2, apksigner, Ghidra, Kuna, Il2CppDumper, mitmproxy, and bundletool. No MCP server required.

Clone this repo and you have a working skill. Drop it into your agent's skills folder and start triaging APKs.

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

Then open `SKILL.md` and follow the routing table for your question.

## Latest release

**3.0.1** — patch release: the Windows platform fixes proven by hosted CI (Git Bash discovery instead of the WSL stub, raw hostile archive names in extraction reports, a working Windows memory-budget source, executable probing), with the full CI matrix green on Linux, macOS and Windows. No new features. Full record: [CHANGELOG.md](CHANGELOG.md) (3.0.1 section).

Version history lives in [CHANGELOG.md](CHANGELOG.md); binaries and notes for published releases are on the [releases page](https://github.com/BakrFayez/nar-skill/releases).

## Example prompts

Copy one, replace the file name with your own APK, and send it to your agent:

**Full analysis**

```
Use the NAR skill to run a full analysis on this APK: app.apk — build the complete case with report, graph, and investigation, and summarize the verified facts only.
```

**Security & permissions audit**

```
Use NAR to audit this APK: permissions, exported components, network endpoints and their classification, protection systems, and security findings — every finding with its evidence and verification status.
```

**Rebuild blueprint**

```
Use the NAR skill to fully reverse-engineer app.apk, then turn the analysis into a rebuild blueprint I can implement from: feature map, architecture, data flows, and an implementation order — from verified evidence only, with anything unverifiable marked UNVERIFIED.
```

The full set — engine identification, version comparison, deep game analysis, pre-install triage, case verification, and the complete rebuild-blueprint prompt — is in `references/example-prompts.md`.

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
| Python | 3.10 or newer (pyproject floor; the doctor enforces it) | `nar-triage.py` |
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

## NAR vs REA

REA (reverse-engineer-anything) covers everything: native binaries, Electron apps, firmware, browsers, and more. NAR covers one thing in depth: Android APKs. If your target is an APK, an AAB, a split APK set, or an OBB file, NAR goes deeper than REA on that target. If your target is anything else, use REA.

## Documentation

The guides in `references/` (26 guides, one per topic) carry the method in depth. The repository-level records:

- [CHANGELOG.md](CHANGELOG.md) — release history (the only place version history lives)
- [NAR_3.0.0_UPDATE_REPORT.md](docs/NAR_3.0.0_UPDATE_REPORT.md) — 3.0.0 update report: per-Part defect → fix → test → measured evidence, Part 13 protocol, Part 15 acceptance transcript, Definition-of-Done verdict
- [NAR_COVERAGE_REPORT.md](docs/NAR_COVERAGE_REPORT.md) — generated coverage matrix and gap list: every non-supported entry with reason + probe
- [NAR_2.6.2_VERIFICATION_REPORT.md](docs/NAR_2.6.2_VERIFICATION_REPORT.md) — 2.6.2 verification, security and integrity round: per-workstream record and final battery
- [NAR_FINAL_VERIFICATION_REPORT.md](docs/NAR_FINAL_VERIFICATION_REPORT.md) — stability & certification campaign: final verification report and Definition-of-Done verdict
- [NAR_STABILITY_AUDIT.md](docs/NAR_STABILITY_AUDIT.md) — stability audit: findings register by priority
- [NAR_SECURITY_AUDIT.md](docs/NAR_SECURITY_AUDIT.md) — security audit: archive, parser and redaction hardening evidence
- [NAR_ACCURACY_REPORT.md](docs/NAR_ACCURACY_REPORT.md) — labeled-corpus accuracy measurements (real and synthetic kept separate; NOT MEASURED where no ground truth exists)
- [NAR_PERFORMANCE_REPORT.md](docs/NAR_PERFORMANCE_REPORT.md) — benchmark matrix, baselines and regression gate
- [NAR_COMPATIBILITY_REPORT.md](docs/NAR_COMPATIBILITY_REPORT.md) — compatibility and regression record
- [NAR_RUNTIME_VALIDATION_REPORT.md](docs/NAR_RUNTIME_VALIDATION_REPORT.md) — runtime validation record (emulator-verified; physical device NOT RUN)
- [NAR_CAPABILITY_MATRIX.md](docs/NAR_CAPABILITY_MATRIX.md) — capability matrix: one row per capability area, with status and evidence
- [NAR_ARCHITECTURE.md](docs/NAR_ARCHITECTURE.md) — system architecture
- [NAR_TEST_MATRIX.md](docs/NAR_TEST_MATRIX.md) — executed test evidence matrix
- [SECURITY.md](SECURITY.md) — analysis boundary, untrusted-sample handling, responsible use

## Repo structure

```text
nar-skill/
  SKILL.md                  Main skill: routing, method, report format
  skill.yaml                Skill metadata
  README.md                 This file
  CHANGELOG.md              Release history
  LICENSE                   MIT
  CONTRIBUTING.md           How to contribute
  SECURITY.md               Analysis boundary, untrusted-sample handling, responsible use
  pyproject.toml            Package metadata + tool configuration
  docs/                     Engineering reports and records
    NAR_2.5.2_UPDATE_REPORT.md      2.5.2 update report
    NAR_2.6.0_UPDATE_REPORT.md      2.6.0 update report
    NAR_2.6.1_VERIFICATION_REPORT.md  2.6.1 verification report
    NAR_2.6.2_VERIFICATION_REPORT.md  2.6.2 verification, security and integrity record
    NAR_3.0.0_UPDATE_REPORT.md      3.0.0 update report: per-Part evidence, acceptance, DoD verdict
    NAR_ACCURACY_REPORT.md          Labeled-corpus accuracy measurements
    NAR_ARCHITECTURE.md             System architecture (2.0 program record)
    NAR_AUDIT.md                    Repository audit + reconciliation record
    NAR_CAPABILITY_MATRIX.md        Capability matrix: one row per capability area, with status + evidence
    NAR_COMPATIBILITY_REPORT.md     Compatibility and regression record
    NAR_COVERAGE_REPORT.md          Generated coverage matrix + gap list (reason + probe per gap)
    NAR_FINAL_VERIFICATION_REPORT.md  Stability & certification campaign: final verification report
    NAR_GAP_ANALYSIS.md             Capability baseline with per-area statuses
    NAR_IMPLEMENTATION_PLAN.md      Phase plans and completion records
    NAR_PERFORMANCE_REPORT.md       Benchmark matrix, baselines and regression gate
    NAR_REPAIR_MATRIX.md            Repository-wide repair matrix (2.6.0 program): issue inventory, fixes, verification
    NAR_RUNTIME_VALIDATION_REPORT.md  Runtime validation record (emulator-verified; physical device NOT RUN)
    NAR_SECURITY_AUDIT.md           Security audit: archive, parser and redaction hardening evidence
    NAR_STABILITY_AUDIT.md          Stability audit: findings register by priority
    NAR_TEST_MATRIX.md              Executed test evidence matrix
  .gitignore                Keeps APKs and decoded output out of git
  references/               One guide per topic (33 guides)
    animation-systems.md
    app-bundles.md
    app-patterns.md
    architecture.md
    asset-formats.md
    benchmarks.md
    dex-smali-and-decompile.md
    dynamic-analysis.md
    evidence-workflows.md
    example-prompts.md
    flutter-dart.md
    frida-scripts.md
    glossary.md
    legacy-analysis.md
    manifest-and-resources.md
    modern-analysis.md
    native-libs-and-jni.md
    network-traffic.md
    output-schema.md
    protection-playbook.md
    question-library.json   Canonical `nar ask` question library (289 questions; validated by question.schema.json)
    question-library.md     Human rendering of question-library.json (kept in sync by test)
    react-native.md
    rebuild-playbook.md
    release-guide.md
    safety-and-authorization.md
    script-formats.md
    setup-and-doctor.md
    signatures-and-integrity.md
    tool-registry.md
    triage-and-inventory.md
    troubleshooting.md
    unity-il2cpp.md
    version-compare-and-feature-map.md
    engines/                Per-family engine guides (26)
      adobe-air.md
      bevy-rust.md
      capacitor.md
      cocos2d-x.md
      cordova.md
      defold.md
      ebitengine.md
      embedded-python.md
      flutter.md
      gamemaker.md
      godot.md
      heaps-haxe.md
      libgdx.md
      love.md
      monogame-fna.md
      qt.md
      react-native.md
      renpy.md
      rpg-maker.md
      sdl.md
      solar2d.md
      unity-il2cpp.md
      unity-mono.md
      unreal.md
      web-assets.md
      xamarin-dotnet.md
  schemas/                  JSON schemas for the structured outputs (38 schemas)
    animation.schema.json
    api-architecture.schema.json
    app.schema.json
    application.schema.json
    ask.schema.json
    blueprint.schema.json
    assets.schema.json
    atlas.schema.json
    case.schema.json
    compare-feature-map.schema.json
    comparison.schema.json
    composition.schema.json
    correlations.schema.json
    coverage.schema.json
    decompile.schema.json
    dex.schema.json
    dex-classes.schema.json
    dex-methods.schema.json
    endpoints.schema.json
    engine.schema.json
    execution-log.schema.json
    fallback-chain.schema.json
    fingerprint.schema.json
    frameworks.schema.json
    graph.schema.json
    input.schema.json
    investigation.schema.json
    manifest.schema.json
    native.schema.json
    native-inventory.schema.json
    network-analysis.schema.json
    permissions.schema.json
    question.schema.json
    report.schema.json
    runtime-session.schema.json
    script.schema.json
    security-findings.schema.json
    timeline.schema.json
  scripts/
    nar.py                  Unified CLI over every module below
    nar-doctor.sh           Toolchain check (plain and --json)
    nar-analyze.py          Orchestrated case workup (case dir, staged, cached)
    nar-input.py            Universal input identify / validate / extract / duplicates
    nar-triage.py           First-5-minutes APK triage (plain and --json)
    nar-strings.py          Ranked string extraction (plain and --json)
    nar-compare.py          Two-version diff (plain and --json)
    nar-perms.py            Permission and component audit (plain and --json)
    nar-fingerprint.py      Normalized application fingerprint with provenance
    nar-dex.py              Deep DEX intelligence: own parser + disassembler, jadx/baksmali adapters
    nar-native.py           Deep native / ELF intelligence: dependencies, JNI map, hardening
    nar-engines.py          Multi-indicator engine/framework detection with confidence
    nar-unity.py            Unity deep dive (Mono / IL2CPP routing, bundles)
    nar-unreal.py           Unreal deep dive (pak, IoStore, Zen + classic packages)
    nar-pak.py              Unreal .pak lister/extractor, pak format v1-7 + v10/v11 encoded index (plain and --json)
    nar-il2cpp.py           Unity IL2CPP locator + Il2CppDumper summary (plain and --json)
    nar-flutter.py          Flutter/Dart fingerprint (plain and --json)
    nar-godot.py            Godot .pck inspector (plain and --json)
    nar-rn.py               React Native bundle inspector (plain and --json)
    nar-cocos.py            Cocos2d-x deep dive: plist atlases/particles, .ccb/.csb, .jsc census (nar-engines --deep)
    nar-libgdx.py           libGDX deep dive: .atlas/.pack, .tmx maps, GWT/RoboVM markers (nar-engines --deep)
    nar-defold.py           Defold deep dive: .arci index walk + .arcd census (nar-engines --deep)
    nar-gamemaker.py        GameMaker deep dive: data.win chunk walk + string census (nar-engines --deep)
    nar-renpy.py            Ren'Py deep dive: .rpa index (restricted unpickler) + .rpyc census (nar-engines --deep)
    nar-solar2d.py          Solar2D deep dive: resource.car listing + Lua census (nar-engines --deep)
    nar-heaps.py            Heaps/HashLink deep dive: hlboot.dat header facts (nar-engines --deep)
    nar-qt.py               Qt deep dive: .rcc tree walk + resource listing (nar-engines --deep)
    nar-cordova.py          Cordova deep dive: config.xml, www census, plugin merge (nar-engines --deep)
    nar-capacitor.py        Capacitor deep dive: config, public/ census, plugin list (nar-engines --deep)
    nar-air.py              Adobe AIR deep dive: application.xml descriptor + SWF tag census (nar-engines --deep)
    nar-love.py             LÖVE deep dive: .love listing + conf.lua facts (nar-engines --deep)
    nar-rpgmaker.py         RPG Maker deep dive: www/data census + plugin list (nar-engines --deep)
    nar-webassets.py        Web-assets deep dive: www inventory + JS framework markers (nar-engines --deep)
    nar-xamarin.py          Xamarin deep dive: assemblies + assemblies.blob carving via dotnetmeta (nar-engines --deep)
    nar-monogame.py         MonoGame/FNA deep dive: framework assembly + .xnb census (nar-engines --deep)
    nar-mono.py             Unity Mono deep dive: Managed assembly census + obfuscation indicator (nar-engines --deep)
    nar-python.py           Embedded Python deep dive: .pyc header + code-object census, Kivy facts (nar-engines --deep)
    nar-sdl.py              SDL deep dive: SDL dynsym census via narlib.elf (nar-engines --deep)
    nar-ebiten.py           Ebitengine deep dive: Go build info + embedded asset census (nar-engines --deep)
    nar-bevy.py             Bevy deep dive: asset census + .ron facts + rust evidence (nar-engines --deep)
    nar-network.py          Static network intelligence: endpoints, services, NSC
    nar-security.py         Structured security findings (NAR-SEC schema)
    nar-assets.py           Typed asset inventory (types, sizes, hashes, duplicates)
    nar-runtime.py          Runtime observation: adb + Frida adapters, session plans
    nar-report.py           Offline HTML dashboard for a case directory
    nar-tools.py            Tool-registry view: declared tools with live probes
    nar-coverage.py         Coverage matrix + gap report from formats.json (nar coverage)
    nar-ask.py              Q&A layer: deterministic intent classification + Answer Contract answers from a case (nar ask)
    nar-blueprint.py        Rebuild layer: 9-file rebuild specification from verified case evidence (nar blueprint)
    nar-atlas.py            Sprite-atlas layer: Cocos/TexturePacker/Starling/libGDX/Godot/Unity atlas parsing + part grouping (nar atlas)
    nar-anim.py             Animation layer: Spine/DragonBones/Lottie/Aseprite/Godot/Spriter/Unity/Cocos systems + composition report (nar anim)
    nar-script.py           Script & bytecode layer: Lua/LuaJIT, GDScript, Dart, Hermes, JS bundles, Wasm, .NET CIL, .pyc, AngelScript/Squirrel/Pawn, custom VM (nar script)
    nar-app.py              App layer: UI frameworks (Compose census, layouts, WebView bridge), navigation/route map, storage (SharedPreferences, Room/SQLite, DataStore), encrypted storage, auth (JWT structure only), background work, permissions in use, SDKs, compliance — app.json companion (nar app)
    formats.json            Single source of truth: engines, asset/script formats, animation systems, frameworks, protections
    coverage.json           Coverage matrix generated from formats.json (freshness-tested)
    registry.json           Capability registry: every orchestrated tool, probed
    protection-signatures.json  Versioned protection-signature database (nar-triage, via narlib)
    narlib/                 Shared core library used by the 2.0 modules
      __init__.py
      anim.py               Animation-system parsers (Spine, DragonBones, Lottie, Aseprite, Godot, Spriter, Rive, Unity, Cocos) + physics-rig detection
      atlas.py              Sprite-atlas parsers (Cocos plist, TexturePacker, Starling/Phaser, libGDX, Godot, Unity SpriteAtlas)
      budget.py             ResourceBudget: validated archive/resource limits shared by the extraction paths
      cdex.py               Compact DEX header + section-table parser (payload not decoded)
      chains.py             Fallback chains: chain runner, chain registry, java-decompile chain (Part 10.5)
      companions.py         Brief-named case companion projections
      composition.py        Part grouping + composition classification over atlas/animation parts (generalised naming discovery)
      container.py          Container detection + split-set resolution (base pick, merged roots, duplicates)
      correlations.py       Cross-module correlation records (DEX/ELF/manifest/network joins)
      dex.py                DEX parser (tables, hierarchies, call edges)
      dexdis.py             DEX disassembler (oracle-verified listings)
      dotnetmeta.py         .NET / Xamarin metadata reader
      elf.py                ELF parser (headers, dynamic, symbols, hardening)
      evidence.py           Evidence envelope + fact classes
      failures.py           Failure classification enum (FailureKind) for fallback chains
      formats.py            Magic + structure format identification
      formats_registry.py   formats.json loader: derived engine/format tables + coverage projection
      graph.py              Unified application intelligence graph (graph.json companion)
      hashing.py            Streaming hashes
      iostore.py            Unreal IoStore (UTOC/UCAS) parser
      investigation.py      Deterministic offline investigation layer (investigation.json companion)
      locres.py             Unreal .locres string-table parser (v1 layout verified on real samples)
      mediainfo.py          Media header facts: Wwise banks, video codec/profile, font glyph/name/subsetting, model counts
      mmapio.py             Read-only file mapping (mmap) for the parsers
      oat.py                OAT / VDEX / ODEX / ART parser
      registry.py           Capability-registry reader
      safearchive.py        Guarded archive extraction (slip/bomb/traversal)
      scriptparse.py        Script/bytecode structural parsers (Lua, GDScript, Wasm, .pyc marshal walker, JS census, Pawn AMX, Squirrel)
      sqlite.py             Read-only SQLite schema parser (header + sqlite_master page walk over raw bytes; never the sqlite3 module)
      signatures.py         Protection-signature database loader + validator
      textures.py           Compressed-texture header decode (ASTC, KTX/KTX2, PVR, DDS, PKM: dimensions, block geometry, mips)
      uasset.py             Classic Unreal package inspector
      zen.py                Unreal Zen package parser
    frida/                  Frida observation scripts (Java, JNI, file, network)
      file-io-observe.js
      java-api-trace.js
      jni-trace.js
      network-observe.js
  tests/
    run_e2e.sh              End-to-end script test harness (fixtures via $NAR_FIXTURES)
    synthetic_fixtures.py   Shared synthetic-fixture builder library (clean-clone reproducible)
    generate_fixtures.py    Fixture generator CLI (writes the synthetic set + manifest)
    expected_outputs.json   Builder-intent expected-output manifest for the synthetic set
    unit/                   Pytest unit suite (parsers, guards, schemas, registry)
    fuzz/                   Deterministic DEX mutation-fuzz harness (seeded; crash artifacts preserved)
    accuracy/               Labeled-corpus accuracy runner (real/synthetic separate, per-analyzer P/R/F1)
    runtime_validation/     Frida runtime validation suite (emulator-provable subset; physical = NOT RUN)
    benchmarks/
      run_benchmarks.py     Fixture-corpus benchmark runner (timings, accuracy metrics, peak memory)
      check_regression.py   Regression gate over the committed baselines
      baseline-2.5.2.json   Per-release performance baselines (2.5.2 … 3.0.0)
      baseline-2.6.0.json
      baseline-2.6.1.json
      baseline-2.6.2.json
      baseline-3.0.0.json   3.0.0 performance record: module timings, peak memory, compact-vs-full DEX sizes
      accuracy-2.6.2.json   The 2.6.2 labeled-corpus accuracy record
  examples/
    sample-report.md        Filled report from a real triage run
    quick-triage.md         Example command session
    unity-il2cpp-triage.md  Unity IL2CPP worked example
    godot-triage.md         Godot 4 worked example
  .claude-plugin/
    plugin.json             Claude Code plugin manifest
```

## Running the tests

The unit suite runs from a clean clone (private-corpus cases SKIP when their fixtures are absent):

```bash
python3 -m pytest tests/unit/ -q
python3 tests/generate_fixtures.py --out /tmp/nar-fixtures
bash tests/run_e2e.sh   # needs the local fixture corpus via $NAR_FIXTURES
```

See the "Test categories" section of `docs/NAR_TEST_MATRIX.md` for what each category needs and what an absence produces.

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

Research by Bakr Fayez

## License

NAR Skill is MIT licensed. See [LICENSE](LICENSE).
