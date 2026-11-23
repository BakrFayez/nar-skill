# Setup and doctor

Install once, then verify with `scripts/nar-doctor.sh` before each session.
NAR needs no MCP server and no paid tool: every core engine is free and
open source except the optional commercial decompilers (Hopper, IDA), which
NAR does not require.

## Core tools

| Tool | Version needed | Install |
|---|---|---|
| Java (full JDK) | 17 or newer (25 for Ghidra 12.2) | Temurin: https://adoptium.net/ |
| apktool | 2.7.0+ | https://apktool.org/docs/install/ |
| jadx | 1.5.x CLI, or a jadx jar | https://github.com/skylot/jadx/releases |
| aapt2 | build-tools 34+ | Android SDK build-tools (see below) |
| apksigner | build-tools 30.0.0+ | Android SDK build-tools |
| zipalign | build-tools 30.0.0+ | Android SDK build-tools |
| Python | 3.9+ | https://www.python.org/downloads/ |

Android SDK tools (aapt2, apksigner, zipalign, adb) come from the SDK
command-line tools. Install the SDK, then:

```bash
export ANDROID_HOME="$HOME/Android/Sdk"   # or wherever the SDK lives
export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
sdkmanager "build-tools;35.0.0" "platform-tools"
export PATH="$ANDROID_HOME/build-tools/35.0.0:$ANDROID_HOME/platform-tools:$PATH"
```

`nar-doctor.sh` also searches `ANDROID_HOME`, `ANDROID_SDK_ROOT`,
`~/Android/Sdk`, and `~/workspace/android-sdk` for build-tools, so tools
work even when they are not on `PATH`. It picks the newest installed
build-tools version.

## jadx: CLI vs jar

The recommended form is the CLI binary from the release zip
(`bin/jadx` on `PATH`). The doctor also accepts a jadx jar:

- A `jadx` binary on `PATH` (the release zip ships `bin/jadx`).
- A jadx jar pointed to by `NAR_JADX_JAR`, for example
  `jadx-1.5.3-all.jar` from a release. Run it as
  `java -cp "$NAR_JADX_JAR" jadx.cli.JadxCLI ...`, not `java -jar`:
  the all-jar's main class is the GUI.
- The `jadx-headless-mcp` jar used by REA is a third form. It serves
  jadx over MCP for REA; it is not a CLI decompiler. The doctor
  counts it as "jadx present" because REA users can decompile
  through REA, but the plain `jadx` commands in the DEX guide need
  the CLI binary or the `-all` jar.

jadx needs a full JDK and a generous heap on large games: run it with
`JADX_OPTS="-Xmx4g" jadx ...` (the launcher also honors `JAVA_OPTS`).
See [DEX, smali, and decompile](dex-smali-and-decompile.md) for flags.

## Optional tools

| Tool | For | Install |
|---|---|---|
| adb | Dynamic analysis, pulling APKs from a device | SDK platform-tools |
| Frida + frida-tools | Runtime hooks on an authorized device/emulator | `python3 -m venv ~/frida-venv && ~/frida-venv/bin/pip install frida-tools` (a venv avoids PEP 668 errors on Ubuntu 24.04+); needs a matching `frida-server` on the device |
| Ghidra | Deep native `.so` decompilation | https://ghidra-sre.org/ (12.2+); set `NAR_GHIDRA_DIR` to the install dir |
| Kuna | Fast whole-program native decompile | https://github.com/ScepticCute/kuna |
| bundletool | AAB inspection, generating APKs from a bundle | https://github.com/google/bundletool/releases |
| Il2CppDumper | Unity IL2CPP metadata dumps | https://github.com/Perfare/Il2CppDumper/releases (net6 build; needs .NET 6+ runtime) |
| mitmproxy | Network capture (mitmdump) | `python3 -m venv ~/mitmproxy-venv && ~/mitmproxy-venv/bin/pip install mitmproxy` |
| tshark | pcap reading | Wireshark: https://www.wireshark.org/ (Ubuntu: `sudo apt install tshark`) |
| GodotPckTool | Godot `.pck` list and extract | https://github.com/hhyyrylainen/GodotPckTool/releases |
| GDRE Tools | Godot project recovery, GDScript decompile | https://github.com/GDRETools/gdsdecomp/releases (keep `gdre_tools.pck` beside the binary) |
| hermes-dec | Hermes bytecode parse, disassemble, decompile | `pip install hermes-dec` (https://pypi.org/project/hermes-dec/); run `hbc-file-parser`, `hbc-disassembler`, `hbc-decompiler` |
| Apktool's `apktool.jar` | Same as the `apktool` binary | Set `NAR_APKTOOL_JAR` to the jar path |

Ghidra 12.2 requires JDK 25+. If your system Java is older, keep a second
JDK and point `JAVA_HOME` at it only for Ghidra runs.

## Environment variables

| Variable | Meaning |
|---|---|
| `JAVA_HOME` | JDK root; selects which Java runs apktool/jadx/Ghidra |
| `ANDROID_HOME` / `ANDROID_SDK_ROOT` | Android SDK root (build-tools + platform-tools lookup) |
| `NAR_JADX_JAR` | Absolute path to a jadx jar when no `jadx` binary is installed |
| `NAR_APKTOOL_JAR` | Absolute path to `apktool.jar` when no `apktool` binary is installed |
| `NAR_BUNDLETOOL_JAR` | Absolute path to `bundletool-all.jar` when no `bundletool` binary is installed |
| `NAR_GHIDRA_DIR` | Ghidra install dir (contains `support/analyzeHeadless`) |

## nar-doctor.sh

```bash
bash scripts/nar-doctor.sh          # human-readable, exit 0 when core is ready
bash scripts/nar-doctor.sh --json   # machine-readable
```

Each line is `OK`, `MISSING` (core, fails the check), or `OPTIONAL`
(optional tool absent, never fails). The detail column gives the version
and path found, or an install hint.

## Common failures

- `java: command not found`, or Java older than 17: install Temurin 17+
  and make sure `java` on `PATH` is the new one (`java -version`).
- `apksigner` / `zipalign` / `aapt2` missing but the SDK exists: set
  `ANDROID_HOME` to the SDK root, or add the newest
  `build-tools/<version>/` directory to `PATH`.
- jadx runs out of memory on a large game: raise the heap
  (`JADX_OPTS="-Xmx8g" jadx ...`) or decompile single classes with
  `--single-class`; see the DEX guide. The APK is never the problem;
  the heap is.
- apktool fails with a framework error (`brut.androlib.AndrolibException`):
  the APK targets a framework apktool does not know. Install the device
  framework (`apktool if framework-res.apk`) or use `apktool d -r` to
  skip resources and decode DEX only.
- Ghidra refuses to start: check the JDK version first (12.2 needs JDK
  25+). `NAR_GHIDRA_DIR` must point at the directory containing `support/`.
- Frida version mismatch (`unable to connect` / protocol errors): the
  `frida-server` on the device must match the desktop `frida` major
  version exactly. See [dynamic analysis](dynamic-analysis.md).
