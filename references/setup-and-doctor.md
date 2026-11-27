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
| Python | 3.10+ | https://www.python.org/downloads/ |

Android SDK tools (aapt2, apksigner, zipalign, adb) come from the SDK
command-line tools. Install the SDK, then:

```bash
export ANDROID_HOME="$HOME/Android/Sdk"   # or wherever the SDK lives
export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
sdkmanager "build-tools;35.0.0" "platform-tools"
export PATH="$ANDROID_HOME/build-tools/35.0.0:$ANDROID_HOME/platform-tools:$PATH"
```

`nar-doctor.sh` also searches `ANDROID_HOME`, `ANDROID_SDK_ROOT`,
`~/Android/Sdk`, `~/workspace/android-sdk`, and — on Windows — the
Android Studio default location `%LOCALAPPDATA%\Android\Sdk` for
build-tools, so tools work even when they are not on `PATH`. It picks
the newest installed build-tools version.

### Python on Windows: the Microsoft Store stub

On a stock Windows machine, `python3` is often not a real interpreter:
it is a Microsoft Store stub that opens the Store (or exits without
running anything) instead of executing your command. A real install
may provide only `python`, or only the `py` launcher. The doctor
already handles this: it resolves its interpreter in the order
`NAR_PYTHON` → `python3` → `python` → `py -3`, executing and
version-probing each candidate (floor: Python 3.10+), and uses the
winner for every self-check. The command examples in these guides are
written as `python3 scripts/…`; on a machine where `python3` is the
Store stub, run the same command with `python` or `py -3` in place of
`python3` — the scripts themselves are identical.

### The Android SDK on Windows

Android Studio installs the SDK at `%LOCALAPPDATA%\Android\Sdk` by
default. That location is in the search list of the doctor, the
registry, and the standalone tools, so a standard Android Studio
install is found with no setup at all. If the SDK lives somewhere
else, set `ANDROID_HOME` to its root — in PowerShell:

```powershell
$env:ANDROID_HOME = "C:\path\to\Sdk"
```

(set it in your profile to make it permanent). The command-line
tools route works as on Linux: `sdkmanager "build-tools;35.0.0"
"platform-tools"` installs into the SDK root.

One Windows form to know: `apksigner` ships in build-tools as
`apksigner.bat`, not an `.exe`. The doctor and the registry resolve
the `.bat` / `.cmd` / `.exe` forms themselves — no shim or wrapper
script is needed, and a `command -v`-style lookup missing it does
not mean it is absent.

## jadx: CLI vs jar

The recommended form is the CLI binary from the release zip
(`bin/jadx` on `PATH`). A jadx jar is the fallback: set
`NAR_JADX_JAR` to it (for example the `jadx-*-all.jar` from the
release zip's `lib/` directory), and NAR launches it with
`java -jar`.

Whichever form is found, presence is not enough: every candidate
is run, and its `--version` output must identify as jadx — a bare
version number (`1.5.3`) or `jadx <version>`. A candidate that
reports another product is rejected by name
(`tool_identity_mismatch`) and the next candidate is tried; the
doctor and the registry the decompile chain consults apply the
same rule. Two consequences worth knowing:

- A wrapper jar around jadx does not satisfy the check. Point
  `NAR_JADX_JAR` at the real jadx jar, or put the CLI binary on
  `PATH`.
- The `jadx-headless-mcp` jar is an MCP server, not the CLI
  decompiler. It does not identify as jadx, so it does not
  satisfy the doctor's jadx check (it once did, by existence
  alone). Decompile through REA's MCP route is unaffected, but
  NAR's own chain needs the CLI binary or the real jar.

If no candidate validates, the decompile chain falls through to
its next rung and the case's Fallback Record names the identity
rejections — an absent or impostor jadx degrades fidelity
openly, never silently.

jadx needs a full JDK and a generous heap on large games: run it with
`JADX_OPTS="-Xmx4g" jadx ...` (the launcher also honors `JAVA_OPTS`).
See [DEX, smali, and decompile](dex-smali-and-decompile.md) for flags.

## Optional tools

| Tool | For | Install |
|---|---|---|
| adb | Dynamic analysis, pulling APKs from a device | SDK platform-tools |
| Frida + frida-tools | Runtime hooks on an authorized device/emulator | `python3 -m venv ~/frida-venv && ~/frida-venv/bin/pip install frida-tools` (a venv avoids PEP 668 errors on Ubuntu 24.04+); needs a matching `frida-server` on the device |
| Ghidra | Deep native `.so` decompilation | https://ghidra-sre.org/ (12.2+); set `NAR_GHIDRA_DIR` to the install dir |
| Kuna | Fast whole-program native decompile | https://github.com/Noelo-Lab/kuna |
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

If Ghidra's `analyzeHeadless` script execution fails (for example the
script JIT on Windows), drive Ghidra through PyGhidra instead — see
the PyGhidra fallback subsection in
[native libraries and JNI](native-libs-and-jni.md).

## Environment variables

| Variable | Meaning |
|---|---|
| `JAVA_HOME` | JDK root; selects which Java runs apktool/jadx/Ghidra |
| `ANDROID_HOME` / `ANDROID_SDK_ROOT` | Android SDK root (build-tools + platform-tools lookup) |
| `NAR_JADX_JAR` | Absolute path to a jadx jar when no `jadx` binary is installed |
| `NAR_APKTOOL_JAR` | Absolute path to `apktool.jar` when no `apktool` binary is installed |
| `NAR_BUNDLETOOL_JAR` | Absolute path to `bundletool-all.jar` when no `bundletool` binary is installed |
| `NAR_GHIDRA_DIR` | Ghidra install dir (contains `support/analyzeHeadless`) |
| `NAR_PYTHON` | Interpreter the doctor probes first for its Python self-checks |
| `NAR_<NAME>_PATH` | Per-tool path override, e.g. `NAR_JADX_PATH` — the first candidate the registry probes for that tool |
| `NAR_NO_MERGE_SPLITS` | `1` (or `true` / `yes` / `on`) disables default split-APK merging in `nar analyze` and the stage tools — the environment form of `--no-merge-splits` |

## nar-doctor.sh

```bash
bash scripts/nar-doctor.sh          # human-readable, exit 0 when core is ready
bash scripts/nar-doctor.sh --json   # machine-readable
```

Each line is `OK`, `MISSING` (core, fails the check), or `OPTIONAL`
(optional tool absent, never fails). The detail column gives the version
and path found, or an install hint.

## What CI proves — and what it does not

The hosted CI matrix (Linux, macOS, Windows) proves that the unit
battery, the schema and documentation-consistency suites, the
doctor's interpreter resolution and self-checks, every script's
`--help` surface, and the fixture-free slice of the e2e harness
pass on hosted runners. Read it as exactly that, no more:

- No CI job installs a consumer toolchain (JDK, Android SDK
  build-tools, jadx, apktool) and runs the documented commands
  against it; the hosted doctor job gates on interpreter
  resolution and the self-checks, not on the doctor's full core
  verdict.
- Much of the Windows platform layer is exercised by
  simulated-Windows unit tests — planted stub tools, a
  monkeypatched platform — not by real consumer-installed tools.
- A clean stock-Windows install (a fresh machine, only the
  install steps in this guide) is therefore NOT RUN as a test.
  A clean-environment Windows job is prepared; until it lands
  and passes, out-of-box Windows compatibility rests on the
  requirements above: a real Python 3.10+ (not the Microsoft
  Store stub), an SDK in a searched location, and the
  `.bat` / `.cmd` tool forms the doctor and registry resolve.

## Common failures

- `java: command not found`, or Java older than 17: install Temurin 17+
  and make sure `java` on `PATH` is the new one (`java -version`).
- `nar doctor` on Windows reports that no usable bash was found:
  the doctor is a bash script. `nar` locates Git Bash itself
  (from the git install, Program Files, or `%LOCALAPPDATA%`) and
  refuses the `bash.exe` in `System32` — that file is the WSL
  launcher stub, not a real bash, and is never used. Install Git
  for Windows (https://git-scm.com/download/win) and retry.
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
