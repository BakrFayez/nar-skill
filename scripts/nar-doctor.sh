#!/usr/bin/env bash
# nar-doctor.sh: check that the NAR toolchain is installed and usable.
# NAR Skill (Nirous Android Reversing).
# MIT License. See LICENSE in the repo root.
# Usage: bash nar-doctor.sh [--json]
# Exit 0 when all CORE tools are present, 1 otherwise.
# Optional tools (adb, frida, ghidra, kuna, bundletool, il2cppdumper,
# cpp2il, mitmproxy, tshark, godotpcktool, gdre, hermes-dec) never
# fail the check.
set -u

JSON=0
if [ "${1:-}" = "--json" ]; then JSON=1; fi
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  # --help previously ran the full check (D-15).
  echo "Usage: bash nar-doctor.sh [--json]"
  echo "Check that the NAR toolchain is installed and usable."
  echo "Exit 0 when all CORE tools are present, 1 otherwise."
  echo "Optional tools never fail the check."
  exit 0
fi

# Candidate locations for SDK tools that are often not on PATH.
SDK_CANDIDATES="${ANDROID_HOME:-} ${ANDROID_SDK_ROOT:-} $HOME/Android/Sdk $HOME/workspace/android-sdk $HOME/android-sdk /opt/android-sdk /usr/lib/android-sdk"
find_sdk_tool() {
  local tool="$1" dir ver ext
  local -a dirs=()
  for dir in $SDK_CANDIDATES; do
    [ -n "$dir" ] && dirs+=("$dir")
  done
  # The Android Studio default SDK location on Windows
  # (%LOCALAPPDATA%\Android\Sdk) is not in SDK_CANDIDATES:
  # the path carries backslashes and usually spaces, which
  # the space-separated list cannot hold. Normalise the
  # separators (Git Bash accepts C:/... paths) and add it
  # as a single quoted entry (field round F-32).
  if [ -n "${LOCALAPPDATA:-}" ]; then
    dirs+=("${LOCALAPPDATA//\\//}/Android/Sdk")
  fi
  for dir in "${dirs[@]}"; do
    for ver in $(ls "$dir/build-tools" 2>/dev/null | sort -t. -k1,1nr -k2,2nr -k3,3nr -k4,4nr); do
      if [ -x "$dir/build-tools/$ver/$tool" ]; then echo "$dir/build-tools/$ver/$tool"; return 0; fi
      # Windows SDK tools ship with a PATHEXT suffix (apksigner.bat,
      # analyzeHeadless-style launchers): bash performs no PATHEXT
      # resolution, so try the suffixed names explicitly. Existence
      # is the honest test for the suffixed forms under Git Bash.
      for ext in exe bat cmd; do
        if [ -f "$dir/build-tools/$ver/$tool.$ext" ]; then echo "$dir/build-tools/$ver/$tool.$ext"; return 0; fi
      done
    done
    if [ -x "$dir/platform-tools/$tool" ]; then echo "$dir/platform-tools/$tool"; return 0; fi
    for ext in exe bat cmd; do
      if [ -f "$dir/platform-tools/$tool.$ext" ]; then echo "$dir/platform-tools/$tool.$ext"; return 0; fi
    done
  done
  return 1
}

# Each check: name | required(core|optional) | version-command | install hint
declare -a NAMES=() STATUS=() DETAILS=() REQUIRED=()

check() {
  local name="$1" required="$2" path="$3" detail="$4" hint="$5" forced="${6:-}"
  NAMES+=("$name")
  REQUIRED+=("$required")
  if [ -n "$forced" ]; then
    STATUS+=("$forced")
    DETAILS+=("$detail")
  elif [ -n "$path" ]; then
    STATUS+=("ok")
    DETAILS+=("$detail")
  else
    if [ "$required" = "core" ]; then STATUS+=("missing"); else STATUS+=("optional-missing"); fi
    DETAILS+=("$hint")
  fi
}

# --- java (core, need 17+) ---
JAVA_BIN="$(command -v java || true)"
if [ -z "$JAVA_BIN" ] && [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then
  JAVA_BIN="$JAVA_HOME/bin/java"
fi
if [ -z "$JAVA_BIN" ]; then
  for cand in "$HOME"/workspace/jdk-*/bin/java "$HOME"/workspace/tools/rea-engines/jdk*/bin/java /usr/lib/jvm/*/bin/java; do
    if [ -x "$cand" ]; then JAVA_BIN="$cand"; break; fi
  done
fi
JAVA_DETAIL=""
JAVA_HINT="Install a JDK 17+ (Temurin): https://adoptium.net/"
if [ -n "$JAVA_BIN" ]; then
  JAVA_VER="$("$JAVA_BIN" -version 2>&1 | head -n 1 | sed 's/.*version \"//;s/\".*//')"
  JAVA_MAJOR="$(echo "$JAVA_VER" | cut -d. -f1)"
  if [ "${JAVA_MAJOR:-0}" -ge 17 ] 2>/dev/null; then
    JAVA_DETAIL="java $JAVA_VER ($JAVA_BIN)"
  else
    JAVA_BIN=""
    JAVA_HINT="Java 17+ required, found $JAVA_VER. Install Temurin 17 or newer: https://adoptium.net/"
  fi
fi
check "java" "core" "$JAVA_BIN" "$JAVA_DETAIL" "$JAVA_HINT"

# Later checks run Java-based tools (jadx --version, apksigner). When java
# was found outside PATH, put its directory on PATH for the rest of the run.
if [ -n "$JAVA_BIN" ]; then
  case ":$PATH:" in
    *":$(dirname "$JAVA_BIN"):"*) ;;
    *) export PATH="$(dirname "$JAVA_BIN"):$PATH" ;;
  esac
fi

# --- apktool (core) ---
APKTOOL_BIN="$(command -v apktool || true)"
APKTOOL_DETAIL=""
if [ -n "$APKTOOL_BIN" ]; then
  APKTOOL_DETAIL="apktool $(apktool --version 2>/dev/null | head -n 1) ($APKTOOL_BIN)"
elif [ -n "${NAR_APKTOOL_JAR:-}" ] && [ -f "$NAR_APKTOOL_JAR" ]; then
  APKTOOL_BIN="jar:$NAR_APKTOOL_JAR"
  APKTOOL_DETAIL="apktool via NAR_APKTOOL_JAR=$NAR_APKTOOL_JAR"
elif [ -f "$HOME/workspace/tools/rea-engines/apktool/apktool.jar" ]; then
  APKTOOL_BIN="jar:$HOME/workspace/tools/rea-engines/apktool/apktool.jar"
  APKTOOL_DETAIL="apktool (REA engines path; run with java -jar)"
fi
check "apktool" "core" "$APKTOOL_BIN" "$APKTOOL_DETAIL" "Install apktool 2.7.0+: https://apktool.org/docs/install/ (or set NAR_APKTOOL_JAR to apktool.jar)"

# --- jadx (core: binary or jar) ---
# Existence is not enough: jadx ships as a launcher script that needs a
# JDK (JAVA_HOME set, or java on PATH). Run it for real. A jadx that
# exists but will not start is a warning with the fix, not an OK, and
# it counts against the core verdict below.
# Identity, not mere executability (field round F-04): a candidate
# counts only when its --version output identifies as jadx — a bare
# version number ("1.5.3") or "jadx <version>". A wrapper jar or an
# impostor binary that reports another product is rejected by name
# (tool_identity_mismatch) and the next candidate is tried, in the
# same order narlib/registry.py resolves: PATH binary, the workspace
# CLI layout, then the NAR_JADX_JAR jar (probed by running it, never
# by existence). The jadx-headless-mcp jar is an MCP server, not the
# CLI decompiler, and no longer satisfies this check.
JADX_BIN=""
JADX_DETAIL=""
JADX_STATUS=""
JADX_REJECTED=""
jadx_try() {
  # Print the version line when the binary actually starts, else fail.
  local out
  out="$("$1" --version 2>&1)" || return 1
  [ -n "$out" ] || return 1
  printf '%s' "$(printf '%s' "$out" | head -n 1)"
}
jadx_identity_ok() {
  # $1 = version line. jadx --version prints a bare version or
  # "jadx <version>"; anything else is another product.
  local line="$1"
  line="${line#jadx }"
  [[ "$line" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?([-+].*)?$ ]]
}
jadx_reject() {
  # $1 = candidate description, $2 = what it reported.
  local rec="tool_identity_mismatch: $1 reported '$2'"
  if [ -n "$JADX_REJECTED" ]; then
    JADX_REJECTED="$JADX_REJECTED; $rec"
  else
    JADX_REJECTED="$rec"
  fi
}
jadx_warn_detail() {
  local home_hint="<path to a JDK 17+>"
  if [ -n "$JAVA_BIN" ]; then
    home_hint="$(dirname "$(dirname "$JAVA_BIN")")"
  fi
  printf 'jadx found at %s but it failed to start (its launcher needs a JDK). Fix: export JAVA_HOME=%s and re-run' "$1" "$home_hint"
}
jadx_try_binary() {
  # $1 = binary path. Sets JADX_BIN/JADX_DETAIL on a validated
  # candidate, JADX_STATUS/JADX_DETAIL on a start failure, and
  # records an identity rejection otherwise.
  local ver
  if ver="$(jadx_try "$1")"; then
    if jadx_identity_ok "$ver"; then
      JADX_BIN="$1"
      JADX_DETAIL="jadx $ver ($1)"
    else
      jadx_reject "$1" "$ver"
    fi
  else
    JADX_STATUS="warning"
    JADX_DETAIL="$(jadx_warn_detail "$1")"
  fi
}
JADX_PATH_BIN="$(command -v jadx || true)"
if [ -n "$JADX_PATH_BIN" ]; then
  jadx_try_binary "$JADX_PATH_BIN"
fi
if [ -z "$JADX_BIN" ] && [ -z "$JADX_STATUS" ] \
    && [ -x "$HOME/workspace/tools/jadx-cli/bin/jadx" ]; then
  jadx_try_binary "$HOME/workspace/tools/jadx-cli/bin/jadx"
fi
if [ -z "$JADX_BIN" ] && [ -z "$JADX_STATUS" ] \
    && [ -n "${NAR_JADX_JAR:-}" ] && [ -f "$NAR_JADX_JAR" ]; then
  JADX_JAVA="${JAVA_BIN:-$(command -v java || true)}"
  if [ -n "$JADX_JAVA" ]; then
    JADX_JAR_VER="$("$JADX_JAVA" -jar "$NAR_JADX_JAR" --version 2>/dev/null | head -n 1)"
    if [ -n "$JADX_JAR_VER" ] && jadx_identity_ok "$JADX_JAR_VER"; then
      JADX_BIN="jar:$NAR_JADX_JAR"
      JADX_DETAIL="jadx $JADX_JAR_VER via NAR_JADX_JAR=$NAR_JADX_JAR"
    elif [ -n "$JADX_JAR_VER" ]; then
      jadx_reject "NAR_JADX_JAR=$NAR_JADX_JAR" "$JADX_JAR_VER"
    else
      jadx_reject "NAR_JADX_JAR=$NAR_JADX_JAR" "no version output"
    fi
  fi
fi
if [ -n "$JADX_REJECTED" ]; then
  if [ -n "$JADX_BIN" ]; then
    JADX_DETAIL="$JADX_DETAIL [rejected: $JADX_REJECTED]"
  elif [ -z "$JADX_STATUS" ]; then
    # Candidates existed but none validated: name the mismatch
    # as a warning instead of a bare "missing".
    JADX_STATUS="warning"
    JADX_DETAIL="no jadx candidate validated — $JADX_REJECTED"
  fi
fi
check "jadx" "core" "$JADX_BIN" "$JADX_DETAIL" "Install jadx: https://github.com/skylot/jadx/releases (or set NAR_JADX_JAR to a jadx jar)" "$JADX_STATUS"

# --- aapt2 (core) ---
AAPT2_BIN="$(command -v aapt2 || find_sdk_tool aapt2 || true)"
AAPT2_DETAIL=""
[ -n "$AAPT2_BIN" ] && AAPT2_DETAIL="aapt2 ($AAPT2_BIN)"
check "aapt2" "core" "$AAPT2_BIN" "$AAPT2_DETAIL" "Install Android SDK build-tools (aapt2 ships in build-tools): https://developer.android.com/tools/sdkmanager. Set ANDROID_HOME to the SDK root"

# --- apksigner (core) ---
APKSIGNER_BIN="$(command -v apksigner || find_sdk_tool apksigner || true)"
APKSIGNER_DETAIL=""
[ -n "$APKSIGNER_BIN" ] && APKSIGNER_DETAIL="apksigner ($APKSIGNER_BIN)"
check "apksigner" "core" "$APKSIGNER_BIN" "$APKSIGNER_DETAIL" "Install Android SDK build-tools 30.0.0+ and set ANDROID_HOME"

# --- zipalign (core) ---
ZIPALIGN_BIN="$(command -v zipalign || find_sdk_tool zipalign || true)"
ZIPALIGN_DETAIL=""
[ -n "$ZIPALIGN_BIN" ] && ZIPALIGN_DETAIL="zipalign ($ZIPALIGN_BIN)"
check "zipalign" "core" "$ZIPALIGN_BIN" "$ZIPALIGN_DETAIL" "Install Android SDK build-tools and set ANDROID_HOME"

# --- python3 (core, 3.10+: the pyproject floor; the
# doctor previously accepted any python3 while the
# docs disagreed with pyproject about the floor —
# E-12) ---
# Interpreter resolution chain (Part 10): try, in order,
# $NAR_PYTHON, python3, python, then the Windows py
# launcher (py -3). Each candidate is probed and must
# report Python >= 3.10; a candidate that is too old (or
# cannot run) falls through to the next. The winner is
# recorded in PY_RESOLVED and used, via py_exec, for
# every Python self-check below (nar-scripts,
# protection-signatures, skill-yaml) — a python3-only
# resolution reported those core checks missing on
# python-only systems (stock Windows).
PY_BIN=""
PY_ARGS=""
PY_RESOLVED=""
PY_DETAIL=""
PY_VER=""
PY_HINT="Install Python 3.10+: https://www.python.org/downloads/"
_py_version_ok() {
  _pv_major="${1%%.*}"; _pv_minor="${1##*.}"
  if [ "${_pv_major:-0}" -gt 3 ] 2>/dev/null; then return 0; fi
  if [ "${_pv_major:-0}" -eq 3 ] 2>/dev/null && [ "${_pv_minor:-0}" -ge 10 ] 2>/dev/null; then return 0; fi
  return 1
}
_py_probe() {
  # $1: candidate path; $2: optional extra arg (e.g. -3).
  # Sets PY_VER to the probed "MAJOR.MINOR"; succeeds
  # only when that version is >= 3.10.
  if [ -n "${2:-}" ]; then
    PY_VER="$("$1" "$2" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo "")"
  else
    PY_VER="$("$1" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo "")"
  fi
  [ -n "$PY_VER" ] && _py_version_ok "$PY_VER"
}
_py_try() {
  # $1: command name or path; $2: optional extra arg.
  _cand=""
  if [ -x "$1" ]; then _cand="$1"; else _cand="$(command -v "$1" || true)"; fi
  [ -n "$_cand" ] || return 1
  if _py_probe "$_cand" "${2:-}"; then
    PY_BIN="$_cand"
    PY_ARGS="${2:-}"
    if [ -n "$PY_ARGS" ]; then PY_RESOLVED="$_cand $PY_ARGS"; else PY_RESOLVED="$_cand"; fi
    return 0
  fi
  return 1
}
if [ -n "${NAR_PYTHON:-}" ]; then _py_try "$NAR_PYTHON" "" || true; fi
if [ -z "$PY_BIN" ]; then _py_try "python3" "" || true; fi
if [ -z "$PY_BIN" ]; then _py_try "python" "" || true; fi
if [ -z "$PY_BIN" ]; then _py_try "py" "-3" || true; fi
if [ -n "$PY_BIN" ]; then
  if [ -n "$PY_ARGS" ]; then
    PY_DETAIL="python3 $("$PY_BIN" $PY_ARGS --version 2>&1) ($PY_BIN)"
  else
    PY_DETAIL="python3 $("$PY_BIN" --version 2>&1) ($PY_BIN)"
  fi
elif [ -n "$PY_VER" ]; then
  PY_HINT="Python 3.10+ required (pyproject floor), found $PY_VER. Install Python 3.10+: https://www.python.org/downloads/"
fi
# Invoke the resolved interpreter (adds the py
# launcher's -3 argument when that candidate won).
py_exec() {
  if [ -n "$PY_ARGS" ]; then
    "$PY_BIN" $PY_ARGS "$@"
  else
    "$PY_BIN" "$@"
  fi
}
check "python3" "core" "$PY_BIN" "$PY_DETAIL" "$PY_HINT"

# --- adb (optional) ---
ADB_BIN="$(command -v adb || find_sdk_tool adb || true)"
ADB_DETAIL=""
[ -n "$ADB_BIN" ] && ADB_DETAIL="adb ($ADB_BIN)"
check "adb" "optional" "$ADB_BIN" "$ADB_DETAIL" "Optional (dynamic analysis only): Android SDK platform-tools"

# --- frida (optional) ---
FRIDA_BIN="$(command -v frida || true)"
FRIDA_DETAIL=""
if [ -n "$FRIDA_BIN" ]; then
  FRIDA_DETAIL="frida $(frida --version 2>/dev/null | head -n 1) ($FRIDA_BIN)"
elif [ -x "$HOME/workspace/tools/frida-venv/bin/frida" ]; then
  FRIDA_BIN="$HOME/workspace/tools/frida-venv/bin/frida"
  FRIDA_DETAIL="frida $("$FRIDA_BIN" --version 2>/dev/null | head -n 1) ($FRIDA_BIN)"
fi
check "frida" "optional" "$FRIDA_BIN" "$FRIDA_DETAIL" "Optional (dynamic analysis only): python3 -m venv ~/frida-venv && ~/frida-venv/bin/pip install frida-tools"

# --- ghidra (optional) ---
GHIDRA_BIN=""
GHIDRA_DETAIL=""
if [ -n "${NAR_GHIDRA_DIR:-}" ] && [ -x "$NAR_GHIDRA_DIR/support/analyzeHeadless" ]; then
  GHIDRA_BIN="$NAR_GHIDRA_DIR/support/analyzeHeadless"
  GHIDRA_DETAIL="ghidra (NAR_GHIDRA_DIR=$NAR_GHIDRA_DIR)"
elif command -v analyzeHeadless >/dev/null 2>&1; then
  GHIDRA_BIN="$(command -v analyzeHeadless)"
  GHIDRA_DETAIL="ghidra ($GHIDRA_BIN)"
elif [ -x "$HOME/workspace/tools/rea-engines/ghidra/ghidra_12.2_PUBLIC/support/analyzeHeadless" ]; then
  GHIDRA_BIN="$HOME/workspace/tools/rea-engines/ghidra/ghidra_12.2_PUBLIC/support/analyzeHeadless"
  GHIDRA_DETAIL="ghidra 12.2 (REA engines path)"
fi
check "ghidra" "optional" "$GHIDRA_BIN" "$GHIDRA_DETAIL" "Optional (native .so deep dive): https://ghidra-sre.org/. Set NAR_GHIDRA_DIR"

# --- kuna (optional) ---
KUNA_BIN="$(command -v kuna || true)"
KUNA_DETAIL=""
if [ -n "$KUNA_BIN" ]; then
  KUNA_DETAIL="kuna ($KUNA_BIN)"
elif [ -x "$HOME/workspace/tools/rea-engines/kuna/kuna" ]; then
  KUNA_BIN="$HOME/workspace/tools/rea-engines/kuna/kuna"
  KUNA_DETAIL="kuna (REA engines path)"
fi
check "kuna" "optional" "$KUNA_BIN" "$KUNA_DETAIL" "Optional (fast native decompile): https://github.com/Noelo-Lab/kuna"

# --- bundletool (optional) ---
BUNDLETOOL_BIN="$(command -v bundletool || true)"
BUNDLETOOL_DETAIL=""
if [ -n "$BUNDLETOOL_BIN" ]; then
  BUNDLETOOL_DETAIL="bundletool ($BUNDLETOOL_BIN)"
elif [ -n "${NAR_BUNDLETOOL_JAR:-}" ] && [ -f "$NAR_BUNDLETOOL_JAR" ]; then
  BUNDLETOOL_BIN="jar:$NAR_BUNDLETOOL_JAR"
  BUNDLETOOL_DETAIL="bundletool via NAR_BUNDLETOOL_JAR=$NAR_BUNDLETOOL_JAR"
elif [ -f "$HOME/workspace/tools/bundletool/bundletool-all-1.18.1.jar" ]; then
  BUNDLETOOL_BIN="jar:$HOME/workspace/tools/bundletool/bundletool-all-1.18.1.jar"
  BUNDLETOOL_DETAIL="bundletool 1.18.1 (tools path)"
fi
check "bundletool" "optional" "$BUNDLETOOL_BIN" "$BUNDLETOOL_DETAIL" "Optional (AAB analysis): https://github.com/google/bundletool/releases (or set NAR_BUNDLETOOL_JAR to bundletool-all.jar)"

# --- il2cppdumper (optional) ---
IL2CPP_BIN="$(command -v il2cppdumper || command -v Il2CppDumper || true)"
IL2CPP_DETAIL=""
if [ -n "$IL2CPP_BIN" ]; then
  IL2CPP_DETAIL="il2cppdumper ($IL2CPP_BIN)"
elif [ -f "$HOME/workspace/tools/il2cppdumper/Il2CppDumper.dll" ]; then
  IL2CPP_BIN="$HOME/workspace/tools/il2cppdumper/Il2CppDumper.dll"
  IL2CPP_DETAIL="il2cppdumper (tools path; run with dotnet)"
fi
check "il2cppdumper" "optional" "$IL2CPP_BIN" "$IL2CPP_DETAIL" "Optional (Unity IL2CPP dumps): https://github.com/Perfare/Il2CppDumper/releases (needs .NET 6+)"

# --- cpp2il (optional; second IL2CPP backend for nar-il2cpp) ---
CPP2IL_BIN="${NAR_CPP2IL:-}"
CPP2IL_DETAIL=""
if [ -n "$CPP2IL_BIN" ] && [ ! -x "$CPP2IL_BIN" ]; then CPP2IL_BIN=""; fi
if [ -z "$CPP2IL_BIN" ]; then
  CPP2IL_BIN="$(command -v Cpp2IL || command -v cpp2il || true)"
fi
if [ -z "$CPP2IL_BIN" ] && [ -x "$HOME/workspace/tools/cpp2il/Cpp2IL" ]; then
  CPP2IL_BIN="$HOME/workspace/tools/cpp2il/Cpp2IL"
fi
if [ -n "$CPP2IL_BIN" ]; then
  CPP2IL_VER="$("$CPP2IL_BIN" --version 2>/dev/null | grep -oE 'Version [^ ]+' | head -1)"
  CPP2IL_DETAIL="cpp2il ($CPP2IL_BIN) ${CPP2IL_VER:-version unknown}"
fi
check "cpp2il" "optional" "$CPP2IL_BIN" "$CPP2IL_DETAIL" "Optional (second Unity IL2CPP backend): https://github.com/SamboyCoding/Cpp2IL/releases (or set NAR_CPP2IL)"

# --- mitmproxy (optional) ---
MITM_BIN="$(command -v mitmdump || command -v mitmproxy || true)"
MITM_DETAIL=""
if [ -n "$MITM_BIN" ]; then
  MITM_DETAIL="mitmproxy ($MITM_BIN)"
elif [ -x "$HOME/workspace/tools/mitmproxy-venv/bin/mitmdump" ]; then
  MITM_BIN="$HOME/workspace/tools/mitmproxy-venv/bin/mitmdump"
  MITM_DETAIL="mitmproxy (tools venv)"
fi
check "mitmproxy" "optional" "$MITM_BIN" "$MITM_DETAIL" "Optional (network capture): python3 -m venv ~/mitmproxy-venv && ~/mitmproxy-venv/bin/pip install mitmproxy"

# --- tshark (optional) ---
TSHARK_BIN="$(command -v tshark || true)"
TSHARK_DETAIL=""
[ -n "$TSHARK_BIN" ] && TSHARK_DETAIL="tshark ($TSHARK_BIN)"
check "tshark" "optional" "$TSHARK_BIN" "$TSHARK_DETAIL" "Optional (pcap reading): install Wireshark/tshark from your distro (Ubuntu: sudo apt install tshark)"

# --- godotpcktool (optional) ---
PCKTOOL_BIN="$(command -v godotpcktool || true)"
PCKTOOL_DETAIL=""
if [ -n "$PCKTOOL_BIN" ]; then
  PCKTOOL_DETAIL="godotpcktool ($PCKTOOL_BIN)"
elif [ -x "$HOME/workspace/tools/godotpcktool/godotpcktool" ]; then
  PCKTOOL_BIN="$HOME/workspace/tools/godotpcktool/godotpcktool"
  PCKTOOL_DETAIL="godotpcktool (tools path)"
fi
check "godotpcktool" "optional" "$PCKTOOL_BIN" "$PCKTOOL_DETAIL" "Optional (Godot .pck list/extract): https://github.com/hhyyrylainen/GodotPckTool/releases"

# --- gdre (optional) ---
GDRE_BIN="$(command -v gdre_tools.x86_64 || command -v gdre_tools || true)"
GDRE_DETAIL=""
if [ -n "$GDRE_BIN" ]; then
  GDRE_DETAIL="gdre ($GDRE_BIN)"
elif [ -x "$HOME/workspace/tools/gdre/gdre_tools.x86_64" ]; then
  GDRE_BIN="$HOME/workspace/tools/gdre/gdre_tools.x86_64"
  GDRE_DETAIL="gdre (tools path; keep gdre_tools.pck beside the binary)"
fi
check "gdre" "optional" "$GDRE_BIN" "$GDRE_DETAIL" "Optional (Godot project recovery, GDScript decompile): https://github.com/GDRETools/gdsdecomp/releases"

# --- hermes-dec (optional) ---
HERMES_BIN="$(command -v hbc-file-parser || true)"
HERMES_DETAIL=""
if [ -n "$HERMES_BIN" ]; then
  HERMES_DETAIL="hermes-dec ($HERMES_BIN)"
elif [ -x "$HOME/workspace/tools/hermes-dec/bin/hbc-file-parser" ]; then
  HERMES_BIN="$HOME/workspace/tools/hermes-dec/bin/hbc-file-parser"
  HERMES_DETAIL="hermes-dec (tools path; set PYTHONPATH to the install dir)"
fi
check "hermes-dec" "optional" "$HERMES_BIN" "$HERMES_DETAIL" "Optional (Hermes bytecode parse/disassemble/decompile): pip install hermes-dec (https://pypi.org/project/hermes-dec/)"

# --- nar scripts (core: the skill's own helpers must at least compile) ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
NAR_SCRIPTS_OK=""
NAR_SCRIPTS_DETAIL=""
if [ -n "$PY_BIN" ]; then
  NAR_SCRIPTS_OK="ok"
  # Compile EVERY scripts/*.py (glob, not a hand-maintained name
  # list, so the checked set cannot drift from the tree again):
  # the detail text claims all bundled scripts compile, so the
  # loop must actually cover all of them.
  # Compile into a throwaway dir: py_compile otherwise writes
  # __pycache__ next to every script in the tree.
  PYC_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nar-doctor.XXXXXX" 2>/dev/null || echo "")"
  NAR_SCRIPTS_COUNT=0
  NARLIB_COUNT=0
  # The narlib package is compiled too (D-08): a broken
  # narlib module previously left the doctor READY while
  # every pipeline stage that imports it failed.
  for script_path in "$SCRIPT_DIR"/*.py "$SCRIPT_DIR"/narlib/*.py; do
    [ -f "$script_path" ] || continue
    s="$(basename "$script_path")"
    case "$script_path" in
      */narlib/*) NARLIB_COUNT=$((NARLIB_COUNT + 1)); rel="narlib/$s" ;;
      *) NAR_SCRIPTS_COUNT=$((NAR_SCRIPTS_COUNT + 1)); rel="scripts/$s" ;;
    esac
    if [ -n "$PYC_DIR" ]; then
      COMPILE_OK="$(py_exec -c 'import py_compile, sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True)' "$script_path" "$PYC_DIR/$(echo "$rel" | tr / _).pyc" 2>/dev/null && echo 1)"
    else
      COMPILE_OK="$(py_exec -m py_compile "$script_path" 2>/dev/null && echo 1)"
    fi
    if [ -z "$COMPILE_OK" ]; then
      NAR_SCRIPTS_OK=""; NAR_SCRIPTS_DETAIL="$rel does not compile"; break
    fi
  done
  if [ "$NAR_SCRIPTS_COUNT" -eq 0 ]; then
    NAR_SCRIPTS_OK=""; NAR_SCRIPTS_DETAIL="no bundled scripts found under scripts/"
  elif [ -n "$NAR_SCRIPTS_OK" ]; then
    NAR_SCRIPTS_DETAIL="all bundled scripts compile ($NAR_SCRIPTS_COUNT scripts + $NARLIB_COUNT narlib modules)"
  fi
  [ -n "$PYC_DIR" ] && rm -rf "$PYC_DIR"
fi
check "nar-scripts" "core" "$NAR_SCRIPTS_OK" "$NAR_SCRIPTS_DETAIL" "The scripts bundled with the skill are missing or broken; reinstall the skill"

# --- protection signature database (core: nar-triage loads it) ---
SIG_DB="$SCRIPT_DIR/protection-signatures.json"
SIG_OK=""; SIG_DETAIL=""
if [ -n "$PY_BIN" ] && [ -f "$SIG_DB" ]; then
  SIG_DETAIL="$(py_exec -c 'import json,sys; d=json.load(open(sys.argv[1])); print("protection signatures DB v%s (%d packers, %d categories, schema %s)" % (d["database_version"], len(d.get("packers",[])), len(d.get("categories",[])), d.get("schema")))' "$SIG_DB" 2>/dev/null)"
  if [ -n "$SIG_DETAIL" ]; then SIG_OK="ok"; fi
fi
check "protection-signatures" "core" "$SIG_OK" "$SIG_DETAIL" "scripts/protection-signatures.json is missing or unreadable; nar-triage cannot run its protection scan without it — reinstall the skill"

# --- skill YAML (optional: skill.yaml + SKILL.md frontmatter must ---
# --- parse as YAML when a YAML parser is available to python3) ---
# Optional by design: PyYAML is a test-only dependency, never a
# runtime one, so a missing parser reports "unavailable" and an
# invalid file reports a warning — neither touches the core
# verdict (the verdict loop only fails core checks).
SKILL_YAML_OK=""; SKILL_YAML_DETAIL=""; SKILL_YAML_FORCED=""
SKILL_ROOT="$(dirname "$SCRIPT_DIR")"
if [ -n "$PY_BIN" ] && py_exec -c "import yaml" 2>/dev/null; then
  YAML_OUT="$(py_exec -c 'import sys, yaml; root = sys.argv[1]; d = yaml.safe_load(open(root + "/skill.yaml", encoding="utf-8")); assert isinstance(d, dict), "skill.yaml is not a mapping"; t = open(root + "/SKILL.md", encoding="utf-8").read(); assert t.startswith("---\n"), "SKILL.md has no frontmatter fence"; f = yaml.safe_load(t.split("---\n", 2)[1]); assert isinstance(f, dict), "SKILL.md frontmatter is not a mapping"; print("skill.yaml + SKILL.md frontmatter parse as valid YAML")' "$SKILL_ROOT" 2>&1)"
  if [ $? -eq 0 ]; then
    SKILL_YAML_OK="ok"
    SKILL_YAML_DETAIL="$YAML_OUT"
  else
    SKILL_YAML_FORCED="warning"
    SKILL_YAML_DETAIL="skill YAML invalid: $(printf '%s' "$YAML_OUT" | tail -n 1)"
  fi
fi
check "skill-yaml" "optional" "$SKILL_YAML_OK" "$SKILL_YAML_DETAIL" "unavailable (no YAML parser): install PyYAML for python3 (pip install pyyaml) to enable skill YAML validation" "$SKILL_YAML_FORCED"

# --- verdict ---
CORE_OK=1
for i in "${!NAMES[@]}"; do
  if [ "${STATUS[$i]}" = "missing" ]; then CORE_OK=0; fi
  if [ "${STATUS[$i]}" = "warning" ] && [ "${REQUIRED[$i]}" = "core" ]; then CORE_OK=0; fi
done

json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g'; }

if [ "$JSON" -eq 1 ]; then
  printf '{\n  "tool": "nar-doctor",\n  "core_ok": %s,\n  "python_resolved": "%s",\n  "checks": [\n' "$([ "$CORE_OK" -eq 1 ] && echo true || echo false)" "$(json_escape "$PY_RESOLVED")"
  for i in "${!NAMES[@]}"; do
    comma=","; [ "$i" -eq $((${#NAMES[@]} - 1)) ] && comma=""
    printf '    {"name": "%s", "status": "%s", "detail": "%s"}%s\n' \
      "$(json_escape "${NAMES[$i]}")" "${STATUS[$i]}" "$(json_escape "${DETAILS[$i]}")" "$comma"
  done
  printf '  ]\n}\n'
else
  echo "NAR doctor: Nirous Android Reversing toolchain check"
  echo "===================================================="
  for i in "${!NAMES[@]}"; do
    case "${STATUS[$i]}" in
      ok) mark="OK      " ;;
      missing) mark="MISSING " ;;
      warning) mark="WARNING " ;;
      *) mark="OPTIONAL" ;;
    esac
    printf '%s %-10s %s\n' "$mark" "${NAMES[$i]}" "${DETAILS[$i]}"
  done
  echo "-----------------------------------------------------"
  if [ "$CORE_OK" -eq 1 ]; then
    echo "Core toolchain: READY"
  else
    echo "Core toolchain: INCOMPLETE. Install the MISSING tools (see references/setup-and-doctor.md)"
  fi
fi

[ "$CORE_OK" -eq 1 ] && exit 0 || exit 1
