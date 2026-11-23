#!/usr/bin/env bash
# nar-doctor.sh: check that the NAR toolchain is installed and usable.
# NAR Skill (Nirous Android Reversing). Research by Bakr Fayez.
# MIT License. See LICENSE in the repo root.
# Usage: bash nar-doctor.sh [--json]
# Exit 0 when all CORE tools are present, 1 otherwise.
# Optional tools (adb, frida, ghidra, kuna, bundletool, il2cppdumper,
# mitmproxy, tshark, godotpcktool, gdre, hermes-dec) never fail the check.
set -u

JSON=0
if [ "${1:-}" = "--json" ]; then JSON=1; fi

# Candidate locations for SDK tools that are often not on PATH.
SDK_CANDIDATES="${ANDROID_HOME:-} ${ANDROID_SDK_ROOT:-} $HOME/Android/Sdk $HOME/workspace/android-sdk $HOME/android-sdk /opt/android-sdk /usr/lib/android-sdk"
find_sdk_tool() {
  local tool="$1" dir ver
  for dir in $SDK_CANDIDATES; do
    [ -z "$dir" ] && continue
    for ver in $(ls "$dir/build-tools" 2>/dev/null | sort -Vr); do
      if [ -x "$dir/build-tools/$ver/$tool" ]; then echo "$dir/build-tools/$ver/$tool"; return 0; fi
    done
    if [ -x "$dir/platform-tools/$tool" ]; then echo "$dir/platform-tools/$tool"; return 0; fi
  done
  return 1
}

# Each check: name | required(core|optional) | version-command | install hint
declare -a NAMES=() STATUS=() DETAILS=()

check() {
  local name="$1" required="$2" path="$3" detail="$4" hint="$5"
  NAMES+=("$name")
  if [ -n "$path" ]; then
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
JADX_BIN="$(command -v jadx || true)"
JADX_DETAIL=""
if [ -n "$JADX_BIN" ]; then
  JADX_DETAIL="jadx $(jadx --version 2>/dev/null | head -n 1) ($JADX_BIN)"
elif [ -n "${NAR_JADX_JAR:-}" ] && [ -f "$NAR_JADX_JAR" ]; then
  JADX_BIN="jar:$NAR_JADX_JAR"
  JADX_DETAIL="jadx via NAR_JADX_JAR=$NAR_JADX_JAR"
elif [ -x "$HOME/workspace/tools/jadx-cli/bin/jadx" ]; then
  JADX_BIN="$HOME/workspace/tools/jadx-cli/bin/jadx"
  JADX_DETAIL="jadx $("$JADX_BIN" --version 2>/dev/null | head -n 1) ($JADX_BIN)"
elif [ -f "$HOME/workspace/tools/rea-engines/jadx/jadx-headless-mcp-0.7.1-all.jar" ]; then
  JADX_BIN="jar:$HOME/workspace/tools/rea-engines/jadx/jadx-headless-mcp-0.7.1-all.jar"
  JADX_DETAIL="jadx headless MCP jar (REA engines path; MCP use, not CLI)"
fi
check "jadx" "core" "$JADX_BIN" "$JADX_DETAIL" "Install jadx: https://github.com/skylot/jadx/releases (or set NAR_JADX_JAR to a jadx jar)"

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

# --- python3 (core, 3.9+) ---
PY_BIN="$(command -v python3 || true)"
PY_DETAIL=""
[ -n "$PY_BIN" ] && PY_DETAIL="python3 $(python3 --version 2>&1) ($PY_BIN)"
check "python3" "core" "$PY_BIN" "$PY_DETAIL" "Install Python 3.9+: https://www.python.org/downloads/"

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
check "kuna" "optional" "$KUNA_BIN" "$KUNA_DETAIL" "Optional (fast native decompile): https://github.com/ScepticCute/kuna"

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

# --- verdict ---
CORE_OK=1
for i in "${!NAMES[@]}"; do
  if [ "${STATUS[$i]}" = "missing" ]; then CORE_OK=0; fi
done

json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g'; }

if [ "$JSON" -eq 1 ]; then
  printf '{\n  "tool": "nar-doctor",\n  "core_ok": %s,\n  "checks": [\n' "$([ "$CORE_OK" -eq 1 ] && echo true || echo false)"
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
