#!/usr/bin/env bash
# run_e2e.sh: end-to-end test harness for every bundled NAR script.
#
# Usage:
#   bash tests/run_e2e.sh
#   NAR_FIXTURES=/path/to/fixtures bash tests/run_e2e.sh
#
# Fixtures are binary and never ship in this repo. The harness reads
# them from $NAR_FIXTURES (default ~/workspace/nar-e2e-fixtures). A
# case whose fixture is absent is reported as SKIP, never as PASS.
# Real-world fixture files are bound to roles through an optional
# local manifest at $NAR_FIXTURES/manifest.env (never committed),
# which may set:
#   FIX_PAIRIP      APK doctored to carry a named packer's artifacts
#   FIX_COMPOSE     modern Kotlin/Compose app APK
#   FIX_JAVA        pure-Java app APK (no Kotlin)
#   FIX_XAPK        .xapk container
#   FIX_GAME_UNREAL Unreal-engine game APK
#   FIX_PAK         Unreal .pak archive
#   FIX_UNITY       Unity IL2CPP game APK
#   FIX_FLUTTER     Flutter app APK
#   FIX_GODOT_PCK   Godot .pck pack
#   FIX_GODOT_LOOSE Godot APK with a loose (no-.pck) export layout
#   FIX_WIDEVINE_COMPILED app whose Widevine UUID ships only as
#                   compiled DEX constants (no dashed string)
#   FIX_SWF_CONTENT app bundling .swf web content but no AIR
#                   descriptor (must NOT be attributed to Adobe AIR)
#   FIX_UNITY_BUNDLES Unity game whose assets/**.bundle files are
#                   Addressables bundles (must NOT read as React Native)
#   FIX_RN          React Native app APK
#   FIX_APP         app APK for the nar-analyze case
#   FIX_GAME        game APK for the nar-analyze case
#   FIX_TV          APK declaring the leanback (Android TV) feature
#   FIX_CLEAN_SET   space-separated APK list that must show zero
#                   attributed commercial packers
# The synthetic demo APKs under $NAR_FIXTURES/demo/ are used directly.
#
# Exit code: 0 when every non-skipped case passes, 1 otherwise.

set -u
SKILL="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
SCRIPTS="$SKILL/scripts"
export NAR_FIXTURES="${NAR_FIXTURES:-$HOME/workspace/nar-e2e-fixtures}"
F="$NAR_FIXTURES"
[ -f "$F/manifest.env" ] && . "$F/manifest.env"

PASS=0; FAIL=0; SKIP=0
FAILED_CASES=""
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ok()   { PASS=$((PASS+1)); printf 'PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); FAILED_CASES="$FAILED_CASES $1"; printf 'FAIL  %s  (%s)\n' "$1" "$2"; }
skip() { SKIP=$((SKIP+1)); printf 'SKIP  %s  (%s)\n' "$1" "$2"; }

# need <case-name> <path> : returns 0 if the fixture file exists
need() { [ -n "${2:-}" ] && [ -f "$2" ]; }

contains()    { grep -q -- "$2" "$1"; }
not_contains(){ ! grep -qi -- "$2" "$1"; }

PY=python3

# ---------------------------------------------------------------- doctor
"$SKILL/scripts/nar-doctor.sh" > "$TMP/doctor.log" 2>&1
if [ $? -eq 0 ] && contains "$TMP/doctor.log" "Core toolchain: READY"; then
  ok "doctor: READY, exit 0"
else
  bad "doctor" "not READY or non-zero exit; see nar-doctor.sh output"
fi

DEMO="$F/demo/NarDemo.apk"
DEMO2="$F/demo/NarDemo_v2.apk"

# ---------------------------------------------------------------- triage
if need triage-demo "$DEMO"; then
  $PY "$SCRIPTS/nar-triage.py" "$DEMO" > "$TMP/triage-demo.log" 2>&1
  if contains "$TMP/triage-demo.log" "Package: com.example.nardemo" \
     && contains "$TMP/triage-demo.log" "v1.0 (code 1)"; then
    ok "triage: demo identity"
  else bad "triage-demo-identity" "package/version line mismatch"; fi
else skip "triage-demo-identity" "demo fixture absent"; fi

if need triage-pairip "${FIX_PAIRIP:-}"; then
  $PY "$SCRIPTS/nar-triage.py" --json "$FIX_PAIRIP" > "$TMP/triage-pairip.json" 2>/dev/null
  if $PY -c "
import json,sys
d=json.load(open('$TMP/triage-pairip.json'))
hits=[p for p in d.get('protections',[]) if p.get('category')=='commercial_packer' and p.get('attributed') and 'Pairip' in p.get('name','')]
sys.exit(0 if hits else 1)"; then
    ok "triage: Pairip named on doctored fixture"
  else bad "triage-pairip" "no attributed Pairip finding"; fi
else skip "triage-pairip" "FIX_PAIRIP unset or absent"; fi

if [ -n "${FIX_CLEAN_SET:-}" ]; then
  CLEAN_OK=1; CHECKED=0
  for apk in $FIX_CLEAN_SET; do
    [ -f "$apk" ] || continue
    CHECKED=$((CHECKED+1))
    $PY "$SCRIPTS/nar-triage.py" --json "$apk" > "$TMP/triage-clean.json" 2>/dev/null
    if ! $PY -c "
import json,sys
d=json.load(open('$TMP/triage-clean.json'))
hits=[p for p in d.get('protections',[]) if p.get('category')=='commercial_packer' and p.get('attributed')]
sys.exit(0 if not hits else 1)"; then
      CLEAN_OK=0; printf '       named packer on clean fixture: %s\n' "$apk"
    fi
  done
  if [ "$CHECKED" -eq 0 ]; then skip "triage-clean-set" "no clean-set files exist"
  elif [ "$CLEAN_OK" -eq 1 ]; then ok "triage: zero named packers on clean set ($CHECKED files)"
  else bad "triage-clean-set" "attributed packer on a clean fixture"; fi
else skip "triage-clean-set" "FIX_CLEAN_SET unset"; fi

# Widevine whose UUID ships only as compiled DEX constants (the
# dashed string never appears) must still be identified.
if need triage-widevine-compiled "${FIX_WIDEVINE_COMPILED:-}"; then
  $PY "$SCRIPTS/nar-triage.py" --json "${FIX_WIDEVINE_COMPILED}" > "$TMP/triage-widevine.json" 2>/dev/null
  if $PY -c "
import json,sys
d=json.load(open('$TMP/triage-widevine.json'))
hits=[p for p in d.get('protections',[]) if p.get('name')=='Widevine DRM' and any('compiled' in e for e in p.get('evidence',[]))]
sys.exit(0 if hits else 1)"; then
    ok "triage: Widevine via compiled UUID constants"
  else bad "triage-widevine-compiled" "no compiled-UUID Widevine finding"; fi
else skip "triage-widevine-compiled" "FIX_WIDEVINE_COMPILED unset or absent"; fi

# Bundled .swf web content without the AIR descriptor must NOT be
# attributed to Adobe AIR.
if need triage-no-air "${FIX_SWF_CONTENT:-}"; then
  $PY "$SCRIPTS/nar-triage.py" --json "${FIX_SWF_CONTENT}" > "$TMP/triage-noair.json" 2>/dev/null
  if $PY -c "
import json,sys
d=json.load(open('$TMP/triage-noair.json'))
hits=[h for h in d.get('engine_hints',[]) if 'Adobe AIR' in h.get('engine','')]
sys.exit(0 if not hits else 1)"; then
    ok "triage: .swf web content not attributed to Adobe AIR"
  else bad "triage-no-air" "Adobe AIR hint on swf-content fixture"; fi
else skip "triage-no-air" "FIX_SWF_CONTENT unset or absent"; fi

if need triage-kotlin "${FIX_COMPOSE:-}"; then
  $PY "$SCRIPTS/nar-triage.py" --json "$FIX_COMPOSE" > "$TMP/triage-kotlin.json" 2>/dev/null
  if $PY -c "
import json,sys
d=json.load(open('$TMP/triage-kotlin.json'))
hits=[m for m in d.get('dex_markers',[]) if 'Kotlin' in m.get('marker','') and m.get('total_hits',0)>0]
sys.exit(0 if hits else 1)"; then
    ok "triage: Kotlin detected on Compose fixture"
  else bad "triage-kotlin-compose" "no Kotlin marker"; fi
else skip "triage-kotlin-compose" "FIX_COMPOSE unset or absent"; fi

if need triage-nokotlin "${FIX_JAVA:-}"; then
  $PY "$SCRIPTS/nar-triage.py" --json "$FIX_JAVA" > "$TMP/triage-java.json" 2>/dev/null
  if $PY -c "
import json,sys
d=json.load(open('$TMP/triage-java.json'))
hits=[m for m in d.get('dex_markers',[]) if 'Kotlin' in m.get('marker','') and m.get('total_hits',0)>0]
sys.exit(0 if not hits else 1)"; then
    ok "triage: Kotlin correctly absent on Java fixture"
  else bad "triage-kotlin-absent" "Kotlin marker on a pure-Java build"; fi
else skip "triage-kotlin-absent" "FIX_JAVA unset or absent"; fi

if need triage-xapk "${FIX_XAPK:-}"; then
  $PY "$SCRIPTS/nar-triage.py" "$FIX_XAPK" > "$TMP/triage-xapk.log" 2>&1
  if contains "$TMP/triage-xapk.log" "XAPK container"; then
    ok "triage: XAPK container parsed"
  else bad "triage-xapk" "container note missing"; fi
else skip "triage-xapk" "FIX_XAPK unset or absent"; fi

# ---------------------------------------------------------------- strings
if need strings-demo "$DEMO"; then
  $PY "$SCRIPTS/nar-strings.py" "$DEMO" > "$TMP/strings-demo.log" 2>&1
  if contains "$TMP/strings-demo.log" "demo_token_"; then
    ok "strings: planted demo token caught"
  else bad "strings-demo-token" "planted token missing"; fi
else skip "strings-demo-token" "demo fixture absent"; fi

if need strings-keys "${FIX_GAME_UNREAL:-}"; then
  $PY "$SCRIPTS/nar-strings.py" --json "$FIX_GAME_UNREAL" > "$TMP/strings-game.json" 2>/dev/null
  COUNT=$($PY -c "
import json
d=json.load(open('$TMP/strings-game.json'))
print(d['groups']['key_patterns']['count'])" 2>/dev/null || echo -1)
  if [ "$COUNT" -gt 0 ] && [ "$COUNT" -lt 200 ]; then
    ok "strings: game key-pattern hits bounded ($COUNT < 200)"
  else bad "strings-key-hits" "count=$COUNT"; fi
else skip "strings-key-hits" "FIX_GAME_UNREAL unset or absent"; fi

# ---------------------------------------------------------------- compare
if need compare-demo "$DEMO" && need compare-demo2 "$DEMO2"; then
  $PY "$SCRIPTS/nar-compare.py" "$DEMO" "$DEMO2" > "$TMP/compare.log" 2>&1
  if contains "$TMP/compare.log" "Permissions added: android.permission.VIBRATE" \
     && contains "$TMP/compare.log" "methods: 33 -> 35"; then
    ok "compare: added permission + method growth caught"
  else bad "compare-demo" "expected deltas missing"; fi
else skip "compare-demo" "demo pair absent"; fi

# ---------------------------------------------------------------- perms
if need perms-demo "$DEMO"; then
  $PY "$SCRIPTS/nar-perms.py" "$DEMO" > "$TMP/perms-demo.log" 2>&1
  if contains "$TMP/perms-demo.log" "Permissions (2): 0 dangerous"; then
    ok "perms: demo dangerous count (0 of 2)"
  else bad "perms-demo" "dangerous count line mismatch"; fi
else skip "perms-demo" "demo fixture absent"; fi

if need perms-defaults "${FIX_GAME_UNREAL:-}"; then
  $PY "$SCRIPTS/nar-perms.py" "$FIX_GAME_UNREAL" > "$TMP/perms-game.log" 2>&1
  if contains "$TMP/perms-game.log" "platform default; attribute absent"; then
    ok "perms: platform-default wording on absent attributes"
  else bad "perms-defaults" "default wording missing"; fi
else skip "perms-defaults" "FIX_GAME_UNREAL unset or absent"; fi

# ---------------------------------------------------------------- pak
if need pak-list "${FIX_PAK:-}"; then
  $PY "$SCRIPTS/nar-pak.py" "$FIX_PAK" > "$TMP/pak.log" 2>&1
  if contains "$TMP/pak.log" "Entries: 1,598" && contains "$TMP/pak.log" "Encryption: none"; then
    ok "pak: 1,598 entries, encryption none"
  else bad "pak-list" "entry count or encryption line mismatch"; fi
else skip "pak-list" "FIX_PAK unset or absent"; fi

if need pak-extract "${FIX_PAK:-}"; then
  if $PY - "$FIX_PAK" "$SCRIPTS/nar-pak.py" "$TMP/pak-out" <<'PYEOF'
import hashlib, json, struct, subprocess, sys, zlib, os
pak, script, outdir = sys.argv[1], sys.argv[2], sys.argv[3]
listing = json.loads(subprocess.run(
    [sys.executable, script, "--json", pak],
    capture_output=True, text=True, check=True).stdout)
entries = listing.get("entries") or []
cand = next((e for e in entries
             if e.get("compression") == "Zlib"
             and e.get("uncompressed_size_bytes", 0) > 0), None)
if cand is None:
    sys.exit("no Zlib entry to extract")
name = cand["name"]
subprocess.run([sys.executable, script, "--extract", name,
                "--out", outdir, pak],
               capture_output=True, text=True, check=True)
extracted = open(os.path.join(outdir, name), "rb").read()
# independent index parse + decompress (does not import the tool)
data = open(pak, "rb").read()
fi = data.rfind(struct.pack("<I", 0x5A6F12E1))
idx_off, idx_size = struct.unpack_from("<qq", data, fi + 8)
idx = data[idx_off:idx_off + idx_size]
p = 0
ln, = struct.unpack_from("<i", idx, p); p += 4 + ln
count, = struct.unpack_from("<i", idx, p); p += 4
found = None
for _ in range(count):
    ln, = struct.unpack_from("<i", idx, p); p += 4
    nm = idx[p:p + ln - 1].decode("utf-8", "replace"); p += ln
    off, csize, usize = struct.unpack_from("<qqq", idx, p); p += 24
    comp, = struct.unpack_from("<i", idx, p); p += 4 + 20
    blocks = []
    if comp != 0:
        nb, = struct.unpack_from("<i", idx, p); p += 4
        for _ in range(nb):
            s, e = struct.unpack_from("<qq", idx, p); p += 16
            blocks.append((s, e))
    p += 5
    if nm == name:
        found = (off, usize, blocks)
        break
if found is None:
    sys.exit("entry not found by independent parse")
off, usize, blocks = found
raw = b"".join(zlib.decompress(data[s:e] if s >= off else data[off + s:off + e])
               for s, e in blocks)
if len(raw) != usize or len(extracted) != usize:
    sys.exit("size mismatch")
if hashlib.sha256(raw).hexdigest() != hashlib.sha256(extracted).hexdigest():
    sys.exit("sha256 mismatch")
PYEOF
  then ok "pak: extract byte-verified vs independent read"
  else bad "pak-extract" "independent verification failed"; fi
else skip "pak-extract" "FIX_PAK unset or absent"; fi

# ---------------------------------------------------------------- il2cpp
if need il2cpp "${FIX_UNITY:-}"; then
  $PY "$SCRIPTS/nar-il2cpp.py" "$FIX_UNITY" > "$TMP/il2cpp.log" 2>&1
  if contains "$TMP/il2cpp.log" "format version" \
     && contains "$TMP/il2cpp.log" "Il2CppDumper: ran" \
     && contains "$TMP/il2cpp.log" "Types:"; then
    ok "il2cpp: metadata version + dumper summary"
  else bad "il2cpp" "summary lines missing"; fi
else skip "il2cpp" "FIX_UNITY unset or absent"; fi

# ---------------------------------------------------------------- flutter
if need flutter-pos "${FIX_FLUTTER:-}"; then
  $PY "$SCRIPTS/nar-flutter.py" "$FIX_FLUTTER" > "$TMP/flutter.log" 2>&1
  if contains "$TMP/flutter.log" "Dart version:" \
     && contains "$TMP/flutter.log" "AOT snapshot markers:"; then
    ok "flutter: Dart fingerprint on Flutter fixture"
  else bad "flutter-positive" "fingerprint lines missing"; fi
else skip "flutter-positive" "FIX_FLUTTER unset or absent"; fi

if need flutter-neg "$DEMO"; then
  $PY "$SCRIPTS/nar-flutter.py" "$DEMO" > "$TMP/flutter-neg.log" 2>&1
  if contains "$TMP/flutter-neg.log" "NOT FLUTTER"; then
    ok "flutter: clean negative on demo"
  else bad "flutter-negative" "NOT FLUTTER verdict missing"; fi
else skip "flutter-negative" "demo fixture absent"; fi

# ---------------------------------------------------------------- godot
if need godot "${FIX_GODOT_PCK:-}"; then
  $PY "$SCRIPTS/nar-godot.py" "$FIX_GODOT_PCK" > "$TMP/godot.log" 2>&1
  if contains "$TMP/godot.log" "Encryption: no" && contains "$TMP/godot.log" "Files:"; then
    ok "godot: pack listing + encryption flag"
  else bad "godot" "listing or encryption line missing"; fi
else skip "godot" "FIX_GODOT_PCK unset or absent"; fi

# A loose Godot export (project ships under assets/ anchored by
# project.binary, no .pck) must be counted, not reported as 0 files.
if need godot-loose "${FIX_GODOT_LOOSE:-}"; then
  $PY "$SCRIPTS/nar-godot.py" --json "${FIX_GODOT_LOOSE}" > "$TMP/godot-loose.json" 2>/dev/null
  if $PY -c "
import json,sys
d=json.load(open('$TMP/godot-loose.json'))
sys.exit(0 if d.get('is_godot') and (d.get('loose_project_files') or 0) > 100 else 1)"; then
    ok "godot: loose export project files counted"
  else bad "godot-loose" "loose_project_files not >100 on loose-export fixture"; fi
else skip "godot-loose" "FIX_GODOT_LOOSE unset or absent"; fi

# ---------------------------------------------------------------- rn
if need rn-pos "${FIX_RN:-}"; then
  $PY "$SCRIPTS/nar-rn.py" "$FIX_RN" > "$TMP/rn.log" 2>&1
  if contains "$TMP/rn.log" "Engine: Hermes" \
     && contains "$TMP/rn.log" "Hermes bytecode version:"; then
    ok "rn: Hermes detection + bytecode version"
  else bad "rn-positive" "Hermes lines missing"; fi
else skip "rn-positive" "FIX_RN unset or absent"; fi

if need rn-neg "$DEMO"; then
  $PY "$SCRIPTS/nar-rn.py" "$DEMO" > "$TMP/rn-neg.log" 2>&1
  if contains "$TMP/rn-neg.log" "NOT REACT NATIVE"; then
    ok "rn: clean negative on demo"
  else bad "rn-negative" "NOT REACT NATIVE verdict missing"; fi
else skip "rn-negative" "demo fixture absent"; fi

# Unity Addressables *.bundle files share the extension with RN
# bundles; content validation must reject them as UnityFS, never
# claim a React Native engine.
if need rn-unity "${FIX_UNITY_BUNDLES:-}"; then
  $PY "$SCRIPTS/nar-rn.py" "${FIX_UNITY_BUNDLES}" > "$TMP/rn-unity.log" 2>&1
  if contains "$TMP/rn-unity.log" "NOT REACT NATIVE" \
     && contains "$TMP/rn-unity.log" "Unity asset bundle"; then
    ok "rn: Unity Addressables bundles rejected as UnityFS"
  else bad "rn-unity-bundles" "Unity bundles not rejected with UnityFS note"; fi
else skip "rn-unity-bundles" "FIX_UNITY_BUNDLES unset or absent"; fi

# ---------------------------------------------------------------- frameworks
# Doctored demo copies under $NAR_FIXTURES/frameworks/, one planted
# marker family each (built locally with the zip-append technique).
FW="$F/frameworks"
fw_case() {
  # $1 fixture file name, $2 pool (hint|dex), $3 expected name
  local file="$FW/$1"
  if [ ! -f "$file" ]; then skip "frameworks-$1-$3" "fixture absent"; return; fi
  $PY "$SCRIPTS/nar-triage.py" --json "$file" > "$TMP/fw.json" 2>/dev/null
  if $PY - "$TMP/fw.json" "$2" "$3" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
pool = ([h["engine"] for h in d.get("engine_hints", [])]
        if sys.argv[2] == "hint"
        else [m["marker"] for m in d.get("dex_markers", [])])
sys.exit(0 if sys.argv[3] in pool else 1)
PYEOF
  then ok "frameworks: $3 detected ($1)"
  else bad "frameworks-$1" "$3 not detected"; fi
}
fw_case xamarin.apk hint "Xamarin / .NET"
fw_case cordova.apk hint "Cordova (hybrid)"
fw_case capacitor.apk hint "Capacitor (hybrid)"
fw_case qt.apk hint "Qt for Android"
fw_case defold.apk hint "Defold"
fw_case renpy.apk hint "Ren'Py"
fw_case rpgmaker.apk hint "RPG Maker (web export)"
fw_case kivy.apk hint "Embedded Python"
if [ -f "$FW/dexmarkers.apk" ]; then
  $PY "$SCRIPTS/nar-triage.py" --json "$FW/dexmarkers.apk" > "$TMP/fw-dex.json" 2>/dev/null
  if $PY - "$TMP/fw-dex.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
pool = {m["marker"] for m in d.get("dex_markers", [])}
want = {"Xamarin / .NET runtime", "Cordova", "Capacitor",
        "Qt for Android", "Kivy", "Ren'Py runtime", "EasyRPG Player"}
sys.exit(0 if want <= pool else 1)
PYEOF
  then ok "frameworks: all planted DEX runtime markers detected"
  else bad "frameworks-dexmarkers" "a planted runtime marker was missed"; fi
else skip "frameworks-dexmarkers" "fixture absent"; fi

# ------------------------------------------------- 16 KB alignment line
if need align16k "$DEMO"; then
  $PY "$SCRIPTS/nar-triage.py" --json "$DEMO" > "$TMP/align.json" 2>/dev/null
  if $PY - "$TMP/align.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
for p in d.get("protections", []):
    if p.get("category") == "native_hardening":
        sys.exit(0 if any("16 KB page alignment:" in e
                          for e in p.get("evidence", [])) else 1)
sys.exit(1)
PYEOF
  then ok "triage: 16 KB page-alignment evidence present"
  else bad "triage-16k" "alignment evidence line missing"; fi
else skip "triage-16k" "demo fixture absent"; fi

# ------------------------------------------------------------- form factor
if need formfactor "${FIX_TV:-}"; then
  $PY "$SCRIPTS/nar-triage.py" --json "$FIX_TV" > "$TMP/ff.json" 2>/dev/null
  if $PY - "$TMP/ff.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
ff = (d.get("badging") or {}).get("form_factors") or []
sys.exit(0 if "Android TV" in ff else 1)
PYEOF
  then ok "triage: Android TV form factor from leanback feature"
  else bad "triage-form-factor" "Android TV not surfaced"; fi
else skip "triage-form-factor" "FIX_TV unset or absent"; fi

# ---------------------------------------------------------------- analyze
analyze_case() {
  # $1 case label, $2 fixture
  $PY "$SCRIPTS/nar-analyze.py" --out "$TMP/analyze-$1" "$2" > "$TMP/analyze-$1.log" 2>&1
  local md="$TMP/analyze-$1/report.md" js="$TMP/analyze-$1/report.json"
  if [ -f "$md" ] && [ -f "$js" ] \
     && contains "$md" "## Identity" \
     && contains "$md" "## Protections" \
     && contains "$md" "## Limitations and unknowns"; then
    ok "analyze: $1 report with identity/protections/limitations"
  else
    bad "analyze-$1" "report or required section missing"
  fi
}
if need analyze-app "${FIX_APP:-}"; then analyze_case app "$FIX_APP"
else skip "analyze-app" "FIX_APP unset or absent"; fi
if need analyze-game "${FIX_GAME:-}"; then analyze_case game "$FIX_GAME"
else skip "analyze-game" "FIX_GAME unset or absent"; fi

# ---------------------------------------------------------------- input (2.0)
# Synthetic inputs are built by the harness itself: no binary
# fixtures ship in the repo for these cases.
$PY - "$TMP" <<'PYEOF'
import os, struct, sys, zipfile
tmp = sys.argv[1]
with zipfile.ZipFile(os.path.join(tmp, "synth.apk"), "w") as zf:
    zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
    zf.writestr("classes.dex", b"dex\n039\x00" + b"\x00" * 120)
with zipfile.ZipFile(os.path.join(tmp, "evil.zip"), "w") as zf:
    zf.writestr("../evil.txt", b"x")
    zf.writestr("ok.txt", b"y")
with open(os.path.join(tmp, "bare.dex"), "wb") as fh:
    fh.write(b"dex\n039\x00" + b"\x00" * 120)
with open(os.path.join(tmp, "plain.bin"), "wb") as fh:
    fh.write(b"no signature here")
PYEOF
input_ok=1
$PY "$SCRIPTS/nar-input.py" identify --json "$TMP/synth.apk" > "$TMP/input-apk.json" 2>/dev/null || input_ok=0
$PY "$SCRIPTS/nar-input.py" identify --json "$TMP/bare.dex" > "$TMP/input-dex.json" 2>/dev/null || input_ok=0
$PY "$SCRIPTS/nar-input.py" identify --json "$TMP/plain.bin" > "$TMP/input-unknown.json" 2>/dev/null || input_ok=0
if [ "$input_ok" -eq 1 ] && $PY - "$TMP" <<'PYEOF'
import json, sys
tmp = sys.argv[1]
a = json.load(open(f"{tmp}/input-apk.json"))
d = json.load(open(f"{tmp}/input-dex.json"))
u = json.load(open(f"{tmp}/input-unknown.json"))
sys.exit(0 if (a["format"] == "apk" and d["format"] == "dex"
               and u["format"] == "unknown") else 1)
PYEOF
then ok "input: signature identification (apk/dex/unknown)"
else bad "input-identify" "a synthetic format verdict was wrong"; fi

$PY "$SCRIPTS/nar-input.py" extract "$TMP/evil.zip" --out "$TMP/evil-out" > "$TMP/input-extract.log" 2>&1
if contains "$TMP/input-extract.log" "REJECTED ../evil.txt" \
   && [ ! -e "$TMP/evil.txt" ] && [ -f "$TMP/evil-out/ok.txt" ]; then
  ok "input: traversal entry rejected and reported on extract"
else bad "input-extract-safety" "traversal entry not handled safely"; fi

if need input-duplicates "$DEMO"; then
  cp "$DEMO" "$TMP/demo-copy.apk"
  $PY "$SCRIPTS/nar-input.py" duplicates "$DEMO" "$TMP/demo-copy.apk" > "$TMP/input-dup.log" 2>&1
  if contains "$TMP/input-dup.log" "1 duplicate group"; then
    ok "input: duplicate detection by hash"
  else bad "input-duplicates" "identical copies not grouped"; fi
else skip "input-duplicates" "demo fixture absent"; fi

# ------------------------------------------------- unreal iostore (2.1.0)
# Synthetic container built byte-exact by the unit-test builder;
# parsed back through nar-unreal in bare and in-APK modes.
$PY - "$SKILL" "$TMP" <<'PYEOF'
import sys, zipfile
skill, tmp = sys.argv[1], sys.argv[2]
sys.path.insert(0, skill + "/tests/unit")
sys.path.insert(0, skill + "/scripts")
import test_iostore
utoc, ucas = test_iostore.build_current()
open(tmp + "/case.utoc", "wb").write(utoc)
open(tmp + "/case.ucas", "wb").write(ucas)
with zipfile.ZipFile(tmp + "/iostore.apk", "w") as zf:
    zf.writestr("assets/case.utoc", utoc)
    zf.writestr("assets/case.ucas", ucas)
PYEOF
if [ -f "$TMP/case.utoc" ]; then
  $PY "$SCRIPTS/nar-unreal.py" "$TMP/case.utoc" --json > "$TMP/iostore.json" 2>&1
  $PY "$SCRIPTS/nar-unreal.py" "$TMP/iostore.apk" --json > "$TMP/iostore-apk.json" 2>&1
  if $PY - "$TMP" <<'PYEOF'
import json, sys
tmp = sys.argv[1]
r = json.load(open(tmp + "/iostore.json"))
c = r["iostore_containers"][0]
assert c["entry_count"] == 3, c.get("entry_count")
paths = {e.get("file") or "" for e in c["entries"]}
assert any(p.endswith("Content/ChunkA.uasset") for p in paths), paths
r2 = json.load(open(tmp + "/iostore-apk.json"))
assert r2["iostore_containers"], r2.get("iostore_containers")
assert r2["iostore_containers"][0]["entry_count"] == 3
PYEOF
  then ok "unreal-iostore: synthetic container parsed (bare + APK)"
  else bad "unreal-iostore" "container inventory mismatch"; fi
else skip "unreal-iostore" "synthetic container build failed"; fi

# ------------------------------------------------ unreal uasset (unreleased)
# Synthetic packages built byte-exact by the unit-test builders;
# parsed back through nar-unreal as a bare package, as a split
# .uasset+.uexp pair, loose inside an APK, and as an
# ExportBundleData chunk inside a synthetic IoStore container.
$PY - "$SKILL" "$TMP" <<'PYEOF'
import struct, sys, zipfile
skill, tmp = sys.argv[1], sys.argv[2]
sys.path.insert(0, skill + "/tests/unit")
sys.path.insert(0, skill + "/scripts")
import test_uasset
from narlib.uasset import parse_package

ue4 = test_uasset.build_ue4()
ue5 = test_uasset.build_ue5()
open(tmp + "/pkg-ue4.uasset", "wb").write(ue4)
ths = parse_package(ue4)["summary"]["total_header_size"]
open(tmp + "/pkg-split.uasset", "wb").write(ue4[:ths])
open(tmp + "/pkg-split.uexp", "wb").write(ue4[ths:])
with zipfile.ZipFile(tmp + "/uasset.apk", "w") as zf:
    zf.writestr("assets/Content/PkgUE4.uasset", ue4)
    zf.writestr("assets/Content/PkgUE5.uasset", ue5)

def fstring(s):
    raw = s.encode() + b"\x00"
    return struct.pack("<i", len(raw)) + raw

INV = 0xFFFFFFFF
dir_index = b"".join([
    fstring("../../../PkgGame/"),
    struct.pack("<I", 2),
    fstring(""), struct.pack("<III", 1, INV, INV),
    fstring("Content"), struct.pack("<III", INV, 0, INV),
    struct.pack("<I", 1),
    fstring("SynthMesh.uasset"), struct.pack("<II", INV, 0),
])
hdr = bytearray()
hdr += b"-==--==--==--==-"
hdr += bytes([6, 0]) + struct.pack("<H", 0)      # version 6
hdr += struct.pack("<I", 144)                    # TocHeaderSize
hdr += struct.pack("<I", 1)                      # entry count
hdr += struct.pack("<I", 1)                      # block count
hdr += struct.pack("<I", 12)                     # block entry size
hdr += struct.pack("<I", 0)                      # method names
hdr += struct.pack("<I", 32)                     # method name len
hdr += struct.pack("<I", 65536)                  # block size
hdr += struct.pack("<I", len(dir_index))
hdr += struct.pack("<I", 1)                      # partitions
hdr += struct.pack("<Q", 0x1234)                 # container id
hdr += b"\x00" * 16                              # encryption GUID
hdr += bytes([0x08, 0]) + struct.pack("<H", 0)   # flags: Indexed
hdr += struct.pack("<I", 0)                      # hash seeds
hdr += struct.pack("<Q", 0xFFFFFFFFFFFFFFFF)     # partition size
hdr += struct.pack("<I", 0)                      # without-hash
hdr += struct.pack("<I", 0) + b"\x00" * 40       # reserved
assert len(hdr) == 144, len(hdr)
chunk_id = struct.pack("<Q", 0xABC) + (0).to_bytes(2, "big") \
    + b"\x00" + bytes([1])                       # ExportBundleData
offsets = (0).to_bytes(5, "big") + len(ue4).to_bytes(5, "big")
block = (0).to_bytes(5, "little") \
    + len(ue4).to_bytes(3, "little") \
    + len(ue4).to_bytes(3, "little") + bytes([0])
utoc = bytes(hdr) + chunk_id + offsets + block + dir_index \
    + b"\x00" * 33                               # one meta record
open(tmp + "/pkg.utoc", "wb").write(utoc)
open(tmp + "/pkg.ucas", "wb").write(ue4)
PYEOF
if [ -f "$TMP/pkg-ue4.uasset" ]; then
  $PY "$SCRIPTS/nar-unreal.py" "$TMP/pkg-ue4.uasset" --json > "$TMP/uasset.json" 2>&1
  $PY "$SCRIPTS/nar-unreal.py" "$TMP/pkg-split.uasset" --json > "$TMP/uasset-split.json" 2>&1
  $PY "$SCRIPTS/nar-unreal.py" "$TMP/uasset.apk" --json > "$TMP/uasset-apk.json" 2>&1
  $PY "$SCRIPTS/nar-unreal.py" "$TMP/pkg.utoc" --json > "$TMP/uasset-iostore.json" 2>&1
  if $PY - "$TMP" <<'PYEOF'
import json, sys
tmp = sys.argv[1]
r = json.load(open(tmp + "/uasset.json"))
assert r["verdict"] == "package", r.get("verdict")
p = r["packages"][0]
assert p["counts"]["names"] == 33, p["counts"]
assert p["counts"]["imports"] == 3 and p["counts"]["exports"] == 2
tags = {t["name"]: t for t in p["exports"][0]["properties"]["tags"]}
assert tags["MaxHealth"]["value"] == 250
r = json.load(open(tmp + "/uasset-split.json"))
assert r["packages"][0]["exports"][0]["data_location"]["file"] \
    == "uexp"
r = json.load(open(tmp + "/uasset-apk.json"))
assert r["package_file_count"] == 2, r.get("package_file_count")
assert len(r["packages"]) == 2
r = json.load(open(tmp + "/uasset-iostore.json"))
ip = r["iostore_packages"]
assert len(ip) == 1, ip
assert ip[0]["counts"]["names"] == 33, ip[0].get("counts")
assert ip[0]["entry"].endswith("Content/SynthMesh.uasset")
PYEOF
  then ok "unreal-uasset: synthetic packages parsed (bare, split, APK, IoStore)"
  else bad "unreal-uasset" "package inspection mismatch"; fi
else skip "unreal-uasset" "synthetic package build failed"; fi

# ------------------------------------------------- il2cpp cpp2il (2.1.0)
CPP2IL_BIN="${NAR_CPP2IL:-}"
[ -z "$CPP2IL_BIN" ] && [ -x "$HOME/workspace/tools/cpp2il/Cpp2IL" ] \
  && CPP2IL_BIN="$HOME/workspace/tools/cpp2il/Cpp2IL"
[ -z "$CPP2IL_BIN" ] && command -v Cpp2IL >/dev/null 2>&1 \
  && CPP2IL_BIN="$(command -v Cpp2IL)"
if need il2cpp-cpp2il "${FIX_UNITY:-}" && [ -n "$CPP2IL_BIN" ]; then
  $PY "$SCRIPTS/nar-il2cpp.py" "$FIX_UNITY" --backend cpp2il --json \
    > "$TMP/il2cpp-cpp2il.json" 2>&1
  if $PY - "$TMP" <<'PYEOF'
import json, sys
r = json.load(open(sys.argv[1] + "/il2cpp-cpp2il.json"))
assert r["backend"] == "cpp2il", r.get("backend")
s = r["summary"]
assert s and s["types"] > 1000, s
assert s["method_count_basis"].startswith("MethodDef"), s
PYEOF
  then ok "il2cpp-cpp2il: Cpp2IL backend summary on Unity fixture"
  else bad "il2cpp-cpp2il" "backend summary missing or implausible"; fi
else skip "il2cpp-cpp2il" "Cpp2IL binary or FIX_UNITY absent"; fi

# ------------------------------------------------- dex disassembly
# Targeted disassembly of the demo fixture through nar-dex's
# own disassembler (narlib.dexdis): selection must decode,
# an invoke target must come back resolved, and the unscoped
# form must refuse (full-corpus disassembly is opt-in only).
if need dex-disasm "$DEMO"; then
  $PY "$SCRIPTS/nar-dex.py" --json --disassemble \
    --disasm-class nardemo "$DEMO" > "$TMP/dexdis.json" 2>/dev/null
  if $PY - "$TMP" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1] + "/dexdis.json"))
dis = d["dex_files"][0]["disassembly"]
assert dis["mode"] == "targeted", dis["mode"]
assert dis["methods_decoded"] > 0, dis
assert dis["methods_failed"] == 0, dis["failures"]
texts = [e["text"] for m in dis["methods"]
         for e in m["instructions"]]
assert any(t.startswith("invoke-") and "->" in t
           for t in texts), texts[:5]
PYEOF
  then ok "dex-disasm: targeted disassembly decodes + resolves on demo"
  else bad "dex-disasm" "targeted disassembly missing or unresolved"; fi
  if $PY "$SCRIPTS/nar-dex.py" "$DEMO" --disassemble \
       > /dev/null 2>&1; then
    bad "dex-disasm-scope" "unscoped --disassemble did not refuse"
  else
    ok "dex-disasm: unscoped disassembly refused"
  fi
else skip "dex-disasm" "demo fixture absent"; fi

# ---------------------------------------------------------------- frida
if command -v node >/dev/null 2>&1; then
  FRIDA_OK=1
  for js in "$SCRIPTS"/frida/*.js; do
    node --check "$js" 2>/dev/null || FRIDA_OK=0
  done
  if [ "$FRIDA_OK" -eq 1 ]; then ok "frida: node --check on all scripts"
  else bad "frida" "a Frida script fails node --check"; fi
else skip "frida" "node not installed"; fi

# ---------------------------------------------------------------- summary
echo "-----------------------------------------------------"
printf 'e2e matrix: %d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
if [ "$FAIL" -gt 0 ]; then
  printf 'failed cases:%s\n' "$FAILED_CASES"
  exit 1
fi
exit 0
