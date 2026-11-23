# Quick triage: example session

This is a realistic command session for the first pass on an APK. Replace
`app.apk` with your file. Commands run from the repo root unless noted.

## 1. Check the toolchain

```bash
bash scripts/nar-doctor.sh
```

Expected output when everything is installed:

```text
NAR doctor: Nirous Android Reversing toolchain check
====================================================
OK       java       java 21.0.13.1 (/usr/bin/java)
OK       apktool    apktool 2.7.0-dirty (/usr/bin/apktool)
OK       jadx       jadx 1.5.3 (.../tools/jadx-cli/bin/jadx)
OK       aapt2      aapt2 (/usr/bin/aapt2)
OK       apksigner  apksigner (.../build-tools/35.0.0/apksigner)
OK       zipalign   zipalign (.../build-tools/35.0.0/zipalign)
OK       python3    python3 Python 3.12.3 (/usr/bin/python3)
OK       adb        adb (.../platform-tools/adb)
OK       frida      frida 17.27.4 (.../tools/frida-venv/bin/frida)
OK       ghidra     ghidra 12.2 (REA engines path)
OK       kuna       kuna (REA engines path)
OK       bundletool bundletool 1.18.1 (tools path)
OK       il2cppdumper il2cppdumper (tools path; run with dotnet)
OK       mitmproxy  mitmproxy (tools venv)
OK       tshark     tshark (/usr/bin/tshark)
OK       godotpcktool godotpcktool (tools path)
OK       gdre       gdre (tools path; keep gdre_tools.pck beside the binary)
OK       hermes-dec hermes-dec (tools path; set PYTHONPATH to the install dir)
-----------------------------------------------------
Core toolchain: READY
```

`OPTIONAL` lines are fine. `MISSING` lines are not: fix those before
going on. See `references/setup-and-doctor.md`.

## 2. Triage the APK

```bash
python3 scripts/nar-triage.py app.apk
```

For a small pure-Java app you get something like this (observed on
a small test APK):

```text
NAR triage: example.apk
=======================
SHA-256: <64-hex digest of the file>
Size:    1,632,491 bytes
Package: com.example.app  v1.0 (code 1)
SDK:     min 24 / target 34  label: Sample App
Permissions (5): android.permission.ACCESS_NETWORK_STATE, android.permission.INTERNET, android.permission.POST_NOTIFICATIONS, android.permission.VIBRATE, com.android.alarm.permission.SET_ALARM
ZIP entries: 32  |  AndroidManifest.xml: yes  |  resources.arsc: yes
DEX: 1 file(s), 227,112 bytes total  |  format version(s): 037
  - classes.dex  (DEX 037, 227,112 bytes)
Native libs: 0 file(s)
  (none: pure DEX app)
META-INF (3): META-INF/CERT.RSA, META-INF/CERT.SF, META-INF/MANIFEST.MF
Signing files: META-INF/CERT.RSA, META-INF/CERT.SF, META-INF/MANIFEST.MF
Signature schemes (apksigner): v1 no, v2 yes, v3 yes, v3.1 no, v4 no  |  signers: 1  |  verifies
Assets: 21 file(s)  |  res/: 5 file(s)  |  other: 2 file(s)
```

For a game you would also see native libs per ABI, asset bundles, and
engine hints, for example `Unity (IL2CPP): 2 marker(s)`.

JSON output for scripts and agents:

```bash
python3 scripts/nar-triage.py app.apk --json
```

## 3. Decode the manifest and resources

```bash
mkdir -p work
apktool d app.apk -o work/apktool
grep -o 'package="[^"]*"' work/apktool/AndroidManifest.xml
grep -c 'uses-permission' work/apktool/AndroidManifest.xml
```

## 4. Decompile the code

```bash
jadx -d work/jadx app.apk
find work/jadx/sources -iname "*main*" | head
grep -r "https://" work/jadx/sources/ | head -10
```

## 5. Check the signature

```bash
apksigner verify --verbose --print-certs app.apk
zipalign -c -v 4 app.apk | tail -2
```

## 6. Write the report

Use the template in `references/evidence-workflows.md`. A filled
example is in `examples/sample-report.md`. Record the SHA-256, the
findings with evidence cites, and what you did not check.
