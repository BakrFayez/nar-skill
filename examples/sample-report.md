# NAR report: Sample App 1.0 (example)

This is a filled example report. Every value below was observed on a
test APK with the NAR scripts and tools. App identity is left out on
purpose: the shape of the report is the example, not the app. An
appendix with observed values from a test bundle follows at the end.

## Identity

- File: example.apk
- SHA-256: <64-hex digest of the file>
- Package: com.example.app, v1.0 (version code 1)
- SDK: min 24, target 34. Label: Sample App
- Size: 1,632,491 bytes. ZIP entries: 32
- DEX: 1 file, classes.dex, 227,112 bytes
- Native libs: 0. Pure DEX app.
- Engine: none detected. No Unity, Unreal, Godot, or Flutter markers.
- Signature: v2 and v3 verified. v1 not verified (see finding 4).
- Signer: CN=Example, O=Example. Certificate SHA-256:
  <64-hex fingerprint>. RSA 2048.
- zipalign: verification successful.

## Findings

### 1. Single-activity app with local actions (Confidence: High)

- Observation: the manifest declares one launcher activity,
  `.MainActivity`, and one provider, `.FilesProvider`. jadx
  decompiled 125 Java files, including `MainActivity`,
  `ApiClient`, and `LocalStore` under `com.example.app`.
- Observation: `MainActivity` holds a configuration string that
  defines local actions (create_file, read_file, download,
  http_get, notify, vibrate, timer, alarm, and others).
- Evidence: `AndroidManifest.xml` (apktool decode),
  `sources/com/example/app/MainActivity.java` (jadx 1.5.3).
- Inference: the app is a client that talks to an upstream
  service and runs local actions on the device.

### 2. Five permissions, all consistent with the features (Confidence: High)

- Observation: INTERNET, ACCESS_NETWORK_STATE, POST_NOTIFICATIONS,
  VIBRATE, and com.android.alarm.permission.SET_ALARM.
- Evidence: `aapt2 dump badging` and decoded `AndroidManifest.xml`.
- Inference: notifications map to the `notify` action, vibration to
  the `vibrate` action, and the alarm permission to the `timer` and
  `alarm` actions. No permission looks unused at this level.

### 3. No native code and no game engine (Confidence: High)

- Observation: triage found zero `.so` files and zero engine
  markers. The DEX is small (227,112 bytes) and the smali tree has
  234 files, mostly the app plus the commonmark library.
- Evidence: `nar-triage.py` output, apktool `smali/` inventory.
- Inference: all behavior is in DEX. Native analysis does not apply
  to this build.

### 4. v2 and v3 signatures verify, v1 does not (Confidence: Medium)

- Observation: `apksigner verify` reports v2 true, v3 true, v1
  false, v3.1 false. `META-INF/` still contains CERT.RSA,
  CERT.SF, and MANIFEST.MF.
- Evidence: `apksigner verify --verbose --print-certs` (build-tools
  35.0.0).
- Inference: the APK is signed for modern Android (v2 and v3). The
  v1 files are present but v1 verification reports false, so v1
  should not be relied on for this file. The signer fingerprint is
  the same across the v2 and v3 blocks, so identity is consistent.

### 5. Assets are icons and a logo (Confidence: High)

- Observation: `assets/` holds 21 files: an `icons/` directory and
  `logo.png`. `res/` holds launcher icons and values only.
- Evidence: apktool decode inventory.
- Inference: no bundled content packs, no downloaded-content
  staging in this build.

## Limitations and unknowns

- DEX was decompiled and read only at class level. Method-level
  behavior (network calls, storage, session handling) was not
  traced in this example.
- No runtime check was done. Nothing here proves runtime behavior.
- The v1 verification result was not root-caused. It does not block
  install on modern Android, which uses v2 and v3.

## Next steps

- To trace a feature end to end, follow the DEX guide from
  `MainActivity` into `ApiClient` and `LocalStore`.
- To check the network surface, search jadx output for URL strings
  and `HttpURLConnection` use.

## Appendix: test bundle (observed triage values)

Triage and bundletool output from a test bundle:

- File: example.aab
- SHA-256: <64-hex digest of the file>
- Size: 14,095,721 bytes. ZIP entries: 142
- Package: com.example.game, v1.0 (version code 1). Min SDK 24,
  target SDK 34, compile SDK 34. From `bundletool dump manifest`.
- DEX: 1 file, base/dex/classes.dex, 132,808 bytes.
- Native libs: 0. Assets: 117 files. res: 17 files.
- META-INF: CERT.RSA, CERT.SF, MANIFEST.MF.
- Manifest notes: fullscreen theme, OpenGL ES 2.0 feature marked
  not required, one exported `.MainActivity`.
