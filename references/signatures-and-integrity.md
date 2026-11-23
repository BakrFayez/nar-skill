# Signatures and integrity

This guide covers verification and analysis of APK signatures only:
which schemes are present, whose certificate signed the APK, and
whether the signed bytes still match. It does not cover bypassing,
removing, or forging signatures.

## The schemes

Android has four signing schemes that can coexist on one APK (v1, v2,
v3, v3.1), plus v4 for fs-verity and an optional source stamp:

| Scheme | Where it lives | Notes |
|---|---|---|
| v1 (JAR signing) | `META-INF/*.SF`, `*.RSA`/`*.DSA`/`*.EC`, `MANIFEST.MF` | Signs each ZIP entry's digest. Oldest; still common. |
| v2 | APK Signing Block before the Central Directory, block ID `0x7109871a` | Signs the whole APK except the block itself. SHA-256 digests over 1 MB chunks; RSA/ECDSA, algorithm ID `0x0103` is SHA256-with-RSA. Required on Android 7.0+ for most installs. |
| v3 | Signing block, ID `0xf05368c0` | Like v2, plus key-rotation lineage: the signer can prove a new key descends from the old one. |
| v3.1 | Signing block, ID `0x1b93ad61` | Rotation that targets Android 13+ only, so old devices keep trusting the old key. |
| v4 | Separate `.idsig` file beside the APK | fs-verity hash tree for streaming installs (Android 11+). Needs the `.idsig` file; the APK alone does not carry it. |
| Source stamp | Signing block, ID `0x6dff800d` (v2) or `0x2b09189e` (v1) | Optional stamp of the source of the APK (for example, a store). Presence is informational. |
| Verity padding | Signing block, ID `0x42726577` | Alignment padding. Not a signature. Ignore it when inventorying schemes. |

`apksigner` reports all of this at once:

```bash
apksigner verify --verbose --print-certs app.apk
```

Output to record: verified or not, per-scheme present/absent, each
signer's certificate SHA-256 fingerprint and subject/issuer, and the
v3 rotation lineage when present.

## What verification proves (and does not prove)

- `apksigner verify` succeeding proves self-consistency: the bytes
  match the digests the signer signed, and the certificate chain
  parses. It does not prove the signer is who they claim to be, and
  it does not prove the app is safe. A certificate is self-signed
  unless you compare its fingerprint against a known-good value from
  the developer or a store listing.
- A fingerprint match against a known value (for example, the
  developer's published SHA-256) is identity evidence. A mismatch
  against a known value is a strong finding: different signer.
- A v3 lineage proves the new key was signed by the old key. It does
  not prove the old key was legitimate.
- `zipalign -c -v 4 app.apk` checks 4-byte alignment of uncompressed
  entries. Misalignment is a build-quality finding (slower loads,
  higher memory), not a security finding.

## Reading certificates

```bash
apksigner verify --print-certs app.apk
keytool -printcert -jarfile app.apk
```

Record for each signer: SHA-256 fingerprint, subject DN, issuer DN,
serial number, validity dates. The v1 certificate comes from the
PKCS#7 block in `META-INF/*.RSA`; v2/v3 certificates come from the
signing block. They are usually the same key, but check: a mismatch
between v1 and v2 signers is a finding.

## Platform signatures (system apps)

System apps are signed with the platform key of the firmware build
(or a vendor key for vendor apps). To check whether an APK carries a
platform signature, compare its signer fingerprint with a known
platform-signed system app from the same device (for example the
Settings app):

```bash
adb shell pm path com.android.settings
adb pull /system/priv-app/Settings/Settings.apk
apksigner verify --print-certs Settings.apk
apksigner verify --print-certs app.apk
# Same SHA-256 fingerprint on both: app.apk is platform-signed.
```

What the comparison tells you:

- Same fingerprint as the platform certificate: the APK can hold
  `signature`-level permissions and run as a system app.
- Different fingerprint: the APK is not platform-signed, whatever
  its install location. An APK placed in `/system/app` without the
  platform key does not gain system privileges.
- AOSP test keys: some firmware builds ship signed with the
  well-known public AOSP test keys. A platform signature that
  matches a public test key proves nothing about the firmware
  vendor; record it as a finding, not as trust.

Do not assert a platform signature from the install path alone.
The fingerprint comparison is the evidence.

## Common findings

- Unsigned APK (`apksigner verify` fails with no signature): expected
  for intermediate build outputs (`*_unsigned.apk`). Never ship one.
- v1-only signing on a modern app: works, but weaker (entry-level
  digests only; some tampering is possible without breaking v1).
- Debug certificate (`CN=Android Debug`): a debug build. Never treat
  its behavior as release behavior.
- Certificate changed between versions without v3 lineage: the app
  cannot update over the old install; users must uninstall first.
  Flag it in version comparisons.
- Signature valid but content suspicious: signature says nothing
  about content. Verify the signer, then analyze the content on its
  own merits.

## Re-signing your own builds

When you rebuild your own app (for example, after modifying your own
APK tooling output), sign with your own keystore:

```bash
apksigner sign --ks my.keystore --out app-signed.apk app.apk
apksigner verify --verbose app-signed.apk
```

Keep the keystore safe and backed up: losing it means you can never
publish an update under the same identity. Never sign someone else's
app with your key, and never ship an app signed with a key you do
not own.
