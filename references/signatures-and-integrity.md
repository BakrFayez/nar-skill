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

### What each scheme actually protects

- **v1** digests each ZIP entry individually and signs the manifest
  of digests. It does not protect the ZIP structure itself: entries
  can be added, removed, or reordered without breaking v1, and the
  digests are computed over uncompressed content, so it says nothing
  about how bytes sit in the file. Weakest scheme; kept for old
  devices.
- **v2** digests the whole APK as byte ranges (everything except the
  signing block itself) in 1 MB chunks. Any change anywhere outside
  the block breaks it. This is the first scheme that protects the
  file as a whole, which is also why alignment must happen *before*
  signing (below).
- **v3** is v2 plus two things: per-signer SDK-range targeting (a
  signer can say "trust this key only from API N") and the key
  rotation lineage, a signed proof chain from an old key to a new
  one.
- **v3.1** is a second, independent rotation lineage that only
  Android 13+ reads, so a rotation can target new devices while old
  devices keep following the v3 lineage to the original key.
- **v4** signs nothing inside the APK: it is a Merkle hash tree of
  the APK in a sidecar `.idsig` file, letting the fs-verity kernel
  feature verify pages as they are read during streaming /
  incremental installs. Without the sidecar, v4 does not exist.
- **Source stamp** is a store's or distributor's countersignature
  in the signing block. It attests where the APK came from, not who
  built it, and the platform does not require it.

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

## Signing your own builds: the full workflow

This section is for signing **your own** apps and for verifying
signatures during analysis. The boundary is exact: sign builds you
own, verify any signature you need to read — never re-sign someone
else's app to defeat its signature checks, never strip or kill
another app's verification, and never present a re-signed build as
the original developer's work.

### Order of operations: align, sign, verify

```bash
zipalign -P 16 -f -v 4 app-unsigned.apk app-aligned.apk
apksigner sign --ks my.keystore --out app.apk app-aligned.apk
apksigner verify --verbose --print-certs app.apk
```

- `zipalign` rewrites ZIP entry offsets so uncompressed entries
  (especially native libraries) start on page boundaries. `-P 16`
  aligns library entries to 16 KB for the page-size requirement in
  the modern guide.
- Alignment must come **before** signing: v2+ digests cover the
  file's byte layout, so aligning after signing invalidates the
  signature. v1 alone would survive it; v2/v3 do not.
- Verify last, on the exact file you ship, and record the
  fingerprint output (below).

### apksigner sign options that matter

```bash
apksigner sign --ks release.keystore --ks-key-alias release \
  --v1-signing-enabled true \
  --v2-signing-enabled true \
  --v3-signing-enabled true \
  --out app.apk app-aligned.apk
```

- Scheme switches (`--v1/v2/v3-signing-enabled`) decide which
  schemes are written. Defaults depend on `minSdkVersion`: v1 is
  added when old devices must install the APK; v2 is the baseline;
  v3 is added when the APK targets devices that read it.
- `--min-sdk-version` / `--max-sdk-version` on sign override the
  values apksigner infers from the APK when it chooses schemes.
- Multiple signers: repeat `--next-signer` blocks. Rare outside
  shared-signature system builds.

### Keystore and certificate analysis

```bash
keytool -list -v -keystore release.keystore -alias release
keytool -exportcert -keystore release.keystore -alias release | keytool -printcert
```

Read from a certificate: the SHA-256 fingerprint (the identity
everyone compares), the subject DN (`CN=`, `O=`, `OU=`, `L=`,
`ST=`, `C=` — who the key claims to be; self-signed keys claim
whatever their creator typed), the issuer DN (equal to the subject
on self-signed keys), the serial, and the validity window.

Expiry works differently than on the web: Android does **not**
reject an app signature because the certificate expired after
signing — install and update checks compare key identity, not
dates. An expired certificate is still a build-hygiene finding
(stores warn about short validity), not a verification failure.
Record the dates; do not over-claim what they mean.

For a signed APK, the same facts come from
`apksigner verify --print-certs` (shown earlier); triage also
inventories the schemes and the signer count.

### Key rotation (v3 / v3.1 lineage)

Rotation replaces a signing key without breaking updates: the new
key carries a lineage — a chain of proofs, each signed by the
previous key — back to the key old installs trust.

```bash
apksigner rotate --out lineage.bin \
  --old-signer --ks old.keystore \
  --new-signer --ks new.keystore
apksigner sign --ks new.keystore --lineage lineage.bin \
  --out app.apk app-aligned.apk
apksigner verify --verbose --print-certs app.apk   # prints the lineage
```

Reading a lineage during analysis: `apksigner verify` reports each
signer in the chain and which SDK ranges trust which key. A
certificate change **with** a valid lineage is a planned rotation.
A certificate change **without** one means the new build cannot
install over the old one — the finding nar-compare is built to
surface (next section). `--rotation-min-sdk-version 33` on sign
writes the rotation into the v3.1 block so only Android 13+
follows it.

### Source stamp

A distributor (typically a store) can countersign with a stamp
signer: `apksigner sign --stamp-signer --ks stamp.keystore …` on
top of an already signed APK. During analysis, triage reports the
stamp's presence (`source_stamp` in the JSON, and in the plain
report). A stamp says where the file was distributed from; it is
not evidence about the developer's key.

### Signature continuity across versions

Android's update rule is signature continuity: an update must be
signed by the same key as the installed app, or carry a v3/v3.1
lineage back to it. The analysis workflow for a version pair:

1. `apksigner verify --print-certs` on both versions; record each
   signer's SHA-256 fingerprint.
2. Same fingerprint on both: continuity holds.
3. Different fingerprint: check the new APK for a rotation lineage
   (`verify --verbose` prints it). Lineage present and rooted in
   the old key: planned rotation, updates still work.
4. Different fingerprint, no lineage: the "update" cannot install
   over the old app. In a comparison report this is a headline
   finding, not a footnote.

`nar-compare.py` automates the mechanical half: it inventories
signing files and reports identity changes between the two files.
The fingerprint comparison itself is the analyst's step — run it
on every version pair you diff.

Keep the keystore safe and backed up: losing it means you can never
publish an update under the same identity. Never sign someone
else's app with your key, and never ship an app signed with a key
you do not own.
