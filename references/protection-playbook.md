# Protection playbook

Per protection kind in `scripts/formats.json` `protection_kinds`.
Signatures live in `scripts/protection-signatures.json` and are consumed
by `nar triage`. Detection and reporting ONLY: a hit means protection
artifacts or protection code ship in the package; it says nothing about
whether a runtime check passed, and NAR never uses this to bypass
anything. A finding is attributed to a named product only when a marker
is dedicated to that product.

Cheapest probe for every kind below is the same first step:

```bash
python3 scripts/nar-triage.py <target>
```

Real run on the demo fixture (only the native-hardening kind fires):

```text
Protection systems (static markers only; a hit means protection artifacts or protection code ship in the package, not that a runtime check passed):
  [Native hardening]
  - Native hardening posture (ELF headers): 1 of 1 native libs are ET_DYN (position-independent); RELRO: 1 full (GNU_RELRO + BIND_NOW), 0 partial (GNU_RELRO only), 0 without GNU_RELRO; symbol tables: 0 of 1 libs stripped (no SHT_SYMTAB); 16 KB page alignment: 0 of 1 libs have every LOAD segment aligned to 16 KB or more
```

## commercial_packer — supported

- What it hides: the real DEX/native payload behind a stub application
  class and a protector runtime library; code appears only at runtime.
- What remains observable: the stub class, the protector's dedicated
  runtime library, unusually small/empty visible DEX, encrypted payload
  blobs in assets.
- Cheapest probe: `nar triage` packer markers, then compare DEX class
  count against the app's manifest surface (`nar dex`).

## obfuscation — supported

- What it hides: meaningful class/method/field names and string literals
  (renaming, string encryption in dedicated obfuscator runtimes).
- What remains observable: renamed identifier shapes, dedicated
  obfuscator runtime packages, string-pool statistics.
- Cheapest probe: `nar triage` obfuscation markers + `nar dex` class-name
  census. Note: kinds with no reliable static marker (for example
  DexGuard string encryption) are deliberately absent from the signature
  database — triage stays silent there rather than guessing.

## anti_tamper_rasp — supported

- What it hides: runtime integrity/root/hook checks and their triggers;
  the checks themselves execute on device, not in the artifact.
- What remains observable: RASP SDK DEX markers, dedicated runtime
  libraries, integrity-check API references.
- Cheapest probe: `nar triage` RASP markers. A marker proves the SDK
  ships, not that any check passed or failed at runtime.

## network_protection — supported

- What it hides: real endpoints and payloads behind certificate pinning
  and encrypted channels.
- What remains observable: pinning configuration (network security
  config, pin constants), TLS library markers, endpoint hosts in strings.
- Cheapest probe: `nar triage` network markers + `nar network` for the
  static endpoint/pin census.

## licensing_drm — supported

- What it hides: entitlement decisions (server-side) and protected media
  keys; the Widevine/licensing client is all that ships.
- What remains observable: licensing DEX markers, Widevine UUID forms in
  native/DEX content, license-service component declarations.
- Cheapest probe: `nar triage` licensing markers. No client-side probe
  can produce the server's entitlement answer.

## code_asset_encryption — supported

- What it hides: DEX, native code or asset payloads behind an encryption
  layer and a loader.
- What remains observable: high-entropy payload members, loader/stub
  classes, decryption-API references, mismatched format headers.
- Cheapest probe: `nar triage` encryption markers + `nar assets` /
  `nar input validate` header checks on the suspect members.

## native_hardening — supported

- What it hides: nothing by itself — this kind reports build posture:
  PIE (ET_DYN), RELRO/BIND_NOW, stripped symbol tables, page alignment.
- What remains observable: all of it, from ELF program/dynamic/section
  headers (see the real run above).
- Cheapest probe: `nar triage` (posture block) or `nar native`.
  Posture describes build flags, not exploit resistance.

## play-integrity-verdict — server_side

- What it hides: the verdict itself; it is computed by Google's servers
  and delivered to the developer's server.
- What remains observable: client-side Play Integrity API presence only.
- Cheapest probe: none exists client-side. The verdict requires the
  developer's server integration; do not claim one from static analysis.
