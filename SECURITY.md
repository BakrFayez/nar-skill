# Security — NAR's analysis boundary and sample handling

Research by Bakr Fayez

This file states, for this repository specifically, what
NAR will and will not do, and how it treats the untrusted
samples it analyzes. Every mechanism named here exists in
the shipped code; the per-guide treatment is in
`references/safety-and-authorization.md`.

## Analysis-only boundary

NAR is a static/dynamic **analysis** system. It does not
defeat protections:

- **No decryption of protected content.** Encrypted Unreal
  pak indexes and IoStore containers are inventoried and
  diagnosed, never decrypted (`narlib/iostore.py`
  capabilities: encrypted payloads "are inventoried, never
  decrypted"; `nar-pak.py` diagnoses an encrypted index from
  its footer and refuses extraction). Encrypted Godot packs
  are detected from the header flag and their listing is
  reported honestly unavailable (`nar-godot.py`). Oodle
  compression is refused by name (proprietary SDK).
- **No signature / license / payment bypass.** Nothing in
  this repo kills or bypasses signature verification,
  license checks, DRM, or Play Integrity verdicts, and
  nothing unlocks paid features or paid currency. Signing
  support covers signing and verifying **your own** builds
  only (see `references/signatures-and-integrity.md`).
- **Detection is not defeat.** Protection systems (packers,
  pinning, RASP, DRM presence) are detected and reported by
  class; NAR stops there.

## Untrusted-sample handling

Samples are hostile input by assumption:

- **Static analysis never executes the sample.** The
  parsers in `scripts/narlib/` and the module scripts read
  bytes and structures only; no code path loads, installs,
  or runs the analyzed app. (Runtime observation is a
  separate, explicitly invoked subsystem that operates on
  the user's own device, on apps the user is authorized to
  instrument — `references/dynamic-analysis.md`.)
- **Extraction is guarded.** Archive extraction goes
  through `narlib/safearchive.py`, whose limits are
  one validated ResourceBudget (narlib/budget.py —
  invalid overrides are refused with a named error):
  zip-slip / path
  traversal, symlink, per-file size (1 GiB), total size
  (2 GiB), entry count (20,000), compression-ratio
  (200 per entry / 100 whole-archive) and nesting-depth
  (2) guards. Every rejection is reported in the extraction
  report, never silent.
- **Parsers carry resource limits.** Capped collections in
  the module reports carry total / processed / skipped /
  failed accounting (for example the Unreal `--max-*` /
  `--all-*` caps and the native library dependency graph's
  500-node / 5,000-edge caps with truncation flags),
  and malformed inputs fail with named errors rather than
  unbounded work — the mutation corpus
  (`tests/unit/test_phase11_mutations.py`) pins clean
  failure for the DEX / ELF / PAK / IoStore / Zen
  parsers; a deterministic mutation-fuzz harness
  (tests/fuzz/) extends that discipline to the DEX
  parsers with preserved crash artifacts and
  regression tests per find (2.6.2).
- **Shipped code is stdlib-only** and contains no
  `shell=True`, `os.system`, `eval`, or `pickle` (Phase 1
  audit record, `NAR_REPAIR_MATRIX.md`).

## Report hygiene

- **Credential-shaped strings are redacted at the source.**
  `nar-network.py`'s `redact_url()` replaces URL userinfo
  and sensitive-named query-parameter values with
  `REDACTED` before an endpoint is stored, and the report
  counts the redacted values (`redaction.endpoint_values_
  redacted`); companions receive the already-redacted URLs.
  A planted-fixture test pins that no secret substring
  reaches the report (`tests/unit/test_network_phase5.py`).
- **No tested app is ever named** in this repository's
  code, docs, tests, or changelog; corpora are referenced
  by role label only, and findings are described
  generically.

## Responsible use

Use NAR on apps and games you own or are authorized to
test: your own builds, authorized security research,
compatibility and interoperability work, and education.
If a request crosses the boundary above, the expected
behaviour is to decline that part, state the boundary
plainly, and offer the legitimate alternative (analyze
your own build, or build the feature in your own original
app).

To report a security problem **in NAR itself**, open an
issue in this repository's tracker describing the affected
module, the input shape that triggers it, and the observed
behaviour; do not attach third-party samples you are not
authorized to share.
