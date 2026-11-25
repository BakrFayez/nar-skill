# NAR Security Audit — 2.6.2 Stability & Certification Campaign

Scope: the security surface of the existing codebase —
archive handling, extraction paths, credential hygiene,
budget enforcement, and the security analyzer itself.
Method: code-level audit (primary) plus crafted-input
reproductions for every headline claim. No security
control was disabled or weakened to make any test pass.

## P0 findings — all fixed

### B-01 — IoStore zlib decompression bomb
`narlib/iostore.py` inflated zlib blocks with an
uncapped `zlib.decompress`: a hostile TOC could expand
a small block without bound before the size check could
refuse it. Fixed: inflation is capped at the
TOC-promised size plus one probe byte via
`decompressobj`; overshoot raises IoStoreError.
Regression-tested (bomb refused, honest chunk
round-trips byte-identically; the real-corpus sweep —
2,644 packages — reconciles exactly, see
NAR_FINAL_VERIFICATION_REPORT.md).

### C-01 — Extraction containment was lexical, not real
`nar-analyze`'s entry extractor (and `nar-pak`'s
extraction path) proved containment with `abspath`
only: a pre-existing symlink directory inside the work
root redirected writes outside it (reproduced). Fixed:
realpath proof on the resolved destination, refusal to
write through a pre-existing symlink at the destination,
mirroring the discipline narlib.safearchive already had.
Regression-tested for both tools.

### D-01 — Credential redaction gaps in nar-network
URLs classified `sensitive` were emitted unredacted
when the credential name was prefixed (`?client_secret=`,
`?refresh_token=`), rode the fragment (`#access_token=`),
used path parameters (`;jsessionid=`), or used names the
fixed alternation didn't know (`AWS_SECRET_ACCESS_KEY`,
`private_key`, `credential`, `bearer`). Leaked values
flowed into reports and into nar-security finding
evidence. Fixed: structural redaction — a token-based
credential-name test over query, fragment, and path
parameters, userinfo covered, benign pairs preserved
byte-for-byte. Regression-tested with exact output and
count assertions.
**D-01b** (found by the campaign's own regression test):
the first fix swallowed the path tail after a matrix
parameter's value (`/a;jsessionid=X/b` lost `/b`). The
value now ends at the next `/`; the tail is preserved.
Also regression-tested.

## P1 security-relevant findings — all fixed

- **C-02 — Stage-cache poisoning chain.** Stage cache
  keys are public (sha256 of input hash + version +
  stage), stage companions were written with no schema
  validation, and verify's manifest check was
  one-directional (C-07): fabricated stage data could
  flow into report/graph/investigation on resume or
  import. Fixed: stage documents are validated (dict
  shape + companion schema) before being written;
  cache writes are atomic with the key written last;
  import extracts and verifies in a staging directory
  before the destination is touched (C-03); verify
  warns on files present but not manifest-listed.
- **C-03 — Failed import overwrote the destination.**
  Fixed by the staging design above; regression-tested
  with a sentinel destination left byte-identical after
  a failed import.
- **D-02 — Tool wrappers ignored failure.** The
  run_json_tool wrappers in nar-network, nar-security,
  nar-engines, and nar-compare ignored child exit codes
  and in-band error documents: a garbage target produced
  exit 0 with empty findings — a silent false negative
  from the security analyzer itself. Fixed: non-zero
  exit returns None; nar-network and nar-security now
  exit 2 on a garbage target (verified live).
  Regression-tested for all four wrappers.
- **D-05 — Unbounded whole-member reads.** nar-dex,
  nar-strings, nar-native (ZIP path), nar-flutter, and
  nar-triage read whole archive members without the
  ResourceBudget discipline sibling tools already had.
  Reproduction: a 598 KB APK carrying a 400 MB DEX and
  a 200 MB library drove 819 MB peak RSS. Fixed: a
  shared capped reader (256 MiB member cap, declared
  size checked before decompression and streamed count
  checked during) in narlib.safearchive, applied at all
  sites; over-cap members produce labeled refusals.
  Post-fix reproduction: nar-dex on the same hostile
  APK peaks at ≈21 MB child RSS. Regression-tested.
- **D-07 — Exported-component check omitted a kind.**
  nar-security's exported-component loop checked 4 of
  the 5 component kinds nar-perms produces;
  `activity-alias` was silently unchecked (false
  negative). Fixed; the loop now covers all kinds, and
  skipped check families are recorded in the report
  (`checks_skipped`, D-13) instead of vanishing.
- **S-03 — Correlations crash on real network data**
  (found in the regression phase): nar-network emits
  network_libraries as strings; the correlations builder
  called `.get()` on each item, so any target with a
  detected network library lost its whole correlations
  document (degraded silently since an earlier
  hardening). Fixed: both shapes accepted.
  Regression-tested.

## Verified sound (re-checked, not assumed)

- narlib.safearchive core guards: traversal (including
  Windows-style), symlink entries, duplicate handling,
  ratio/entry-count/aggregate budgets, streamed-byte
  caps that stored entries cannot bypass.
- ResourceBudget validation strictness; elapsed-time
  budget enforced when a caller sets it.
- Encrypted content discipline: IoStore containers
  flagged Encrypted are inventoried, never decrypted;
  Oodle is refused by name — in the real-corpus sweep,
  all 13,911 Oodle extraction records were refused by
  name, none decoded.
- nar-security findings: every finding is built through
  the validating evidence constructor with all 13
  fields and an explicit verification_status (all 12
  call sites re-read in this campaign).
- verify's evidence-integrity section and its era
  policy; companion projections are schema-validated
  before write; report rendering escapes content and
  emits zero external references.
- No `shell=True` anywhere in the tree; every subprocess
  call carries a timeout (AST-verified in the audit).

## Security test evidence (final tree)

- CI security-regression subset (archive budget,
  safearchive, security regression, deep-audit
  remediation, phase-10 hardening, phase-11 mutations,
  DEX fuzz regressions, ELF robustness): **122 passed**
  from clean extraction.
- DEX fuzz smoke, fixed seed, 500 iterations:
  **0 distinct failures**.
- Full unit battery (includes all security suites):
  **653 passed**.
- New targeted regressions for B-01, C-01, C-03, D-01,
  D-01b, D-02, D-05, S-03 in
  tests/unit/test_stability_campaign.py.

## Residual notes

- Stage cache keys remain public by design (they bind
  content, not secrecy); the poisoning chain is closed
  by validation + atomic writes + staged import, not by
  key secrecy.
- Path arguments to subprocesses are not separated by
  `--` (P3, recorded in the stability audit): targets
  are operator-supplied local paths in NAR's threat
  model; no change made under the freeze.

MIT License.
