# NAR Stability Audit — 2.6.2 Stability & Certification Campaign

Scope: the complete existing 2.6.2 codebase under the
owner's feature freeze — no new features, modules, or
subsystems; no architecture rewrites; no
backward-compatibility breaks. Allowed work only: bug
fixes, security fixes, reliability, performance/memory,
accuracy corrections, test coverage, documentation
corrections, compatibility fixes, CI improvements.

Method: five parallel read-only audit slices over every
module, parser, analyzer, CLI command, archive path,
graph/investigation operation, export/import path,
schema, config, test, CI file, and document — code-level
reading as the primary instrument, with a crafted-input
reproduction for every headline finding. Settled items
from the 2.6.0–2.6.2 verification reports were verified,
not re-litigated. Fixes shipped in groups on the
`stability-certification` branch; every fix carries a
regression test (tests/unit/test_stability_campaign.py,
43 tests, plus additions to existing suites).

Version identity: the stabilized tree remains **2.6.2**
(owner-confirmed; no bump).

## Register summary

| Priority | Found | Fixed | Documented-only / accepted |
|---|---|---|---|
| P0 | 3 | 3 | 0 |
| P1 | 21 | 21 | 0 |
| P2 | ~30 | most | B-19, C-16, D-16 (documented) |
| P3 | ~20 | most | remainder recorded below |

Findings found by the campaign's own fix/regression
phases are marked ◆: D-01b, S-01, S-02, S-03, CI-01.

## P0 — security / data corruption / arbitrary write

- **B-01** IoStore `extract_chunk` inflated zlib blocks
  uncapped (zlib bomb). Fixed: capped inflation at the
  TOC-promised size. *(group 1)*
- **C-01** nar-analyze `extract_entry` containment was
  lexical only — a pre-existing symlink directory in
  the work root redirected writes outside it; nar-pak
  extraction had the same class. Fixed: realpath proof
  + symlink-destination refusal in both. *(group 4)*
- **D-01** nar-network redaction leaked prefixed
  credential names, fragment credentials, path
  parameters, and several credential name forms into
  reports and security-finding evidence. Fixed:
  structural token-based redaction. **D-01b ◆** the
  first fix swallowed the path tail after a matrix
  parameter value; corrected, tail preserved byte for
  byte. *(groups 4, 7)*

## P1 — incorrect findings / broken parsers / wrong evidence / compat

Parsers and engines:

- **A-01** dexdis resolver leaked DexError/struct.error;
  one bad method poisoned whole batches. Fixed: errors
  converted to the module's failure record; call-site
  bounds checked. *(group 1)*
- **A-02** oat scan emitted a DEX hit with
  file_size=None → TypeError in the carve path. Fixed:
  truncated-header hits skipped, size guarded. *(g1)*
- **A-03** dotnetmeta leaked struct.error/IndexError/
  ValueError instead of its named error, crashing the
  nar-il2cpp stage. Fixed: checked helpers throughout.
  *(group 1)*
- **A-04** ELF section contents were never
  extent-validated: an inflated .dynsym decoded
  following file bytes into fabricated symbols that
  flowed into facts(). Fixed: extent validation in
  _section_data (NOBITS returns empty). One pre-existing
  test pinned the same lenient behavior for relocations;
  it now asserts the named ElfError, matching the
  module's documented contract. *(groups 1, 8)*
- **B-02** uasset negative non-table offsets leaked
  struct.error. Fixed: negative offsets rejected (the
  −1 sentinel fields are exempted and documented). *(g1)*
- **B-03** uasset negative serial_size accepted by the
  range locator. Fixed. *(group 1)*
- **B-04** Unity bundle scan broke at the cap
  (off-by-one, 201), truncating Data-file and
  Addressables counts while the note claimed the
  inventory complete. Fixed: counting is uncapped; only
  the deep-scan list is capped, with truncation flags
  and an inventory-scope statement. *(group 4)*
- **B-05** Godot truncated packs leaked struct.error.
  Fixed: header/record length guards raise PckError.
  *(group 4)*

Orchestration and evidence:

- **C-02** Stage-cache poisoning chain: forgeable
  public keys + companions written with no schema
  validation + one-directional verify → fabricated
  evidence on resume/import. Fixed: stage documents
  validated before write; atomic cache writes, key
  last; staged import (C-03). *(group 4)*
- **C-03** Failed case import overwrote destination
  files. Fixed: extract + verify in a staging
  directory; destination touched only after the
  imported case verifies. *(group 4)*
- **C-04** Investigation promoted any status other than
  UNVERIFIED into verified_facts (CONTRADICTED,
  POTENTIAL, and null all promoted). Fixed: allowlist
  {CONFIRMED, STRONGLY_INDICATED}. *(group 2)*
- **C-05** Corrupt/wrong-shaped stage cache crashed
  the whole analysis with a traceback. Fixed: a corrupt
  pair is a cache miss (pair dropped, stage re-run).
  *(group 4)*
- **C-06** Correlations and companion projections
  crashed on malformed stage documents. Fixed: built
  inside the same degrade-don't-crash discipline as the
  graph/investigation builders. *(group 4)*
- **S-01 ◆** Stage cache keys derived from the
  extracted base APK's hash for containers, but
  case.json records the container hash — every
  container-built case falsely failed verify's cache
  integrity. Fixed: keys derive from the case target
  hash; legacy container keys (unverifiable from case
  data) are a stated warning in verify, never a failure
  and never silent. *(group 4)*
- **S-02 ◆** Verify hard-failed every pre-2.6.2 case
  whose endpoints carried the retired `confirmed`
  label. Fixed: era mapping to `dex-string` in verify's
  schema loop, following the existing legacy pattern.
  *(group 4)*
- **S-03 ◆** nar-network emits network_libraries as
  strings; correlations called `.get()` on each item —
  any real target with a detected network library lost
  its correlations document. Masked by every retained
  case having an empty list, and by test stubs encoding
  the wrong shape. Fixed: both shapes accepted; stubs
  corrected to the producer shape. *(group 7)*

Analyzers and registry:

- **D-02** run_json_tool wrappers in nar-network,
  nar-security, nar-engines, nar-compare ignored exit
  codes and in-band error documents: a garbage target
  produced exit 0 with zero findings. Fixed: non-zero
  exit returns None; the CLIs exit 2. *(group 4)*
- **D-03** Registry probe faked availability: an error
  banner was recorded as a version; paths were accepted
  without executability or a successful version run;
  nar-dex's jadx adapter reported decompile_errors 0 on
  hard failure. Fixed: versions only on exit 0, probe
  requires an executable file + successful version run,
  min_version_major enforced, jadx hard failure becomes
  an error document. *(groups 3, 4)*
- **D-04** Registry discovery ≠ doctor discovery
  despite docs claiming parity (live: doctor READY
  while nar-tools reported java and apktool missing).
  Fixed: JAVA_HOME/env_home/home_globs and apktool
  jar discovery mirror the doctor. Live result on the
  final tree: registry and doctor agree. *(group 3)*
- **D-05** Unbounded whole-member reads in nar-dex,
  nar-strings, nar-native, nar-flutter, nar-triage
  (598 KB hostile APK → 819 MB peak RSS). Fixed:
  shared capped reader in narlib.safearchive (256 MiB),
  streamed head reads; post-fix peak ≈21 MB on the
  same input. *(group 5)*
- **D-06** nar-runtime computed frida-server `present`
  from unfiltered `frida-server*` names — a lone
  frida-server.log reported the server present. Fixed:
  binary candidates only. *(group 5)*
- **D-07** nar-security's exported-component loop
  omitted `activity-alias` — silent false negative.
  Fixed; skipped check families are now recorded
  (D-13). *(group 4)*

Verification-state claims (documentation as evidence):

- **E-01** Capability matrix claimed real-corpus engine
  precision was NOT RUN; it was measured in 2.6.2
  (30 samples, P/R/F1 1.0). Corrected. *(group 6)*
- **E-03** comparison.schema.json described a pre-2.0
  document; a real comparison.json failed it, and no
  test validated one. Schema rewritten to the producer
  shape; validation test added. *(group 6)*
- **E-04** Four schemas use `const`, which the bundled
  validator silently ignored, while the docs claimed
  schemas are written to the validator's subset. Fixed:
  the validator implements `const`; the claim is now
  true. *(groups 2, 6)*
- **E-05** Capability matrix presented the 2.5.2 doctor
  compile defect as current; it was fixed in 2.5.2.
  Corrected, with the campaign's narlib coverage noted.
  *(group 6)*

## P2 — fixed (selection)

- **A-05** ELF build-id: endian-aware, namesz-based
  descriptor offset. **A-06** dex class_annotations cap
  now marks truncation instead of silently dropping.
  **A-07** dexdis _enc_value float/double/char decoding
  corrected. **A-08** formats identify/validate no
  longer fully decompresses every entry twice
  (budgeted streamed CRC pass; classes.jar read gated).
  **A-09** dotnetmeta whole-file read capped at
  512 MiB. **A-10** dex aggregators isolate one corrupt
  class instead of aborting the whole DEX, with a
  failure count emitted. *(group 1)*
- **B-06** Zen zero-count name batch returned early
  and misaligned sections; removed. **B-07** Zen Verse
  cell offsets validated; bundle-entry end bounded
  (an exact-landing check was tried and rejected — real
  packages carry further header content; the bounded
  check is the correct one). **B-08** IoStore directory
  index validates toc_entry_index; parse failure is
  surfaced in a field instead of swallowed to None.
  **B-09** Classic pak v1–7 entry offsets/sizes
  validated at parse. **B-10** Godot fallback triggers
  on listing errors too, and the tool path requires
  exit 0. **B-11** nar-unreal IoStore accounting
  carries an explicit error for missing/unparseable
  containers. **B-12** APK-mode.ucas is streamed to a
  mapped work file instead of read whole. **B-13**
  UnityPy census distinguishes unavailable from
  load-failed; il2cpp subprocess failure is recorded,
  not silently dropped. **B-14** Unity inventory scope
  is stated in the report. *(groups 1, 4)*
- **C-07** Verify's manifest check was one-directional;
  unmanifested files are now a warning. **C-08**
  verify_case itself tracebacked on malformed
  case/manifest shapes; shape guards added. **C-09**
  _contained_join compared a relative destination
  against an absolute root — a relative --work silently
  disabled all container extraction; root is
  absolutized. **C-10** Export of a nonexistent case
  "succeeded" with an empty bundle; in-case bundles
  included themselves. Both refused. **C-11**
  nar-report tracebacked on incomplete companions;
  row builders are now defensive. **C-12** Graph
  provenance cap dropped references silently past 8;
  a dropped counter + note is emitted, and edge
  confidence upgrades by rank instead of
  first-writer-wins. **C-13** nar-input extract exited
  0 when every entry was rejected; now exit 1, and
  non-archive input is exit 2. *(groups 2, 4, 5)*
- **D-08** Doctor's compile glob covered scripts but
  not the 22 narlib modules; both are compiled now.
  **D-09** Signature-loader gaps closed (non-dict
  entries, dead packers, duplicate names, empty marker
  patterns — an empty pattern previously manufactured
  hits — absurd thresholds). **D-10** Traceback-instead
  -of-exit-2 gaps closed across nar-dex, nar-native,
  nar-assets, nar-rn, nar-input, nar-il2cpp. **D-11**
  classify_device could return "physical" from a
  near-empty property set, and "intel" was a strong
  emulator marker; sparse sets are now "unknown" and
  intel is weak. **D-12** Frida network-observe.js
  logged URL userinfo credentials; stripped. **D-13**
  nar-security records checks_skipped. **D-14**
  nar-compare feature maps stamped version 2.4.0; now
  current, and the file joined the version guard.
  *(groups 2–5)*
- **E-02** benchmarks.md and the 2.6.2 baseline's stale
  NOT RUN strings corrected/explained (the baseline
  JSON is a historical measurement record and is left
  untouched; the matrix and benchmarks doc now point
  at the accuracy corpus for the precision question).
  **E-06** NAR_TEST_MATRIX's stale battery claims
  corrected. **E-07** Architecture doc's data-flow
  corrected (Unreal records joined graph.json in
  2.6.1). **E-08** CI: the schema job installed a
  validator nothing invoked; the e2e-public job had a
  fixture-generation step whose output was never read;
  header counts corrected to measured hosted shapes.
  **CI-01 ◆** the fuzz-smoke job never installed
  pytest, but the fuzz harness loads a unit-test module
  that imports it — the job would have failed on its
  first hosted run; install step added. **E-09**
  output-schema.md case table completed;
  permissions.json schema added (see E-03/E-09 in the
  compatibility report). **E-10** README structure
  block completed and the docs guard strengthened to
  enumerate the real tests/ tree. *(group 6, 9)*

## P2/P3 — documented only (with reasons)

- **B-19** Godot scene-relationship join is quadratic
  in section counts within one file, and the per-file
  instanced_scenes list is not length-capped. Bounded
  by the 25-file / 4 MiB-per-file caps. Documented as a
  known limit in references/native-libs-and-jni.md;
  an algorithmic fix is an optimization, not a
  correctness defect, and was not risked under the
  freeze.
- **C-16** Exit-code split between bare `nar` (help,
  exit 0) and bare `nar case` (usage error, exit 2)
  reads as deliberate; changing either risks scripted
  expectations. Documented as accepted.
- **D-16** Triage protection records carry no
  per-record confidence/verification_status fields.
  Documented explicitly in
  references/triage-and-inventory.md: records are
  UNVERIFIED static indicators. Adding fields would
  change a shipped document shape under the freeze.
- **A-15 (partial)** dex strings() has a quadratic
  corner in the worst case (per-string NUL scan);
  recorded here. The 5-byte ULEB128 width behavior is
  a deliberate, test-pinned 2.6.1 design decision
  (length-capped, consumers range-check) — audited and
  left as designed.
- Assorted P3s fixed in passing: safearchive symlink
  reporting (C-14/C-15), formats pak tail-scan
  off-by-one (A-13), evidence.validate recursion depth
  cap (A-14), IoStore TOC version 0 rejection (B-15),
  chunk_sha1_ok index guard (B-16), dead duplicated Zen
  predicate removed (B-17), Unreal relationship cap
  threaded through limits (B-18), embedded-pack
  disclosure (B-20), Unity LZMA output ceiling (B-21),
  doctor --help (D-15), nar-runtime exit codes (D-15),
  SECURITY.md fragment (E-11), Python floor alignment
  (E-12), README retired endpoint label (E-13),
  capability-matrix stale rows (E-14).

## Verified sound — re-checked, not assumed

safearchive's core guards; ResourceBudget validation;
mkdtemp work dirs; the streamed DEX stage and windowed
reader (byte-identical outputs); verify's
evidence-integrity section and era policy; the
investigation hypothesis gate; graph count
reconciliation; companion projections schema-validated
before write; nar-report escaping and zero external
references; the nar.py router's exit-2 discipline; DEX
LEB128 bounds (the 2.6.1 fix holds), header extents,
code_item_info, encoded-value depth cap; the dexdis
opcode/width tables (224/224 cross-checked); the cdex
parser; ELF header/entry-size hardening; IoStore's
exact-consumption walk, cycle-safe directory walk, and
encrypted/Oodle discipline; Zen's offset chain and
exact-landing bulk map; pak v10+ SHA-1-before-decode;
Godot encrypted honesty; the doctor's jadx real-start
check and Java ≥17 enforcement; nar-security's finding
construction; classify_device's weak-marker discipline;
bounded connection recovery; Frida version
compatibility logic; skip discipline across the suite
(no tautological tests found); accuracy discipline
(real/synthetic separation, unclassified = miss, null
rates on zero denominators); version 2.6.2 in all
guarded locations (19 files after nar-compare joined).

## Outcome

All P0 and P1 findings are fixed with regression tests.
No P0/P1 is carried as "justified open". The full
battery on the final tree is in
NAR_FINAL_VERIFICATION_REPORT.md.

Research by Bakr Fayez. MIT License.
