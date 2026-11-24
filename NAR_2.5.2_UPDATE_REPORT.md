# NAR 2.5.2 Update Report

Research by Bakr Fayez.

This report records the 2.5.2 update program (branch
`update-2.5.2`): the issues fixed, the files changed, the
tests executed, and the before/after performance
measurements. It is built up per workstream (W0–W8) as the
program runs; the final state is the release record for
2.5.2. Statuses use the project vocabulary: measured facts
are stated with their evidence, NOT RUN items are stated
plainly, and synthetic vs real corpora are always reported
separately.

## W0 — Baseline and claim verification (2026-11-24)

### Executed baseline (untouched tree, 7f16b7f == 2.5.1)

- pytest: **246 passed, 0 failed**.
- e2e (`bash tests/run_e2e.sh`): **65 passed, 0 failed,
  0 skipped**.
- doctor: **Core toolchain: READY**.

### Brief claims verified against the code

1. **YAML (§1) — CONFIRMED, both files invalid.**
   PyYAML `safe_load` fails on `skill.yaml` with
   "mapping values are not allowed here", line 2
   column 11 (the unquoted colon in the `title:` value),
   and on the SKILL.md frontmatter with the same error,
   line 2 column 85 (the unquoted colon in the
   `description:` value). All existing validation is
   regex-only: `tests/unit/test_docs_consistency.py`
   (version grabs) and
   `tests/unit/test_phase10_guide_audit.py`
   (`test_skill_frontmatter_and_plugin_versions` uses
   `startswith` + `re.search`, never a YAML parser) —
   which is exactly how invalid frontmatter shipped.
   `nar-doctor.sh` has no YAML check. No PyYAML
   dependency is declared anywhere in the repo.
2. **Unreal capability reporting (§2) — CONFIRMED
   stale.** `scripts/nar-unreal.py`
   `_package_limitations()` (line 233) claims UE5
   property tag extensions (UE5 object version >= 1011)
   "are reported as unsupported". `scripts/narlib/
   uasset.py` in fact implements both layouts — 1011
   (tag-extension tail) and 1012+ (complete type
   names) — verified against synthetic packages and
   documented as synthetic-verified in that module's
   docstring. Reporting contradicts the parser.
   Unreal reporting test coverage is thin:
   `tests/unit/test_unreal.py` holds exactly one test.
3. **Hardcoded Unreal limits (§3) — CONFIRMED, full
   inventory** (`scripts/nar-unreal.py`):
   `ENTRY_CAP = 250` (line 67; chunk detail and
   import/export/depends detail), `CONTAINER_CAP = 5`
   (line 68), `PACKAGE_CAP = 5` (line 71),
   `NAME_CAP = 500` (line 72); hidden caps:
   searchable-names detail 100 (line ~198),
   `config_files[:25]` and `package_files[:25]`
   display lists, and `utoc_names[:2]` for IoStore
   package extraction in APK mode. Chunk/name/import/
   export caps emit "capped" notes; the package caps
   truncate WITHOUT a skipped count in the report
   (a total exists only as `package_file_count` /
   `pak_package_file_count`).
4. **Whole-file loads (§4) — CONFIRMED.**
   `nar-unreal.py` reads the entire sibling .ucas
   (line 402), .utoc (404), loose .uasset/.uexp
   (369/372) and zip members via `zf.read()`;
   `nar-native.py` reads whole .so files (line 77)
   and whole zip members; `nar-pak.py` reads the
   whole pak (lines 471, 719). The narlib parsers
   are bytes-based APIs (`iostore.parse_utoc(data)`,
   `iostore.extract_chunk(parsed, ucas_data)`,
   `zen.parse_zen_package(data)`,
   `uasset.parse_package(data)`, `elf.Elf(data)`),
   so every caller materializes whole files.
   **Brief error:** §4 names `scripts/narlib/pak.py`;
   that file does not exist — pak parsing lives in
   `scripts/nar-pak.py` (`parse_entries`, line 133).
5. **Testing infrastructure (§5) — PARTIALLY as the
   brief implies.** The unit suite is largely
   self-contained (in-test synthetic builders) and
   fixture-dependent tests SKIP cleanly when
   `NAR_FIXTURES` is empty (measured on the four
   fixture-bound files: 19 passed, 8 skipped,
   0 failed). But there are no fixture generator
   scripts, no expected-output manifests, and no
   documented test categories; `tests/run_e2e.sh`
   hard-requires the private fixture corpus
   (including the demo APK, which is not in the
   repo), so a clean clone cannot run the e2e suite.

### Performance baseline (before)

Full record: `tests/benchmarks/baseline-2.5.2.json`
(role labels + sizes; local path bindings stay outside
the repo). Method: fresh wrapper process per run, peak
RSS = RUSAGE_CHILDREN of the direct child, identical
inputs re-run in W4.

| Run | Input | Wall | Peak RSS |
|---|---|---:|---:|
| nar-unreal | UE 5.3 IoStore set (.utoc 885,376 B + .ucas 219,935,664 B, 7,171 chunks) | 0.94 s | 258,871,296 B |
| nar-unreal | TOC v8 IoStore set (.utoc 327,627 B + .ucas 97,140,736 B, 2,912 chunks) | 0.67 s | 124,968,960 B |
| nar-native | largest ELF in the 273 MB fixture (81,159,656 B) | 1.84 s | 306,999,296 B |
| nar-analyze | the 273 MB fixture (273,366,540 B) | 462.73 s | 1,888,186,368 B |

The pattern is already visible: nar-unreal's peak RSS
tracks the whole-.ucas read (≈ UCAS size + overhead),
and nar-native peaks at ~3.8× the ELF's size.

Correctness oracles recorded for the W4 re-check:
IoStore directory-index file counts 6,743 (UE 5.3 set)
and 13,494 (TOC v8 set); Zen parses 684 + 525 stored
packages with 0 failures; nar-unreal report identity
(verdicts, container/chunk/package counts) on both
IoStore sets.

## W1 — P0 YAML and skill validation (2026-11-24)

### The fix

- `skill.yaml`: the `title:` and `description:` values are
  now double-quoted scalars. Both carried an unquoted colon
  inside a plain scalar (the title itself, and "CLI tools:"
  in the description).
- `SKILL.md`: the frontmatter `description:` value is now a
  double-quoted scalar (same "CLI tools:" colon). The
  `metadata.version` line stays in its existing quoted form
  (`version: "2.5.1"`), so the regex version grabs keep
  working unchanged.

### Before / after parse evidence (PyYAML `safe_load`)

- Before: `skill.yaml` failed with "mapping values are not
  allowed here", line 2 column 11; the SKILL.md frontmatter
  failed with the same error, line 2 column 85 (the W0
  record above).
- After: both parse. `skill.yaml` yields `name` "nar" (str),
  `title` "NAR: Nirous Android Reversing" (str), `version`
  "2.5.1" (str), `description` (str, non-empty), `category`
  "Work and knowledge" (str), `include_in_prompt` false
  (bool) — the fields skill loaders expect, with the
  expected types. The SKILL.md frontmatter yields `name`
  "nar", `description` (str, non-empty) and
  `metadata.version` "2.5.1" (str).
- Semantic preservation was checked mechanically: every
  parsed string equals the raw text that followed the key
  colon in the pre-fix files, word for word (title and both
  descriptions included). The regex grabs also still agree
  with the parsed values: skill.yaml `^version:\s*(\S+)`
  and SKILL.md `version:\s*"([^"]+)"` both return "2.5.1".

### Real parser validation in the test suite

- New `tests/unit/test_yaml_validation.py` (18 tests):
  parses `skill.yaml` and the SKILL.md frontmatter with
  PyYAML and asserts the expected keys/types and the exact
  metadata text; cross-checks parsed versions against the
  regex grabs; malformed variants must FAIL parsing
  (unquoted colon in a title and in a description value,
  unclosed double and single quotes, tab indentation, tab
  inside a nested mapping, plus the same three shapes as
  frontmatter). Duplicate keys: stock PyYAML accepts them
  (last value wins), so that case is asserted with a
  duplicate-rejecting SafeLoader, under which the document
  fails. The module SKIPs with a stated reason when PyYAML
  is not importable — verified by an import-blocked run:
  18 skipped here, 0 fake-passes.
- `tests/unit/test_docs_consistency.py`: new
  `YamlValidityTest` (2 tests, `skipIf` PyYAML is missing)
  parses both files and asserts the parsed versions agree
  with `collect_versions()`. The regex behaviour is
  unchanged.
- `tests/unit/test_phase10_guide_audit.py`:
  `test_skill_frontmatter_and_plugin_versions` keeps its
  regex checks and, when PyYAML is importable, additionally
  parses the frontmatter and asserts name, a non-empty
  string description, and `metadata.version` agreement.
- `pyproject.toml`: PyYAML is declared as a test-only
  dependency — added to the existing `dev` extra and a new
  `test` extra (`pytest>=8`, `pyyaml>=6`). The shipped
  tools stay stdlib-only; no runtime dependency was added.
  `.github/workflows/ci.yml` was NOT edited (workflow
  changes cannot ride this update channel; read-only
  check confirmed the CI job installs only pytest today).
  The YAML tests ride the existing pytest job: they run
  for real wherever PyYAML is installed and SKIP honestly
  where it is not. Locally, PyYAML 6.0.4 was installed
  into the test virtualenv so the suite below exercised
  them for real.

### Doctor

- `scripts/nar-doctor.sh`: new optional `skill-yaml`
  check, following the existing `check()` pattern. It
  probes `python3 -c "import yaml"`; with a parser present
  it parses `skill.yaml` and the SKILL.md frontmatter.
  Measured in all three states, core verdict READY and
  exit 0 in each: valid files → `OK skill-yaml skill.yaml
  + SKILL.md frontmatter parse as valid YAML` (also `ok`
  in `--json` output and via `python3 scripts/nar.py
  doctor`); pre-fix files (temporarily restored) →
  `WARNING skill-yaml skill YAML invalid: … line 2,
  column 11`; parser probe blocked → `OPTIONAL skill-yaml
  unavailable (no YAML parser): install PyYAML for
  python3 …`. Before W1 the doctor had no YAML check at
  all (21 checks, READY); it now reports 22 checks. The
  check is classed optional, so it can never turn the
  core verdict non-READY.

### Files changed and totals

- Changed: `skill.yaml`, `SKILL.md`, `pyproject.toml`,
  `scripts/nar-doctor.sh`,
  `tests/unit/test_docs_consistency.py`,
  `tests/unit/test_phase10_guide_audit.py`,
  `NAR_2.5.2_UPDATE_REPORT.md` (this record). Added:
  `tests/unit/test_yaml_validation.py`.
- Full unit suite with PyYAML installed in the test
  virtualenv: **266 passed, 0 failed, 0 skipped** (W0
  baseline 246; +18 new YAML tests, +2 new consistency
  tests). Doctor after: **Core toolchain: READY**.

## W2 — Unreal capability reporting (2026-11-24)

### Capability design (each module owns its own facts)

- `scripts/narlib/uasset.py`: new `capabilities()` —
  table layouts (UE4 object versions from
  `OLDEST_LOADABLE_UE4`/`FINAL_UE4`, UE5 from 1000,
  legacy file versions -8 to -1 with the -2 enum-form
  exception), `tag_extension_layouts` (1011:
  `ue5-tag-extension`, implemented, verification
  synthetic; 1012+: `ue5-complete-type-name`,
  implemented, verification synthetic, minimum 1012),
  the unversioned assumption (derived from
  `ASSUMED_UE5_FOR_UNVERSIONED` and `FINAL_UE4`),
  best-effort property decoding (confidence string
  derived from `PROPERTY_CONFIDENCE`), the not-decoded
  list (class-specific export data, Kismet/Blueprint
  graphs) and the `.usmap` requirement.
- `scripts/narlib/zen.py`: new `capabilities()` —
  layouts `ue5_3_plus` (implemented, verification
  real, 1,209 real packages verified — the stored Zen
  packages of the two local IoStore corpora, 684 +
  525; the count lives in the module constant
  `ZEN_UE5_3_PLUS_REAL_PACKAGES`), `pre_ue5_3` and
  `ea_legacy` (implemented, synthetic), the decoded
  section list, the located-and-measured-not-decoded
  list (dependency-bundle sections, imported-package-
  name contents, Zen export property streams, Verse
  cell map contents) and the `.usmap` requirement.
- `scripts/narlib/iostore.py`: new `capabilities()` —
  TOC versions derived from `TOC_VERSIONS` itself
  (range 0-10), current/legacy TOC layouts, directory-
  index layouts (classic, pooled), compression methods
  decoded (`COMPRESSION_METHODS_DECODED` = None, Zlib)
  vs named-only (any other named method, e.g. Oodle),
  and encrypted containers (inventoried, never
  decrypted, including AES-sealed indexes).
- `scripts/nar-unreal.py`: new `unreal_capabilities()`
  composes the three module dicts; reports for a bare
  package, a bare `.utoc`, and an APK now carry the
  composed dict under `capabilities`.

### Generated limitations

- `_package_limitations()` and `_iostore_limitations()`
  are now GENERATED from those facts (each takes an
  optional composed-caps argument). No factual claim
  in either list is hand-written prose any more: the
  tag-extension sentence is built from the 1011/1012+
  capability entries, the unversioned sentence from
  the assumption fields, the Zen sentence from the
  layout list (with the real-package count), and the
  IoStore sentences from the TOC table, the directory-
  index layouts and the decoded-method list.
- Exact generated text for a versioned-1011 case (the
  tag-extension limitation, verbatim): "UE5 property
  tag extensions are implemented: UE5 object version
  1011 uses the ue5-tag-extension layout
  (implemented, verification: synthetic) and UE5
  object version 1012+ uses the ue5-complete-type-name
  layout (implemented, verification: synthetic); no
  real package with a recorded UE5 object version >=
  1011 is in the corpus, so both tag-extension layouts
  are verified against synthetic packages only."
- Genuinely not-decoded items stay, in generated form:
  Oodle (named, not decoded), AES-sealed indexes /
  Encrypted containers (inventoried, never decrypted),
  class-specific export data (by size, not decoded),
  Kismet/Blueprint graphs, Zen dependency-bundle and
  imported-package-name contents, and Zen export
  property streams (located and measured, not decoded).

### Tests

- `tests/unit/test_unreal.py`: +5 tests (the file held
  exactly one test before W2). They pin the capability
  values against the parsers' own constants
  (`ASSUMED_UE5_FOR_UNVERSIONED`, `FINAL_UE4`,
  `OLDEST_LOADABLE_UE4`, `PROPERTY_CONFIDENCE`,
  `TOC_VERSIONS`, `COMPRESSION_METHODS_DECODED`), assert
  no generated limitation containing 1011 or 1012 also
  contains "unsupported", assert every major capability
  fact (both tag layouts, the 1010/522 assumption,
  `.usmap`, primitive-only decoding, class-specific
  data, Kismet/Blueprint, all three Zen layouts with
  the 1,209 count, both directory-index layouts, the
  TOC range, Oodle named-not-decoded, AES-sealed never
  decrypted) appears in the generated limitations, and
  run nar-unreal on a synthetic 1011 package built with
  the existing `test_uasset.py` builders: the export's
  properties parse with layout `ue5-tag-extension` and
  the report limitations show the implemented status.
- Full unit suite before the W2 commit: **271 passed,
  0 failed** (W1 baseline 266; +5 new).

### SKILL.md / README / references claim check

- Grep evidence: `grep -rn "1011|1012" SKILL.md
  README.md references/` — no hits; `grep -rn
  "tag extension|tag-extension"` over the same files —
  no hits; there is no `references/unreal*.md` file
  (Unreal is documented in
  `references/native-libs-and-jni.md` and
  `references/modern-analysis.md`). The only
  "unsupported" hits in `references/` are unrelated to
  the tag extensions: Unity metadata tooling
  (`native-libs-and-jni.md:88`), pak format versions
  8/9 (`native-libs-and-jni.md:142` — accurate:
  `nar-pak.py` refuses version >= 8), a triage listing
  rule, and a Unity IL2CPP note. **No stale Unreal
  limitation claim exists in SKILL.md, README.md or
  references/, so no doc file was changed in W2.**
  The stale sentence lived only in
  `scripts/nar-unreal.py` itself and is the one
  rewritten above.

### Files changed

- Changed: `scripts/narlib/uasset.py`,
  `scripts/narlib/zen.py`, `scripts/narlib/iostore.py`,
  `scripts/nar-unreal.py`, `tests/unit/test_unreal.py`,
  `NAR_2.5.2_UPDATE_REPORT.md` (this record).
- Banned-identifier / forbidden-credit grep over the
  W2 diff: zero hits. (The substring "seal" matches
  only inside "AES-sealed", the capability wording
  for encrypted indexes — not a tested-app name.)

## W3 — Configurable Unreal limits (2026-11-24)

### CLI and threading

- `scripts/nar-unreal.py` gains `--max-packages`,
  `--max-containers`, `--max-chunks`, `--max-names`
  (integers, negative values rejected) and
  `--all-packages`, `--all-containers`, `--all-details`
  (flags). Defaults equal the historical behaviour
  exactly: packages 5, containers 5, chunks (chunk /
  import / export / depends detail) 250, names 500,
  searchable-names detail 100, display lists 25, and
  IoStore package extraction in APK mode considering
  the first 2 `.utoc` containers. `--all-packages`
  lifts the package cap and that 2-container extraction
  limit together; `--all-containers` lifts the
  container cap; `--all-details` lifts the chunk, name,
  import/export/depends, searchable and display caps.
- A new `UnrealLimits` value (defaults from the
  historical constants, `None` = unlimited) is built by
  `limits_from_args()` and threaded through `analyze()`
  and every helper: `iostore_summary`,
  `zen_package_summary`, `package_summary`,
  `iostore_packages`, `pak_packages`, the bare
  `.pak`/`.utoc` paths, and every APK-mode loop (loose
  packages, containers, IoStore package extraction with
  a shared remaining allowance across the containers
  considered, and pak packages with a shared remaining
  allowance across the paks visited). Every report now
  carries the resolved limits under `limits`.
- Display-list decision: `config_files` and
  `package_files` are pure display lists with their own
  cap (`DISPLAY_CAP` = 25 by default, lifted by
  `--all-details`); their totals are always present
  alongside (`config_file_counts`, `package_file_counts`
  and the long-standing `package_file_count`), so a
  truncated display never hides a total.
- Memory discipline: packages and chunks are still
  processed one at a time and each extracted blob is
  released before the next item (the IoStore extractor
  loop drops its blob reference per chunk; the pak loop
  drops its blob dict per entry). The `--all-*` help
  text states the consequence honestly: items are
  processed one at a time, but the report grows with
  every item, which is the user's explicit choice.

### Accounting (no silent truncation)

- Every capped collection gains a structured
  `*_counts` record — `total` / `processed` / `skipped`
  / `failed`, where `failed` counts items attempted but
  recorded with an error: container chunk detail
  (`entries_counts`), per-package name / import /
  export / depends / searchable detail (`names_counts`
  etc. in classic and Zen records), bare-`.utoc`
  containers and packages (`iostore_container_counts`,
  `iostore_package_counts`), bare-`.pak` packages
  (`pak_package_counts`), and in APK mode
  `iostore_container_counts`, `package_counts`,
  `iostore_package_counts` (plus `containers_considered`
  vs `containers_total`), `pak_package_counts`,
  `config_file_counts` and `package_file_counts`.
- Cap notes were updated to name the active limit and
  how to lift it, e.g. the real-set chunk note now
  reads "chunk detail limited to 250 of 7,171
  (--all-details to lift); counts and totals cover
  every chunk", and APK-mode package/container caps
  append limitation notes of the same shape. Slice
  audit: every slice in `nar-unreal.py` is now either
  accounted as above or is one of the two display lists
  whose totals sit beside them; no unaccounted slice
  remains.

### Before / after on both local IoStore sets

- Method: `nar-unreal <utoc> --json` with default flags
  before the W3 change (tree at the W2 commit) and
  after it, JSON compared after stripping the allowed
  differences (limitations text, the `limits` record,
  the new `*_counts` records and the reworded capped
  notes). **Verdict: identical on both sets** —
  verdicts, container counts, chunk counts, file counts
  and package counts unchanged.
- UE 5.3 IoStore set (role label): 1 container, 7,171
  chunks (250 shown, counts 7,171/250/6,921/0),
  directory index 6,743 files, 5 package records
  (package counts: total 5,645 named, processed 0,
  skipped 5,640, failed 5 — the first five named
  packages are Oodle-compressed, so extraction fails
  per item, exactly as before).
- TOC v8 IoStore set (role label): 1 container, 2,912
  chunks (250 shown, counts 2,912/250/2,662/0),
  directory index 2,184 files, 5 package records
  (total 1,765 named, processed 1, skipped 1,760,
  failed 4). **Brief discrepancy, recorded plainly:**
  the W3 brief (and the W0 oracle list) names 13,494
  files for this set; the local set at the brief's own
  path measures 2,184 directory-index files (528
  directories). 13,494 is the file count of a different
  historical TOC v8 container (674 directories) cited
  in `CHANGELOG.md` / `NAR_GAP_ANALYSIS.md`. The
  before/after identity above is measured on the
  actual local set, whose chunk count (2,912) and
  stored-package count do match the brief.
- A raised-limits spot check on the TOC v8 set
  (`--all-details --max-packages 3`) showed all 2,912
  chunk entries with skipped 0 and package counts
  total 1,765 / failed 3 / skipped 1,762.

### Tests and battery

- `tests/unit/test_unreal.py`: +6 tests — defaults pin
  the historical caps exactly (`UnrealLimits` vs the
  module constants); a synthetic multi-package /
  multi-container APK built from the existing builders
  (30 loose packages, 7 IoStore containers, 30 config
  files) reproduces today's caps with correct
  total/processed/skipped/failed counts; raised limits
  (`--max-packages 10 --max-containers 6`) process more
  with correct counts; `--all-packages
  --all-containers --all-details` processes everything;
  a cap hit always leaves an explicit note plus counts
  in the JSON (chunk detail on a bare container and
  package/container notes in APK mode); per-package
  detail caps are accounted.
- Full unit suite before the W3 commit: **277 passed,
  0 failed** (W2 baseline 271; +6 new). E2E after W3:
  **65 passed, 0 failed, 0 skipped**. Doctor after:
  **Core toolchain: READY**.
- Banned-identifier / forbidden-credit grep over the
  W3 diff: zero hits.

### Files changed

- Changed: `scripts/nar-unreal.py`,
  `tests/unit/test_unreal.py`,
  `NAR_2.5.2_UPDATE_REPORT.md` (this record).

## W4 — Memory and performance (2026-11-24)

### What was mapped / streamed, per file

- **New helper `scripts/narlib/mmapio.py`** (tiny):
  `mapped_file(path)` context manager yielding a
  read-only `mmap.mmap` (`ACCESS_READ`) for a regular
  file, or the file's bytes for a tiny file (≤ 64 KiB,
  where a copy is cheaper than a mapping), an empty
  file, or when mmap fails. The mapping and the file
  handle are closed on context exit. The narlib parsers
  keep accepting plain bytes unchanged (zip members and
  test fixtures still pass bytes); one parser fix was
  needed for mmap input: `narlib/elf.py` tested the ELF
  magic with `bytes.startswith`, which mmap does not
  have — it now compares the `data[:4]` slice, identical
  for bytes and mmap.
- **`scripts/nar-unreal.py`**: the bare `.utoc` path
  maps the `.utoc` and the sibling `.ucas` (the large
  file: 219,935,664 B / 97,140,736 B in the benchmark
  sets) instead of `fh.read()`-ing both;
  `iostore.extract_chunk` slices only the blocks of the
  chunks actually extracted. The bare `.uasset`/`.umap`
  path maps the package (and its `.uexp` sibling when
  present) the same way. **APK/zip boundary (unchanged,
  stated plainly):** zip members still materialize via
  `zf.read()` — decompression requires it — and W4 did
  not restructure zip handling; the W3 one-at-a-time
  processing inside `iostore_packages` already releases
  each extracted blob before the next.
- **`scripts/nar-native.py`**: a bare `.so` is parsed
  by constructing `Elf` over an mmap. APK mode now
  processes libraries **one at a time inside the zip
  loop** (read member, write the readelf cross-check
  temp file exactly as before, parse, record, release)
  instead of accumulating every library's bytes in a
  list first. Additionally, profiling the benchmark ELF
  showed its remaining peak was not file bytes at all:
  `Elf.relocation_summary()` materialized all 551,383
  relocation entries as dicts (~218 MB transient) just
  to count them. `relocations()` is now a list built
  over a new `_iter_relocations()` generator, and
  `relocation_summary()` counts by streaming that
  generator — same logic, same output, no list.
- **`scripts/nar-pak.py`**: stays standalone
  (stdlib-only, no narlib import, by design), so it
  carries a local copy of the same idea (`_mapped()`).
  `list_pak` parses the footer/index from the mapping;
  `extract_pak` re-maps and the entry extractors read
  only the matched entries' ranges (plus their entry
  headers) — they already sliced per entry; now the
  backing store is a mapping instead of a whole-file
  bytes copy.
- **`scripts/nar-analyze.py`**: NOT restructured (see
  the diagnosis under the table). `sha256_of` already
  streamed and was left alone, here and in narlib.

### Oracle correction (from W3, applied here)

The W0 oracle line for the TOC v8 set read **13,494
files**; that count belongs to the *other* local TOC
v8 set (extracted under `nar-ue5-hunt/biy/`). The
br-work TOC v8 set used by the benchmarks and sweeps
names **2,184 directory-index files in 528 dirs**.
`tests/benchmarks/baseline-2.5.2.json` is corrected
accordingly (with an `oracle_correction_w4` note), and
the corrected counts were re-measured in W4, before
and after optimization, identical both times.

### Correctness gate (run BEFORE benchmarking)

Any mismatch would have stopped the workstream; there
were none.

- Full pytest (pre-benchmark): **284 passed, 1 failed**
  — the one failure was the docs-consistency guard
  `test_narlib_all_named`, because the README repo-
  structure block must name every narlib module and
  did not yet name the new `mmapio.py`. Fixed in this
  workstream by adding the README line; the final
  battery below is 285 passed, 0 failed (W3-end
  baseline 277, +8 new `test_mmapio.py` tests that
  parse synthetic iostore / Zen / uasset / ELF inputs
  as bytes and as forced mmaps and assert identical
  results, plus the helper's own
  tiny/large/empty/missing-file cases).
- IoStore directory-index counts (sweep over both
  sets, parsers fed via the new mapping): **6,743
  files / 489 dirs (UE 5.3 set)** and **2,184 files /
  528 dirs (br-work TOC v8 set)** — the corrected
  oracle, matching the pre-change byte-fed sweep
  exactly.
- Zen sweeps (same sweep): **684 stored packages
  parsed, 0 failures (UE 5.3 set)** and **525 parsed,
  0 failures (TOC v8 set)**, before and after.
- nar-unreal identity: `--json` output on both bare
  `.utoc` sets is **byte-identical** to the pre-W4
  output on this tree and to the W3 after outputs kept
  outside the repo (strip nothing). APK-mode output on
  a fixture APK and bare-`.uasset` output on a package
  extracted from the UE 5.3 set are likewise
  byte-identical old vs new.
- nar-native identity: `--json` output on the
  benchmark ELF is **byte-identical** before/after
  (checked again after the relocation-streaming
  change); APK-mode output on two fixture APKs (one
  Unity, one Unreal, both with `--work` so the readelf
  cross-check ran) is byte-identical old vs new, and
  the cross-check temp files are identical.
- nar-pak identity: `--json` listings on both local
  paks (UE 5.3-set pak: v11, 1,564 entries; br-work
  pak: v11, 1,598 entries) are **byte-identical**
  before/after; single-entry extractions from both
  paks produce byte-identical files (SHA-256 equal)
  and extraction reports identical modulo the output
  paths themselves.

### Before / after benchmarks (identical harness)

Same harness as W0 (`measure252.py`: fresh wrapper per
run, peak RSS = RUSAGE_CHILDREN of the direct child),
same inputs, same commands. Full record in
`tests/benchmarks/baseline-2.5.2.json` under
`after_w4`.

| Run | Wall before | Wall after | Peak RSS before | Peak RSS after | Δ peak |
|---|---:|---:|---:|---:|---:|
| nar-unreal, UE 5.3 IoStore set | 0.94 s | 0.48 s | 258,871,296 B | 40,079,360 B | −84.5% |
| nar-unreal, TOC v8 IoStore set | 0.67 s | 0.34 s | 124,968,960 B | 28,352,512 B | −77.3% |
| nar-native, largest ELF (81,159,656 B) | 1.84 s | 1.20 s | 306,999,296 B | 46,964,736 B | −84.7% |
| nar-analyze, 273 MB fixture | 462.73 s | 429.75 s | 1,888,186,368 B | 1,885,212,672 B | −0.16% |

Stated plainly: **the nar-analyze peak did not
improve** (−0.16% is noise; its wall time improved
7.1% as a side effect of the lighter stage tools).
The two nar-unreal stdout sizes differ from the W0
record because W2/W3 added report fields in between;
identity was proven against the W3 after outputs, not
against the W0 byte counts.

### Where the nar-analyze peak actually lives

Not in the optimized tools, and not in a whole-file
read in nar-analyze itself. Live RSS sampling during
the after run (stage subprocesses are grandchildren
of the measuring wrapper and excluded by the
methodology): nar-analyze sat at ~386 MB while its
early stage subprocesses ran; the nar-dex subprocess
peaked separately at ~1.2 GB; **the moment nar-dex
exited, nar-analyze itself spiked to a ~1.54 GB
plateau and stayed there** for the rest of the run.
The DEX stage document for this input is 298 MB as
compact JSON (373 MB as the indented companion file
in the finished case). nar-analyze's stage plumbing
captures that stdout whole (`subprocess.run` with
capture), `json.loads` it into a full dict graph,
`json.dump`s it twice (stage cache, then companion),
and retains the parsed graph for the correlation
stage. The peak is that JSON round-trip — captured
text + parsed graph + re-serialization overlapping —
inside the orchestrator process. No low-risk
in-process spot fix exists: the only whole-file reads
in nar-analyze are small cache-key/schema files, and
its hash already streams. Reducing this peak means
restructuring the orchestrator's stage plumbing
(e.g. file-based stage handoff instead of stdout
JSON), which W4 was instructed not to do; it is
recorded here as the diagnosed cause for a future
workstream. No nar-analyze code was changed in W4.

### Files changed

- Added: `scripts/narlib/mmapio.py`,
  `tests/unit/test_mmapio.py`.
- Changed: `scripts/nar-unreal.py`,
  `scripts/nar-native.py`, `scripts/nar-pak.py`,
  `scripts/narlib/elf.py` (magic slice comparison +
  streaming relocation summary), `README.md`
  (structure block names the new `narlib/mmapio.py`),
  `tests/benchmarks/baseline-2.5.2.json` (oracle
  correction + `after_w4` record),
  `NAR_2.5.2_UPDATE_REPORT.md` (this record).

### Battery after W4

- pytest: **285 passed, 0 failed** (277 at W3 end;
  +8 new mmapio tests).
- e2e (`bash tests/run_e2e.sh`): **65 passed,
  0 failed, 0 skipped**.
- doctor: **Core toolchain: READY**.
- Banned-identifier / forbidden-credit grep over the
  W4 diff: zero hits.

## W5 — Reproducible testing infrastructure

Goal: consolidate the suite's scattered synthetic builders
into one documented, reproducible testing infrastructure,
so what a clean clone can run — and what it cannot — is
explicit, and parser regressions against synthetic inputs
are caught by recorded builder intent rather than by the
private corpus alone. No existing test file was rewritten;
W5 adds new files and documentation only.

### What was built

- `tests/synthetic_fixtures.py` — a library of named
  builders producing minimal-but-valid synthetic samples
  on disk in a caller-chosen directory, for 11 fixtures:
  a DEX, an ELF shared object, a classic encoded-index
  v11 pak (4 entries), an IoStore .utoc/.ucas pair
  (TOC v6, 3 chunks, 3 directory-index files), a Zen
  package chunk (UE 5.3+ layout, 7 names / 3 imports /
  1 export), classic UAsset packages (UE4-versioned
  513, unversioned, and UE5 at object versions 1010,
  1011 and 1012+), and a Godot .pck (format 2, 2 files;
  a builder already existed in the suite, so it is
  included, not skipped). Where a builder already
  existed inside a test file and is importable under a
  bare python3, the library IMPORTS it (DEX/ELF from
  `test_dex_elf.py`, pak from `test_pak.py`, IoStore
  from `test_iostore.py`, UAsset from `test_uasset.py`,
  Godot from `test_godot.py`). One honest exception:
  the Zen builder is a minimal equivalent implemented
  in the library, because `test_zen.py` imports pytest
  at module level and is therefore not importable under
  the bare python3 that runs the generator CLI; the
  equivalence is pinned by the parser assertions below.
- `tests/generate_fixtures.py` — CLI:
  `python3 tests/generate_fixtures.py --out DIR` writes
  all 12 fixture files + the manifest into DIR, on a
  bare python3 (stdlib only), verified in this run.
- `tests/expected_outputs.json` — the committed
  expected-output manifest, generated BY the generator
  script. Design: the manifest records the BUILDER's
  intended facts (pak entry count and per-entry
  compression, IoStore chunk/file/directory counts and
  layout, Zen layout + counts, UAsset versions +
  name/import/export counts and tag layouts, DEX
  string/type/proto/method/class-def counts, ELF arch
  and section/program-header counts, Godot file count),
  never facts measured from the parsers at generation
  time — a parser-measured manifest would be circular
  and could never catch a regression. The regression
  tests assert parser output == builder intent.
- `tests/unit/test_synthetic_fixtures.py` — 18 new
  tests, needing NO private files: (a) a drift guard
  asserting the committed manifest equals the library's
  builder intent and the generated files match its
  recorded sizes; (b) per-fixture parser assertions
  against the manifest facts using the real narlib
  parsers (and the nar-pak / nar-godot script modules);
  (c) CLI smoke on the synthetic files for every parser
  CLI that takes a bare file — nar-unreal on the
  synthetic .utoc and on the synthetic .uasset, nar-pak
  on the synthetic pak, nar-native on the synthetic
  ELF, and nar-dex on the synthetic DEX (nar-dex's help
  names a bare .dex target explicitly, so it fits and
  is smoked, not skipped) — each asserting exit 0 plus
  the key JSON fields. No CLI was skipped: all five
  fit the synthetic fixtures.

### Test categories (documented in NAR_TEST_MATRIX.md)

A new "Test categories" section in `NAR_TEST_MATRIX.md`
classifies the whole suite, with how to run each
category and what an absence produces:

- **Public Synthetic Tests** — the unit suite's
  self-contained tests plus the new synthetic-fixture
  tests; runnable from a clean clone; this is what
  nar-ci runs. Absence: not applicable.
- **Private Corpus Tests** — the individual unit cases
  bound to `$NAR_FIXTURES`: `test_engine_intel.py` (1
  case), `test_schemas.py` (the generated-case class,
  4 tests, + 1 sidecar case), `test_phase8_orchestration.py`
  (1 case), `test_runtime_sessions.py` (1 case).
  Absence: SKIP with reason, never a failure.
- **Real-World Authorized Tests** — the e2e harness
  (65 cases, role-bound private corpus incl. the demo
  APK, which is not in the repo) and corpus sweeps;
  local-only, never in CI. Absence: per-case SKIP.
- **Optional Tool Integration Tests** — no test
  hard-requires an external tool: registry probes treat
  `available=False` as a normal result (pinned by
  `test_registry.py`), runtime tests use fabricated
  probe records, and the only library gate is PyYAML
  (`test_yaml_validation.py`, one class in
  `test_docs_consistency.py`). Absence: probe records
  or SKIP, never a failure.
- **Performance Benchmarks** —
  `tests/benchmarks/run_benchmarks.py` +
  `baseline-2.5.2.json`. Absence: metrics report
  NOT RUN with the reason, never estimated.

`README.md` had no "Running the tests" pointer, so a
short one was added (unit suite, fixture generator,
e2e, and a link to the categories section); its
structure block needed no change (the docs-consistency
test enumerates scripts/references/schemas, not tests/).

### The proof (clean extraction)

The committed tree was exported with `git archive HEAD`
into a scratch directory under `~/workspace/nar-tmp/`
and the pytest suite was run there with
`NAR_FIXTURES` pointed at an EMPTY directory and no
reliance on `~/workspace` paths (the venv interpreter
excepted, as the test runner):

- Normal run (working tree, real corpus bound):
  **303 passed, 0 skipped, 0 failed** (285 at W4 end
  + 18 new synthetic-fixture tests).
- Clean-extraction run (empty `NAR_FIXTURES`):
  **295 passed, 8 skipped, 0 failed** — exactly the 8
  private-corpus cases report SKIP (the four bound
  files alone: 19 passed, 8 skipped, 0 failed,
  matching the W0 measurement). No test hard-fails on
  absence.

### Defects found

None in the shipped code: no test hard-fails when the
private corpus is absent, so no skip-fix was needed.
One authoring correction during development, in the
new test file only: the IoStore directory index's
flattened paths ride on the parsed entries' `file`
fields, not on the directory-index summary dict; the
assertion was corrected to the parser's actual record
shape (the manifest fact itself was unchanged).

### Files changed

- Added: `tests/synthetic_fixtures.py`,
  `tests/generate_fixtures.py`,
  `tests/expected_outputs.json`,
  `tests/unit/test_synthetic_fixtures.py`.
- Changed: `NAR_TEST_MATRIX.md` ("Test categories"
  section), `README.md` ("Running the tests" pointer),
  `NAR_2.5.2_UPDATE_REPORT.md` (this record).

### Battery after W5

- pytest: **303 passed, 0 failed** (285 at W4 end;
  +18 new synthetic-fixture tests).
- e2e (`bash tests/run_e2e.sh`): **65 passed,
  0 failed, 0 skipped**.
- doctor: **Core toolchain: READY**.
- Banned-identifier / forbidden-credit grep over the
  W5 diff: zero hits.

## W6 — Cross-system consistency and capability matrix

### Surfaces audited (method)

- **Parser capabilities vs reporting:** the three narlib
  `capabilities()` dicts (uasset / zen / iostore) printed
  and compared against nar-unreal's generated limitations,
  the Unreal sections of SKILL.md / README.md /
  references/native-libs-and-jni.md, and
  `nar-unreal --help`.
- **Tool registry, four ways:** scripts/registry.json
  parsed (35 tools, registry_version 2.5.1, 9 entries of
  kind `unavailable`), scripts/narlib/registry.py read,
  `python3 scripts/nar.py tools --json` executed (same
  35 names/kinds/required levels), and
  references/tool-registry.md read against both.
- **Schemas:** all 24 files in schemas/ parsed as JSON;
  the case-document table in references/output-schema.md
  compared against the schema set and the 2.5.1 record.
- **CLI surface:** `python3 scripts/nar.py --help`,
  `nar version` (2.5.1, agreeing with all version-bearing
  files), every `nar-*.py --help` (24 scripts, all exit
  0), and every dispatcher verb's `--help` path through
  nar.py (27 verbs in COMMANDS + `case` + `version`).
  SKILL.md routing verbs/scripts were re-checked beyond
  the phase-10 tests by reading the actual help text.
- **Documents:** SKILL.md, README.md,
  NAR_ARCHITECTURE.md, NAR_GAP_ANALYSIS.md,
  NAR_TEST_MATRIX.md, CHANGELOG.md read in full against
  the tree (narlib inventory, schema count, guide count,
  W1–W5 changed facts).

### Contradictions found and fixed (doc-side; code is truth)

1. **NAR_ARCHITECTURE.md — narlib inventory stale.**
   The Core library list named 8 modules; the tree has
   18. It omitted dexdis, dotnetmeta, oat, iostore,
   uasset, zen, signatures, companions, correlations,
   and mmapio (the last four from the 2.5.x / evolution
   workstreams). Fixed in place: all 18 modules now
   listed with their roles, plus an inventory addendum
   header recording the re-audit.
2. **NAR_ARCHITECTURE.md — schema inventory stale.**
   The Schemas section listed 9 schema names ("the 2.0
   outputs"); schemas/ holds 24 (2.5.1). Fixed: the
   section now states 24 and names the full set.
3. **NAR_ARCHITECTURE.md — doctor "profile groupings"
   do not exist.** The Registries section claimed
   nar-doctor.sh "gains profile groupings"; the script
   has no profiles — it is a flat core/optional list
   (22 checks at 2.5.2). Fixed to describe the actual
   checks and the test-kept (not by-construction)
   consistency with the registry.
4. **NAR_ARCHITECTURE.md — unified CLI "profiles"
   do not exist.** The Compatibility section claimed
   nar.py "adds profiles, module selection"; nar.py
   has no profile or `--module`/`--engine` flags.
   Fixed: 27 dispatcher verbs + `case` + `version`,
   module selection = choice of verb, budgets live on
   nar-analyze.
5. **NAR_ARCHITECTURE.md — external-tool list stale.**
   The layer diagram's orchestrated-tools list omitted
   Cpp2IL (a registered, doctor-probed backend since
   2.1.0) and smali/objdump. Fixed; the diagram now
   also states the registry totals (35 declared,
   9 unavailable), matching registry.json and
   `nar tools --json`.
6. **references/output-schema.md — DEX/native schemas
   shown as absent.** The case table gave the schema
   column for `dex.json` / `dex/classes.json` /
   `dex/methods.json` and for `native.json` as "—",
   contradicting 2.5.1, which shipped dex.schema.json,
   dex-classes.schema.json, dex-methods.schema.json,
   and native.schema.json (all present and parsing).
   Fixed: the rows now name their schemas.
7. **references/tool-registry.md — discovery order
   imprecise.** Step 5 claimed probing falls back to
   "`~/workspace/tools/<name>`"; narlib/registry.py
   actually uses each entry's declared
   `workspace_subdirs` under `~/workspace/`. Fixed,
   and a sentence added pinning the registry totals
   (35 tools, 9 unavailable) to the `nar tools --json`
   output, which was executed and agrees.
8. **SKILL.md — doctor check list incomplete.** The
   "Check tools first" paragraph omitted cpp2il
   (optional, doctor-probed since 2.1.0) and all three
   self-checks (bundled-scripts compile and
   protection-signatures, both core; skill-yaml,
   optional, added in W1). Fixed to name them.
9. **SKILL.md — Unreal routing row predates W2/W3.**
   The `.uasset`/`.umap` row described only summary +
   tables; nar-unreal reports now carry `limits` +
   generated `capabilities` and the `--max-*` /
   `--all-*` flags with accounting. Fixed in the row
   (every flag named there is defined by
   nar-unreal.py, as the phase-10 guard verifies).
10. **README.md — "What's new in 2.0" misattributes
    later Unreal work.** That bullet credited 2.0 with
    "IoStore entry-level parsing and UAsset-level
    package inspection"; CHANGELOG.md records
    entry-level IoStore parsing as new in 2.1.0 and
    UAsset-level inspection as new in 2.2.0 (2.0.0's
    nar-unreal shipped IoStore inventory with its
    parsing limit stated). Fixed: the bullet now
    describes the 2.0 scope and points to the
    changelog for the 2.1.0 / 2.2.0 arrivals.
11. **README.md — no 2.5.1 section.** The README is
    version 2.5.1 but its newest "What's new" section
    was 2.5.0. Fixed: a short 2.5.1 section (schema
    layer, 24 schemas, regression guards) added above
    the 2.5.0 section, matching CHANGELOG.md.
12. **NAR_GAP_ANALYSIS.md — end-state statuses
    predated W1–W5 (and the Phase 0 table reads as
    current).** Fixed by the document's own convention
    (historical tables untouched): a "2.5.2 W6
    reconciliation addendum" now (a) indexes which
    Phase 1–11 addenda supersede each Phase 0 PI row,
    (b) corrects the "frontmatter valid" record —
    both skill YAML files were invalid under a real
    parser in the shipped 2.5.0/2.5.1 tree until W1,
    (c) supersedes the Unreal row's "tag-extension
    layouts missing/unproven" with implemented,
    synthetic-verified + W2 generated reporting,
    (d) records the W3 configurable-limits change
    (the caps were hardcoded in code, never stated in
    this document), (e) clarifies the two TOC v8
    file counts (13,494 = the historical set;
    2,184 = the br-work benchmark set — both correct
    for their own set, not an error), and (f) records
    the W4 mmap layer and the W5 test-reproducibility
    state.
13. **NAR_TEST_MATRIX.md — executed record stopped at
    2.5.0.** Its addenda ended at pytest 239 (Phase
    12); the 2.5.1 schema guards and the W1–W5 test
    additions were recorded only in CHANGELOG.md /
    this report (W5's categories section excepted).
    Fixed: a "2.5.1 + 2.5.2 W1–W5" addendum now
    records them, including the correction that the
    Phase 10 addendum's "frontmatter parses" was a
    regex-level check.
14. **README.md structure block — new files
    registered.** NAR_CAPABILITY_MATRIX.md (below) and
    the W5 test files (tests/synthetic_fixtures.py,
    tests/generate_fixtures.py,
    tests/expected_outputs.json) are now named in the
    block, so the block stays a complete inventory.

### Checked and found consistent (no change)

- Registry four-way agreement: registry.json,
  narlib/registry.py, `nar tools --json`, and
  references/tool-registry.md statuses agree
  (35 tools; the same 9 unavailable names everywhere
  they are listed). The doctor's check list is a
  deliberate subset (core + common optional + 3
  self-checks), documented as a parallel implementation
  in the gap analysis — not a contradiction.
- nar-unreal `--help` already reflects the W3 flags
  exactly (defaults 5 / 5 / 250 / 500 and the three
  `--all-*` lifts); no stale "unsupported" claim for
  1011/1012 exists in SKILL.md, README.md, or
  references/ (grep-verified, as in W2).
- Version agreement: `nar version`, skill.yaml,
  SKILL.md, plugin.json, pyproject, README, registry,
  and the module `"version"` fields all read 2.5.1
  (guarded by test_docs_consistency).
- pyproject `requires-python >=3.10` vs the guides'
  "Python 3.9+" for running the scripts directly:
  left unchanged — the pyproject field governs the
  (empty) packaging metadata, the scripts parse under
  a 3.9 grammar check, and a 3.9 runtime was NOT RUN
  in this audit, so neither side could be corrected
  on evidence.

### CHANGELOG.md entries flagged (listed, not edited)

Per the workstream rule, history sections were not
rewritten. Entries that later work proved inaccurate
or superseded, for the W8 author's attention:

- **2.5.0, Phase 10 entry:** "programmatic SKILL.md
  frontmatter + plugin.json validation" — the
  validation was regex-level; the frontmatter was in
  fact invalid YAML in the shipped 2.5.0/2.5.1 tree
  (proven in W0/W1). The entry overstates what was
  validated.
- **2.2.0, UAsset entry:** "the UE5 tag-extension
  layouts are reported as unparsed" — true at 2.2.0,
  superseded by the 2.5.0 Phase 4 entry (implemented,
  synthetic-verified) in the same file.
- **2.4.0, runtime entry:** "no RegisterNatives
  events … the event path remains labeled unverified"
  — true at 2.4.0, superseded by the 2.5.0 Phase 6
  entry (events captured live on the emulator).
- **2.1.0, runtime entry:** runtime
  IMPLEMENTED_BUT_UNVERIFIED — superseded for emulator
  scope by the 2.2.0 entries, which say so themselves.
- No flat factual error requiring an in-place
  correction was found in the 2.5.0/2.5.1 sections;
  the 2.5.1 "schema set is now 24" claim was verified
  against the tree (24 files, all parsing).

### Code defect found (reported, not fixed — doc-side
workstream)

- **nar-doctor.sh `nar-scripts` check overclaims.**
  The check compiles only 10 named scripts
  (nar-triage, nar-strings, nar-perms, nar-compare,
  nar-pak, nar-analyze, nar-il2cpp, nar-flutter,
  nar-godot, nar-rn — the 1.1.0-era set) but reports
  the detail "all bundled scripts compile". The tree
  has 24 Python scripts under scripts/; the other 14
  (including nar.py, nar-dex.py, nar-native.py,
  nar-unreal.py, nar-tools.py) are not compile-checked
  by the doctor. Evidence: the loop list in
  scripts/nar-doctor.sh (nar-scripts block) vs
  `ls scripts/*.py` = 24. The matrix's Tool registry
  row carries this defect note. Fix belongs to a
  code workstream: extend the loop to every
  scripts/*.py (and narlib) or narrow the detail text.

### Capability matrix (new file)

- **NAR_CAPABILITY_MATRIX.md** (repo root, registered
  in the README structure block): 47 rows, one per
  capability area (gap-analysis skeleton, refined),
  columns Capability | Status | Evidence, using
  exactly the prescribed status vocabulary. Counts:
  Tested 21, Independently verified 7, Partially
  supported 8, Implemented 4, Unsupported 7.
- Honest partials/unsupported are rows in their own
  right: physical-device runtime (Implemented,
  emulator-verified only), UE5 1011/1012 (Implemented,
  synthetic-verified), Zen pre-5.3/EA layouts
  (Implemented, synthetic), OAT beyond API 26
  (Partially supported, synthetic beyond 26), CDEX
  payload decoding (Unsupported), Kismet/Blueprint
  graph decoding (Unsupported, PLANNED), Oodle
  decompression (Unsupported by design), AES
  decryption (Unsupported by design), real-corpus
  engine precision (Unsupported — NOT RUN, no labeled
  negatives), and the Play Integrity server-side
  verdict (Unsupported from the client).
- Every row's evidence names its backing test file,
  corpus role label, or oracle (dexdump 40,837
  methods, readelf cross-checks, byte-walk oracles
  on the real IoStore/Zen sets, the labeled-corpus
  benchmark metrics). No new claims were introduced.

### Files changed

- Added: `NAR_CAPABILITY_MATRIX.md`.
- Changed: `NAR_ARCHITECTURE.md`,
  `NAR_GAP_ANALYSIS.md`, `NAR_TEST_MATRIX.md`,
  `README.md`, `SKILL.md`,
  `references/output-schema.md`,
  `references/tool-registry.md`,
  `NAR_2.5.2_UPDATE_REPORT.md` (this record).
- No code files changed; the one code defect found is
  reported above, not fixed.

### Battery after W6

- pytest: **303 passed, 0 failed** (same count as W5
  end — W6 adds no tests; the docs-consistency and
  phase-10 guards pass over all edited documents,
  including the SKILL.md flag line and the README
  structure block with the new matrix file).
- e2e (`bash tests/run_e2e.sh`): **65 passed,
  0 failed, 0 skipped**.
- doctor: **Core toolchain: READY** (22 checks,
  including `skill-yaml` OK).
- Banned-identifier / forbidden-credit grep over the
  W6 diff: zero hits (the only credit line used is
  "Research by Bakr Fayez").

## W7 — Regression and security testing (2026-11-24)

### Mandated fix first: the doctor `nar-scripts` check

- **Defect (found by W6):** `scripts/nar-doctor.sh`'s
  `nar-scripts` check compiled only 10 hand-listed
  1.1.0-era scripts but reported "all bundled scripts
  compile"; the tree has 24 Python scripts under
  `scripts/`.
- **Fix:** the check now iterates the `scripts/*.py`
  glob (no name list, so the checked set cannot drift
  from the tree again), compiles each file into the
  same throwaway temp dir as before (verified: no new
  `__pycache__` entries in the tree), and its detail
  text now states the true count. The check stays
  core-class; READY semantics unchanged.
- **Evidence:** doctor after the fix reports
  `OK nar-scripts all bundled scripts compile
  (24 scripts)` and **Core toolchain: READY** (also
  `ok` with count 24 in `--json` output). All 24
  scripts were also compile-checked independently
  before the fix: zero failures — the defect was in
  the check's coverage, not in any script.
- **Regression tests:** two tests in the new file
  below — a static drift guard (the nar-scripts block
  must glob `scripts/*.py` and must not contain the
  old hand list) and a behavioral test that runs the
  doctor, asserts the nar-scripts detail names the
  live `scripts/*.py` count, and asserts the run left
  the tree's `__pycache__` set unchanged.

### Coverage inventory (what already existed, relied on, not duplicated)

- `test_phase11_mutations.py` — truncated/corrupt
  DEX, ELF, PAK, IoStore TOC and Zen headers failing
  with named errors (bad magic, truncation, one
  inflated DEX count).
- `test_safearchive.py` — traversal / absolute /
  symlink rejection, compression-ratio and total-size
  limits, nested-archive listing.
- `test_schemas.py`, `test_yaml_validation.py` (W1),
  `test_evidence.py` — schema files, skill YAML,
  evidence builders and the generic validator.
- `test_phase8_orchestration.py` — budgets, case
  tamper/verify; `test_unreal.py` (W2/W3) — capability
  reporting, limits accounting, per-item failures;
  `test_network_phase5.py` — nar-network redaction of
  planted credentials at its own layer.
- Parser suites `test_dex_elf.py`, `test_iostore.py`,
  `test_zen.py`, `test_uasset.py`, `test_pak.py` and
  the W5 `test_synthetic_fixtures.py` builders —
  valid-input oracles and builder libraries reused
  for the mutations below.

### Tests added: `tests/unit/test_security_regression.py` (29 tests)

1. **Invalid offsets (7):** DEX string-table and
   type-table offsets beyond EOF → DexError; ELF
   section-header offset beyond EOF, program-header
   offset beyond EOF, `shstrndx` out of range, and a
   truncated ELF64 header → ElfError; UAsset
   name-offset and import-offset beyond EOF →
   UAssetError; IoStore `extract_chunk` with an
   out-of-range chunk index and with a block offset
   outside the .ucas → IoStoreError; Zen offset-table
   entry (imported package names) beyond the chunk →
   ZenError. No IndexError/struct.error leaks.
2. **Oversized/hostile archives (3):** a zip whose
   central directory declares a ~4 GiB member over 16
   real bytes → safearchive per-file declared-size
   guard fires, nothing extracted; a 6-member zip
   against a 5-entry limit → whole-archive rejection;
   a pak footer claiming an index size 10× the file →
   `list_pak` reports unsupported, "outside the file".
3. **Memory-exhaustion guards (1 test, 4 cases):**
   absurd counts — DEX `string_ids` (Phase 11
   regression), Zen name-batch count, IoStore TOC
   entry count, UAsset name count — each fails with
   its named error; the group asserts a fast return
   (< 10 s for all four; measured in well under 1 s).
4. **Invalid container metadata (4):** pak with no
   footer magic → PakError; pak footer version 9 →
   reported unsupported by name; .utoc with bad magic
   and with TOC version 99 (> max supported 10) →
   IoStoreError; Zen chunk with a bad trailer magic →
   `is_zen_package` is False and parsing raises
   ZenError (identification never claims a parse).
5. **Partial extraction failures (3):** the W5-era
   v11 pak builder with the stored entry's payload
   flipped (SHA-1 mismatch) among intact zlib entries
   — module level: both zlib entries extract, the
   corrupt entry and the undecodable entry are
   per-entry errors; CLI level: `nar-pak --extract
   --json` exits 1, no traceback, JSON shows 2
   extracted / 2 errors; plus the decompression-cap
   regression test under Defects below.
6. **Orchestration/evidence/CLI/security (3):**
   nar-analyze on a garbage non-archive file (see
   Defects); `evidence.validate` against the shipped
   security-findings schema rejecting a finding with
   required fields removed (and a bad severity enum),
   while a complete `make_finding` result validates;
   nar-security composed over the real nar-network
   redaction pass (tool calls stubbed, the phase-5
   pattern) on a planted cleartext endpoint carrying
   a credential value — the raw value never appears
   in nar-security's JSON, the REDACTED marker and
   the cleartext finding's count do.
7. **Path traversal (2):** a classic v5 pak (small
   builder in the new file, for names the encoded
   builder cannot express) with a `../../evil.txt`
   entry — extraction stays inside the out dir (the
   entry lands under a sanitized relative path; the
   naive-join target is never written); nar-input's
   own `extract` command on a traversal zip — the
   entry is rejected as traversal and the good entry
   extracts. (Zip-level traversal itself was already
   covered by `test_safearchive.py` and is not
   duplicated.)
8. **Doctor (2):** as recorded above.

### Defects found and fixed in-cycle (each with its proof test)

1. **narlib.elf leaked / silently tolerated corrupt
   header offsets.** `program_headers()` with `phoff`
   beyond EOF raised a bare `struct.error`; a 52–63
   byte ELF64 header leaked the same way from the
   header unpack; `sections()` silently returned `[]`
   for a section-header offset beyond EOF (so
   `facts()` reported a section-less file instead of
   a corrupt one) and silently treated an out-of-range
   `shstrndx` as "no string table". Fix
   (`scripts/narlib/elf.py`): the constructor rejects
   a header shorter than the class's fixed size;
   `program_headers()` and `sections()` raise
   ElfError naming the entry that extends past EOF;
   a nonzero `shstrndx` outside the section table
   raises ElfError (the SHN_XINDEX escape keeps its
   old behaviour, and `shoff == 0` still means no
   section table). Proof: the four ELF tests in
   area 1; the good synthetic ELF's facts are
   unchanged, and the full battery below passes over
   the real corpus.
2. **nar-analyze exited 0 on a garbage target.**
   Triage records `"not a valid ZIP/APK container"`
   (and nar-triage's own CLI exits 1 on it), but the
   orchestrator ignored the field and produced a
   full workup — including a default identity kind of
   "apk" — for a non-archive file. Fix
   (`scripts/nar-analyze.py`): after triage, a target
   with a triage error records the same `fatal` the
   missing-JSON path records and returns, so the CLI
   exits 1 with the fatal in the report. OBBs are
   exempt: an OBB may legitimately be a non-ZIP
   container and its string stage runs by design.
   Proof: the area-6 nar-analyze test (exit 1, fatal
   recorded in stdout JSON and in the written
   report.json, no traceback); measured before the
   fix: exit 0, no fatal, identity kind "apk".
3. **nar-pak inflated compressed entries fully
   before checking their promised size.** The only
   bound was an after-the-fact length comparison, so
   a hostile entry expanding far beyond its declared
   uncompressed size was fully materialized first.
   Fix (`scripts/nar-pak.py`): a `_decompress_capped`
   helper (zlib/gzip via `decompressobj`) bounds
   inflation at the size the index/header already
   promise — per entry, and per block against the
   remaining promised bytes — and refuses streams
   that expand past it, are corrupt, or are
   truncated; both extractors (classic and encoded)
   use it. Successful extractions are byte-identical
   (any entry that succeeded before decompresses to
   exactly its promised size, so the cap never
   binds). Proof: the area-5 cap test (a stream
   expanding to 100,000 bytes against a promised 10
   is refused with "expands past"); the existing
   pak extraction tests and the e2e pak cases pass
   unchanged.

No other defect was found: every other area's
expected guard already fired as designed (DEX /
UAsset / IoStore / Zen named-error paths, the
safearchive declared-size and count guards, the pak
footer bounds check, and the nar-network →
nar-security redaction chain).

### Files changed

- Added: `tests/unit/test_security_regression.py`
  (29 tests).
- Changed: `scripts/nar-doctor.sh` (nar-scripts glob
  fix), `scripts/narlib/elf.py` (named-error header
  validation), `scripts/nar-analyze.py` (fatal on a
  triage-error target), `scripts/nar-pak.py`
  (bounded decompression; the now-unused `gzip`
  import removed), `NAR_2.5.2_UPDATE_REPORT.md`
  (this record).

### Battery after W7

- pytest: **332 passed, 0 failed** (303 at W6 end;
  +29 new).
- e2e (`bash tests/run_e2e.sh`): **65 passed,
  0 failed, 0 skipped**.
- doctor: **Core toolchain: READY** (nar-scripts:
  "all bundled scripts compile (24 scripts)").
- Banned-identifier / forbidden-credit grep over
  the W7 diff: zero hits.

## W8 — Release preparation (2026-11-24)

- Version bumped to **2.5.2 in all 18 version-bearing
  locations** (20 replacements; nar-runtime carries
  three version fields). The docs-consistency
  version test passes at 2.5.2 and `nar version`
  prints "NAR 2.5.2".
- CHANGELOG gained "## 2.5.2 (2026-11-24)" (the W1–W7
  record, including the correction of the 2.5.0
  Phase 10 "programmatic frontmatter validation"
  overstatement flagged by W6). README gained a
  "What's new in 2.5.2" section.
- **Final battery on the release tree (executed):**
  pytest **332 passed, 0 failed**; e2e **65 passed,
  0 failed, 0 skipped**; doctor **Core toolchain:
  READY** (24 scripts compiled by the nar-scripts
  check, skill-yaml OK); CLI smoke **28/28** (every
  registered verb + `nar version` answers --help
  with exit 0).
- Greps over the whole branch diff (7f16b7f..HEAD):
  banned identifiers **0 real hits** (one regex
  false positive on the word "measuring"), forbidden
  credits **0**; the only credit anywhere is
  "Research by Bakr Fayez".
- Branch totals (W0–W8): 9 commits on
  `update-2.5.2`; W0–W7 changed 32 files
  (+5,386/−234); the W8 commit changes 20 files
  (+217/−26; the 18 version locations, CHANGELOG,
  README, this report), 8 of them already counted
  in the W0–W7 set; the branch union is 44 files
  (+5,599/−256). **Nothing was pushed, tagged,
  merged or released** — the tree is clean and
  release-ready; publication is the owner's
  separate authorization.

### Tests summary for the program

- Executed: the full pytest suite at every
  workstream gate (246 → 266 → 271 → 277 → 285 →
  303 → 303 → 332), the e2e suite at W0/W3/W4/W5/
  W6/W7/W8 (65 passed every time), doctor at every
  gate (READY every time), the clean-extraction
  public-suite proof (W5: 295 passed, 8 skipped,
  0 failed), the correctness oracles (W4: IoStore
  6,743 + 2,184 files, Zen 684 + 525 parses,
  byte-identical tool outputs), and the W0/W4
  benchmark pairs on identical inputs.
- Failed: 0 in every final gate run. (Two transient
  in-development failures were fixed in-cycle and
  are recorded in their workstream sections: a
  docs-consistency failure over the new mmapio
  module in W4, and a test-authoring correction in
  W5.)
- Skipped: only the 8 private-corpus pytest cases
  in the clean-extraction proof, each with a stated
  reason — SKIP never counted as PASS anywhere.

## Remaining limitations

Stated plainly, unchanged in kind from the capability
matrix (NAR_CAPABILITY_MATRIX.md):

- **nar-analyze peak memory did not improve.** Its
  ~1.89 GB peak on the 273 MB fixture is the
  orchestrator's DEX-stage JSON round-trip (a
  ~298 MB compact stage document captured, parsed,
  written twice and retained for correlations).
  Fixing it needs a stage-plumbing restructure,
  which this program's scope excluded; the optimized
  tools themselves (nar-unreal, nar-native, nar-pak)
  all improved 77–85% on peak RSS with
  byte-identical output.
- **Runtime verification is emulator-only.**
  Physical-device (owner's phone) verification
  remains NOT RUN; all Frida paths are live-proven
  on the API 26 emulator only.
- **Synthetic-verified areas remain synthetic:**
  UE5 tag-extension layouts 1011/1012+ (no real
  versioned classic UE5 package exists in any
  examined corpus), Zen pre-5.3/EA layouts, OAT/VDEX
  beyond API 26 x86_64, recorded Zen versioning.
- **Unsupported by design (not defects):** Oodle
  decompression, AES/encryption decryption and key
  extraction, Kismet/Blueprint graph decoding,
  class-specific export decoding, Play Integrity
  server-side verdicts, CDEX decoding.
- **Real-corpus engine precision is NOT RUN** — no
  labeled engine-negative real corpus exists; recall
  on labeled positives is measured (6/6), precision
  is not claimed.
- **CI:** nar-ci runs the pytest suite; the new
  YAML tests exercise fully only where PyYAML is
  installed (declared in pyproject's test/dev
  extras in W1) and SKIP honestly where it is not.
  `.github/workflows/ci.yml` itself was not edited
  in this program (the push channel cannot carry
  workflow changes); adding `pip install pyyaml` to
  it is a one-line follow-up for the owner to apply
  via the web UI if full CI YAML coverage is wanted.
- **pyproject `requires-python >=3.10` vs guides'
  "Python 3.9+":** neither side corrected — a 3.9
  runtime was NOT RUN in this program, so there is
  no evidence to move either claim (recorded in W6).
