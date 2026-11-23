# NAR Test Matrix — 2.0 program

How every 2.0 requirement is tested, with what fixture, and
its status. Fixtures are bound by role through
`$NAR_FIXTURES` + the local uncommitted manifest (never named
in this repo). "Synthetic" fixtures are purpose-built by the
project's own demo build pipeline or planted-marker copies.

## Test layers

1. **Unit tests** — `tests/unit/` (pytest; tests also run
   under plain `unittest`). Pure-parser and guard tests with
   synthetic inputs built inside the test.
2. **End-to-end harness** — `tests/run_e2e.sh`: every script
   against the fixture corpus; exit 1 on any failure; absent
   fixtures SKIP, never PASS.
3. **Benchmarks** — `tests/benchmarks/`: measured accuracy
   and timing over the corpus, methodology documented.
4. **Regression** — 1.x script outputs on the corpus diffed
   before/after 2.0 changes; additive-only JSON changes pass.

## Matrix

| Area (brief §) | Test | Fixture / input | Layer | Status at audit |
|---|---|---|---|---|
| Doctor verdict (§19) | READY + exit 0; jadx real-start | host toolchain | e2e | IT |
| Triage identity (§3.2) | package + version line | synthetic demo APK | e2e | IT |
| Container parsing (§3.1) | XAPK manifest + splits | container fixture | e2e | IT |
| Packer attribution (§8.4/§3.3) | named on doctored, zero on clean set (9 files) | doctored + clean fixtures | e2e | IT |
| Kotlin evidence (§4.3) | present on Compose, absent on pure-Java | two app fixtures | e2e | IT |
| Strings discipline (§7.1) | planted token caught; key hits bounded | demo + Unreal game fixtures | e2e | IT |
| Compare deltas (§11) | added permission + method growth | demo version pair | e2e | IT |
| Perms defaults (§9.1) | platform-default wording | Unreal game fixture | e2e | IT |
| Pak list/extract (§5.2) | 1,598 entries; extract byte-verified vs independent parse | Unreal pak fixture | e2e | IT |
| IL2CPP (§5.1) | metadata version + dumper summary | Unity fixture | e2e | IT |
| Flutter (§5.4) | Dart fingerprint + clean negative | Flutter + demo fixtures | e2e | IT |
| Godot (§5.3) | listing + encryption flag | PCK fixture | e2e | IT |
| React Native (§5.5) | Hermes version + clean negative | RN + demo fixtures | e2e | IT |
| Framework markers (§3.3) | 8 path + 7 DEX marker families | doctored framework fixtures | e2e | IT |
| 16 KB alignment (§6) | evidence line present | demo fixture | e2e | IT |
| Form factors (§3.2) | Android TV from leanback | TV-declaring fixture | e2e | IT |
| Analyze reports (§12/§13) | sections present, app + game | two fixtures | e2e | IT |
| Frida templates (§8.2) | node --check ×4 | repo files | e2e | IT |
| Format identification (§3.1) | magic/structure verdicts per format | synthetic per-format files | unit | M → Phase 2 |
| Safe extraction (§3.1) | slip/traversal/symlink/bomb/nesting all rejected + reported | planted archives | unit | M → Phase 2 |
| Evidence schema (§13) | valid + invalid documents | synthetic JSON | unit | M → Phase 2 |
| Registry (§12/§19) | every declared tool probes consistently with doctor | registry.json | unit+e2e | M → Phase 2 |
| Input CLI (§3.1) | identify/validate/duplicates on corpus | corpus | e2e | M → Phase 2 |
| Fingerprint (§3.2) | provenance + confidence on every property | demo + app fixtures | e2e | M → Phase 3 |
| DEX enumeration (§4.1) | class/method/field counts vs header truth + jadx index cross-check | demo + multi-DEX fixture | unit+e2e | M → Phase 3 |
| Reflection/dynamic/native evidence (§4.1) | planted-pattern DEX (synthetic) + real fixture scan | synthetic + corpus | unit+e2e | M → Phase 3 |
| Kotlin inventory (§4.3) | coroutines/serialization evidence on Kotlin fixture | Compose fixture | e2e | M → Phase 3 |
| ELF intelligence (§6) | imports/exports/needed vs readelf ground truth | demo + game native libs | e2e | M → Phase 3 |
| Compare extended (§11) | planted endpoint/asset/class changes caught + severity | planted pair | e2e | M → Phase 3/8 |
| Engine verdicts (§3.3) | confidence + multi-indicator rule; no verdict on one weak signature | corpus + weak-signature synthetic | e2e | M → Phase 4 |
| Unity adapter (§5.1) | Mono/IL2CPP routing, bundle inventory; UnityPy deep counts when available | Unity fixture | e2e | M → Phase 4 |
| Unreal adapter (§5.2) | UE4 version + pak; IoStore detected + limits stated | Unreal + synthetic IoStore header | e2e | M → Phase 4 |
| Network static (§7.1/7.3) | taxonomy applied; planted Firebase config found; NSC parsed | synthetic + corpus | e2e | M → Phase 5 |
| Runtime offline (§8) | zero-device discovery behaves; timeline from recorded log parses to schema | recorded log fixture | unit+e2e | M → Phase 6 |
| Runtime on-device (§8) | — | no device in this environment | — | IU by environment |
| Security findings (§9) | known findings on purpose-built fixture; no highs on clean fixture | demo pair | e2e | M → Phase 7 |
| Assets (§10) | typed inventory, dimensions, duplicates on planted set | synthetic + corpus | e2e | M → Phase 9 |
| Output set (§13) | every emitted JSON validates against schemas/ | case outputs | e2e | M → Phase 9 |
| HTML dashboard (§15) | sections present; zero external references (offline) | generated case | e2e | M → Phase 9 |
| Unified CLI (§14) | every brief command routes + help + exit codes | corpus | e2e | M → Phase 9/11 |
| Case workspace (§17) | resume skips completed stages; hash change re-runs | temp case | e2e | M → Phase 9 |
| Benchmarks (§21.4) | metrics computed from corpus, methodology shipped | corpus | bench | M → Phase 10 |
| CI (§22) | workflow files valid YAML; local pytest+lint run | repo | local | M → Phase 11 |

## Rules

- A case with an absent fixture is SKIP, never PASS.
- A feature without a passing case is not "tested",
  whatever its code state.
- Benchmark numbers are produced by running the benchmark
  runner; they are never written by hand.
- Device-dependent rows stay `IMPLEMENTED_BUT_UNVERIFIED`
  until a real device run exists.

## Results addendum — 2.0.0 final QA (2026-11-23)

Measured on the build VM (1.5 shared CPU), system python
3.12 except where noted:

- pytest unit suite: **33/33 pass** (formats, safe archive,
  evidence/schema, registry, DEX parser, ELF parser — all
  on synthetic builders; the ELF suite caught and fixed the
  missing PT_DYNAMIC fallback).
- py_compile sweep over scripts/*.py + narlib: clean.
- nar-doctor: core toolchain READY (after clearing /tmp
  scratch; see troubleshooting.md for the full-tmpfs/java
  interaction).
- Full nar-analyze case on a real app fixture: exit 0 in
  23s; report.md carries the required Identity / Protections
  / Limitations sections; all 7 companions written; case.json
  + execution-log.json written; report.html generated with
  zero external resource references (verified: no src=/href=
  externals). Second run on the demo case: 2.0 stages report
  status `cached`, wall time 12.5s → 3.2s.
- Engine fusion spot checks: Unreal fixture → high (72)
  with version evidence; Unity IL2CPP fixture → high (84);
  React Native fixture → high (73) + new-architecture
  variant; Godot fixture → medium (52), raised to high (85)
  by --deep confirmation; two native apps → no verdicts
  (clean negatives).
- nar-unity on the Unity fixture: backend IL2CPP, editor
  version string recovered, metadata v31, Addressables
  detected; UnityPy census produced under the venv
  interpreter and honestly skipped under system python.
- nar-dex on a modern Kotlin fixture: 6,124 classes,
  31,212 methods, 180,290 call edges; Kotlin inventory
  (coroutines/flow/serialization type counts, 1,085 suspend
  candidates, metadata-absent noted). Demo cross-check:
  nar-dex's 1 native method == nar-native's 1 JNI export;
  baksmali adapter's 7 smali files == nar-dex's 7 classes.
- nar-security on the demo: exactly the exported-launcher
  finding (with its false-positive note); findings validate
  against schemas/security-findings.schema.json with zero
  errors.
- nar-network on a real app fixture: 69 endpoints
  classified (51 confirmed / 10 potential / 1 third-party /
  7 unverified — the unverified are path fragments and a
  format template, honestly bucketed); a malformed-IPv6
  URL in real string data found and fixed during testing.
- Benchmarks (tests/benchmarks/run_benchmarks.py): 28 runs
  across demo/app/game/unity roles, all exit 0; slowest
  measured: nar-network on the game role 21.2s (string scan
  dominated).
- Runtime: adb + frida probed live (frida 17.27.4), zero
  devices → IMPLEMENTED_BUT_UNVERIFIED, as designed.
- Banned-identifier grep over the repo: no tested-app
  names, packages, file names, or hashes (only generic
  harness role labels such as FIX_WIDEVINE_COMPILED).
- The 1.1.1 e2e harness (41 cases) was last run green at
  the Phase 2 baseline this cycle; new 2.0-module e2e cases
  were not added to it this cycle — 2.0 coverage is the
  unit suite + the direct fixture runs recorded here.

---

## 2.1.0 addendum (2026-11-23) — gap-closure program

Evidence recorded per phase of the 2.1.0 program. Statuses are
only ever what was executed and observed in this cycle.

### Phase A — CI truth

The nar-ci workflow HAS executed on GitHub Actions; the 2.0-era
"authored, not executed" wording was stale and is corrected in
ci.yml and CHANGELOG.md. Runs on main, 2026-11-23:

| Run | Commit | Duration | Conclusion |
|-----|--------|----------|------------|
| #1 (45165312840) | workflow-add commit (ca23b9e) | 11 s | success |
| #2 (45165732920) | credit-line commit (2274b759) | 11 s | success |
| #3 (45209487654) | link-fix commit (143abe69) | 15 s | success |

Method: the GitHub MCP toolset available here exposes no
workflow-runs tool, so conclusions were read from the Actions
web UI run pages. Each run's summary carries exactly one
annotation — a Node.js 20 deprecation warning for
actions/checkout@v4 / actions/setup-python@v5 — and no error
annotation; GitHub surfaces every step failure as an error
annotation on that page. Durations match full execution of
all steps (checkout, setup-python, pip install pytest,
pytest, py_compile sweep, CLI smoke), and the identical steps
pass locally on the same trees. No run has failed to date.

### Phase B — runtime verification attempt (emulator)

Attempted 2026-11-23, time-boxed to ~25 minutes. Environment:
workspace Android SDK (emulator 37.3.6), system image
android-34 google_apis x86_64, host has NO /dev/kvm and ~1.5
shared CPUs / ~8 GB RAM.

What happened, in order:

1. avdmanager refused to create the AVD ("emulator package
   must be installed") because this SDK was assembled without
   the emulator package's package.xml. The AVD was therefore
   written by hand (nar-test.ini + config.ini) and the
   emulator binary accepted it.
2. First boot attempt died on `unknown skin name 'pixel_6'`
   (the manually assembled SDK ships no skins); skin keys
   removed.
3. Second attempt: the emulator refuses `-accel off` without
   a hardware accelerator unless ANDROID_I_WANT_MY_TCG=yes is
   set; relaunched with it (QEMU TCG software emulation,
   swiftshader/swangle software GL, 2 cores, 2048 MB).
4. QEMU ran and adbd came up: adb reached state `device`,
   `init.svc.bootanim` read `stopped`. But
   `sys.boot_completed` / `dev.bootcomplete` never read 1
   inside the time box (guest still crawling under TCG), so
   the demo install, the on-device nar-runtime run, and the
   Frida observation step could NOT be executed. A
   version/ABI-matched frida-server (17.27.4, android-x86_64)
   was downloaded and staged but never pushed.
5. Emulator killed via `adb emu kill`; AVD and staged files
   removed; `adb devices` empty afterwards.

Precise blocker: no /dev/kvm on this host forces QEMU TCG
software emulation, under which an API-34 google_apis image
does not reach boot completion within 25 minutes on ~1.5
shared CPUs. Runtime status therefore stays
IMPLEMENTED_BUT_UNVERIFIED — for emulator AND physical
device alike. Re-attempt requires a KVM-capable host or a
physical device.

### Phase C — IoStore entry-level parsing

`narlib/iostore.py` (new) parses .utoc containers at entry
level; `nar-unreal` exposes per-container inventories for
APK targets and bare .utoc files, and `nar-analyze` embeds a
counts-level summary as `engines.unreal_iostore`.

First contact with real data corrected the parser's layout
assumptions (the initial implementation and its synthetic
builder agreed with each other but not with real files —
the exact failure mode the two-way verification exists to
catch). Two real TOC v6 containers from a free UE5 Android
demo (obtained from itch.io; the earlier APKPure route was
challenge-gated and the Uptodown route served a store stub
instead of the game) showed, against the current upstream
CUE4Parse sources: a TocHeaderSize header field shifting
every later field, 10-byte big-endian offset/length
records, seeds-only perfect-hash sections at v4 (the
without-hash array starts at v5), per-block signature
bytes in signed sections, and 33-byte meta records
(32-byte chunk hash + flags). Manual section accounting
on both real containers reconciles to the byte (599 and
89,826 bytes, both EOF-exact, including the method-name
and directory-index landmarks). The downloaded target was
retired after a security flag on the download, so the
corrected parser's byte-exactness is proven on synthetic
containers of both eras (tests/unit/test_iostore.py,
6 tests): current v6 and legacy v4 containers parse,
inventories and directory-index paths match, stored /
zlib / multi-block chunks extract byte-exactly, legacy
SHA-1 meta verifies, Oodle chunks are named and refused.
A layout is accepted only when its section walk consumes
the file exactly; otherwise the container reports a parse
error, never a partial invention. Status: VERIFIED
(synthetic byte-exact, both eras; real-container layout
verified by exact section accounting).

### Phase D — Cpp2IL as an optional second IL2CPP backend

Cpp2IL 2022.1.0-pre-release.21 (upstream release binary)
installed outside the repo and integrated into nar-il2cpp
as a probed optional backend: `--backend cpp2il` or
$NAR_IL2CPP_BACKEND, Il2CppDumper stays the default.
registry.json's cpp2il entry flipped from kind=unavailable
to a probed cli entry; nar-doctor gained a matching probe
(reports OK with the full version string). Cpp2IL's
dummy-DLL output is summarized by narlib/dotnetmeta.py, a
new ECMA-335-lite reader (TypeDef/MethodDef row counts +
TypeDef namespaces; unit-tested on a synthetic CLI image,
tests/unit/test_dotnetmeta.py, 2 tests).

Same-fixture comparison (one Unity IL2CPP fixture,
metadata v31):
- Il2CppDumper (default): 12,555 types, 95,988 RVA-marked
  methods.
- Cpp2IL backend: 12,497 types (−58, −0.5%), 106,117
  MethodDef rows across 60 assemblies. The method delta
  is definitional and stated in the output: MethodDef
  rows count every declared method; the dumper figure
  counts only methods with native bodies (RVA-marked).
  Top-namespace agreement is exact for the four largest
  named namespaces (555 / 494 / 405 / 349 types), which
  cross-validates the ECMA-335 reader against dump.cs.
- Directory (extracted-pair) targets: Cpp2IL's force-path
  options demand a Unity version a bare pair does not
  carry; the backend refuses with that precise reason
  instead of guessing one. APK targets are the supported
  Cpp2IL route; extracted pairs keep the default backend.

### Phase E — nar-dex performance (and a field-parsing defect)

Target: the ~273 MB multi-DEX Unity game fixture (8 DEX
files, 64,480 classes, 422,381 methods, 1,391,217 counted
call edges). Baseline (steady state, import-level split):
analyze 11.33 s + JSON emission 14.28 s = 25.61 s; cold
CLI wall 35.5 s.

Profile findings (cProfile proportions + component
benchmarks): the call-edge resolution the phase brief
suspected was NOT the dominant cost — narlib primitives
total ~1 s per DEX. The dominant cost was serialization:
nar-dex emitted --json with indent=2, and CPython's C
JSON encoder refuses an indent argument (its fast path
requires indent=None), so a 462 MB document went through
the pure-Python encoder. Second: report construction and
input handling inside analyze itself.

Changes shipped:
- nar-dex --json now uses the compact C encoder (2.32 s
  for the same document, 311 MB). The parsed document is
  field-identical; every consumer of this output parses
  JSON (nar-analyze's stage runner included). A docstring
  records why.
- narlib scan_code unpacks the instruction stream in one
  C pass and walks it by index; value-identical across
  all 55,786 code items of the fixture's main DEX
  (old-vs-new scan comparison: 0 differences).
- DEFECT FOUND AND FIXED: narlib class_fields started
  its walk two ULEB128s early — it never skipped the
  class_data header's two method counts — so every field
  list it produced was shifted onto wrong field ids
  (wrong names/types/flags, wrong per-class attribution).
  The equivalence proof caught it: outputs differed only
  in field data. Hand-decoding raw class_data bytes
  confirmed the corrected walk matches the DEX spec, and
  an independent oracle agreed: SDK dexdump field lists
  vs the corrected parser on the fixture's main DEX —
  9,949 classes compared, 0 mismatches. Field totals on
  the target move 219,134 -> 223,655 (+4,521 correctly
  attributed fields); classes/methods/call-edges/native
  totals are unchanged, and the full output is
  field-identical to baseline outside field data.
- Tried and reverted: id-table precomputation and
  proto/method/class-data caching in narlib. Component
  benchmarks showed them neutral on this target (the
  resolution paths were already cheap per call), so they
  were not kept — no cosmetic complexity.

Result (interleaved 3x medians, same target): analyze
11.98 s -> 11.14 s; emission 14.28 s -> 2.32 s; total
~25.6 s -> ~13.5 s (~1.9x). Cold CLI wall 35.5 s ->
16.7 s.

### Phase F — Release 2.1.0

Full battery on the final tree (2026-11-23):

- tests/run_e2e.sh: 43 passed, 0 failed, 0 skipped. The
  harness gained two cases this cycle: unreal-iostore
  (synthetic container built byte-exact by the unit-test
  builder, parsed back through nar-unreal in bare and
  in-APK modes, directory-index path asserted) and
  il2cpp-cpp2il (Cpp2IL backend on the Unity fixture,
  12,497 types / 106,117 MethodDef-row methods asserted).
  First run of the new cpp2il case failed on a wrong
  assertion key in the harness itself (type_count vs the
  summary's types); fixed and re-run green — the tool
  output was correct throughout.
- pytest: 41/41 (33 at 2.0.0 + 6 IoStore + 2 dotnetmeta).
- py_compile sweep over scripts/, narlib/, tests/: clean.
- nar-doctor: core toolchain READY (incl. the new cpp2il
  probe).
- Version stamps moved to 2.1.0: skill.yaml, SKILL.md,
  .claude-plugin/plugin.json, README, pyproject.toml,
  nar.py VERSION, nar-analyze NAR_VERSION, narlib
  __version__, registry.json registry_version, and the
  per-module report version fields. CHANGELOG gained the
  2.1.0 entry; NAR_GAP_ANALYSIS.md gained a 2.1.0 status
  addendum (its Phase-Zero tables stay as the historical
  audit of v1.1.0). The installed copy at
  ~/workspace/custom-skills/nar/ was re-synced and
  diff-verified against this tree.
- NOT pushed by this program: the parent reviews and
  pushes. Note the Phase A ci.yml header change lives
  under .github/workflows/ and must route via the web UI
  like the original workflow commit.
