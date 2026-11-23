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
