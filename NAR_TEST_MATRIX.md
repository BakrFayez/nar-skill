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

## Post-2.1.0 addendum — runtime verification (2026-11-23)

A renewed, multi-method attempt to verify the runtime layer
(nar-runtime: adb + Frida), ordered after the 2.1.0 Phase B
attempt failed on the API-34 image. Environment first:
docker is absent and the kernel exposes no binder/ashmem
devices, so container/VM-translation routes (redroid,
Waydroid) are impossible on this host; QEMU TCG (no
/dev/kvm) is the only emulation path.

Method that succeeded — lean SDK emulator image:

- The API 26 (Android 8.0.0) google_apis x86_64 system
  image (r16; zip fetched directly from dl.google.com
  because this SDK's sdkmanager repository view is
  frozen, SHA-1 verified against the repository XML,
  installed with a hand-written package.xml; the SDK's
  emulator package needed one too before avdmanager
  would create an AVD).
- AVD: 1536 MB RAM, 4 cores, 2 GB data partition.
  Emulator 37.3.6 flags: `-accel off` with
  ANDROID_I_WANT_MY_TCG=yes, `-gpu swiftshader_indirect`,
  `-no-window -no-audio -no-boot-anim -no-snapshot`,
  first boot with `-wipe-data`.
- Boot result: adb showed the target as `device` within
  seconds; the package manager answered at ~6 minutes;
  `sys.boot_completed=1` at ~9 minutes — the same TCG
  conditions under which the API-34 image never completed
  in 25 minutes during Phase B.

Runtime checks executed against the booted target:

- `adb devices` lists the emulator; getprop reads return
  model "Android SDK built for x86_64", Android 8.0.0,
  API 26, abi x86_64; `pm list packages` answers
  (97 packages).
- Install + launch of the demo fixture. One adaptation,
  recorded plainly: the shipped fixture carries only an
  arm64-v8a native library and the x86_64 target refused
  it (INSTALL_FAILED_NO_MATCHING_ABIS). The identical
  demo was rebuilt from its own source — the same JNI C
  file compiled for x86_64 with the same NDK and added
  as a second ABI beside the original arm64 library,
  re-signed with the demo's own test keystore (same
  package, same signer; the fixture file itself is
  untouched). Install succeeded; launch via the plan's
  monkey step; the process ran, its activity resumed,
  and the UI showed the native greeting, proving the
  x86_64 library loads and the JNI call works.
- nar-runtime itself: `status` enumerated the attached
  device and reported **verified-live** (the first time
  this status was produced by a real run); `plan` and
  `timeline-template` ran clean. (CLI note: `--json`
  must precede the subcommand.)
- Frida: `adb root` works on this image. frida-server
  17.27.4 (android-x86_64, matching host frida-tools
  17.27.4) was pushed to /data/local/tmp and started as
  root; `frida-ps -U` listed the demo process.
  - network-observe.js attached to the live demo
    process: hooks installed for URL.openConnection,
    HttpURLConnection.connect/.getResponseCode, and
    Socket.connect; OkHttp absent and skipped
    gracefully, as the script is written to do.
  - file-io-observe.js attached in a second session:
    hooks installed for the FileInputStream/
    FileOutputStream/RandomAccessFile constructors,
    File.delete/mkdir/mkdirs/renameTo, and
    libcore.io.IoBridge.open.
  - The sessions captured hook installation, not
    connection/file events: the demo app, by its own
    source, never opens a network connection (its
    endpoint string is only logged) and performs no
    Java-layer file I/O, so zero event lines is the
    truthful observation for this fixture.

What did NOT verify in this attempt:

- Frida spawn mode: three `frida -U -f` sessions
  (jni-trace.js) each launched the app — the process
  appeared and ran — but the session died during script
  load ("error sending data: Broken pipe"; twice "the
  connection is closed"). Attach mode worked in both
  sessions it was tried. Under QEMU TCG, spawn is the
  fragile path; attach is the verified path.
- jni-trace.js and java-api-trace.js have still not
  executed live (jni-trace was the spawn-mode script).
- No physical device was involved; all physical-device
  runtime rows remain IMPLEMENTED_BUT_UNVERIFIED.
- Android-x86 in plain QEMU (the next method in line)
  was not needed and not attempted; its ISO was staged
  only.

Status change recorded by this addendum: the runtime
rows for adb discovery/inspection, install/launch, and
Frida attach-mode observation are IMPLEMENTED_AND_TESTED
**for emulator targets**; the subsystem as a whole keeps
the IMPLEMENTED_BUT_UNVERIFIED label for physical
devices and for Frida spawn mode. Full session evidence
(command outputs) is kept with the attempt log outside
this repository.

## Post-2.1.0 addendum — Frida spawn-mode verification (2026-11-23)

A dedicated retry of the one sub-mode the runtime
addendum above left unverified: Frida spawn mode, on the
same emulator target (API 26 / Android 8.0.0, google_apis
x86_64, QEMU TCG, frida-server 17.27.4 as root).

Root cause of the original failures, established from
logcat: ActivityManager logs "Process ... failed to
attach" and kills the spawned demo process with reason
"start timeout" ~10 s after process start. A
Frida-gated child cannot call attachApplication while
gated, and under TCG the host-side spawn -> attach ->
script-load sequence cannot finish inside that ~10 s
window, so the child is killed mid-load ("the connection
is closed"). A no-attach lifetime probe confirmed the
gated child vanishes on its own at ~13.5 s. Script
weight is not the cause: a no-op script loses the same
race, including via the canonical `frida -U -f` CLI
path on a warm, settled system.

Verified recipe (hybrid), executed twice with pid
continuity polled throughout:

1. Frida API: `device.spawn([package])`, then
   `device.resume(pid)` as the very next call (<=0.3 s),
   shrinking the gated window to ~zero so the child
   attaches to ActivityManager inside its start timeout.
2. Settle ~40-50 s, polling that the spawned pid
   persists unchanged.
3. Load the bundled script through the standard CLI
   path, `frida -U -p <spawned pid> -l <script>` (the
   CLI session provides the Java bridge, which raw API
   script loads in Frida 17 do not).

Results: network-observe.js ran in the Frida-spawned
demo process (spawned pid 6400; hooks installed for
URL.openConnection, HttpURLConnection.connect/
.getResponseCode, and Socket.connect; OkHttp absent and
skipped gracefully), and file-io-observe.js ran in a
second Frida-spawned process (spawned pid 6718; hooks
installed for the stream constructors, File.delete/
mkdir/mkdirs/renameTo, and libcore.io.IoBridge.open).
Both sessions ended by clean detach/exit. As in attach
mode, the sessions captured hook installation, not
events: the demo app performs no network or Java-layer
file activity by design.

Precise scope of this verification: Frida spawn mode is
IMPLEMENTED_AND_TESTED **for emulator targets** with
the hybrid recipe above. The textbook one-command form
(load while gated, resume after load) remains unusable
under TCG for the root-caused reason above; with the
recipe, hooks install seconds after the app starts
rather than before its first instruction. jni-trace.js
and java-api-trace.js have still not executed live in
either mode. No physical device was involved; all
physical-device runtime rows remain
IMPLEMENTED_BUT_UNVERIFIED. Full session evidence
(spawn retry log and command outputs) is kept with the
runtime attempt log outside this repository.

## Unreleased addendum (2026-11-23) — DEX bytecode disassembler

New module narlib/dexdis (pure-Python instruction decoder
over the existing narlib.dex primitives) plus a targeted
nar-dex mode (`--disassemble` with `--disasm-class` /
`--disasm-method` selection, `--disasm-all` for an explicit
full decode, `--disasm-limit` on listings). Built and
verified on its own branch; not yet released.

### Unit tests

- tests/unit/test_dexdis.py: 17 tests over a spec-shaped
  synthetic DEX builder — every format family, switch and
  fill-array payloads consumed in-stream, jumbo strings,
  wide literals, DEX 038 gates (pass at 039, clean failure
  at 035), and the failure discipline (unknown opcode,
  truncated stream, out-of-range string/method/call-site
  indices, payload-identifier mismatch, absent call-site
  table) asserting per-method failure with reason + offset.
- The decoder's operand-width table was cross-checked
  against narlib.dex's independent OP_WIDTH table: 0
  mismatches across all 224 assigned opcodes.

### Oracle cross-check (SDK disassembler as oracle)

An independent comparator (throwaway, outside the repo)
parsed the SDK disassembler's output and compared, per
method: instruction and payload counts for the whole file,
and per instruction the address, mnemonic, resolved
reference index, branch target, and integer literal.
Formatting was normalized; semantics never.

- Demo fixture DEX (037): 12 methods, 91 instructions,
  full agreement.
- Corpus app DEX A (035): 8,507 methods, 230,836
  instructions, 709 payloads — full agreement.
- Corpus app DEX A, second file (035): 4,271 methods,
  64,316 instructions, 526 payloads — full agreement.
- Corpus app DEX B (035): 28,035 methods, 477,822
  instructions, 1,128 payloads — full agreement.
- Toolchain-built DEX 038 file (compiled from source with
  the SDK's own compiler/dexer for this check; carries a
  real invoke-polymorphic): 12 methods, 99 instructions —
  full agreement.
- Totals: 40,837 methods, 773,166 instructions and 2,363
  payloads compared; 0 semantic mismatches; 0 decode
  failures on any real file.
- The DEX 038/039 gated forms (invoke-custom and its range
  form, const-method-handle for method and field handles,
  const-method-type) were additionally rendered by an
  independent smali disassembler from the spec-built gated
  unit-test file: all seven gated instructions agree
  exactly, including the full call-site rendering. No
  real-world file in the local corpus (59 packages probed)
  uses invoke-custom, so that form's evidence is the
  spec-built file plus unit tests — stated plainly rather
  than rounded up.
- Findings fixed during the cross-check: prototype
  parameter descriptors are concatenated with no separator
  (three render sites corrected); invoke-custom text now
  renders the whole call site; const-method-handle uses
  the kind@target form; register ranges always render in
  {vF .. vL} form. All were rendering issues — indices,
  targets, and literals already agreed.

### Performance

Full-corpus decode at library level: the largest corpus
DEX (9.1 MB, 56,073 methods, 1,217,078 instructions)
decodes in ~6.2 s with 0 failures (~197k instructions/s);
a second large DEX (8.4 MB, 48,854 methods, 615,746
instructions) in ~3.5 s. No pathological cost observed.

### Battery on the branch

- pytest: 58/58 (41 at 2.1.0 + 17 new).
- tests/run_e2e.sh: 45 passed, 0 failed, 0 skipped (43 at
  2.1.0 + 2 new: targeted disassembly decodes and resolves
  references on the demo fixture; unscoped --disassemble
  is refused).
- py_compile sweep over scripts/, narlib/, tests/: clean.
- nar-doctor: core toolchain READY.

## Unreleased addendum — UAsset-level inspection (2026-11-23)

New module `narlib/uasset.py` (original code, public
package layout), integrated into nar-unreal (bare package,
loose-in-APK, IoStore-chunk and --work pak modes) and into
nar-analyze's engine companions. Verification ladder, as
executed:

- Synthetic fixtures (unit suite, tests/unit/
  test_uasset.py, 10 tests): three packages built
  byte-exactly from the documented layout — UE4-era
  (legacy file version -6, UE4 object version 513), UE5-era
  (legacy -8, UE4 522, UE5 object version 1010), and an
  unversioned package (legacy -7, object versions zero,
  read under the parser's stated final-UE4 assumption).
  Round-trip assertions cover the summary fields and
  version gates, name/import/export resolution (including
  FName number suffixes), the depends map, preload
  dependency indices, soft package references, the UE5
  soft object path list, searchable names, the property
  stream (scalar values, a nested struct with float
  members, bool/enum/byte/name/object tags, a UE5 array
  tag with inner type), and a split .uasset + .uexp pair
  whose export data resolves into the .uexp. Error cases:
  bad magic, legacy file version -2 (enum custom
  versions), a pre-434 UE4 object version, and a truncated
  package all raise clean, reasoned errors.
- End-to-end harness (tests/run_e2e.sh, case
  unreal-uasset): the same synthetic packages parsed back
  through nar-unreal in four modes — bare, split pair,
  loose inside an APK, and as an ExportBundleData chunk
  of a synthetic IoStore container (stored chunk, directory
  index naming the package) in bare .utoc mode.
- Real-asset rung (EXECUTED 2026-11-23, with the owner's
  explicit approval to process the local corpus): cooked
  packages were extracted from a locally held UE4-era
  (4.16-generation) game pak (1,598 entries, 387
  packages) and parsed bare and through the in-pak path.
  The packages are unversioned (legacy file version -7,
  both object versions zero) and were read under the
  parser's stated final-UE4 assumption. Results: a small
  physical-material package (638-byte package, 16-byte
  .uexp): 9 names / 3 imports / 1 export; a small font
  package (641 B): 11 / 3 / 1; a large gameplay Blueprint
  package (~41 KB package, ~18 KB .uexp): 365 / 138 /
  212; the largest map package (~100 KB package, ~116 KB
  .uexp): 872 / 421 / 488. One further package was parsed
  both bare and through the in-pak path with identical
  counts, names, and property outcomes; the in-pak
  path's presentation cap covers the first 5 of the 387
  packages, and all 5 parsed cleanly.
- Independent oracle (EXECUTED): the small package's
  summary and tables were re-walked byte by byte with a
  throwaway script written from the documented layout
  (no code shared with the parser): the summary walk
  ends exactly at the name offset, the name walk exactly
  at the import offset, the import walk (28-byte
  FilterEditorOnly entries) exactly at the export
  offset, and the export walk (104-byte entries) exactly
  at the depends offset; every name, import field, and
  export field agreed with the parser, and the export's
  serial range lands in the .uexp opening on the
  expected terminating name. No third-party oracle tool
  was run; the manual accounting is the oracle of
  record.
- Defect found by this rung and fixed in-cycle: the
  property-tag reader skipped two documented tag-header
  fields — the array inner type (UE4 object version
  >= 500) and the property-GUID field (UE4 object
  version >= 503) — so any real tag stream holding a
  non-trivial tag desynchronized after its first tag;
  the synthetic fixtures had been built to the same
  incomplete layout and could not catch it. On the real
  corpus the fix moved the large Blueprint package from
  196/212 to 212/212 property streams parsed and the
  font package from failed to parsed with its string
  value decoded. The synthetic builders now serialize
  the documented fields, and a regression assertion
  covers a tag that carries a property GUID. The
  struct-GUID version gate was also corrected to the
  documented 441 while this code was open (no effect at
  or above 441).
- Scope proven: package summary and tables in full;
  property streams best-effort under the per-export
  confidence note (primitive values, struct recursion);
  class-specific export data is reported by size, never
  decoded. Packages flagged PKG_UnversionedProperties and
  UE5 tag-extension layouts (object version >= 1011)
  report their property streams as unparsed, with the
  reason.
- Real-asset rung, UE5 (EXECUTED 2026-11-23 — unsealed
  title; rung closed for the unversioned case): a
  second free UE5 Android title, a small independent
  developer's exploration showcase obtained the same
  way with the owner's approval, ships its content in
  a single pak (format version 11) inside an OBB
  carried in the APK. Encryption check first: the pak
  footer's index-encryption flag is clear, the footer
  index SHA-1 matches the stored index bytes, the
  full-directory-index SHA-1 matches, and 0 of its
  2,859 entries are flagged encrypted — the container
  is unsealed, so the run proceeded. The title is
  genuinely UE5 from its own data: the engine binary's
  version string reads ++UE5+Release-5.2 (the store
  page named an earlier 5.1; the binary is the
  authority). New in-cycle support made this readable:
  nar-pak now parses the v10/v11 encoded index
  (path-hash + full directory index); the decoded
  records were verified against an independent
  header-chaining walk of the same file (2,859 of
  2,859 entries in full agreement on offsets, sizes,
  methods, block tables, and encoded lengths). All
  220 stored (uncompressed) .uasset packages in the
  pak were extracted through nar-pak and parsed by
  narlib.uasset: 220 of 220 parsed, 0 failures (the
  remaining packages are Oodle-compressed and refused
  by name, as designed; the title's three level
  packages are among them). An independent byte-walk
  oracle on one project package agreed with the parser
  on 23 of 23 compared facts (summary fields, the full
  name list, every import, the export's indices and
  serial range). One real defect was found and fixed
  in-cycle: every package in this title is unversioned
  (object versions stripped at cook time) with legacy
  summary version -8, and the parser read those with
  the UE4-only layout, landing eight bytes behind and
  failing on the package GUID; a legacy -8 summary is
  the variant that carries the UE5 version field, so
  unversioned -8 packages are now read under the
  final-UE4 (522) + UE5 1010 layout assumption, stated
  in the report. UE5-gated structures the real data
  exercises: the soft-object-path list field, the
  payload-TOC offset, and the data-resource offset in
  every summary (the data-resource offset carries a
  real table offset in 41 packages), the
  names-referenced-from-export-data count (nonzero in
  115), the import-optional flag, and the export
  package-GUID removal and inherited-instance fields.
  Stated plainly as absent or unexercised: every
  sampled package is unversioned, so no package with a
  recorded UE5 object version (1000+) has been parsed
  yet; the soft-object-path list is empty in all 220
  packages (its entries are unexercised); the payload
  TOC offset is -1 everywhere; structures gated above
  this title's engine generation (saved hash, metadata
  offset, Verse cells, import type hierarchies) do not
  occur in its data; and Oodle-compressed packages
  (407 of 627 package files) remain unextractable by
  design. In-container routes: nar-unreal on the pak
  reports the full listing and records a plain
  per-package refusal for the first five packages in
  directory order (all Oodle-compressed editor
  resources); nar-analyze on the OBB finds the pak
  inside it and reports the same listing. Regression
  coverage: tests/unit/test_pak.py gained a byte-exact
  synthetic v11 pak (stored / one-block zlib /
  two-block zlib / refused-method entries; listing,
  extraction, and the 64-bit-field and block-size-
  escape decode paths), and tests/unit/test_uasset.py
  gained an unversioned UE5 (legacy -8) fixture
  mirroring this title's layout.
- Prior attempt, same rung (2026-11-23): a first free
  UE5 title (~2.6 GB bundle: split APKs, an install-
  time asset pack, and an OBB) shipped all seven of
  its paks with AES-encrypted indexes (footer flag
  set, footer index SHA-1 mismatch, ~8 bits/byte index
  entropy, Oodle the only registered compression
  method), so no cooked package could be obtained and
  the parser stayed unexercised on real UE5 data; key
  extraction is outside this skill's scope by design.
  That attempt produced the nar-pak index_encrypted
  diagnosis (report field, explicit error sentence,
  human-output line, and a nar-unreal pak-summary
  passthrough), covered by tests/unit/test_pak.py on
  synthetic byte-exact footers.

## Addendum (2026-11-23) — merged 2.2.0 tree battery

- The dex-disassembler, uasset-inspection, and runtime/spawn
  workstreams were merged into main for the 2.2.0 release.
  On the merged tree, re-run end to end by the reviewer:
  pytest 72/72, end-to-end harness 46 passed / 0 failed /
  0 skipped, nar-doctor core toolchain READY, py_compile
  clean. The unit total is the exact union of the branch
  suites (41 base + 17 disassembler + 10 uasset + 4 pak);
  the end-to-end total is 43 base + 2 disassembler cases
  + 1 UAsset case. A pre-release consistency pass also
  corrected the capability registry's FModel entry, whose
  limitations text still called UAsset-level inspection a
  documented limitation after narlib.uasset shipped.

## Addendum (2026-11-23) — merged 2.3.0 tree battery

- The ue5-real-rung workstream was merged into main for
  the 2.3.0 release. On the merged tree, re-run end to end
  by the reviewer: pytest 76/76, end-to-end harness 46
  passed / 0 failed / 0 skipped, nar-doctor core toolchain
  READY, py_compile clean.

## Addendum (2026-11-23) — close-all-gaps: runtime scripts + compiled artifacts

- jni-trace.js and java-api-trace.js have now executed
  live on the same emulator target (API 26, TCG,
  frida-server 17.27.4), in attach mode via the CLI load
  path, against the live demo process. jni-trace.js
  installed its RegisterNatives hook in attach mode and
  in a Frida-spawned process (resume-first recipe);
  neither session recorded a registration or entry
  event — the demo's native library binds its one
  native method statically (name-mangled export,
  resolved by symbol lookup, never via RegisterNatives),
  and in attach mode the library is loaded before the
  hook exists. The [jni-register]/[jni-entry] event
  paths remain unverified live; script execution and
  hook installation are verified in both modes.
  java-api-trace.js installed both URL.openConnection
  hooks and captured one genuine [call]/[return] pair,
  recorded as REPL-triggered (the demo's own code never
  calls the traced method). nar-runtime status against
  the live device reported verified-live; plan and
  timeline-template ran clean. All four bundled Frida
  scripts have now executed live (emulator scope);
  physical-device rows remain IMPLEMENTED_BUT_UNVERIFIED.
- Compiled artifacts verified on real files pulled from
  the same target (demo force-compiled, speed filter):
  the app .odex parses as OAT 124 (x86_64, key-value
  store recovered incl. the dex2oat command line); the
  companion .vdex parses as VDEX 006 and nar-dex
  extracted and fully parsed its carried DEX 037
  (7 classes, 13 methods, 36 call edges — matching the
  fixture's known contents); boot.oat reads as OAT 124
  and boot.art as ART 043. Baseline defects fixed in
  the same cycle: compiled artifacts were misidentified
  (OAT as plain ELF, VDEX magic-only, no CDEX/ART
  verdicts) and nar-dex refused them outright.
  Regression coverage: tests/unit/test_oat.py (20
  tests) + one e2e case; branch battery pytest 96/96,
  e2e 47/47 before merge.

## Addendum (2026-11-23) — close-all-gaps: Godot encrypted packs

- Encrypted-pack detection verified at REAL level: a
  pack written by a real engine pack writer with a
  256-bit key is reported by nar-godot as encrypted
  (header flag) with the listing honestly unavailable
  and no decryption attempted; an independent pack tool
  refuses the same file as encrypted, and the producing
  tool re-opens it only with the key. A plain control
  pack lists correctly. The same cycle fixed Godot
  format 3 (directory at end of file, relative entry
  offsets), which had silently reported "Files: 0" on a
  valid pack, and format 4 headers now report facts +
  encryption flag with the listing marked unsupported.
  Regression coverage: tests/unit/test_godot.py (10
  tests); branch battery pytest 86/86, e2e 46/46 before
  merge.

## Addendum (2026-11-23) — close-all-gaps: invoke-custom wide scan

- The invoke-custom evidence was widened from the
  earlier 59-package scan to every package on the local
  corpora: 125 package files, 233 DEX occurrences (108
  unique), 6,235,951 code-bearing methods walked
  instruction-by-instruction — 0 invoke-custom /
  invoke-custom-range instructions, 0 call_site_ids
  tables, 0 method_handle_ids tables. All unique DEX
  at version 038+ were independently cross-checked with
  full baksmali disassembly and dexdump renders (0
  hits). A hand-built DEX 039 positive control carrying
  real invoke-custom instructions was detected by the
  scanner, and the disassembler rendered them textually
  identical to baksmali (3/3 methods). Conclusion
  stands: the decoder path is proven against a control
  and an independent renderer; shipped apps in the
  local corpora simply do not carry the instruction
  (build-time desugaring). One 2.8 GB package exceeded
  the scan size cap and its members were not examined;
  recorded here rather than silently skipped.

## Addendum (2026-11-23) — close-all-gaps: mega sweep

- The full tool was run over every target in the local
  corpora: 75 targets (real apps and games incl. split
  sets and each split member, engine samples for Unity
  IL2CPP / Flutter / Godot / React Native, bundle and
  .apks sets, protection fixtures, the sealed and
  unsealed Unreal titles, loose pak/pck/DEX files, and
  the existing scenario case, whose re-run reproduced
  its recorded identity and IL2CPP numbers exactly).
  Every analysis stage ran ok on every target except
  three designed degradations (a non-ZIP synthetic, a
  fake pak, both reported with exact diagnostics) and
  one genuine defect, fixed and re-run green.
- Six defects were found and fixed in the same cycle,
  each with regression tests and a real-target proof:
  a native-stage crash on APKs bundling ZIP payloads
  under a .so name; IL2CPP split-pair reporting (a
  member holding one half of the pair claimed neither
  half was found); a silent IL2CPP skip in the case
  workflow for a metadata-without-library split base
  (now an explicit step note); missed detection of
  legacy versioned Cordova/PhoneGap runtimes; engine
  scoring that left Ren'Py / RPG Maker unique payloads
  below the detection threshold; and hollow reports
  for bundletool .apks sets (now classified as
  containers and routed to the canonical base split).
  No defects were observed in the runtime, Godot, or
  Unreal modules during the sweep. The local results
  matrix (target x stage x verdict) is retained with
  the sweep evidence outside the repo.
- Wear OS / APEX / instant-app samples: none exists in
  any local corpus and one time-boxed attempt to fetch
  a free Wear sample failed (404); those rows remain
  unexercised and labeled as such. TV form factors are
  covered by two TV targets in the sweep.

## Addendum (2026-11-23) — merged close-all-gaps tree battery

- All close-all-gaps workstreams merged (runtime +
  compiled artifacts, Godot packs, mega sweep) plus
  the coordinator's doc updates. On the merged tree,
  re-run end to end by the coordinator: pytest 122/122
  (76 base + 20 compiled-artifact + 10 Godot + 16
  sweep), end-to-end harness 47 passed / 0 failed /
  0 skipped, nar-doctor core toolchain READY,
  py_compile clean. Banned-identifier and
  forbidden-credit greps over the full branch diff:
  clean.

## Addendum (2026-11-24) — close-all-gaps stream E:
## real IoStore UE5 set

A complete, unsealed UE5 title (engine 5.3, confirmed
from the title's own engine build string) supplied the
real IoStore set the earlier rungs lacked: a global
container (1 chunk) plus one chunk container (TOC v5,
7,171 chunks: 5,645 ExportBundleData, 1,096 BulkData,
427 ShaderCode, 2 ShaderCodeLibrary, 1 ContainerHeader;
compression methods None + Oodle) and a companion
classic pak (v11, 1,564 entries). Seal evidence: both
TOCs carry only the Compressed and Indexed flags, a
zero encryption-key GUID, encryption method 0 and an
IV count of 0; the pak footer records an unencrypted
index with a zero key GUID.

### Target 1 — real IoStore set end to end: CLOSED

- narlib.iostore parses the full set (header, chunk
  tables, block table, directory index, chunk-hash
  meta) with zero trailing bytes; the classic pak
  parses through narlib.pak / nar-unreal with matching
  accounting.
- DEFECT FOUND AND FIXED in-cycle: the directory
  index of this set uses the pooled name-index layout
  written by UE 5.3-era packagers (fixed-size rows —
  directory: name index, first child, next sibling,
  first file; file: name index, next file, TOC entry —
  over a shared FString pool). narlib implemented only
  the classic inline-FString layout and silently
  reported the index as absent. The parser now tries
  both layouts and accepts one only on exact buffer
  consumption plus a complete tree walk; an index
  matching neither is reported absent, never guessed.
  Regression coverage: byte-exact pooled fixture,
  classic-layout assertion, truncated-index drop test.
- Independent oracle (throwaway byte-walk, no narlib
  code) on the chunk container's directory index:
  489 directories, 6,743 files, 7,049 pool strings,
  buffer consumed exactly, complete walk, and 6,743 of
  6,743 file-extension <-> chunk-type agreements. After
  the fix, narlib's flattened path map equals the
  oracle's on all 6,743 files. Pak-level accounting
  (footer/index walk) likewise agrees with narlib
  exactly (1,564 entries, 39,612-byte index).
- Extraction through narlib: all 684 stored (method
  None) package chunks byte-exact (aggregate length
  equal to the TOC accounting), plus the global
  container's single ScriptObjects chunk (2,290,013
  bytes). Oodle stays refused by name: 4,926
  Oodle-only and 35 mixed-method package chunks are
  named in the report, never decoded.
- Routes: nar-unreal on the .utoc reports the
  container with the directory index populated
  (489 directories / 6,743 files named); its package
  route classifies all 5,645 named package chunks —
  684 Zen records (below) and 4,961 honest Oodle
  extraction refusals.

### The set's packages are Zen-format — Target 2
### stays open, with the blocker now precise

All 684 extractable package chunks are UE5
IoStore-native (Zen) packages, not classic
FPackageFileSummary packages: 0 of 684 carry the
package magic at the head; 684 of 684 carry it as a
4-byte trailer, and the Zen header-size field is in
range in 684 of 684. A partial manual header decode
confirms the layout: word 0 is zero, word 1 is the
header size, the FName at +8 resolves through the
chunk's own name map to the package's asset name on
sampled chunks, and the flags word matches the Zen
package-flags shape. nar-unreal now identifies such
chunks as "zen-package" records (with header size)
instead of misreporting them as corrupt classic
packages; regression coverage in
tests/unit/test_unreal.py.

Zen package summaries record no FileVersionUE4 /
FileVersionUE5 at all — versioning is a property of
the engine build, not of the package — so this title
cannot satisfy the versioned-classic-package target,
and neither can any Zen-native title. Target 2 remains
open with a sharpened definition: a real title that
ships classic-format packages (loose or in classic
paks) cooked by a UE5 build with version recording
enabled. A full Zen package parser (name / import /
export maps in the Zen layout) is a separate format
implementation and is NOT claimed here: Zen chunks
are identified and inventoried only. The companion
classic pak in this title holds no packages at all
(registry, configs, fonts, ICU data only).

### Zen package parser addendum

The Zen parser the section above deferred is now
implemented (narlib.zen, wired into nar-unreal's
package routes — bare package, loose-in-APK, IoStore
and pak packages all dispatch on the Zen trailer
trait). Coverage, from the publicly documented Zen
layout: the FZenPackageSummary in its current
(UE 5.3+) layout, its pre-5.3 layout, and the UE5
Early Access legacy layout, each accepted only when
every section it implies validates end to end; the
optional versioning info (the only place a Zen
header records UE4/UE5 object versions — absent
headers say so per field); the optional Verse cell
offsets; the per-package name batch (UTF-8 and
UTF-16 names, accepted only when the decoded names
total exactly the recorded string byte count); the
bulk data map; the imported public export hashes;
the import map (export / script-import /
package-import / null object indices, with package
imports resolved to their public export hashes);
the 72-byte export map entries (object names
resolved through the package's own name map,
outer/class/super/template references rendered
readably, export data located at header size +
cooked serial offset); the export bundle entries;
and the pre-5.3 graph data (imported package ids).
Located and measured, not decoded, by design: the
dependency-bundle sections and the imported
package names section (no public reader decodes
them), Verse cell map contents, and export property
streams (unversioned Zen packages report the .usmap
rule, exactly as classic packages do).

Verification, synthetic level: tests/unit/
test_zen.py builds Zen packages byte-exact from the
documented layout (full current-layout parse
asserted field by field, a versioning-info variant,
a UTF-16 name batch, the pre-5.3 graph-data layout,
an out-of-range summary name downgraded to a note,
and five refusal cases — classic-magic head, bad
trailer, name-batch byte count mismatch, a
non-whole export-map span, a truncated chunk), plus
nar-unreal integration tests (a parseable Zen
package reported as a real parse with generation
evidence; an unvalidatable Zen-shaped chunk keeping
its identification record with the parse reason in
the note, never an error verdict).

The real-corpus runs deferred in the first Zen
round have now been executed, with the owner's
explicit go-ahead after an execution-risk flag had
stopped corpus processing in the implementing
session. The sweep ran the parser over all 684
stored package chunks of the real UE 5.3 IoStore
set inventoried above: 684/684 parse in full, 0
failures. Every chunk takes the current (UE 5.3+)
header layout, and none records versioning info —
per-package counts: names 2–13 (total 3,263),
imports 3–15 (total 3,007), exports 1–3 (total
704), imported public export hashes 0–6 (total
446), bulk-data entries 0–11 (total 399), export
bundle entries 2–6 (total 1,408). The sweep caught
one real defect the fixtures had hidden: four
chunks whose first export references a later export
(a class or outer defined further down the map)
crashed the parser with a raw KeyError, because
export names were assigned in the same pass that
resolved references. The export parse is now
two-pass (all object names first, references
second), with a regression test; the sweep is clean
after the fix. Anchor cross-check against the
container directory index: the resolved package
name's leaf equals the directory file's base name
in 683/684 chunks — the one exception is case-only
(a lowercase file name for a capitalized package
name); the base name appears among the package's
export object names in 676/684, and all 8 exceptions
are accounted for: seven Blueprint-class packages
whose exports are the generated class, its default
object, and subobjects (the asset name is the
package name, not an export), plus the same
case-only file. An independent byte-walk oracle
(no parser code) on one real package agreed with
the parser on 45/45 field checks: the header fields
and section offsets, the full name batch, bulk-map
and hash counts and values, import kinds, every
export field, and the bundle entries. Unit battery
after this round: 138/138 (125 baseline + 13 Zen).
Still not exercised on real data: the pre-5.3 and
Early Access header layouts and recorded versioning
info (this corpus's writer used neither) — those
rest on the synthetic fixtures.

### Second Zen corpus addendum (newer writer)

A second real title was evaluated as the last
candidate for the versioned-classic-package target:
an indie UE5 horror title (2025 build) shipping
unsealed TOC v8 IoStore containers (encryption key
GUID zero, method 0, no IVs) inside a disguised OBB,
plus one classic pak. Seal and inventory results:
the classic pak (v11) has an unencrypted index that
SHA-verifies and holds 1,598 entries — engine
support files only (configs, fonts, ICU data,
plugin descriptors); it contains zero packages. No
loose package files exist anywhere in the bundle.
The IoStore main container holds 1,765
ExportBundleData chunks: 525 stored, 1,199
Oodle-only, and 41 mixed whose header blocks are
Oodle (the stored blocks sit at the tail), so 1,240
chunks have compressed headers and are refused by
name under the Oodle rule.

Package-format distribution over every readable
package: 525/525 Zen format (magic as trailer),
0 classic. Before the fix below, the shipped parser
failed all 525 — root-caused by an independent
byte-walk to a writer variant no earlier corpus had
shown: between the name batch and the bulk data map,
this writer serializes a count-prefixed byte array
(an int64 element count, 0–7 across the corpus,
followed by that many bytes — 1,820 bytes in total
across all 525 packages, every one zero). The
classic map behind the array lands exactly on the
imported-public-export-hashes section in 525/525
chunks under that reading. narlib.zen now accepts
the variant under the same discipline as every
other layout (classic reading first; the prefixed
reading only when the map behind the array lands
exactly, with all downstream sections still
required to validate end to end), and reports the
array as a located-and-measured section, contents
not decoded. After the fix the corpus parses
525/525 in full: totals across the 525 — names
2,085, imports 2,459, exports 568, imported public
export hashes 374, bulk-data entries 246, export
bundle entries 1,136; every package takes the
current header layout, every one uses the prefix
variant, and none records versioning info. An
independent byte-walk oracle (no parser code) on
one real package agreed with the parser on 20/20
field checks (header fields and offsets, the full
name batch, the prefix count and its all-zero
bytes, bulk-map and hash sections, the export
entry, the bundle entries, the trailer). Three
regression tests cover the variant (with a map,
with an empty map, and a misaligned prefix that
must stay refused).

Target verdict, stated plainly: this title cannot
satisfy the versioned-classic target either — it
is Zen-native, and its classic pak carries no
packages. Across the five real UE5 titles examined
in this program (one AES-sealed, one
classic-but-version-stripped, three Zen-native) no
shipped title has provided a classic-format package
with a recorded FileVersionUE5 (1000+); every
version-gated classic structure (soft-object-path
entries, payload-TOC contents, data-resource table
contents, saved hash, metadata offset, Verse cells,
import type hierarchies) remains unexercised on
real classic data, and the target stays open on
exactly those terms.

### DEX scan addendum (stream C residual)

This title's two DEX files (038) were scanned with the
narlib disassembler for the one opcode class the wide
scan tracks: 84,263 methods with code, 1,217,458
instructions decoded, 0 decode failures, 0
invoke-custom / invoke-custom-range hits — consistent
with the wide scan's zero-hit result over 125 packages.

### Battery after stream E

pytest 125/125 (baseline 122 + pooled-index,
dropped-index, and Zen-identification tests), e2e
47/47 PASS, py_compile clean, nar-doctor READY — all
on branch close-all-gaps.

## Addendum (2026-11-24) — close-all-gaps: TOC v8
## directory index

A second unsealed UE5 title (indie horror; UE5
generation proven from the title's own data — TOC v8
IoStore containers and IoStoreOnDemand engine
strings; no plaintext engine build string survives)
supplied a container of the newest TOC generation:
TOC v8 (ReplaceIoChunkHashWithIoHash), 14,867 chunks,
a 583,290-byte directory index, a global container
(1 chunk), and a companion classic pak (v12) whose
index is AES-sealed — footer encryption flag set,
footer index SHA-1 mismatch against the stored index
region, index entropy ~8.00 bits/byte — discarded
unread under the analysis-only boundary. Both TOCs
are unsealed: zero encryption-key GUID, encryption
method 0, IV count 0, flags Compressed|Indexed only.

- DEFECT FOUND AND FIXED in-cycle: narlib returned
  no directory index for this container. The root
  cause was NOT a new layout. An independent
  byte-walk oracle (no narlib code) proves the v8
  writers ship the pooled name-index layout
  unchanged: 674 directories, 13,494 files, 13,845
  pool strings, buffer consumed exactly, complete
  tree walk. The failure sat in narlib's flattening
  walk, which recursed into sibling links with the
  same counter it used for nesting depth: this
  tree's true depth is 9, but its longest
  child+sibling hop chain is 87 — past the walk's
  bound of 64 — so the whole index was rejected as
  matching no layout. The walk now traverses
  sibling chains iteratively and bounds true
  nesting depth only (stack-safety cap of 256;
  cycles remain impossible because every row is
  marked on entry and a revisit raises).
- Oracle agreement: the oracle's flattened path map
  equals narlib's on all 13,494 files, and the
  file-extension <-> chunk-type agreement is
  13,494 of 13,494. A swapped child/sibling reading
  also consumes the buffer exactly and completes a
  walk, but produces visibly concatenated nonsense
  paths and the wrong root set; the extension
  agreement and the root children (the project
  directory and Engine) discriminate the two.
- Regression: the UE 5.3 (TOC v5) set re-parsed
  after the fix — its flattened path map is
  bit-identical to the pre-fix map (489 directories,
  6,743 files). Unit coverage in
  tests/unit/test_iostore.py: a byte-exact pooled
  fixture with a 100-wide sibling chain (verified
  refused by the pre-fix code with the same error
  signature), a cyclic index refused outright, and
  a 300-deep index refused at the depth cap.
- The title's readable packages are again
  Zen-format (1,435 of 1,435 stored package
  chunks), so Target 2 (versioned classic UE5
  packages) is untouched by this addendum.

### Battery after the TOC v8 fix

pytest 128/128 (baseline 125 + wide-sibling-chain,
cycle-refusal, and depth-cap tests), e2e 47/47 PASS,
py_compile clean, nar-doctor READY — all on branch
close-all-gaps.

## Reconciliation addendum (2026-11-24) — Evolution Phase 0 baseline

The matrix's "Status at audit" column is the v1.1.0
Phase-Zero baseline by design and is not edited; the
addenda above carry the status forward release by
release. This addendum records the executed baseline of
the TOTAL INTELLIGENCE EVOLUTION program's Phase 0,
run on the `evolution` branch at the v2.4.0 tree
(local main c31c072, identical to the published
2.4.0 tree) on 2026-11-24:

- Unit tests: pytest 144/144 passed
  (`tests/unit/`, 20 test files).
- End-to-end harness: 47 passed, 0 failed, 0 skipped
  (`tests/run_e2e.sh`, full fixture corpus bound).
- Doctor: core toolchain READY, exit 0.
- Unified CLI smoke: all 23 `nar` subcommands
  (doctor, input, triage, fingerprint, engines, unity,
  unreal, il2cpp, flutter, godot, rn, pak, dex, native,
  perms, strings, network, security, assets, compare,
  analyze, report, runtime, version) answer `--help`
  with exit 0.
- Orchestrated case, executed end to end on the demo
  fixture: 10/10 stages ok (triage, perms, strings,
  fingerprint, engines, dex, native, network, security,
  assets); emitted report.md + report.json +
  report.html + case.json + execution-log.json and the
  companions assets.json, dex.json (+ dex/classes.json,
  dex/methods.json), endpoints.json, engines.json,
  fingerprint.json, native.json, security-findings.json;
  cold run 9.2 s. A second identical run exercised the
  stage cache: execution log records 7 stages "cached",
  3 "ok", wall time 4.4 s.
- Version consistency: skill.yaml, SKILL.md
  frontmatter, .claude-plugin/plugin.json,
  pyproject.toml, README version line, nar.py VERSION,
  narlib __version__, nar-analyze NAR_VERSION and
  registry.json registry_version all read 2.4.0
  (grep-verified in this pass).

Capability statuses reconciled against this executed
baseline live in NAR_GAP_ANALYSIS.md (Evolution Phase 0
reconciliation addendum, 2026-11-24); the forward plan
lives in NAR_IMPLEMENTATION_PLAN.md (evolution section).
Nothing in this addendum re-labels a device-dependent
row: physical-device runtime rows remain
IMPLEMENTED_BUT_UNVERIFIED, and no test in this pass
ran on a physical device.

## Evolution Phase 1 addendum (2026-11-24) — docs/version guards

New executed evidence (local, this branch):

- tests/unit/test_docs_consistency.py: 10/10 pass —
  README structure block names every scripts/ (25 files),
  narlib/ (14), frida/ (4), references/ (22) and schemas/
  (11) file; stated guide count (22) equals the tree;
  SKILL.md routing targets all exist; version consistency
  across 18 locations agrees at 2.4.0; a planted version
  mismatch in a temp copy is detected; the brand headline
  carries no version number.
- Doctor hygiene: after removing all `__pycache__` under
  scripts/, a full nar-doctor.sh run leaves zero
  `__pycache__` directories under scripts/ and still
  reports Core toolchain: READY (exit 0).
- Full battery: pytest 154/154, e2e harness 47/47
  (0 skipped), doctor READY.

## Evolution Phase 2 addendum (2026-11-24) — companions, compile_sdk, AAR/JAR

New executed evidence (local, this branch):

- tests/unit/test_companions.py: 11/11 pass — the four
  companion projections validate against their shipped
  schemas on synthetic stage data; degraded-source
  projections carry an explicit unavailable field and
  still validate; planted AAR (manifest + classes.jar
  with 2 classes + R.txt + res/ + one jni lib) and JAR
  summaries report exact counts; a class-only archive
  keeps the shipped zip identification and reports its
  missing MANIFEST.MF as a fact when summarized as a jar;
  compileSdkVersion is parsed off a planted stub-aapt2
  badging package line (34), with the Codename field not
  captured.
- Live verification: nar-fingerprint on the SDK-built
  demo fixture reports compile_sdk "34" (provenance:
  aapt2 dump badging). A full nar-analyze case on the
  same fixture emits application.json, manifest.json,
  native-inventory.json and frameworks.json (all
  schema-valid at write time), registered additively in
  report.json companions; application.json carries the
  fixture's package identity and compile_sdk 34.
- Full battery: pytest 165/165, doctor READY; the e2e
  analyze cases (app + game fixtures) assert the four
  companions exist, parse, and carry their kind markers.

## Evolution Phase 3 addendum (2026-11-24) — DEX/ELF depth

New executed evidence (local, this branch):

- tests/unit/test_android_intel.py: 6/6 pass — synthetic
  DEX code item with a known try range + typed handler +
  catch-all + debug offset parses exactly; a no-try item
  reports none; dexdis block summary on a known-branch
  method yields the exact two blocks and edge set;
  synthetic @Metadata parses (mv [1,9,0], kind 1) with
  the stream-desync regression case (string index 300
  inside an array element placed before mv/k); synthetic
  ELF64 with .rela.plt + .comment yields the planted
  JUMP_SLOT entry with its symbol resolved and clang +
  gcc fingerprints as observed; a section-less ELF claims
  no relocations and no fingerprints.
- Independent cross-checks (this phase, real fixtures):
  SDK dexdump vs narlib on a corpus DEX — methods with
  tries 484/484, try items 1,178/1,178, handler entries
  1,357/1,357; readelf -r vs narlib on the demo native
  library — .rela.dyn 3, .rela.plt 2, total 5, PLT/GOT 2,
  all agree (readelf also corrected the AArch64
  JUMP_SLOT type number to 1026); dexdis oracle harness
  re-run on the corpus DEX — FULL AGREEMENT, 230,836
  instructions compared, 0 mismatches, 709 payloads,
  0 mismatches.
- Real-target runs: nar-dex over a Kotlin corpus fixture
  reports 10,213 classes with parsed @Metadata (metadata
  versions 1.8.0 and 2.2.0 dominant; kind names class /
  file facade / synthetic class) and 14,762 try items /
  16,703 handler entries across its DEX files; nar-native
  on the demo fixture reports the readelf-matching
  relocation summary and the clang fingerprint.
- Full battery: pytest 171/171, doctor READY; e2e in the
  phase battery.

## Evolution Phase 4 addendum (2026-11-24) — engines

New executed evidence (local, this branch):

- tests/unit/test_engine_intel.py: 5/5 pass — synthetic
  Addressables catalog (locations, types, decoded entry
  table with per-type/per-provider counts exact); the
  REAL bundles fixture catalog (6,798 locations, 24,820
  entries decoded, all three index fields validated);
  planted text RN bundle (2 TurboModules, 1 Fabric
  component, 1 NativeModules reference, source map entry
  + sourceMappingURL detected); planted Flutter APK
  (5-entry inventory, JSON manifest declared keys = 2);
  synthetic Godot pack classification ([gd_scene header
  -> scene, PNG magic -> texture, RSRC -> binary resource
  with type name 'PackedScene', .gd -> script by
  extension, encrypted .png entry unclassified).
- tests/unit/test_uasset.py: +2 synthetic-layout tests —
  a versioned 1011 package (extension tail incl. the
  overridable payload: operation 3, experimental flag)
  and a 1012 package (complete type names:
  ArrayProperty<NameProperty> rendering + inner type,
  flags-carried bool, nested struct children values,
  GUID + extension tail behind the flags byte), both
  asserting the parser's synthetic-verification label.
- Real-target runs: nar-unity on the bundles fixture
  (catalog above); nar-rn on the Hermes fixture
  (architecture markers TurboModuleRegistry /
  codegenNativeComponent / NativeModules /
  __turboModuleProxy all present; names honestly not
  extracted); nar-flutter on the Flutter fixture (370
  entries, 2,845,674 bytes, by-type counts);
  nar-godot on the real pack (396 entries classified:
  36 scenes, 89 compiled scripts, 58 textures, 65 import
  metadata, 1 binary resource, 136 unknown).
- Full battery: pytest 178/178, doctor READY; e2e in the
  phase battery (new cases: unity-catalog, flutter-assets,
  godot-types; rn-positive extended with the markers line).

## Evolution Phase 5 addendum (2026-11-24) — protection + network

New executed evidence (local, this branch):

- tests/unit/test_signatures.py: 9/9 pass — the
  signature database loads (version 1.0.0, schema 1;
  counts: 7 categories, 11 packers, 6 RASP markers,
  1 licensing marker, 4 Widevine forms); its canonical
  digest equals the digest of the pre-extraction code
  literals (pinned in the test); malformed databases
  (missing file, wrong schema, bad matcher kind) are
  hard errors; nar-triage's module constants ARE the
  loaded database.
- Behavioral equivalence, executed directly: nar-triage
  --json from the pre-change tree vs the extracted tree
  on pairip-so, pairip-jiagu-dex, stub-unattributed and
  the demo fixture — outputs identical except the new
  protection_signatures provenance field.
- tests/unit/test_network_phase5.py: 7/7 pass —
  redact_url counts per planted shape (query param,
  userinfo, multi-param); analyze() over planted URLs
  reports exactly 5 redacted values with no secret
  substring anywhere in the serialized report and the
  3 sensitive classifications preserved; both network
  companions validate against their schemas, degraded
  (no-stage) projections are explicit, and the
  architecture projection's paths carry no query strings.
- Real case run on the demo fixture: network-analysis
  and api-architecture companions emitted + validated;
  endpoints document carries the redaction block.
- Full battery: pytest 194/194, e2e 52/52 (protection
  cases pass unchanged), doctor READY with the new
  protection-signatures check ok.

## Evolution Phase 6 addendum (2026-11-24) — runtime + security

New executed evidence (local + live emulator):

- tests/unit/test_runtime_sessions.py: 8/8 pass —
  session records built from recorded status snapshots
  validate against runtime-session.schema.json for both
  kinds; the no-device record keeps
  IMPLEMENTED_BUT_UNVERIFIED; plan records carry 6
  step-planned events and the target's real SHA-256;
  device errors land in the record's errors list;
  write/read round-trip. make_finding validates
  verification_status against the vocabulary (default
  UNVERIFIED); the security-findings schema accepts new
  AND legacy (field-less) findings and rejects values
  outside the vocabulary; nar-security over the demo
  fixture emits only in-vocabulary statuses and the
  report validates.
- Live session record: nar-runtime plan --session-out
  into a scratch case dir recorded the attached
  emulator (attached: true, label verified-live, 7
  events, target hash set).
- LIVE jni-trace (API 26 emulator, Frida 17.27.4,
  dynamic-registration demo variant built for this
  phase; full log in the runtime-test workspace):
  attach — "[jni-register] class=…DetailsActivity
  methods=1 via JNIEnv table", the per-method
  "[jni-register]" line (method name, signature, and
  the resolved symbol in the variant library), "[jni-entry]"
  on invocation; logcat shows the registered method
  returning its string. Spawn (resume-first recipe,
  pid continuity confirmed after a 50 s settle) —
  class-level [jni-register] captured. First attempts
  (CLI attach timeout under contention; transient
  empty pidof) recorded in the attempt log; the live
  run caught the Frida-17 Memory-statics defect in
  jni-trace.js, fixed in-cycle and re-captured.
- Full battery: pytest 202/202, e2e 52/52, doctor READY.

## Evolution Phase 7 addendum (2026-11-24) — assets + comparison

New executed evidence (local, this branch):

- tests/unit/test_assets_audio.py: 7/7 pass — WAV
  (2 ch / 44100 Hz / exactly 2.0 s from data÷byte-rate),
  Ogg Vorbis (final granule → exactly 3.0 s), MP3 Xing
  (100 frames → 2.612 s, basis names the Xing count),
  MP3 CBR estimate (2.0 s, basis labeled an estimate),
  FLAC + M4A + truncated WAV all unmeasured with
  reasons; inventory attaches the audio block to audio
  entries only.
- tests/unit/test_compare_artifacts.py: 4/4 pass —
  the feature map validates against
  compare-feature-map.schema.json and carries the
  fabricated deltas (permission, method delta, endpoint
  add); the build-noise separation counts the signing
  change as churn and the DEX change as content, with
  the signing dimension itself never hidden; the
  Markdown renders the same deltas; write_artifacts
  round-trips all three files.
- Planted-pair e2e (new case): nar-compare --out on
  the demo pair emits all three artifacts; assertions
  on the added permission, the +2 method delta, and
  the endpoint change (1 added / 1 removed) pass —
  the endpoint assertion exposed and fixed the
  group-dict iteration defect in the extended diff.
- Full battery: pytest 213/213, e2e 53/53, doctor READY.

## Evolution Phase 8 addendum (2026-11-24) — evidence + orchestration

New executed evidence (local, this branch):

- tests/unit/test_phase8_orchestration.py: 7/7 pass —
  correlation joins over fabricated stage documents
  (known pair matched/CONFIRMED; planted declaration
  declaration-only; unclaimed export export-only;
  component matched + declaration-only; endpoint
  code-referenced via string-reference classes;
  library matched by class prefix; degraded inputs
  produce noted empty sections, all schema-valid);
  the fact-class → verification mapping; budget tests
  (exhausted total budget stops a stage unrun with a
  budget-exceeded execution-log entry; a 1 ms stage
  cap on a real tool records budget-exceeded, no
  hang); case bundle round-trip on a synthetic case
  (4 files) with cache-key verification, and a
  tampered file failing verify by name.
- Real case run (demo fixture): correlations.json —
  jni_matched 1 (CONFIRMED, static-export),
  components_matched 2, endpoints 1 code-referenced /
  1 no-code-reference; JNI entries embedded in
  native.json; counts in report.json. Full-case schema
  sweep: 13/13 documents valid (fingerprint, findings,
  execution log, correlations, endpoints, case, six
  companions, assets).
- Real bundle round-trip: a 35-file case exported,
  imported to a fresh directory, verify OK; appending
  to the imported report.json makes verify FAIL
  naming the manifest mismatch (exit 1), cache
  integrity independently OK (7 entries).
- e2e (new cases): correlations.json consistency on
  the app case; case bundle round-trip + tamper on
  the app case. Full battery: pytest 220/220,
  e2e 55/55, doctor READY.

## Evolution Phase 9 addendum (2026-11-24) — reporting + CLI

New executed evidence (local, this branch):

- tests/unit/test_phase9_reporting_cli.py: 9/9 pass —
  dashboard dependency graph rendered from a synthetic
  native.json (section + inline SVG present, a label
  carrying markup characters escaped, a cyclic pair
  rendered, zero external references: no http(s)://,
  src=, href=, <link, @import), absent/empty graph
  renders no section, a 161-node graph truncates at
  120 with the native.json note; unified CLI: --help
  lists the five new verbs beside the old, each new
  verb's --help exits 0, `nar tools --json` returns
  the 35-tool registry view, identify/validate run on
  a synthetic APK (format apk, valid=True), a full
  case export → import → verify round-trip through
  `nar case`, unknown case subcommand exits 2.
- e2e (10 new cases, all PASS): cli tools JSON;
  --help sweep for tools/identify/validate/benchmark/
  case; identify + validate on the demo fixture;
  `nar case verify` + `nar case export` on the real
  app case; dashboard graph section + offline SVG +
  zero external references on a synthetic case;
  `nar benchmark` smoke on a demo-only corpus (runs
  emitted, JSON parses).
- Full battery: pytest 229/229, e2e 65/65
  (0 skipped), doctor READY.

## Evolution Phase 10 addendum (2026-11-24) — skill + integrations

New executed evidence (local, this branch):

- tests/unit/test_phase10_guide_audit.py: 5/5 pass —
  every (references|scripts) link target in SKILL.md +
  all 22 guides exists; every nar-*.py/sh filename
  mentioned exists; every --flag on a line naming a
  nar script is defined by that script; every
  backticked `nar <verb>` is a real dispatcher verb;
  SKILL.md frontmatter parses (name nar, version ==
  narlib version) and plugin.json parses with a
  matching version.
- One-time scripted audit (same extraction, wider
  net): block-level flag attribution 0 mismatches;
  51 flag tokens defined by no nar script, each read
  in context — all external-tool flags (bundletool,
  apksigner, jadx, frida-tools, oatdump, GDRE,
  mitmproxy, dotnet-install, pip, node --check),
  including one guide correction note (--jvm-args is
  documented as NOT a jadx flag). Discrepancies fixed:
  1 stale capability claim (DEX guide scope limit),
  2 discoverability gaps (session records, nar tools).
- Full battery: pytest 234/234, e2e 65/65
  (0 skipped), doctor READY.

## Evolution Phase 11 addendum (2026-11-24) — testing + benchmarks

New executed evidence (local, this branch):

- tests/unit/test_phase11_mutations.py: 5/5 pass —
  DEX (bad magic, half-truncated, inflated
  string_ids count, empty), ELF (bad magic,
  16-byte truncation, invalid EI_CLASS, empty), PAK
  (zero-filled, half-truncated, empty), IoStore TOC
  (bad magic, half/40-byte truncation, empty) and Zen
  (flipped magic byte, half/24-byte truncation,
  empty) inputs each raise exactly the parser's named
  error type (DexError / ElfError / PakError /
  IoStoreError / ZenError) on construct + materialize.
  Two defects found by the corpus and fixed in-phase:
  narlib.dex header-table extent validation (was: a
  bare struct.error leaked from strings() on an
  inflated count), narlib.elf EI_CLASS validation
  (was: invalid class silently treated as 32-bit).
- Benchmark run (tests/benchmarks/run_benchmarks.py,
  full local corpus): 28/28 timing runs exit 0.
  Metrics as measured — protection (real: 1 protected
  + 9 clean): precision 1.0, recall 1.0, 0 FP;
  engines (real): recall 1.0, 6/6 labeled positives;
  engines (synthetic): accuracy 1.0, 8/8 (first run
  0.875 was a runner label typo — "Xamarin /.NET" vs
  the canonical "Xamarin / .NET"; the engine detected
  the fixture at score 44; corrected + re-run);
  formats (real): accuracy 1.0, 10/10. Engine
  precision on the real corpus: NOT RUN (no labeled
  engine-negative real corpus). Peak memory:
  nar-analyze on the largest fixture (273,366,540 B)
  → peak RSS 1,887,338,496 B (nar-analyze process
  only; stage subprocess peaks excluded), 304.69 s.
- Full battery: pytest 239/239, e2e 65/65
  (0 skipped), doctor READY.

## Evolution Phase 12 addendum (2026-11-24) — release preparation

New executed evidence (local, this branch):

- Version consistency at 2.5.0: test_docs_consistency
  + test_phase10_guide_audit pass with all 18
  version-bearing locations at 2.5.0; `nar version`
  prints "NAR 2.5.0".
- CLI smoke, all verbs: 28 verbs (27 dispatcher verbs
  + the case router) each run with --help → exit 0;
  `nar version` → 2.5.0. 29/29 invocations clean.
- Final battery: pytest 239/239, e2e 65/65
  (0 skipped), doctor "Core toolchain: READY".
- Whole-evolution-diff greps (ba2ad2e..HEAD):
  banned identifiers 0 hits; forbidden credits
  0 hits.
- Tree state: clean on branch `evolution`;
  release-ready. No merge, push, tag, or publication
  performed (owner's explicit decision reserved).
