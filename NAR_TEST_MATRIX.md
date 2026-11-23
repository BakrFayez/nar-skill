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
- Real-asset rung, UE5 (EXECUTED 2026-11-23 — sample
  obtained; containers sealed): a free UE5 Android
  title was lawfully obtained with the owner's explicit
  approval (a ~2.6 GB bundle: split APKs, an install-
  time asset pack, and an OBB) and its containers were
  located and inspected. The UE5 generation is
  confirmed from the data itself: the engine binary
  carries UE5 console-variable category strings and a
  help string referencing UE 5.4.2, and every content
  container is pak format version 11. Seven paks in
  total (six in the install-time asset pack, one
  inside the OBB) were footer-checked individually:
  all seven set the footer index-encryption flag, the
  footer index SHA-1 does not match the stored index
  bytes, and the index regions measure ~8 bits/byte of
  entropy — the indexes are AES-encrypted. The only
  compression method registered in any footer is
  Oodle. No entry can therefore be listed or extracted
  through the pak path, and key extraction is outside
  this skill's scope by design, so no cooked package
  could be obtained for narlib.uasset: the parser
  remains unexercised on real UE5 packages, and the
  UE5 evidence of record is unchanged (the UE5-era
  synthetic fixture, object version 1010, and the
  exact section accounting previously done on real
  IoStore TOC containers). The rung's question stays
  open, with the blocker now precisely identified:
  this title's containers are sealed, so a future
  attempt needs a UE5 title that ships unencrypted
  pak indexes or IoStore containers.
- In-cycle change from this rung: nar-pak now surfaces
  the v7+ footer index-encryption flag (report field
  index_encrypted, an explicit sentence in the v8+
  unsupported error, a human-output line, and a
  nar-unreal pak-summary passthrough), so a sealed
  modern pak states both of its blockers instead of
  only the index-layout one. Covered by
  tests/unit/test_pak.py on synthetic byte-exact
  footers (v11 encrypted / v11 plain / v5 no-field).

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
