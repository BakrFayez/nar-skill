# Troubleshooting

Symptoms seen in real runs, with the actual cause and fix.

## A module says a tool is "not available"

The capability registry could not find it. Run
`bash scripts/nar-doctor.sh` for the human view, then either
install the tool, put it on PATH, or point the registry at
it with `NAR_<NAME>_PATH=/path/to/tool`. Optional tools
degrade only their own stage; the rest of the workup still
runs and the report says what was skipped.

## jadx / baksmali adapter produced nothing

`nar-dex.py --jadx/--baksmali` probes the registry first and
reports the probe result in its `jadx`/`baksmali` block —
check there before assuming a parse failure. jadx lives at
`~/workspace/tools/jadx-cli` in the reference environment
and is not on PATH; the registry finds it by design.

## UnityPy census missing in nar-unity

UnityPy is an optional dependency, probed by import in the
*running interpreter*. System python3 may not have it while
a project venv does. The bundle inventory is unaffected
(magic-verified); only the object census needs UnityPy.

## Stage results look stale after changing the input

The case cache is keyed by input SHA-256 + stage + NAR
version, so a changed input can never hit a stale entry.
If you changed the *tooling*, re-run with
`nar-analyze.py --no-cache`.

## nar-network found no network security config

The NSC pass needs an apktool decode: pass `--work DIR`.
Without it the module says so in its notes instead of
guessing. An app may also simply ship no NSC resource
(cleartext field then reads `None`, not `false`).

## Endpoints classified "unverified"

Those strings have no parseable host (path fragments,
format templates like `http://][USER:PASSWORD@]HOST[:PORT`).
That is the honest bucket for them — they are listed so a
human can judge, not silently dropped.

## Engine verdict is "weak candidate"

Score under the detection bar: the indicators are listed
with the verdict. Run with `--deep` to let the engine's own
deep-dive tool confirm or refute it, and read the
ambiguities list (bare `assets/www` and leftover Mono
payloads are the usual causes).

## Huge apps are slow in nar-dex / nar-analyze

The DEX parser walks every class's code items for call
edges. On very large apps this takes minutes, not seconds;
the orchestrator's per-tool timeout is 1800s and the stage
cache means it is paid once per input. The execution log
shows where the time went.

## Doctor says java is MISSING but java works

Check /tmp space first: on a full tmpfs the JVM prints an
"Insufficient space for shared memory file" warning into
its version output and the doctor's parse fails. The usual
cause is accumulated analysis scratch (Il2CppDumper outputs
are ~250 MB per Unity title) — pass `--work`/`--out` into a
roomy directory (nar-unity, nar-engines, nar-analyze all
accept one) and clear old scratch dirs.

## report.html has no fingerprint table

The dashboard renders the companions that exist. If a stage
degraded (see report.json `limitations` and the execution
log), its section is absent rather than empty-faked.

## Emulator never finishes booting on a KVM-less host

nar-runtime's device steps need a booted device. On a host
without /dev/kvm, the Android emulator falls back to QEMU
TCG software emulation (it refuses `-accel off` unless
ANDROID_I_WANT_MY_TCG=yes is set), and a modern google_apis
image may not reach `sys.boot_completed=1` within any
practical time box on a small shared-CPU VM — adb can show
state `device` and a stopped boot animation while the guest
is still crawling. That is an environment limit, not a NAR
defect: the runtime subsystem stays IMPLEMENTED_BUT_UNVERIFIED
until it is run against a booted emulator on a KVM-capable
host or a physical device. Related traps on hand-assembled
SDKs: avdmanager may refuse AVD creation when the emulator
package lacks package.xml (write the AVD config by hand), and
an unknown `skin.name` in config.ini is fatal even headless.

Resolution (verified 2026-11-23 on the same KVM-less host):
image choice is the lever. A lean older image — API 26
(Android 8.0.0) google_apis x86_64, 1536 MB RAM, 4 cores,
`-accel off -gpu swiftshader_indirect -no-window -no-audio
-no-boot-anim -no-snapshot` — reached `sys.boot_completed=1`
in about 9 minutes under TCG and ran the full runtime
workflow (adb, install/launch, frida-server as root, Frida
observation by attach). The modern API-34 image remains a
dead end on such hosts; do not generalize its failure to the
runtime layer. Two more traps from the same session: when
sdkmanager's repository view is frozen, the system-image zip
can be fetched directly from dl.google.com and installed by
hand (verify the SHA-1 from the repository XML and write a
package.xml modeled on an installed image's); and Frida
spawn mode (`frida -U -f`) repeatedly lost its session
during script load under TCG even though the app launched —
attach (`-p <pid>`) to the already-running process instead.
The spawn failure was later root-caused and resolved:
logcat shows ActivityManager killing the spawned process
with reason "start timeout" — a started process must
attach to ActivityManager within ~10 s, a Frida-gated
child cannot attach while gated, and the load-before-
resume sequence cannot beat that clock under TCG. The
verified resolution is the resume-first recipe: spawn
with the Frida API (`device.spawn`), resume in the very
next call, let the process settle ~40-50 s, then load
the script with `frida -U -p <spawned pid> -l <script>`;
both bundled observation scripts were verified live in
Frida-spawned processes this way (see
references/frida-scripts.md).

## frida-ps fails with a PackageManagerInternal NPE

If frida-server was started before the system finished
booting and settling, `frida-ps -U` can fail with a
PackageManagerInternal NPE even though the server is
running and the device is healthy. Restart frida-server
after `sys.boot_completed=1` and a settle period; process
enumeration then works normally. Observed on the API 26
emulator target during the verified runtime sessions.
