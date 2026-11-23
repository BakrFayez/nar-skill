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
