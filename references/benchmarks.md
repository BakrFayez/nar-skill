# Benchmarks and accuracy metrics

`tests/benchmarks/run_benchmarks.py` (also reachable as
`nar benchmark`) measures three things on the local
fixture corpus, and reports each as measured — nothing
is estimated, extrapolated, or carried over from another
machine:

1. **Wall-clock timings** for a fixed module set
   (triage, fingerprint, engines, dex, native, network,
   assets) over the demo / app / game / Unity fixture
   roles.
2. **Accuracy metrics** computed from the labeled
   corpora that actually exist locally (below).
3. **Peak memory** for one full `nar-analyze` run over
   the largest locally bound fixture.

Corpora are bound through `$NAR_FIXTURES/manifest.env`
(the same role pattern as the e2e harness). Output —
console and the `--out` JSON — uses role labels only,
never fixture file names. A metric whose labeled corpus
is not bound is reported `not_run` with the reason.

## The labeled corpora

**Protection attribution (real).** One protected
fixture (a real app carrying a known commercial packer)
and a clean set of real apps known to carry no packer.
A detection is an *attributed* `commercial_packer`
finding in `nar-triage --json` output. Precision and
recall are computed for that single class over that
corpus: recall is 1.0 or 0.0 by construction (one
positive), so the informative number is the clean-set
false-positive count.

**Engine detection (real).** Fixture roles whose engine
is known by construction (Unity ×2, Flutter, React
Native, Unreal, Godot). A detection is a verdict with
`detected: true` naming the expected engine (either
Unity variant counts for the Unity roles). The metric
is recall over labeled positives. **Real-corpus
precision is NOT RUN**: no labeled engine-negative real
corpus exists locally — the clean app set's engines are
unlabeled, so a "false positive" cannot be scored
honestly.

**Engine detection (synthetic).** Doctored demo copies
of the project's own demo app, each carrying one
framework's marker set (Xamarin, Cordova, Capacitor,
Qt, Defold, Ren'Py, RPG Maker, embedded Python). These
are synthetic by construction — the numbers measure
marker recognition, not real-world engine prevalence —
and are always reported separately from the real
corpus.

**Format identification (real).** Fixture roles whose
container format is known (eight APKs, one XAPK, one
bare Godot pack), scored against `nar-input identify`.

## Peak memory: what the number is

The runner measures memory **before** running anything
else: it starts one `nar-analyze` subprocess on the
largest bound fixture and reads
`resource.getrusage(RUSAGE_CHILDREN).ru_maxrss` after it
exits. That is the peak resident set size of the
nar-analyze process itself. nar-analyze runs its stages
as subprocesses (grandchildren of the runner), whose
peaks are **not** included — so the figure is a floor
for the whole tree's peak, stated as such wherever it
is reported. It is a measurement from one run on one
machine, not a guarantee or a limit.

## Synthetic-corpus parser completeness (2.6.0 Phase 11)

The public synthetic corpus (`tests/synthetic_fixtures.py`
+ `tests/expected_outputs.json`) supports a second,
fully reproducible accuracy measure that needs no private
files: for each of the 11 fixtures, the fields the unit
suite asserts (parser output vs builder intent) are
counted as checked / matched. The 2.6.0 measurement
(recorded in `tests/benchmarks/baseline-2.6.0.json`):
**85 of 85 asserted fields matched across all 11
fixtures** (dex 10, elf 8, pak 7, iostore 12, zen 6,
uasset ×5 6–8 each, godot 6). Format identification over
the 12 generated files: the identifier names a specific
format for the DEX, ELF, Godot pack and IoStore .utoc
files, and — after the Phase 11 tail-window fix — the
v11 pak; bare .uasset/.ucas files are content formats
reached through `nar-unreal` / `nar-pak`, not intake
formats, and identify as `unknown` by design.

## Line coverage (2.6.0 Phase 11, R-016)

Coverage is test-side tooling only (never a shipped
dependency). Measured with coverage.py in the test venv
over the unit suite; the number, tool version, command
and scope are recorded in
`tests/benchmarks/baseline-2.6.0.json` — see that file
for the current figure and its exact methodology.

## Reproducing

```bash
export NAR_FIXTURES=~/workspace/nar-e2e-fixtures
python3 tests/benchmarks/run_benchmarks.py --out metrics.json
# or: python3 scripts/nar.py benchmark --out metrics.json
```

`--no-metrics` / `--no-memory` skip sections. Timings
vary by machine and load; accuracy metrics over the
same corpus are deterministic and should reproduce
exactly.
