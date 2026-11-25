# DEX mutation fuzzing (tests/fuzz)

Deterministic, stdlib-only mutation fuzzing for the DEX parsers
(`narlib/dex.py` and `narlib/dexdis.py`). Research by Bakr Fayez.

## Invariant under test

Any malformed input raises `DexError` (the module's named error)
— or, inside dexdis, fails that one method's listing with a
recorded reason. It never leaks `IndexError` / `struct.error` /
`ValueError` / `RecursionError`, never hangs, and never performs
an allocation sized by an attacker-controlled count without a
count-vs-remaining-bytes check.

## Running

```sh
python3 tests/fuzz/dex_fuzz.py --seed 1 --iterations 2000 --out /tmp/dex-fuzz-out
```

Exit status is 0 when no distinct failure is found, 1 when at
least one was. A per-case timeout (default 2 s, `--timeout`)
turns a hang into a recorded `Timeout` failure. Runs are fully
deterministic: the same `--seed` and `--iterations` reproduce
the same mutants in the same order.

## Seed corpus

Seeds are generated at runtime from the repo's synthetic DEX
builders (`tests/unit/test_dex_elf.build_dex` and the
with-class builder in `tests/unit/test_deep_audit_remediation`),
plus one derived seed that appends a code item and an annotation
directory to the with-class output. No fixture bytes are
committed for fuzzing.

Optionally, real DEX files from local analysis work can be added
as seeds by pointing the environment variable at a local
directory:

```sh
NAR_DEX_FUZZ_SEEDS=/path/to/local/dex-seeds \
    python3 tests/fuzz/dex_fuzz.py --seed 1 --iterations 2000
```

Files from that directory are read as seeds only. They are never
committed to the repo, and crash artifacts derived from them stay
in the `--out` directory the operator chose.

## Mutation strategy

Each iteration applies one strategy, chosen by the seeded RNG:

- **byte-flip** — 1–8 random byte replacements anywhere.
- **header-field** — a header table size/offset word (0x38–0x6C)
  set to 0, 1, a huge value, or a past-EOF offset.
- **count-blast** — a random aligned word set to an absurd count.
- **leb-run** — an overlong or unterminated LEB128 byte run
  spliced in at a random position.
- **truncate** — the tail cut at a random point.
- **random-word** — random 16-bit words overwritten.
- **class-data** — corruption aimed at the tail region where the
  synthetic layouts keep class defs / class data / annotations.

Every mutant is exercised through the parser entry points:
header construction, string/type tables, class defs, class
fields/methods (both walks), class annotations, proto info,
method/field refs, code-item info, the code scan, identifier
shape stats, call-graph assembly, and dexdis disassembly + CFG
batch over all methods.

## Crash artifacts and repro

Failures are deduplicated by (exception type, message shape,
top frame). Each distinct failure is preserved in `--out` as:

- `crash-<id>.dex` — the exact mutated bytes, and
- `crash-<id>.repro.json` — seed, iteration, base seed,
  strategy, artifact hash, and the repro command.

To reproduce one artifact directly, feed its bytes to
`narlib.dex.Dex` and the entry points listed above, or rerun the
harness with the recorded seed and an `--iterations` count one
past the recorded iteration.

## From crash to regression

A distinct failure is not done when it is found:

1. Minimize/explain it (which offset or count drives it).
2. Fix the parser so the input raises the named error (or the
   per-method listing failure in dexdis) — never special-case
   the artifact bytes.
3. Add a regression test to
   `tests/unit/test_dex_fuzz_regressions.py` that constructs the
   failing shape synthetically and pins the fixed behavior.
4. Re-run the harness on the finding seed (must be clean) and a
   wider sweep before calling the round done.

## Optional: Atheris

Atheris (Google's coverage-guided Python fuzzer, built on
libFuzzer) can drive the same `exercise` entry point for
coverage-guided campaigns on a workstation that has it
installed. It is an optional operator tool only: it is never
imported by shipped code, never required by the test suite, and
the seeded harness above remains the reproducible baseline.
