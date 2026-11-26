#!/usr/bin/env python3
"""Deterministic mutation fuzz harness for the binary
Android XML (AXML) and resources.arsc parsers.

Stdlib only. Given a seed and an iteration count, the harness
generates mutated inputs from the repo's synthetic builders
(the AXML builder in tests/unit/test_app.py, the animator
AXML builder in tests/unit/test_phase2_anim.py, and the
resources.arsc builder in tests/unit/test_phase2_app.py --
no fixture bytes are committed), runs each mutant through
every parser that consumes the format, and records every
*distinct* failure that violates the parser invariant:

    AXML (nar-perms): any malformed input raises
    ManifestError (the named error) or parses -- never a
    bare IndexError / struct.error / ValueError leak,
    never a hang.
    AXML (narlib.anim tree walk): returns a node tree or
    None -- never raises.
    AXML (nar-flutter embedding walk): returns a record
    dict (a parse failure is an "error" record) -- never
    raises.
    ARSC (nar-app string lookup): returns the resolved
    string or None -- never raises.

The mutators are structure-aware: they walk the seed's chunk
table and blast chunk-header fields (type, header size,
chunk size), string-pool fields (string/style counts, flags,
string/style start offsets, per-string offset table entries,
string length prefixes), element attribute counts / starts /
sizes, the ARSC table header (package count), package
fields (id, type/key string-pool offsets) and type-chunk
fields (entry count, entries start, per-entry offsets) --
plus truncations and seeded byte flips.

A failure is distinct by (parser, exception type, exception
message shape, top traceback frame). Each distinct failure
is preserved under ``--out`` as the mutated bytes plus a
``*.repro.json`` describing seed/iteration/mutation and the
exact repro command.

Usage:
    python3 tests/fuzz/axml_fuzz.py --seed 1 --iterations 1000 \
        --out /tmp/axml-fuzz-out

``--iterations`` is the count PER FORMAT (AXML and ARSC are
swept separately). Exit status is 0 when no distinct failure
was found, 1 when at least one was.

Part of NAR (Nirous Android Reversing).
"""
import argparse
import hashlib
import importlib.util
import json
import os
import random
import signal
import struct
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
SCRIPTS = os.path.join(ROOT, "scripts")
UNIT = os.path.join(ROOT, "tests", "unit")
sys.path.insert(0, SCRIPTS)


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


nar_perms = _load("nar_perms_fuzz", os.path.join(SCRIPTS,
                                                 "nar-perms.py"))
nar_app = _load("nar_app_fuzz", os.path.join(SCRIPTS,
                                             "nar-app.py"))
nar_flutter = _load("nar_flutter_fuzz",
                    os.path.join(SCRIPTS, "nar-flutter.py"))
from narlib import anim  # noqa: E402

ManifestError = nar_perms.ManifestError

#: Resource ids probed against every ARSC mutant: the seed's
#: real string entry, a wrong-type id, a wrong-package id,
#: and the extremes of each id field.
ARSC_PROBE_IDS = (0x7F010000, 0x7F020000, 0x7F01FFFF,
                  0x01010000, 0xFFFFFFFF, 0x00000000)


def seed_corpus():
    """Synthetic seeds from the repo's own builders,
    generated at runtime. Returns (axml_seeds, arsc_seeds),
    each a list of (name, bytes)."""
    app_tests = _load("_fuzz_test_app",
                      os.path.join(UNIT, "test_app.py"))
    anim_tests = _load("_fuzz_test_phase2_anim",
                       os.path.join(UNIT, "test_phase2_anim.py"))
    app2_tests = _load("_fuzz_test_phase2_app",
                       os.path.join(UNIT, "test_phase2_app.py"))
    axml_seeds = [
        ("synthetic-manifest", app_tests.manifest_axml()),
        ("synthetic-layout",
         app_tests.build_axml("LinearLayout", [], [])),
        ("synthetic-animator-set", anim_tests._axml_set_doc()),
    ]
    arsc_seeds = [
        ("synthetic-arsc", app2_tests.make_arsc("Synthetic App")),
    ]
    seed_dir = os.environ.get("NAR_AXML_FUZZ_SEEDS")
    if seed_dir and os.path.isdir(seed_dir):
        for name in sorted(os.listdir(seed_dir)):
            path = os.path.join(seed_dir, name)
            if os.path.isfile(path):
                with open(path, "rb") as fh:
                    blob = fh.read()
                if blob[:2] == b"\x02\x00":
                    arsc_seeds.append((f"local:{name}", blob))
                else:
                    axml_seeds.append((f"local:{name}", blob))
    return axml_seeds, arsc_seeds


def _chunk_offsets(data):
    """Chunk start offsets of a chunked binary (AXML file
    header at 0, then chunks; ARSC table header, then
    chunks), walked leniently: stop at the first implausible
    size. Used only to AIM mutations; the parsers re-walk
    everything themselves."""
    offs = []
    if len(data) < 8:
        return offs
    off = 8 if struct.unpack_from("<I", data, 0)[0] == 0x00080003 \
        else struct.unpack_from("<H", data, 2)[0]
    while 0 < off and off + 8 <= len(data):
        _t, _h, size = struct.unpack_from("<HHI", data, off)
        if size < 8 or off + size > len(data) + 8:
            break
        offs.append(off)
        off += size
    return offs


_DWORD_VALUES = (0, 1, 2, 0x7FFFFFFF, 0xFFFFFFFF)
_WORD_VALUES = (0, 1, 8, 0x8000, 0xFFFF)


def _blast(rng, buf, off, size):
    if off + size > len(buf):
        return False
    if size == 2:
        struct.pack_into("<H", buf, off,
                         rng.choice(_WORD_VALUES))
    elif size == 4:
        struct.pack_into("<I", buf, off, rng.choice(
            _DWORD_VALUES + (len(buf) + rng.randrange(1, 4096),)))
    return True


def mutate_axml(rng, data):
    """One mutated AXML copy plus a strategy label."""
    buf = bytearray(data)
    chunks = _chunk_offsets(bytes(buf))
    strategy = rng.choice([
        "chunk-header", "chunk-header", "pool-field",
        "pool-offset", "string-length", "attr-field",
        "truncate", "byte-flip", "count-blast",
    ])
    if strategy == "chunk-header" and chunks:
        base = rng.choice(chunks + [0])
        field = rng.choice((0, 2, 4))  # type, headerSize, size
        if not _blast(rng, buf, base + field, 2 if field < 4 else 4):
            strategy = "byte-flip"
    elif strategy == "pool-field" and chunks:
        # String-pool chunk fields: stringCount, styleCount,
        # flags, stringsStart, stylesStart at +8..+28.
        pools = [c for c in chunks
                 if c + 2 <= len(buf)
                 and struct.unpack_from("<H", buf, c)[0] == 0x0001]
        if pools:
            base = rng.choice(pools)
            _blast(rng, buf, base + rng.choice(
                (8, 12, 16, 20, 24)), 4)
        else:
            strategy = "byte-flip"
    elif strategy == "pool-offset" and chunks:
        # One string-offset table entry of the pool.
        pools = [c for c in chunks
                 if c + 2 <= len(buf)
                 and struct.unpack_from("<H", buf, c)[0] == 0x0001]
        if pools:
            base = rng.choice(pools)
            header_size = struct.unpack_from(
                "<H", buf, base + 2)[0] if base + 4 <= len(buf) \
                else 28
            count = struct.unpack_from(
                "<I", buf, base + 8)[0] if base + 12 <= len(buf) \
                else 0
            if count:
                entry = base + header_size \
                    + 4 * rng.randrange(min(count, 64))
                _blast(rng, buf, entry, 4)
            else:
                strategy = "byte-flip"
        else:
            strategy = "byte-flip"
    elif strategy == "string-length":
        # Length prefixes live in the pool body; a random
        # byte in the back half lands on them often enough.
        if len(buf) > 32:
            pos = rng.randrange(16, len(buf))
            buf[pos] = rng.choice((0x80, 0xFF, 0x7F, 0x00))
    elif strategy == "attr-field" and chunks:
        # Start-element fields: name index (+20), attribute
        # start/size/count (+24..+30), or one attribute
        # record's indices.
        starts = [c for c in chunks
                  if c + 2 <= len(buf)
                  and struct.unpack_from("<H", buf, c)[0] == 0x0102]
        if starts:
            base = rng.choice(starts)
            field = rng.choice((20, 24, 26, 28, 36, 40, 44))
            _blast(rng, buf, base + field,
                   2 if field in (24, 26, 28) else 4)
        else:
            strategy = "byte-flip"
    elif strategy == "count-blast":
        off = rng.randrange(0, max(1, len(buf) - 3))
        struct.pack_into("<I", buf, off,
                         rng.choice([0xFFFFFFFF, 0x7FFFFFFF,
                                     0x10000000, 65535]))
    elif strategy == "truncate":
        if len(buf) > 16:
            del buf[rng.randrange(1, len(buf)):]
    if strategy == "byte-flip":
        for _ in range(rng.randint(1, 8)):
            if buf:
                buf[rng.randrange(len(buf))] = rng.randrange(256)
    return bytes(buf), strategy


def mutate_arsc(rng, data):
    """One mutated ARSC copy plus a strategy label."""
    buf = bytearray(data)
    chunks = _chunk_offsets(bytes(buf))
    strategy = rng.choice([
        "table-header", "chunk-header", "chunk-header",
        "pool-field", "package-field", "type-field",
        "entry-offset", "truncate", "byte-flip", "count-blast",
    ])
    if strategy == "table-header":
        # ResTable header: headerSize (+2), total size (+4),
        # package count (+8).
        field = rng.choice((2, 4, 8))
        if not _blast(rng, buf, field, 2 if field == 2 else 4):
            strategy = "byte-flip"
    elif strategy == "chunk-header" and chunks:
        base = rng.choice(chunks)
        field = rng.choice((0, 2, 4))
        if not _blast(rng, buf, base + field,
                      2 if field < 4 else 4):
            strategy = "byte-flip"
    elif strategy == "pool-field" and chunks:
        pools = [c for c in chunks
                 if c + 2 <= len(buf)
                 and struct.unpack_from("<H", buf, c)[0]
                 in (0x0001,)]
        pkgs = [c for c in chunks
                if c + 2 <= len(buf)
                and struct.unpack_from("<H", buf, c)[0] == 0x0200]
        bases = pools + [p + 288 for p in pkgs]  # package pools
        if bases:
            base = rng.choice(bases)
            if base + 28 <= len(buf):
                _blast(rng, buf, base + rng.choice(
                    (8, 12, 16, 20, 24)), 4)
            else:
                strategy = "byte-flip"
        else:
            strategy = "byte-flip"
    elif strategy == "package-field" and chunks:
        pkgs = [c for c in chunks
                if c + 2 <= len(buf)
                and struct.unpack_from("<H", buf, c)[0] == 0x0200]
        if pkgs:
            base = rng.choice(pkgs)
            # id (+8), name area, typeStrings (+268),
            # keyStrings (+276), typeIdOffset (+284).
            field = rng.choice((8, 268, 272, 276, 280, 284))
            _blast(rng, buf, base + field, 4)
        else:
            strategy = "byte-flip"
    elif strategy in ("type-field", "entry-offset"):
        types = []
        for c in chunks:
            if c + 2 <= len(buf) and \
                    struct.unpack_from("<H", buf, c)[0] == 0x0200:
                phdr = struct.unpack_from("<H", buf, c + 2)[0]
                sub = c + phdr
                end = min(c + struct.unpack_from(
                    "<I", buf, c + 4)[0], len(buf)) \
                    if c + 8 <= len(buf) else len(buf)
                while sub + 8 <= end:
                    t, _h, s = struct.unpack_from("<HHI", buf, sub)
                    if s < 8:
                        break
                    if t == 0x0201:
                        types.append(sub)
                    sub += s
        if types:
            base = rng.choice(types)
            if strategy == "type-field":
                # id/reserved (+8), entryCount (+12),
                # entriesStart (+16), config size (+20).
                field = rng.choice((8, 12, 16, 20))
                _blast(rng, buf, base + field,
                       1 if field == 8 else 4)
            else:
                chdr = struct.unpack_from(
                    "<H", buf, base + 2)[0]
                _blast(rng, buf, base + chdr, 4)
        else:
            strategy = "byte-flip"
    elif strategy == "count-blast":
        off = rng.randrange(0, max(1, len(buf) - 3))
        struct.pack_into("<I", buf, off,
                         rng.choice([0xFFFFFFFF, 0x7FFFFFFF,
                                     0x10000000, 65535]))
    elif strategy == "truncate":
        if len(buf) > 16:
            del buf[rng.randrange(1, len(buf)):]
    if strategy == "byte-flip":
        for _ in range(rng.randint(1, 8)):
            if buf:
                buf[rng.randrange(len(buf))] = rng.randrange(256)
    return bytes(buf), strategy


class _Timeout(Exception):
    pass


def _alarm(_signum, _frame):
    raise _Timeout()


def _probe(parser, fn):
    """Run one parser probe; None = clean, else failure."""
    try:
        fn()
    except _Timeout:
        raise
    except RecursionError as e:
        return (parser, "RecursionError", str(e)[:200])
    except Exception as e:  # noqa: BLE001 - the invariant probe
        tb = sys.exc_info()[2]
        frame = traceback.extract_tb(tb)[-1].name if tb else "?"
        return (parser, type(e).__name__, f"{e} @ {frame}")
    return None


def exercise_axml(data):
    """All AXML consumers over one input. Returns None on
    clean handling, or the first failure tuple
    (parser, kind, detail)."""
    failures = []

    def perms_probe():
        try:
            nar_perms.parse_axml(data)
        except ManifestError:
            pass  # refused by name: the invariant holds

    failures.append(_probe("nar-perms.parse_axml", perms_probe))

    def anim_probe():
        tree = anim._parse_axml_tree(data)
        assert tree is None or isinstance(tree, dict)
        rec = anim.parse_android_view(
            data, "res/anim/fuzz.xml", None)
        assert rec is None or isinstance(rec, dict)

    failures.append(_probe("narlib.anim axml", anim_probe))

    def flutter_probe():
        rec = nar_flutter.manifest_embedding(data)
        assert isinstance(rec, dict) and "present" in rec

    failures.append(_probe("nar-flutter.manifest_embedding",
                           flutter_probe))
    for failure in failures:
        if failure is not None:
            return failure
    return None


def exercise_arsc(data):
    """The ARSC string lookup over one input, probed with
    several resource ids. Returns None on clean handling,
    or a failure tuple."""
    def arsc_probe():
        for res_id in ARSC_PROBE_IDS:
            out = nar_app._arsc_lookup(data, res_id)
            assert out is None or isinstance(out, str)

    return _probe("nar-app._arsc_lookup", arsc_probe)


def _run_format(label, seeds, mutate, exercise, rng, args,
                out_dir, seen):
    failures = 0
    for i in range(args.iterations):
        seed_name, seed_bytes = seeds[rng.randrange(len(seeds))]
        mutant, strategy = mutate(rng, seed_bytes)
        use_alarm = hasattr(signal, "SIGALRM")
        if use_alarm:
            signal.setitimer(signal.ITIMER_REAL, args.timeout)
        try:
            failure = exercise(mutant)
        except _Timeout:
            failure = (label, "Timeout",
                       f"exceeded {args.timeout}s per-case budget")
        finally:
            if use_alarm:
                signal.setitimer(signal.ITIMER_REAL, 0)
        if failure is None:
            continue
        parser, kind, detail = failure
        key = hashlib.sha256(
            f"{parser}|{kind}|{detail}".encode()).hexdigest()[:12]
        if key in seen:
            continue
        seen[key] = {"parser": parser, "kind": kind,
                     "detail": detail, "seed": args.seed,
                     "iteration": i, "format": label,
                     "base_seed": seed_name, "strategy": strategy}
        failures += 1
        print(f"DISTINCT FAILURE {key}: [{label}] {parser}: "
              f"{kind}: {detail} (seed={args.seed} iter={i} "
              f"base={seed_name} strategy={strategy})")
        if out_dir:
            ext = "arsc" if label == "arsc" else "axml"
            artifact = os.path.join(out_dir, f"crash-{key}.{ext}")
            with open(artifact, "wb") as fh:
                fh.write(mutant)
            repro = dict(seen[key])
            repro.update({
                "artifact": os.path.basename(artifact),
                "sha256": hashlib.sha256(mutant).hexdigest(),
                "repro": (f"python3 tests/fuzz/axml_fuzz.py "
                          f"--seed {args.seed} "
                          f"--iterations {i + 1} --out DIR "
                          f"# or feed {os.path.basename(artifact)} "
                          f"to the {parser} entry point directly"),
            })
            with open(os.path.join(
                    out_dir, f"crash-{key}.repro.json"),
                    "w", encoding="utf-8") as fh:
                json.dump(repro, fh, indent=1, sort_keys=True)
    print(f"done[{label}]: seed={args.seed} "
          f"iterations={args.iterations} "
          f"distinct_failures={failures}")
    return failures


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--iterations", type=int, default=1000,
                        help="iterations PER FORMAT")
    parser.add_argument("--out", default=None,
                        help="directory for crash artifacts")
    parser.add_argument("--timeout", type=float, default=2.0,
                        help="per-case timeout in seconds")
    args = parser.parse_args(argv)

    axml_seeds, arsc_seeds = seed_corpus()
    if not axml_seeds or not arsc_seeds:
        print("no seeds available", file=sys.stderr)
        return 2
    rng = random.Random(args.seed)
    out_dir = args.out
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    seen = {}
    failures = 0
    use_alarm = hasattr(signal, "SIGALRM")
    old_handler = (signal.signal(signal.SIGALRM, _alarm)
                   if use_alarm else None)
    try:
        failures += _run_format("axml", axml_seeds, mutate_axml,
                                exercise_axml, rng, args,
                                out_dir, seen)
        failures += _run_format("arsc", arsc_seeds, mutate_arsc,
                                exercise_arsc, rng, args,
                                out_dir, seen)
    finally:
        if use_alarm:
            signal.signal(signal.SIGALRM, old_handler)
    print(f"done: seed={args.seed} "
          f"iterations_per_format={args.iterations} "
          f"distinct_failures={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
