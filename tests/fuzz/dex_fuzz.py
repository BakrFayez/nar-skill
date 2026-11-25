#!/usr/bin/env python3
"""Deterministic mutation fuzz harness for narlib.dex / dexdis.

Stdlib only. Given a seed and an iteration count, the harness
generates mutated DEX inputs from the repo's synthetic DEX
builders (plus an optional local seed directory -- see
README.md), runs each mutant through the parser entry points,
and records every *distinct* failure that violates the parser
invariant:

    any malformed input raises DexError (the named error),
    never IndexError / struct.error / ValueError /
    RecursionError leaks, never a hang, never an unbounded
    allocation driven by an attacker count.

A failure is distinct by (exception type, exception message
shape, top traceback frame). Each distinct failure is preserved
under ``--out`` as the mutated bytes plus a ``*.repro.json``
describing seed/iteration/mutation and the exact repro command.

Usage:
    python3 tests/fuzz/dex_fuzz.py --seed 1 --iterations 2000 \
        --out /tmp/dex-fuzz-out

Exit status is 0 when no distinct failure was found, 1 when at
least one was (the artifacts carry the details).

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
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

from narlib.dex import Dex, DexError  # noqa: E402
from narlib import dexdis  # noqa: E402


def _load_unit(name):
    spec = importlib.util.spec_from_file_location(
        "_fuzz_" + name, os.path.join(UNIT, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _derived_seed_with_code_and_annotations(base, class_defs_off):
    """Derive a richer seed from the with-class builder output:
    append a code item (const-string / return-void) and an
    annotation directory holding one class annotation whose
    single element is an encoded array, then point the class
    def at both. Still fully synthetic, built at runtime."""
    data = bytearray(base)
    code_off = len(data)
    # code_item: regs=1 ins=0 outs=0 tries=0 debug=0 insns=3
    # insns: const-string v0, str0 (0x1a 0x00 0x0000); return-void
    data += struct.pack("<HHHHII", 1, 0, 0, 0, 0, 3)
    data += struct.pack("<HHH", 0x001A, 0x0000, 0x000E)
    ann_dir_off = len(data)
    class_set_off = ann_dir_off + 16
    item_off = class_set_off + 8
    # annotation_item: visibility=1, encoded_annotation:
    # type_idx=0, size=1, element(name_idx=1, value=array[str])
    encoded = _uleb(0) + _uleb(1) + _uleb(1) + \
        bytes([0x1C]) + _uleb(1) + bytes([0x17, 0x00])
    data += struct.pack("<IIII", class_set_off, 0, 0, 0)
    data += struct.pack("<II", 1, item_off)
    data += bytes([1]) + encoded
    class_data_off = len(data)
    # class_data: 0 static, 0 instance, 1 direct, 0 virtual;
    # method 0: delta 0, flags 1, code_off.
    data += _uleb(0) + _uleb(0) + _uleb(1) + _uleb(0)
    data += _uleb(0) + _uleb(1) + _uleb(code_off)
    struct.pack_into("<I", data, class_defs_off + 20, ann_dir_off)
    struct.pack_into("<I", data, class_defs_off + 24,
                     class_data_off)
    struct.pack_into("<I", data, 32, len(data))  # file_size
    return bytes(data)


def seed_corpus():
    """Synthetic seeds from the repo's own builders, generated
    at runtime (no fixture bytes are committed for fuzzing)."""
    seeds = []
    dex_elf = _load_unit("test_dex_elf")
    seeds.append(("synthetic-minimal", dex_elf.build_dex()))
    remed = _load_unit("test_deep_audit_remediation")
    built = remed.build_dex_with_class()
    seeds.append(("synthetic-with-class", built[0]))
    seeds.append(("synthetic-code-annotations",
                  _derived_seed_with_code_and_annotations(
                      built[0], built[1])))
    seed_dir = os.environ.get("NAR_DEX_FUZZ_SEEDS")
    if seed_dir and os.path.isdir(seed_dir):
        for name in sorted(os.listdir(seed_dir)):
            path = os.path.join(seed_dir, name)
            if os.path.isfile(path):
                with open(path, "rb") as fh:
                    seeds.append((f"local:{name}", fh.read()))
    return seeds


# Header table fields (size, off) pairs live at 0x38..0x68;
# class_defs fields and class_data live past the header. The
# targeted mutators aim at those regions; the generic ones go
# anywhere.
_HEADER_FIELDS = list(range(0x38, 0x70, 4))


def mutate(rng, data):
    """One mutated copy of ``data`` plus a strategy label."""
    buf = bytearray(data)
    strategy = rng.choice([
        "byte-flip", "byte-flip", "header-field", "count-blast",
        "leb-run", "truncate", "random-word", "class-data",
    ])
    if strategy == "byte-flip":
        for _ in range(rng.randint(1, 8)):
            if buf:
                buf[rng.randrange(len(buf))] = rng.randrange(256)
    elif strategy == "header-field":
        off = rng.choice(_HEADER_FIELDS)
        if off + 4 <= len(buf):
            struct.pack_into("<I", buf, off, rng.choice([
                0, 1, 0x7FFFFFFF, 0xFFFFFFFF,
                rng.randrange(0, 0x10000), len(buf) + rng.randrange(1, 4096)]))
    elif strategy == "count-blast":
        off = rng.randrange(0, max(1, len(buf) - 3))
        struct.pack_into("<I", buf, off,
                         rng.choice([0xFFFFFFFF, 0x7FFFFFFF,
                                     0x10000000, 65535]))
    elif strategy == "leb-run":
        # Splice an overlong / unterminated LEB128 run in.
        pos = rng.randrange(len(buf) + 1)
        run = bytes([0x80] * rng.randint(1, 12)) + \
            bytes([rng.choice([0x00, 0x7F, 0x80])])
        buf[pos:pos] = run
    elif strategy == "truncate":
        if len(buf) > 16:
            del buf[rng.randrange(1, len(buf)):]
    elif strategy == "random-word":
        for _ in range(rng.randint(1, 4)):
            off = rng.randrange(0, max(1, len(buf) - 1))
            if off + 2 <= len(buf):
                struct.pack_into("<H", buf, off,
                                 rng.randrange(0x10000))
    elif strategy == "class-data":
        # Aim at the tail (class defs / class data in the
        # synthetic layouts): corrupt ULEB-ish bytes there.
        start = max(0x70, len(buf) - 96)
        for _ in range(rng.randint(1, 10)):
            pos = rng.randrange(start, len(buf)) if len(buf) > start \
                else rng.randrange(len(buf))
            buf[pos] = rng.choice([0x80, 0xFF, 0x7F, 0x00,
                                   rng.randrange(256)])
    return bytes(buf), strategy


class _Timeout(Exception):
    pass


def _alarm(_signum, _frame):
    raise _Timeout()


def exercise(data):
    """Run one input through the parser entry points.

    Returns None on clean handling (parsed, or DexError), or a
    (kind, detail) failure tuple."""
    try:
        dex = Dex(data, name="fuzz.dex")
    except DexError:
        return None
    try:
        dex.strings()
        dex.types()
        defs = dex.class_defs()
        for idx in range(min(dex.proto_ids_size, 64)):
            dex.proto_info(idx)
        for idx in range(min(dex.method_ids_size, 64)):
            dex.method_full(idx)
            dex.method_ref(idx)
        for idx in range(min(dex.field_ids_size, 64)):
            dex.field_ref(idx)
        for cdef in defs[:64]:
            list(dex.class_fields(cdef["class_data_off"]))
            list(dex.class_methods(cdef["class_data_off"]))
            list(dex.class_methods_indexed(cdef["class_data_off"]))
            dex.class_annotations(cdef)
            for _m, _f, code_off, _k in dex.class_methods(
                    cdef["class_data_off"]):
                dex.code_item_info(code_off)
                dex.scan_code(code_off)
        from narlib.dex import (assemble_call_graph,
                                identifier_shape_stats)
        identifier_shape_stats(dex)
        assemble_call_graph([("fuzz.dex", dex)])
        dexdis.disassemble(dex, want_all=True, limit=16)
        dexdis.cfg_batch(dex, want_all=True, limit=16)
    except DexError:
        return None
    except _Timeout:
        raise
    except RecursionError as e:
        return ("RecursionError", str(e)[:200])
    except Exception as e:  # noqa: BLE001 - the invariant probe
        return (type(e).__name__,
                f"{e} @ {traceback.extract_tb(sys.exc_info()[2])[-1].name if sys.exc_info()[2] else '?'}")
    return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--out", default=None,
                        help="directory for crash artifacts")
    parser.add_argument("--timeout", type=float, default=2.0,
                        help="per-case timeout in seconds")
    args = parser.parse_args(argv)

    seeds = seed_corpus()
    if not seeds:
        print("no seeds available", file=sys.stderr)
        return 2
    rng = random.Random(args.seed)
    out_dir = args.out
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    seen = {}
    failures = 0
    old_handler = signal.signal(signal.SIGALRM, _alarm)
    try:
        for i in range(args.iterations):
            seed_name, seed_bytes = seeds[rng.randrange(len(seeds))]
            mutant, strategy = mutate(rng, seed_bytes)
            signal.setitimer(signal.ITIMER_REAL, args.timeout)
            try:
                failure = exercise(mutant)
            except _Timeout:
                failure = ("Timeout",
                           f"exceeded {args.timeout}s per-case budget")
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
            if failure is None:
                continue
            kind, detail = failure
            key = hashlib.sha256(
                f"{kind}|{detail}".encode()).hexdigest()[:12]
            if key in seen:
                continue
            seen[key] = {"kind": kind, "detail": detail,
                         "seed": args.seed, "iteration": i,
                         "base_seed": seed_name,
                         "strategy": strategy}
            failures += 1
            print(f"DISTINCT FAILURE {key}: {kind}: {detail} "
                  f"(seed={args.seed} iter={i} base={seed_name} "
                  f"strategy={strategy})")
            if out_dir:
                artifact = os.path.join(out_dir, f"crash-{key}.dex")
                with open(artifact, "wb") as fh:
                    fh.write(mutant)
                repro = dict(seen[key])
                repro.update({
                    "artifact": os.path.basename(artifact),
                    "sha256": hashlib.sha256(mutant).hexdigest(),
                    "repro": (f"python3 tests/fuzz/dex_fuzz.py "
                              f"--seed {args.seed} "
                              f"--iterations {i + 1} --out DIR "
                              f"# or feed {os.path.basename(artifact)} "
                              "to narlib.dex.Dex directly"),
                })
                with open(os.path.join(
                        out_dir, f"crash-{key}.repro.json"),
                        "w", encoding="utf-8") as fh:
                    json.dump(repro, fh, indent=1, sort_keys=True)
    finally:
        signal.signal(signal.SIGALRM, old_handler)
    print(f"done: seed={args.seed} iterations={args.iterations} "
          f"distinct_failures={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
