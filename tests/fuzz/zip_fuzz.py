#!/usr/bin/env python3
"""Deterministic mutation fuzz harness for the ZIP container
layer (narlib.safearchive, plus narlib.safearchive's capped
member reader).

Stdlib only. Given a seed and an iteration count, the harness
generates mutated ZIP inputs from small synthetic archives
built at runtime (no fixture bytes are committed), runs each
mutant through the safe-extraction / read layer, and records
every *distinct* failure that violates the layer invariant:

    any malformed archive is refused BY NAME -- the archive
    cannot be opened (zipfile.BadZipFile), a budget refuses
    it (narlib.budget.BudgetError / ValueError from the
    capped reader), an entry is rejected in the extraction
    report, or the archive processes cleanly -- never an
    unhandled exception class escaping the layer, never a
    hang, never an unbounded allocation driven by a declared
    size.

The mutators aim at the ZIP structure the hand-crafted unit
cases cannot cover systematically: central-directory fields,
local-header fields, extra fields, data-descriptor flags,
declared-size lies, end-of-central-directory fields, and
truncated streams.

A failure is distinct by (exception type, exception message
shape, top traceback frame). Each distinct failure is
preserved under ``--out`` as the mutated bytes plus a
``*.repro.json`` describing seed/iteration/mutation and the
exact repro command.

Usage:
    python3 tests/fuzz/zip_fuzz.py --seed 1 --iterations 300 \
        --out /tmp/zip-fuzz-out

Exit status is 0 when no distinct failure was found, 1 when
at least one was (the artifacts carry the details).

Part of NAR (Nirous Android Reversing).
"""
import argparse
import hashlib
import io
import json
import os
import random
import shutil
import signal
import struct
import sys
import tempfile
import traceback
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
SCRIPTS = os.path.join(ROOT, "scripts")
sys.path.insert(0, SCRIPTS)

from narlib import safearchive  # noqa: E402
from narlib.budget import BudgetError  # noqa: E402

#: Exceptions that count as "refused by name": the archive
#: could not be opened as a ZIP at all, a budget/cap refused
#: it, or a platform-level read failure surfaced while the
#: layer was opening it. Per-entry corruption never reaches
#: here -- safe_extract records it in the report instead.
NAMED_ERRORS = (zipfile.BadZipFile, BudgetError, ValueError,
                RuntimeError, EOFError, OSError)

#: Tight limits for fuzz runs: mutants that declare huge
#: sizes must be refused by the budget, not by the host's
#: memory.
FUZZ_LIMITS = {"max_file_bytes": 65536,
               "max_total_bytes": 262144}
MEMBER_CAP = 65536


def _zip_bytes(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for info, data in entries:
            zf.writestr(info, data)
    return buf.getvalue()


def _info(name, compress_type, extra=b""):
    info = zipfile.ZipInfo(name)
    info.compress_type = compress_type
    info.external_attr = 0o644 << 16
    info.extra = extra
    return info


def seed_corpus():
    """Synthetic seeds, generated at runtime (no fixture
    bytes are committed for fuzzing)."""
    seeds = []
    # Mixed stored/deflated members plus a directory entry.
    seeds.append(("synthetic-mixed", _zip_bytes([
        (_info("dir/", zipfile.ZIP_STORED), b""),
        (_info("a/b.txt", zipfile.ZIP_DEFLATED),
         b"hello world" * 8),
        (_info("data.bin", zipfile.ZIP_STORED),
         bytes(range(256)) * 2),
        (_info("nested/inner.txt", zipfile.ZIP_DEFLATED),
         b"z" * 500),
    ])))
    # One deflated member carrying a ZIP64 extra field.
    zip64_extra = struct.pack("<HHQQ", 0x0001, 16, 4096, 4096)
    seeds.append(("synthetic-zip64-extra", _zip_bytes([
        (_info("big.txt", zipfile.ZIP_DEFLATED, zip64_extra),
         b"A" * 4096),
        (_info("small.txt", zipfile.ZIP_STORED), b"y"),
    ])))
    # Stored-only archive (declared sizes are the stream).
    seeds.append(("synthetic-stored", _zip_bytes([
        (_info("one.bin", zipfile.ZIP_STORED), b"\x00" * 128),
        (_info("two.bin", zipfile.ZIP_STORED), b"\xff" * 64),
    ])))
    seed_dir = os.environ.get("NAR_ZIP_FUZZ_SEEDS")
    if seed_dir and os.path.isdir(seed_dir):
        for name in sorted(os.listdir(seed_dir)):
            path = os.path.join(seed_dir, name)
            if os.path.isfile(path):
                with open(path, "rb") as fh:
                    seeds.append((f"local:{name}", fh.read()))
    return seeds


def _find_all(data, sig):
    out = []
    idx = data.find(sig)
    while idx >= 0:
        out.append(idx)
        idx = data.find(sig, idx + 1)
    return out


# Central-directory field offsets (from the PK\x01\x02
# signature) worth blasting: version fields, flags, method,
# crc, sizes, name/extra/comment lengths, header offset.
_CEN_FIELDS = (6, 8, 10, 12, 14, 16, 20, 24, 28, 30, 32, 42)
# Local-header field offsets (from PK\x03\x04): version,
# flags, method, crc, sizes, name/extra lengths.
_LOC_FIELDS = (6, 8, 10, 14, 18, 22, 26, 28)
_WORD_VALUES = (0, 1, 0x8000, 0xFFFF)
_DWORD_VALUES = (0, 1, 8, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF)


def mutate(rng, data):
    """One mutated copy of ``data`` plus a strategy label."""
    buf = bytearray(data)
    cens = _find_all(bytes(buf), b"PK\x01\x02")
    locs = _find_all(bytes(buf), b"PK\x03\x04")
    eocd = bytes(buf).rfind(b"PK\x05\x06")
    strategy = rng.choice([
        "cen-field", "cen-field", "local-field", "extra-field",
        "descriptor-flag", "size-lie", "truncate", "eocd-field",
        "byte-flip",
    ])
    if strategy == "cen-field" and cens:
        off = rng.choice(cens) + rng.choice(_CEN_FIELDS)
        if off + 4 <= len(buf):
            struct.pack_into("<I", buf, off,
                             rng.choice(_DWORD_VALUES +
                                        (len(buf) + 4096,)))
    elif strategy == "local-field" and locs:
        off = rng.choice(locs) + rng.choice(_LOC_FIELDS)
        if off + 2 <= len(buf):
            struct.pack_into("<H", buf, off,
                             rng.choice(_WORD_VALUES))
    elif strategy == "extra-field" and locs:
        # Splice junk into one local header's extra field and
        # grow its declared extra length to match.
        base = rng.choice(locs)
        name_len, extra_len = struct.unpack_from("<HH", buf,
                                                 base + 26)
        pos = base + 30 + name_len
        run = bytes(rng.randrange(256)
                    for _ in range(rng.randint(1, 12)))
        buf[pos:pos] = run
        struct.pack_into("<H", buf, base + 28,
                         extra_len + len(run))
    elif strategy == "descriptor-flag" and locs:
        # Toggle the data-descriptor bit (0x0008) in a local
        # header's flags: readers must then hunt for a
        # descriptor that is not really there (or ignore one
        # that is).
        base = rng.choice(locs)
        flags = struct.unpack_from("<H", buf, base + 6)[0]
        struct.pack_into("<H", buf, base + 6, flags ^ 0x0008)
    elif strategy == "size-lie" and cens:
        # Declared-size lies in the central directory:
        # compressed size (+20) or uncompressed size (+24)
        # understated / overstated against the real stream.
        base = rng.choice(cens)
        off = base + rng.choice((20, 24))
        struct.pack_into("<I", buf, off,
                         rng.choice(_DWORD_VALUES))
    elif strategy == "truncate":
        if len(buf) > 16:
            del buf[rng.randrange(1, len(buf)):]
    elif strategy == "eocd-field" and eocd >= 0:
        off = eocd + rng.choice((4, 6, 8, 10, 12, 16, 20))
        if off + 2 <= len(buf):
            struct.pack_into("<H", buf, off,
                             rng.choice(_WORD_VALUES))
    else:  # byte-flip fallback (also when a target is absent)
        strategy = "byte-flip"
        for _ in range(rng.randint(1, 8)):
            if buf:
                buf[rng.randrange(len(buf))] = rng.randrange(256)
    return bytes(buf), strategy


class _Timeout(Exception):
    pass


def _alarm(_signum, _frame):
    raise _Timeout()


_WORKDIR = None


def exercise(data):
    """Run one input through the safe-extraction/read layer.

    Returns None on clean handling (extracted/rejected via
    the report, or refused with a named error), or a
    (kind, detail) failure tuple."""
    src = os.path.join(_WORKDIR, "fuzz.zip")
    with open(src, "wb") as fh:
        fh.write(data)
    out = os.path.join(_WORKDIR, "out")
    shutil.rmtree(out, ignore_errors=True)
    try:
        safearchive.safe_extract(src, out, limits=FUZZ_LIMITS)
        with zipfile.ZipFile(src) as zf:
            for name in zf.namelist():
                try:
                    safearchive.read_member_capped(
                        zf, name, cap_bytes=MEMBER_CAP)
                except NAMED_ERRORS:
                    pass
    except NAMED_ERRORS:
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
    parser.add_argument("--iterations", type=int, default=300)
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
    global _WORKDIR
    _WORKDIR = tempfile.mkdtemp(prefix="nar-zip-fuzz-")
    # SIGALRM is POSIX-only; on Windows the per-case timeout
    # cannot be enforced this way, so the harness runs
    # without it there (bounded iterations still apply).
    use_alarm = hasattr(signal, "SIGALRM")
    old_handler = (signal.signal(signal.SIGALRM, _alarm)
                   if use_alarm else None)
    try:
        for i in range(args.iterations):
            seed_name, seed_bytes = seeds[rng.randrange(len(seeds))]
            mutant, strategy = mutate(rng, seed_bytes)
            if use_alarm:
                signal.setitimer(signal.ITIMER_REAL, args.timeout)
            try:
                failure = exercise(mutant)
            except _Timeout:
                failure = ("Timeout",
                           f"exceeded {args.timeout}s per-case budget")
            finally:
                if use_alarm:
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
                artifact = os.path.join(out_dir, f"crash-{key}.zip")
                with open(artifact, "wb") as fh:
                    fh.write(mutant)
                repro = dict(seen[key])
                repro.update({
                    "artifact": os.path.basename(artifact),
                    "sha256": hashlib.sha256(mutant).hexdigest(),
                    "repro": (f"python3 tests/fuzz/zip_fuzz.py "
                              f"--seed {args.seed} "
                              f"--iterations {i + 1} --out DIR "
                              f"# or feed {os.path.basename(artifact)} "
                              "to narlib.safearchive.safe_extract "
                              "directly"),
                })
                with open(os.path.join(
                        out_dir, f"crash-{key}.repro.json"),
                        "w", encoding="utf-8") as fh:
                    json.dump(repro, fh, indent=1, sort_keys=True)
    finally:
        if use_alarm:
            signal.signal(signal.SIGALRM, old_handler)
        shutil.rmtree(_WORKDIR, ignore_errors=True)
        _WORKDIR = None
    print(f"done: seed={args.seed} iterations={args.iterations} "
          f"distinct_failures={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
