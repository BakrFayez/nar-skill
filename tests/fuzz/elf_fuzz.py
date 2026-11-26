#!/usr/bin/env python3
"""Deterministic mutation fuzz harness for narlib.elf.

Stdlib only. Given a seed and an iteration count, the harness
generates mutated ELF inputs from synthetic seeds built at
runtime (no fixture bytes are committed), runs each mutant
through the parser entry points, and records every *distinct*
failure that violates the parser invariant:

    any malformed input raises ElfError (the named error),
    never IndexError / struct.error / ValueError /
    RecursionError leaks, never a hang, never an unbounded
    allocation driven by an attacker count.

The mutators are structure-aware: they aim at the ELF header
fields (class / data / version, type / machine, program- and
section-header offsets, entry sizes and counts, the section
name string-table index), at program/section header entry
fields, at string-table indices carried by dynamic entries
and symbol records, and at whole-file truncations and seeded
byte flips (finding D-06: the pre-harness coverage was four
hand-picked header shapes).

A failure is distinct by (exception type, exception message
shape, top traceback frame). Each distinct failure is
preserved under ``--out`` as the mutated bytes plus a
``*.repro.json`` describing seed/iteration/mutation and the
exact repro command.

Usage:
    python3 tests/fuzz/elf_fuzz.py --seed 1 --iterations 2000 \
        --out /tmp/elf-fuzz-out

Exit status is 0 when no distinct failure was found, 1 when
at least one was (the artifacts carry the details).

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

from narlib.elf import Elf, ElfError  # noqa: E402
from narlib.elf import SHT_DYNSYM, SHT_SYMTAB  # noqa: E402


def _load_unit(name):
    spec = importlib.util.spec_from_file_location(
        "_fuzz_" + name, os.path.join(UNIT, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _build_elf32():
    """Minimal ELF32 LE ARM: one PT_LOAD + one PT_DYNAMIC
    with SONAME / NEEDED, mirroring the ELF64 seed's shape."""
    dynstr = b"\x00libfoo.so\x00libbar.so\x00"
    ehdr_size, phdr_size = 52, 32
    phoff = ehdr_size
    dyn_off = phoff + 2 * phdr_size
    dynstr_off = dyn_off + 5 * 8
    file_size = dynstr_off + len(dynstr)
    base = 0x10000

    out = bytearray(file_size)
    out[0:4] = b"\x7fELF"
    out[4] = 1      # ELFCLASS32
    out[5] = 1      # little endian
    struct.pack_into("<H", out, 16, 3)      # ET_DYN
    struct.pack_into("<H", out, 18, 40)     # ARM
    struct.pack_into("<I", out, 28, phoff)
    struct.pack_into("<H", out, 40, ehdr_size)
    struct.pack_into("<H", out, 42, phdr_size)
    struct.pack_into("<H", out, 44, 2)      # phnum
    struct.pack_into("<IIIIIHHH", out, phoff, 1, 0, base, base,
                     file_size, file_size, 0x1000, 5)
    struct.pack_into("<IIIIIHHH", out, phoff + phdr_size, 2,
                     dyn_off, base + dyn_off, base + dyn_off,
                     5 * 8, 5 * 8, 4, 4)
    entries = [(14, 1), (1, 11), (5, base + dynstr_off),
               (10, len(dynstr)), (0, 0)]
    for i, (tag, val) in enumerate(entries):
        struct.pack_into("<iI", out, dyn_off + i * 8, tag, val)
    out[dynstr_off:dynstr_off + len(dynstr)] = dynstr
    return bytes(out)


def _build_elf64_rich():
    """ELF64 LE AArch64 with a full section table: .dynstr,
    .dynsym (one undefined import, one defined export),
    .strtab, .symtab, .dynamic, .rela.dyn (one entry),
    .comment and .note.gnu.build-id -- so the sweep exercises
    the section, symbol, relocation and facts paths, not
    just the header / program-header paths."""
    dynstr = b"\x00libfoo.so\x00libbar.so\x00Java_com_example_Native_run\x00"
    strtab = b"\x00local_sym\x00"
    shstr = (b"\x00.dynstr\x00.dynsym\x00.strtab\x00.symtab\x00"
             b".dynamic\x00.rela.dyn\x00.comment\x00"
             b".note.gnu.build-id\x00.shstrtab\x00")
    comment = b"clang version 17.0.0\x00"
    build_id = bytes(range(20))
    note = struct.pack("<III", 4, len(build_id), 3) \
        + b"GNU\x00" + build_id

    ehdr_size, phdr_size, shdr_size = 64, 56, 64
    phoff = ehdr_size
    off = phoff + 2 * phdr_size

    def place(blob):
        nonlocal off
        start = off
        off += len(blob)
        return start

    dynstr_off = place(dynstr)
    # .dynsym: null, undefined import (libbar func), export.
    dynsym = b"\x00" * 24
    dynsym += struct.pack("<IBBHQQ", 11, 0x12, 0, 0, 0, 0)
    dynsym += struct.pack("<IBBHQQ", 21, 0x12, 0, 1, 0x1000, 16)
    dynsym_off = place(dynsym)
    strtab_off = place(strtab)
    symtab = b"\x00" * 24
    symtab += struct.pack("<IBBHQQ", 1, 0x10, 0, 1, 0x2000, 8)
    symtab_off = place(symtab)
    dyn_entries = [(14, 1), (1, 11), (5, 0x10000 + dynstr_off),
                   (10, len(dynstr)), (0, 0)]
    dynamic = b"".join(struct.pack("<qQ", t, v)
                        for t, v in dyn_entries)
    dynamic_off = place(dynamic)
    rela = struct.pack("<QQq", 0x10000 + dynstr_off,
                       (1 << 32) | 1027, 0)
    rela_off = place(rela)
    comment_off = place(comment)
    note_off = place(note)
    shstr_off = place(shstr)
    shoff = off

    def name_off(name):
        return shstr.index(name.encode())

    # type, link: dynsym->dynstr(1), symtab->strtab(3),
    # rela->dynsym(2); entsizes per fixed entry structs.
    sections = [
        # name, type, off, size, link, entsize
        (None, 0, 0, 0, 0, 0),
        (".dynstr", 3, dynstr_off, len(dynstr), 0, 0),
        (".dynsym", 11, dynsym_off, len(dynsym), 1, 24),
        (".strtab", 3, strtab_off, len(strtab), 0, 0),
        (".symtab", 2, symtab_off, len(symtab), 3, 24),
        (".dynamic", 6, dynamic_off, len(dynamic), 1, 16),
        (".rela.dyn", 4, rela_off, len(rela), 2, 24),
        (".comment", 1, comment_off, len(comment), 0, 0),
        (".note.gnu.build-id", 7, note_off, len(note), 0, 0),
        (".shstrtab", 3, shstr_off, len(shstr), 0, 0),
    ]
    file_size = shoff + len(sections) * shdr_size
    base = 0x10000
    out = bytearray(file_size)
    out[0:4] = b"\x7fELF"
    out[4] = 2
    out[5] = 1
    struct.pack_into("<H", out, 16, 3)
    struct.pack_into("<H", out, 18, 183)
    struct.pack_into("<Q", out, 32, phoff)
    struct.pack_into("<Q", out, 40, shoff)
    struct.pack_into("<H", out, 52, ehdr_size)
    struct.pack_into("<H", out, 54, phdr_size)
    struct.pack_into("<H", out, 56, 2)
    struct.pack_into("<H", out, 58, shdr_size)
    struct.pack_into("<H", out, 60, len(sections))
    struct.pack_into("<H", out, 62, len(sections) - 1)
    struct.pack_into("<IIQQQQQQ", out, phoff, 1, 5, 0, base, base,
                     file_size, file_size, 0x1000)
    struct.pack_into("<IIQQQQQQ", out, phoff + phdr_size, 2, 4,
                     dynamic_off, base + dynamic_off,
                     base + dynamic_off, len(dynamic),
                     len(dynamic), 8)
    for blob, blob_off in ((dynstr, dynstr_off),
                           (dynsym, dynsym_off),
                           (strtab, strtab_off),
                           (symtab, symtab_off),
                           (dynamic, dynamic_off),
                           (rela, rela_off),
                           (comment, comment_off),
                           (note, note_off), (shstr, shstr_off)):
        out[blob_off:blob_off + len(blob)] = blob
    for i, (name, stype, soff, ssize, link, entsize) in \
            enumerate(sections):
        struct.pack_into(
            "<IIQQQQIIQQ", out, shoff + i * shdr_size,
            name_off(name) if name else 0, stype, 0, base + soff,
            soff, ssize, link, 0, 1, entsize)
    return bytes(out)


def seed_corpus():
    """Synthetic seeds, generated at runtime (no fixture
    bytes are committed for fuzzing)."""
    seeds = []
    dex_elf = _load_unit("test_dex_elf")
    seeds.append(("synthetic-elf64-phdr", dex_elf.build_elf64()))
    seeds.append(("synthetic-elf32-phdr", _build_elf32()))
    seeds.append(("synthetic-elf64-rich", _build_elf64_rich()))
    seed_dir = os.environ.get("NAR_ELF_FUZZ_SEEDS")
    if seed_dir and os.path.isdir(seed_dir):
        for name in sorted(os.listdir(seed_dir)):
            path = os.path.join(seed_dir, name)
            if os.path.isfile(path):
                with open(path, "rb") as fh:
                    seeds.append((f"local:{name}", fh.read()))
    return seeds


_WORD_VALUES = (0, 1, 2, 0x7FFF, 0xFFFF)
_QWORD_VALUES = (0, 1, 8, 0xFFFF, 0x7FFFFFFF,
                 0xFFFFFFFFFFFFFFFF)


def _header_layout(data):
    """(is_64, endian) of a seed, for field targeting."""
    if len(data) < 6 or data[:4] != b"\x7fELF":
        return None
    return data[4] == 2, "<" if data[5] != 2 else ">"


def _blast_word(rng, buf, off, size, values):
    if off + size > len(buf):
        return False
    value = rng.choice(values + (len(buf) + rng.randrange(1, 4096),))
    if size == 2:
        struct.pack_into("<H", buf, off, value & 0xFFFF)
    elif size == 4:
        struct.pack_into("<I", buf, off, value & 0xFFFFFFFF)
    else:
        struct.pack_into("<Q", buf, off, value)
    return True


def mutate(rng, data):
    """One mutated copy of ``data`` plus a strategy label."""
    buf = bytearray(data)
    layout = _header_layout(bytes(buf))
    strategy = rng.choice([
        "header-field", "header-field", "ident-byte",
        "entry-header-field", "strtab-index", "count-blast",
        "truncate", "byte-flip", "random-word",
    ])
    if strategy == "ident-byte":
        # EI_CLASS / EI_DATA / EI_VERSION and the magic's tail:
        # class and data have named-error checks; the rest of
        # e_ident is fair game for flips.
        pos = rng.choice((4, 5, 6, 7, 8, 15))
        if pos < len(buf):
            buf[pos] = rng.choice((0, 1, 2, 3, 0xFF,
                                   rng.randrange(256)))
    elif strategy == "header-field" and layout:
        is_64, _e = layout
        # (offset, size): e_type, e_machine, e_version,
        # e_entry, e_phoff, e_shoff, e_flags, e_ehsize,
        # e_phentsize, e_phnum, e_shentsize, e_shnum,
        # e_shstrndx -- the full header-field sweep.
        if is_64:
            fields = [(16, 2), (18, 2), (20, 4), (24, 8),
                      (32, 8), (40, 8), (48, 4), (52, 2),
                      (54, 2), (56, 2), (58, 2), (60, 2),
                      (62, 2)]
        else:
            fields = [(16, 2), (18, 2), (20, 4), (24, 4),
                      (28, 4), (32, 4), (36, 4), (40, 2),
                      (42, 2), (44, 2), (46, 2), (48, 2),
                      (50, 2)]
        off, size = rng.choice(fields)
        values = _WORD_VALUES if size == 2 else _QWORD_VALUES
        if not _blast_word(rng, buf, off, size, values):
            strategy = "byte-flip"
    elif strategy == "entry-header-field" and layout:
        # Blast one field of one program/section header entry.
        is_64, e = layout
        try:
            if is_64:
                phoff, shoff = struct.unpack_from(e + "QQ", buf, 32)
                phentsize, phnum = struct.unpack_from(
                    e + "HH", buf, 54)
                shentsize, shnum = struct.unpack_from(
                    e + "HH", buf, 58)
            else:
                phoff, shoff = struct.unpack_from(e + "II", buf, 28)
                phentsize, phnum = struct.unpack_from(
                    e + "HH", buf, 42)
                shentsize, shnum = struct.unpack_from(
                    e + "HH", buf, 46)
        except struct.error:
            phoff = shoff = phnum = shnum = 0
            phentsize = shentsize = 0
        tables = []
        if phoff and phnum and phentsize:
            tables.append((phoff, phentsize, phnum))
        if shoff and shnum and shentsize:
            tables.append((shoff, shentsize, shnum))
        if tables:
            base, entsize, count = rng.choice(tables)
            entry = base + rng.randrange(min(count, 16)) * entsize
            off = entry + rng.randrange(0, max(1, entsize - 3))
            if not _blast_word(rng, buf, off, 4, _QWORD_VALUES):
                strategy = "byte-flip"
        else:
            strategy = "byte-flip"
    elif strategy == "strtab-index":
        # String-table indices: dynamic entries' string
        # offsets and symbol name offsets live wherever the
        # seed put them; a random aligned word blast in the
        # file's back half lands on them often enough, and
        # the dedicated shstrndx blast is exact.
        layout_ok = layout is not None
        if layout_ok and rng.random() < 0.5:
            is_64, _e = layout
            off = 62 if is_64 else 50  # e_shstrndx
            _blast_word(rng, buf, off, 2,
                        (0, 1, 0xFFFE, 0xFFFF))
        else:
            start = max(16, len(buf) // 2)
            if len(buf) - start >= 4:
                off = start + 4 * rng.randrange(
                    (len(buf) - start) // 4)
                _blast_word(rng, buf, off, 4, _QWORD_VALUES)
    elif strategy == "count-blast":
        off = rng.randrange(0, max(1, len(buf) - 3))
        struct.pack_into("<I", buf, off,
                         rng.choice([0xFFFFFFFF, 0x7FFFFFFF,
                                     0x10000000, 65535]))
    elif strategy == "truncate":
        if len(buf) > 16:
            del buf[rng.randrange(1, len(buf)):]
    elif strategy == "random-word":
        for _ in range(rng.randint(1, 4)):
            off = rng.randrange(0, max(1, len(buf) - 1))
            if off + 2 <= len(buf):
                struct.pack_into("<H", buf, off,
                                 rng.randrange(0x10000))
    if strategy == "byte-flip":
        for _ in range(rng.randint(1, 8)):
            if buf:
                buf[rng.randrange(len(buf))] = rng.randrange(256)
    return bytes(buf), strategy


class _Timeout(Exception):
    pass


def _alarm(_signum, _frame):
    raise _Timeout()


def exercise(data):
    """Run one input through the parser entry points.

    Returns None on clean handling (parsed, or ElfError), or
    a (kind, detail) failure tuple."""
    try:
        elf = Elf(data, name="fuzz.so")
    except ElfError:
        return None
    try:
        elf.program_headers()
        elf.sections()
        elf.dynamic_entries()
        elf.symbols(SHT_DYNSYM)
        elf.symbols(SHT_SYMTAB)
        elf.relocations()
        elf.relocation_summary()
        elf.comment_strings()
        elf.compiler_fingerprints()
        elf.facts()
    except ElfError:
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
                artifact = os.path.join(out_dir, f"crash-{key}.elf")
                with open(artifact, "wb") as fh:
                    fh.write(mutant)
                repro = dict(seen[key])
                repro.update({
                    "artifact": os.path.basename(artifact),
                    "sha256": hashlib.sha256(mutant).hexdigest(),
                    "repro": (f"python3 tests/fuzz/elf_fuzz.py "
                              f"--seed {args.seed} "
                              f"--iterations {i + 1} --out DIR "
                              f"# or feed {os.path.basename(artifact)} "
                              "to narlib.elf.Elf directly"),
                })
                with open(os.path.join(
                        out_dir, f"crash-{key}.repro.json"),
                        "w", encoding="utf-8") as fh:
                    json.dump(repro, fh, indent=1, sort_keys=True)
    finally:
        if use_alarm:
            signal.signal(signal.SIGALRM, old_handler)
    print(f"done: seed={args.seed} iterations={args.iterations} "
          f"distinct_failures={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
