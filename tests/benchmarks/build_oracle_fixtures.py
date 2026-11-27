#!/usr/bin/env python3
"""build_oracle_fixtures.py: generate the synthetic oracle
fixtures committed under tests/benchmarks/fixtures/.

The fixtures are INPUTS only. No expected value is stored
anywhere: every expectation is computed at run time by an
independent oracle (the SDK dexdump binary for the DEX
fixtures; the struct-based ELF reader inside
oracle_inventory.py, optionally cross-checked with readelf,
for the inventory fixture). See tests/benchmarks/README.md
for the provenance note.

DEX inputs are built with the repo's own synthetic DEX
builder (DexBuilder in tests/unit/test_dexdis.py, loaded by
file path the same way tests/synthetic_fixtures.py loads its
builders). The ELF inputs are built with the minimal ELF64
builder below, modelled on the one in
tests/unit/test_engines_jni_symbols.py and extended with a
.dynamic section (DT_NEEDED / DT_SONAME) and program headers
so readelf can read the dynamic table too.

Everything here is synthetic: class, method, library and
symbol names are invented for these fixtures. No real target
data is read or embedded.

Usage:
    python3 tests/benchmarks/build_oracle_fixtures.py
        [--out DIR]   (default: tests/benchmarks/fixtures)

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import importlib.util
import io
import struct
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]
FIXTURES = HERE.parent / "fixtures"

JNI_LIB = "lib/arm64-v8a/liboracle_jni.so"
PLAIN_LIB = "lib/arm64-v8a/liboracle_plain.so"
NOTE_MEMBER = "assets/oracle_note.txt"

# Synthetic JNI surface planted in the JNI library: three
# exports under one engine family's public JNI prefix (the
# family nar-engines exercises on this fixture), plus the
# generic bridge entry point and a plain helper.
JNI_EXPORTS = [
    "Java_org_cocos2dx_lib_SyntheticBridge_nativeInit",
    "Java_org_cocos2dx_lib_SyntheticBridge_nativeRender",
    "Java_org_cocos2dx_lib_SyntheticBridge_nativeSetPath",
    "JNI_OnLoad",
    "oracle_bridge_helper",
]
PLAIN_EXPORTS = [
    "oracle_core_init",
    "oracle_core_step",
    "oracle_core_shutdown",
]


def _load_dex_builder():
    """DexBuilder + U from tests/unit/test_dexdis.py."""
    spec = importlib.util.spec_from_file_location(
        "_oracle_dexdis_builder", ROOT / "tests" / "unit"
        / "test_dexdis.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_basic_dex(mod):
    """One class, two small methods, one field-table entry."""
    U = mod.U
    b = mod.DexBuilder("039")
    foo = b.t("LFoo;")
    obj = b.t("Ljava/lang/Object;")
    void = b.t("V")
    integer = b.t("I")
    proto = b.proto("V", void)
    b.field(foo, integer, "count")
    alpha = b.method(foo, proto, "alpha")
    beta = b.method(foo, proto, "beta")
    b.classes.append({
        "class": foo, "super": obj,
        "direct": [
            (alpha, [U(0x12, 0x10), U(0x0E)]),
            (beta, [U(0x13, 2), 0xFFFE, U(0x0E)]),
        ]})
    return b.build()


def build_branches_dex(mod):
    """One class whose method carries branches and all three
    payload pseudo-instructions (packed-switch, sparse-switch,
    fill-array-data), plus a trivial second method."""
    U = mod.U
    b = mod.DexBuilder("039")
    bar = b.t("LBar;")
    obj = b.t("Ljava/lang/Object;")
    void = b.t("V")
    proto = b.proto("V", void)
    branchy = b.method(bar, proto, "branchy")
    plain = b.method(bar, proto, "plain")
    units = [
        U(0x28, 0x02),                       # goto +2
        U(0x00),                             # nop
        U(0x29, 0), 2,                       # goto/16 +2
        U(0x2A, 0), 3, 0,                    # goto/32 +3
        U(0x38, 1), 2,                       # if-eqz -> +2
        U(0x32, 0x10), 0xFFFE,               # if-eq -> -2
        U(0x2B, 1), 10, 0,                   # packed-switch
        U(0x2C, 2), 15, 0,                   # sparse-switch
        U(0x26, 3), 18, 0,                   # fill-array-data
        U(0x0E),                             # return-void
        U(0x0100), 2, 10, 0,                 # packed payload
        0xFFFE, 0xFFFF, 9, 0,
        U(0x0200), 1, 7, 0,                  # sparse payload
        0xFFF9, 0xFFFF,
        U(0x0300), 2, 3, 0,                  # fill payload
        0x0102, 0x0304, 0x0005,
    ]
    b.classes.append({
        "class": bar, "super": obj,
        "virtual": [(branchy, units)],
        "direct": [(plain, [U(0x0E)])]})
    return b.build()


def build_multi_dex(mod):
    """Two classes; direct and virtual methods; one method
    with no code item (abstract/native shape)."""
    U = mod.U
    b = mod.DexBuilder("039")
    foo = b.t("LFoo;")
    bar = b.t("LBar;")
    obj = b.t("Ljava/lang/Object;")
    void = b.t("V")
    integer = b.t("I")
    proto_v = b.proto("V", void)
    proto_iv = b.proto("IV", void, (integer,))
    b.field(foo, integer, "total")
    with_code = b.method(foo, proto_v, "withCode")
    no_code = b.method(foo, proto_v, "noCode")
    takes_int = b.method(bar, proto_iv, "takesInt")
    b.classes.append({
        "class": foo, "super": obj,
        "direct": [(with_code, [U(0x0E)]), (no_code, None)]})
    b.classes.append({
        "class": bar, "super": obj,
        "virtual": [(takes_int, [U(0x12, 0x10), U(0x0E)])]})
    return b.build()


def build_elf64(exports, needed=(), soname=None):
    """Minimal ELF64 (LE, ET_DYN, AArch64) with .dynsym,
    .dynstr, .dynamic and .shstrtab sections and PT_LOAD /
    PT_DYNAMIC program headers. Identity-mapped (vaddr ==
    file offset) so DT_STRTAB / DT_SYMTAB are plain offsets.
    """
    dynstr = bytearray(b"\x00")
    offsets = {}

    def intern(text):
        if text not in offsets:
            offsets[text] = len(dynstr)
            dynstr.extend(text.encode() + b"\x00")
        return offsets[text]

    for name in list(needed) + ([soname] if soname else []) \
            + list(exports):
        intern(name)

    dynsym = bytearray(b"\x00" * 24)  # null symbol
    for name in exports:
        dynsym += struct.pack(
            "<IBBHQQ", offsets[name], 0x12, 0, 1, 0, 0)

    ehsize, phentsize, phnum = 64, 56, 2
    phoff = ehsize
    dynstr_off = phoff + phnum * phentsize
    dynsym_off = (dynstr_off + len(dynstr) + 7) & ~7
    dyn_entries = [(1, offsets[n]) for n in needed]
    if soname:
        dyn_entries.append((14, offsets[soname]))
    dyn_entries += [
        (5, dynstr_off),               # DT_STRTAB
        (10, len(dynstr)),             # DT_STRSZ
        (6, dynsym_off),               # DT_SYMTAB
        (11, 24),                      # DT_SYMENT
        (0, 0),                        # DT_NULL
    ]
    dynamic = b"".join(
        struct.pack("<qQ", tag, val) for tag, val in dyn_entries)
    dynamic_off = (dynsym_off + len(dynsym) + 7) & ~7
    shstrtab = b"\x00.dynsym\x00.dynstr\x00.dynamic\x00.shstrtab\x00"
    sh_name = {".dynsym": 1, ".dynstr": 9,
               ".dynamic": 17, ".shstrtab": 26}
    shstr_off = dynamic_off + len(dynamic)
    shoff = (shstr_off + len(shstrtab) + 7) & ~7
    file_size = shoff + 5 * 64

    out = bytearray(file_size)
    out[0:16] = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    struct.pack_into(
        "<HHIQQQIHHHHHH", out, 16,
        3, 0xB7, 1, 0, phoff, shoff, 0,
        ehsize, phentsize, phnum, 64, 5, 4)
    # PT_LOAD (whole file) + PT_DYNAMIC.
    struct.pack_into("<IIQQQQQQ", out, phoff,
                     1, 5, 0, 0, 0, file_size, file_size, 0x1000)
    struct.pack_into("<IIQQQQQQ", out, phoff + phentsize,
                     2, 4, dynamic_off, dynamic_off, dynamic_off,
                     len(dynamic), len(dynamic), 8)
    out[dynstr_off:dynstr_off + len(dynstr)] = dynstr
    out[dynsym_off:dynsym_off + len(dynsym)] = dynsym
    out[dynamic_off:dynamic_off + len(dynamic)] = dynamic
    out[shstr_off:shstr_off + len(shstrtab)] = shstrtab

    def sh(name, shtype, offset, size, link, info, entsize):
        return struct.pack(
            "<IIQQQQIIQQ", sh_name.get(name, 0), shtype, 0, 0,
            offset, size, link, info, 8, entsize)

    sections = b"\x00" * 64
    sections += sh(".dynsym", 11, dynsym_off, len(dynsym),
                   2, 1, 24)
    sections += sh(".dynstr", 3, dynstr_off, len(dynstr),
                   0, 0, 0)
    sections += sh(".dynamic", 6, dynamic_off, len(dynamic),
                   2, 0, 16)
    sections += sh(".shstrtab", 3, shstr_off, len(shstrtab),
                   0, 0, 0)
    out[shoff:shoff + len(sections)] = sections
    return bytes(out)


def build_apk(dex_bytes):
    """The inventory fixture: one DEX, two native libraries
    (one JNI-exporting with DT_NEEDED entries, one plain) and
    one non-native member. Fixed zip timestamps keep the
    bytes reproducible."""
    jni_so = build_elf64(
        JNI_EXPORTS, needed=["liboracle_plain.so", "liblog.so"],
        soname="liboracle_jni.so")
    plain_so = build_elf64(
        PLAIN_EXPORTS, needed=["liblog.so"],
        soname="liboracle_plain.so")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in [
                ("classes.dex", dex_bytes),
                (JNI_LIB, jni_so),
                (PLAIN_LIB, plain_so),
                (NOTE_MEMBER,
                 b"synthetic oracle fixture note\n")]:
            info = zipfile.ZipInfo(
                name, date_time=(2020, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            zf.writestr(info, data)
    return buf.getvalue()


def build_all(out_dir):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    mod = _load_dex_builder()
    written = {}
    dexes = {
        "oracle_basic.dex": build_basic_dex(mod),
        "oracle_branches.dex": build_branches_dex(mod),
        "oracle_multi.dex": build_multi_dex(mod),
    }
    for name, blob in dexes.items():
        (out / name).write_bytes(blob)
        written[name] = len(blob)
    apk = build_apk(dexes["oracle_basic.dex"])
    (out / "oracle_inventory.apk").write_bytes(apk)
    written["oracle_inventory.apk"] = len(apk)
    return written


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate the synthetic oracle fixtures.")
    parser.add_argument("--out", default=str(FIXTURES),
                        help="output directory")
    args = parser.parse_args(argv)
    written = build_all(args.out)
    for name, size in sorted(written.items()):
        print(f"{name}: {size} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
