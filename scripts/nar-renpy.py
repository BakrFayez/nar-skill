#!/usr/bin/env python3
"""nar-renpy.py: inspect Ren'Py .rpa archives and .rpyc scripts.

Finds *.rpa archives in a target's asset roots (resolved
through narlib.container, splits merged) and also accepts a
bare .rpa file as the target. Archive header lines:

    RPA-3.0 <16 hex index offset> <8 hex key>
    RPA-2.0 <16 hex index offset>
    RPA-1.0 <index offset>            (no key)

At the index offset sits a zlib stream holding a pickle of
{str: [(offset, length, prefix)]} (RPA-3.0; RPA-2.0/1.0
entries are (offset, length) pairs). RPA-3.0 deobfuscation:
real_offset = stored_offset ^ key and
real_length = stored_length ^ key; RPA-2.0/1.0 entries are
plain (key = 0).

SECURITY: the index pickle is target-controlled data and is
NEVER loaded with plain pickle.loads. The decompressed
bytes are first scanned with pickletools.genops and refused
when they contain GLOBAL / STACK_GLOBAL / REDUCE / OBJ /
INST / NEWOBJ opcodes, and the load itself goes through a
RestrictedUnpickler whose find_class ALWAYS raises
UnpicklingError, so no class or callable from the archive
can ever be resolved, let alone executed.

.rpyc members are identification only: the "RENPY RPC2"
magic is checked and the sequence of length-prefixed zlib
slots after the header is censused (slot count/sizes) when
the walk validates. No decompilation is attempted — that
boundary is stated in the report.

Layout knowledge note: the RPA/RPC2 layouts here are from
public Ren'Py format documentation/source, not from a
local real Ren'Py corpus (no real Ren'Py corpus is
available locally); the parser is synthetic-fixture
verified only.

Usage:
    python3 nar-renpy.py app.apk [--json]
    python3 nar-renpy.py archive.rpa [--json]

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import io
import json
import os
import pickle
import pickletools
import re
import sys
import zipfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import container as container_mod  # noqa: E402

VERSION = "3.0.1"
MEMBER_CAP_BYTES = 32 * 1024 * 1024
INDEX_CAP_BYTES = 64 * 1024 * 1024

FORBIDDEN_OPCODES = frozenset({
    "GLOBAL", "STACK_GLOBAL", "REDUCE", "OBJ", "INST",
    "NEWOBJ", "NEWOBJ_EX", "EXT1", "EXT2", "EXT4"})

_HEADER_RE = re.compile(
    r"^RPA-(\d+\.\d+)\s+([0-9a-fA-F]+)(?:\s+([0-9a-fA-F]+))?\s*$")


class RestrictedUnpickler(pickle.Unpickler):
    """An unpickler that can never resolve a global: any
    class/function lookup raises, so only plain data
    (dicts, lists, tuples, strings, numbers, bytes) can
    be reconstructed."""

    def find_class(self, module, name):
        raise pickle.UnpicklingError(
            f"global {module}.{name} is forbidden in an "
            "archive index")


def _prescan_pickle(raw):
    """Refuse pickle bytes carrying code-referencing opcodes.

    Returns an error string, or None when the byte stream is
    free of every forbidden opcode."""
    try:
        for opcode, _arg, _pos in pickletools.genops(raw):
            if opcode.name in FORBIDDEN_OPCODES:
                return (f"pickle refused: forbidden opcode "
                        f"{opcode.name} present in the "
                        "archive index (code-referencing "
                        "opcodes are never loaded)")
    except Exception as e:  # malformed pickle byte stream
        return f"pickle refused: opcode scan failed: {e}"
    return None


def _load_index(raw):
    """Restricted-load an RPA index pickle.

    Returns (index_dict, error). Exactly one of the two is
    not None."""
    refusal = _prescan_pickle(raw)
    if refusal:
        return None, refusal
    try:
        obj = RestrictedUnpickler(io.BytesIO(raw)).load()
    except Exception as e:
        return None, f"pickle refused: restricted load failed: {e}"
    if not isinstance(obj, dict):
        return None, ("pickle refused: index is not a dict "
                      f"(got {type(obj).__name__})")
    return obj, None


def parse_rpa(data, source):
    """Parse one .rpa blob. Never raises on bad data and
    never executes archive content."""
    rec = {"source": source, "size_bytes": len(data),
           "archive": {"version": None, "index_offset": None,
                       "key_present": False},
           "files": None, "error": None}
    newline = data.find(b"\n", 0, 128)
    if newline < 0:
        rec["error"] = "no header line in the first 128 bytes"
        return rec
    try:
        header = data[:newline].decode("ascii")
    except UnicodeDecodeError:
        rec["error"] = "header line is not ASCII"
        return rec
    m = _HEADER_RE.match(header.strip())
    if not m:
        rec["error"] = f"unrecognised RPA header line: {header!r}"
        return rec
    version = m.group(1)
    index_offset = int(m.group(2), 16)
    key = int(m.group(3), 16) if m.group(3) else 0
    rec["archive"] = {"version": version,
                      "index_offset": index_offset,
                      "key_present": bool(m.group(3)),
                      "header": header.strip()}
    if index_offset < 0 or index_offset >= len(data):
        rec["error"] = (f"index offset {index_offset} is "
                        f"outside the {len(data)}-byte archive")
        return rec
    # Bounded zlib decompression of the index stream.
    try:
        d = zlib.decompressobj()
        raw = d.decompress(data[index_offset:], INDEX_CAP_BYTES + 1)
    except zlib.error as e:
        rec["error"] = f"index zlib stream does not decode: {e}"
        return rec
    if len(raw) > INDEX_CAP_BYTES:
        rec["error"] = ("index expands past the "
                        f"{INDEX_CAP_BYTES}-byte cap; refused")
        return rec
    index, error = _load_index(raw)
    if error:
        rec["error"] = error
        return rec
    # Validate + deobfuscate the listing. Only plain data
    # shapes are accepted; anything else degrades the whole
    # listing to an error rather than a partial guess.
    names = []
    total = 0
    by_ext = {}
    for name, segments in index.items():
        if not isinstance(name, str) or \
                not isinstance(segments, (list, tuple)):
            rec["error"] = "index entry has an unexpected shape"
            rec["files"] = None
            return rec
        names.append(name)
        base = name.rsplit("/", 1)[-1]
        _stem, dot, ext = base.rpartition(".")
        ext_key = f".{ext.lower()}" if dot and ext else "(none)"
        by_ext[ext_key] = by_ext.get(ext_key, 0) + 1
        for seg in segments:
            if not isinstance(seg, (list, tuple)) or len(seg) < 2:
                rec["error"] = ("index segment has an "
                                "unexpected shape")
                rec["files"] = None
                return rec
            stored_off, stored_len = seg[0], seg[1]
            if not isinstance(stored_off, int) or \
                    not isinstance(stored_len, int):
                rec["error"] = ("index segment offset/length "
                                "are not integers")
                rec["files"] = None
                return rec
            real_len = stored_len ^ key if version == "3.0" \
                else stored_len
            if real_len < 0:
                rec["error"] = "index segment has a negative length"
                rec["files"] = None
                return rec
            total += real_len
    names.sort()
    rec["files"] = {"count": len(names), "total_bytes": total,
                    "by_ext": dict(sorted(by_ext.items())),
                    "sample": names[:20]}
    return rec


def parse_rpyc(data, source):
    """Identification + slot census for one .rpyc blob.

    After the 10-byte "RENPY RPC2" header the file is a
    sequence of length-prefixed zlib slots (u32 little-endian
    length + that many bytes). The census is reported only
    when the walk ends exactly at EOF; otherwise the slot
    fields stay null and the failure is named. No
    decompilation is attempted."""
    rec = {"source": source, "size_bytes": len(data),
           "magic_ok": False, "slot_count": None,
           "slot_sizes": None, "walk_failed": None,
           "note": "identification only: .rpyc bytecode is "
                   "not decompiled by this tool"}
    if not data.startswith(b"RENPY RPC2"):
        rec["walk_failed"] = "no RENPY RPC2 magic"
        return rec
    rec["magic_ok"] = True
    import struct
    pos = len(b"RENPY RPC2")
    sizes = []
    while pos < len(data):
        if pos + 4 > len(data):
            rec["walk_failed"] = "trailing bytes shorter than a slot header"
            return rec
        length = struct.unpack_from("<I", data, pos)[0]
        if length == 0 or pos + 4 + length > len(data):
            rec["walk_failed"] = (
                f"slot at offset {pos} declares length "
                f"{length}, outside the {len(data)}-byte file")
            return rec
        if data[pos + 4:pos + 6] not in (b"\x78\x01", b"\x78\x9c",
                                         b"\x78\xda", b"\x78\x5e"):
            # Not a zlib-looking slot: the walk does not
            # validate in the documented shape.
            rec["walk_failed"] = (
                f"slot at offset {pos} does not start with a "
                "zlib header")
            return rec
        sizes.append(length)
        pos += 4 + length
        if len(sizes) > 10_000:
            rec["walk_failed"] = "slot walk exceeded the slot cap"
            return rec
    rec["slot_count"] = len(sizes)
    rec["slot_sizes"] = sizes
    return rec


def _collect(resolved, roots):
    rpas, rpycs = [], []
    for root in roots:
        label = os.path.basename(root)
        try:
            zf = zipfile.ZipFile(root)
        except (zipfile.BadZipFile, OSError):
            continue
        with zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                low = info.filename.lower()
                if not low.endswith((".rpa", ".rpyc")):
                    continue
                if info.file_size > MEMBER_CAP_BYTES:
                    rec = {"source": info.filename,
                           "source_archive": label,
                           "size_bytes": info.file_size,
                           "error": "member exceeds the "
                                    "32 MiB read cap"}
                    (rpas if low.endswith(".rpa") else rpycs).append(rec)
                    continue
                data = zf.read(info.filename)
                if low.endswith(".rpa"):
                    rec = parse_rpa(data, info.filename)
                else:
                    rec = parse_rpyc(data, info.filename)
                rec["source_archive"] = label
                (rpas if low.endswith(".rpa") else rpycs).append(rec)
    return rpas, rpycs


def inspect(target):
    if not os.path.isfile(target):
        raise FileNotFoundError(f"not a file: {target}")
    resolved = container_mod.resolve_target(target)
    try:
        report = {"tool": "nar-renpy", "version": VERSION,
                  "target": os.path.abspath(target),
                  "container": resolved.container_block(),
                  "verdict": "absent", "archives": [],
                  "archive": None, "files": None, "rpyc": [],
                  "limitations": [
                      "The RPA/RPC2 layouts are implemented "
                      "from public Ren'Py format "
                      "documentation/source; no real Ren'Py "
                      "corpus is available locally, so the "
                      "parse is synthetic-fixture verified "
                      "only.",
                      ".rpyc files are identified and slot-"
                      "censused only; bytecode decompilation "
                      "is not attempted."]}
        rpas, rpycs = [], []
        low = os.path.basename(target).lower()
        if not resolved.is_container and low.endswith(".rpa"):
            with open(target, "rb") as fh:
                data = fh.read(MEMBER_CAP_BYTES + 1)
            if len(data) > MEMBER_CAP_BYTES:
                rpas.append({"source": os.path.basename(target),
                             "size_bytes": os.path.getsize(target),
                             "archive": {"version": None,
                                         "index_offset": None,
                                         "key_present": False},
                             "files": None,
                             "error": "file exceeds the 32 MiB "
                                      "read cap"})
            else:
                rpas.append(parse_rpa(data, os.path.basename(target)))
        elif not resolved.is_container and low.endswith(".rpyc"):
            with open(target, "rb") as fh:
                data = fh.read(MEMBER_CAP_BYTES + 1)
            rpycs.append(parse_rpyc(data, os.path.basename(target)))
        else:
            roots = list(resolved.assets_roots)
            if not roots and not resolved.is_container and \
                    zipfile.is_zipfile(target):
                roots = [os.path.abspath(target)]
            rpas, rpycs = _collect(resolved, roots)
        report["archives"] = rpas
        report["rpyc"] = rpycs
        if rpas:
            report["archive"] = rpas[0].get("archive")
            report["files"] = rpas[0].get("files")
        if rpas or rpycs:
            report["verdict"] = "present"
        return report
    finally:
        resolved.cleanup()


def human(report):
    lines = [f"NAR Ren'Py inspection: {report['target']}",
             f"Verdict: {report['verdict']}"]
    for rec in report["archives"]:
        arch = rec.get("archive") or {}
        lines.append(f"Archive: {rec.get('source')} "
                     f"(RPA-{arch.get('version')}, index at "
                     f"{arch.get('index_offset')}, key present: "
                     f"{arch.get('key_present')})")
        if rec.get("files"):
            f = rec["files"]
            lines.append(f"  files: {f['count']}, "
                         f"{f['total_bytes']:,} bytes, "
                         f"by ext: {f['by_ext']}")
            lines.append(f"  sample: {f['sample']}")
        else:
            lines.append(f"  error: {rec.get('error')}")
    for rec in report["rpyc"]:
        lines.append(f"RPYC: {rec.get('source')} "
                     f"(magic ok: {rec.get('magic_ok')}, slots: "
                     f"{rec.get('slot_count')}"
                     f"{', walk failed: ' + rec['walk_failed'] if rec.get('walk_failed') else ''})")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR Ren'Py .rpa archive / .rpyc inspector "
                    "(restricted unpickling only).")
    p.add_argument("target", help="path to an .apk, a container, "
                                  "or a bare .rpa/.rpyc file")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    try:
        report = inspect(args.target)
    except FileNotFoundError as e:
        print(f"nar-renpy: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(human(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
