#!/usr/bin/env python3
"""nar-heaps.py: inspect HashLink bytecode (Heaps / Haxe).

Finds hlboot.dat in a target's asset roots (resolved through
narlib.container, splits merged) — canonically
assets/hlboot.dat — plus any *.hl members, and also accepts
a bare hlboot.dat / *.hl file as the target.

HashLink bytecode header (public HL format documentation):
the 3 magic bytes "HLB" (0x48 0x4C 0x42), then uindex-encoded
integers. uindex encoding: read a byte b; if b < 0x80 the
value is b; otherwise v = b & 0x7F, then repeatedly read b2
with v = (v << 7) | (b2 & 0x7F) until b2 < 0x80. The first
two uindex values after the magic are the format version
and the flags.

DELIVERABLE SCOPE, stated honestly: only the magic, version
and flags are named here. The deeper header walk (section
counts in their documented order) is NOT emitted: the count
sequence could not be validated against a real sample, so
``section_counts`` is null with the reason recorded, rather
than positional integers dressed up as named counts. No
section counts are invented.

Layout knowledge note: the HLB header/uindex encoding here
is from public HashLink format documentation, not from a
local real HashLink corpus (no real HashLink corpus is
available locally); the parser is synthetic-fixture
verified only, built to the same documented encoding.

Usage:
    python3 nar-heaps.py app.apk [--json]
    python3 nar-heaps.py hlboot.dat [--json]

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import container as container_mod  # noqa: E402

VERSION = "3.0.0"
MEMBER_CAP_BYTES = 32 * 1024 * 1024
HL_MAGIC = b"HLB"

SECTION_COUNTS_REASON = (
    "deeper header walk not validated: the section-count "
    "sequence after version/flags could not be verified "
    "against a real HashLink sample locally, so no section "
    "counts are named (public-documentation layout only, "
    "synthetic-fixture verified)")


def read_uindex(data, pos):
    """Decode one uindex at ``pos`` per the documented
    encoding. Returns (value, new_pos); raises ValueError
    when the encoding runs past the end of the data."""
    if pos >= len(data):
        raise ValueError("uindex starts past the end of the data")
    b = data[pos]
    pos += 1
    if b < 0x80:
        return b, pos
    value = b & 0x7F
    while True:
        if pos >= len(data):
            raise ValueError("uindex continuation runs past "
                             "the end of the data")
        b2 = data[pos]
        pos += 1
        value = (value << 7) | (b2 & 0x7F)
        if b2 < 0x80:
            return value, pos


def encode_uindex(value):
    """Encode one uindex (the inverse of read_uindex, per
    the same documented encoding). Used by the tests to
    build fixtures; shipped here so the encoding lives in
    exactly one place."""
    if value < 0:
        raise ValueError("uindex cannot be negative")
    groups = []
    v = value
    while True:
        groups.append(v & 0x7F)
        v >>= 7
        if not v:
            break
    groups.reverse()
    out = bytearray()
    for i, g in enumerate(groups):
        out.append(g | 0x80 if i < len(groups) - 1 else g)
    # Multi-byte values need the leading byte flagged as a
    # continuation too: every byte except the last carries
    # the high bit.
    if len(out) > 1:
        out[0] |= 0x80
    return bytes(out)


def parse_hl(data, source):
    """Parse one HashLink blob's header. Never raises."""
    rec = {"source": source, "size_bytes": len(data),
           "magic_ok": False, "version": None, "flags": None,
           "section_counts": None,
           "section_counts_reason": SECTION_COUNTS_REASON,
           "error": None}
    if not data.startswith(HL_MAGIC):
        rec["error"] = "no HLB magic: not HashLink bytecode"
        return rec
    rec["magic_ok"] = True
    try:
        version, pos = read_uindex(data, len(HL_MAGIC))
        flags, _pos = read_uindex(data, pos)
    except ValueError as e:
        rec["error"] = f"header uindex walk failed: {e}"
        return rec
    rec["version"] = version
    rec["flags"] = flags
    return rec


def _census(resolved, roots, bare_dir=None):
    members = []
    for root in roots:
        try:
            zf = zipfile.ZipFile(root)
        except (zipfile.BadZipFile, OSError):
            continue
        with zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                low = info.filename.lower()
                if low.endswith((".hl", ".dat")):
                    members.append({"member": info.filename,
                                    "size_bytes": info.file_size,
                                    "archive":
                                        os.path.basename(root)})
    if bare_dir:
        try:
            for name in sorted(os.listdir(bare_dir)):
                if name.lower().endswith((".hl", ".dat")):
                    full = os.path.join(bare_dir, name)
                    if os.path.isfile(full):
                        members.append({
                            "member": name,
                            "size_bytes": os.path.getsize(full),
                            "archive": None})
        except OSError:
            pass
    return members


def inspect(target):
    if not os.path.isfile(target):
        raise FileNotFoundError(f"not a file: {target}")
    resolved = container_mod.resolve_target(target)
    try:
        report = {"tool": "nar-heaps", "version": VERSION,
                  "target": os.path.abspath(target),
                  "container": resolved.container_block(),
                  "verdict": "absent", "files": [],
                  "header": None, "census": [],
                  "limitations": [
                      "Only the HLB magic, version and flags "
                      "are decoded; section counts are not "
                      "named (see section_counts_reason).",
                      "The header layout is implemented from "
                      "public HashLink format documentation; "
                      "no real HashLink corpus is available "
                      "locally, so the parse is synthetic-"
                      "fixture verified only."]}
        files = []
        low = os.path.basename(target).lower()
        roots = list(resolved.assets_roots)
        if not roots and not resolved.is_container and \
                zipfile.is_zipfile(target):
            roots = [os.path.abspath(target)]
        bare_dir = None
        if not resolved.is_container and (
                low == "hlboot.dat" or low.endswith(".hl")):
            bare_dir = os.path.dirname(os.path.abspath(target))
            with open(target, "rb") as fh:
                data = fh.read(MEMBER_CAP_BYTES + 1)
            if len(data) > MEMBER_CAP_BYTES:
                files.append({"source": os.path.basename(target),
                              "size_bytes": os.path.getsize(target),
                              "magic_ok": False, "version": None,
                              "flags": None, "section_counts": None,
                              "section_counts_reason":
                                  SECTION_COUNTS_REASON,
                              "error": "file exceeds the 32 MiB "
                                       "read cap"})
            else:
                files.append(parse_hl(data, os.path.basename(target)))
        else:
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
                        ilow = info.filename.lower()
                        base = ilow.rsplit("/", 1)[-1]
                        if base != "hlboot.dat" and \
                                not ilow.endswith(".hl"):
                            continue
                        if info.file_size > MEMBER_CAP_BYTES:
                            files.append({
                                "source": info.filename,
                                "source_archive": label,
                                "size_bytes": info.file_size,
                                "magic_ok": False, "version": None,
                                "flags": None,
                                "section_counts": None,
                                "section_counts_reason":
                                    SECTION_COUNTS_REASON,
                                "error": "member exceeds the "
                                         "32 MiB read cap"})
                            continue
                        rec = parse_hl(
                            zf.read(info.filename), info.filename)
                        rec["source_archive"] = label
                        files.append(rec)
        report["files"] = files
        report["census"] = _census(resolved, roots, bare_dir)
        for rec in files:
            if rec.get("magic_ok"):
                report["verdict"] = "present"
                report["header"] = {
                    "version": rec.get("version"),
                    "flags": rec.get("flags"),
                    "section_counts": None,
                    "section_counts_reason": SECTION_COUNTS_REASON}
                break
        return report
    finally:
        resolved.cleanup()


def human(report):
    lines = [f"NAR Heaps/HashLink inspection: {report['target']}",
             f"Verdict: {report['verdict']}"]
    for rec in report["files"]:
        lines.append(f"File: {rec.get('source')} "
                     f"({rec.get('size_bytes')} bytes, magic ok: "
                     f"{rec.get('magic_ok')}, version: "
                     f"{rec.get('version')}, flags: "
                     f"{rec.get('flags')})")
        if rec.get("error"):
            lines.append(f"  error: {rec['error']}")
    lines.append(f"Census (.hl/.dat members): "
                 f"{len(report.get('census') or [])}")
    if report.get("header"):
        lines.append(f"Section counts: not named — "
                     f"{SECTION_COUNTS_REASON}")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR Heaps/HashLink bytecode header "
                    "inspector (magic + version + flags).")
    p.add_argument("target", help="path to an .apk, a container, "
                                  "or a bare hlboot.dat/*.hl file")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    try:
        report = inspect(args.target)
    except FileNotFoundError as e:
        print(f"nar-heaps: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(human(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
