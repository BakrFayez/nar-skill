#!/usr/bin/env python3
"""nar-gamemaker.py: inspect a GameMaker data.win file.

Finds data.win in a target's asset roots (resolved through
narlib.container, splits merged) — canonically assets/data.win
— and also accepts a bare data.win (or *.win) file as the
target.

Layout (public GameMaker format documentation): the file
opens with the 4-byte magic "FORM" and a u32 little-endian
total size, followed by a walk of chunks from offset 8, each
chunk being a 4-byte name + u32 size (the size includes the
8-byte chunk header). Every chunk size is validated (>= 8
and within the file) before the walk advances; a failed
validation stops the walk with the reason named.

GEN8 facts: GEN8 string fields are absolute file offsets to
length-prefixed strings (u32 length + bytes, optionally
padded to 4). The game name is conventionally the string at
the offset stored at GEN8 data start + 8; this reader tries
the candidate field positions +4, +8 and +12 (in that order)
and accepts the first that resolves to a plausible printable
string, reporting which offset basis was used. STRG holds a
u32 count + count x u32 absolute offsets to the same string
shape. TXTR / AUDO / SPRT entry counts are the u32 count
fields at those chunk starts, validated for plausibility.

Layout knowledge note: the chunk/GEN8/STRG layout here is
from public GameMaker format documentation, not from a
local real GameMaker corpus (no real GameMaker corpus is
available locally); the parser is synthetic-fixture
verified only.

Usage:
    python3 nar-gamemaker.py app.apk [--json]
    python3 nar-gamemaker.py data.win [--json]

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import struct
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import container as container_mod  # noqa: E402

VERSION = "3.0.0"
MEMBER_CAP_BYTES = 32 * 1024 * 1024
MAX_CHUNKS = 10_000
MAX_STRINGS = 200_000
MAX_COUNT = 1_000_000
MAX_STRING_LEN = 4096


def _read_string_at(data, offset):
    """Length-prefixed string at an absolute file offset.

    Returns the decoded string, or None when the offset,
    length or bytes do not validate as a plausible printable
    string."""
    if offset is None or offset < 0 or offset + 4 > len(data):
        return None
    length = struct.unpack_from("<I", data, offset)[0]
    if length > MAX_STRING_LEN or offset + 4 + length > len(data):
        return None
    raw = data[offset + 4:offset + 4 + length]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    printable = sum(1 for c in text if c.isprintable() or c in " \t")
    if printable < max(1, int(len(text) * 0.9)):
        return None
    return text


def _chunk_count(data, chunk):
    """The u32 entry count at a chunk's data start, validated."""
    if chunk is None or chunk["size"] < 12:
        return None
    count = struct.unpack_from("<I", data, chunk["offset"] + 8)[0]
    if count > MAX_COUNT:
        return None
    return count


def parse_data_win(data, source):
    """Parse one data.win blob. Never raises on bad data."""
    rec = {"source": source, "size_bytes": len(data),
           "form_ok": False, "declared_size": None,
           "chunks": [], "walk_failed": None,
           "gen8": {"game_name": None, "name_basis": None,
                    "name_error": None},
           "strings": {"count": None, "sample": [],
                       "total_chars": None},
           "counts": {"textures": None, "audio": None,
                      "sprites": None}}
    if len(data) < 8 or data[:4] != b"FORM":
        rec["walk_failed"] = "no FORM magic: not a GameMaker data file"
        return rec
    rec["form_ok"] = True
    rec["declared_size"] = struct.unpack_from("<I", data, 4)[0]
    chunks = []
    by_name = {}
    pos = 8
    while pos + 8 <= len(data):
        if len(chunks) >= MAX_CHUNKS:
            rec["walk_failed"] = "chunk walk exceeded the chunk cap"
            break
        name = data[pos:pos + 4].decode("ascii", "replace")
        size = struct.unpack_from("<I", data, pos + 4)[0]
        if size < 8 or pos + size > len(data):
            rec["walk_failed"] = (
                f"chunk {name!r} at offset {pos} declares size "
                f"{size}, outside the {len(data)}-byte file")
            break
        chunk = {"name": name, "offset": pos, "size": size}
        chunks.append(chunk)
        by_name.setdefault(name, chunk)
        pos += size
    rec["chunks"] = chunks
    # GEN8 game name via candidate string-offset fields.
    gen8 = by_name.get("GEN8")
    if gen8 is not None:
        data_start = gen8["offset"] + 8
        tried = []
        for delta in (4, 8, 12):
            if data_start + delta + 4 > gen8["offset"] + gen8["size"]:
                continue
            field = struct.unpack_from(
                "<I", data, data_start + delta)[0]
            tried.append(f"GEN8+{delta} -> {field}")
            text = _read_string_at(data, field)
            if text is not None:
                rec["gen8"] = {
                    "game_name": text,
                    "name_basis": f"GEN8 data start +{delta} "
                                  f"(absolute string offset "
                                  f"{field})",
                    "name_error": None}
                break
        if rec["gen8"]["game_name"] is None:
            rec["gen8"]["name_error"] = (
                "no candidate GEN8 string-offset field "
                f"({' ; '.join(tried) or 'none in range'}) "
                "resolved to a plausible printable string")
    else:
        rec["gen8"]["name_error"] = "no GEN8 chunk present"
    # STRG string table.
    strg = by_name.get("STRG")
    if strg is not None:
        start = strg["offset"] + 8
        if strg["size"] >= 12:
            count = struct.unpack_from("<I", data, start)[0]
            if count > MAX_STRINGS:
                rec["strings"] = {
                    "count": None, "sample": [],
                    "total_chars": None,
                    "error": f"STRG count {count} exceeds the "
                             f"plausibility cap {MAX_STRINGS}"}
            elif start + 4 + count * 4 > strg["offset"] + strg["size"]:
                rec["strings"] = {
                    "count": None, "sample": [],
                    "total_chars": None,
                    "error": "STRG offset table runs past the "
                             "end of the STRG chunk"}
            else:
                sample = []
                total_chars = 0
                error = None
                for i in range(count):
                    off = struct.unpack_from(
                        "<I", data, start + 4 + i * 4)[0]
                    text = _read_string_at(data, off)
                    if text is None:
                        error = (f"STRG entry {i} at offset "
                                 f"{off} does not resolve to a "
                                 "plausible string")
                        break
                    total_chars += len(text)
                    if len(sample) < 20:
                        sample.append(text)
                rec["strings"] = {
                    "count": count if error is None else None,
                    "declared_count": count,
                    "sample": sample,
                    "total_chars": total_chars if error is None
                    else None,
                    "error": error}
    rec["counts"] = {
        "textures": _chunk_count(data, by_name.get("TXTR")),
        "audio": _chunk_count(data, by_name.get("AUDO")),
        "sprites": _chunk_count(data, by_name.get("SPRT"))}
    return rec


def _collect(resolved, roots):
    found = []
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
                base = info.filename.rsplit("/", 1)[-1].lower()
                if base != "data.win" and not base.endswith(".win"):
                    continue
                if info.file_size > MEMBER_CAP_BYTES:
                    found.append({"source": info.filename,
                                  "source_archive": label,
                                  "size_bytes": info.file_size,
                                  "form_ok": False, "chunks": [],
                                  "walk_failed": "member "
                                                 "exceeds the "
                                                 "32 MiB read "
                                                 "cap"})
                else:
                    rec = parse_data_win(
                        zf.read(info.filename), info.filename)
                    rec["source_archive"] = label
                    found.append(rec)
    return found


def inspect(target):
    if not os.path.isfile(target):
        raise FileNotFoundError(f"not a file: {target}")
    resolved = container_mod.resolve_target(target)
    try:
        report = {"tool": "nar-gamemaker", "version": VERSION,
                  "target": os.path.abspath(target),
                  "container": resolved.container_block(),
                  "verdict": "absent", "files": [],
                  "chunks": [], "gen8": None, "strings": None,
                  "counts": None,
                  "limitations": [
                      "The data.win layout is implemented "
                      "from public GameMaker format "
                      "documentation; no real GameMaker "
                      "corpus is available locally, so the "
                      "parse is synthetic-fixture verified "
                      "only."]}
        files = []
        low = os.path.basename(target).lower()
        if not resolved.is_container and (
                low == "data.win" or low.endswith(".win")):
            with open(target, "rb") as fh:
                data = fh.read(MEMBER_CAP_BYTES + 1)
            if len(data) > MEMBER_CAP_BYTES:
                files.append({"source": os.path.basename(target),
                              "size_bytes":
                                  os.path.getsize(target),
                              "form_ok": False, "chunks": [],
                              "walk_failed": "file exceeds the "
                                             "32 MiB read cap"})
            else:
                files.append(parse_data_win(
                    data, os.path.basename(target)))
        else:
            roots = list(resolved.assets_roots)
            if not roots and not resolved.is_container and \
                    zipfile.is_zipfile(target):
                roots = [os.path.abspath(target)]

            class _View:
                assets_roots = roots
            files = _collect(_View(), roots)
        report["files"] = files
        if files:
            first = files[0]
            report["chunks"] = first.get("chunks") or []
            report["gen8"] = first.get("gen8")
            report["strings"] = first.get("strings")
            report["counts"] = first.get("counts")
            if first.get("form_ok"):
                report["verdict"] = "present"
        return report
    finally:
        resolved.cleanup()


def human(report):
    lines = [f"NAR GameMaker inspection: {report['target']}",
             f"Verdict: {report['verdict']}"]
    for rec in report["files"]:
        lines.append(f"File: {rec.get('source')} "
                     f"({rec.get('size_bytes')} bytes, "
                     f"FORM ok: {rec.get('form_ok')})")
        if rec.get("walk_failed"):
            lines.append(f"  walk failed: {rec['walk_failed']}")
        lines.append("  chunks: " + ", ".join(
            f"{c['name']}@{c['offset']}+{c['size']}"
            for c in rec.get("chunks") or []))
        gen8 = rec.get("gen8") or {}
        lines.append(f"  game name: {gen8.get('game_name')} "
                     f"(basis: {gen8.get('name_basis') or gen8.get('name_error')})")
        strings = rec.get("strings") or {}
        lines.append(f"  strings: {strings.get('count')} "
                     f"(sample: {strings.get('sample')})")
        lines.append(f"  counts: {rec.get('counts')}")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR GameMaker data.win inspector.")
    p.add_argument("target", help="path to an .apk, a container, "
                                  "or a bare data.win file")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    try:
        report = inspect(args.target)
    except FileNotFoundError as e:
        print(f"nar-gamemaker: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(human(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
