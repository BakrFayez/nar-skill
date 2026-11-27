#!/usr/bin/env python3
"""nar-defold.py: inspect Defold archives (.arci index + .arcd data).

Finds Defold archive pairs in a target's asset roots (resolved
through narlib.container, splits merged) — canonically
assets/game.arci + assets/game.arcd, or any .arci/.arcd pair —
and also accepts a bare .arci file as the target (its sibling
.arcd is read from the same directory).

The .arci index layout implemented here is the public Defold
engine source layout (little-endian): u32 version, u32 pad,
u64 user_data, u32 entry_count, then entry_count records of
(u64 hash, u32 offset, u32 size, u32 flags), with offsets and
sizes relative to the .arcd data file. The entry walk is
attempted ONLY in that documented shape and is fully
validated (plausible count, every offset+size inside the
.arcd, nonzero hashes); a failed validation degrades the
archive to identification + header facts with the failed
check named — never an exception, never fabricated counts.

Structural boundary, stated plainly: index hashes are
MurmurHash64 values of resource paths; the paths themselves
are NOT recoverable from the index, so entries are reported
by hash/offset/size only.

Layout knowledge note: the .arci layout here is from public
Defold engine documentation/source, not from a local real
Defold corpus (no real Defold corpus is available locally);
the parser is synthetic-fixture verified only.

Usage:
    python3 nar-defold.py app.apk [--json]
    python3 nar-defold.py game.arci [--json]

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

VERSION = "3.0.3"
MEMBER_CAP_BYTES = 32 * 1024 * 1024
MAX_ENTRIES = 1_000_000
ENTRY_SIZE = 20  # u64 hash + u32 offset + u32 size + u32 flags
HEADER_SIZE = 20  # u32 version + u32 pad + u64 user_data + u32 count

FLAG_COMPRESSED = 0x1
FLAG_ENCRYPTED = 0x2

BOUNDARY = (
    "Entry hashes are MurmurHash64 of resource paths; paths "
    "are NOT recoverable from the .arci index, so entries are "
    "reported by hash/offset/size only.")


def parse_arci(data, arcd_size):
    """Parse one .arci blob against its .arcd size.

    Returns a dict with the header facts and either a
    validated ``entries`` summary or ``walk_failed`` naming
    the check that failed. Never raises on bad data."""
    rec = {"arci_size": len(data), "arcd_size": arcd_size,
           "version": None, "entry_count_declared": None,
           "entries": None, "walk_failed": None}
    if len(data) < HEADER_SIZE:
        rec["walk_failed"] = (
            f"index is {len(data)} bytes, shorter than the "
            f"{HEADER_SIZE}-byte documented header")
        return rec
    version, _pad, user_data, count = struct.unpack_from(
        "<IIQI", data, 0)
    rec["version"] = version
    rec["user_data"] = user_data
    rec["entry_count_declared"] = count
    if arcd_size is None:
        rec["walk_failed"] = "sibling .arcd data file is missing"
        return rec
    if count > MAX_ENTRIES:
        rec["walk_failed"] = (
            f"declared entry_count {count} exceeds the "
            f"plausibility cap {MAX_ENTRIES}")
        return rec
    need = HEADER_SIZE + count * ENTRY_SIZE
    if need > len(data):
        rec["walk_failed"] = (
            f"declared entry_count {count} needs {need} index "
            f"bytes but the index is {len(data)} bytes")
        return rec
    entries = []
    total = 0
    compressed = 0
    encrypted = 0
    for i in range(count):
        off = HEADER_SIZE + i * ENTRY_SIZE
        ehash, eoff, esize, eflags = struct.unpack_from(
            "<QIII", data, off)
        if ehash == 0:
            rec["walk_failed"] = f"entry {i} has a zero hash"
            return rec
        if eoff + esize > arcd_size:
            rec["walk_failed"] = (
                f"entry {i} offset+size ({eoff}+{esize}) "
                f"exceeds the .arcd size {arcd_size}")
            return rec
        total += esize
        if eflags & FLAG_COMPRESSED:
            compressed += 1
        if eflags & FLAG_ENCRYPTED:
            encrypted += 1
        entries.append({"hash": ehash, "offset": eoff,
                        "size": esize, "flags": eflags})
    largest = sorted(entries, key=lambda e: -e["size"])[:10]
    rec["entries"] = {
        "count": len(entries),
        "total_payload_bytes": total,
        "compressed_count": compressed,
        "encrypted_count": encrypted,
        "largest": [{"hash": f"{e['hash']:016x}",
                     "offset": e["offset"], "size": e["size"],
                     "flags": e["flags"]} for e in largest],
    }
    return rec


def _root_names(resolved):
    names = []
    for root in resolved.assets_roots:
        try:
            with zipfile.ZipFile(root) as zf:
                names.extend(zf.namelist())
        except (zipfile.BadZipFile, OSError):
            continue
    return names


def _root_members(resolved):
    """(archive_label, member, data_or_None, size) for every
    .arci member (data capped) plus .arcd sizes by member."""
    arcis = []
    arcd_sizes = {}
    for root in resolved.assets_roots:
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
                if low.endswith(".arcd"):
                    arcd_sizes[info.filename] = info.file_size
                elif low.endswith(".arci"):
                    if info.file_size > MEMBER_CAP_BYTES:
                        arcis.append((label, info.filename,
                                      None, info.file_size))
                    else:
                        arcis.append((label, info.filename,
                                      zf.read(info.filename),
                                      info.file_size))
    return arcis, arcd_sizes


def _pair_arcd(arci_member, arcd_sizes):
    stem = arci_member[:-len(".arci")]
    for cand in (stem + ".arcd", stem + ".ARCD"):
        if cand in arcd_sizes:
            return cand, arcd_sizes[cand]
    # Fall back to any .arcd in the same directory.
    folder = arci_member.rsplit("/", 1)[0] if "/" in arci_member else ""
    for name, size in arcd_sizes.items():
        if (name.rsplit("/", 1)[0] if "/" in name else "") == folder:
            return name, size
    return None, None


def inspect(target):
    if not os.path.isfile(target):
        raise FileNotFoundError(f"not a file: {target}")
    resolved = container_mod.resolve_target(target)
    try:
        report = {"tool": "nar-defold", "version": VERSION,
                  "target": os.path.abspath(target),
                  "container": resolved.container_block(),
                  "verdict": "absent", "archives": [],
                  "archive": None, "boundary": BOUNDARY,
                  "limitations": [
                      "The .arci layout is implemented from "
                      "public Defold engine documentation/"
                      "source; no real Defold corpus is "
                      "available locally, so the parse is "
                      "synthetic-fixture verified only."]}
        archives = []
        low_name = os.path.basename(target).lower()
        roots = list(resolved.assets_roots)
        if not roots and not resolved.is_container and \
                zipfile.is_zipfile(target):
            roots = [os.path.abspath(target)]
        if low_name.endswith(".arci") and not resolved.is_container:
            with open(target, "rb") as fh:
                data = fh.read(MEMBER_CAP_BYTES + 1)
            if len(data) > MEMBER_CAP_BYTES:
                rec = {"source": os.path.basename(target),
                       "arci_size": os.path.getsize(target),
                       "arcd_size": None, "version": None,
                       "entries": None,
                       "walk_failed": "index exceeds the "
                                      "32 MiB read cap"}
            else:
                sibling = target[:-len(".arci")] + ".arcd"
                arcd_size = (os.path.getsize(sibling)
                             if os.path.isfile(sibling) else None)
                rec = parse_arci(data, arcd_size)
                rec["source"] = os.path.basename(target)
                rec["arcd_source"] = (
                    os.path.basename(sibling)
                    if arcd_size is not None else None)
            archives.append(rec)
        elif low_name.endswith(".arcd") and not resolved.is_container:
            archives.append({
                "source": os.path.basename(target),
                "arci_size": None,
                "arcd_size": os.path.getsize(target),
                "version": None, "entries": None,
                "walk_failed": "bare .arcd without its .arci "
                               "index; data file identified "
                               "only"})
        else:
            # Re-resolve roots for member scanning: build a
            # shallow resolved-like view over the roots found.
            class _View:
                assets_roots = roots
            arcis, arcd_sizes = _root_members(_View())
            for label, member, data, size in arcis:
                arcd_member, arcd_size = _pair_arcd(
                    member, arcd_sizes)
                if data is None:
                    rec = {"source": member,
                           "source_archive": label,
                           "arci_size": size,
                           "arcd_size": arcd_size,
                           "version": None, "entries": None,
                           "walk_failed": "index exceeds the "
                                          "32 MiB read cap"}
                else:
                    rec = parse_arci(data, arcd_size)
                    rec["source"] = member
                    rec["source_archive"] = label
                    rec["arcd_source"] = arcd_member
                archives.append(rec)
            if not arcis and arcd_sizes:
                for member, size in sorted(arcd_sizes.items()):
                    archives.append({
                        "source": member, "arci_size": None,
                        "arcd_size": size, "version": None,
                        "entries": None,
                        "walk_failed": ".arcd data file "
                                       "without a sibling "
                                       ".arci index"})
        names = _root_names(resolved) if roots else []
        projectc = [n for n in names
                    if n.lower().endswith("game.projectc")]
        dmanifest = [n for n in names
                     if n.lower().endswith("game.dmanifest")]
        liveupdate = [n for n in names
                      if "liveupdate" in n.lower()
                      and not n.endswith("/")]
        report["project_files"] = {
            "game_projectc": projectc,
            "game_dmanifest": dmanifest,
            "liveupdate_members": liveupdate}
        report["archives"] = archives
        report["archive"] = archives[0] if archives else None
        if archives or projectc or dmanifest:
            report["verdict"] = "present"
        return report
    finally:
        resolved.cleanup()


def human(report):
    lines = [f"NAR Defold inspection: {report['target']}",
             f"Verdict: {report['verdict']}"]
    for rec in report["archives"]:
        lines.append(
            f"Archive: {rec.get('source')} "
            f"(arci {rec.get('arci_size')}, "
            f"arcd {rec.get('arcd_size')}, "
            f"version {rec.get('version')})")
        if rec.get("entries"):
            e = rec["entries"]
            lines.append(
                f"  entries: {e['count']}, "
                f"{e['total_payload_bytes']:,} payload bytes, "
                f"{e['compressed_count']} compressed, "
                f"{e['encrypted_count']} encrypted")
        else:
            lines.append(f"  walk failed: {rec.get('walk_failed')}")
    pf = report.get("project_files") or {}
    lines.append(f"game.projectc: {pf.get('game_projectc')}; "
                 f"game.dmanifest: {pf.get('game_dmanifest')}; "
                 f"liveupdate members: "
                 f"{len(pf.get('liveupdate_members') or [])}")
    lines.append(f"Boundary: {report['boundary']}")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR Defold .arci/.arcd archive inspector.")
    p.add_argument("target", help="path to an .apk, a container, "
                                  "or a bare .arci/.arcd file")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    try:
        report = inspect(args.target)
    except FileNotFoundError as e:
        print(f"nar-defold: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(human(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
