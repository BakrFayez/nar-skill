#!/usr/bin/env python3
"""nar-qt.py: inspect Qt .rcc resource archives.

Finds *.rcc members in a target's asset roots (resolved
through narlib.container, splits merged) and also accepts a
bare .rcc file as the target.

Qt RCC binary format (public Qt documentation / rcc.cpp):
a 20-byte header of big-endian u32 fields — magic
0x71726573 ("qres"), format version (1 or 2), tree offset,
data offset, names offset (all from file start). Names
section entries are: u16 BE length (in characters), u32 BE
hash, then length x u16 BE UTF-16BE characters. Tree nodes
are 22-byte records: name_offset u32 BE (relative to the
names section), flags u16 BE (0x01 = directory, 0x02 =
compressed), country u16 BE, language u16 BE, data_offset
u32 BE (relative to the data section; for files, a u32 BE
length followed by the payload — a compressed payload is
a u32 BE uncompressed length followed by a zlib stream),
child_count u32 BE, first_child u32 BE.

The tree is walked recursively from node 0 (bounded:
<= 100k nodes, depth <= 64) and every offset is validated
before use; a failed validation degrades the archive to
identification + header facts with the failed check named.
.qmlc/.jsc members are identification only (extension,
size, first-8-bytes hex).

Layout knowledge note: the RCC layout here is from public
Qt documentation, not from a local real Qt corpus (no real
Qt corpus is available locally); the parser is synthetic-
fixture verified only.

Usage:
    python3 nar-qt.py app.apk [--json]
    python3 nar-qt.py resources.rcc [--json]

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
RCC_MAGIC = 0x71726573  # "qres"
HEADER_SIZE = 20
NODE_SIZE = 22
MAX_NODES = 100_000
MAX_DEPTH = 64
RESOURCE_LIST_CAP = 500

FLAG_DIRECTORY = 0x01
FLAG_COMPRESSED = 0x02


def _read_name(data, names_offset, rel_offset):
    """One names-section entry; the decoded name or None."""
    pos = names_offset + rel_offset
    if pos < 0 or pos + 6 > len(data):
        return None
    length, _hash = struct.unpack_from(">HI", data, pos)
    if length > 4096 or pos + 6 + length * 2 > len(data):
        return None
    raw = data[pos + 6:pos + 6 + length * 2]
    try:
        return raw.decode("utf-16-be")
    except UnicodeDecodeError:
        return None


def parse_rcc(data, source):
    """Parse one .rcc blob. Never raises on bad data."""
    rec = {"source": source, "size_bytes": len(data),
           "header": None, "resources": None,
           "resource_count": None, "resources_truncated": False,
           "totals": None, "walk_failed": None}
    if len(data) < HEADER_SIZE:
        rec["walk_failed"] = (
            f"file is {len(data)} bytes, shorter than the "
            f"{HEADER_SIZE}-byte RCC header")
        return rec
    magic, fmt, tree_off, data_off, names_off = struct.unpack_from(
        ">IIIII", data, 0)
    rec["header"] = {"magic_ok": magic == RCC_MAGIC,
                     "version": fmt, "tree_offset": tree_off,
                     "data_offset": data_off,
                     "names_offset": names_off}
    if magic != RCC_MAGIC:
        rec["walk_failed"] = "bad magic: not a Qt RCC file"
        return rec
    if fmt not in (1, 2):
        rec["walk_failed"] = f"unsupported RCC version {fmt}"
        return rec
    for label, off in (("tree", tree_off), ("data", data_off),
                       ("names", names_off)):
        if off >= len(data):
            rec["walk_failed"] = (
                f"{label} offset {off} is outside the "
                f"{len(data)}-byte file")
            return rec
    max_nodes = (len(data) - tree_off) // NODE_SIZE
    resources = []
    state = {"visited": 0, "directories": 0, "total_bytes": 0,
             "error": None}

    def read_node(index):
        pos = tree_off + index * NODE_SIZE
        if index < 0 or pos + NODE_SIZE > len(data):
            return None
        fields = struct.unpack_from(">IHHHIII", data, pos)
        return {"name_offset": fields[0], "flags": fields[1],
                "country": fields[2], "language": fields[3],
                "data_offset": fields[4],
                "child_count": fields[5],
                "first_child": fields[6]}

    def walk(index, prefix, depth):
        if state["error"] is not None:
            return
        if depth > MAX_DEPTH:
            state["error"] = f"tree depth exceeds {MAX_DEPTH}"
            return
        state["visited"] += 1
        if state["visited"] > MAX_NODES:
            state["error"] = f"tree walk exceeds {MAX_NODES} nodes"
            return
        node = read_node(index)
        if node is None:
            state["error"] = f"tree node {index} is outside the file"
            return
        name = _read_name(data, names_off, node["name_offset"])
        if name is None:
            state["error"] = (
                f"tree node {index} name_offset "
                f"{node['name_offset']} does not resolve in "
                "the names section")
            return
        path = f"{prefix}/{name}" if prefix and name else \
            (prefix or name)
        if node["flags"] & FLAG_DIRECTORY:
            state["directories"] += 1
            first = node["first_child"]
            count = node["child_count"]
            if count > MAX_NODES or first + count > max_nodes + 1:
                state["error"] = (
                    f"directory node {index} declares "
                    f"{count} children from index {first}, "
                    "outside the tree section")
                return
            for child in range(first, first + count):
                walk(child, path, depth + 1)
                if state["error"] is not None:
                    return
        else:
            dpos = data_off + node["data_offset"]
            if dpos + 4 > len(data):
                state["error"] = (
                    f"file node {index} ({path!r}) data_offset "
                    f"{node['data_offset']} is outside the "
                    "data section")
                return
            size = struct.unpack_from(">I", data, dpos)[0]
            if dpos + 4 + size > len(data):
                state["error"] = (
                    f"file node {index} ({path!r}) declares "
                    f"{size} data bytes, outside the file")
                return
            entry = {"path": path, "size": size,
                     "compressed": bool(
                         node["flags"] & FLAG_COMPRESSED)}
            if entry["compressed"] and size >= 4 and \
                    dpos + 8 <= len(data):
                entry["uncompressed_size"] = struct.unpack_from(
                    ">I", data, dpos + 4)[0]
            resources.append(entry)
            state["total_bytes"] += size

    walk(0, "", 0)
    if state["error"] is not None:
        rec["walk_failed"] = state["error"]
        return rec
    rec["resources"] = resources[:RESOURCE_LIST_CAP]
    rec["resource_count"] = len(resources)
    rec["resources_truncated"] = len(resources) > RESOURCE_LIST_CAP
    rec["totals"] = {"resource_count": len(resources),
                     "directory_count": state["directories"],
                     "total_bytes": state["total_bytes"]}
    return rec


def _collect(resolved, roots):
    rccs, identified = [], []
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
                if low.endswith(".rcc"):
                    if info.file_size > MEMBER_CAP_BYTES:
                        rccs.append({
                            "source": info.filename,
                            "source_archive": label,
                            "size_bytes": info.file_size,
                            "header": None, "resources": None,
                            "walk_failed": "member exceeds the "
                                           "32 MiB read cap"})
                    else:
                        rec = parse_rcc(
                            zf.read(info.filename), info.filename)
                        rec["source_archive"] = label
                        rccs.append(rec)
                elif low.endswith((".qmlc", ".jsc")):
                    head = b""
                    if info.file_size <= MEMBER_CAP_BYTES:
                        try:
                            with zf.open(info.filename) as fh:
                                head = fh.read(8)
                        except (KeyError, OSError, RuntimeError):
                            head = b""
                    identified.append({
                        "member": info.filename,
                        "kind": low.rsplit(".", 1)[-1],
                        "size_bytes": info.file_size,
                        "first8_hex": head.hex(),
                        "source_archive": label})
    return rccs, identified


def inspect(target):
    if not os.path.isfile(target):
        raise FileNotFoundError(f"not a file: {target}")
    resolved = container_mod.resolve_target(target)
    try:
        report = {"tool": "nar-qt", "version": VERSION,
                  "target": os.path.abspath(target),
                  "container": resolved.container_block(),
                  "verdict": "absent", "archives": [],
                  "resources": None, "totals": None,
                  "identified": [],
                  "limitations": [
                      "The RCC layout is implemented from "
                      "public Qt documentation; no real Qt "
                      "corpus is available locally, so the "
                      "parse is synthetic-fixture verified "
                      "only.",
                      ".qmlc/.jsc members are identification "
                      "only; their bytecode is not decoded."]}
        rccs, identified = [], []
        low = os.path.basename(target).lower()
        if not resolved.is_container and low.endswith(".rcc"):
            with open(target, "rb") as fh:
                data = fh.read(MEMBER_CAP_BYTES + 1)
            if len(data) > MEMBER_CAP_BYTES:
                rccs.append({"source": os.path.basename(target),
                             "size_bytes": os.path.getsize(target),
                             "header": None, "resources": None,
                             "walk_failed": "file exceeds the "
                                            "32 MiB read cap"})
            else:
                rccs.append(parse_rcc(data, os.path.basename(target)))
        else:
            roots = list(resolved.assets_roots)
            if not roots and not resolved.is_container and \
                    zipfile.is_zipfile(target):
                roots = [os.path.abspath(target)]
            rccs, identified = _collect(resolved, roots)
        report["archives"] = rccs
        report["identified"] = identified
        if rccs:
            report["resources"] = rccs[0].get("resources")
            report["totals"] = rccs[0].get("totals")
        if rccs or any(i["kind"] == "qmlc" for i in identified):
            report["verdict"] = "present"
        return report
    finally:
        resolved.cleanup()


def human(report):
    lines = [f"NAR Qt inspection: {report['target']}",
             f"Verdict: {report['verdict']}"]
    for rec in report["archives"]:
        hdr = rec.get("header") or {}
        lines.append(f"RCC: {rec.get('source')} "
                     f"(version {hdr.get('version')}, magic ok: "
                     f"{hdr.get('magic_ok')})")
        if rec.get("resources") is not None:
            lines.append(f"  resources: {rec.get('resource_count')}"
                         f", totals: {rec.get('totals')}")
            for r in rec["resources"][:50]:
                lines.append(f"    {r['path']} ({r['size']} bytes"
                             f"{', compressed' if r['compressed'] else ''})")
        else:
            lines.append(f"  walk failed: {rec.get('walk_failed')}")
    for item in report["identified"]:
        lines.append(f"Identified: {item['member']} "
                     f"({item['kind']}, {item['size_bytes']} bytes, "
                     f"first8 {item['first8_hex']})")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR Qt .rcc resource archive inspector.")
    p.add_argument("target", help="path to an .apk, a container, "
                                  "or a bare .rcc file")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    try:
        report = inspect(args.target)
    except FileNotFoundError as e:
        print(f"nar-qt: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(human(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
