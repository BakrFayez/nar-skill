#!/usr/bin/env python3
"""nar-mono.py: Unity Mono backend deep dive (Part 3.2).

Reads a target through narlib.container.resolve_target and
scans the resolved asset/native roots for the Unity Mono
payload:

- the Managed census: every member under a
  */bin/Data/Managed/ directory ending .dll, plus any
  Assembly-CSharp.dll wherever it sits. Each assembly is
  summarized with narlib.dotnetmeta (its count_assembly
  entry point takes a file path, so DLL bytes are written
  to a temporary directory, never into the repo): typedef
  and methoddef counts and a sample of the distinct
  namespaces;
- Assembly-CSharp facts: presence, its typedef count, and
  an obfuscation indicator computed from the TypeDef name
  strings — the share of type names that are shorter than
  2 characters or contain characters invalid in C#
  identifiers. The indicator is a labelled heuristic, not
  a proof of obfuscation;
- a backend cross-check: the libmono*.so and libil2cpp.so
  member paths, so a Mono verdict can be weighed against
  the IL2CPP backend's presence.

The verdict is "present" when at least one Managed DLL
parsed.

Usage:
    python3 nar-mono.py game.apk [--json]

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import fnmatch
import json
import os
import re
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import container as _container  # noqa: E402
from narlib import dotnetmeta  # noqa: E402

TOOL = "nar-mono"
VERSION = "3.0.2"
MEMBER_CAP = 32 * 1024 * 1024        # per-member read cap
_IDENT_OK = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class Scan:
    """Bounded member access across a resolved target's
    asset and native roots (deduplicated, base first)."""

    def __init__(self, resolved):
        self.members = []
        self._zfs = {}
        seen = set()
        for root in list(resolved.assets_roots) + \
                list(resolved.native_roots):
            if root in seen or not os.path.isfile(root):
                continue
            seen.add(root)
            try:
                zf = zipfile.ZipFile(root)
            except (zipfile.BadZipFile, OSError):
                continue
            self._zfs[root] = zf
            for info in zf.infolist():
                if info.filename.endswith("/"):
                    continue
                self.members.append({
                    "root": root,
                    "archive": os.path.basename(root),
                    "name": info.filename,
                    "size": info.file_size})

    def read(self, member, cap=MEMBER_CAP):
        if member["size"] > cap:
            return None
        try:
            return self._zfs[member["root"]].read(member["name"])
        except (KeyError, OSError, RuntimeError,
                zipfile.BadZipFile):
            return None

    def close(self):
        for zf in self._zfs.values():
            try:
                zf.close()
            except Exception:
                pass


def _metadata_tables(data):
    """Build narlib.dotnetmeta's tables view for in-memory
    DLL bytes, mirroring count_assembly's PE / CLI-header /
    stream-directory walk with the module's own helpers.
    Raises on malformed input; callers degrade to notes."""
    dm = dotnetmeta
    if data[:2] != b"MZ":
        raise dm.DotNetMetaError("not a PE file (no MZ header)")
    pe_off = dm._u32(data, 0x3C)
    if data[pe_off:pe_off + 4] != b"PE\x00\x00":
        raise dm.DotNetMetaError("no PE signature")
    coff = pe_off + 4
    section_count = dm._u16(data, coff + 2)
    opt_size = dm._u16(data, coff + 16)
    opt = coff + 20
    magic = dm._u16(data, opt)
    if magic == 0x10B:
        dd_base = opt + 96
    elif magic == 0x20B:
        dd_base = opt + 112
    else:
        raise dm.DotNetMetaError(
            f"unknown optional-header magic {magic:#x}")
    cli_rva = dm._u32(data, dd_base + 14 * 8)
    if cli_rva == 0:
        raise dm.DotNetMetaError("no CLI header")
    sections = []
    sec_base = opt + opt_size
    for i in range(section_count):
        off = sec_base + i * 40
        vsize, vaddr, raw_size, raw_ptr = dm._unpack(
            "<IIII", data, off + 8, "section header")
        sections.append((vaddr, max(vsize, raw_size), raw_ptr))

    def rva_to_off(rva):
        for vaddr, span, raw_ptr in sections:
            if vaddr <= rva < vaddr + span:
                return raw_ptr + (rva - vaddr)
        raise dm.DotNetMetaError(f"RVA {rva:#x} not in any "
                                 "section")

    cli_off = rva_to_off(cli_rva)
    meta_rva = dm._u32(data, cli_off + 8)
    meta_off = rva_to_off(meta_rva)
    if dm._u32(data, meta_off) != 0x424A5342:
        raise dm.DotNetMetaError("bad metadata root signature")
    ver_len = dm._u32(data, meta_off + 12)
    pos = meta_off + 16 + ((ver_len + 3) & ~3)
    stream_count = dm._u16(data, pos + 2)
    pos += 4
    streams = {}
    for _ in range(stream_count):
        s_off, s_size = dm._unpack(
            "<II", data, pos, "stream directory entry")
        pos += 8
        end = data.index(b"\x00", pos)
        name = data[pos:end].decode("ascii", "replace")
        pos += ((end - pos + 1) + 3) & ~3
        streams[name] = (meta_off + s_off, s_size)
    if "#~" not in streams:
        raise dm.DotNetMetaError("no #~ tables stream")
    tables_off, _ = streams["#~"]
    strings = b""
    if "#Strings" in streams:
        s_off, s_size = streams["#Strings"]
        strings = data[s_off:s_off + s_size]
    return dm._Tables(data, tables_off, strings)


def _typedef_names(data):
    """TypeDef name strings (excluding the <Module>
    pseudo-type), via narlib.dotnetmeta's tables view."""
    tables = _metadata_tables(data)
    rows = tables.rows.get(dotnetmeta.T_TYPEDEF, 0)
    names = []
    if rows:
        base = tables.table_offset(dotnetmeta.T_TYPEDEF)
        row_size = tables.row_size(dotnetmeta.T_TYPEDEF)
        s = tables.str_size
        for i in range(rows):
            row = base + i * row_size
            name_idx = dotnetmeta._unpack(
                "<I" if s == 4 else "<H", tables.data,
                row + 4, "TypeDef name index")[0]
            name = tables.string(name_idx)
            if i == 0 and name == "<Module>":
                continue
            names.append(name)
    return names


def obfuscation_indicator(data):
    """Heuristic indicator over TypeDef names, or None when
    the names cannot be read."""
    try:
        names = _typedef_names(data)
    except Exception:
        return None
    total = len(names)
    short_or_invalid = sum(
        1 for n in names
        if len(n) < 2 or not _IDENT_OK.match(n or ""))
    return {
        "short_or_invalid_names": short_or_invalid,
        "total_types": total,
        "ratio": (short_or_invalid / total) if total else 0.0,
        "basis": "heuristic: type names shorter than 2 chars "
                 "or containing characters invalid in C# "
                 "identifiers"}


def inspect(target):
    report = {"tool": TOOL, "version": VERSION,
              "target": os.path.abspath(target),
              "notes": []}
    resolved = _container.resolve_target(target)
    try:
        report["container"] = resolved.container_block()
        scan = Scan(resolved)
        try:
            candidates = []
            seen_names = set()
            for m in scan.members:
                low = m["name"].lower()
                if not low.endswith(".dll"):
                    continue
                if "/bin/data/managed/" in low or \
                        os.path.basename(low) == \
                        "assembly-csharp.dll":
                    if m["name"] not in seen_names:
                        seen_names.add(m["name"])
                        candidates.append(m)
            census = []
            unparseable = 0
            csharp = {"present": False}
            with tempfile.TemporaryDirectory(
                    prefix="nar-mono-") as tmpdir:
                for i, m in enumerate(candidates):
                    data = scan.read(m)
                    if data is None:
                        unparseable += 1
                        continue
                    path = os.path.join(tmpdir, f"a{i}.dll")
                    with open(path, "wb") as fh:
                        fh.write(data)
                    try:
                        result = dotnetmeta.count_assembly(path)
                    except dotnetmeta.DotNetMetaError:
                        unparseable += 1
                        continue
                    entry = {
                        "name": os.path.basename(m["name"]),
                        "path": m["name"],
                        "typedef_count": result["types"],
                        "methoddef_count": result["methods"],
                        "namespaces_sample": list(
                            result["namespaces"])[:10]}
                    census.append(entry)
                    if entry["name"].lower() == \
                            "assembly-csharp.dll":
                        csharp = {
                            "present": True,
                            "typedef_count": result["types"],
                            "methoddef_count":
                                result["methods"],
                            "obfuscation_indicator":
                                obfuscation_indicator(data)}
            report["managed"] = {
                "count": len(census),
                "unparseable": unparseable,
                "assemblies": census[:100]}
            report["assembly_csharp"] = csharp
            names = [m["name"] for m in scan.members]
            report["backend_crosscheck"] = {
                "libmono": [n for n in names
                            if fnmatch.fnmatchcase(
                                os.path.basename(n).lower(),
                                "libmono*.so")],
                "libil2cpp": [n for n in names
                              if os.path.basename(n).lower()
                              == "libil2cpp.so"],
                "note": "paths only: libmono*.so supports the "
                        "Mono backend; libil2cpp.so marks the "
                        "IL2CPP backend (see nar-il2cpp)"}
        finally:
            scan.close()
    finally:
        resolved.cleanup()
    report["verdict"] = "present" if \
        report["managed"]["count"] > 0 else "absent"
    return report


def human(report):
    lines = [f"NAR Unity Mono deep dive: {report['target']}",
             f"Verdict: {report['verdict']}"]
    mg = report["managed"]
    lines.append(f"Managed assemblies parsed: {mg['count']} "
                 f"({mg['unparseable']} unparseable)")
    for a in mg["assemblies"][:20]:
        lines.append(f"  {a['name']}: {a['typedef_count']} "
                     f"typedefs, {a['methoddef_count']} "
                     f"methoddefs, namespaces "
                     f"{a['namespaces_sample']}")
    cs = report["assembly_csharp"]
    lines.append(f"Assembly-CSharp: present={cs['present']}")
    if cs["present"] and cs.get("obfuscation_indicator"):
        ind = cs["obfuscation_indicator"]
        lines.append(f"  obfuscation indicator: "
                     f"{ind['short_or_invalid_names']}/"
                     f"{ind['total_types']} short-or-invalid "
                     f"type names (ratio {ind['ratio']:.2f}; "
                     f"heuristic)")
    bc = report["backend_crosscheck"]
    lines.append(f"libmono: {bc['libmono']}; libil2cpp: "
                 f"{bc['libil2cpp']}")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR Unity Mono backend deep dive.")
    p.add_argument("target", help="APK / container to inspect")
    p.add_argument("--json", action="store_true",
                   help="machine-readable JSON output")
    args = p.parse_args(argv)
    if os.path.isdir(args.target):
        # Directory targets are an input error (exit 2) on
        # every platform. This cannot be left to the open()
        # below: POSIX raises IsADirectoryError for a
        # directory open (caught under the try), but Windows
        # raises PermissionError instead, which would escape
        # as a traceback and the wrong exit code.
        print(f"{TOOL}: is a directory: {args.target}",
              file=sys.stderr)
        return 2
    if not os.path.exists(args.target):
        print(f"{TOOL}: no such target: {args.target}",
              file=sys.stderr)
        return 2
    report = inspect(args.target)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(human(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
