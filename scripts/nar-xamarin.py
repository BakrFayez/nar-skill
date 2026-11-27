#!/usr/bin/env python3
"""nar-xamarin.py: Xamarin / .NET for Android deep dive
(Part 3.2).

Reads a target through narlib.container.resolve_target and
scans the resolved asset/native roots for the Xamarin
payload:

- assemblies, from both shipping shapes:
  (a) loose *.dll members (under assets/assemblies/ or any
      path ending .dll), and
  (b) assemblies.blob members: embedded assemblies are
      carved by scanning the blob for MZ headers whose span
      (to the next MZ header, or the blob end; capped at
      64 MiB per carve and 256 carves) contains the .NET
      metadata root signature "BSJB".
  Every loose/carved DLL is summarized with
  narlib.dotnetmeta (its count_assembly entry point takes a
  file path, so DLL bytes are written to a temporary
  directory, never into the repo): typedef and methoddef
  counts from the metadata tables, and the assembly name
  from the Module table's name string;
- the native runtime: libmonosgen*.so / libxamarin-app.so /
  libmonodroid*.so members with sizes;
- XALZ blocks: "XALZ" magic occurrences inside the blob are
  counted. XALZ payloads are LZ4-compressed assembly data;
  the stdlib has no LZ4 decoder, so they are identified and
  counted, never decoded;
- AssemblyStore markers: assemblies.blob members and an
  assemblies.manifest member, when present.

The verdict is "present" when a Mono runtime library is
found or at least one assembly parsed.

Usage:
    python3 nar-xamarin.py app.apk [--json]

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import fnmatch
import json
import os
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import container as _container  # noqa: E402
from narlib import dotnetmeta  # noqa: E402

TOOL = "nar-xamarin"
VERSION = "3.0.2"
MEMBER_CAP = 32 * 1024 * 1024        # per-member read cap
CARVE_CAP = 64 * 1024 * 1024         # per-carved-assembly cap
MAX_CARVES = 256
_RUNTIME_PATTERNS = ("libmonosgen*.so", "libxamarin-app.so",
                     "libmonodroid*.so")


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


def carve_assemblies(blob):
    """Carve embedded assemblies out of an assemblies.blob
    payload: every MZ header whose span (to the next MZ
    header or the blob end, capped at CARVE_CAP) contains
    the .NET metadata root signature "BSJB". Returns a list
    of {"offset", "data"} (at most MAX_CARVES)."""
    offsets = []
    pos = blob.find(b"MZ")
    while pos >= 0 and len(offsets) < 4096:
        offsets.append(pos)
        pos = blob.find(b"MZ", pos + 2)
    out = []
    for i, off in enumerate(offsets):
        if len(out) >= MAX_CARVES:
            break
        end = offsets[i + 1] if i + 1 < len(offsets) \
            else len(blob)
        chunk = blob[off:min(end, off + CARVE_CAP)]
        if b"BSJB" in chunk:
            out.append({"offset": off, "data": chunk})
    return out


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


def _module_name(data):
    """The Module table's name string (the assembly's own
    file name as recorded in its metadata), or None."""
    try:
        tables = _metadata_tables(data)
        if not tables.rows.get(dotnetmeta.T_MODULE, 0):
            return None
        base = tables.table_offset(dotnetmeta.T_MODULE)
        s = tables.str_size
        idx = dotnetmeta._unpack(
            "<I" if s == 4 else "<H", tables.data, base + 2,
            "Module name index")[0]
        return tables.string(idx) or None
    except Exception:
        return None


def summarize_dll(data, tmpdir, tag, fallback_name=None):
    """One DLL's summary via narlib.dotnetmeta, or None when
    the bytes do not parse as a .NET assembly. dotnetmeta's
    entry point takes a file path, so the bytes are written
    under a temporary directory (never the repo)."""
    path = os.path.join(tmpdir, tag)
    with open(path, "wb") as fh:
        fh.write(data)
    try:
        result = dotnetmeta.count_assembly(path)
    except dotnetmeta.DotNetMetaError:
        return None
    return {"name": _module_name(data) or fallback_name,
            "typedef_count": result["types"],
            "methoddef_count": result["methods"]}


def inspect(target):
    report = {"tool": TOOL, "version": VERSION,
              "target": os.path.abspath(target),
              "notes": []}
    resolved = _container.resolve_target(target)
    try:
        report["container"] = resolved.container_block()
        scan = Scan(resolved)
        try:
            assemblies = []
            unparseable = 0
            xalz_blocks = 0
            blob_members = []
            with tempfile.TemporaryDirectory(
                    prefix="nar-xamarin-") as tmpdir:
                serial = [0]

                def add_dll(data, source, fallback_name):
                    nonlocal unparseable
                    serial[0] += 1
                    summary = summarize_dll(
                        data, tmpdir, f"dll{serial[0]}.bin",
                        fallback_name)
                    if summary is None:
                        unparseable += 1
                        return
                    summary["source"] = source
                    assemblies.append(summary)

                for m in scan.members:
                    low = m["name"].lower()
                    if low.endswith(".dll"):
                        data = scan.read(m)
                        if data is not None:
                            add_dll(data, m["name"],
                                    os.path.basename(m["name"]))
                    elif os.path.basename(low) == \
                            "assemblies.blob" or \
                            (low.endswith(".blob")
                             and "assemblies" in low):
                        data = scan.read(m)
                        if data is None:
                            continue
                        blob_members.append(m["name"])
                        xalz_blocks += data.count(b"XALZ")
                        for carve in carve_assemblies(data):
                            add_dll(
                                carve["data"],
                                f"{m['name']}@"
                                f"{carve['offset']:#x}",
                                None)
            report["assemblies"] = {
                "count": len(assemblies),
                "unparseable": unparseable,
                "items": assemblies[:100]}
            report["xalz"] = {
                "xalz_blocks": xalz_blocks,
                "note": "LZ4-compressed assembly payloads "
                        "identified, not decoded (no stdlib "
                        "LZ4)"}
            names = [m["name"] for m in scan.members]
            report["assembly_store"] = {
                "blob_members": blob_members,
                "manifest_present": any(
                    os.path.basename(n).lower()
                    == "assemblies.manifest" for n in names),
                "assemblies_dir_dlls": sum(
                    1 for n in names
                    if "assemblies/" in n.lower()
                    and n.lower().endswith(".dll"))}
            runtime = []
            for m in scan.members:
                base = os.path.basename(m["name"]).lower()
                if any(fnmatch.fnmatchcase(base, pat)
                       for pat in _RUNTIME_PATTERNS):
                    runtime.append({"path": m["name"],
                                    "size": m["size"]})
            report["native_runtime"] = runtime
        finally:
            scan.close()
    finally:
        resolved.cleanup()
    report["verdict"] = "present" if (
        report["native_runtime"]
        or report["assemblies"]["count"] > 0) else "absent"
    return report


def human(report):
    lines = [f"NAR Xamarin deep dive: {report['target']}",
             f"Verdict: {report['verdict']}"]
    a = report["assemblies"]
    lines.append(f"Assemblies parsed: {a['count']} "
                 f"({a['unparseable']} unparseable)")
    for item in a["items"][:20]:
        lines.append(f"  {item['name']}: "
                     f"{item['typedef_count']} typedefs, "
                     f"{item['methoddef_count']} methoddefs "
                     f"[{item['source']}]")
    lines.append(f"XALZ blocks: "
                 f"{report['xalz']['xalz_blocks']} "
                 f"(identified, not decoded)")
    lines.append(f"AssemblyStore: blobs "
                 f"{report['assembly_store']['blob_members']}, "
                 f"manifest present: "
                 f"{report['assembly_store']['manifest_present']}")
    for rt in report["native_runtime"]:
        lines.append(f"Native runtime: {rt['path']} "
                     f"({rt['size']:,} bytes)")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR Xamarin / .NET deep dive.")
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
