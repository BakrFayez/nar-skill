#!/usr/bin/env python3
"""nar-monogame.py: MonoGame / FNA deep dive (Part 3.2).

Reads a target through narlib.container.resolve_target and
scans the resolved asset/native roots for:

- the framework assembly: MonoGame.Framework.dll, loose or
  carved out of an assemblies.blob (the same MZ/BSJB carving
  rule nar-xamarin uses, duplicated here so each deep dive
  stays standalone), summarized with narlib.dotnetmeta;
- FNA markers: FNA.dll, FAudio (FNA.dll's native audio
  library, libFAudio.so) and libtheorafile members;
- the XNB content census: every *.xnb member's header is
  parsed — "XNB" magic, the platform byte (w=Windows,
  x=Xbox 360, m=Windows Phone, l=Linux, a=Android, ...),
  the format version byte (4 or 5), the flags byte (0x01 =
  HiDef profile, 0x80 = compressed with LZX) and the u32
  total size, which must equal the member size exactly.
  Compressed files are counted, never decoded (LZX has no
  stdlib decoder). For uncompressed files the type-reader
  table after the 10-byte header is parsed (reader count as
  a 7-bit-encoded integer, then per reader a
  length-prefixed UTF-8 name and a u32 version) and the
  census is grouped by the primary reader's short name.

Usage:
    python3 nar-monogame.py game.apk [--json]

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import struct
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import container as _container  # noqa: E402
from narlib import dotnetmeta  # noqa: E402

TOOL = "nar-monogame"
VERSION = "3.0.2"
MEMBER_CAP = 32 * 1024 * 1024        # per-member read cap
CARVE_CAP = 64 * 1024 * 1024         # per-carved-assembly cap
MAX_CARVES = 256
_PLATFORMS = {"w": "Windows", "x": "Xbox 360",
              "m": "Windows Phone", "l": "Linux",
              "a": "Android", "i": "iOS", "X": "Mac OS X",
              "r": "Raspberry Pi"}


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
    of {"offset", "data"} (at most MAX_CARVES). (Same rule
    as nar-xamarin; duplicated so this tool is standalone.)
    """
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
    """The Module table's name string, or None."""
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


def _read_7bit_int(data, pos):
    """A 7-bit-encoded integer (XNB / BinaryReader form).
    Returns (value, new_pos); raises ValueError if the
    encoding runs past the data or never terminates."""
    result = 0
    shift = 0
    while True:
        if pos >= len(data) or shift > 28:
            raise ValueError("7-bit integer overruns the data")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7


def _read_xnb_string(data, pos):
    length, pos = _read_7bit_int(data, pos)
    if length < 0 or pos + length > len(data):
        raise ValueError("string overruns the XNB data")
    return data[pos:pos + length].decode(
        "utf-8", "replace"), pos + length


def parse_xnb(data, name):
    """Header + (when uncompressed) reader-table facts for
    one .xnb member. Malformed headers raise ValueError."""
    if len(data) < 10 or data[:3] != b"XNB":
        raise ValueError("no XNB magic")
    platform = chr(data[3])
    version = data[4]
    flags = data[5]
    total_size = struct.unpack_from("<I", data, 6)[0]
    record = {
        "file": name,
        "platform": platform,
        "platform_name": _PLATFORMS.get(platform),
        "version": version,
        "flags": flags,
        "hidef_profile": bool(flags & 0x01),
        "compressed": bool(flags & 0x80),
        "declared_size": total_size,
        "size_bytes": len(data),
        "size_valid": total_size == len(data)}
    if record["compressed"]:
        record["note"] = ("compressed XNB (LZX): counted, "
                          "not decoded (no stdlib LZX)")
        return record
    # Reader table: count (7-bit int), then per reader a
    # length-prefixed name string and a u32 version.
    pos = 10
    count, pos = _read_7bit_int(data, pos)
    if count > 4096:
        raise ValueError(f"implausible reader count {count}")
    readers = []
    for _ in range(count):
        reader_name, pos = _read_xnb_string(data, pos)
        if pos + 4 > len(data):
            raise ValueError("reader table overruns the data")
        reader_version = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        readers.append({"name": reader_name,
                        "version": reader_version})
    record["readers"] = readers
    record["reader_count"] = len(readers)
    if readers:
        record["primary_reader"] = readers[0]["name"]
        record["primary_reader_short"] = \
            readers[0]["name"].rsplit(".", 1)[-1].split(",")[0] \
            .strip()
    return record


def inspect(target):
    report = {"tool": TOOL, "version": VERSION,
              "target": os.path.abspath(target),
              "notes": []}
    resolved = _container.resolve_target(target)
    try:
        report["container"] = resolved.container_block()
        scan = Scan(resolved)
        try:
            framework = {"present": False}
            with tempfile.TemporaryDirectory(
                    prefix="nar-monogame-") as tmpdir:

                def try_framework(data, source):
                    if framework["present"]:
                        return
                    path = os.path.join(tmpdir, "framework.dll")
                    with open(path, "wb") as fh:
                        fh.write(data)
                    try:
                        result = dotnetmeta.count_assembly(path)
                    except dotnetmeta.DotNetMetaError:
                        return
                    framework.update({
                        "present": True,
                        "typedef_count": result["types"],
                        "methoddef_count": result["methods"],
                        "source": source})

                for m in scan.members:
                    base = os.path.basename(m["name"])
                    if base.lower() == \
                            "monogame.framework.dll":
                        data = scan.read(m)
                        if data is not None:
                            try_framework(data, m["name"])
                    elif os.path.basename(
                            m["name"].lower()) == \
                            "assemblies.blob" or \
                            (m["name"].lower().endswith(".blob")
                             and "assemblies"
                             in m["name"].lower()):
                        data = scan.read(m)
                        if data is None:
                            continue
                        for carve in carve_assemblies(data):
                            if _module_name(carve["data"]) \
                                    and _module_name(
                                        carve["data"]).lower() \
                                    == "monogame.framework.dll":
                                try_framework(
                                    carve["data"],
                                    f"{m['name']}@"
                                    f"{carve['offset']:#x}")
            report["framework"] = framework

            fna = []
            for m in scan.members:
                base = os.path.basename(m["name"]).lower()
                if base == "fna.dll":
                    fna.append({"marker": "FNA.dll",
                                "path": m["name"]})
                elif base in ("libfaudio.so", "faudio.dll"):
                    fna.append({"marker": "FAudio",
                                "path": m["name"]})
                elif "libtheorafile" in base:
                    fna.append({"marker": "libtheorafile",
                                "path": m["name"]})
            report["fna_markers"] = fna

            files = []
            by_reader = {}
            compressed_count = 0
            invalid_count = 0
            for m in scan.members:
                if not m["name"].lower().endswith(".xnb"):
                    continue
                data = scan.read(m)
                if data is None:
                    invalid_count += 1
                    continue
                try:
                    record = parse_xnb(data, m["name"])
                except (ValueError, struct.error) as exc:
                    invalid_count += 1
                    files.append({"file": m["name"],
                                  "error": str(exc)})
                    continue
                if not record["size_valid"]:
                    invalid_count += 1
                    record["note"] = (
                        "declared total size "
                        f"{record['declared_size']} != member "
                        f"size {record['size_bytes']}")
                if record["compressed"]:
                    compressed_count += 1
                short = record.get("primary_reader_short")
                if short:
                    by_reader[short] = by_reader.get(short, 0) + 1
                files.append(record)
            report["xnb"] = {
                "count": len(files),
                "by_reader": dict(sorted(
                    by_reader.items(),
                    key=lambda kv: (-kv[1], kv[0]))),
                "compressed_count": compressed_count,
                "invalid_count": invalid_count,
                "files": files[:100]}
        finally:
            scan.close()
    finally:
        resolved.cleanup()
    report["verdict"] = "present" if (
        report["framework"]["present"]
        or report["xnb"]["count"] > 0
        or report["fna_markers"]) else "absent"
    return report


def human(report):
    lines = [f"NAR MonoGame/FNA deep dive: {report['target']}",
             f"Verdict: {report['verdict']}"]
    fw = report["framework"]
    if fw["present"]:
        lines.append(f"MonoGame.Framework.dll: present "
                     f"({fw['typedef_count']} typedefs) "
                     f"[{fw['source']}]")
    else:
        lines.append("MonoGame.Framework.dll: not found")
    for marker in report["fna_markers"]:
        lines.append(f"FNA marker: {marker['marker']} at "
                     f"{marker['path']}")
    x = report["xnb"]
    lines.append(f"XNB files: {x['count']} "
                 f"({x['compressed_count']} compressed, "
                 f"{x['invalid_count']} invalid)")
    for short, n in x["by_reader"].items():
        lines.append(f"  reader {short}: {n}")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR MonoGame / FNA deep dive.")
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
