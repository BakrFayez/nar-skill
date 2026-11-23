#!/usr/bin/env python3
"""nar-godot.py: inspect a Godot .pck pack (standalone or inside an APK).

Parses the PCK header and file directory directly, stdlib only:
magic GDPC, pack format version, engine version, the pack-level
encryption flag (format 2+), and the contained file list with sizes.
Format 3 (Godot 4.5+) moves the directory to the end of the pack:
the header gains a directory-offset field and entry offsets are
relative to the file base. When the stdlib parse cannot read the
directory (an encrypted pack encrypts its directory too),
GodotPckTool is used as a fallback when installed; if neither
works, the header facts are reported and the listing is honestly
marked unavailable.

For an APK: embedded *.pck files are listed; an APK with the Godot
engine library but no .pck ships its project files loose under
assets/ instead, and that is what gets reported.

Usage:
    python3 nar-godot.py game.pck [--json] [--limit N]
    python3 nar-godot.py game.apk [--json] [--limit N]

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

PCK_MAGIC = b"GDPC"
FLAG_ENCRYPTED = 0x1
FLAG_RELATIVE_BASE = 0x2


class PckError(Exception):
    pass


def parse_pck(data):
    """Parse header + directory. Returns a report dict (no file list
    truncation; callers slice for display). Raises PckError."""
    if len(data) < 32 or data[:4] != PCK_MAGIC:
        raise PckError("no GDPC magic: not a Godot .pck file")
    fmt, vmaj, vmin, vpatch = struct.unpack_from("<IIII", data, 4)
    report = {"format_version": fmt,
              "engine_version": f"{vmaj}.{vmin}.{vpatch}",
              "size_bytes": len(data)}
    if fmt >= 2:
        flags, file_base = struct.unpack_from("<IQ", data, 20)
        report["pack_flags"] = flags
        report["encrypted"] = bool(flags & FLAG_ENCRYPTED)
        # Entry offsets are stored relative to the file base in
        # format 3 (always) and in format 2 when the relative-base
        # flag is set; in plain format 2 they are absolute.
        base = file_base if (fmt >= 3
                             or flags & FLAG_RELATIVE_BASE) else 0
        if fmt == 2:
            dir_offset = 96  # header + 16 reserved uint32
        elif fmt == 3:
            # Format 3 header is 104 bytes and the directory sits
            # at the recorded offset (the end of the pack), not
            # right after the header.
            dir_offset = struct.unpack_from("<Q", data, 32)[0]
            report["directory_offset"] = dir_offset
        else:
            dir_offset = None  # newer layout this reader does not know
    elif fmt == 1:
        file_base = struct.unpack_from("<Q", data, 20)[0]
        report["pack_flags"] = None
        report["encrypted"] = None  # v1 header carries no flag field
        dir_offset = 92
        base = 0
    else:
        raise PckError(f"unknown pack format version {fmt}")
    report["file_base"] = file_base
    if report["encrypted"]:
        report["files"] = []
        report["file_count"] = None
        report["listing_error"] = (
            "pack is flagged encrypted; the directory is encrypted"
            " too and cannot be listed without the key")
        return report
    if dir_offset is None:
        report["files"] = []
        report["file_count"] = None
        report["listing_error"] = (
            f"pack format {fmt} directory layout is not supported"
            " by this reader; only the header facts above are"
            " reported")
        return report
    if dir_offset + 4 > len(data):
        raise PckError("directory offset points outside the pack")
    pos = dir_offset
    if pos + 4 > len(data):
        raise PckError("truncated before the file directory")
    count = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    if count > 1_000_000:
        raise PckError(f"implausible file count in directory: {count}")
    files = []
    for _ in range(count):
        if pos + 4 > len(data):
            raise PckError("directory is truncated")
        plen = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if plen == 0 or plen > 8192 or pos + plen > len(data):
            raise PckError("directory entry has an implausible path"
                           " length; the directory may be encrypted"
                           " or the layout differs")
        raw = data[pos:pos + plen]
        pos += (plen + 3) & ~3
        try:
            path = raw.rstrip(b"\x00").decode("utf-8")
        except UnicodeDecodeError as e:
            raise PckError(f"directory path does not decode: {e}") from e
        if pos + 32 > len(data):
            raise PckError("directory is truncated at entry data")
        off, size = struct.unpack_from("<QQ", data, pos)
        pos += 16
        pos += 16  # MD5 of the file data
        entry_flags = 0
        if fmt >= 2:
            entry_flags = struct.unpack_from("<I", data, pos)[0]
            pos += 4
        if base + off + size > len(data):
            raise PckError(f"entry {path!r} points outside the pack"
                           " (offset+size beyond end of file)")
        files.append({"path": path, "offset": base + off,
                      "size_bytes": size,
                      "flags": entry_flags,
                      "encrypted": bool(entry_flags & FLAG_ENCRYPTED)})
    report["files"] = files
    report["file_count"] = len(files)
    report["total_content_bytes"] = sum(f["size_bytes"] for f in files)
    return report


def find_godotpcktool():
    cand = shutil.which("godotpcktool")
    if cand:
        return cand
    path = os.path.expanduser("~/workspace/tools/godotpcktool/godotpcktool")
    return path if os.path.isfile(path) else None


def tool_listing(pck_path):
    """Fallback listing via GodotPckTool. Returns (files, error)."""
    tool = find_godotpcktool()
    if not tool:
        return None, "GodotPckTool is not installed"
    try:
        proc = subprocess.run([tool, "-p", pck_path, "-a", "list"],
                              capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, f"GodotPckTool did not run: {e}"
    files = []
    for line in proc.stdout.splitlines():
        path, sep, size = line.rpartition(" size: ")
        if sep and size.strip().isdigit():
            files.append({"path": path.strip(),
                          "size_bytes": int(size.strip())})
    if not files:
        return None, ("GodotPckTool produced no parseable listing"
                      f" (exit {proc.returncode})")
    return files, None


def inspect_pck_bytes(data, label):
    report = {"source": label, "listing_via": "stdlib"}
    try:
        parsed = parse_pck(data)
        report.update(parsed)
    except PckError as e:
        report["parse_error"] = str(e)
    return report


def loose_project_files(names):
    """Entries that make up a loose (no-.pck) Godot export.

    The anchor is the compiled project file: exports ship
    assets/project.binary (Godot 3.1+ and 4) or, in source form,
    assets/project.godot. When the anchor is present, the whole
    assets/ tree except the dexopt profiles IS the exported
    project. Without an anchor, only the Godot-specific subtrees
    count: .godot/ (editor data), .import/ (the import cache with
    its .stex/.ctex resources), and stray project.godot files.
    """
    if any(n in ("assets/project.binary", "assets/project.godot")
           for n in names):
        return [n for n in names
                if n.startswith("assets/")
                and not n.startswith("assets/dexopt/")
                and not n.endswith("/")]
    return [n for n in names
            if n.startswith("assets/.godot/")
            or n.startswith("assets/.import/")
            or n.endswith("project.godot")]


def inspect(target):
    report = {"tool": "nar-godot", "target": os.path.abspath(target),
              "is_godot": False}
    if not os.path.isfile(target):
        raise FileNotFoundError(f"not a file: {target}")
    if target.lower().endswith(".pck"):
        with open(target, "rb") as fh:
            data = fh.read()
        sub = inspect_pck_bytes(data, os.path.basename(target))
        report["is_godot"] = "parse_error" not in sub
        report["pck"] = sub
        if "parse_error" in sub:
            files, err = tool_listing(target)
            if files is not None:
                sub["files"] = files
                sub["file_count"] = len(files)
                sub["listing_via"] = "godotpcktool"
                report["is_godot"] = True
            else:
                sub["fallback_error"] = err
        return report
    if not zipfile.is_zipfile(target):
        report["error"] = "target is neither a .pck nor an APK/ZIP"
        return report
    with zipfile.ZipFile(target) as zf:
        names = zf.namelist()
        report["has_godot_engine_lib"] = any(
            "libgodot" in n for n in names)
        pcks = [n for n in names if n.lower().endswith(".pck")]
        report["embedded_pcks"] = pcks
        loose = loose_project_files(names)
        report["loose_project_files"] = len(loose)
        report["is_godot"] = bool(report["has_godot_engine_lib"]
                                  or pcks or loose)
        if pcks:
            data = zf.read(pcks[0])
            sub = inspect_pck_bytes(data, pcks[0])
            report["pck"] = sub
            if "parse_error" in sub:
                tmp = os.path.join(tempfile.mkdtemp(prefix="nar-godot-"),
                                   os.path.basename(pcks[0]))
                with open(tmp, "wb") as fh:
                    fh.write(data)
                files, err = tool_listing(tmp)
                if files is not None:
                    sub["files"] = files
                    sub["file_count"] = len(files)
                    sub["listing_via"] = "godotpcktool"
                else:
                    sub["fallback_error"] = err
        elif report["is_godot"]:
            report["note"] = (
                "no embedded .pck: this export ships its project files"
                f" loose ({len(loose)} project files under assets/),"
                " so there is no pack directory to list")
    return report


def human(report, limit):
    lines = [f"NAR Godot pack inspection: {report['target']}"]
    if not report.get("is_godot"):
        lines.append(f"NOT GODOT: {report.get('error') or 'no Godot engine lib, .pck, or project files found'}")
        return "\n".join(lines)
    pck = report.get("pck")
    if pck:
        lines.append(f"Pack: {pck['source']} (format {pck.get('format_version')},"
                     f" engine {pck.get('engine_version')},"
                     f" {pck.get('size_bytes', 0):,} bytes)")
        enc = pck.get("encrypted")
        lines.append("Encryption: " + (
            "YES (pack flag)" if enc else
            "no (pack flag clear)" if enc is False else
            "unknown (format 1 header has no flag field)"))
        if pck.get("file_count") is not None:
            lines.append(f"Files: {pck['file_count']} (listed via"
                         f" {pck.get('listing_via', 'stdlib')}),"
                         f" {pck.get('total_content_bytes', 0):,} content bytes")
            shown = pck["files"] if limit <= 0 else pck["files"][:limit]
            for f in shown:
                mark = " [encrypted]" if f.get("encrypted") else ""
                lines.append(f"  {f['path']} ({f['size_bytes']:,} bytes)"
                             f"{mark}")
            if len(shown) < pck["file_count"]:
                lines.append(f"  ... and {pck['file_count'] - len(shown)} more"
                             " (raise --limit, or use --json for all)")
        else:
            lines.append(f"Listing unavailable: "
                         f"{pck.get('listing_error') or pck.get('parse_error')}"
                         f"{'; fallback: ' + pck['fallback_error'] if pck.get('fallback_error') else ''}")
    if report.get("note"):
        lines.append(report["note"])
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR Godot .pck inspector (stdlib header/directory"
                    " parse, GodotPckTool fallback).")
    p.add_argument("target", help="path to a .pck file or an .apk")
    p.add_argument("--json", action="store_true",
                   help="machine-readable JSON output")
    p.add_argument("--limit", type=int, default=50,
                   help="max files to print in human output (default 50)")
    args = p.parse_args(argv)
    try:
        report = inspect(args.target)
    except FileNotFoundError as e:
        print(f"nar-godot: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(human(report, args.limit))
    return 0 if report.get("is_godot") else 1


if __name__ == "__main__":
    sys.exit(main())
