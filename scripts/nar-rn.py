#!/usr/bin/env python3
"""nar-rn.py: inspect a React Native JS bundle inside an APK.

Extracts assets/index.android.bundle (or another *.bundle /
*.jsbundle asset) to a work directory, then identifies the JS
engine that compiled it:

- Hermes: the 8-byte bytecode magic is checked and the bytecode
  version, function count, and string counts are read straight from
  the Hermes file header (stdlib). When hermes-dec is installed its
  hbc-file-parser output is used as a cross-check.
- JSC / plain JS: no Hermes magic; the bundle ships as JavaScript
  text and that is what gets reported.

Usage:
    python3 nar-rn.py app.apk [--json] [--work DIR]

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

HERMES_MAGIC = struct.pack("<Q", 0x1F1903C103BC1FC6)
BUNDLE_CANDIDATES = ("assets/index.android.bundle",)


def find_bundle(names):
    for cand in BUNDLE_CANDIDATES:
        if cand in names:
            return cand
    others = [n for n in names
              if n.startswith("assets/")
              and (n.endswith(".bundle") or n.endswith(".jsbundle"))]
    return others[0] if others else None


def parse_hermes_header(data):
    """Hermes BytecodeFileHeader fields at fixed offsets."""
    version, = struct.unpack_from("<I", data, 8)
    fields = struct.unpack_from("<10I", data, 32)
    keys = ("file_length", "global_code_index", "function_count",
            "string_kind_count", "identifier_count", "string_count",
            "overflow_string_count", "string_storage_size",
            "big_int_count", "big_int_storage_size")
    header = {"bytecode_version": version}
    header.update(dict(zip(keys, fields)))
    return header


def find_hbc_parser():
    cand = shutil.which("hbc-file-parser")
    if cand:
        return cand, None
    path = os.path.expanduser("~/workspace/tools/hermes-dec/bin/hbc-file-parser")
    if os.path.isfile(path):
        root = os.path.expanduser("~/workspace/tools/hermes-dec")
        return path, root
    return None, None


def hbc_cross_check(bundle_path):
    """Run hbc-file-parser; return (info_dict, error)."""
    parser, root = find_hbc_parser()
    if not parser:
        return None, "hermes-dec (hbc-file-parser) is not installed"
    env = dict(os.environ)
    if root:
        env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")
    try:
        proc = subprocess.run([sys.executable, parser, bundle_path],
                              capture_output=True, text=True, timeout=600,
                              env=env)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, f"hbc-file-parser did not run: {e}"
    out = proc.stdout or ""
    info = {}
    for key, pat in (("version", r"Version\s*\|\s*(\d+)"),
                     ("function_count", r"FunctionCount\s*\|\s*(\d+)"),
                     ("string_count", r"StringCount\s*\|\s*(\d+)")):
        m = re.search(pat, out)
        if m:
            info[key] = int(m.group(1))
    if not info:
        return None, ("hbc-file-parser produced no parseable header"
                      f" (exit {proc.returncode})")
    info["ran"] = True
    return info, None


def inspect(apk_path, work_dir):
    report = {"tool": "nar-rn", "file": os.path.basename(apk_path),
              "path": os.path.abspath(apk_path), "is_react_native": False}
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"not a file: {apk_path}")
    if not zipfile.is_zipfile(apk_path):
        report["error"] = "not a ZIP/APK file"
        return report
    with zipfile.ZipFile(apk_path) as zf:
        entry = find_bundle(zf.namelist())
        if entry is None:
            report["note"] = ("no JS bundle asset (index.android.bundle"
                               " or *.jsbundle) found: not a React"
                               " Native build, or the bundle ships"
                               " elsewhere")
            return report
        report["is_react_native"] = True
        report["bundle_entry"] = entry
        data = zf.read(entry)
    os.makedirs(work_dir, exist_ok=True)
    out_path = os.path.join(work_dir, os.path.basename(entry))
    with open(out_path, "wb") as fh:
        fh.write(data)
    report["bundle_path"] = os.path.abspath(out_path)
    report["bundle_size_bytes"] = len(data)
    if data[:8] == HERMES_MAGIC:
        report["engine"] = "Hermes"
        report["is_hermes"] = True
        header = parse_hermes_header(data)
        report["hermes"] = header
        info, err = hbc_cross_check(out_path)
        report["hermes_dec"] = info if info else {"ran": False,
                                                  "error": err}
        if info:
            report["cross_check_agrees"] = (
                info.get("function_count") == header["function_count"]
                and info.get("version") == header["bytecode_version"])
    else:
        report["engine"] = "JSC / plain JavaScript"
        report["is_hermes"] = False
        sample = data[:4096]
        printable = sum(1 for b in sample if 9 <= b <= 126)
        report["looks_like_text_js"] = bool(sample) and \
            printable / max(len(sample), 1) > 0.95
        report["first_bytes_hex"] = data[:16].hex()
    return report


def human(report):
    lines = [f"NAR React Native bundle: {report['file']}"]
    if not report.get("is_react_native"):
        lines.append(f"NOT REACT NATIVE: "
                     f"{report.get('note') or report.get('error')}")
        return "\n".join(lines)
    lines.append(f"Bundle: {report['bundle_entry']}"
                 f" ({report['bundle_size_bytes']:,} bytes)"
                 f" -> {report['bundle_path']}")
    lines.append(f"Engine: {report['engine']}")
    if report.get("is_hermes"):
        h = report["hermes"]
        lines.append(f"Hermes bytecode version: {h['bytecode_version']}")
        lines.append(f"Functions: {h['function_count']:,};"
                     f" strings: {h['string_count']:,};"
                     f" identifiers: {h['identifier_count']:,}")
        dec = report.get("hermes_dec") or {}
        if dec.get("ran"):
            lines.append(f"hermes-dec cross-check: ran;"
                         f" agrees with header parse:"
                         f" {report.get('cross_check_agrees')}")
        else:
            lines.append(f"hermes-dec cross-check: unavailable"
                         f" ({dec.get('error')})")
    else:
        lines.append(f"Ships as JavaScript text: "
                     f"{report['looks_like_text_js']}")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR React Native bundle inspector (Hermes vs JSC).")
    p.add_argument("apk", help="path to the .apk file")
    p.add_argument("--json", action="store_true",
                   help="machine-readable JSON output")
    p.add_argument("--work", metavar="DIR",
                   help="directory the bundle is extracted to"
                        " (default: temp dir)")
    args = p.parse_args(argv)
    stem = os.path.splitext(os.path.basename(args.apk))[0] or "app"
    work_dir = args.work or os.path.join(
        tempfile.gettempdir(), f"nar-rn-{stem}")
    try:
        report = inspect(args.apk, work_dir)
    except FileNotFoundError as e:
        print(f"nar-rn: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(human(report))
    return 0 if report.get("is_react_native") else 1


if __name__ == "__main__":
    sys.exit(main())
