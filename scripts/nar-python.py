#!/usr/bin/env python3
"""nar-python.py: embedded Python / Kivy deep dive
(Part 3.2).

Reads a target through narlib.container.resolve_target and
scans the resolved asset/native roots for:

- compiled Python: every .pyc/.pyo member's header is
  parsed — the magic u32 (little-endian) mapped to a
  CPython version through the magic table below (an unknown
  magic reports version null and the magic value itself),
  the PEP 552 flags word for 3.7+ files, and the header
  size (16 bytes for CPython >= 3.7, 12 before). The code
  census unmarshals the payload (capped at 16 MiB) and
  walks the code-object tree: total code objects, function
  count (code objects whose co_name is not "<module>") and
  a sample of the module-level co_names. A payload that
  fails to unmarshal degrades to the header facts plus an
  error note;
- the interpreter library: lib/libpython3.*.so members,
  with the version taken from the file name;
- Kivy markers: *.kv members (count + name sample), and
  the presence of a main.py or an assets/main.pyc entry
  point. No Kivy version is claimed: there is no reliable
  static version string to read, so it stays null.

Usage:
    python3 nar-python.py app.apk [--json]

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import marshal
import os
import re
import sys
import types
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import container as _container  # noqa: E402

TOOL = "nar-python"
VERSION = "3.0.1"
MEMBER_CAP = 32 * 1024 * 1024        # per-member read cap
MARSHAL_CAP = 16 * 1024 * 1024       # marshal payload cap
PYC_LIST_CAP = 50

# CPython magic numbers (u32 little-endian) -> version.
# The magic identifies the bytecode format, which tracks
# the interpreter version that wrote the file.
MAGIC_VERSIONS = {
    3379: "3.6",
    3394: "3.7",
    3413: "3.8",
    3425: "3.9",
    3439: "3.10",
    3495: "3.11",
    3531: "3.12",
    3559: "3.13",
}
# First magic with the 16-byte PEP 552 header (3.7).
_PEP552_FIRST_MAGIC = 3394
_LIBPYTHON_RE = re.compile(r"libpython(3\.\d+)\.so")


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


def _code_census(code):
    """Recursive code-object census over co_consts."""
    total = 0
    functions = 0
    stack = [code]
    while stack:
        current = stack.pop()
        total += 1
        if current.co_name != "<module>":
            functions += 1
        for const in current.co_consts:
            if isinstance(const, types.CodeType):
                stack.append(const)
    return total, functions


def parse_pyc(data, name):
    """Header facts + code census for one .pyc/.pyo member.

    NOTE on safety: marshal.loads on the payload only
    *reconstructs* code objects in memory; nothing is
    executed (no code object is ever called or imported
    here). The payload is still treated as untrusted: the
    read is capped and any marshal failure degrades to the
    header facts plus an error note."""
    record = {"file": name, "size_bytes": len(data)}
    if len(data) < 4:
        record["error"] = "shorter than the 4-byte magic"
        return record
    magic = int.from_bytes(data[:4], "little")
    record["magic"] = magic
    record["python_version"] = MAGIC_VERSIONS.get(magic)
    header_size = 16 if magic >= _PEP552_FIRST_MAGIC else 12
    record["header_size"] = header_size
    if header_size == 16 and len(data) >= 8:
        flags = int.from_bytes(data[4:8], "little")
        record["flags"] = flags
        record["hash_based"] = bool(flags & 0x1)
    else:
        record["flags"] = None
        record["hash_based"] = None
    payload = data[header_size:]
    if len(payload) > MARSHAL_CAP:
        record["code_error"] = (
            f"payload of {len(payload)} bytes exceeds the "
            f"{MARSHAL_CAP}-byte marshal cap; header facts "
            "only")
        return record
    try:
        code = marshal.loads(payload)
    except (ValueError, EOFError, TypeError) as exc:
        record["code_error"] = f"marshal failed: {exc}"
        return record
    if not isinstance(code, types.CodeType):
        record["code_error"] = ("payload did not unmarshal "
                                "to a code object")
        return record
    total, functions = _code_census(code)
    record["code_objects"] = total
    record["functions"] = functions
    record["module_names_sample"] = list(code.co_names)[:15]
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
            pyc_records = []
            pyc_total = 0
            pyc_parsed = 0
            for m in scan.members:
                if not m["name"].lower().endswith(
                        (".pyc", ".pyo")):
                    continue
                pyc_total += 1
                data = scan.read(m)
                if data is None:
                    continue
                record = parse_pyc(data, m["name"])
                if "code_objects" in record:
                    pyc_parsed += 1
                if len(pyc_records) < PYC_LIST_CAP:
                    pyc_records.append(record)
            report["pyc"] = pyc_records
            report["pyc_totals"] = {
                "count": pyc_total, "parsed": pyc_parsed,
                "listed": len(pyc_records)}

            libpython = []
            for m in scan.members:
                match = _LIBPYTHON_RE.search(
                    os.path.basename(m["name"]))
                if match:
                    libpython.append({
                        "path": m["name"],
                        "version": match.group(1),
                        "size": m["size"]})
            report["libpython"] = libpython

            names = [m["name"] for m in scan.members]
            kv = [n for n in names
                  if n.lower().endswith(".kv")]
            report["kivy"] = {
                "kv_count": len(kv),
                "kv_names_sample": kv[:10],
                "main_py": any(
                    os.path.basename(n) == "main.py"
                    for n in names),
                "main_pyc": any(
                    n.lower().endswith("assets/main.pyc")
                    or os.path.basename(n).lower()
                    == "main.pyc" for n in names),
                "kivy_version": None}
        finally:
            scan.close()
    finally:
        resolved.cleanup()
    report["verdict"] = "present" if (
        report["pyc_totals"]["count"] > 0
        or report["libpython"]
        or report["kivy"]["kv_count"] > 0) else "absent"
    return report


def human(report):
    lines = [f"NAR embedded Python deep dive: "
             f"{report['target']}",
             f"Verdict: {report['verdict']}"]
    t = report["pyc_totals"]
    lines.append(f"Compiled Python files: {t['count']} "
                 f"({t['parsed']} code-parsed)")
    for rec in report["pyc"][:20]:
        lines.append(
            f"  {rec['file']}: magic {rec.get('magic')} "
            f"(CPython {rec.get('python_version')}), "
            f"code objects {rec.get('code_objects')}, "
            f"functions {rec.get('functions')}"
            + (f", error: {rec.get('code_error') or rec.get('error')}"
               if rec.get("code_error") or rec.get("error")
               else ""))
    for lp in report["libpython"]:
        lines.append(f"libpython: {lp['path']} "
                     f"(Python {lp['version']})")
    k = report["kivy"]
    lines.append(f"Kivy: {k['kv_count']} .kv files, "
                 f"main.py={k['main_py']}, "
                 f"main.pyc={k['main_pyc']}")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR embedded Python / Kivy deep dive.")
    p.add_argument("target", help="APK / container to inspect")
    p.add_argument("--json", action="store_true",
                   help="machine-readable JSON output")
    args = p.parse_args(argv)
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
