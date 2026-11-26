#!/usr/bin/env python3
"""nar-script.py: script & bytecode universe (Part 5).

    python3 nar-script.py <target> [--json]

Scans a target (resolved through narlib.container, splits
merged like nar-assets) for every script-bearing member and
identifies its format, emitting per-file records
(schemas/script.schema.json) at the fidelity the format
genuinely supports:

- WebAssembly .wasm: full structural parse (sections,
  type/import/function/global/export counts, memory
  limits) — supported.
- Lua / LuaJIT bytecode: 5.x chunk-header + prototype walk
  (function count, string-constant pool) and the LuaJIT
  BCDump framing walk; chunks failing validation (the
  encrypted/obfuscated presentation) degrade to
  identified_only with the reason named.
- GDScript .gdc: GDSC token-stream header (tokenizer
  version, identifier/constant/token counts, identifier
  sample); Zstd-compressed Godot 4 streams and GDEC
  encrypted scripts are identified, never decoded.
- Hermes .hbc / RN bundles: the header parse wired from
  nar-rn.parse_hermes_header (bytecode version,
  function/string/identifier counts).
- Dart snapshot / kernel: nar-flutter's extraction wired
  in (Dart VM + Flutter version strings, snapshot markers,
  kernel_blob presence + kernel header version); class and
  string-pool counts are not stdlib-derivable and stay
  null, stated in the record.
- JavaScript bundles: minified/bundled detection,
  source-map presence, webpack module-count estimate —
  heuristics, labelled with their basis.
- .NET CIL (.dll): narlib.dotnetmeta wired standalone
  (TypeDef/MethodDef counts, namespaces, obfuscation
  markers labelled heuristic).
- Python .pyc: magic -> CPython version plus a STRUCTURAL
  marshal census of code objects (narlib.scriptparse).
  The payload is never executed, imported, or passed to
  marshal.loads; hostile marshal streams are refused with
  a named failure.
- AngelScript / Squirrel / Pawn: header identification
  and the entry counts the formats document (Pawn .amx
  table counts parse fully; Squirrel and AngelScript stay
  identified_only, with the reason stated per format).
- Custom VM bytecode (.jsc SpiderMonkey and friends):
  detected and named, never decoded.

Every record states its fidelity honestly; undecoded
bytecode is never presented as source. Reads are bounded
(per-member caps below; oversize members are recorded as
skips in limitations). Exit 0 whenever the scan completes,
including when no script format is present (verdict
"absent").

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import importlib.util
import json
import os
import struct
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import container as container_mod  # noqa: E402
from narlib import scriptparse as sp  # noqa: E402

VERSION = "3.0.1"
TOOL = "nar-script"
IL2CPP_METADATA_MAGIC = 0xFAB11BAF

PARSE_CAP = 32 * 1024 * 1024       # full-member parse cap
JS_CAP = 16 * 1024 * 1024          # text-bundle scan cap
SCAN_CAP = 64 * 1024 * 1024        # native-library scan cap (Dart)
HEAD_BYTES = 8192                  # magic/header probe

BASE_LIMITATIONS = [
    "Bytecode is reported structurally (headers, counts, "
    "string pools where the format carries them); no record "
    "in this report is source code, and undecoded bytecode "
    "is never presented as source.",
    "Dart class/string-pool counts are not derivable from "
    "an AOT snapshot with the stdlib and are reported null; "
    "the same applies to Squirrel closure counts (no "
    "documented entry-count header) and AngelScript (no "
    "standard compiled format).",
    "Custom VM bytecode (for example SpiderMonkey .jsc) is "
    "detected and named, never decoded.",
]


def _load_sibling(name):
    """Import a sibling nar-*.py tool as a module (the
    wiring route for nar-rn's Hermes header parser and
    nar-flutter's Dart extraction constants)."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        name)
    spec = importlib.util.spec_from_file_location(
        name.replace("-", "_").replace(".py", ""), path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_RN = None
_FLUTTER = None


def _rn():
    global _RN
    if _RN is None:
        _RN = _load_sibling("nar-rn.py")
    return _RN


def _flutter():
    global _FLUTTER
    if _FLUTTER is None:
        _FLUTTER = _load_sibling("nar-flutter.py")
    return _FLUTTER


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

    def read(self, member, cap):
        if member["size"] > cap:
            return None
        try:
            return self._zfs[member["root"]].read(member["name"])
        except (KeyError, OSError, RuntimeError,
                zipfile.BadZipFile):
            return None

    def read_head(self, member, n):
        try:
            with self._zfs[member["root"]].open(member["name"]) as fh:
                return fh.read(n)
        except (KeyError, OSError, RuntimeError,
                zipfile.BadZipFile):
            return b""

    def names(self):
        return [m["name"] for m in self.members]

    def close(self):
        for zf in self._zfs.values():
            try:
                zf.close()
            except Exception:
                pass


def _mk(status, fidelity, facts, reason=None, error=None):
    return {"status": status, "fidelity": fidelity,
            "facts": facts, "reason": reason, "error": error}


def _rec(member, fmt, parsed):
    return {
        "file": member["name"],
        "source_archive": member["archive"],
        "format": fmt,
        "status": parsed["status"],
        "fidelity": parsed["fidelity"],
        "size_bytes": member["size"],
        "facts": parsed["facts"],
        "reason": parsed["reason"],
        "error": parsed["error"],
    }


def _oversize(member, fmt, cap):
    return {
        "file": member["name"],
        "source_archive": member["archive"],
        "format": fmt,
        "status": "identified_only",
        "fidelity": "identified-only",
        "size_bytes": member["size"],
        "facts": {},
        "reason": f"member exceeds the {cap}-byte read cap; "
                  "identified by name, not parsed",
        "error": None,
    }


def scan_target(target):
    resolved = container_mod.resolve_target(target)
    try:
        return _scan_resolved(target, resolved)
    finally:
        resolved.cleanup()


def _scan_resolved(target, resolved):
    files = []
    limitations = list(BASE_LIMITATIONS)
    roots = list(resolved.assets_roots) + list(resolved.native_roots)
    if not roots and os.path.isfile(target) \
            and not zipfile.is_zipfile(target):
        return _scan_loose(target)
    scan = Scan(resolved)
    try:
        names = scan.names()
        dart_vm_version = None
        # First pass: the Flutter engine library carries the
        # Dart VM version for every Dart record in the target.
        for m in scan.members:
            base = os.path.basename(m["name"]).lower()
            if base == "libflutter.so":
                data = scan.read_head(m, SCAN_CAP)
                fl = _flutter()
                dart_vm_version = fl._first_version(
                    data, (fl.DART_VM_RE, fl.STABLE_RE))
        for m in scan.members:
            try:
                _scan_member(scan, m, names, files, limitations,
                             dart_vm_version)
            except Exception as exc:  # one bad member must
                # never crash the run
                files.append({
                    "file": m["name"],
                    "source_archive": m["archive"],
                    "format": "unknown",
                    "status": "identified_only",
                    "fidelity": "identified-only",
                    "size_bytes": m["size"],
                    "facts": {},
                    "reason": None,
                    "error": f"member scan failed: {exc}",
                })
    finally:
        scan.close()
    # Coverage honesty: members the container resolution
    # could not merge are named in the limitations, and a
    # scan that covered nothing because resolution failed
    # (no readable roots, or every content-bearing member
    # skipped) must not exit as a silently empty "absent":
    # it carries a named degraded record stating why the
    # target could not be measured.
    for skipped in resolved.split_skipped:
        limitations.append(
            f"Container member {skipped['name']} was not "
            f"merged into the scan: {skipped['reason']}; "
            "content carried only by that member is not "
            "covered by this report.")
    if not files:
        problems = []
        if not roots:
            problems.append(
                "target resolution produced no readable "
                "archive roots (no base archive identified)")
        for skipped in resolved.split_skipped:
            problems.append(
                f"container member {skipped['name']} not "
                f"merged: {skipped['reason']}")
        if problems:
            files.append({
                "file": "(target resolution)",
                "source_archive": None,
                "format": "unknown",
                "status": "identified_only",
                "fidelity": "identified-only",
                "size_bytes": 0,
                "facts": {"resolution_problems": problems},
                "reason": "the scan could not cover this "
                          "target: " + "; ".join(problems),
                "error": None,
            })
    return _report(target, resolved.container_block(), files,
                   limitations)


def _scan_loose(target):
    """A loose script file (not an archive) as a one-member
    target."""
    name = os.path.basename(target)
    member = {"root": None, "archive": None, "name": name,
              "size": os.path.getsize(target)}
    files = []
    limitations = list(BASE_LIMITATIONS)
    with open(target, "rb") as fh:
        data = fh.read(PARSE_CAP + 1)
    if len(data) > PARSE_CAP:
        files.append(_oversize(member, "unknown", PARSE_CAP))
        return _report(target, None, files, limitations)
    fake = _LooseScan(data)
    _scan_member(fake, member, [name], files, limitations, None)
    return _report(target, None, files, limitations)


class _LooseScan:
    def __init__(self, data):
        self._data = data

    def read(self, member, cap):
        return self._data if len(self._data) <= cap else None

    def read_head(self, member, n):
        return self._data[:n]


def _report(target, container_block, files, limitations):
    by_format = {}
    by_status = {}
    for rec in files:
        by_format[rec["format"]] = by_format.get(rec["format"], 0) + 1
        by_status[rec["status"]] = by_status.get(rec["status"], 0) + 1
    return {
        "tool": TOOL,
        "version": VERSION,
        "target": os.path.abspath(target),
        "verdict": "present" if files else "absent",
        "container": container_block,
        "files": files,
        "totals": {"file_count": len(files),
                   "by_format": by_format,
                   "by_status": by_status},
        "limitations": limitations,
    }


def _container_signature(head):
    """The binary container signature at the start of a
    member, or None. Unity AssetBundles open with one of
    the UnityFS / UnityWeb / UnityRaw magics."""
    for sig in (b"UnityFS", b"UnityWeb", b"UnityRaw"):
        if head.startswith(sig):
            return sig.decode("ascii")
    return None


def _looks_html(data):
    """True when the member's content is an HTML document:
    after an optional BOM and leading whitespace it opens
    with a doctype or an <html> tag."""
    probe = data[:4096].lstrip(b"\xef\xbb\xbf").lstrip().lower()
    return probe.startswith(b"<!doctype") or \
        probe.startswith(b"<html")


def _scan_member(scan, m, names, files, limitations, dart_vm_version):
    name = m["name"]
    base = os.path.basename(name).lower()
    ext = os.path.splitext(base)[1]
    head = scan.read_head(m, HEAD_BYTES)

    # IL2CPP metadata: the name is the deterministic
    # evidence (the Unity IL2CPP pair member); the header
    # magic/version corroborate it and the native library's
    # presence in the merged target is reported as a fact.
    if base == "global-metadata.dat":
        magic_ok = False
        version = None
        if len(head) >= 8:
            magic, version_raw = struct.unpack_from("<II", head, 0)
            magic_ok = magic == IL2CPP_METADATA_MAGIC
            version = version_raw if magic_ok else None
        facts = {
            "metadata_magic_ok": magic_ok,
            "metadata_version": version,
            "native_library_present": any(
                os.path.basename(n).lower() == "libil2cpp.so"
                for n in names),
        }
        if magic_ok:
            files.append(_rec(m, "il2cpp-metadata", _mk(
                "supported", "structural-summary", facts)))
        else:
            files.append(_rec(m, "il2cpp-metadata", _mk(
                "identified_only", "identified-only", facts,
                reason="IL2CPP metadata member present but "
                       "its header magic is not the standard "
                       "IL2CPP magic; the file may be "
                       "encrypted or obfuscated, so no "
                       "version is read from it")))
        return

    # Hermes first: the magic decides, whatever the name.
    if head[:8] == _hermes_magic():
        try:
            header = _rn().parse_hermes_header(head)
        except ValueError as exc:
            files.append(_rec(m, "hermes", _mk(
                "identified_only", "identified-only", {},
                reason=str(exc))))
            return
        facts = dict(header)
        facts["magic"] = "hermes"
        files.append(_rec(m, "hermes", _mk(
            "supported", "structural-summary", facts)))
        return

    if ext == ".wasm" or head[:4] == b"\x00asm":
        data = scan.read(m, PARSE_CAP)
        if data is None:
            files.append(_oversize(m, "wasm", PARSE_CAP))
            return
        files.append(_rec(m, "wasm", sp.parse_wasm(data)))
        return

    if ext in (".luac", ".lua") or head[:4] == sp.LUA_MAGIC \
            or head[:3] == sp.LUAJIT_MAGIC:
        if ext == ".lua" and head[:4] != sp.LUA_MAGIC \
                and head[:3] != sp.LUAJIT_MAGIC:
            data = scan.read(m, JS_CAP)
            if data is None:
                files.append(_oversize(m, "lua", JS_CAP))
                return
            text = data.decode("utf-8", "replace")
            files.append(_rec(m, "lua", _mk(
                "identified_only", "identified-only",
                {"variant": "source",
                 "line_count": text.count("\n") + 1},
                reason="Lua source text (.lua), not a compiled "
                       "chunk; line census only")))
            return
        data = scan.read(m, PARSE_CAP)
        if data is None:
            files.append(_oversize(m, "lua", PARSE_CAP))
            return
        files.append(_rec(m, "lua", sp.parse_lua(data)))
        return

    if ext in (".gdc", ".gde") or head[:4] in (sp.GDSC_MAGIC,
                                              sp.GDEC_MAGIC):
        data = scan.read(m, PARSE_CAP)
        if data is None:
            files.append(_oversize(m, "gdscript", PARSE_CAP))
            return
        parsed = sp.parse_gdscript(data)
        if ext == ".gde" and parsed["facts"].get("encrypted") is None \
                and data[:4] != sp.GDSC_MAGIC:
            parsed = _mk(
                "identified_only", "identified-only",
                {"encrypted": True},
                reason="encrypted GDScript (.gde): named, "
                       "never decoded")
        files.append(_rec(m, "gdscript", parsed))
        return

    if ext == ".gd":
        data = scan.read(m, JS_CAP)
        if data is None:
            files.append(_oversize(m, "gdscript", JS_CAP))
            return
        text = data.decode("utf-8", "replace")
        files.append(_rec(m, "gdscript", _mk(
            "identified_only", "identified-only",
            {"variant": "source",
             "line_count": text.count("\n") + 1},
            reason="GDScript source text (.gd); the compiled "
                   "form is .gdc")))
        return

    if base == "libapp.so":
        fl = _flutter()
        data = scan.read(m, SCAN_CAP)
        if data is None:
            files.append(_oversize(m, "dart-snapshot", SCAN_CAP))
            return
        markers = [mk.decode("ascii", "replace")
                   for mk in fl.SNAPSHOT_MARKERS if mk in data]
        flutter_version = fl._first_version(
            data, (fl.STABLE_RE,))
        facts_parse = sp.dart_snapshot_facts(
            data, dart_vm_version=dart_vm_version,
            flutter_version=flutter_version, markers=markers)
        facts_parse["facts"]["kernel_blob_present"] = any(
            os.path.basename(n).lower() == "kernel_blob.bin"
            for n in names)
        files.append(_rec(m, "dart-snapshot", facts_parse))
        return

    if base in ("kernel_blob.bin", "vm_snapshot_data",
                "isolate_snapshot_data"):
        data = scan.read(m, PARSE_CAP)
        if data is None:
            files.append(_oversize(m, "dart-snapshot", PARSE_CAP))
            return
        if base == "kernel_blob.bin":
            files.append(_rec(m, "dart-snapshot",
                              sp.parse_kernel_blob(data)))
        else:
            files.append(_rec(m, "dart-snapshot", _mk(
                "identified_only", "identified-only",
                {"member_kind": base},
                reason="Dart snapshot data member: the AOT "
                       "snapshot object graph has no "
                       "stdlib-feasible structural census")))
        return

    if ext == ".jsc":
        files.append(_rec(m, "custom-vm", sp.custom_vm_record(
            "SpiderMonkey bytecode (.jsc)",
            "compiled JavaScript shipped as SpiderMonkey "
            "bytecode (Cocos Creator family)")))
        return

    if ext in (".js", ".mjs", ".cjs") or (
            ext == ".bundle"):
        # Content gate: a name is not evidence of a text
        # script. Binary containers (Unity AssetBundles
        # carry the UnityFS/UnityWeb/UnityRaw signature)
        # and members whose bytes are binary must never be
        # run through the text-statistics fallback, and
        # HTML content must never be claimed as JavaScript.
        container_sig = _container_signature(head)
        if container_sig is not None:
            files.append(_rec(m, "unknown", _mk(
                "identified_only", "identified-only",
                {"container_signature": container_sig},
                reason=f"binary container ({container_sig} "
                       "signature); not a text script, no "
                       "script format is claimed for it")))
            return
        if b"\x00" in head:
            files.append(_rec(m, "unknown", _mk(
                "identified_only", "identified-only",
                {"content_kind": "binary"},
                reason="binary content (NUL bytes in the "
                       "header probe); not a text script, "
                       "no script format is claimed for it")))
            return
        data = scan.read(m, JS_CAP)
        truncated = False
        if data is None:
            data = scan.read_head(m, JS_CAP)
            truncated = True
        if _looks_html(data):
            files.append(_rec(m, "unknown", _mk(
                "identified_only", "identified-only",
                {"content_kind": "html"},
                reason="content is HTML (document markup "
                       "at the start of the member), not "
                       "JavaScript; no script format is "
                       "claimed for it")))
            return
        parsed = sp.parse_javascript(data, sibling_names=names)
        if truncated:
            parsed["facts"]["scan_truncated_at_bytes"] = JS_CAP
        files.append(_rec(m, "javascript", parsed))
        return

    if ext == ".dll":
        data = scan.read(m, PARSE_CAP)
        if data is None:
            files.append(_oversize(m, "dotnet-cil", PARSE_CAP))
            return
        tmp = os.path.join(tempfile.mkdtemp(prefix="nar-script-"),
                           "member.dll")
        files.append(_rec(m, "dotnet-cil",
                          sp.parse_dotnet(data, tmp)))
        return

    if ext in (".pyc", ".pyo"):
        data = scan.read(m, PARSE_CAP)
        if data is None:
            files.append(_oversize(m, "pyc", PARSE_CAP))
            return
        files.append(_rec(m, "pyc", sp.parse_pyc(data)))
        return

    if ext == ".py":
        data = scan.read(m, JS_CAP)
        if data is None:
            files.append(_oversize(m, "python", JS_CAP))
            return
        text = data.decode("utf-8", "replace")
        files.append(_rec(m, "python", _mk(
            "identified_only", "identified-only",
            {"variant": "source",
             "line_count": text.count("\n") + 1},
            reason="Python source text (.py), not compiled "
                   "bytecode; line census only")))
        return

    if ext == ".as":
        data = scan.read(m, JS_CAP)
        if data is None:
            files.append(_oversize(m, "angelscript", JS_CAP))
            return
        files.append(_rec(m, "angelscript",
                          sp.parse_angelscript_source(data)))
        return

    if ext in (".nut", ".cnut"):
        data = scan.read(m, PARSE_CAP)
        if data is None:
            files.append(_oversize(m, "squirrel", PARSE_CAP))
            return
        files.append(_rec(m, "squirrel", sp.parse_squirrel(data)))
        return

    if ext == ".amx":
        data = scan.read(m, PARSE_CAP)
        if data is None:
            files.append(_oversize(m, "pawn", PARSE_CAP))
            return
        files.append(_rec(m, "pawn", sp.parse_pawn_amx(data)))
        return

    if ext == ".pwn":
        data = scan.read(m, JS_CAP)
        if data is None:
            files.append(_oversize(m, "pawn", JS_CAP))
            return
        files.append(_rec(m, "pawn", sp.parse_pawn_source(data)))
        return


_HERMES_MAGIC = None


def _hermes_magic():
    global _HERMES_MAGIC
    if _HERMES_MAGIC is None:
        _HERMES_MAGIC = _rn().HERMES_MAGIC
    return _HERMES_MAGIC


def human(report):
    lines = [f"NAR script & bytecode inventory: "
             f"{os.path.basename(report['target'])}"]
    lines.append("=" * 60)
    totals = report["totals"]
    lines.append(f"Verdict: {report['verdict']} — "
                 f"{totals['file_count']} script file(s): "
                 f"{totals['by_format']}")
    cont = report.get("container")
    if cont:
        lines.append(
            f"Container: {cont['input_kind']} — base "
            f"{cont['base']}; splits merged: "
            f"{[s['name'] for s in cont['splits_merged']]}")
    for rec in report["files"]:
        facts = rec.get("facts") or {}
        counts = ", ".join(
            f"{k}={facts[k]}" for k in (
                "version", "function_count", "string_count",
                "identifier_count", "token_count",
                "constant_count", "typedef_count",
                "methoddef_count", "code_object_count",
                "total_functions", "public_count",
                "bytecode_version", "cpython_version",
                "metadata_version")
            if facts.get(k) is not None)
        lines.append(f"  [{rec['format']}] {rec['file']} "
                     f"({rec['status']})"
                     + (f" — {counts}" if counts else ""))
        if rec.get("reason"):
            lines.append(f"      reason: {rec['reason']}")
        if rec.get("error"):
            lines.append(f"      error: {rec['error']}")
    lines.append("Limitations:")
    for line in report["limitations"]:
        lines.append(f"  - {line}")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Script & bytecode inventory: Lua/LuaJIT, "
                    "GDScript, Dart, Hermes, JavaScript, "
                    "WebAssembly, .NET CIL, Python .pyc, "
                    "AngelScript, Squirrel, Pawn and custom "
                    "VM bytecode, at honest fidelity.")
    parser.add_argument("target",
                        help="path to an APK/AAB/container "
                             "target (or a loose script file)")
    parser.add_argument("--json", action="store_true",
                        help="emit the report as JSON "
                             "(schemas/script.schema.json)")
    args = parser.parse_args(argv)
    if not os.path.isfile(args.target):
        print(f"nar-script: target not found: {args.target}",
              file=sys.stderr)
        return 2
    try:
        report = scan_target(args.target)
    except (FileNotFoundError, IsADirectoryError,
            zipfile.BadZipFile) as exc:
        print(f"nar-script: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(human(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
