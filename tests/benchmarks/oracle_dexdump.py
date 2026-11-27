#!/usr/bin/env python3
"""oracle_dexdump.py: independent-oracle differential for
the DEX parser (narlib.dex) and the DEX disassembler
(narlib.dexdis) against the SDK dexdump binary.

dexdump is the independent decoder: the expected side of
every comparison is computed from dexdump's own output,
never from NAR. NAR supplies only the actual side. This is
the committed, CI-sized successor of the Phase 2-era
dexdump agreement RECORD (40,837 methods / 773,166
instructions, preserved in docs/NAR_TEST_MATRIX.md): that
campaign's harness was never committed, so the agreement
could not be re-run. This harness re-runs the same method
on small synthetic fixtures (see build_oracle_fixtures.py)
and on any target handed to it.

Measured, per DEX file:
- header table sizes (string / type / proto / field /
  method ids, class defs) — dexdump -f vs narlib.dex header;
- class count + descriptor set — dexdump class dump vs
  narlib.dex class_defs();
- per-class defined method / field counts — dexdump vs
  class_methods_indexed() / class_fields();
- per-method insns size (16-bit code units) and real
  instruction count — dexdump -d (its `insns size` line and
  its disassembly listing; payload data lines are not
  instructions) vs narlib.dex code items + narlib.dexdis
  instruction_count. Methods are keyed by class descriptor
  + method name + full prototype signature as printed by
  dexdump; a per-method (insns size, instruction count)
  multiset digest is compared as well, so a key collision
  cannot hide a count drift.

dexdump is invoked with -i -j: the synthetic fixtures carry
no valid checksum/signature and no map the verifier likes;
verification is dexdump's own gate, not the measurement.
The decode itself is unaffected.

Locating dexdump: $NAR_DEXDUMP, then the newest
build-tools directory under $ANDROID_HOME /
$ANDROID_SDK_ROOT, then PATH, then the conventional SDK
locations narlib.registry itself searches (~/Android/Sdk,
~/workspace/android-sdk, ~/android-sdk, /opt/android-sdk,
/usr/lib/android-sdk). When no dexdump is found the
harness reports unavailable (CLI exit 2) and callers skip —
it never falls back to a NAR-derived expectation.

Usage:
    python3 tests/benchmarks/oracle_dexdump.py <target>
        [--json]
    target is a .dex file or an .apk (its classes*.dex
    members are extracted to a temp dir and each is
    measured).

Exit codes: 0 agreement, 1 mismatch (readable diff summary
printed), 2 dexdump unavailable or target unreadable.

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

DEX_MEMBER_RE = re.compile(r"^classes\d*\.dex$")

_HEADER_RE = re.compile(
    r"^(string_ids_size|type_ids_size|proto_ids_size|"
    r"field_ids_size|method_ids_size|class_defs_size)"
    r"\s+:\s+(\d+)")
_CLASS_RE = re.compile(r"^Class #\d+")
_DESC_RE = re.compile(r"^\s+Class descriptor\s+:\s+'([^']+)'")
_SECTION_RE = re.compile(
    r"^\s+(Static fields|Instance fields|Direct methods|"
    r"Virtual methods)\s+-")
_MEMBER_RE = re.compile(r"^\s+#\d+\s+:\s+\(in (.+)\)\s*$")
_NAME_RE = re.compile(r"^\s+name\s+:\s+'([^']*)'")
_TYPE_RE = re.compile(r"^\s+type\s+:\s+'([^']*)'")
_CODE_NONE_RE = re.compile(r"^\s+code\s+:\s+\(none\)")
_INSNS_RE = re.compile(
    r"^\s+insns size\s+:\s+(\d+)\s+16-bit code units")
_DISASM_RE = re.compile(
    r"^[0-9a-f]+:\s+.*\|([0-9a-f]{4,8}):\s+(.*)$")
_PAYLOAD_TAIL_RE = re.compile(r"\(\d+ units\)\s*$")


# ------------------------------------------------------------------
# dexdump location
# ------------------------------------------------------------------

def locate_dexdump(env=None):
    """Path to a dexdump binary, or None.

    Order: $NAR_DEXDUMP, then build-tools (newest version
    directory first) under $ANDROID_HOME / $ANDROID_SDK_ROOT,
    then PATH, then the conventional SDK locations the
    repo's own registry searches. `env` defaults to
    os.environ; tests pass a controlled mapping to exercise
    the not-found path."""
    env = os.environ if env is None else env
    override = env.get("NAR_DEXDUMP")
    if override and os.path.isfile(override):
        return override
    names = ["dexdump", "dexdump.exe"]

    def from_sdk(home):
        tools = Path(home) / "build-tools"
        if not tools.is_dir():
            return None
        versions = sorted(
            (d for d in tools.iterdir() if d.is_dir()),
            key=lambda d: d.name, reverse=True)
        for version in versions:
            for name in names:
                cand = version / name
                if cand.is_file():
                    return str(cand)
        return None

    for var in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        home = env.get(var)
        if home:
            found = from_sdk(home)
            if found:
                return found
    found = shutil.which("dexdump", path=env.get("PATH"))
    if found:
        return found
    # Conventional SDK locations (the same list the repo's
    # registry searches). The home-based entries resolve
    # against the env's HOME when one is supplied, so a
    # caller passing a controlled env controls this route
    # too; the two system locations are always checked.
    home = env.get("HOME") or str(Path.home())
    for sdk in (Path(home) / "Android" / "Sdk",
                Path(home) / "workspace" / "android-sdk",
                Path(home) / "android-sdk",
                Path("/opt/android-sdk"),
                Path("/usr/lib/android-sdk")):
        found = from_sdk(sdk)
        if found:
            return found
    return None


# ------------------------------------------------------------------
# Expected side: dexdump only
# ------------------------------------------------------------------

def _run_dexdump(dexdump, dex_path, flags):
    proc = subprocess.run(
        [dexdump] + flags + ["-i", "-j", str(dex_path)],
        capture_output=True, text=True, timeout=300)
    return proc.stdout


def parse_dexdump_header(text):
    header = {}
    for line in text.splitlines():
        m = _HEADER_RE.match(line.strip())
        if m:
            header[m.group(1)] = int(m.group(2))
    return header


def parse_dexdump_classes(text):
    """Parse the class dump of `dexdump -d` output.

    Returns {"classes": [descriptors in file order],
    "per_class": {desc: {"methods": int, "fields": int}},
    "methods": {key: {"insns_size": int|None,
    "instruction_count": int}}, where key is
    "Lclass;->name(proto)return" exactly as dexdump prints
    the defining class, the name and the type signature.}
    """
    classes = []
    per_class = {}
    methods = {}
    cur_class = None
    section = None
    member = None  # dict being accumulated

    def flush():
        nonlocal member
        if member is None or cur_class is None:
            member = None
            return
        if member["kind"] == "method":
            per_class[cur_class]["methods"] += 1
            key = (f"{cur_class}->"
                   f"{member['name']}{member['sig']}")
            methods[key] = {
                "insns_size": member["insns_size"],
                "instruction_count":
                    member["instruction_count"],
            }
        else:
            per_class[cur_class]["fields"] += 1
        member = None

    for line in text.splitlines():
        if _CLASS_RE.match(line):
            flush()
            cur_class = None
            section = None
            continue
        m = _DESC_RE.match(line)
        if m:
            flush()
            cur_class = m.group(1)
            classes.append(cur_class)
            per_class[cur_class] = {"methods": 0, "fields": 0}
            section = None
            continue
        m = _SECTION_RE.match(line)
        if m:
            flush()
            section = m.group(1)
            continue
        m = _MEMBER_RE.match(line)
        if m and section in ("Static fields", "Instance fields",
                             "Direct methods",
                             "Virtual methods"):
            flush()
            member = {
                "kind": "field" if section.endswith("fields")
                        else "method",
                "name": None, "sig": None,
                "insns_size": None, "instruction_count": 0,
                "has_code": False,
            }
            continue
        if member is not None:
            m = _NAME_RE.match(line)
            if m and member["name"] is None:
                member["name"] = m.group(1)
                continue
            m = _TYPE_RE.match(line)
            if m and member["sig"] is None:
                member["sig"] = m.group(1)
                continue
            if _CODE_NONE_RE.match(line):
                member["insns_size"] = None
                member["has_code"] = False
                continue
            m = _INSNS_RE.match(line)
            if m:
                member["insns_size"] = int(m.group(1))
                member["has_code"] = True
                continue
            m = _DISASM_RE.match(line)
            if m and member["kind"] == "method" \
                    and member["has_code"]:
                tail = m.group(2)
                # Payload pseudo-instructions print as one
                # `...-data (N units)` line each; they are
                # data, not instructions (dexdis counts them
                # separately as payloads).
                if _PAYLOAD_TAIL_RE.search(tail) \
                        and "-data" in tail:
                    continue
                member["instruction_count"] += 1
                continue
    flush()
    return {"classes": classes, "per_class": per_class,
            "methods": methods}


def dexdump_facts(dexdump, dex_path):
    """The expected side for one DEX, from dexdump alone."""
    header = parse_dexdump_header(
        _run_dexdump(dexdump, dex_path, ["-f"]))
    body = parse_dexdump_classes(
        _run_dexdump(dexdump, dex_path, ["-d"]))
    return _assemble_facts(header, body)


def _assemble_facts(header, body):
    methods = body["methods"]
    with_code = {k: v for k, v in methods.items()
                 if v["insns_size"] is not None}
    digest = hashlib.sha256(repr(sorted(
        (v["insns_size"], v["instruction_count"])
        for v in with_code.values())).encode()).hexdigest()
    return {
        "header": {
            "string_ids": header.get("string_ids_size"),
            "type_ids": header.get("type_ids_size"),
            "proto_ids": header.get("proto_ids_size"),
            "field_ids": header.get("field_ids_size"),
            "method_ids": header.get("method_ids_size"),
            "class_defs": header.get("class_defs_size"),
        },
        "classes": sorted(body["classes"]),
        "per_class": body["per_class"],
        "methods": methods,
        "totals": {
            "methods_defined": len(methods),
            "methods_with_code": len(with_code),
            "instructions": sum(
                v["instruction_count"]
                for v in with_code.values()),
            "insns_units": sum(
                v["insns_size"] for v in with_code.values()),
        },
        "method_multiset_digest": digest,
    }


# ------------------------------------------------------------------
# Actual side: NAR (narlib.dex + narlib.dexdis)
# ------------------------------------------------------------------

def nar_facts(dex_path):
    """The actual side for one DEX, from NAR's own parsers.
    Never used to build an expectation."""
    from narlib.dex import Dex
    from narlib import dexdis

    dex = Dex(Path(dex_path).read_bytes(),
              name=Path(dex_path).name)
    header = {
        "string_ids": dex.string_ids_size,
        "type_ids": dex.type_ids_size,
        "proto_ids": dex.proto_ids_size,
        "field_ids": dex.field_ids_size,
        "method_ids": dex.method_ids_size,
        "class_defs": dex.class_defs_size,
    }
    classes = []
    per_class = {}
    methods = {}
    failures = []
    for cdef in dex.class_defs():
        desc = cdef["class"]
        classes.append(desc)
        defined_methods = list(dex.class_methods_indexed(
            cdef["class_data_off"]))
        defined_fields = list(dex.class_fields(
            cdef["class_data_off"]))
        per_class[desc] = {
            "methods": len(defined_methods),
            "fields": len(defined_fields),
        }
        for midx, name, _flags, code_off, _kind in \
                defined_methods:
            full = dex.method_full(midx)
            if full:
                sig = (f"({''.join(full[3])}){full[2]}")
            else:
                sig = "?"
            key = f"{desc}->{name}{sig}"
            if not code_off:
                methods[key] = {"insns_size": None,
                                "instruction_count": 0}
                continue
            info = dex.code_item_info(code_off)
            result = dexdis.disassemble_method(dex, code_off)
            if result.get("status") != "ok":
                failures.append(
                    f"{key}: dexdis failed: "
                    f"{result.get('error', {}).get('reason')}")
                methods[key] = {
                    "insns_size":
                        info["insns_size"] if info else None,
                    "instruction_count": None,
                }
                continue
            methods[key] = {
                "insns_size": result["insns_size"],
                "instruction_count":
                    result["instruction_count"],
            }
    with_code = {k: v for k, v in methods.items()
                 if v["insns_size"] is not None}
    digest = hashlib.sha256(repr(sorted(
        (v["insns_size"], v["instruction_count"])
        for v in with_code.values()
        if v["instruction_count"] is not None)).encode()
        ).hexdigest()
    facts = {
        "header": header,
        "classes": sorted(classes),
        "per_class": per_class,
        "methods": methods,
        "totals": {
            "methods_defined": len(methods),
            "methods_with_code": len(with_code),
            "instructions": sum(
                v["instruction_count"]
                for v in with_code.values()
                if v["instruction_count"] is not None),
            "insns_units": sum(
                v["insns_size"] for v in with_code.values()),
        },
        "method_multiset_digest": digest,
    }
    return facts, failures


# ------------------------------------------------------------------
# Comparison (pure; the planted-discrepancy tests drive this)
# ------------------------------------------------------------------

def compare_facts(expected, actual):
    """Diff two fact dicts of the shape built above.
    Returns a list of readable diff strings; [] is agreement.
    """
    diffs = []
    for key in sorted(expected["header"]):
        e, a = expected["header"][key], actual["header"].get(key)
        if e != a:
            diffs.append(
                f"header {key}: dexdump={e} nar={a}")
    if expected["classes"] != actual["classes"]:
        diffs.append(
            f"class set: dexdump={expected['classes']} "
            f"nar={actual['classes']}")
    for desc in sorted(set(expected["per_class"])
                       | set(actual["per_class"])):
        e = expected["per_class"].get(desc)
        a = actual["per_class"].get(desc)
        if e != a:
            diffs.append(
                f"class {desc}: per-class counts "
                f"dexdump={e} nar={a}")
    e_methods, a_methods = expected["methods"], actual["methods"]
    for key in sorted(set(e_methods) | set(a_methods)):
        if key not in e_methods:
            diffs.append(f"method {key}: only in NAR")
            continue
        if key not in a_methods:
            diffs.append(f"method {key}: only in dexdump")
            continue
        e, a = e_methods[key], a_methods[key]
        if e["insns_size"] != a["insns_size"]:
            diffs.append(
                f"method {key}: insns_size "
                f"dexdump={e['insns_size']} "
                f"nar={a['insns_size']}")
        if e["instruction_count"] != a["instruction_count"]:
            diffs.append(
                f"method {key}: instruction_count "
                f"dexdump={e['instruction_count']} "
                f"nar={a['instruction_count']}")
    for key in sorted(expected["totals"]):
        e, a = expected["totals"][key], actual["totals"].get(key)
        if e != a:
            diffs.append(f"total {key}: dexdump={e} nar={a}")
    if expected["method_multiset_digest"] != \
            actual["method_multiset_digest"]:
        diffs.append(
            "per-method multiset digest differs "
            f"(dexdump={expected['method_multiset_digest'][:12]} "
            f"nar={actual['method_multiset_digest'][:12]})")
    return diffs


# ------------------------------------------------------------------
# Driver
# ------------------------------------------------------------------

def _dex_targets(target):
    """Yield (display_name, dex_path, cleanup) for a .dex
    file or an .apk's classes*.dex members."""
    path = Path(target)
    if path.suffix.lower() == ".dex":
        yield path.name, path, None
        return
    tmp = tempfile.TemporaryDirectory(prefix="oracle-dex-")
    try:
        with zipfile.ZipFile(path) as zf:
            # Root-level classes*.dex members only.
            names = [n for n in zf.namelist()
                     if DEX_MEMBER_RE.match(n)]
            if not names:
                raise ValueError(
                    f"{target}: no classes*.dex members")
            for name in sorted(names):
                out = Path(tmp.name) / name
                out.write_bytes(zf.read(name))
                yield name, out, tmp
    except Exception:
        tmp.cleanup()
        raise


def run_differential(target, dexdump_path=None, env=None):
    """Run the differential over one target. Returns a
    report dict with status agree / mismatch / unavailable /
    error. `dexdump_path` overrides location; when omitted
    the locator runs (against `env` when given)."""
    dexdump = dexdump_path or locate_dexdump(env)
    report = {"tool": "oracle_dexdump", "oracle": "dexdump",
              "oracle_path": dexdump,
              "target": str(target), "dex_files": [],
              "diffs": []}
    if not dexdump:
        report["status"] = "unavailable"
        report["reason"] = (
            "dexdump not found ($NAR_DEXDUMP, "
            "$ANDROID_HOME/$ANDROID_SDK_ROOT build-tools, "
            "PATH all empty)")
        return report
    try:
        targets = list(_dex_targets(target))
    except (OSError, ValueError, zipfile.BadZipFile) as e:
        report["status"] = "error"
        report["reason"] = str(e)
        return report
    cleanup = targets[0][2] if targets else None
    try:
        for name, dex_path, _c in targets:
            expected = dexdump_facts(dexdump, dex_path)
            actual, failures = nar_facts(dex_path)
            diffs = compare_facts(expected, actual)
            diffs.extend(failures)
            report["dex_files"].append({
                "name": name,
                "totals": expected["totals"],
                "diffs": diffs,
            })
            report["diffs"].extend(
                f"{name}: {d}" for d in diffs)
    finally:
        if cleanup is not None:
            cleanup.cleanup()
    report["status"] = "mismatch" if report["diffs"] else "agree"
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Differential: narlib.dex/dexdis vs the "
                    "independent dexdump decoder.")
    parser.add_argument("target", help=".dex file or .apk")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = run_differential(args.target)
    if args.json:
        print(json.dumps(report, indent=2))
    elif report["status"] == "unavailable":
        print(f"oracle_dexdump: unavailable — "
              f"{report['reason']}")
    elif report["status"] == "error":
        print(f"oracle_dexdump: error — {report['reason']}")
    else:
        print(f"oracle_dexdump vs {report['oracle_path']}: "
              f"{args.target}")
        for entry in report["dex_files"]:
            t = entry["totals"]
            print(f"  {entry['name']}: {t['methods_defined']} "
                  f"methods ({t['methods_with_code']} with "
                  f"code), {t['instructions']} instructions, "
                  f"{t['insns_units']} code units — "
                  f"{'AGREE' if not entry['diffs'] else 'DIFF'}")
        for diff in report["diffs"]:
            print(f"  DIFF {diff}")
        print(f"result: {report['status'].upper()}")
    if report["status"] == "unavailable" \
            or report["status"] == "error":
        return 2
    return 0 if report["status"] == "agree" else 1


if __name__ == "__main__":
    sys.exit(main())
