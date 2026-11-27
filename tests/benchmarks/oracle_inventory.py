#!/usr/bin/env python3
"""oracle_inventory.py: independent-oracle differential
for the native inventory (nar-native) and the engine JNI
scan (nar-engines) on a small synthetic APK fixture.

Everything on the expected side is derived independently
of NAR:

- the library inventory comes from Python zipfile's member
  list (the archive itself is the ground truth for what it
  contains);
- each library's DT_NEEDED list and JNI export census come
  from the minimal struct-based ELF dynamic-symbol reader
  in this file. It deliberately does NOT import narlib:
  an oracle that shares the parser under test cannot catch
  that parser's misreading. When readelf is on PATH its
  -d / -s -W output cross-checks the in-harness reader, and
  a disagreement between the two oracles is reported too;
- engine JNI match counts are the one place shared data is
  unavoidable: which prefixes belong to which family is
  declared in scripts/formats.json. The harness reads that
  data file (never narlib code) and applies the prefixes to
  its own independent census, so what is checked is
  nar-engines' counting and attribution over the census,
  given the declared marker data. The ELF fact layer above
  is fully independent.

The actual side is nar-native's and nar-engines' own JSON,
produced by running the tools as subprocesses.

The fixture (tests/benchmarks/fixtures/
oracle_inventory.apk, built by build_oracle_fixtures.py)
is SYNTHETIC: this differential proves the differential
mechanism and the ELF fact layer on a known input. It is
NOT real-target accuracy evidence, and the report says so
(label "SYNTHETIC" in text and JSON output).

Usage:
    python3 tests/benchmarks/oracle_inventory.py <apk>
        [--json]

Exit codes: 0 agreement, 1 mismatch, 2 tooling error.

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import io
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"

SO_MEMBER_RE = re.compile(r"^(?:base/)?lib/([^/]+)/(.+\.so)$")

SHT_DYNAMIC = 6
SHT_DYNSYM = 11
DT_NULL = 0
DT_NEEDED = 1
DT_SONAME = 14
STB_GLOBAL = 1
STB_WEAK = 2


# ------------------------------------------------------------------
# Independent ELF reader (struct only; no narlib import)
# ------------------------------------------------------------------

class OracleElfError(Exception):
    pass


def _cstr(blob, off):
    if off < 0 or off >= len(blob):
        return ""
    end = blob.find(b"\x00", off)
    if end < 0:
        end = len(blob)
    return blob[off:end].decode("utf-8", "replace")


def read_elf_facts(data, name="lib.so"):
    """{needed, soname, exports, jni_exports} for one ELF,
    parsed from its section headers, .dynsym/.dynstr and
    .dynamic sections with struct alone."""
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise OracleElfError(f"{name}: not an ELF file")
    is_64 = data[4] == 2
    if data[4] not in (1, 2):
        raise OracleElfError(f"{name}: bad EI_CLASS {data[4]}")
    endian = "<" if data[5] != 2 else ">"
    if is_64:
        (_etype, _mach, _ver, _entry, _phoff, shoff, _flags,
         _ehsize, _phentsize, _phnum, shentsize, shnum,
         shstrndx) = struct.unpack_from(
            endian + "HHIQQQIHHHHHH", data, 16)
        sh_fmt, sh_size = endian + "IIQQQQIIQQ", 64
        sym_fmt, sym_size = endian + "IBBHQQ", 24
        dyn_fmt, dyn_size = endian + "qQ", 16
    else:
        (_etype, _mach, _ver, _entry, _phoff, shoff, _flags,
         _ehsize, _phentsize, _phnum, shentsize, shnum,
         shstrndx) = struct.unpack_from(
            endian + "HHIIIIIHHHHHH", data, 16)
        sh_fmt, sh_size = endian + "IIIIIIIIII", 40
        sym_fmt, sym_size = endian + "IIIBBH", 16
        dyn_fmt, dyn_size = endian + "iI", 8
    if shentsize and shentsize < sh_size:
        raise OracleElfError(f"{name}: bad section entry size")
    step = shentsize or sh_size
    sections = []
    for i in range(shnum if shoff else 0):
        off = shoff + i * step
        if off + sh_size > len(data):
            raise OracleElfError(
                f"{name}: section header {i} past end of file")
        vals = struct.unpack_from(sh_fmt, data, off)
        sections.append({
            "name_off": vals[0], "type": vals[1],
            "offset": vals[4], "size": vals[5],
            "link": vals[6], "entsize": vals[9]})
    shstr = b""
    if 0 <= shstrndx < len(sections):
        s = sections[shstrndx]
        shstr = data[s["offset"]:s["offset"] + s["size"]]
    for s in sections:
        s["name"] = _cstr(shstr, s["name_off"])

    def section_data(s):
        end = s["offset"] + s["size"]
        if end > len(data):
            raise OracleElfError(
                f"{name}: section {s['name']} past end of file")
        return data[s["offset"]:end]

    dynstr = b""
    for s in sections:
        if s["name"] == ".dynstr":
            dynstr = section_data(s)
    needed, soname = [], None
    for s in sections:
        if s["type"] != SHT_DYNAMIC:
            continue
        blob = section_data(s)
        for off in range(0, len(blob) - dyn_size + 1, dyn_size):
            tag, val = struct.unpack_from(dyn_fmt, blob, off)
            if tag == DT_NULL:
                break
            if tag == DT_NEEDED:
                needed.append(_cstr(dynstr, val))
            elif tag == DT_SONAME:
                soname = _cstr(dynstr, val)
    exports = []
    for s in sections:
        if s["type"] != SHT_DYNSYM:
            continue
        strtab = b""
        if 0 <= s["link"] < len(sections):
            strtab = section_data(sections[s["link"]])
        blob = section_data(s)
        entsize = s["entsize"] or sym_size
        if entsize < sym_size:
            raise OracleElfError(
                f"{name}: bad symbol entry size")
        for off in range(0, len(blob) - sym_size + 1, entsize):
            if is_64:
                name_off, info, _other, shndx, _v, _sz = \
                    struct.unpack_from(sym_fmt, blob, off)
            else:
                name_off, _v, _sz, info, _other, shndx = \
                    struct.unpack_from(sym_fmt, blob, off)
            bind = info >> 4
            sym_name = _cstr(strtab, name_off)
            if shndx != 0 and sym_name \
                    and bind in (STB_GLOBAL, STB_WEAK):
                exports.append(sym_name)
    exports = sorted(set(exports))
    return {
        "needed": sorted(set(needed)),
        "soname": soname,
        "exports": exports,
        "jni_exports": [e for e in exports
                        if e.startswith("Java_")],
    }


def readelf_facts(data):
    """Cross-check facts via GNU readelf (-d -s -W) on a
    temp copy, or None when readelf is unavailable/fails."""
    readelf = shutil.which("readelf")
    if not readelf:
        return None
    with tempfile.NamedTemporaryFile(
            suffix=".so", delete=True) as fh:
        fh.write(data)
        fh.flush()
        try:
            proc = subprocess.run(
                [readelf, "-W", "-d", "-s", fh.name],
                capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired):
            return None
    if proc.returncode != 0:
        return None
    needed = sorted(set(re.findall(
        r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]",
        proc.stdout)))
    exports = set()
    in_dynsym = False
    for line in proc.stdout.splitlines():
        if "Symbol table '.dynsym'" in line:
            in_dynsym = True
            continue
        if "Symbol table '" in line and ".dynsym" not in line:
            in_dynsym = False
        if not in_dynsym:
            continue
        parts = line.split()
        # Num: Value Size Type Bind Vis Ndx Name
        if len(parts) >= 8 and parts[0].rstrip(":").isdigit():
            bind, ndx, sym_name = parts[4], parts[6], parts[7]
            if bind in ("GLOBAL", "WEAK") and ndx != "UND" \
                    and sym_name:
                exports.add(sym_name.split("@")[0])
    exports = sorted(exports)
    return {
        "needed": needed,
        "exports": exports,
        "jni_exports": [e for e in exports
                        if e.startswith("Java_")],
    }


# ------------------------------------------------------------------
# Expected side
# ------------------------------------------------------------------

def _family_prefixes():
    """{family name: [jni prefixes]} from scripts/
    formats.json — marker DATA only (see module docstring).
    """
    data = json.loads(
        (SCRIPTS / "formats.json").read_text(encoding="utf-8"))
    out = {}
    for entry in (data.get("engines") or {}).values():
        prefixes = ((entry.get("jni") or {}).get("prefixes")
                    or [])
        if prefixes:
            out[entry["name"]] = list(prefixes)
    return out


def build_expected(apk_path):
    """Expected facts for one APK, derived without NAR:
    zipfile inventory + the in-harness ELF reader (+ the
    readelf cross-check where available)."""
    libraries = {}
    with zipfile.ZipFile(apk_path) as zf:
        for member in sorted(zf.namelist()):
            m = SO_MEMBER_RE.match(member)
            if not m:
                continue
            display = f"{m.group(1)}/{m.group(2)}"
            data = zf.read(member)
            facts = read_elf_facts(data, member)
            cross = readelf_facts(data)
            libraries[display] = {
                "member": member,
                "needed": facts["needed"],
                "jni_exports": facts["jni_exports"],
                "exports": facts["exports"],
                "readelf": cross,
            }
    engine_jni = {}
    prefixes = _family_prefixes()
    for family, prefs in sorted(prefixes.items()):
        matched = set()
        libs = []
        for display, lib in libraries.items():
            hits = [e for e in lib["exports"]
                    if any(e.startswith(p) for p in prefs)]
            if hits:
                matched.update(hits)
                libs.append(display)
        if matched:
            engine_jni[family] = {
                "count": len(matched),
                "libraries": sorted(libs),
            }
    return {
        "label": "SYNTHETIC",
        "libraries": libraries,
        "library_count": len(libraries),
        "engine_jni": engine_jni,
    }


# ------------------------------------------------------------------
# Actual side: NAR tools as subprocesses
# ------------------------------------------------------------------

def _run_tool_json(script, target):
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / script), str(target),
         "--json"],
        capture_output=True, text=True, timeout=900)
    if proc.returncode != 0:
        raise RuntimeError(
            f"{script} exited {proc.returncode}: "
            f"{proc.stderr.strip()[:400]}")
    return json.loads(proc.stdout)


def nar_actual(apk_path):
    native = _run_tool_json("nar-native.py", apk_path)
    engines = _run_tool_json("nar-engines.py", apk_path)
    libraries = {}
    for lib in native.get("libraries") or []:
        display = lib.get("display_name") or lib.get("name")
        if "error" in lib:
            libraries[display] = {"error": lib["error"]}
            continue
        libraries[display] = {
            "needed": sorted(lib.get("needed") or []),
            "jni_exports": sorted(lib.get("jni_exports") or []),
        }
    engine_jni = {}
    for verdict in engines.get("verdicts") or []:
        jni = verdict.get("jni_symbols")
        if not jni:
            continue
        # nar-engines records plain member paths for a
        # single-archive target; normalise to the display
        # form (abi/file) nar-native uses.
        norm = []
        for entry in jni.get("libraries") or []:
            m = SO_MEMBER_RE.match(entry)
            norm.append(f"{m.group(1)}/{m.group(2)}"
                        if m else entry)
        engine_jni[verdict["engine"]] = {
            "count": jni.get("match_count"),
            "libraries": sorted(norm),
        }
    scan = engines.get("jni_scan") or {}
    return {
        "libraries": libraries,
        "library_count": native.get("native_library_count"),
        "engine_jni": engine_jni,
        "libraries_scanned": scan.get("libraries_scanned"),
    }


# ------------------------------------------------------------------
# Comparison (pure; the planted-discrepancy tests drive this)
# ------------------------------------------------------------------

def compare_inventory(expected, actual):
    """Diff an expected dict (build_expected shape) against
    an actual dict (nar_actual shape). [] is agreement."""
    diffs = []
    e_libs, a_libs = expected["libraries"], actual["libraries"]
    if set(e_libs) != set(a_libs):
        diffs.append(
            f"library set: oracle={sorted(e_libs)} "
            f"nar={sorted(a_libs)}")
    if expected["library_count"] != actual["library_count"]:
        diffs.append(
            f"native_library_count: "
            f"oracle={expected['library_count']} "
            f"nar={actual['library_count']}")
    for display in sorted(set(e_libs) & set(a_libs)):
        e, a = e_libs[display], a_libs[display]
        if "error" in a:
            diffs.append(
                f"library {display}: nar-native error "
                f"{a['error']}")
            continue
        if e["needed"] != a["needed"]:
            diffs.append(
                f"library {display}: DT_NEEDED "
                f"oracle={e['needed']} nar={a['needed']}")
        if e["jni_exports"] != a["jni_exports"]:
            diffs.append(
                f"library {display}: JNI exports "
                f"oracle={e['jni_exports']} "
                f"nar={a['jni_exports']}")
        cross = e.get("readelf")
        if cross is not None:
            if cross["needed"] != e["needed"]:
                diffs.append(
                    f"library {display}: oracle self-check — "
                    f"readelf DT_NEEDED {cross['needed']} vs "
                    f"in-harness reader {e['needed']}")
            if cross["jni_exports"] != e["jni_exports"]:
                diffs.append(
                    f"library {display}: oracle self-check — "
                    f"readelf JNI exports "
                    f"{cross['jni_exports']} vs in-harness "
                    f"reader {e['jni_exports']}")
    if expected["library_count"] != actual["libraries_scanned"]:
        diffs.append(
            f"engines libraries_scanned: "
            f"oracle={expected['library_count']} "
            f"nar={actual['libraries_scanned']}")
    e_eng, a_eng = expected["engine_jni"], actual["engine_jni"]
    for family in sorted(set(e_eng) | set(a_eng)):
        if family not in e_eng:
            diffs.append(
                f"engine {family}: JNI match only in NAR "
                f"({a_eng[family]})")
            continue
        if family not in a_eng:
            diffs.append(
                f"engine {family}: oracle census has "
                f"{e_eng[family]['count']} JNI match(es), "
                f"nar-engines reports none")
            continue
        e, a = e_eng[family], a_eng[family]
        if e["count"] != a["count"]:
            diffs.append(
                f"engine {family}: JNI match count "
                f"oracle={e['count']} nar={a['count']}")
        if e["libraries"] != a["libraries"]:
            diffs.append(
                f"engine {family}: JNI libraries "
                f"oracle={e['libraries']} "
                f"nar={a['libraries']}")
    return diffs


# ------------------------------------------------------------------
# Driver
# ------------------------------------------------------------------

def run_inventory(apk_path, expected=None):
    """Run the differential over one APK. `expected` may be
    supplied (the planted-discrepancy tests build the
    expectation from a pristine fixture and run the actual
    side against an altered copy)."""
    report = {"tool": "oracle_inventory", "label": "SYNTHETIC",
              "target": str(apk_path)}
    try:
        exp = expected if expected is not None \
            else build_expected(apk_path)
        act = nar_actual(apk_path)
    except (OSError, ValueError, RuntimeError,
            zipfile.BadZipFile, OracleElfError) as e:
        report["status"] = "error"
        report["reason"] = str(e)
        return report
    diffs = compare_inventory(exp, act)
    report["expected"] = {
        "library_count": exp["library_count"],
        "libraries": {
            k: {"needed": v["needed"],
                "jni_exports": v["jni_exports"],
                "readelf_cross_check":
                    "unavailable" if v.get("readelf") is None
                    else "run"}
            for k, v in exp["libraries"].items()},
        "engine_jni": exp["engine_jni"],
    }
    report["diffs"] = diffs
    report["status"] = "mismatch" if diffs else "agree"
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Differential: nar-native / nar-engines "
                    "vs an independent ELF census "
                    "(SYNTHETIC fixture scope).")
    parser.add_argument("apk", help="path to the .apk file")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = run_inventory(args.apk)
    if args.json:
        print(json.dumps(report, indent=2))
    elif report["status"] == "error":
        print(f"oracle_inventory: error — {report['reason']}")
    else:
        print(f"oracle_inventory [SYNTHETIC]: {args.apk}")
        exp = report["expected"]
        for display, lib in sorted(
                exp["libraries"].items()):
            print(f"  {display}: needed={lib['needed']} "
                  f"jni_exports={len(lib['jni_exports'])} "
                  f"(readelf cross-check: "
                  f"{lib['readelf_cross_check']})")
        for family, match in sorted(
                exp["engine_jni"].items()):
            print(f"  engine {family}: {match['count']} JNI "
                  f"match(es) in {match['libraries']}")
        for diff in report["diffs"]:
            print(f"  DIFF {diff}")
        print(f"result: {report['status'].upper()} "
              f"[SYNTHETIC]")
    if report["status"] == "error":
        return 2
    return 0 if report["status"] == "agree" else 1


if __name__ == "__main__":
    sys.exit(main())
