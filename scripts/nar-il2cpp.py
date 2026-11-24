#!/usr/bin/env python3
"""nar-il2cpp.py: locate a Unity IL2CPP pair and summarize the dump.

Given an APK (or a directory holding an extracted pair), finds
assets/bin/Data/Managed/Metadata/global-metadata.dat and
lib/<abi>/libil2cpp.so, reads the metadata format version from the
metadata header, then runs Il2CppDumper when one is available and
summarizes its output: type count, method count, and the top
namespaces by type count.

When Il2CppDumper (or the .NET runtime it needs) is missing, the pair
and the metadata version are still reported and the missing piece is
named plainly; nothing is invented.

An optional second backend, Cpp2IL, can be selected with
--backend cpp2il (or $NAR_IL2CPP_BACKEND=cpp2il); Il2CppDumper
remains the default. Cpp2IL's dummy-DLL output is summarized
by narlib's own ECMA-335 reader (TypeDef / MethodDef row
counts), so its summary has the same shape with one stated
difference: its method count is MethodDef rows (all declared
methods), while Il2CppDumper's is RVA-marked methods (methods
with native bodies).

Usage:
    python3 nar-il2cpp.py game.apk [--json] [--out DIR]
    python3 nar-il2cpp.py extracted-dir/ [--json] [--out DIR]
    python3 nar-il2cpp.py game.apk --backend cpp2il [--json]

The extracted pair and the dump are written under --out (default: a
nar-il2cpp-<name> directory in the system temp dir); the paths are
printed either way. Stdlib only; Il2CppDumper and dotnet are external
tools located the same way nar-doctor locates them.

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import collections
import glob
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib.dotnetmeta import DotNetMetaError, summarize_dlls  # noqa: E402

METADATA_MAGIC = 0xFAB11BAF
DUMP_TIMEOUT = 1800  # seconds; big games dump slowly

# Bounded pair extraction (2.6.1 deep-audit remediation):
# the IL2CPP pair is streamed out of the APK, but a
# crafted entry could inflate without limit. The cap
# matches narlib.safearchive's per-file ceiling — far
# above any real libil2cpp.so / global-metadata.dat —
# and is enforced on the declared size and again on the
# streamed byte count.
MAX_PAIR_ENTRY_BYTES = 1024 * 1024 * 1024


def _extract_capped(zf, entry, dst_path):
    """Stream one zip entry to dst_path under the pair
    cap. Raises ValueError on refusal; a partially
    written file is removed first."""
    declared = zf.getinfo(entry).file_size
    if declared > MAX_PAIR_ENTRY_BYTES:
        raise ValueError(
            f"entry {entry} declares {declared} bytes, "
            f"over the {MAX_PAIR_ENTRY_BYTES}-byte "
            "extraction cap")
    written = 0
    try:
        with zf.open(entry) as src, open(dst_path, "wb") as dst:
            while True:
                chunk = src.read(1 << 20)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_PAIR_ENTRY_BYTES:
                    raise ValueError(
                        f"entry {entry} exceeded the "
                        f"{MAX_PAIR_ENTRY_BYTES}-byte "
                        "extraction cap while streaming "
                        "(declared size understated)")
                dst.write(chunk)
    except ValueError:
        try:
            os.unlink(dst_path)
        except OSError:
            pass
        raise
    return dst_path

TYPEDEF_RE = re.compile(r"// TypeDefIndex: \d+")
RVA_RE = re.compile(r"// RVA: 0x[0-9A-Fa-f]+")
NAMESPACE_RE = re.compile(r"^// Namespace: (.*)$", re.MULTILINE)


def find_dotnet():
    cand = shutil.which("dotnet")
    if cand:
        return cand
    for path in (os.path.expanduser("~/workspace/tools/dotnet/dotnet"),
                 "/usr/share/dotnet/dotnet", "/usr/lib/dotnet/dotnet"):
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def find_dumper():
    """Return (kind, path): kind is 'dotnet-dll' or 'binary'."""
    env = os.environ.get("NAR_IL2CPPDUMPER_DLL")
    if env and os.path.isfile(env):
        return "dotnet-dll", env
    dll = os.path.expanduser("~/workspace/tools/il2cppdumper/Il2CppDumper.dll")
    if os.path.isfile(dll):
        return "dotnet-dll", dll
    for name in ("Il2CppDumper", "il2cppdumper"):
        cand = shutil.which(name)
        if cand:
            return "binary", cand
    return None, None


CPP2IL_VERSION_RE = re.compile(r"Version (\S+)")


def find_cpp2il():
    """Return (path, version): probe $NAR_CPP2IL, the tools
    dir, then PATH; version from the tool's own banner."""
    candidates = []
    env = os.environ.get("NAR_CPP2IL")
    if env:
        candidates.append(env)
    candidates.append(os.path.expanduser(
        "~/workspace/tools/cpp2il/Cpp2IL"))
    for name in ("Cpp2IL", "cpp2il"):
        found = shutil.which(name)
        if found:
            candidates.append(found)
    for cand in candidates:
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            version = None
            try:
                proc = subprocess.run(
                    [cand, "--version"], capture_output=True,
                    text=True, timeout=30)
                m = CPP2IL_VERSION_RE.search(
                    (proc.stdout or "") + (proc.stderr or ""))
                if m:
                    version = m.group(1)
            except (OSError, subprocess.TimeoutExpired):
                pass
            return cand, version
    return None, None


def run_cpp2il(target, out_dir):
    """Run the Cpp2IL backend; returns the backend block
    (and fills summary/outputs on the caller's report)."""
    block = {"found": False, "path": None, "version": None,
             "ran": False, "exit_code": None, "error": None}
    path, version = find_cpp2il()
    block["path"] = path
    block["version"] = version
    if not path:
        block["error"] = (
            "Cpp2IL not found (looked at $NAR_CPP2IL,"
            " ~/workspace/tools/cpp2il/Cpp2IL, and PATH)."
            " Il2CppDumper remains available as the default"
            " backend.")
        return block, None, None
    block["found"] = True
    if os.path.isdir(target):
        # Cpp2IL discovers its inputs from a game layout or
        # an APK; its force-path options additionally demand
        # a Unity version, which a bare extracted pair does
        # not carry (the metadata version is not the Unity
        # version, and guessing one would fabricate input).
        block["error"] = (
            "Cpp2IL backend needs an APK target: it discovers"
            " the IL2CPP pair and Unity version from the game"
            " package, and a bare extracted pair carries no"
            " Unity version to give its force-path options."
            " Use the default Il2CppDumper backend for"
            " extracted pairs.")
        return block, None, None
    cpp_dir = os.path.join(out_dir, "cpp2il")
    os.makedirs(cpp_dir, exist_ok=True)
    cmd = [path, "--game-path", target,
           "--output-as", "dll_default",
           "--output-to", cpp_dir]
    try:
        proc = subprocess.run(cmd, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True,
                              timeout=DUMP_TIMEOUT)
        block["ran"] = True
        block["exit_code"] = proc.returncode
        tail = (proc.stdout or "") + (proc.stderr or "")
        block["output_tail"] = tail.strip()[-500:]
        if proc.returncode != 0:
            block["error"] = (
                f"Cpp2IL exited {proc.returncode}; see output_tail")
            return block, None, None
    except subprocess.TimeoutExpired:
        block["error"] = (
            f"Cpp2IL did not finish within {DUMP_TIMEOUT}s")
        return block, None, None
    except OSError as e:
        block["error"] = f"could not start Cpp2IL: {e}"
        return block, None, None
    dlls = sorted(glob.glob(os.path.join(cpp_dir, "**", "*.dll"),
                            recursive=True))
    if not dlls:
        block["error"] = "Cpp2IL ran but produced no DLL output"
        return block, None, None
    try:
        summary = summarize_dlls(dlls)
    except DotNetMetaError as e:
        block["error"] = f"could not summarize Cpp2IL output: {e}"
        return block, None, None
    summary["dump_cs_lines"] = None
    summary["method_count_basis"] = (
        "MethodDef rows (all declared methods)")
    outputs = {"dir": os.path.abspath(cpp_dir),
               "assemblies": summary.pop("assemblies"),
               "dll_glob": os.path.join(
                   os.path.abspath(cpp_dir), "*.dll")}
    return block, summary, outputs


def metadata_version(blob):
    """(magic_ok, version) from the first 8 bytes of global-metadata.dat."""
    if len(blob) < 8:
        return False, None
    magic, version = struct.unpack_from("<II", blob, 0)
    return magic == METADATA_MAGIC, (version if magic == METADATA_MAGIC
                                     else None)


def locate_in_zip(zf):
    names = zf.namelist()
    meta = next((n for n in names
                 if n.endswith("Managed/Metadata/global-metadata.dat")), None)
    libs = [n for n in names
            if n.startswith("lib/") and n.endswith("/libil2cpp.so")]
    libs.sort(key=lambda n: (0 if "arm64-v8a" in n else 1, n))
    return meta, (libs[0] if libs else None)


def locate_in_dir(root):
    meta = so = None
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            path = os.path.join(dirpath, name)
            if name == "global-metadata.dat" and meta is None:
                meta = path
            elif name == "libil2cpp.so" and so is None:
                so = path
    return meta, so


def summarize_dump(dump_dir):
    """Count types, methods, and namespaces in Il2CppDumper output."""
    summary = {"types": None, "methods": None, "top_namespaces": [],
               "dump_cs_lines": None}
    dump_cs = os.path.join(dump_dir, "dump.cs")
    if os.path.isfile(dump_cs):
        types = methods = lines = 0
        ns_counts = collections.Counter()
        with open(dump_cs, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                lines += 1
                if TYPEDEF_RE.search(line):
                    types += 1
                if RVA_RE.search(line):
                    methods += 1
                m = NAMESPACE_RE.match(line)
                if m:
                    ns_counts[m.group(1).strip() or "(global)"] += 1
        summary["types"] = types
        summary["methods"] = methods
        summary["dump_cs_lines"] = lines
        summary["top_namespaces"] = [
            {"namespace": ns, "types": n}
            for ns, n in ns_counts.most_common(10)]
    script_json = os.path.join(dump_dir, "script.json")
    if os.path.isfile(script_json) and summary["methods"] is None:
        try:
            with open(script_json, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            summary["methods"] = len(data.get("ScriptMethod", []))
        except (OSError, ValueError):
            pass
    return summary


def analyze(target, out_dir, backend=None):
    report = {"tool": "nar-il2cpp", "target": os.path.abspath(target),
              "is_il2cpp": False}
    backend = (backend or os.environ.get("NAR_IL2CPP_BACKEND")
               or "il2cppdumper")
    if backend not in ("il2cppdumper", "cpp2il"):
        report["error"] = (
            f"unknown IL2CPP backend {backend!r} (expected"
            " 'il2cppdumper' or 'cpp2il')")
        return report
    report["backend"] = backend
    if not os.path.exists(target):
        raise FileNotFoundError(f"not found: {target}")
    os.makedirs(out_dir, exist_ok=True)
    inputs_dir = os.path.join(out_dir, "inputs")
    dump_dir = os.path.join(out_dir, "dump")
    meta_src = so_src = None
    meta_entry = so_entry = None
    if os.path.isdir(target):
        meta_src, so_src = locate_in_dir(target)
    elif zipfile.is_zipfile(target):
        with zipfile.ZipFile(target) as zf:
            meta_entry, so_entry = locate_in_zip(zf)
            if meta_entry and so_entry:
                os.makedirs(inputs_dir, exist_ok=True)
                meta_src = os.path.join(inputs_dir, "global-metadata.dat")
                so_src = os.path.join(inputs_dir, "libil2cpp.so")
                try:
                    _extract_capped(zf, meta_entry, meta_src)
                    _extract_capped(zf, so_entry, so_src)
                except ValueError as e:
                    report["error"] = (
                        f"IL2CPP pair extraction refused: {e}")
                    return report
    else:
        report["error"] = "target is neither an APK/ZIP nor a directory"
        return report
    if not meta_src or not so_src:
        report["error"] = ("no IL2CPP pair found (need both"
                           " global-metadata.dat and libil2cpp.so);"
                           " this is not a Unity IL2CPP build, or the"
                           " pair lives outside the given target")
        # Report which piece WAS located: for ZIP targets the
        # extraction above only materializes meta_src/so_src when
        # BOTH entries exist, so the entry names are the evidence
        # (regression: a split config APK carrying libil2cpp.so
        # alone reported found={metadata: False, binary: False}).
        report["found"] = {"metadata": bool(meta_src or meta_entry),
                           "binary": bool(so_src or so_entry)}
        return report
    report["is_il2cpp"] = True
    with open(meta_src, "rb") as fh:
        head = fh.read(8)
    magic_ok, version = metadata_version(head)
    abi = None
    if so_entry and so_entry.startswith("lib/"):
        abi = so_entry.split("/")[1]
    report["metadata"] = {
        "source": meta_entry or meta_src,
        "size_bytes": os.path.getsize(meta_src),
        "magic_ok": magic_ok,
        "version": version,
        "note": None if magic_ok else
                "metadata magic is not the standard IL2CPP magic; the"
                " file may be encrypted or obfuscated, so no version"
                " can be read from the header",
    }
    report["binary"] = {
        "source": so_entry or so_src,
        "abi": abi,
        "size_bytes": os.path.getsize(so_src),
    }
    if backend == "cpp2il":
        block, summary, outputs = run_cpp2il(target, out_dir)
        report["cpp2il"] = block
        if summary is not None:
            report["summary"] = summary
            report["outputs"] = outputs
        return report
    kind, dumper_path = find_dumper()
    dotnet = find_dotnet() if kind == "dotnet-dll" else None
    report["dumper"] = {"found": bool(dumper_path), "path": dumper_path,
                        "via": kind, "dotnet": dotnet, "ran": False,
                        "exit_code": None, "error": None}
    if not dumper_path:
        report["dumper"]["error"] = (
            "Il2CppDumper not found (looked for Il2CppDumper.dll under"
            " ~/workspace/tools/il2cppdumper, $NAR_IL2CPPDUMPER_DLL,"
            " and PATH). The pair and metadata version above are the"
            " full result without it.")
        return report
    if kind == "dotnet-dll" and not dotnet:
        report["dumper"]["error"] = (
            "Il2CppDumper.dll found but no .NET runtime (dotnet) to run"
            " it with; install .NET 6+ or set PATH to one.")
        return report
    os.makedirs(dump_dir, exist_ok=True)
    cmd = ([dotnet, dumper_path] if kind == "dotnet-dll"
           else [dumper_path])
    cmd += [so_src, meta_src, dump_dir]
    try:
        proc = subprocess.run(cmd, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True,
                              timeout=DUMP_TIMEOUT)
        report["dumper"]["ran"] = True
        report["dumper"]["exit_code"] = proc.returncode
        tail = (proc.stdout or "") + (proc.stderr or "")
        report["dumper"]["output_tail"] = tail.strip()[-500:]
        if proc.returncode != 0:
            report["dumper"]["error"] = (
                f"Il2CppDumper exited {proc.returncode}; see output_tail")
    except subprocess.TimeoutExpired:
        report["dumper"]["error"] = (
            f"Il2CppDumper did not finish within {DUMP_TIMEOUT}s")
    except OSError as e:
        report["dumper"]["error"] = f"could not start Il2CppDumper: {e}"
    if os.path.isfile(os.path.join(dump_dir, "dump.cs")):
        report["summary"] = summarize_dump(dump_dir)
        report["outputs"] = {
            "dir": os.path.abspath(dump_dir),
            "dump_cs": os.path.join(os.path.abspath(dump_dir), "dump.cs"),
            "script_json": os.path.join(os.path.abspath(dump_dir),
                                        "script.json"),
            "il2cpp_h": os.path.join(os.path.abspath(dump_dir), "il2cpp.h"),
        }
    return report


def human(report):
    lines = [f"NAR IL2CPP: {report['target']}"]
    if not report.get("is_il2cpp"):
        lines.append(f"NOT IL2CPP: {report.get('error', 'pair not found')}")
        return "\n".join(lines)
    meta = report["metadata"]
    binary = report["binary"]
    lines.append(f"Metadata: {meta['source']} ({meta['size_bytes']:,} bytes),"
                 f" format version {meta['version']}")
    if meta.get("note"):
        lines.append(f"  note: {meta['note']}")
    lines.append(f"Binary:   {binary['source']} ({binary['size_bytes']:,}"
                 f" bytes, ABI {binary['abi'] or 'unknown'})")
    if report.get("backend") == "cpp2il":
        cpp = report["cpp2il"]
        if not cpp["found"]:
            lines.append(f"Cpp2IL: NOT FOUND. {cpp['error']}")
        elif report.get("summary"):
            s = report["summary"]
            lines.append(
                f"Cpp2IL {cpp.get('version') or ''}: ran "
                f"(exit {cpp['exit_code']})")
            lines.append(f"Types: {s['types']:,}   Methods "
                         f"(MethodDef rows): {s['methods']:,}")
            lines.append("Top namespaces by type count:")
            for item in s["top_namespaces"]:
                lines.append(f"  {item['namespace']}: {item['types']:,}")
            lines.append(f"Assemblies: "
                         f"{report['outputs']['assemblies']} in "
                         f"{report['outputs']['dir']}")
        else:
            lines.append(
                f"Cpp2IL: {cpp.get('error') or 'ran but produced no summary'}")
        return "\n".join(lines)
    dumper = report["dumper"]
    if not dumper["found"]:
        lines.append(f"Il2CppDumper: NOT FOUND. {dumper['error']}")
    elif dumper["error"] and not dumper["ran"]:
        lines.append(f"Il2CppDumper: {dumper['error']}")
    elif report.get("summary"):
        s = report["summary"]
        lines.append(f"Il2CppDumper: ran (exit {dumper['exit_code']})")
        lines.append(f"Types: {s['types']:,}   Methods (RVA-marked):"
                     f" {s['methods']:,}")
        lines.append("Top namespaces by type count:")
        for item in s["top_namespaces"]:
            lines.append(f"  {item['namespace']}: {item['types']:,}")
        lines.append(f"Dump: {report['outputs']['dump_cs']}")
    else:
        lines.append(f"Il2CppDumper: {dumper.get('error') or 'ran but produced no dump.cs'}")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR Unity IL2CPP locator + Il2CppDumper summary.")
    p.add_argument("target", help="path to the .apk or an extracted dir")
    p.add_argument("--json", action="store_true",
                   help="machine-readable JSON output")
    p.add_argument("--out", metavar="DIR",
                   help="work/output directory (default: temp dir)")
    p.add_argument("--backend", choices=("il2cppdumper", "cpp2il"),
                   default=None,
                   help="dump backend (default: il2cppdumper, or"
                        " $NAR_IL2CPP_BACKEND)")
    args = p.parse_args(argv)
    stem = os.path.splitext(os.path.basename(
        os.path.abspath(args.target).rstrip("/")))[0] or "target"
    # mkdtemp, not a predictable gettempdir()/<stem> path
    # (Phase 10 temp audit): unpredictable + 0700, so a
    # pre-planted directory or symlink cannot redirect the
    # dump output. The chosen path is reported as out_dir.
    out_dir = args.out or tempfile.mkdtemp(
        prefix=f"nar-il2cpp-{stem}-")
    try:
        report = analyze(args.target, out_dir, backend=args.backend)
    except FileNotFoundError as e:
        print(f"nar-il2cpp: {e}", file=sys.stderr)
        return 2
    report["out_dir"] = os.path.abspath(out_dir)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(human(report))
    return 0 if report.get("is_il2cpp") else 1


if __name__ == "__main__":
    sys.exit(main())
