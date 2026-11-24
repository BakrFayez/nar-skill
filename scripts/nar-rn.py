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

A *.bundle extension alone is NOT React Native evidence: Unity
Addressables asset bundles share the extension. Candidates found
by extension are therefore content-validated (Hermes magic or
JavaScript text) before anything is claimed, and UnityFS-magic
files are rejected as Unity asset bundles by name.

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
UNITYFS_MAGIC = b"UnityFS"
BUNDLE_CANDIDATES = ("assets/index.android.bundle",)


def find_bundle_candidates(names):
    """Split bundle-looking entries into (contract, fallbacks).

    The contract entry is React Native's own asset name; its mere
    presence is RN evidence. Fallbacks are any other *.bundle /
    *.jsbundle under assets/ — an extension Unity Addressables
    shares — so they are claims only after content validation.
    """
    contract = next((c for c in BUNDLE_CANDIDATES if c in names), None)
    fallbacks = [n for n in names
                 if n.startswith("assets/") and n != contract
                 and (n.endswith(".bundle") or n.endswith(".jsbundle"))]
    return contract, fallbacks


def classify_bundle_head(head):
    """Classify a bundle from its first bytes.

    Returns "hermes", "unityfs", "js" (JavaScript text), or
    "binary" (anything else). Only the first two and "js" are
    decisive; "binary" means the bytes prove nothing either way.
    """
    if head[:8] == HERMES_MAGIC:
        return "hermes"
    if head[:len(UNITYFS_MAGIC)] == UNITYFS_MAGIC:
        return "unityfs"
    sample = head[:4096]
    if sample:
        printable = sum(1 for b in sample if 9 <= b <= 126)
        if printable / len(sample) > 0.95:
            return "js"
    return "binary"


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


_TURBO_RE = re.compile(
    r"TurboModuleRegistry\.(?:get|getEnforcing)"
    r"\(\s*['\"]([A-Za-z_$][\w$]*)['\"]")
_FABRIC_RE = re.compile(
    r"codegenNativeComponent(?:<[^>]*>)?"
    r"\(\s*['\"]([A-Za-z_$][\w$]*)['\"]")
_NATIVE_REF_RE = re.compile(r"NativeModules\.([A-Za-z_$][\w$]*)")
_SOURCEMAP_URL_RE = re.compile(r"//# sourceMappingURL=(\S+)")


_ARCH_MARKERS = ("TurboModuleRegistry", "codegenNativeComponent",
                 "NativeModules", "__turboModuleProxy")


def bundle_module_inventory(data, is_text):
    """Native-module inventory from bundle markers.

    Architecture markers (TurboModuleRegistry,
    codegenNativeComponent, NativeModules,
    __turboModuleProxy) are counted in the raw bundle for
    both text and Hermes bundles — in Hermes bytecode they
    appear as standalone string-table entries, which proves
    the architecture is present but does not attribute
    module names: the literals sit in the table separately
    from their call sites, and attributing them needs
    bytecode reference analysis (out of scope, stated in
    the report). For text bundles the names are extracted
    from the call sites themselves (TurboModuleRegistry
    .get/.getEnforcing, codegenNativeComponent,
    NativeModules.<name> references). Either way this is
    an inventory of what the bundle references — not proof
    of what the native side registers.
    """
    markers = {m: data.count(m.encode()) for m in _ARCH_MARKERS}
    out = {"architecture_markers": markers}
    text = data.decode("utf-8", "ignore")
    m = _SOURCEMAP_URL_RE.search(text[-8192:])
    out["bundle_source_mapping_url"] = m.group(1) if m else None
    if not is_text:
        out["module_names_extracted"] = False
        out["note"] = ("Hermes bytecode: module names are "
                       "standalone string-table entries and "
                       "cannot be attributed to TurboModule / "
                       "Fabric call sites without bytecode "
                       "reference analysis; marker counts "
                       "above are the evidence available")
        return out
    turbo = sorted(set(_TURBO_RE.findall(text)))
    fabric = sorted(set(_FABRIC_RE.findall(text)))
    referenced = sorted(set(_NATIVE_REF_RE.findall(text)))
    out.update({
        "module_names_extracted": True,
        "turbomodules": turbo[:100],
        "turbomodule_count": len(turbo),
        "fabric_components": fabric[:100],
        "fabric_component_count": len(fabric),
        "native_modules_referenced": referenced[:100],
        "native_module_reference_count": len(referenced),
        "evidence": "names extracted from bundle call sites "
                    "(TurboModuleRegistry / "
                    "codegenNativeComponent / NativeModules "
                    "references)",
    })
    return out


def inspect(apk_path, work_dir):
    report = {"tool": "nar-rn", "file": os.path.basename(apk_path),
              "path": os.path.abspath(apk_path), "is_react_native": False}
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"not a file: {apk_path}")
    if not zipfile.is_zipfile(apk_path):
        report["error"] = "not a ZIP/APK file"
        return report
    with zipfile.ZipFile(apk_path) as zf:
        report["source_maps"] = sorted(
            n for n in zf.namelist() if n.endswith(".map"))
        contract, fallbacks = find_bundle_candidates(zf.namelist())
        entry = None
        data = None
        rejected = []
        if contract is not None:
            entry = contract
            data = zf.read(entry)
        else:
            for cand in fallbacks:
                with zf.open(cand) as fh:
                    kind = classify_bundle_head(fh.read(8192))
                if kind in ("hermes", "js"):
                    entry = cand
                    data = zf.read(cand)
                    report["bundle_match"] = ("content-validated"
                                              " fallback asset")
                    break
                rejected.append({
                    "entry": cand,
                    "kind": ("Unity asset bundle (UnityFS)"
                             if kind == "unityfs" else
                             "binary, not Hermes or JavaScript text"),
                })
        if entry is None:
            if rejected:
                report["rejected_bundles"] = rejected
                report["note"] = (
                    "found *.bundle assets but none is a React Native"
                    " JS bundle ("
                    + "; ".join(f"{r['entry']}: {r['kind']}"
                                for r in rejected[:3])
                    + "): not a React Native build")
            else:
                report["note"] = ("no JS bundle asset"
                                  " (index.android.bundle or"
                                  " *.jsbundle) found: not a React"
                                  " Native build, or the bundle ships"
                                  " elsewhere")
            return report
        report["is_react_native"] = True
        report["bundle_entry"] = entry
    os.makedirs(work_dir, exist_ok=True)
    out_path = os.path.join(work_dir, os.path.basename(entry))
    with open(out_path, "wb") as fh:
        fh.write(data)
    report["bundle_path"] = os.path.abspath(out_path)
    report["bundle_size_bytes"] = len(data)
    kind = classify_bundle_head(data[:8192])
    report["native_modules"] = bundle_module_inventory(
        data, is_text=(kind == "js"))
    if kind == "hermes":
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
    elif kind == "js":
        report["engine"] = "JSC / plain JavaScript"
        report["is_hermes"] = False
        report["looks_like_text_js"] = True
        report["first_bytes_hex"] = data[:16].hex()
    else:
        # At the contract path a non-Hermes, non-text bundle is a
        # binary bundle format (e.g. a legacy RAM bundle): report
        # the shape, never a guessed engine.
        report["engine"] = "unknown binary bundle format"
        report["is_hermes"] = False
        report["looks_like_text_js"] = False
        report["first_bytes_hex"] = data[:16].hex()
        report["note"] = ("bundle is neither Hermes bytecode nor"
                          " plain JavaScript text; engine not"
                          " determined from content")
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
    nm = report.get("native_modules") or {}
    if nm.get("module_names_extracted"):
        lines.append(
            f"Native modules: {nm['turbomodule_count']} "
            f"TurboModules, {nm['fabric_component_count']} "
            f"Fabric components, "
            f"{nm['native_module_reference_count']} "
            f"NativeModules references")
    elif nm:
        marks = nm.get("architecture_markers") or {}
        present = [k for k, v in marks.items() if v]
        lines.append(f"Architecture markers in bundle: "
                     f"{present or 'none'} (module names not "
                     f"attributable from bytecode string table)")
    if report.get("source_maps"):
        lines.append(f"Source maps: {report['source_maps']}")
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
