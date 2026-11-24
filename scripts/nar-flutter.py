#!/usr/bin/env python3
"""nar-flutter.py: fingerprint a Flutter build from its native libs.

Given an APK, looks for lib/<abi>/libflutter.so (the engine) and
lib/<abi>/libapp.so (the compiled Dart application) and reports:

- whether the app is Flutter at all (clean negative otherwise),
- the ABIs the engine ships for,
- the Dart VM version string embedded in the engine binary,
- the Flutter framework version string embedded in the app snapshot,
- AOT snapshot markers (_kDartVmSnapshotData and friends) and
  whether a kernel blob (debug/JIT build) ships instead.

All reads are static byte scans of the shipped binaries; nothing is
executed and no behavior is claimed. Stdlib only.

Usage:
    python3 nar-flutter.py app.apk [--json]

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import re
import sys
import zipfile

STABLE_RE = re.compile(rb"(\d+\.\d+\.\d+) \(stable\)")
DART_VM_RE = re.compile(rb"Dart VM version:?\s*(\d+\.\d+\.\d+)")
SNAPSHOT_MARKERS = (
    b"_kDartVmSnapshotData",
    b"_kDartVmSnapshotInstructions",
    b"_kDartIsolateSnapshotData",
    b"_kDartIsolateSnapshotInstructions",
)
SCAN_CAP = 64 * 1024 * 1024  # bytes per library; versions sit early


_ASSET_TYPES = (
    ("image", (".png", ".jpg", ".jpeg", ".webp", ".gif",
               ".svg", ".bmp", ".ico")),
    ("font", (".ttf", ".otf", ".ttc")),
    ("audio", (".mp3", ".ogg", ".wav", ".m4a", ".flac",
               ".aac")),
    ("video", (".mp4", ".webm", ".mov")),
    ("shader", (".frag", ".vert", ".glsl", ".spv")),
    ("data", (".json", ".yaml", ".yml", ".txt", ".md",
              ".csv", ".xml", ".html")),
)


def _asset_type(rel_path):
    low = rel_path.lower()
    if low in ("assetmanifest.json", "assetmanifest.bin"):
        return "asset manifest"
    if low in ("kernel_blob.bin", "vm_snapshot_data",
               "isolate_snapshot_data"):
        return "dart snapshot/kernel"
    if low == "fontmanifest.json":
        return "font manifest"
    if low.startswith("notices"):
        return "licenses"
    for kind, exts in _ASSET_TYPES:
        if low.endswith(exts):
            return kind
    return "other"


def flutter_asset_inventory(zf, names):
    """Real inventory of assets/flutter_assets: every entry
    with its size and a type (classified by file name /
    extension — labeled as such; the engine's own
    AssetManifest is parsed for the declared asset keys
    when the JSON form ships)."""
    prefix = "assets/flutter_assets/"
    entries = []
    by_type = {}
    total = 0
    manifest = {"json_present": False, "bin_present": False,
                "declared_assets": None}
    for name in names:
        if not name.startswith(prefix) or name.endswith("/"):
            continue
        rel = name[len(prefix):]
        size = zf.getinfo(name).file_size
        kind = _asset_type(rel)
        entries.append({"path": rel, "size_bytes": size,
                        "type": kind})
        by_type[kind] = by_type.get(kind, 0) + 1
        total += size
        if rel == "AssetManifest.json":
            manifest["json_present"] = True
            try:
                doc = json.loads(zf.read(name).decode(
                    "utf-8", "replace"))
                if isinstance(doc, dict):
                    manifest["declared_assets"] = len(doc)
            except ValueError:
                pass
        elif rel == "AssetManifest.bin":
            manifest["bin_present"] = True
    entries.sort(key=lambda e: e["path"])
    return {
        "entry_count": len(entries),
        "total_bytes": total,
        "by_type": dict(sorted(by_type.items())),
        "entries": entries[:200],
        "entries_truncated": len(entries) > 200,
        "asset_manifest": manifest,
        "type_evidence": "file name / extension",
    }


def _first_version(data, patterns):
    for pat in patterns:
        m = pat.search(data)
        if m:
            return m.group(1).decode("ascii", "replace")
    return None


def fingerprint(apk_path):
    report = {"tool": "nar-flutter", "file": os.path.basename(apk_path),
              "path": os.path.abspath(apk_path), "is_flutter": False}
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"not a file: {apk_path}")
    if not zipfile.is_zipfile(apk_path):
        report["error"] = "not a ZIP/APK file"
        return report
    with zipfile.ZipFile(apk_path) as zf:
        names = zf.namelist()
        engine = sorted(n for n in names
                        if n.startswith("lib/")
                        and n.endswith("/libflutter.so"))
        app = sorted(n for n in names
                     if n.startswith("lib/") and n.endswith("/libapp.so"))
        abis = sorted({n.split("/")[1] for n in engine + app
                       if n.startswith("lib/")})
        report["abis"] = abis
        report["engine_libs"] = engine
        report["app_libs"] = app
        report["has_flutter_assets"] = any(
            n.startswith("assets/flutter_assets/") for n in names)
        if report["has_flutter_assets"]:
            report["flutter_assets"] = flutter_asset_inventory(
                zf, names)
        report["kernel_blob"] = any(
            n.endswith("kernel_blob.bin") for n in names)
        if not engine and not app:
            report["note"] = ("no libflutter.so or libapp.so in any ABI"
                               " directory: not a Flutter build")
            return report
        report["is_flutter"] = True
        markers = set()
        dart_version = flutter_version = None
        if engine:
            data = zf.read(engine[0])[:SCAN_CAP]
            dart_version = _first_version(data, (DART_VM_RE, STABLE_RE))
            markers |= {m.decode() for m in SNAPSHOT_MARKERS if m in data}
        if app:
            data = zf.read(app[0])[:SCAN_CAP]
            flutter_version = _first_version(data, (STABLE_RE,))
            markers |= {m.decode() for m in SNAPSHOT_MARKERS if m in data}
        report["dart_version"] = dart_version
        report["dart_version_source"] = (
            "libflutter.so (engine)" if dart_version else None)
        report["flutter_version"] = flutter_version
        report["flutter_version_source"] = (
            "libapp.so (app snapshot)" if flutter_version else None)
        report["snapshot_markers"] = sorted(markers)
        report["aot_snapshot"] = bool(markers)
        if report["kernel_blob"]:
            report["build_mode"] = ("kernel blob present: debug/JIT-style"
                                     " build, Dart ships as bytecode, not"
                                     " AOT machine code")
        elif markers:
            report["build_mode"] = ("AOT snapshot present: release/profile"
                                    " style build")
        else:
            report["build_mode"] = ("no snapshot markers found in the"
                                     " scanned prefix; mode undetermined")
    return report


def human(report):
    lines = [f"NAR Flutter fingerprint: {report['file']}"]
    if not report.get("is_flutter"):
        lines.append(f"NOT FLUTTER: {report.get('note') or report.get('error')}")
        return "\n".join(lines)
    lines.append(f"ABIs: {', '.join(report['abis'])}")
    lines.append(f"Dart version: {report['dart_version'] or 'not found'}"
                 f" (source: {report['dart_version_source'] or 'n/a'})")
    lines.append(f"Flutter version: {report['flutter_version'] or 'not found'}"
                 f" (source: {report['flutter_version_source'] or 'n/a'})")
    lines.append(f"AOT snapshot markers: "
                 f"{', '.join(report['snapshot_markers']) or 'none'}")
    lines.append(f"Build mode: {report['build_mode']}")
    inv = report.get("flutter_assets")
    if inv:
        lines.append(f"Flutter assets: {inv['entry_count']} "
                     f"entries, {inv['total_bytes']:,} bytes; "
                     f"by type: {inv['by_type']}")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR Flutter/Dart fingerprint from libflutter/libapp.")
    p.add_argument("apk", help="path to the .apk file")
    p.add_argument("--json", action="store_true",
                   help="machine-readable JSON output")
    args = p.parse_args(argv)
    try:
        report = fingerprint(args.apk)
    except FileNotFoundError as e:
        print(f"nar-flutter: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(human(report))
    return 0 if "error" not in report else 1


if __name__ == "__main__":
    sys.exit(main())
