#!/usr/bin/env python3
"""nar-flutter.py: fingerprint a Flutter build from its native libs.

Given an APK, looks for lib/<abi>/libflutter.so (the engine) and
lib/<abi>/libapp.so (the compiled Dart application) and reports:

- whether the app is Flutter at all (clean negative otherwise),
- the ABIs the engine ships for,
- the Dart VM version string embedded in the engine binary,
- the Flutter framework version string embedded in the app snapshot,
- AOT snapshot markers (_kDartVmSnapshotData and friends) and
  whether a kernel blob (debug/JIT build) ships instead,
- a plugin / platform-channel evidence inventory built only
  from shipped artifacts: the generated plugin registrant
  and plugin classes in the DEX class tables (narlib.dex),
  classes declaring the embedding's FlutterPlugin
  interface, channel-shaped strings in the DEX string
  tables and the app library (string evidence, labeled),
  and the manifest's flutterEmbedding meta-data value
  (binary-XML parse).

All reads are static byte scans of the shipped binaries; nothing is
executed and no behavior is claimed. Stdlib only.

Usage:
    python3 nar-flutter.py app.apk [--json]

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import re
import struct
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib.dex import Dex, DexError  # noqa: E402
from narlib.safearchive import read_member_capped  # noqa: E402

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


# ---------------------------------------------------------------
# Plugin registration + platform-channel evidence inventory
#
# Framework facts used below (the Flutter embedding's own
# namespaces, not app facts): the generated registrant is
# io.flutter.plugins.GeneratedPluginRegistrant; embedding
# plugin classes live under io/flutter/plugins/; a plugin
# implementation declares the interface
# io.flutter.embedding.engine.plugins.FlutterPlugin; the
# manifest meta-data name recording the embedding
# generation is "flutterEmbedding".

REGISTRANT_CLASS = "Lio/flutter/plugins/GeneratedPluginRegistrant;"
PLUGIN_NAMESPACE = "Lio/flutter/plugins/"
FLUTTER_PLUGIN_INTERFACE = \
    "Lio/flutter/embedding/engine/plugins/FlutterPlugin;"
EMBEDDING_METADATA_NAME = "flutterEmbedding"
_CLASS_LIST_CAP = 100
_CHANNEL_LIST_CAP = 100

# A platform-channel name is a namespaced string: a
# dotted domain-style segment (or the framework's own
# "flutter" segment), a slash, and a channel path. Plain
# DEX type paths (java/lang/...) have no dot in the first
# segment and are excluded by construction.
_CHANNEL_RE = re.compile(
    r"^(?:[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+|flutter)"
    r"/[A-Za-z][\w./-]*$")
_ASCII_RUN_RE = re.compile(rb"[\x20-\x7e]{4,}")


def _channel_candidates(strings, source):
    out = []
    for s in strings:
        if len(s) <= 128 and _CHANNEL_RE.match(s):
            out.append({"name": s, "source": source,
                        "evidence": "string"})
    return out


def _axml_string_pool(data, off):
    """String list of one AXML string-pool chunk."""
    _type, header_size, _size, count, _styles, flags, \
        strings_start = struct.unpack_from("<HHIIIII", data, off)
    utf8 = bool(flags & 0x100)
    offsets = struct.unpack_from(f"<{count}I", data,
                                 off + header_size)
    strings = []
    base = off + strings_start
    for rel in offsets:
        pos = base + rel
        if utf8:
            # uleb128 char count, uleb128 byte count, bytes
            for _ in range(2):
                while data[pos] & 0x80:
                    pos += 1
                pos += 1
            end = data.index(b"\x00", pos)
            strings.append(data[pos:end].decode(
                "utf-8", "replace"))
        else:
            ln = struct.unpack_from("<H", data, pos)[0]
            pos += 2
            if ln & 0x8000:
                ln = ((ln & 0x7FFF) << 16) | struct.unpack_from(
                    "<H", data, pos)[0]
                pos += 2
            strings.append(data[pos:pos + ln * 2].decode(
                "utf-16-le", "replace"))
    return strings


def manifest_embedding(data):
    """The flutterEmbedding meta-data value from binary
    AndroidManifest.xml bytes, or a record saying why not.

    Minimal AXML walk: string pool + start-element chunks;
    only <meta-data> elements are interpreted. The value
    is the raw string when the writer stored one, else
    the typed integer rendered as text.
    """
    try:
        if len(data) < 8 or \
                struct.unpack_from("<I", data, 0)[0] != 0x00080003:
            return {"present": None,
                    "error": "not a binary AndroidManifest.xml"}
        strings = []
        off = 8
        found = None
        while off + 8 <= len(data):
            chunk_type, _hs, chunk_size = struct.unpack_from(
                "<HHI", data, off)
            if chunk_size < 8 or off + chunk_size > len(data):
                return {"present": None,
                        "error": "malformed AXML chunk"}
            if chunk_type == 0x0001:
                strings = _axml_string_pool(data, off)
            elif chunk_type == 0x0102 and strings:
                _ns, name_idx = struct.unpack_from(
                    "<II", data, off + 16)
                el_name = strings[name_idx] \
                    if name_idx < len(strings) else ""
                if el_name == "meta-data":
                    attr_start, attr_size, attr_count = \
                        struct.unpack_from("<HHH", data, off + 24)
                    attrs = {}
                    for i in range(attr_count):
                        a_off = off + 16 + attr_start \
                            + i * attr_size
                        _a_ns, a_name, a_raw, _sz, _z, \
                            a_type, a_data = struct.unpack_from(
                                "<IIIHBBI", data, a_off)
                        key = strings[a_name] \
                            if a_name < len(strings) else ""
                        if a_raw != 0xFFFFFFFF:
                            val = strings[a_raw] \
                                if a_raw < len(strings) else ""
                        elif a_type == 0x03:  # string
                            val = strings[a_data] \
                                if a_data < len(strings) else ""
                        elif a_type == 0x10:  # int
                            val = str(a_data)
                        elif a_type == 0x12:  # boolean
                            val = "true" if a_data else "false"
                        else:
                            val = f"0x{a_data:08x}"
                        attrs[key] = val
                    if attrs.get("name") == EMBEDDING_METADATA_NAME:
                        found = attrs.get("value")
            off += chunk_size
        if found is not None:
            return {"present": True, "value": found,
                    "evidence": "AndroidManifest.xml "
                                "<meta-data> binary-XML parse"}
        return {"present": False,
                "evidence": "AndroidManifest.xml <meta-data> "
                            "binary-XML parse"}
    except (struct.error, IndexError, ValueError) as e:
        return {"present": None,
                "error": f"manifest parse failed: {e}"}


def plugin_inventory(zf, names):
    """Plugin registration + platform-channel evidence,
    from the APK's own artifacts only (DEX class/string
    tables via narlib.dex, the app library's ASCII
    strings, the binary manifest). Channel names are
    string evidence: a string's presence does not prove
    a channel is registered at runtime."""
    dex_names = sorted(
        n for n in names
        if re.fullmatch(r"classes\d*\.dex", n))
    registrant = {"present": False, "dex": None,
                  "evidence": "DEX class table"}
    framework_classes = []
    implementations = []
    channels = []
    dex_errors = []
    classes_total = 0
    for dex_name in dex_names:
        try:
            dex = Dex(read_member_capped(zf, dex_name),
                      dex_name)
            defs = dex.class_defs()
        except (DexError, struct.error, IndexError,
                ValueError) as e:
            dex_errors.append({"dex": dex_name,
                               "error": str(e)})
            continue
        classes_total += len(defs)
        for d in defs:
            cls = d["class"]
            if cls == REGISTRANT_CLASS:
                registrant = {"present": True, "dex": dex_name,
                              "evidence": "DEX class table"}
            elif cls.startswith(PLUGIN_NAMESPACE):
                framework_classes.append(
                    {"class": cls, "dex": dex_name})
            if FLUTTER_PLUGIN_INTERFACE in \
                    (d.get("interfaces") or []):
                implementations.append(
                    {"class": cls, "dex": dex_name})
        channels += _channel_candidates(
            dex.strings(), f"{dex_name} string table")
    app_libs = sorted(n for n in names
                      if n.startswith("lib/")
                      and n.endswith("/libapp.so"))
    if app_libs:
        with zf.open(app_libs[0]) as fh:
            data = fh.read(SCAN_CAP)
        native_strings = [m.group().decode("ascii")
                          for m in _ASCII_RUN_RE.finditer(data)]
        channels += _channel_candidates(
            native_strings,
            f"{app_libs[0]} ASCII string scan")
    impl_record = {
        "classes": implementations[:_CLASS_LIST_CAP],
        "counts": {"total": len(implementations),
                   "processed": len(implementations),
                   "skipped": 0, "failed": 0},
        "evidence": "DEX class table: classes declaring "
                    "the embedding FlutterPlugin interface",
    }
    if not implementations and registrant["present"]:
        impl_record["note"] = (
            "no class declares the FlutterPlugin interface "
            "under its framework name; in minified (R8) "
            "builds the embedding's own types are renamed "
            "too, so implementations then surface only as "
            "framework-namespace classes and through the "
            "registrant")
    seen = set()
    unique_channels = []
    for c in channels:
        key = (c["name"], c["source"])
        if key not in seen:
            seen.add(key)
            unique_channels.append(c)
    unique_channels.sort(key=lambda c: c["name"])
    manifest = None
    if "AndroidManifest.xml" in names:
        manifest = manifest_embedding(
            zf.read("AndroidManifest.xml"))
    return {
        "dex_files": dex_names,
        "dex_errors": dex_errors,
        "dex_class_count": classes_total,
        "generated_plugin_registrant": registrant,
        "framework_plugin_classes": {
            "classes": framework_classes[:_CLASS_LIST_CAP],
            "counts": {"total": len(framework_classes),
                       "processed": len(framework_classes),
                       "skipped": 0, "failed": 0},
            "evidence": "DEX class table: classes under "
                        "the embedding plugin namespace "
                        "io/flutter/plugins/",
        },
        "flutter_plugin_implementations": impl_record,
        "platform_channels": {
            "candidates": unique_channels[:_CHANNEL_LIST_CAP],
            "counts": {"total": len(unique_channels),
                       "processed": len(unique_channels),
                       "skipped": 0, "failed": 0},
            "evidence": "string evidence: channel-shaped "
                        "strings in the named artifacts; "
                        "presence does not prove runtime "
                        "registration",
            "confidence": "candidate",
        },
        "manifest_embedding": manifest,
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
            with zf.open(engine[0]) as fh:
                data = fh.read(SCAN_CAP)
            dart_version = _first_version(data, (DART_VM_RE, STABLE_RE))
            markers |= {m.decode() for m in SNAPSHOT_MARKERS if m in data}
        if app:
            with zf.open(app[0]) as fh:
                data = fh.read(SCAN_CAP)
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
        report["plugin_inventory"] = plugin_inventory(zf, names)
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
    pinv = report.get("plugin_inventory")
    if pinv:
        reg = pinv["generated_plugin_registrant"]
        lines.append(
            f"Generated plugin registrant: "
            f"{'present in ' + str(reg['dex']) if reg['present'] else 'not found'}")
        lines.append(
            f"Plugin implementations (FlutterPlugin interface): "
            f"{pinv['flutter_plugin_implementations']['counts']['total']}; "
            f"framework plugin classes: "
            f"{pinv['framework_plugin_classes']['counts']['total']}")
        lines.append(
            f"Platform-channel string candidates: "
            f"{pinv['platform_channels']['counts']['total']} "
            f"(string evidence only)")
        emb = pinv.get("manifest_embedding") or {}
        if emb.get("present"):
            lines.append(f"Manifest flutterEmbedding: "
                         f"{emb.get('value')}")
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
