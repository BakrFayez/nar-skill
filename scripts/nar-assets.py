#!/usr/bin/env python3
"""nar-assets.py: asset inventory and classification (brief
section 10).

Inventories the payload files of an APK (assets/, raw
resources, and engine containers wherever they sit): each
entry gets its type (magic first, extension second), a
category (texture, audio, video, model, font, data, config,
code, container, other), size and SHA-256. Image dimensions
are read from PNG/JPEG/WebP headers; duplicate payloads
(same hash, several paths) are grouped; engine containers
(UnityFS bundles, Unreal paks, Godot packs, IoStore) are
cross-referenced so the inventory ties back to the engine
verdicts. OBB files can be inventoried directly too.

Usage:
    python3 nar-assets.py app.apk [--json] [--top N]
    python3 nar-assets.py expansion.obb [--json]

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import hashlib
import json
import os
import struct
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib.hashing import sha256_of  # noqa: E402

EXT_TYPES = {
    ".png": ("png-image", "texture"), ".jpg": ("jpeg-image", "texture"),
    ".jpeg": ("jpeg-image", "texture"), ".webp": ("webp-image", "texture"),
    ".gif": ("gif-image", "texture"), ".bmp": ("bmp-image", "texture"),
    ".mp3": ("mp3-audio", "audio"), ".ogg": ("ogg-audio", "audio"),
    ".wav": ("wav-audio", "audio"), ".m4a": ("m4a-audio", "audio"),
    ".flac": ("flac-audio", "audio"), ".mp4": ("mp4-video", "video"),
    ".webm": ("webm-video", "video"), ".mkv": ("mkv-video", "video"),
    ".fbx": ("fbx-model", "model"), ".obj": ("obj-model", "model"),
    ".glb": ("glb-model", "model"), ".gltf": ("gltf-model", "model"),
    ".ttf": ("ttf-font", "font"), ".otf": ("otf-font", "font"),
    ".json": ("json", "data"), ".xml": ("xml", "data"),
    ".txt": ("text", "data"), ".csv": ("csv", "data"),
    ".ini": ("ini-config", "config"), ".properties": ("properties", "config"),
    ".yaml": ("yaml", "config"), ".yml": ("yaml", "config"),
    ".dex": ("dex", "code"), ".so": ("elf", "code"),
    ".pak": ("unreal-pak", "container"), ".pck": ("godot-pck", "container"),
    ".utoc": ("unreal-iostore", "container"),
    ".ucas": ("unreal-iostore", "container"),
    ".bundle": ("bundle", "container"), ".unity3d": ("unityfs", "container"),
    ".hbc": ("hermes-bytecode", "code"), ".js": ("javascript", "code"),
    ".html": ("html", "data"), ".css": ("css", "data"),
    ".proto": ("protobuf-schema", "data"),
    ".bytes": ("binary", "data"), ".dat": ("binary", "data"),
    ".bin": ("binary", "data"),
}


def magic_type(head):
    if head.startswith(b"\x89PNG"):
        return ("png-image", "texture")
    if head.startswith(b"\xff\xd8\xff"):
        return ("jpeg-image", "texture")
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return ("webp-image", "texture")
    if head.startswith(b"UnityFS"):
        return ("unityfs", "container")
    if head.startswith(b"GDPC"):
        return ("godot-pck", "container")
    if head.startswith(b"OggS"):
        return ("ogg-audio", "audio")
    if head.startswith(b"PK\x03\x04"):
        return ("zip", "container")
    if head.startswith(b"\x7fELF"):
        return ("elf", "code")
    if head.startswith(b"dex\n"):
        return ("dex", "code")
    return None


def image_dimensions(kind, data):
    try:
        if kind == "png-image" and len(data) >= 24:
            w, h = struct.unpack_from(">II", data, 16)
            return w, h
        if kind == "webp-image" and len(data) >= 30:
            if data[12:16] == b"VP8X":
                w = int.from_bytes(data[24:27], "little") + 1
                h = int.from_bytes(data[27:30], "little") + 1
                return w, h
        if kind == "jpeg-image":
            off = 2
            while off + 9 < len(data):
                if data[off] != 0xFF:
                    off += 1
                    continue
                marker = data[off + 1]
                if marker in (0xC0, 0xC1, 0xC2):
                    h, w = struct.unpack_from(">HH", data, off + 5)
                    return w, h
                length = struct.unpack_from(">H", data, off + 2)[0]
                off += 2 + length
    except (struct.error, IndexError):
        pass
    return None, None


def inventory(target):
    assets = []
    by_hash = {}
    total_bytes = 0
    with zipfile.ZipFile(target) as zf:
        for info in zf.infolist():
            name = info.filename
            if name.endswith("/"):
                continue
            in_scope = (name.startswith("assets/")
                        or name.startswith("res/raw")
                        or name.startswith("base/assets/")
                        or name.lower().endswith(
                            (".pak", ".pck", ".utoc", ".ucas",
                             ".bundle", ".unity3d", ".obb")))
            if not in_scope:
                continue
            with zf.open(name) as fh:
                head = fh.read(64)
                fh.seek(0)
                digest = hashlib.sha256()
                while True:
                    chunk = fh.read(1 << 20)
                    if not chunk:
                        break
                    digest.update(chunk)
            ext = os.path.splitext(name)[1].lower()
            kind_cat = magic_type(head) or EXT_TYPES.get(
                ext, ("unknown", "other"))
            if kind_cat[0] == "unknown" and not ext and (
                    "/bin/Data/" in name):
                # Extensionless files inside the Unity Data
                # layout are Unity serialized files.
                kind_cat = ("unity-serialized", "data")
            width = height = None
            if kind_cat[1] == "texture":
                with zf.open(name) as fh:
                    width, height = image_dimensions(
                        kind_cat[0], fh.read(1 << 16))
            entry = {"path": name, "type": kind_cat[0],
                     "category": kind_cat[1],
                     "size_bytes": info.file_size,
                     "sha256": digest.hexdigest(),
                     "source_archive": os.path.basename(target),
                     "width": width, "height": height}
            assets.append(entry)
            total_bytes += info.file_size
            by_hash.setdefault(entry["sha256"], []).append(name)
    duplicates = [{"sha256": h, "paths": paths,
                   "count": len(paths)}
                  for h, paths in sorted(by_hash.items())
                  if len(paths) > 1]
    by_category = {}
    for a in assets:
        by_category[a["category"]] = \
            by_category.get(a["category"], 0) + 1
    return {"tool": "nar-assets", "version": "2.0.0",
            "target": os.path.abspath(target),
            "target_sha256": sha256_of(target),
            "assets": assets, "total_assets": len(assets),
            "total_bytes": total_bytes, "duplicates": duplicates,
            "by_category": by_category,
            "largest": sorted(assets, key=lambda a: -a["size_bytes"]
                              )[:10]}


def human(report, top=10):
    print(f"NAR asset inventory: "
          f"{os.path.basename(report['target'])}")
    print("=" * 60)
    print(f"Assets: {report['total_assets']} "
          f"({report['total_bytes']:,} bytes) — "
          f"{report['by_category']}")
    print(f"Duplicate groups: {len(report['duplicates'])}")
    print(f"Largest {top}:")
    for a in report["largest"][:top]:
        dims = (f" {a['width']}x{a['height']}"
                if a.get("width") else "")
        print(f"  {a['size_bytes']:>12,}  [{a['category']}/"
              f"{a['type']}]{dims}  {a['path']}")


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Asset inventory: types, categories, "
                    "dimensions, duplicates, containers.")
    p.add_argument("target", help="path to an .apk or .obb file")
    p.add_argument("--json", action="store_true")
    p.add_argument("--top", type=int, default=10)
    args = p.parse_args(argv)
    try:
        report = inventory(args.target)
    except (FileNotFoundError, zipfile.BadZipFile) as e:
        print(f"nar-assets: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        human(report, args.top)
    return 0


if __name__ == "__main__":
    sys.exit(main())
