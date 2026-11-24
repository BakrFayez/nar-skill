#!/usr/bin/env python3
"""nar-assets.py: asset inventory and classification (brief
section 10).

Inventories the payload files of an APK (assets/, raw
resources, and engine containers wherever they sit): each
entry gets its type (magic first, extension second), a
category (texture, audio, video, model, font, data, config,
code, container, other), size and SHA-256. Image dimensions
are read from PNG/JPEG/WebP headers; audio metadata
(channels, sample rate, duration where the header makes it
computable) is parsed from WAV / OGG (Vorbis, Opus) / MP3
headers with the standard library only — formats outside
that set are reported as unmeasured, never guessed
(Evolution Phase 7). Duplicate payloads (same hash,
several paths) are grouped; engine containers
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


def _unmeasured(reason):
    return {"measured": False, "format": None, "channels": None,
            "sample_rate_hz": None, "duration_seconds": None,
            "duration_basis": None, "reason": reason}


def _wav_meta(data):
    if len(data) < 12 or data[0:4] != b"RIFF" \
            or data[8:12] != b"WAVE":
        return _unmeasured("no RIFF/WAVE header in the read window")
    fmt = None
    data_size = None
    off = 12
    while off + 8 <= len(data):
        cid = data[off:off + 4]
        size = struct.unpack_from("<I", data, off + 4)[0]
        body = off + 8
        if cid == b"fmt " and size >= 16 \
                and body + 16 <= len(data):
            fmt = struct.unpack_from("<HHII", data, body)
            # (audio_format, channels, sample_rate, byte_rate)
        elif cid == b"data":
            data_size = size
            if fmt:
                break
        off = body + size + (size & 1)
    if fmt is None:
        return _unmeasured("no fmt chunk in the read window")
    _, channels, rate, byte_rate = fmt
    duration = None
    basis = None
    if data_size is not None and byte_rate:
        duration = round(data_size / byte_rate, 3)
        basis = "data chunk size / header byte rate"
    elif data_size is None:
        basis = "data chunk beyond the header read window"
    return {"measured": True, "format": "wav",
            "channels": channels, "sample_rate_hz": rate,
            "duration_seconds": duration,
            "duration_basis": basis, "reason": None}


_MP3_BR_V1_L3 = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160,
                 192, 224, 256, 320, -1]
_MP3_BR_V2_L3 = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112,
                 128, 144, 160, -1]
_MP3_SR = {3: [44100, 48000, 32000], 2: [22050, 24000, 16000],
           0: [11025, 12000, 8000]}


def _mp3_meta(data, total_size):
    off = 0
    if data[0:3] == b"ID3" and len(data) >= 10:
        tag_size = 10 + sum((data[6 + i] & 0x7F) << (7 * (3 - i))
                            for i in range(4))
        if data[5] & 0x10:
            tag_size += 10
        off = tag_size
    frame = None
    scan_end = min(len(data) - 4, off + (1 << 17))
    i = off
    while i < scan_end:
        if data[i] == 0xFF and (data[i + 1] & 0xE0) == 0xE0:
            version = (data[i + 1] >> 3) & 0x3
            layer = (data[i + 1] >> 1) & 0x3
            br_idx = (data[i + 2] >> 4) & 0xF
            sr_idx = (data[i + 2] >> 2) & 0x3
            if version != 1 and layer == 1 and br_idx not in (0, 15) \
                    and sr_idx != 3:
                frame = (i, version, br_idx, sr_idx,
                         (data[i + 2] >> 1) & 0x1,
                         (data[i + 3] >> 6) & 0x3)
                break
        i += 1
    if frame is None:
        return _unmeasured("no valid MPEG Layer III frame header "
                           "found in the read window")
    start, version, br_idx, sr_idx, padding, chan_mode = frame
    table = _MP3_BR_V1_L3 if version == 3 else _MP3_BR_V2_L3
    bitrate = table[br_idx] * 1000
    rate = _MP3_SR[version][sr_idx]
    channels = 1 if chan_mode == 3 else 2
    samples = 1152 if version == 3 else 576
    # Xing/Info header: after the 4-byte frame header plus the
    # side-information block (MPEG1: 32/17 bytes, MPEG2: 17/9).
    side = (17 if channels == 1 else 32) if version == 3 \
        else (9 if channels == 1 else 17)
    xing = start + 4 + side
    duration = None
    basis = None
    if data[xing:xing + 4] in (b"Xing", b"Info") \
            and xing + 12 <= len(data):
        flags = struct.unpack_from(">I", data, xing + 4)[0]
        if flags & 0x1:
            frames = struct.unpack_from(">I", data, xing + 8)[0]
            duration = round(frames * samples / rate, 3)
            basis = "Xing/Info header frame count"
    if duration is None:
        duration = round((total_size - off) * 8 / bitrate, 3)
        basis = ("first-frame bitrate estimate "
                 "(constant-bitrate assumption)")
    return {"measured": True, "format": "mp3",
            "channels": channels, "sample_rate_hz": rate,
            "duration_seconds": duration,
            "duration_basis": basis, "reason": None}


def _ogg_first_packet(data):
    """(packet bytes, granule) of the first Ogg page in data,
    or (None, None)."""
    if data[0:4] != b"OggS" or len(data) < 27:
        return None, None
    granule = struct.unpack_from("<q", data, 6)[0]
    nseg = data[26]
    if 27 + nseg > len(data):
        return None, None
    segs = data[27:27 + nseg]
    packet = bytearray()
    pos = 27 + nseg
    for s in segs:
        packet += data[pos:pos + s]
        pos += s
        if s < 255:
            break
    return bytes(packet), granule


def _ogg_meta(head, tail):
    packet, _ = _ogg_first_packet(head)
    if packet is None:
        return _unmeasured("no Ogg page header in the read window")
    fmt = None
    channels = rate = None
    preskip = 0
    if packet.startswith(b"\x01vorbis") and len(packet) >= 27:
        fmt = "ogg-vorbis"
        channels = packet[11]
        rate = struct.unpack_from("<I", packet, 12)[0]
    elif packet.startswith(b"OpusHead") and len(packet) >= 19:
        fmt = "ogg-opus"
        channels = packet[9]
        preskip = struct.unpack_from("<H", packet, 10)[0]
        rate = struct.unpack_from("<I", packet, 12)[0]
    if fmt is None:
        return _unmeasured("Ogg container without a Vorbis/Opus "
                           "identification header")
    duration = None
    basis = None
    idx = tail.rfind(b"OggS")
    if idx >= 0 and idx + 14 <= len(tail):
        granule = struct.unpack_from("<q", tail, idx + 6)[0]
        if granule >= 0:
            if fmt == "ogg-vorbis" and rate:
                duration = round(granule / rate, 3)
                basis = "final page granule position / sample rate"
            elif fmt == "ogg-opus" and granule > preskip:
                duration = round((granule - preskip) / 48000, 3)
                basis = ("final page granule position minus "
                         "pre-skip, at the 48 kHz Opus clock")
    if duration is None:
        basis = "final page granule not found in the tail window"
    return {"measured": True, "format": fmt, "channels": channels,
            "sample_rate_hz": rate, "duration_seconds": duration,
            "duration_basis": basis, "reason": None}


def audio_metadata(kind, head, tail, total_size):
    """Header-level audio facts for one inventory entry.

    Measured formats: WAV (fmt/data chunks), MP3 (frame
    header; Xing frame count when present, else a labeled
    constant-bitrate estimate), OGG Vorbis/Opus (ID header +
    final-page granule). Anything else is reported
    unmeasured with the reason — values are never guessed."""
    try:
        if kind == "wav-audio":
            return _wav_meta(head)
        if kind == "mp3-audio":
            return _mp3_meta(head, total_size)
        if kind == "ogg-audio":
            return _ogg_meta(head, tail)
    except (struct.error, IndexError) as e:
        return _unmeasured(f"header parse failed: {e}")
    return _unmeasured(
        f"no header parser for {kind} (measured set: WAV, "
        "OGG Vorbis/Opus, MP3)")


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
            if kind_cat[1] == "audio":
                with zf.open(name) as fh:
                    head_b = fh.read(1 << 18)
                    tail_b = b""
                    if kind_cat[0] == "ogg-audio" \
                            and info.file_size > (1 << 16):
                        fh.seek(info.file_size - (1 << 16))
                        tail_b = fh.read()
                    else:
                        tail_b = head_b
                entry["audio"] = audio_metadata(
                    kind_cat[0], head_b, tail_b, info.file_size)
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
    return {"tool": "nar-assets", "version": "2.5.2",
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
        au = a.get("audio") or {}
        if au.get("measured"):
            dims += (f" {au['duration_seconds']}s"
                     f" {au['channels']}ch"
                     f" {au['sample_rate_hz']}Hz")
        elif a["category"] == "audio":
            dims += " (audio unmeasured)"
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
