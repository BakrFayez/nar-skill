#!/usr/bin/env python3
"""nar-assets.py: asset inventory and classification (brief
section 10).

Inventories the payload files of an APK: every member
under assets/ and res/ in each archive root (the base
archive, merged splits, and bundle module roots), engine
containers (.pak/.pck/.utoc/.ucas/.bundle/.unity3d/.obb)
wherever they sit, and every member of an OBB payload
archive (the target itself, or one contained in / beside
the target — an OBB carries payload only). Each entry
gets its type (magic first, extension second, content
evidence third), a category (texture, audio, video,
model, font, data, config, code, container, other), size
and SHA-256. Code and platform metadata are inventoried
by their own stages and stay out of scope here: DEX
(nar-dex), native libraries (nar-native), the manifest,
resources.arsc and META-INF signing metadata (the app /
triage stages). Container members are listed as members;
their contents are not recursed into (the engine stages
open the containers they parse). Image dimensions
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

Part of NAR (Nirous Android Reversing).
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
from narlib import container as container_mod  # noqa: E402
from narlib import mediainfo as mediainfo_mod  # noqa: E402
from narlib import textures as textures_mod  # noqa: E402
from narlib.hashing import sha256_of  # noqa: E402

EXT_TYPES = {
    ".png": ("png-image", "texture"), ".jpg": ("jpeg-image", "texture"),
    ".jpeg": ("jpeg-image", "texture"), ".webp": ("webp-image", "texture"),
    ".gif": ("gif-image", "texture"), ".bmp": ("bmp-image", "texture"),
    ".svg": ("svg-image", "texture"),
    ".mp3": ("mp3-audio", "audio"), ".ogg": ("ogg-audio", "audio"),
    ".wav": ("wav-audio", "audio"), ".m4a": ("m4a-audio", "audio"),
    ".flac": ("flac-audio", "audio"), ".mp4": ("mp4-video", "video"),
    ".webm": ("webm-video", "video"), ".mkv": ("mkv-video", "video"),
    ".fbx": ("fbx-model", "model"), ".obj": ("obj-model", "model"),
    ".glb": ("glb-model", "model"), ".gltf": ("gltf-model", "model"),
    ".ttf": ("ttf-font", "font"), ".otf": ("otf-font", "font"),
    ".woff": ("woff-font", "font"), ".woff2": ("woff2-font", "font"),
    ".fnt": ("bitmap-font", "font"),
    ".json": ("json", "data"), ".xml": ("xml", "data"),
    ".txt": ("text", "data"), ".csv": ("csv", "data"),
    ".ini": ("ini-config", "config"), ".properties": ("properties", "config"),
    ".prop": ("properties", "config"),
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
    ".bin": ("binary", "data"), ".pack": ("libgdx-pack", "data"),
    ".plist": ("plist", "data"), ".atlas": ("libgdx-atlas", "data"),
    ".skel": ("spine-skeleton", "animation"),
    ".spriteatlas": ("unity-spriteatlas", "data"),
    ".tres": ("godot-resource", "data"),
    ".tscn": ("godot-scene", "data"),
    ".godot": ("godot-project", "config"),
    ".import": ("godot-import", "config"),
    ".uasset": ("unreal-asset", "data"),
    ".umap": ("unreal-map", "data"),
    ".wem": ("wwise-audio", "audio"), ".bnk": ("wwise-bank", "audio"),
    ".bank": ("fmod-bank", "audio"),
    ".astc": ("astc-texture", "texture"),
    ".ktx": ("ktx-texture", "texture"),
    ".ktx2": ("ktx2-texture", "texture"),
    ".pvr": ("pvr-texture", "texture"),
    ".dds": ("dds-texture", "texture"),
    ".pkm": ("pkm-texture", "texture"),
    ".tga": ("tga-image", "texture"), ".psd": ("psd-image", "texture"),
    ".lua": ("lua-script", "code"), ".gd": ("gdscript", "code"),
    ".dart": ("dart-source", "code"), ".wasm": ("wasm", "code"),
    ".obb": ("obb", "container"), ".zip": ("zip", "container"),
    ".gz": ("gzip-archive", "container"),
    ".7z": ("7z-archive", "container"),
    ".ase": ("aseprite", "animation"),
    ".aseprite": ("aseprite", "animation"),
    ".riv": ("rive-animation", "animation"),
    ".scml": ("spriter", "animation"),
    ".jsc": ("javascript-compiled", "code"),
    ".py": ("python", "code"),
    ".pyc": ("python-bytecode", "code"),
    ".ccb": ("cocos-ccb", "data"), ".csb": ("cocos-csb", "data"),
    ".locres": ("unreal-locres", "data"),
    ".ron": ("ron-data", "data"), ".kv": ("kivy-layout", "data"),
    ".rpa": ("renpy-archive", "container"),
    ".love": ("love-package", "container"),
    ".rcc": ("qt-resource", "container"),
    ".car": ("solar2d-car", "container"),
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
    if head.startswith(b"\x13\xab\xa1\x5c"):
        return ("astc-texture", "texture")
    if head.startswith(b"\xabKTX 11\xbb\r\n\x1a\n"):
        return ("ktx-texture", "texture")
    if head.startswith(b"\xabKTX 20\xbb\r\n\x1a\n"):
        return ("ktx2-texture", "texture")
    if head.startswith(b"PVR\x03"):
        return ("pvr-texture", "texture")
    if head.startswith(b"DDS "):
        return ("dds-texture", "texture")
    if head.startswith(b"PKM 10") or head.startswith(b"PKM 20"):
        return ("pkm-texture", "texture")
    if head.startswith(b"\x1f\x8b"):
        return ("gzip-archive", "container")
    if head.startswith(b"wOF2"):
        return ("woff2-font", "font")
    if head.startswith(b"wOFF"):
        return ("woff-font", "font")
    if head.startswith(b"BMF\x03"):
        return ("bitmap-font", "font")
    if head.startswith(b"bplist00"):
        return ("plist", "data")
    if head.startswith(b"\x00\x01\x00\x00") \
            or head.startswith(b"ttcf") \
            or head.startswith(b"true\x00"):
        return ("ttf-font", "font")
    if head.startswith(b"OTTO"):
        return ("otf-font", "font")
    if head[:4] == b"\x03\x00\x08\x00":
        # Android binary XML (RES_XML_TYPE chunk header).
        return ("xml", "data")
    if head.startswith(b"\xc1\x83\x2a\x9e"):
        return ("unreal-asset", "data")
    if head.startswith(
            b"\x0e\x14\x74\x75\x67\x4a\x03\xfc"
            b"\x4a\x15\x90\x9d\xc3\x37\x7f\x1b"):
        return ("unreal-locres", "data")
    if head.startswith(b"\x1bLua"):
        return ("lua-script", "code")
    if head.startswith(b"RIVE") and len(head) > 4 \
            and head[4] < 0x20:
        return ("rive-animation", "animation")
    if len(head) >= 6 and head[4:6] == b"\xe0\xa5":
        return ("aseprite", "animation")
    # SVG is a text format: an XML document whose root is
    # <svg (possibly behind a BOM, whitespace or the XML
    # declaration). Deterministic content evidence, checked
    # after every binary signature above.
    stripped = head[3:] if head.startswith(b"\xef\xbb\xbf") \
        else head
    stripped = stripped.lstrip()
    if stripped.startswith(b"<svg"):
        return ("svg-image", "texture")
    if stripped.startswith(b"<?xml") and b"<svg" in head[:1024]:
        return ("svg-image", "texture")
    return None


#: Bytes of member content read for classification (magic,
#: then content evidence). Bounded and header-only: the
#: full member is still streamed separately for hashing.
_CLASSIFY_WINDOW = 8192


def _content_is_binary(data):
    """Deterministic content evidence: True when the read
    window is binary — a NUL byte, bytes that do not decode
    as UTF-8 (a multi-byte sequence split by the window
    edge is trimmed before judging), or C0 control bytes
    other than the usual text whitespace. An empty window
    carries no binary evidence."""
    if not data:
        return False
    if b"\x00" in data:
        return True
    text = None
    for trimmed in (data, data[:-1], data[:-2], data[:-3]):
        try:
            text = trimmed.decode("utf-8")
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        return True
    return any(ord(ch) < 0x20 and ch not in "\t\n\r\x0b\x0c"
               for ch in text)


#: Categories whose extension rule asserts a text/data
#: nature, plus the source-code types that assert readable
#: source. For these, an extension alone never commits the
#: category when the content is binary with no recognized
#: signature (the signature check runs first): the member
#: is reported unknown/other instead. Formats that
#: genuinely carry no magic but read as text (JSON, XML,
#: shader source, BMFont text, ...) pass the content check
#: and keep their extension classification.
_DISCIPLINE_CATEGORIES = ("data", "config", "animation",
                          "font")
_DISCIPLINE_TYPES = {"javascript", "lua-script", "gdscript",
                     "dart-source", "python", "svg-image"}


def _classify(name, data):
    """(type, category) for one member from its content
    window: magic first, extension second, content evidence
    third. With no signature and no extension rule, content
    that reads as text is ("text", "data") and anything
    else stays ("unknown", "other")."""
    kind_cat = magic_type(data)
    if kind_cat is not None:
        return kind_cat
    ext = os.path.splitext(name)[1].lower()
    rule = EXT_TYPES.get(ext)
    if rule is None:
        if data and not _content_is_binary(data):
            return ("text", "data")
        return ("unknown", "other")
    if rule[1] in _DISCIPLINE_CATEGORIES \
            or rule[0] in _DISCIPLINE_TYPES:
        if _content_is_binary(data):
            return ("unknown", "other")
    return rule


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


_TEXTURE_KIND_EXT = {
    "astc-texture": ".astc", "ktx-texture": ".ktx",
    "ktx2-texture": ".ktx2", "pvr-texture": ".pvr",
    "dds-texture": ".dds", "pkm-texture": ".pkm",
}


def texture_metadata(kind, head):
    """Header-level compressed-texture facts for one
    inventory entry, delegated to narlib.textures (ASTC /
    KTX1 / KTX2 / PVR v3 / DDS / PKM headers: dimensions,
    block geometry, stored mip count). Header-only: pixel
    data is never decoded, and fields a header does not
    store come back null with their basis named."""
    ext = _TEXTURE_KIND_EXT.get(kind)
    if ext is None:
        return {"format": None, "width": None, "height": None,
                "depth": None, "block_width": None,
                "block_height": None, "block_bytes": None,
                "mip_count": None, "mip_count_basis": None,
                "array_elements": None, "faces": None,
                "error": f"no texture header parser for {kind}"}
    return textures_mod.parse_texture_header(head, ext)


# Media kinds whose §4.3 header facts are derivable from a
# bounded prefix (font tables directory, glTF JSON chunk and
# the Wwise/FMOD bank headers all sit at the start of the
# file). Video and OBJ/FBX model facts stay narlib-level:
# a video's moov atom may sit at the end of the file and an
# OBJ census needs a full scan, so a prefix read would
# silently under-report them.
_MEDIA_KIND_FACTS = {
    "ttf-font": (".ttf", "font"), "otf-font": (".otf", "font"),
    "glb-model": (".glb", "model"),
    "gltf-model": (".gltf", "model"),
    "wwise-audio": (".wem", "bank"),
    "wwise-bank": (".bnk", "bank"),
    "fmod-bank": (".bank", "bank"),
}


def media_metadata(kind, head):
    """Header-level media facts (§4.3) for one inventory
    entry, delegated to narlib.mediainfo: font glyph count /
    name table / subsetting signals, glTF model counts,
    Wwise/FMOD bank header facts. Values a bounded prefix
    cannot derive come back null with the basis named."""
    ext, group = _MEDIA_KIND_FACTS[kind]
    if group == "font":
        return mediainfo_mod.font_facts(head)
    if group == "model":
        return mediainfo_mod.model_facts(head, ext)
    return mediainfo_mod.wwise_bank_facts(head, ext)


#: Engine containers are payload wherever they sit in an
#: archive (the pre-existing extension rule).
_CONTAINER_EXTS = (".pak", ".pck", ".utoc", ".ucas",
                   ".bundle", ".unity3d", ".obb")


def _in_scope(name):
    """Payload scope for one archive member: the assets/
    and res/ trees — at the archive root or one level down,
    which covers bundle (AAB) module roots such as
    base/assets/ and feature-module assets/ — plus engine
    containers by extension wherever they sit. Code and
    platform metadata (DEX, lib/, the manifest,
    resources.arsc, META-INF/) are other stages' scope and
    are never inventoried here."""
    if name.lower().endswith(_CONTAINER_EXTS):
        return True
    parts = name.split("/")
    return parts[0] in ("assets", "res") or (
        len(parts) > 1 and parts[1] in ("assets", "res"))


def inventory(target, merge_splits=True):
    if not merge_splits:
        return _inventory_single(target)
    resolved = container_mod.resolve_target(target)
    try:
        if not resolved.is_container and \
                resolved.input_kind not in ("apk", "aab", "obb"):
            return _inventory_single(target)
        return _inventory_merged(target, resolved)
    finally:
        resolved.cleanup()


def _inventory_merged(target, resolved):
    """Merged inventory across the resolved roots (base
    first, then splits): every asset carries `source_split`
    (the archive file name it came from), the report carries
    `assets_by_split` counts and a `duplicates` section from
    the cross-archive delta detection (each duplicate once,
    with all locations)."""
    assets = []
    by_hash = {}
    total_bytes = 0
    # Inventory roots: the resolved archive roots (base
    # first, then splits), then the OBB payload archives
    # the resolution carries (contained in / beside the
    # target). An OBB carries payload only, so every member
    # of an OBB root is in scope; a direct OBB target's own
    # root is an OBB root too.
    roots = [(root, resolved.input_kind == "obb")
             for root in resolved.assets_roots]
    seen_roots = {root for root, _ in roots}
    for obb in resolved.obbs:
        if obb["path"] not in seen_roots:
            roots.append((obb["path"], True))
            seen_roots.add(obb["path"])
    for root, whole_archive in roots:
        archive_name = os.path.basename(root)
        with zipfile.ZipFile(root) as zf:
            for info in zf.infolist():
                name = info.filename
                if name.endswith("/"):
                    continue
                if not whole_archive and not _in_scope(name):
                    continue
                with zf.open(name) as fh:
                    head = fh.read(_CLASSIFY_WINDOW)
                    fh.seek(0)
                    digest = hashlib.sha256()
                    while True:
                        chunk = fh.read(1 << 20)
                        if not chunk:
                            break
                        digest.update(chunk)
                kind_cat = _classify(name, head)
                width = height = None
                if kind_cat[1] == "texture":
                    with zf.open(name) as fh:
                        width, height = image_dimensions(
                            kind_cat[0], fh.read(1 << 16))
                entry = {"path": name, "type": kind_cat[0],
                         "category": kind_cat[1],
                         "size_bytes": info.file_size,
                         "sha256": digest.hexdigest(),
                         "source_archive": archive_name,
                         "source_split": archive_name,
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
                        kind_cat[0], head_b, tail_b,
                        info.file_size)
                if kind_cat[0] in _TEXTURE_KIND_EXT:
                    with zf.open(name) as fh:
                        entry["texture"] = texture_metadata(
                            kind_cat[0], fh.read(512))
                if kind_cat[0] in _MEDIA_KIND_FACTS:
                    with zf.open(name) as fh:
                        entry[
                            _MEDIA_KIND_FACTS[kind_cat[0]][1]
                        ] = media_metadata(
                            kind_cat[0], fh.read(1 << 22))
                assets.append(entry)
                total_bytes += info.file_size
                by_hash.setdefault(
                    entry["sha256"], []).append(
                        {"archive": archive_name,
                         "member": name})
    duplicates = []
    for h, locations in sorted(by_hash.items()):
        if len(locations) <= 1:
            continue
        duplicates.append({
            "sha256": h,
            "paths": [loc["member"] for loc in locations],
            "count": len(locations),
            "locations": locations})
    by_category = {}
    assets_by_split = {}
    for root, _whole in roots:
        assets_by_split[os.path.basename(root)] = 0
    for a in assets:
        by_category[a["category"]] = \
            by_category.get(a["category"], 0) + 1
        assets_by_split[a["source_split"]] = \
            assets_by_split.get(a["source_split"], 0) + 1
    report = {"tool": "nar-assets", "version": "3.0.1",
              "target": os.path.abspath(target),
              "target_sha256": sha256_of(target),
              "assets": assets, "total_assets": len(assets),
              "total_bytes": total_bytes,
              "duplicates": duplicates,
              "by_category": by_category,
              "assets_by_split": assets_by_split,
              "largest": sorted(
                  assets, key=lambda a: -a["size_bytes"])[:10]}
    if resolved.is_container:
        report["container"] = resolved.container_block()
    return report


def _inventory_single(target):
    assets = []
    by_hash = {}
    total_bytes = 0
    with zipfile.ZipFile(target) as zf:
        for info in zf.infolist():
            name = info.filename
            if name.endswith("/"):
                continue
            if not _in_scope(name):
                continue
            with zf.open(name) as fh:
                head = fh.read(_CLASSIFY_WINDOW)
                fh.seek(0)
                digest = hashlib.sha256()
                while True:
                    chunk = fh.read(1 << 20)
                    if not chunk:
                        break
                    digest.update(chunk)
            kind_cat = _classify(name, head)
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
            if kind_cat[0] in _TEXTURE_KIND_EXT:
                with zf.open(name) as fh:
                    entry["texture"] = texture_metadata(
                        kind_cat[0], fh.read(512))
            if kind_cat[0] in _MEDIA_KIND_FACTS:
                with zf.open(name) as fh:
                    entry[
                        _MEDIA_KIND_FACTS[kind_cat[0]][1]
                    ] = media_metadata(
                        kind_cat[0], fh.read(1 << 22))
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
    return {"tool": "nar-assets", "version": "3.0.1",
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
    if report.get("assets_by_split"):
        print(f"Assets by archive: {report['assets_by_split']}")
    cont = report.get("container")
    if cont:
        print(f"Container: {cont['input_kind']} — base "
              f"{cont['base']}; splits merged: "
              f"{[s['name'] for s in cont['splits_merged']]}; "
              f"skipped: {cont['split_skipped']}")
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
    p.add_argument("--no-merge-splits", action="store_true",
                   help="analyse only the base APK of a "
                        "container (pre-3.0 behaviour, "
                        "byte-identical output)")
    args = p.parse_args(argv)
    if os.path.isdir(args.target):
        # Directory targets are an input error (exit 2) on
        # every platform. This cannot be left to the open()
        # below: POSIX raises IsADirectoryError for a
        # directory open (caught under the try), but Windows
        # raises PermissionError instead, which would escape
        # as a traceback and the wrong exit code.
        print(f"nar-assets: is a directory: {args.target}",
              file=sys.stderr)
        return 2
    try:
        report = inventory(args.target,
                           merge_splits=not args.no_merge_splits)
    except (FileNotFoundError, IsADirectoryError,
            zipfile.BadZipFile) as e:
        print(f"nar-assets: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        human(report, args.top)
    return 0


if __name__ == "__main__":
    sys.exit(main())
