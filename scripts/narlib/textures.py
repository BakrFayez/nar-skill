"""Compressed texture container header decoding.

Header-only facts for the compressed texture containers
common in Android game payloads: ASTC standalone files,
Khronos KTX1 / KTX2, Imagination PVR v3, Microsoft DDS and
ETC1/ETC2 PKM. Only the fixed-size headers are decoded
(dimensions, block geometry, mip counts as stored); pixel
data is never decoded and no value is guessed — a field a
header does not store is reported as null with its basis
named, and malformed input degrades to a facts dict with a
named ``error`` instead of raising.

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import struct

_ASTC_MAGIC = b"\x13\xab\xa1\x5c"
_KTX1_ID = b"\xabKTX 11\xbb\r\n\x1a\n"
_KTX2_ID = b"\xabKTX 20\xbb\r\n\x1a\n"
_PVR_VERSION = 0x03525650
_DDS_MAGIC = b"DDS "

# ASTC block sizes in GL enum order 0x93B0..0x93BD (also the
# PVR v3 enum order from 24 and the KTX2 vkFormat order).
_ASTC_BLOCKS = [(4, 4), (5, 4), (5, 5), (6, 5), (6, 6),
                (8, 5), (8, 6), (8, 8), (10, 5), (10, 6),
                (10, 8), (10, 10), (12, 10), (12, 12)]

# GL internal format -> (name, block_width, block_height,
# block_bytes). PVRTC has no fixed block grid: geometry null.
_KTX1_FORMATS = {
    0x8D64: ("ETC1 RGB", 4, 4, 8),
    0x9274: ("ETC2 RGB", 4, 4, 8),
    0x9278: ("ETC2 RGBA", 4, 4, 16),
    0x9276: ("ETC2 RGB A1", 4, 4, 8),
    0x9270: ("EAC R11", 4, 4, 8),
    0x9272: ("EAC RG11", 4, 4, 16),
    0x83F1: ("BC1 (DXT1)", 4, 4, 8),
    0x83F2: ("BC2 (DXT3)", 4, 4, 16),
    0x83F3: ("BC3 (DXT5)", 4, 4, 16),
    0x8DBB: ("BC4", 4, 4, 8),
    0x8DBD: ("BC5", 4, 4, 16),
    0x8C00: ("PVRTC 2bpp RGB", None, None, None),
    0x8C01: ("PVRTC 2bpp RGBA", None, None, None),
    0x8C02: ("PVRTC 4bpp RGB", None, None, None),
    0x8C03: ("PVRTC 4bpp RGBA", None, None, None),
}
for _i, (_bw, _bh) in enumerate(_ASTC_BLOCKS):
    _KTX1_FORMATS[0x93B0 + _i] = (f"ASTC {_bw}x{_bh}",
                                  _bw, _bh, 16)

# Vulkan vkFormat -> (name, block_width, block_height,
# block_bytes) for the compressed formats.
_KTX2_FORMATS = {
    131: ("BC1 RGB (UNORM)", 4, 4, 8),
    132: ("BC1 RGB (SRGB)", 4, 4, 8),
    133: ("BC1 RGBA (UNORM)", 4, 4, 8),
    134: ("BC1 RGBA (SRGB)", 4, 4, 8),
    135: ("BC2 (UNORM)", 4, 4, 16),
    136: ("BC2 (SRGB)", 4, 4, 16),
    137: ("BC3 (UNORM)", 4, 4, 16),
    138: ("BC3 (SRGB)", 4, 4, 16),
    139: ("BC4 (UNORM)", 4, 4, 8),
    140: ("BC4 (SNORM)", 4, 4, 8),
    141: ("BC5 (UNORM)", 4, 4, 16),
    142: ("BC5 (SNORM)", 4, 4, 16),
    143: ("BC6H (UF16)", 4, 4, 16),
    144: ("BC6H (SF16)", 4, 4, 16),
    145: ("BC7 (UNORM)", 4, 4, 16),
    146: ("BC7 (SRGB)", 4, 4, 16),
    147: ("ETC2 RGB (UNORM)", 4, 4, 8),
    148: ("ETC2 RGB (SRGB)", 4, 4, 8),
    149: ("ETC2 RGB A1 (UNORM)", 4, 4, 8),
    150: ("ETC2 RGB A1 (SRGB)", 4, 4, 8),
    151: ("ETC2 RGBA (UNORM)", 4, 4, 16),
    152: ("ETC2 RGBA (SRGB)", 4, 4, 16),
    153: ("EAC R11 (UNORM)", 4, 4, 8),
    154: ("EAC R11 (SNORM)", 4, 4, 8),
    155: ("EAC RG11 (UNORM)", 4, 4, 16),
    156: ("EAC RG11 (SNORM)", 4, 4, 16),
    37: ("R8G8B8A8 (UNORM)", 1, 1, 4),
    44: ("B8G8R8A8 (UNORM)", 1, 1, 4),
}
for _i, (_bw, _bh) in enumerate(_ASTC_BLOCKS):
    _KTX2_FORMATS[157 + 2 * _i] = (f"ASTC {_bw}x{_bh} (UNORM)",
                                   _bw, _bh, 16)
    _KTX2_FORMATS[158 + 2 * _i] = (f"ASTC {_bw}x{_bh} (SRGB)",
                                   _bw, _bh, 16)
    _KTX2_FORMATS[185 + _i] = (f"ASTC {_bw}x{_bh} (SFLOAT)",
                               _bw, _bh, 16)

_SUPERCOMPRESSION = {0: "none", 1: "BasisLZ", 2: "ZLIB",
                     3: "ZSTD"}

# PVR v3 pixelFormat enum -> (name, block_w, block_h,
# block_bytes); ASTC entries (24+) are appended below.
_PVR_FORMATS = {
    0: ("PVRTC 2bpp RGB", None, None, None),
    1: ("PVRTC 2bpp RGBA", None, None, None),
    2: ("PVRTC 4bpp RGB", None, None, None),
    3: ("PVRTC 4bpp RGBA", None, None, None),
    4: ("PVRTC-II 2bpp", None, None, None),
    5: ("PVRTC-II 4bpp", None, None, None),
    6: ("ETC1", 4, 4, 8),
    7: ("BC1 (DXT1)", 4, 4, 8),
    8: ("BC2 (DXT3)", 4, 4, 16),
    9: ("BC3 (DXT5)", 4, 4, 16),
    10: ("BC4", 4, 4, 8),
    11: ("BC5", 4, 4, 16),
    12: ("BC6H", 4, 4, 16),
    13: ("BC7", 4, 4, 16),
    19: ("ETC2 RGB", 4, 4, 8),
    20: ("ETC2 RGBA", 4, 4, 16),
    21: ("ETC2 RGB A1", 4, 4, 8),
    22: ("EAC R11", 4, 4, 8),
    23: ("EAC RG11", 4, 4, 16),
}
for _i, (_bw, _bh) in enumerate(_ASTC_BLOCKS):
    _PVR_FORMATS[24 + _i] = (f"ASTC {_bw}x{_bh}", _bw, _bh, 16)

_DDS_FOURCC = {
    b"DXT1": ("BC1 (DXT1)", 4, 4, 8),
    b"DXT3": ("BC2 (DXT3)", 4, 4, 16),
    b"DXT5": ("BC3 (DXT5)", 4, 4, 16),
    b"ATI1": ("BC4 (ATI1)", 4, 4, 8),
    b"BC4U": ("BC4", 4, 4, 8),
    b"ATI2": ("BC5 (ATI2)", 4, 4, 16),
    b"BC5U": ("BC5", 4, 4, 16),
}

# DXGI format -> (name, block_bytes); all BC formats are
# 4x4 blocks.
_DXGI_FORMATS = {}
for _base, _name, _bb in ((70, "BC1", 8), (73, "BC2", 16),
                          (76, "BC3", 16), (79, "BC4", 8),
                          (82, "BC5", 16), (94, "BC6H", 16),
                          (97, "BC7", 16)):
    for _off, _suffix in ((0, "TYPELESS"), (1, "UNORM"),
                          (2, "SRGB/SNORM/UF16")):
        _DXGI_FORMATS[_base + _off] = (
            f"{_name} (DXGI {_base + _off})", _bb)
_DXGI_FORMATS[95] = ("BC6H (UF16)", 16)
_DXGI_FORMATS[96] = ("BC6H (SF16)", 16)
_DXGI_FORMATS[98] = ("BC7 (UNORM)", 16)
_DXGI_FORMATS[99] = ("BC7 (SRGB)", 16)
_DXGI_FORMATS[80] = ("BC4 (UNORM)", 8)
_DXGI_FORMATS[83] = ("BC5 (UNORM)", 16)
_DXGI_FORMATS[71] = ("BC1 (UNORM)", 8)
_DXGI_FORMATS[74] = ("BC2 (UNORM)", 16)
_DXGI_FORMATS[77] = ("BC3 (UNORM)", 16)


def _base(container):
    return {"format": None, "container": container,
            "width": None, "height": None, "depth": None,
            "block_width": None, "block_height": None,
            "block_bytes": None, "mip_count": None,
            "mip_count_basis": None, "array_elements": None,
            "faces": None, "error": None}


def _u24le(data, off):
    return data[off] | (data[off + 1] << 8) | (data[off + 2] << 16)


def _parse_astc(data):
    r = _base("astc")
    if len(data) < 16:
        r["error"] = (f"truncated ASTC header: {len(data)} "
                      "bytes, 16 needed")
        return r
    if data[0:4] != _ASTC_MAGIC:
        r["error"] = "bad ASTC magic"
        return r
    bw, bh, bz = data[4], data[5], data[6]
    r["width"] = _u24le(data, 7)
    r["height"] = _u24le(data, 10)
    r["depth"] = _u24le(data, 13)
    r["block_width"], r["block_height"] = bw, bh
    r["block_bytes"] = 16
    r["format"] = (f"ASTC {bw}x{bh}" if bz == 1
                   else f"ASTC {bw}x{bh}x{bz}")
    r["mip_count"] = None
    r["mip_count_basis"] = "not stored in header"
    return r


def _parse_ktx1(data):
    r = _base("ktx1")
    if len(data) < 64:
        r["error"] = (f"truncated KTX1 header: {len(data)} "
                      "bytes, 64 needed")
        return r
    if data[0:12] != _KTX1_ID:
        r["error"] = "bad KTX1 identifier"
        return r
    if data[12:16] == b"\x01\x02\x03\x04":
        endian = "<"
    elif data[12:16] == b"\x04\x03\x02\x01":
        endian = ">"
    else:
        r["error"] = "unrecognized KTX1 endianness marker"
        return r
    (gl_type, gl_type_size, gl_format, gl_internal,
     _gl_base, width, height, depth, num_array, num_faces,
     num_mips) = struct.unpack_from(endian + "11I", data, 16)
    r["gl_type"] = gl_type
    r["gl_type_size"] = gl_type_size
    r["gl_format"] = gl_format
    r["gl_internal_format"] = gl_internal
    r["width"], r["height"], r["depth"] = width, height, depth
    r["array_elements"] = num_array
    r["faces"] = num_faces
    r["mip_count"] = num_mips
    r["mip_count_basis"] = "header numberOfMipmapLevels"
    hit = _KTX1_FORMATS.get(gl_internal)
    if hit:
        r["format"], r["block_width"], r["block_height"], \
            r["block_bytes"] = hit
    else:
        r["format"] = f"gl-internal-0x{gl_internal:04x}"
    return r


def _parse_ktx2(data):
    r = _base("ktx2")
    if len(data) < 80:
        r["error"] = (f"truncated KTX2 header: {len(data)} "
                      "bytes, 80 needed")
        return r
    if data[0:12] != _KTX2_ID:
        r["error"] = "bad KTX2 identifier"
        return r
    (vk_format, type_size, width, height, depth, layer_count,
     face_count, level_count, supercomp) = \
        struct.unpack_from("<9I", data, 12)
    r["vk_format"] = vk_format
    r["type_size"] = type_size
    r["width"], r["height"], r["depth"] = width, height, depth
    r["array_elements"] = layer_count
    r["faces"] = face_count
    r["mip_count"] = level_count
    r["mip_count_basis"] = "header levelCount"
    r["supercompression_scheme"] = supercomp
    r["supercompression"] = _SUPERCOMPRESSION.get(
        supercomp, f"unknown-{supercomp}")
    hit = _KTX2_FORMATS.get(vk_format)
    if hit:
        r["format"], r["block_width"], r["block_height"], \
            r["block_bytes"] = hit
    else:
        r["format"] = f"vk-format-{vk_format}"
    return r


def _parse_pvr(data):
    r = _base("pvr")
    if len(data) < 52:
        r["error"] = (f"truncated PVR header: {len(data)} "
                      "bytes, 52 needed")
        return r
    version = struct.unpack_from("<I", data, 0)[0]
    if version != _PVR_VERSION:
        r["error"] = (f"bad PVR version field "
                      f"{version:#010x} (not PVR v3)")
        return r
    flags, pixel_format = struct.unpack_from("<IQ", data, 4)
    (colour_space, channel_type, height, width, depth,
     num_surfaces, num_faces, mip_count, meta_size) = \
        struct.unpack_from("<9I", data, 16)
    r["flags"] = flags
    r["pixel_format_id"] = pixel_format
    r["colour_space"] = colour_space
    r["channel_type"] = channel_type
    r["width"], r["height"], r["depth"] = width, height, depth
    r["array_elements"] = num_surfaces
    r["faces"] = num_faces
    r["mip_count"] = mip_count
    r["mip_count_basis"] = "header mipMapCount"
    r["metadata_size"] = meta_size
    pf_bytes = struct.pack("<Q", pixel_format)
    if pixel_format in _PVR_FORMATS:
        r["format"], r["block_width"], r["block_height"], \
            r["block_bytes"] = _PVR_FORMATS[pixel_format]
    elif all(32 <= b < 127 for b in pf_bytes[0:4]):
        fourcc = pf_bytes[0:4].decode("ascii")
        r["format"] = f"fourcc-{fourcc}"
        r["pixel_format_fourcc"] = fourcc
        r["channel_bits"] = list(pf_bytes[4:8])
    else:
        r["format"] = f"pvr-pixel-format-{pixel_format}"
    return r


def _parse_dds(data):
    r = _base("dds")
    if len(data) < 128:
        r["error"] = (f"truncated DDS header: {len(data)} "
                      "bytes, 128 needed")
        return r
    if data[0:4] != _DDS_MAGIC:
        r["error"] = "bad DDS magic"
        return r
    header_size = struct.unpack_from("<I", data, 4)[0]
    if header_size != 124:
        r["error"] = (f"bad DDS header size {header_size} "
                      "(expected 124)")
        return r
    height, width = struct.unpack_from("<II", data, 12)
    depth = struct.unpack_from("<I", data, 24)[0]
    mip_count = struct.unpack_from("<I", data, 28)[0]
    pf_flags = struct.unpack_from("<I", data, 80)[0]
    fourcc = data[84:88]
    caps2 = struct.unpack_from("<I", data, 112)[0]
    r["width"], r["height"], r["depth"] = width, height, depth
    r["mip_count"] = mip_count
    r["mip_count_basis"] = "header mipMapCount"
    if caps2 & 0x200:
        face_bits = (caps2 >> 10) & 0x3F
        r["faces"] = bin(face_bits).count("1") or None
    if fourcc == b"DX10":
        if len(data) < 148:
            r["error"] = ("truncated DDS DX10 header: "
                          f"{len(data)} bytes, 148 needed")
            return r
        (dxgi, _dim, misc_flag, array_size, _misc2) = \
            struct.unpack_from("<5I", data, 128)
        r["dxgi_format"] = dxgi
        r["array_elements"] = array_size
        if misc_flag & 0x4:
            r["faces"] = 6
        hit = _DXGI_FORMATS.get(dxgi)
        if hit:
            r["format"] = hit[0]
            r["block_width"], r["block_height"] = 4, 4
            r["block_bytes"] = hit[1]
        else:
            r["format"] = f"dxgi-format-{dxgi}"
        r["fourcc"] = "DX10"
    elif pf_flags & 0x4 and fourcc.strip(b"\x00"):
        r["fourcc"] = fourcc.decode("ascii", "replace")
        hit = _DDS_FOURCC.get(fourcc)
        if hit:
            r["format"], r["block_width"], r["block_height"], \
                r["block_bytes"] = hit
        else:
            r["format"] = f"fourcc-{r['fourcc']}"
    else:
        r["format"] = "uncompressed (no fourcc)"
        r["fourcc"] = None
    return r


_PKM_FORMATS = {
    ("10", 0): ("ETC1 RGB", 4, 4, 8),
    ("10", 1): ("ETC1 RGB + alpha", 4, 4, 8),
    ("20", 0): ("ETC2 RGB", 4, 4, 8),
    ("20", 1): ("ETC2 RGBA", 4, 4, 16),
    ("20", 2): ("ETC2 RGB A1", 4, 4, 8),
    ("20", 3): ("EAC R11", 4, 4, 8),
    ("20", 4): ("EAC RG11", 4, 4, 16),
}


def _parse_pkm(data):
    r = _base("pkm")
    if len(data) < 16:
        r["error"] = (f"truncated PKM header: {len(data)} "
                      "bytes, 16 needed")
        return r
    if data[0:4] != b"PKM " or data[4:6] not in (b"10", b"20"):
        r["error"] = "bad PKM magic/version"
        return r
    version = data[4:6].decode("ascii")
    fmt_id, ext_w, ext_h, width, height = \
        struct.unpack_from(">5H", data, 6)
    r["width"], r["height"] = width, height
    r["padded_width"], r["padded_height"] = ext_w, ext_h
    r["pkm_format_id"] = fmt_id
    r["mip_count_basis"] = "not stored in header"
    hit = _PKM_FORMATS.get((version, fmt_id))
    if hit:
        r["format"], r["block_width"], r["block_height"], \
            r["block_bytes"] = hit
    else:
        family = "ETC1" if version == "10" else "ETC2"
        r["format"] = f"{family} (format {fmt_id})"
        r["block_width"], r["block_height"] = 4, 4
    return r


_PARSERS = {
    ".astc": _parse_astc,
    ".ktx": _parse_ktx1,
    ".ktx2": _parse_ktx2,
    ".pvr": _parse_pvr,
    ".dds": _parse_dds,
    ".pkm": _parse_pkm,
}


def _sniff(data):
    if data[0:4] == _ASTC_MAGIC:
        return _parse_astc
    if data[0:12] == _KTX1_ID:
        return _parse_ktx1
    if data[0:12] == _KTX2_ID:
        return _parse_ktx2
    if len(data) >= 4 and \
            struct.unpack_from("<I", data, 0)[0] == _PVR_VERSION:
        return _parse_pvr
    if data[0:4] == _DDS_MAGIC:
        return _parse_dds
    if data[0:4] == b"PKM ":
        return _parse_pkm
    return None


def parse_texture_header(data, ext=""):
    """Parse one compressed-texture header.

    ``data`` is a bounded prefix of the file (512 bytes is
    enough for every header here); ``ext`` selects the
    parser (".astc"/".ktx"/".ktx2"/".pvr"/".dds"/".pkm"),
    with magic sniffing as a fallback when the extension is
    unknown. Returns a facts dict:

    {format, container, width, height, depth, block_width,
     block_height, block_bytes, mip_count, mip_count_basis,
     array_elements, faces, error, ...format extras}

    Header-only: pixel data is never decoded. Malformed
    input yields ``error`` with a named reason; no exception
    escapes.
    """
    try:
        if not data:
            r = _base(None)
            r["error"] = "empty input"
            return r
        parser = _PARSERS.get((ext or "").lower())
        if parser is None:
            parser = _sniff(data)
        if parser is None:
            r = _base(None)
            r["error"] = (f"no texture parser for extension "
                          f"{ext!r} and no known magic matched")
            return r
        return parser(bytes(data))
    except (struct.error, IndexError, ValueError) as e:
        r = _base(None)
        r["error"] = f"header parse failed: {e}"
        return r
