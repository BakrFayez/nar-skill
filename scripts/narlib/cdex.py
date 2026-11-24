"""Compact DEX (CDEX) header + section-table parser.

Implements header/structure parsing for ART compact DEX
per the publicly documented layout (AOSP libdexfile
``compact_dex_file.h``): a compact DEX file starts with the
standard 112-byte DEX header (magic ``cdex`` + version
``001`` instead of ``dex\\n`` + version) followed by six
compact-DEX-specific uint32 fields, for a 136-byte header:

    feature_flags, debug_info_offsets_pos,
    debug_info_offsets_table_offset, debug_info_base,
    owned_data_begin, owned_data_end

The standard section table (string/type/proto/field/method
ids and class defs, each a size + offset pair) is read from
the shared header fields, and every section's declared
extent is validated against the header's file_size and the
bytes actually available. Malformed input fails with a
named CdexError, following the narlib error style.

HONEST LABELS: this is header/structure parsing only,
verified against synthetic files built to the public
layout in the unit tests. String contents, code items and
the rest of the payload are NOT decoded: compact DEX uses
its own code-item and string encodings, and no payload
decoding is claimed here or in the capability records.

Part of NAR (Nirous Android Reversing).
Research by Bakr Fayez. MIT License. See LICENSE in the repo root.
"""
import struct

CDEX_MAGIC = b"cdex"
CDEX_VERSION = "001"
STANDARD_HEADER_SIZE = 112
CDEX_HEADER_SIZE = 136
_ENDIAN_TAG = 0x12345678

# (section name, header offset of the size field, item size)
_SECTIONS = (
    ("string_ids", 56, 4),
    ("type_ids", 64, 4),
    ("proto_ids", 72, 12),
    ("field_ids", 80, 8),
    ("method_ids", 88, 8),
    ("class_defs", 96, 32),
)


class CdexError(Exception):
    pass


def parse_cdex(data, name="classes.cdex"):
    """Parse and validate one compact DEX header.

    `data` is the file (or a carved slice of a carrier);
    bytes beyond the header's declared file_size are
    ignored, so a slice that runs into the following file
    of a container still parses. Returns a dict of header
    facts:

    {version, checksum, file_size, header_size,
     endian_tag, link_size, link_off, map_off, data_size,
     data_off, sections: {name: {size, offset}},
     feature_flags, debug_info_offsets_pos,
     debug_info_offsets_table_offset, debug_info_base,
     owned_data_begin, owned_data_end,
     payload_decoded: False}

    Raises CdexError with a named reason on malformed
    input (not_cdex / unsupported_version /
    truncated_header / bad_header_size / bad_endian /
    truncated_file / section_out_of_bounds /
    data_out_of_bounds / owned_data_out_of_bounds /
    debug_info_out_of_bounds).
    """
    if len(data) < 8 or data[:4] != CDEX_MAGIC:
        raise CdexError(f"{name}: not a compact DEX file "
                        "(bad magic)")
    version = data[4:7].decode("ascii", "replace")
    if data[7] != 0 or version != CDEX_VERSION:
        raise CdexError(
            f"{name}: unsupported compact DEX version "
            f"{version!r} (only cdex001 is documented)")
    if len(data) < CDEX_HEADER_SIZE:
        raise CdexError(
            f"{name}: truncated_header: compact DEX header "
            f"needs {CDEX_HEADER_SIZE} bytes, "
            f"{len(data)} available")
    checksum = struct.unpack_from("<I", data, 8)[0]
    file_size, header_size, endian = \
        struct.unpack_from("<III", data, 32)
    if header_size != CDEX_HEADER_SIZE:
        raise CdexError(
            f"{name}: bad_header_size: compact DEX header "
            f"declares {header_size} bytes, expected "
            f"{CDEX_HEADER_SIZE}")
    if endian != _ENDIAN_TAG:
        raise CdexError(
            f"{name}: bad_endian: endian tag {endian:#x} is "
            "not the little-endian tag 0x12345678")
    if file_size < CDEX_HEADER_SIZE:
        raise CdexError(
            f"{name}: bad file_size {file_size} (smaller "
            "than the compact DEX header)")
    if len(data) < file_size:
        raise CdexError(
            f"{name}: truncated_file: header declares "
            f"{file_size} bytes, {len(data)} available")
    (link_size, link_off, map_off) = struct.unpack_from(
        "<III", data, 44)
    sections = {}
    for label, off, item in _SECTIONS:
        size, sec_off = struct.unpack_from("<II", data, off)
        if size:
            if sec_off < header_size or \
                    sec_off + size * item > file_size:
                raise CdexError(
                    f"{name}: section_out_of_bounds: "
                    f"{label} ({size} entries at {sec_off:#x}, "
                    f"{item} bytes each) extends past "
                    f"file_size {file_size}")
        sections[label] = {"size": size, "offset": sec_off}
    data_size, data_off = struct.unpack_from("<II", data, 104)
    if data_size and data_off + data_size > file_size:
        raise CdexError(
            f"{name}: data_out_of_bounds: data section "
            f"[{data_off:#x}, {data_off + data_size:#x}) "
            f"extends past file_size {file_size}")
    (feature_flags, dbg_pos, dbg_table_off, dbg_base,
     owned_begin, owned_end) = struct.unpack_from(
        "<IIIIII", data, STANDARD_HEADER_SIZE)
    if owned_begin or owned_end:
        if owned_begin > owned_end or owned_end > file_size:
            raise CdexError(
                f"{name}: owned_data_out_of_bounds: owned "
                f"data range [{owned_begin:#x}, "
                f"{owned_end:#x}) is not within file_size "
                f"{file_size}")
    if dbg_pos and dbg_pos >= file_size:
        raise CdexError(
            f"{name}: debug_info_out_of_bounds: debug info "
            f"offsets position {dbg_pos:#x} is not within "
            f"file_size {file_size}")
    return {
        "version": version,
        "checksum": checksum,
        "file_size": file_size,
        "header_size": header_size,
        "endian_tag": endian,
        "link_size": link_size,
        "link_off": link_off,
        "map_off": map_off,
        "data_size": data_size,
        "data_off": data_off,
        "sections": sections,
        "feature_flags": feature_flags,
        "debug_info_offsets_pos": dbg_pos,
        "debug_info_offsets_table_offset": dbg_table_off,
        "debug_info_base": dbg_base,
        "owned_data_begin": owned_begin,
        "owned_data_end": owned_end,
        "payload_decoded": False,
    }
