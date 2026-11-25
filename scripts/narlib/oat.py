"""OAT / VDEX / ODEX / ART-image parser primitives.

Parses the ART compiled-artifact family directly:

- OAT: an ELF shared object whose .rodata holds an OatHeader
  (magic ``oat\\n`` + three-digit version). Produced by dex2oat
  from Android 5.0; on Android 8.0+ it is also the content of
  the files named ``*.odex`` under an app's ``oat/<abi>/``
  directory. The header fields that are stable across versions
  are read from their documented offsets; the key-value store
  is recovered by scanning for its known keys, because the
  store's offset moves as the header grows between versions.
- VDEX: the verified-DEX companion of an OAT file (Android
  8.0+). Holds the app's DEX files (standard DEX, or Compact
  DEX from Android 9.0) plus verifier dependencies and
  quickening info. Version 006 (API 26) layout is parsed
  field-by-field; later versions report their version and
  fall back to magic-scan extraction of the embedded DEX
  files, which is layout-independent.
- ODEX (Dalvik): the pre-ART optimized DEX (magic ``dey\\n``)
  whose header points at the embedded DEX it wraps.
- ART image (``*.art``): the runtime image header (magic
  ``art\\n``), parsed for its version and section bounds.

DEX extraction is carving, not de-optimization: VDEX files
hold byte-exact DEX (the quickening lives in the separate
quickening-info section), and a Dalvik ODEX's embedded DEX
still carries quickened opcodes, which callers must label.
Nothing here executes, decrypts, or de-optimizes anything.

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import re
import struct

from . import cdex as _cdex

OAT_MAGIC = b"oat\n"
VDEX_MAGIC = b"vdex"
ODEX_MAGIC = b"dey\n"
ART_MAGIC = b"art\n"
DEX_MAGIC = b"dex\n"
CDEX_MAGIC = b"cdex"

INSTRUCTION_SETS = {
    0: "none", 1: "arm", 2: "arm64", 3: "thumb2", 4: "x86",
    5: "x86_64", 6: "mips", 7: "mips64",
}

# Keys ART writes into the OAT key-value store. The store is a
# run of NUL-terminated key/value string pairs; scanning for
# these known keys recovers it without depending on the
# version-specific header size.
OAT_KV_KEYS = (
    "dex2oat-cmdline", "dex2oat-host", "compiler-filter",
    "debuggable", "native-debuggable", "has-patch-info",
    "instruction-set", "instruction-set-features",
    "instruction-set-variant", "pic", "apex-versions",
    "compilation-reason", "vdex",
)


class OatError(Exception):
    pass


def _version3(raw):
    """Three ASCII digits of a format version, or None."""
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    return text if text.isdigit() else None


def find_oat_header(data):
    """Offset of the OatHeader inside a blob, or None.

    The header is ``oat\\n`` followed by a three-digit version
    and a NUL. A bare ``oat\\n`` substring is not enough.
    """
    start = 0
    while True:
        idx = data.find(OAT_MAGIC, start)
        if idx < 0 or idx + 8 > len(data):
            return None
        if _version3(data[idx + 4:idx + 7]) is not None \
                and data[idx + 7] == 0:
            return idx
        start = idx + 1


def oat_key_value_store(data, header_off):
    """Recover OAT key-value pairs after the header at
    header_off. Returns a dict (possibly empty)."""
    # The fixed header is well under 1 KB in every known
    # version; the store follows it. Scan a bounded window.
    window = data[header_off:header_off + 65536]
    pairs = {}
    for key in set(OAT_KV_KEYS):
        needle = key.encode() + b"\x00"
        pos = window.find(needle)
        if pos < 0:
            continue
        val_start = pos + len(needle)
        val_end = window.find(b"\x00", val_start)
        if val_end < 0:
            continue
        try:
            pairs[key] = window[val_start:val_end].decode(
                "utf-8", "replace")
        except Exception:  # noqa: BLE001 - best-effort store
            continue
    return pairs


def parse_oat(data, name="app.oat"):
    """Parse an OAT file (whole file bytes). Returns a dict:

    {oat_version, oat_header_offset, adler32_checksum,
     instruction_set, instruction_set_name, dex_file_count,
     key_value_store{}, is_elf, elf_class, dex_locations[]}

    dex_locations are the location strings ART recorded for
    its dex files, recovered from the OatDexFile table area
    (printable strings ending in .apk/.dex/.jar near the
    header); they are observed strings, not a table decode.
    """
    off = find_oat_header(data)
    if off is None:
        raise OatError(f"{name}: no OatHeader (oat magic + "
                       "version) found")
    if off + 32 > len(data):
        raise OatError(f"{name}: OatHeader truncated")
    version = _version3(data[off + 4:off + 7])
    adler, iset, _features, dex_count = struct.unpack_from(
        "<IIII", data, off + 8)
    locations = []
    tail = data[off:off + 16384]
    for m in re.finditer(rb"[ -~]{4,}\.(?:apk|dex|jar)", tail):
        text = m.group(0).decode("ascii", "replace")
        # A dex location is a path: it contains no spaces and
        # is not a command-line fragment (the key-value store
        # nearby holds a full dex2oat command line whose
        # --zip-location value would otherwise leak in here).
        if " " in text or text.startswith("-"):
            continue
        if text not in locations:
            locations.append(text)
    return {
        "oat_version": version,
        "oat_header_offset": off,
        "adler32_checksum": adler,
        "instruction_set": iset,
        "instruction_set_name": INSTRUCTION_SETS.get(
            iset, f"unknown-{iset}"),
        "dex_file_count": dex_count,
        "key_value_store": oat_key_value_store(data, off),
        "is_elf": data[:4] == b"\x7fELF",
        "elf_class": ({1: "ELF32", 2: "ELF64"}.get(data[4])
                      if data[:4] == b"\x7fELF"
                      and len(data) > 4 else None),
        "dex_locations": locations,
    }


def parse_vdex(data, name="app.vdex"):
    """Parse a VDEX file header. Returns a dict:

    {vdex_version, number_of_dex_files (006 only, else None),
     dex_size, verifier_deps_size, quickening_info_size,
     embedded[]: [{offset, kind, version, file_size}]}

    embedded[] comes from a magic scan of the whole file and
    is layout-independent: every standard or compact DEX the
    file carries, with the size its own header declares.
    """
    if len(data) < 8 or data[:len(VDEX_MAGIC)] != VDEX_MAGIC:
        raise OatError(f"{name}: not a VDEX file")
    version = _version3(data[4:7])
    out = {"vdex_version": version,
           "number_of_dex_files": None, "dex_size": None,
           "verifier_deps_size": None,
           "quickening_info_size": None, "embedded": []}
    if version == "006" and len(data) >= 24:
        (out["number_of_dex_files"], out["dex_size"],
         out["verifier_deps_size"],
         out["quickening_info_size"]) = struct.unpack_from(
            "<IIII", data, 8)
    out["embedded"] = scan_embedded_dex(data)
    return out


def scan_embedded_dex(data):
    """Find every DEX/CDEX embedded in a blob by magic.

    Each hit: {offset, kind ('dex'|'cdex'), version,
    file_size (from the file's own header; for cdex only
    when its compact header parses, with the parsed header
    carried as cdex_header)}. Overlapping or duplicate
    offsets are reported once, in file order.
    """
    hits = []
    seen = set()
    for magic, kind in ((DEX_MAGIC, "dex"), (CDEX_MAGIC, "cdex")):
        start = 0
        while True:
            idx = data.find(magic, start)
            if idx < 0:
                break
            start = idx + 1
            if idx in seen or idx + 8 > len(data):
                continue
            version = _version3(data[idx + 4:idx + 7])
            if version is None or data[idx + 7] != 0:
                continue
            file_size = None
            if kind == "dex":
                if idx + 36 > len(data):
                    # A DEX magic in the final bytes cannot
                    # be a real embedded DEX (its header alone
                    # is 112 bytes); emitting the hit with
                    # file_size=None crashed the carve with a
                    # TypeError (stability audit A-02).
                    continue
                file_size = struct.unpack_from(
                    "<I", data, idx + 32)[0]
                if file_size < 112 or idx + file_size > len(data):
                    # A dex magic inside string data can carry a
                    # nonsense size; a real embedded dex always
                    # fits the file that carries it.
                    continue
            hit = {"offset": idx, "kind": kind,
                   "version": version,
                   "file_size": file_size}
            if kind == "cdex":
                # Header facts where parseable (narlib.cdex):
                # the compact header declares a trustworthy
                # file_size, which also bounds the carve.
                try:
                    header = _cdex.parse_cdex(data[idx:])
                    hit["file_size"] = header["file_size"]
                    hit["cdex_header"] = header
                except _cdex.CdexError as e:
                    hit["cdex_header_error"] = str(e)
            seen.add(idx)
            hits.append(hit)
    hits.sort(key=lambda h: h["offset"])
    return hits


def extract_dex_from_vdex(data, name="app.vdex"):
    """Carve the DEX files out of a VDEX file.

    Returns [(entry_name, bytes, kind)]: standard DEX slices
    are byte-exact (VDEX stores them unquickened); compact
    DEX slices are returned with kind 'cdex' so callers can
    label them instead of feeding them to a DEX parser.
    """
    hits = scan_embedded_dex(data)
    out = []
    for i, hit in enumerate(hits):
        label = "classes" if i == 0 else f"classes{i + 1}"
        if hit["kind"] == "dex":
            if not hit["file_size"]:
                # Unreachable after the scan-side guard
                # (A-02); never slice on an unknown size.
                continue
            blob = data[hit["offset"]:
                        hit["offset"] + hit["file_size"]]
            out.append((f"{label}.dex", blob, "dex"))
        elif hit.get("file_size"):
            # The compact header parsed: its declared
            # file_size bounds the slice exactly.
            out.append((f"{label}.cdex",
                        data[hit["offset"]:
                             hit["offset"] + hit["file_size"]],
                        "cdex"))
        else:
            # Compact DEX whose header did not parse: no
            # trustworthy total size; bound the slice by the
            # next embedded file or EOF, labeled cdex.
            end = (hits[i + 1]["offset"] if i + 1 < len(hits)
                   else len(data))
            out.append((f"{label}.cdex",
                        data[hit["offset"]:end], "cdex"))
    return out


def parse_odex_dalvik(data, name="app.odex"):
    """Parse a Dalvik ODEX header and carve its embedded DEX.

    Returns {odex_version, dex_offset, dex_length,
    deps_offset, deps_length, aux_offset, aux_length, flags,
    dex: bytes}. The embedded DEX carries quickened opcodes;
    the bytes are returned as stored, never de-optimized.
    """
    if len(data) < 40 or data[:len(ODEX_MAGIC)] != ODEX_MAGIC:
        raise OatError(f"{name}: not a Dalvik ODEX file")
    version = _version3(data[4:7])
    (dex_off, dex_len, deps_off, deps_len, aux_off, aux_len,
     flags) = struct.unpack_from("<IIIIIII", data, 8)
    if dex_off + dex_len > len(data):
        raise OatError(
            f"{name}: embedded DEX [{dex_off}, "
            f"{dex_off + dex_len}) exceeds file size "
            f"{len(data)}")
    return {"odex_version": version, "dex_offset": dex_off,
            "dex_length": dex_len, "deps_offset": deps_off,
            "deps_length": deps_len, "aux_offset": aux_off,
            "aux_length": aux_len, "flags": flags,
            "dex": data[dex_off:dex_off + dex_len]}


def parse_art_image(data, name="app.art"):
    """Parse an ART image header (``art\\n`` + version).

    Returns {art_version, image_begin, image_size,
    oat_checksum, oat_file_begin, oat_data_begin, oat_data_end,
    oat_file_end} — the header's own section bounds.
    """
    if len(data) < 40 or data[:len(ART_MAGIC)] != ART_MAGIC:
        raise OatError(f"{name}: not an ART image file")
    version = _version3(data[4:7])
    (image_begin, image_size, oat_checksum, oat_file_begin,
     oat_data_begin, oat_data_end, oat_file_end) = \
        struct.unpack_from("<IIIIIII", data, 8)
    return {"art_version": version, "image_begin": image_begin,
            "image_size": image_size,
            "oat_checksum": oat_checksum,
            "oat_file_begin": oat_file_begin,
            "oat_data_begin": oat_data_begin,
            "oat_data_end": oat_data_end,
            "oat_file_end": oat_file_end}
