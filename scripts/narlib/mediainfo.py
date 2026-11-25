"""Media header facts: Wwise banks, video containers,
fonts and 3D models (brief section 4.3).

Header/structure facts only, from bounded prefixes:

- Wwise .bnk soundbanks (BKHD version/id + section walk)
  and .wem / RIFF audio (fmt/fact/data chunk facts);
- MP4/MOV (ftyp brand, mvhd timing, tkhd size, first stsd
  codec + avcC/hvcC profile/level) and WebM/MKV (EBML
  DocType + track CodecIDs). ``b_frames`` is NOT derivable
  from container headers and is reported null with that
  basis named — never guessed;
- sfnt fonts (maxp glyph count, name table, post format,
  plus explicitly heuristic subsetting signals); CFF OTF
  glyph counts come from the Top DICT CharStrings INDEX
  when feasible, else null with the reason;
- glTF/GLB (mesh/primitive/vertex/material/skin/joint/
  animation counts), OBJ (bounded line census) and FBX
  (binary version + labelled structural note; ASCII Model
  line census).

Malformed input degrades to a facts dict with a named
``error``; no exception escapes and no value is fabricated.

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import json
import re
import struct

_OBJ_SCAN_CAP = 2 * 1024 * 1024

# ----------------------------------------------------------------
# Wwise


def _bnk_facts(data):
    r = {"format": "wwise-bank", "is_wem": False,
         "version": None, "bank_id": None, "sections": [],
         "section_ids": [], "sections_present": {},
         "error": None}
    if len(data) < 8 or data[0:4] != b"BKHD":
        r["error"] = "no BKHD chunk at offset 0 (not a Wwise bank)"
        return r
    sections = []
    off = 0
    while off + 8 <= len(data):
        cid = data[off:off + 4]
        if not all(32 <= b < 127 for b in cid):
            break
        size = struct.unpack_from("<I", data, off + 4)[0]
        sections.append({"id": cid.decode("ascii", "replace"),
                         "size": size, "offset": off})
        if cid == b"BKHD" and off == 0 and size >= 8 \
                and off + 16 <= len(data):
            r["version"] = struct.unpack_from(
                "<I", data, off + 8)[0]
            r["bank_id"] = struct.unpack_from(
                "<I", data, off + 12)[0]
        if size > len(data):
            break
        off += 8 + size
        if size == 0:
            break
    r["sections"] = sections
    r["section_ids"] = [s["id"] for s in sections]
    for want in ("DIDX", "HIRC", "DATA", "STID"):
        r["sections_present"][want] = want in r["section_ids"]
    return r


def _riff_facts(data, is_wem):
    r = {"format": "wwise-wem" if is_wem else "riff-wave",
         "is_wem": bool(is_wem), "riff_size": None,
         "audio_format": None, "channels": None,
         "sample_rate_hz": None, "byte_rate": None,
         "bits_per_sample": None, "data_size": None,
         "fact_size": None, "chunks": [], "error": None}
    if len(data) < 12 or data[0:4] != b"RIFF":
        r["error"] = "no RIFF header"
        return r
    r["riff_size"] = struct.unpack_from("<I", data, 4)[0]
    chunks = []
    off = 12
    while off + 8 <= len(data):
        cid = data[off:off + 4]
        size = struct.unpack_from("<I", data, off + 4)[0]
        chunks.append({"id": cid.decode("ascii", "replace"),
                       "size": size, "offset": off})
        body = off + 8
        if cid == b"fmt " and size >= 16 \
                and body + 16 <= len(data):
            (r["audio_format"], r["channels"],
             r["sample_rate_hz"], r["byte_rate"]) = \
                struct.unpack_from("<HHII", data, body)
            if size >= 18 and body + 18 <= len(data):
                r["bits_per_sample"] = struct.unpack_from(
                    "<H", data, body + 14)[0]
        elif cid == b"data":
            r["data_size"] = size
        elif cid == b"fact":
            r["fact_size"] = size
        off = body + size + (size & 1)
        if size == 0 and cid not in (b"fmt ",):
            # A zero-size non-fmt chunk ends a bounded walk
            # only when nothing follows; keep walking is
            # unsafe (no progress on data), so stop unless
            # it is the trailing data chunk already recorded.
            if cid == b"data":
                break
    r["chunks"] = chunks
    return r


def wwise_bank_facts(data, ext=""):
    """Facts for a Wwise .bnk soundbank or .wem audio file.

    ``ext`` (".bnk"/".wem") decides the ``is_wem`` flag;
    the parse itself follows the content (BKHD bank chunk
    walk vs RIFF chunk walk)."""
    try:
        is_wem = (ext or "").lower() == ".wem"
        if data[0:4] == b"BKHD":
            r = _bnk_facts(bytes(data))
            r["is_wem"] = False
            return r
        if data[0:4] == b"RIFF":
            return _riff_facts(bytes(data), is_wem)
        r = _bnk_facts(b"")
        r["error"] = ("unrecognized Wwise content: neither "
                      "BKHD bank nor RIFF header")
        return r
    except (struct.error, IndexError) as e:
        return {"format": None, "is_wem": (ext or "").lower()
                == ".wem", "error": f"parse failed: {e}"}


# ----------------------------------------------------------------
# Video: MP4 / MOV

_AVC_PROFILES = {66: "Baseline", 77: "Main", 88: "Extended",
                 100: "High", 110: "High 10", 122: "High 4:2:2",
                 244: "High 4:4:4 Predictive"}


def _mp4_boxes(data, start, end):
    off = start
    while off + 8 <= end:
        size = struct.unpack_from(">I", data, off)[0]
        btype = data[off + 4:off + 8]
        header = 8
        if size == 1 and off + 16 <= end:
            size = struct.unpack_from(">Q", data, off + 8)[0]
            header = 16
        elif size == 0:
            size = end - off
        if size < header or off + size > end:
            # Clamp a truncated final box to what is present.
            if off + header > end:
                break
            yield btype, off + header, end
            break
        yield btype, off + header, off + size
        off += size


def _mp4_find(data, start, end, path):
    """Follow a box path (container boxes) from start..end."""
    cur_start, cur_end = start, end
    for depth, want in enumerate(path):
        found = None
        for btype, bs, be in _mp4_boxes(data, cur_start, cur_end):
            if btype == want:
                found = (bs, be)
                break
        if found is None:
            return None
        if depth == len(path) - 1:
            return found
        cur_start, cur_end = found
    return None


def _mp4_facts(data):
    r = {"format": "mp4", "major_brand": None,
         "minor_version": None, "compatible_brands": [],
         "timescale": None, "duration": None,
         "duration_seconds": None, "width": None,
         "height": None, "codec": None, "codec_profile": None,
         "codec_profile_name": None, "codec_level": None,
         "b_frames": None,
         "b_frames_basis": "not derivable from container headers",
         "error": None}
    top = list(_mp4_boxes(data, 0, len(data)))
    if not top:
        r["error"] = "no MP4 boxes in the read window"
        return r
    for btype, bs, be in top:
        if btype == b"ftyp" and be - bs >= 8:
            r["major_brand"] = data[bs:bs + 4].decode(
                "ascii", "replace")
            r["minor_version"] = struct.unpack_from(
                ">I", data, bs + 4)[0]
            brands = []
            for i in range(bs + 8, be - 3, 4):
                brands.append(data[i:i + 4].decode(
                    "ascii", "replace"))
            r["compatible_brands"] = brands
            if r["major_brand"] in ("qt  ",):
                r["format"] = "mov"
    moov = None
    for btype, bs, be in top:
        if btype == b"moov":
            moov = (bs, be)
            break
    if moov is None:
        r["error"] = "no moov box in the read window"
        return r
    mvhd = _mp4_find(data, moov[0], moov[1], [b"mvhd"])
    if mvhd is not None:
        bs, be = mvhd
        if be - bs >= 4:
            version = data[bs]
            try:
                if version == 1 and be - bs >= 32:
                    r["timescale"] = struct.unpack_from(
                        ">I", data, bs + 20)[0]
                    r["duration"] = struct.unpack_from(
                        ">Q", data, bs + 24)[0]
                elif version == 0 and be - bs >= 20:
                    r["timescale"] = struct.unpack_from(
                        ">I", data, bs + 12)[0]
                    r["duration"] = struct.unpack_from(
                        ">I", data, bs + 16)[0]
            except struct.error:
                pass
            if r["timescale"]:
                r["duration_seconds"] = round(
                    r["duration"] / r["timescale"], 3)
    for btype, bs, be in _mp4_boxes(data, moov[0], moov[1]):
        if btype != b"trak":
            continue
        tkhd = _mp4_find(data, bs, be, [b"tkhd"])
        if tkhd is not None and tkhd[1] - tkhd[0] >= 8:
            w_fixed = struct.unpack_from(
                ">I", data, tkhd[1] - 8)[0]
            h_fixed = struct.unpack_from(
                ">I", data, tkhd[1] - 4)[0]
            if w_fixed:
                r["width"] = w_fixed / 65536.0
                if r["width"] == int(r["width"]):
                    r["width"] = int(r["width"])
            if h_fixed:
                r["height"] = h_fixed / 65536.0
                if r["height"] == int(r["height"]):
                    r["height"] = int(r["height"])
        stsd = _mp4_find(data, bs, be,
                         [b"mdia", b"minf", b"stbl", b"stsd"])
        if stsd is not None and r["codec"] is None:
            sbs, sbe = stsd
            if sbe - sbs >= 16:
                entry_off = sbs + 8
                esize = struct.unpack_from(
                    ">I", data, entry_off)[0]
                codec = data[entry_off + 4:entry_off + 8].decode(
                    "ascii", "replace")
                r["codec"] = codec
                entry_end = min(entry_off + esize, sbe) \
                    if esize >= 8 else sbe
                child_off = entry_off + 8 + 78
                if codec in ("avc1", "hvc1", "hev1") \
                        and child_off < entry_end:
                    for ctype, cbs, cbe in _mp4_boxes(
                            data, child_off, entry_end):
                        if ctype == b"avcC" and cbe - cbs >= 4:
                            r["codec_profile"] = data[cbs + 1]
                            r["codec_profile_name"] = \
                                _AVC_PROFILES.get(data[cbs + 1])
                            r["codec_level"] = data[cbs + 3]
                        elif ctype == b"hvcC" and cbe - cbs >= 13:
                            r["codec_profile"] = data[cbs + 1] & 0x1F
                            r["codec_level"] = data[cbs + 12]
        if r["codec"] is not None and r["width"] is not None:
            break
    return r


# ----------------------------------------------------------------
# Video: WebM / MKV (EBML)

def _ebml_id(data, off):
    if off >= len(data):
        raise ValueError("eof in element id")
    first = data[off]
    for length in (1, 2, 3, 4):
        if first & (0x80 >> (length - 1)):
            if off + length > len(data):
                raise ValueError("truncated element id")
            return int.from_bytes(
                data[off:off + length], "big"), length
    raise ValueError("bad element id")


def _ebml_size(data, off):
    if off >= len(data):
        raise ValueError("eof in element size")
    first = data[off]
    for length in range(1, 9):
        if first & (0x80 >> (length - 1)):
            if off + length > len(data):
                raise ValueError("truncated element size")
            raw = int.from_bytes(data[off:off + length], "big")
            mask = (1 << (7 * length)) - 1
            value = raw & mask
            if value == mask:
                return None, length  # unknown size
            return value, length
    raise ValueError("bad element size")


def _ebml_header(data, off):
    eid, idlen = _ebml_id(data, off)
    size, sizelen = _ebml_size(data, off + idlen)
    return eid, size, off + idlen + sizelen


def _ebml_children(data, start, end):
    off = start
    while off < end:
        try:
            eid, size, body = _ebml_header(data, off)
        except ValueError:
            return
        body_end = end if size is None else min(body + size, end)
        yield eid, body, body_end
        if size is None:
            return
        off = body + size


def _mkv_facts(data):
    r = {"format": "matroska", "doc_type": None,
         "doc_type_version": None, "codec": None,
         "tracks": [], "b_frames": None,
         "b_frames_basis": "not derivable from container headers",
         "error": None}
    if len(data) < 4 or data[0:4] != b"\x1a\x45\xdf\xa3":
        r["error"] = "no EBML header magic"
        return r
    try:
        _eid, esize, ebody = _ebml_header(data, 0)
        eend = len(data) if esize is None else min(
            ebody + esize, len(data))
        for cid, cbs, cbe in _ebml_children(data, ebody, eend):
            if cid == 0x4282:
                r["doc_type"] = data[cbs:cbe].decode(
                    "ascii", "replace")
            elif cid == 0x4287:
                r["doc_type_version"] = int.from_bytes(
                    data[cbs:cbe], "big")
        if r["doc_type"] == "webm":
            r["format"] = "webm"
        # Top-level walk to the Segment, then its children.
        off = eend
        seg = None
        while off < len(data):
            eid, size, body = _ebml_header(data, off)
            if eid == 0x18538067:
                seg = (body, len(data) if size is None
                       else min(body + size, len(data)))
                break
            if size is None:
                break
            off = body + size
        if seg is None:
            r["error"] = "no Segment element in the read window"
            return r
        for cid, cbs, cbe in _ebml_children(data, seg[0], seg[1]):
            if cid != 0x1654AE6B:  # Tracks
                continue
            for tid, tbs, tbe in _ebml_children(data, cbs, cbe):
                if tid != 0xAE:  # TrackEntry
                    continue
                track = {"track_number": None,
                         "track_type": None, "codec_id": None}
                for fid, fbs, fbe in _ebml_children(
                        data, tbs, tbe):
                    if fid == 0xD7:
                        track["track_number"] = int.from_bytes(
                            data[fbs:fbe], "big")
                    elif fid == 0x83:
                        track["track_type"] = int.from_bytes(
                            data[fbs:fbe], "big")
                    elif fid == 0x86:
                        track["codec_id"] = data[fbs:fbe].decode(
                            "ascii", "replace")
                r["tracks"].append(track)
            break
        for track in r["tracks"]:
            if track["track_type"] == 1 and track["codec_id"]:
                r["codec"] = track["codec_id"]
                break
        if r["codec"] is None and r["tracks"]:
            r["codec"] = r["tracks"][0]["codec_id"]
    except (ValueError, IndexError) as e:
        r["error"] = f"EBML parse failed: {e}"
    return r


def video_facts(data, ext=""):
    """Container-level video facts for MP4/MOV or WebM/MKV.

    ``b_frames`` is always null: B-frame presence lives in
    the elementary stream, not the container headers, and
    is never guessed."""
    try:
        data = bytes(data)
        low = (ext or "").lower()
        if low in (".webm", ".mkv") or \
                data[0:4] == b"\x1a\x45\xdf\xa3":
            return _mkv_facts(data)
        return _mp4_facts(data)
    except (struct.error, IndexError) as e:
        return {"format": None, "b_frames": None,
                "b_frames_basis":
                    "not derivable from container headers",
                "error": f"parse failed: {e}"}


# ----------------------------------------------------------------
# Fonts

def _cff_index(data, pos):
    """(object byte ranges, next pos) for one CFF INDEX."""
    if pos + 2 > len(data):
        raise ValueError("truncated INDEX")
    count = struct.unpack_from(">H", data, pos)[0]
    if count == 0:
        return [], pos + 2
    off_size = data[pos + 2]
    offs_at = pos + 3
    offsets = []
    for i in range(count + 1):
        at = offs_at + i * off_size
        offsets.append(int.from_bytes(
            data[at:at + off_size], "big"))
    base = offs_at + (count + 1) * off_size - 1
    ranges = [(base + offsets[i], base + offsets[i + 1])
              for i in range(count)]
    return ranges, base + offsets[count]


def _cff_dict_charstrings_offset(dict_bytes):
    operands = []
    i = 0
    result = None
    while i < len(dict_bytes):
        b = dict_bytes[i]
        if b == 12:
            i += 2
            operands = []
        elif b <= 21:
            if b == 17 and operands:
                result = operands[-1]
            i += 1
            operands = []
        elif b == 28 and i + 2 < len(dict_bytes):
            operands.append(struct.unpack_from(
                ">h", dict_bytes, i + 1)[0])
            i += 3
        elif b == 29 and i + 4 < len(dict_bytes):
            operands.append(struct.unpack_from(
                ">i", dict_bytes, i + 1)[0])
            i += 5
        elif b == 30:
            i += 1
            while i < len(dict_bytes):
                nib = dict_bytes[i]
                i += 1
                if (nib & 0x0F) == 0x0F or (nib >> 4) == 0x0F:
                    break
            operands.append(0.0)
        elif 32 <= b <= 246:
            operands.append(b - 139)
            i += 1
        elif 247 <= b <= 250 and i + 1 < len(dict_bytes):
            operands.append((b - 247) * 256
                            + dict_bytes[i + 1] + 108)
            i += 2
        elif 251 <= b <= 254 and i + 1 < len(dict_bytes):
            operands.append(-(b - 251) * 256
                            - dict_bytes[i + 1] - 108)
            i += 2
        else:
            i += 1
    return result


def _cff_num_glyphs(cff):
    """Glyph count from the Top DICT CharStrings INDEX."""
    if len(cff) < 4:
        return None, "CFF data truncated (<4 bytes)"
    hdr_size = cff[2]
    try:
        _names, pos = _cff_index(cff, hdr_size)
        dicts, _pos = _cff_index(cff, pos)
        if not dicts:
            return None, "CFF Top DICT INDEX is empty"
        top = cff[dicts[0][0]:dicts[0][1]]
        cs_off = _cff_dict_charstrings_offset(top)
        if cs_off is None:
            return None, ("Top DICT carries no CharStrings "
                          "offset (operator 17)")
        if cs_off + 2 > len(cff):
            return None, "CharStrings INDEX beyond CFF data"
        count = struct.unpack_from(">H", cff, cs_off)[0]
        return count, "CFF CharStrings INDEX count"
    except (ValueError, IndexError, struct.error) as e:
        return None, f"CFF parse failed: {e}"


def font_facts(data):
    """sfnt font facts: glyph count, names, post format and
    explicitly heuristic subsetting signals."""
    r = {"format": None, "num_glyphs": None,
         "num_glyphs_basis": None, "family_name": None,
         "subfamily": None, "full_name": None,
         "preferred_family": None, "names": {},
         "post_format": None, "signals": [],
         "subset_suspected": False,
         "basis": ("heuristic: subsetting is suspected from "
                   "header signals only (post format 3.0 / "
                   "missing or truncated name data); this is "
                   "not proof of subsetting"),
         "error": None}
    try:
        data = bytes(data)
        if len(data) < 12:
            r["error"] = "truncated sfnt header"
            return r
        magic = data[0:4]
        if magic == b"OTTO":
            r["format"] = "otf-cff"
        elif magic == b"\x00\x01\x00\x00" or magic == b"true":
            r["format"] = "ttf"
        elif magic == b"ttcf":
            r["format"] = "ttc"
            r["error"] = ("font collection: per-font tables "
                          "not parsed")
            return r
        else:
            r["error"] = f"unrecognized sfnt magic {magic!r}"
            return r
        num_tables = struct.unpack_from(">H", data, 4)[0]
        tables = {}
        name_truncated = False
        for i in range(num_tables):
            at = 12 + i * 16
            if at + 16 > len(data):
                name_truncated = True
                break
            tag = data[at:at + 4].decode("ascii", "replace")
            _chk, off, length = struct.unpack_from(
                ">III", data, at + 4)
            tables[tag] = (off, length)
        cff_data = None
        if "CFF " in tables:
            off, length = tables["CFF "]
            cff_data = data[off:off + length]
        if "maxp" in tables:
            off, length = tables["maxp"]
            if length >= 4 and off + 4 <= len(data):
                version = struct.unpack_from(
                    ">I", data, off)[0]
                if version == 0x00010000 and length >= 6 \
                        and off + 6 <= len(data):
                    r["num_glyphs"] = struct.unpack_from(
                        ">H", data, off + 4)[0]
                    r["num_glyphs_basis"] = \
                        "maxp v1.0 numGlyphs"
                elif version == 0x00005000:
                    if cff_data is not None:
                        count, why = _cff_num_glyphs(cff_data)
                        r["num_glyphs"] = count
                        r["num_glyphs_basis"] = why
                    else:
                        r["num_glyphs_basis"] = (
                            "maxp v0.5 carries no numGlyphs "
                            "and no CFF table is present")
        if "post" in tables:
            off, length = tables["post"]
            if length >= 4 and off + 4 <= len(data):
                fixed = struct.unpack_from(">I", data, off)[0]
                r["post_format"] = fixed / 65536.0
                if r["post_format"] == int(r["post_format"]):
                    r["post_format"] = int(r["post_format"])
        names = {}
        if "name" in tables:
            off, length = tables["name"]
            if off + length > len(data):
                name_truncated = True
            if off + 6 <= len(data):
                _fmt, count, str_off = struct.unpack_from(
                    ">HHH", data, off)
                for i in range(count):
                    rat = off + 6 + i * 12
                    if rat + 12 > len(data):
                        name_truncated = True
                        break
                    (plat, _enc, _lang, name_id, nlen,
                     noff) = struct.unpack_from(
                        ">HHHHHH", data, rat)
                    if name_id not in (1, 2, 4, 16):
                        continue
                    sat = off + str_off + noff
                    raw = data[sat:sat + nlen]
                    if len(raw) < nlen:
                        name_truncated = True
                        continue
                    try:
                        if plat in (0, 3):
                            text = raw.decode("utf-16-be")
                        elif plat == 1:
                            text = raw.decode("latin-1")
                        else:
                            continue
                    except UnicodeDecodeError:
                        continue
                    text = text.strip("\x00").strip()
                    if text and name_id not in names:
                        names[name_id] = text
        else:
            name_truncated = name_truncated or False
        r["names"] = {str(k): v for k, v in names.items()}
        r["family_name"] = names.get(1)
        r["preferred_family"] = names.get(16)
        r["subfamily"] = names.get(2)
        r["full_name"] = names.get(4)
        signals = []
        if r["post_format"] == 3.0:
            signals.append("post format 3.0 (no glyph names)")
        if "name" not in tables:
            signals.append("name table absent")
        elif name_truncated:
            signals.append("name table truncated")
        if r["num_glyphs"] is not None:
            signals.append(
                f"glyph count present ({r['num_glyphs']})")
        r["signals"] = signals
        r["subset_suspected"] = (
            r["post_format"] == 3.0 or "name" not in tables
            or name_truncated)
        return r
    except (struct.error, IndexError) as e:
        r["error"] = f"font parse failed: {e}"
        return r


# ----------------------------------------------------------------
# Models

def _gltf_counts(doc):
    accessors = doc.get("accessors") or []
    meshes = doc.get("meshes") or []
    primitives = 0
    vertices = 0
    for mesh in meshes:
        for prim in mesh.get("primitives") or []:
            primitives += 1
            attrs = prim.get("attributes") or {}
            pos = attrs.get("POSITION")
            if isinstance(pos, int) \
                    and 0 <= pos < len(accessors):
                count = accessors[pos].get("count")
                if isinstance(count, int):
                    vertices += count
    skins = doc.get("skins") or []
    return {"meshes": len(meshes), "primitives": primitives,
            "vertex_count": vertices,
            "materials": len(doc.get("materials") or []),
            "skins": len(skins),
            "joints": sum(len(s.get("joints") or [])
                          for s in skins),
            "animations": len(doc.get("animations") or []),
            "nodes": len(doc.get("nodes") or [])}


def _glb_facts(data):
    r = {"format": "glb", "version": None, "meshes": None,
         "primitives": None, "vertex_count": None,
         "materials": None, "skins": None, "joints": None,
         "animations": None, "nodes": None, "error": None}
    if len(data) < 12 or data[0:4] != b"glTF":
        r["error"] = "no glTF magic (not a GLB)"
        return r
    r["version"] = struct.unpack_from("<I", data, 4)[0]
    if len(data) < 20:
        r["error"] = "truncated GLB: no JSON chunk header"
        return r
    chunk_len = struct.unpack_from("<I", data, 12)[0]
    chunk_type = data[16:20]
    if chunk_type != b"JSON":
        r["error"] = "first GLB chunk is not JSON"
        return r
    raw = data[20:20 + chunk_len]
    if len(raw) < chunk_len:
        r["error"] = "GLB JSON chunk truncated"
        return r
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        r["error"] = f"GLB JSON parse failed: {e}"
        return r
    r.update(_gltf_counts(doc))
    return r


def _gltf_facts(data):
    r = {"format": "gltf", "version": None, "meshes": None,
         "primitives": None, "vertex_count": None,
         "materials": None, "skins": None, "joints": None,
         "animations": None, "nodes": None, "error": None}
    try:
        doc = json.loads(bytes(data).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        r["error"] = f"glTF JSON parse failed: {e}"
        return r
    asset = doc.get("asset") or {}
    r["version"] = asset.get("version")
    r.update(_gltf_counts(doc))
    return r


def _obj_facts(data):
    r = {"format": "obj", "vertices": 0, "texcoords": 0,
         "normals": 0, "faces": 0, "materials_used": [],
         "material_count": 0, "mtllib": [], "truncated": False,
         "error": None}
    if len(data) > _OBJ_SCAN_CAP:
        r["truncated"] = True
        data = data[:_OBJ_SCAN_CAP]
    text = bytes(data).decode("utf-8", "replace")
    used = set()
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("v "):
            r["vertices"] += 1
        elif line.startswith("vt "):
            r["texcoords"] += 1
        elif line.startswith("vn "):
            r["normals"] += 1
        elif line.startswith("f "):
            r["faces"] += 1
        elif line.startswith("usemtl "):
            used.add(line[7:].strip())
        elif line.startswith("mtllib "):
            r["mtllib"].append(line[7:].strip())
    r["materials_used"] = sorted(used)
    r["material_count"] = len(used)
    return r


_FBX_MODEL_RE = re.compile(
    r'Model:\s*\d+,\s*"[^"]*",\s*"(Mesh|LimbNode)"')


def _fbx_facts(data):
    r = {"format": "fbx", "version": None, "meshes": None,
         "limb_nodes": None, "models": None, "error": None,
         "note": None}
    magic = b"Kaydara FBX Binary  \x00\x1a\x00"
    if data.startswith(magic):
        r["format"] = "fbx-binary"
        if len(data) >= 27:
            r["version"] = struct.unpack_from(
                "<I", data, 23)[0]
        r["note"] = ("binary FBX node-tree census is not "
                     "reliable from a header scan; mesh/limb "
                     "counts are null, not estimated")
        return r
    text = bytes(data[:_OBJ_SCAN_CAP]).decode("utf-8", "replace")
    if "FBXHeaderExtension" in text or "; FBX" in text[:64]:
        r["format"] = "fbx-ascii"
        meshes = 0
        limbs = 0
        for match in _FBX_MODEL_RE.finditer(text):
            if match.group(1) == "Mesh":
                meshes += 1
            else:
                limbs += 1
        r["meshes"] = meshes
        r["limb_nodes"] = limbs
        r["models"] = meshes + limbs
        return r
    r["error"] = "unrecognized FBX content (no binary magic, no ASCII header)"
    return r


def model_facts(data, ext=""):
    """Model facts for GLB / glTF / OBJ / FBX content."""
    try:
        data = bytes(data)
        low = (ext or "").lower()
        if low == ".glb" or data[0:4] == b"glTF":
            return _glb_facts(data)
        if low == ".gltf" or data.lstrip()[0:1] == b"{":
            return _gltf_facts(data)
        if low == ".fbx" or data.startswith(
                b"Kaydara FBX Binary"):
            return _fbx_facts(data)
        if low == ".obj":
            return _obj_facts(data)
        # Sniff OBJ text as a last resort.
        head = data[:256].decode("utf-8", "replace")
        if any(line.startswith(("v ", "vt ", "vn ", "f ",
                                "mtllib ", "#"))
               for line in head.splitlines()):
            return _obj_facts(data)
        return {"format": None,
                "error": f"no model parser matched ext {ext!r}"}
    except (struct.error, IndexError) as e:
        return {"format": None, "error": f"parse failed: {e}"}
