#!/usr/bin/env python3
"""nar-air.py: deep-dive inspection of an Adobe AIR app
inside an APK (or split set / container), or of a bare .swf.

Evidence is the family's own: the AIR application
descriptor (META-INF/AIR/application.xml, or any
application.xml in the http://ns.adobe.com/air/application/*
namespace) and the SWF movie(s) it launches. SWF parsing is
structural: header (FWS / CWS zlib / ZWS LZMA, decompression
bounded), frame rate + count, a tag census, ExportAssets /
SymbolClass exported symbol names (real AS3 class names),
and DoABC tag count + bytes — ABC bytecode is counted, NOT
decoded. Stdlib only; reads are capped and malformed members
degrade to notes, never a crash.

Usage:
    python3 nar-air.py app.apk [--json]
    python3 nar-air.py movie.swf [--json]

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import lzma
import os
import struct
import sys
import zipfile
import zlib
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import container as container_mod  # noqa: E402
from narlib.safearchive import read_member_capped  # noqa: E402

VERSION = "3.0.1"
MEMBER_CAP = 32 * 1024 * 1024
SWF_BODY_CAP = 64 * 1024 * 1024
SYMBOL_SAMPLE_CAP = 50

TAG_NAMES = {
    0: "End", 1: "ShowFrame", 2: "DefineShape",
    6: "DefineBits", 8: "JPEGTables", 9: "SetBackgroundColor",
    10: "DefineFont", 11: "DefineText", 12: "DoAction",
    14: "DefineSound", 17: "DefineButtonSound",
    18: "SoundStreamHead", 19: "SoundStreamBlock",
    20: "DefineBitsLossless", 21: "DefineBitsJPEG2",
    22: "DefineShape2", 24: "Protect", 26: "PlaceObject2",
    28: "RemoveObject2", 32: "DefineShape3", 33: "DefineText2",
    34: "DefineButton2", 35: "DefineBitsJPEG3",
    36: "DefineBitsLossless2", 37: "DefineEditText",
    39: "DefineSprite", 43: "FrameLabel",
    46: "DefineMorphShape", 48: "DefineFont2",
    56: "ExportAssets", 57: "ImportAssets",
    58: "EnableDebugger", 59: "DoInitAction",
    60: "DefineVideoStream", 61: "VideoFrame",
    62: "DefineFontInfo2", 64: "EnableDebugger2",
    65: "ScriptLimits", 66: "SetTabIndex",
    69: "FileAttributes", 70: "PlaceObject3",
    71: "ImportAssets2", 73: "DefineFontAlignZones",
    74: "CSMTextSettings", 75: "DefineFont3",
    76: "SymbolClass", 77: "Metadata", 78: "DefineScalingGrid",
    82: "DoABC", 83: "DefineShape4", 84: "DefineMorphShape2",
    86: "DefineSceneAndFrameLabelData", 87: "DefineBinaryData",
    88: "DefineFontName", 90: "DefineBitsJPEG4",
    91: "DefineFont4",
}


def _local(tag):
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _child(elem, name):
    for c in elem:
        if _local(c.tag) == name:
            return c
    return None


def _children(elem, name):
    return [c for c in elem if _local(c.tag) == name]


def _text(elem):
    if elem is None:
        return None
    if elem.text and elem.text.strip():
        return elem.text.strip()
    for c in elem:  # localized <name><text>..</text></name>
        if c.text and c.text.strip():
            return c.text.strip()
    return None


def build_index(resolved):
    index = {}
    for root in resolved.assets_roots:
        try:
            zf = zipfile.ZipFile(root)
        except (zipfile.BadZipFile, OSError):
            continue
        with zf:
            for info in zf.infolist():
                if info.filename.endswith("/"):
                    continue
                if info.filename not in index:
                    index[info.filename] = (root, info.file_size)
    return index


def read_member(index, name, cap=MEMBER_CAP):
    root, _size = index[name]
    with zipfile.ZipFile(root) as zf:
        return read_member_capped(zf, name, cap)


def parse_descriptor(data):
    """Parse an AIR application.xml. Raises ValueError when
    the document is not in the AIR application namespace."""
    root = ET.fromstring(data)
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag[1:].split("}")[0]
    if "ns.adobe.com/air/application" not in ns:
        raise ValueError(f"namespace {ns!r} is not the AIR "
                         "application namespace")
    initial = _child(root, "initialWindow")
    win = {}
    if initial is not None:
        for key in ("content", "title", "systemChrome",
                    "transparent", "visible", "renderMode"):
            win[key] = _text(_child(initial, key))
    profiles = _text(_child(root, "supportedProfiles"))
    extensions = _child(root, "extensions")
    ext_ids = []
    if extensions is not None:
        ext_ids = [_text(e) for e in
                   _children(extensions, "extensionID")]
    return {
        "id": _text(_child(root, "id")),
        "version": _text(_child(root, "versionNumber")) or
                   _text(_child(root, "versionLabel")),
        "versionNumber": _text(_child(root, "versionNumber")),
        "versionLabel": _text(_child(root, "versionLabel")),
        "filename": _text(_child(root, "filename")),
        "name": _text(_child(root, "name")),
        "initialWindow": win,
        "supportedProfiles": profiles.split() if profiles
                             else [],
        "extension_count": len(ext_ids),
        "extension_ids": ext_ids,
    }


def _decompress_body(sig, data, declared):
    """Return the uncompressed SWF body (after the 8-byte
    header), bounded at SWF_BODY_CAP. Raises ValueError."""
    if sig == b"FWS":
        return data[8:8 + SWF_BODY_CAP]
    if sig == b"CWS":
        dec = zlib.decompressobj()
        out = dec.decompress(data[8:], SWF_BODY_CAP + 1)
        if len(out) > SWF_BODY_CAP:
            raise ValueError("decompressed SWF body exceeds "
                             f"the {SWF_BODY_CAP}-byte cap")
        return out
    if sig == b"ZWS":
        if len(data) < 17:
            raise ValueError("truncated ZWS header")
        props = data[12:17]
        payload = data[17:]
        header = props + struct.pack("<Q", max(declared - 8, 0))
        dec = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
        out = dec.decompress(header + payload, SWF_BODY_CAP + 1)
        if len(out) > SWF_BODY_CAP:
            raise ValueError("decompressed SWF body exceeds "
                             f"the {SWF_BODY_CAP}-byte cap")
        return out
    raise ValueError(f"unknown SWF signature {sig!r}")


def _symbol_pairs(body):
    """(count, [names]) from an ExportAssets / SymbolClass
    tag body: u16 count, then (u16 id, NUL-terminated name)
    pairs. Truncation ends the walk quietly."""
    names = []
    if len(body) < 2:
        return 0, names
    count = struct.unpack_from("<H", body, 0)[0]
    pos = 2
    for _ in range(count):
        if pos + 2 > len(body):
            break
        pos += 2  # character id
        end = body.find(b"\x00", pos)
        if end == -1:
            break
        names.append(body[pos:end].decode("utf-8", "replace"))
        pos = end + 1
    return count, names


def parse_swf(data, label):
    """Structural SWF parse. Returns a report dict; parse
    problems land in its 'error' field, never raise."""
    out = {"file": label, "signature": None, "version": None,
           "declared_length": None, "frame_rate": None,
           "frame_count": None, "tag_census": {},
           "exported_symbols": [], "doabc_count": 0,
           "doabc_bytes": 0,
           "doabc_note": "DoABC (ABC bytecode) tags are counted "
                         "and sized only; bytecode is not "
                         "decoded"}
    if len(data) < 8:
        out["error"] = "file shorter than the 8-byte SWF header"
        return out
    sig = data[:3]
    out["signature"] = sig.decode("ascii", "replace")
    out["version"] = data[3]
    declared = struct.unpack_from("<I", data, 4)[0]
    out["declared_length"] = declared
    if sig not in (b"FWS", b"CWS", b"ZWS"):
        out["error"] = f"signature {sig!r} is not FWS/CWS/ZWS"
        return out
    try:
        body = _decompress_body(sig, data, declared)
    except (ValueError, zlib.error, lzma.LZMAError) as e:
        out["error"] = f"body decompression failed: {e}"
        return out
    if len(body) < 4:
        out["error"] = "body too short for RECT + frame header"
        return out
    nbits = body[0] >> 3
    rect_bytes = (5 + 4 * nbits + 7) // 8
    pos = rect_bytes
    if pos + 4 > len(body):
        out["error"] = "body truncated before frame rate/count"
        return out
    rate_raw, frame_count = struct.unpack_from("<HH", body, pos)
    out["frame_rate"] = rate_raw / 256.0
    out["frame_count"] = frame_count
    pos += 4
    census = {}
    symbols = []
    while pos + 2 <= len(body):
        head = struct.unpack_from("<H", body, pos)[0]
        pos += 2
        # RECORDHEADER: high 10 bits are the tag code, low 6
        # bits the short length (0x3F -> long u32 length).
        code = head >> 6
        length = head & 0x3F
        if length == 0x3F:
            if pos + 4 > len(body):
                out.setdefault("notes", []).append(
                    "tag walk stopped: truncated long length")
                break
            length = struct.unpack_from("<I", body, pos)[0]
            pos += 4
        if pos + length > len(body):
            out.setdefault("notes", []).append(
                f"tag walk stopped: tag {code} declares "
                f"{length} bytes past the end of the body")
            break
        tag_body = body[pos:pos + length]
        name = TAG_NAMES.get(code, f"tag-{code}")
        census[name] = census.get(name, 0) + 1
        if code in (56, 76):
            _count, names = _symbol_pairs(tag_body)
            symbols.extend(names)
        elif code == 82:
            out["doabc_count"] += 1
            out["doabc_bytes"] += length
        pos += length
        if code == 0:
            break
    out["tag_census"] = dict(sorted(census.items()))
    out["exported_symbols"] = symbols[:SYMBOL_SAMPLE_CAP]
    out["exported_symbol_count"] = len(symbols)
    return out


def inspect(target):
    report = {"tool": "nar-air", "version": VERSION,
              "target": os.path.abspath(target),
              "verdict": "absent", "descriptor": {},
              "swf": [], "notes": []}
    notes = report["notes"]
    # Bare .swf target: no container resolution applies.
    if target.lower().endswith(".swf"):
        report["container"] = {"input_kind": "swf",
                               "base": os.path.basename(target),
                               "base_entry": None,
                               "splits_merged": [],
                               "split_skipped": [], "obbs": []}
        try:
            with open(target, "rb") as fh:
                data = fh.read(MEMBER_CAP + 1)
            if len(data) > MEMBER_CAP:
                notes.append("bare SWF exceeds the member read "
                             "cap; header facts only")
                data = data[:MEMBER_CAP]
            parsed = parse_swf(data, os.path.basename(target))
            report["swf"] = [parsed]
            if "error" not in parsed:
                notes.append("bare SWF target: no AIR descriptor "
                             "applies; verdict stays absent "
                             "without one")
        except OSError as e:
            notes.append(f"bare SWF unreadable: {e}")
        return report
    resolved = container_mod.resolve_target(target)
    try:
        report["container"] = resolved.container_block()
        index = build_index(resolved)
        candidates = [n for n in index
                      if n.endswith("application.xml")]
        candidates.sort(key=lambda n: (
            n != "META-INF/AIR/application.xml", n))
        descriptor = None
        desc_path = None
        for name in candidates:
            try:
                data = read_member(index, name)
            except (KeyError, OSError, ValueError,
                    zipfile.BadZipFile) as e:
                notes.append(f"{name}: unreadable ({e})")
                continue
            try:
                descriptor = parse_descriptor(data)
            except (ET.ParseError, ValueError) as e:
                notes.append(f"{name}: not an AIR descriptor "
                             f"({e})")
                continue
            desc_path = name
            break
        if descriptor is None:
            notes.append("no application.xml in the AIR "
                         "application namespace found")
            return report
        descriptor["path"] = desc_path
        report["descriptor"] = descriptor
        report["verdict"] = "present"
        # --- SWFs: the descriptor's content file first ------
        swf_names = [n for n in index
                     if n.lower().endswith(".swf")]
        content = (descriptor.get("initialWindow") or {}).get(
            "content")
        swf_names.sort(key=lambda n: (
            content is None or
            n.rsplit("/", 1)[-1] != content, n))
        for name in swf_names:
            try:
                data = read_member(index, name)
            except (KeyError, OSError, ValueError,
                    zipfile.BadZipFile) as e:
                report["swf"].append(
                    {"file": name, "error": f"unreadable ({e})"})
                continue
            report["swf"].append(parse_swf(data, name))
        if not swf_names:
            notes.append("descriptor found but no .swf member "
                         "ships in the resolved roots")
        return report
    finally:
        resolved.cleanup()


def human(report):
    lines = [f"NAR Adobe AIR deep dive: {report['target']}"]
    if report["verdict"] != "present":
        lines.append("ABSENT: no AIR application descriptor "
                     "found")
    else:
        d = report["descriptor"]
        lines.append(f"PRESENT: {d.get('id')} version "
                     f"{d.get('version')} (file name: "
                     f"{d.get('filename')}) via {d.get('path')}")
        win = d.get("initialWindow") or {}
        lines.append(f"Initial window: content={win.get('content')} "
                     f"title={win.get('title')} "
                     f"chrome={win.get('systemChrome')} "
                     f"transparent={win.get('transparent')}")
        lines.append(f"Profiles: "
                     f"{', '.join(d['supportedProfiles']) or 'none'}"
                     f"; extensions: {d['extension_count']}")
    for s in report["swf"]:
        if "error" in s and s.get("frame_count") is None:
            lines.append(f"SWF {s['file']}: {s['error']}")
        else:
            lines.append(
                f"SWF {s['file']}: {s['signature']} v"
                f"{s['version']}, {s['frame_count']} frames @ "
                f"{s['frame_rate']} fps, tags={s['tag_census']}, "
                f"DoABC x{s['doabc_count']} "
                f"({s['doabc_bytes']} bytes), symbols="
                f"{s['exported_symbols']}")
    for n in report["notes"]:
        lines.append(f"  note: {n}")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR Adobe AIR / SWF deep dive.")
    p.add_argument("target", help="path to an .apk / container "
                                  "or a bare .swf")
    p.add_argument("--json", action="store_true",
                   help="machine-readable JSON output")
    args = p.parse_args(argv)
    if not os.path.isfile(args.target):
        print(f"nar-air: not a file: {args.target}",
              file=sys.stderr)
        return 2
    report = inspect(args.target)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(human(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
