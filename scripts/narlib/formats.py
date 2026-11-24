"""Signature + structure based format identification.

Implements the brief section 3.1 input layer: a file is
identified by its magic bytes and its internal structure,
never by its filename alone (the filename is only one piece of
evidence, and a mismatch between name and content is itself
reported). Supported verdicts:

    apk, apks, xapk (incl. APKM), aab, aar, jar, dex, odex,
    vdex, oat, cdex, art, zip, obb, elf, unity-assetbundle,
    unreal-pak, unreal-iostore, godot-pck, unknown

Every verdict carries the evidence that produced it and a
confidence. Structural validation notes (bad entries, CRC
failures, truncation) are reported, not hidden.
"""
import os
import re
import struct
import zipfile

from . import cdex as _cdex
from . import oat as _oat
from .hashing import sha256_of

_HEAD_BYTES = 4096
_TAIL_BYTES = 64
# Phase 10 parser resource cap: the whole-file structural
# readers below (vdex/odex/cdex/art in validate_structure,
# cdex in identify) refuse to materialize a file larger
# than this in memory. The oat reader already self-caps
# (_OAT_SCAN_BYTES); the formats named here have no
# internal scan cap, so the guard lives at the read site.
# 512 MiB is far above every real specimen of these
# formats in the project corpora; above it the parse is
# skipped with a named note instead of an unbounded read.
STRUCT_READ_CAP_BYTES = 512 * 1024 * 1024


def _read_whole_capped(path):
    """Read a whole file under STRUCT_READ_CAP_BYTES.
    Returns (bytes, None) or (None, skip-note)."""
    size = os.path.getsize(path)
    if size > STRUCT_READ_CAP_BYTES:
        return None, (f"file size {size} exceeds the parser "
                      f"read cap {STRUCT_READ_CAP_BYTES} bytes; "
                      "whole-file structural parse skipped")
    with open(path, "rb") as fh:
        return fh.read(), None
PAK_MAGIC = 0x5A6F12E1
OBB_NAME_RE = re.compile(r"^(main|patch)\.\d+\..+\.obb$", re.IGNORECASE)
DEX_RE = re.compile(r"^classes\d*\.dex$")
# IoStore TOC header magic (16 ASCII bytes) used by UE5 IoStore.
IOSTORE_MAGIC = b"-==--==--==--==-"


def _read_head(path, n=_HEAD_BYTES):
    with open(path, "rb") as fh:
        return fh.read(n)


def _read_tail(path, n=_TAIL_BYTES):
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        fh.seek(max(0, size - n))
        return fh.read(n)


def _zip_verdict(path, ext):
    """Structural verdict for a ZIP-family file."""
    evidence = ["PK zip signature"]
    details = {}
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        return {"format": "zip", "confidence": "low",
                "evidence": evidence + ["zip central directory unreadable"],
                "details": {"corrupt": True}}
    with zf:
        names = zf.namelist()
        details["entry_count"] = len(names)
        bad = zf.testzip()
        if bad is not None:
            details["crc_failure_entry"] = bad
        name_set = set(names)
        has_manifest = "AndroidManifest.xml" in name_set
        has_dex = any(DEX_RE.match(n) for n in names)
        has_base_manifest = any(
            n.endswith("/manifest/AndroidManifest.xml") for n in names)
        has_proto_buf = any(n.endswith(".pb") for n in names)
        contained_apks = [n for n in names if n.lower().endswith(".apk")]
        details["contained_apks"] = contained_apks
        if has_manifest and has_dex:
            return {"format": "apk", "confidence": "high",
                    "evidence": evidence + ["AndroidManifest.xml and DEX"
                                            " entries present"],
                    "details": details}
        if has_base_manifest and has_proto_buf:
            return {"format": "aab", "confidence": "high",
                    "evidence": evidence + ["module manifest and protobuf"
                                            " resources present"],
                    "details": details}
        if "manifest.json" in name_set and contained_apks:
            return {"format": "xapk", "confidence": "high",
                    "evidence": evidence + ["container manifest.json and"
                                            " contained APKs"],
                    "details": details}
        if contained_apks and len(contained_apks) == len(
                [n for n in names if not n.endswith("/")]):
            return {"format": "apks", "confidence": "medium",
                    "evidence": evidence + ["archive of APKs only"],
                    "details": details}
        if contained_apks:
            return {"format": "apks", "confidence": "medium",
                    "evidence": evidence + ["contains APK entries"],
                    "details": details}
        if has_manifest and any(n.endswith("classes.jar")
                                for n in names):
            return {"format": "aar", "confidence": "high",
                    "evidence": evidence + ["library manifest and"
                                            " classes.jar"],
                    "details": details}
        if "META-INF/MANIFEST.MF" in name_set and not has_manifest:
            return {"format": "jar", "confidence": "medium",
                    "evidence": evidence + ["META-INF/MANIFEST.MF, no"
                                            " Android manifest"],
                    "details": details}
        if OBB_NAME_RE.match(os.path.basename(path)):
            return {"format": "obb", "confidence": "medium",
                    "evidence": evidence + ["OBB filename pattern; no"
                                            " APK structure inside"],
                    "details": details}
        return {"format": "zip", "confidence": "medium",
                "evidence": evidence + ["no Android structure found"],
                "details": details}


_OAT_SCAN_BYTES = 16 * 1024 * 1024


def _oat_verdict(path, size):
    """OAT verdict for an ELF file, or None when the file
    carries no OatHeader. An ART OAT file is an ELF whose
    .rodata holds the header; on Android 8.0+ the same bytes
    are what a file named *.odex under oat/<abi>/ contains,
    so the .odex extension is an expected name for this
    format. The scan is bounded: the header of a real OAT
    file sits in its first megabytes."""
    with open(path, "rb") as fh:
        blob = fh.read(min(size, _OAT_SCAN_BYTES))
    try:
        info = _oat.parse_oat(blob, os.path.basename(path))
    except _oat.OatError:
        return None
    evidence = ["ELF magic",
                f"OatHeader version {info['oat_version']} at "
                f"offset {info['oat_header_offset']}"]
    details = {
        "oat_version": info["oat_version"],
        "oat_header_offset": info["oat_header_offset"],
        "instruction_set": info["instruction_set_name"],
        "dex_file_count": info["dex_file_count"],
        "key_value_store": info["key_value_store"],
        "dex_locations": info["dex_locations"],
    }
    if size > _OAT_SCAN_BYTES:
        details["oat_scan_truncated"] = True
    return {"format": "oat", "confidence": "high",
            "evidence": evidence, "details": details}


def identify(path):
    """Identify one file. Returns a verdict dict:

    {format, confidence, evidence[], details{}, sha256,
     size_bytes, extension, extension_mismatch}
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"not a file: {path}")
    size = os.path.getsize(path)
    ext = os.path.splitext(path)[1].lower()
    head = _read_head(path, min(_HEAD_BYTES, size)) if size else b""
    verdict = None

    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        verdict = _zip_verdict(path, ext)
    elif head.startswith(b"dex\n"):
        version = head[4:7].decode("ascii", "replace")
        verdict = {"format": "dex", "confidence": "high",
                   "evidence": [f"DEX magic, format version {version}"],
                   "details": {"dex_version": version}}
    elif head.startswith(b"cdex"):
        version = head[4:7].decode("ascii", "replace")
        details = {"cdex_version": version}
        evidence = [f"CDEX magic, format version {version}"]
        blob, skip = _read_whole_capped(path)
        if skip:
            details["cdex_error"] = skip
        else:
            try:
                details["cdex_header"] = _cdex.parse_cdex(
                    blob, os.path.basename(path))
                evidence.append("CDEX header + section table "
                                "parsed (payload not decoded)")
            except _cdex.CdexError as e:
                details["cdex_error"] = str(e)
        verdict = {"format": "cdex", "confidence": "high",
                   "evidence": evidence,
                   "details": details}
    elif head.startswith(b"dey\n"):
        version = head[4:7].decode("ascii", "replace")
        verdict = {"format": "odex", "confidence": "high",
                   "evidence": [f"ODEX magic (dey), version {version}"],
                   "details": {"odex_version": version}}
    elif head.startswith(b"vdex"):
        version = head[4:7].decode("ascii", "replace")
        details = {"vdex_version": version}
        if version == "006" and len(head) >= 24:
            (details["number_of_dex_files"], details["dex_size"],
             details["verifier_deps_size"],
             details["quickening_info_size"]) = \
                struct.unpack_from("<IIII", head, 8)
        verdict = {"format": "vdex", "confidence": "high",
                   "evidence": [f"VDEX magic, version {version}"],
                   "details": details}
    elif head.startswith(b"art\n"):
        version = head[4:7].decode("ascii", "replace")
        verdict = {"format": "art", "confidence": "high",
                   "evidence": [f"ART image magic, version {version}"],
                   "details": {"art_version": version}}
    elif head.startswith(b"\x7fELF"):
        elf_class = {1: "ELF32", 2: "ELF64"}.get(
            head[4] if len(head) > 4 else 0, "ELF?")
        oat_info = _oat_verdict(path, size)
        if oat_info is not None:
            verdict = oat_info
            verdict["details"]["elf_class"] = elf_class
        else:
            verdict = {"format": "elf", "confidence": "high",
                       "evidence": [f"ELF magic, {elf_class}"],
                       "details": {"elf_class": elf_class}}
    elif head.startswith(b"GDPC"):
        verdict = {"format": "godot-pck", "confidence": "high",
                   "evidence": ["GDPC pack magic"], "details": {}}
    elif head.startswith(b"UnityFS") or head.startswith(b"UnityWeb") \
            or head.startswith(b"UnityRaw"):
        verdict = {"format": "unity-assetbundle", "confidence": "high",
                   "evidence": ["UnityFS bundle signature"],
                   "details": {}}
    elif head.startswith(IOSTORE_MAGIC):
        verdict = {"format": "unreal-iostore", "confidence": "high",
                   "evidence": ["IoStore TOC header magic"],
                   "details": {}}
    else:
        # Unreal pak: the magic lives in the footer, not the head.
        # The footer is version-sized: v10/v11 footers carry a
        # compression-method table after the magic and run to
        # ~204+ bytes, so a 64-byte tail window misses them
        # (measured on the synthetic v11 fixture in Phase 11:
        # magic 204 bytes from EOF). Scan a bounded 4 KiB tail.
        tail = _read_tail(path, 4096) if size >= 4 else b""
        found = False
        for off in range(0, max(0, len(tail) - 4)):
            if struct.unpack_from("<I", tail, off)[0] == PAK_MAGIC:
                verdict = {"format": "unreal-pak", "confidence": "high",
                           "evidence": ["pak footer magic found in tail"],
                           "details": {}}
                found = True
                break
        if not found:
            if ext == ".utoc":
                verdict = {"format": "unreal-iostore",
                           "confidence": "low",
                           "evidence": [".utoc extension only; header"
                                        " magic not confirmed"],
                           "details": {}}
            elif OBB_NAME_RE.match(os.path.basename(path)):
                verdict = {"format": "obb", "confidence": "low",
                           "evidence": ["OBB filename pattern; content"
                                        " is not a readable zip"],
                           "details": {}}
            else:
                verdict = {"format": "unknown", "confidence": "high",
                           "evidence": ["no known signature matched"],
                           "details": {}}

    expected_ext = {
        "apk": {".apk"}, "aab": {".aab"}, "aar": {".aar"},
        "jar": {".jar"}, "dex": {".dex"}, "odex": {".odex"},
        "vdex": {".vdex"}, "obb": {".obb"}, "elf": {".so"},
        "oat": {".oat", ".odex"}, "cdex": {".cdex"},
        "art": {".art"},
        "godot-pck": {".pck"}, "unreal-pak": {".pak"},
        "unreal-iostore": {".utoc", ".ucas"},
        "unity-assetbundle": {".bundle", ".unity3d", ""},
        "xapk": {".xapk", ".apkm"}, "apks": {".apks", ".zip"},
        "zip": {".zip"},
    }
    mismatch = False
    if verdict["format"] in expected_ext and ext:
        mismatch = ext not in expected_ext[verdict["format"]]
    verdict.update({
        "sha256": sha256_of(path),
        "size_bytes": size,
        "extension": ext,
        "extension_mismatch": mismatch,
    })
    return verdict


def validate_structure(path, verdict=None):
    """Cheap structural validation notes for an identified file."""
    verdict = verdict or identify(path)
    notes = []
    fmt = verdict["format"]
    if fmt in ("apk", "apks", "xapk", "aab", "aar", "jar", "zip", "obb"):
        try:
            with zipfile.ZipFile(path) as zf:
                bad = zf.testzip()
                if bad is not None:
                    notes.append(f"CRC failure in entry: {bad}")
                if not zf.namelist():
                    notes.append("zip has zero entries")
        except zipfile.BadZipFile:
            notes.append("zip central directory is unreadable")
    elif fmt == "dex":
        with open(path, "rb") as fh:
            header = fh.read(112)
        if len(header) < 112:
            notes.append("DEX header truncated (<112 bytes)")
        else:
            file_size = struct.unpack_from("<I", header, 32)[0]
            if file_size != os.path.getsize(path):
                notes.append(
                    f"DEX header file_size {file_size} != actual "
                    f"{os.path.getsize(path)}")
    elif fmt == "elf":
        with open(path, "rb") as fh:
            header = fh.read(64)
        if len(header) < 16:
            notes.append("ELF header truncated")
    elif fmt == "oat":
        with open(path, "rb") as fh:
            blob = fh.read(min(os.path.getsize(path),
                               _OAT_SCAN_BYTES))
        try:
            info = _oat.parse_oat(blob)
            if info["dex_file_count"] > 1024:
                notes.append(
                    f"OAT dex_file_count {info['dex_file_count']} "
                    "is implausibly large")
        except _oat.OatError as e:
            notes.append(f"OAT header unreadable: {e}")
    elif fmt == "vdex":
        blob, skip = _read_whole_capped(path)
        if skip:
            notes.append(f"VDEX: {skip}")
        else:
            try:
                info = _oat.parse_vdex(blob)
                if info["dex_size"] is not None \
                        and info["dex_size"] > len(blob):
                    notes.append(
                        f"VDEX dex_size {info['dex_size']} exceeds "
                        f"file size {len(blob)}")
                if info["number_of_dex_files"] is not None \
                        and len(info["embedded"]) \
                        != info["number_of_dex_files"]:
                    notes.append(
                        f"VDEX header declares "
                        f"{info['number_of_dex_files']} dex file(s) "
                        f"but {len(info['embedded'])} embedded "
                        "DEX/CDEX header(s) were found")
                if not info["embedded"]:
                    notes.append("VDEX carries no embedded DEX/CDEX")
            except _oat.OatError as e:
                notes.append(f"VDEX header unreadable: {e}")
    elif fmt == "odex":
        blob, skip = _read_whole_capped(path)
        if skip:
            notes.append(f"ODEX: {skip}")
        else:
            try:
                info = _oat.parse_odex_dalvik(blob)
                if not info["dex"].startswith(b"dex\n"):
                    notes.append("ODEX embedded payload does not "
                                 "start with DEX magic")
            except _oat.OatError as e:
                notes.append(f"ODEX header unreadable: {e}")
    elif fmt == "cdex":
        if os.path.getsize(path) < 112:
            notes.append("CDEX file truncated (<112 bytes)")
        else:
            blob, skip = _read_whole_capped(path)
            if skip:
                notes.append(f"CDEX: {skip}")
            else:
                try:
                    _cdex.parse_cdex(blob, os.path.basename(path))
                except _cdex.CdexError as e:
                    notes.append(f"CDEX header unreadable: {e}")
    elif fmt == "art":
        blob, skip = _read_whole_capped(path)
        if skip:
            notes.append(f"ART: {skip}")
        else:
            try:
                info = _oat.parse_art_image(blob)
                # image_size is the size of the image data, not
                # of the file: a real boot image's file is larger
                # (verified on a pulled API 26 boot image, where
                # image_size < file size). Only an image_size
                # beyond the file is impossible.
                if info["image_size"] \
                        and info["image_size"] > len(blob):
                    notes.append(
                        f"ART image_size {info['image_size']} "
                        f"exceeds file size {len(blob)}")
            except _oat.OatError as e:
                notes.append(f"ART image header unreadable: {e}")
    if verdict.get("extension_mismatch"):
        notes.append(
            f"extension {verdict['extension']} does not match the "
            f"identified format {fmt}")
    return notes


def archive_structure_summary(path, fmt=None):
    """Structural summary for AAR / JAR archives (Evolution
    Phase 2): entry inventory facts — class entries, manifest
    presence, and for AAR the classes.jar / R.txt / res/ /
    jni/ layout. Returns None for other formats or when the
    archive cannot be opened. Facts only: a missing part is
    reported as absent, never inferred."""
    fmt = fmt or identify(path)["format"]
    if fmt not in ("aar", "jar"):
        return None
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            summary = {
                "format": fmt,
                "entry_count": len(names),
                "class_entries": sum(
                    1 for n in names if n.endswith(".class")),
                "has_manifest_mf": "META-INF/MANIFEST.MF" in names,
            }
            if fmt == "aar":
                summary["has_android_manifest"] = \
                    "AndroidManifest.xml" in names
                summary["has_classes_jar"] = "classes.jar" in names
                summary["classes_jar_class_count"] = None
                if summary["has_classes_jar"]:
                    try:
                        import io
                        inner = zipfile.ZipFile(
                            io.BytesIO(zf.read("classes.jar")))
                        summary["classes_jar_class_count"] = sum(
                            1 for n in inner.namelist()
                            if n.endswith(".class"))
                    except zipfile.BadZipFile:
                        summary["classes_jar_class_count"] = None
                summary["has_r_txt"] = "R.txt" in names
                summary["res_entries"] = sum(
                    1 for n in names if n.startswith("res/"))
                summary["jni_libraries"] = sorted(
                    n for n in names
                    if n.startswith("jni/") and n.endswith(".so"))
            return summary
    except (zipfile.BadZipFile, OSError):
        return None
