"""Signature + structure based format identification.

Implements the brief section 3.1 input layer: a file is
identified by its magic bytes and its internal structure,
never by its filename alone (the filename is only one piece of
evidence, and a mismatch between name and content is itself
reported). Supported verdicts:

    apk, apks, xapk (incl. APKM), aab, aar, jar, dex, odex,
    vdex, zip, obb, elf, unity-assetbundle, unreal-pak,
    unreal-iostore, godot-pck, unknown

Every verdict carries the evidence that produced it and a
confidence. Structural validation notes (bad entries, CRC
failures, truncation) are reported, not hidden.
"""
import os
import re
import struct
import zipfile

from .hashing import sha256_of

_HEAD_BYTES = 4096
_TAIL_BYTES = 64
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
    elif head.startswith(b"dey\n"):
        verdict = {"format": "odex", "confidence": "high",
                   "evidence": ["ODEX magic (dey)"], "details": {}}
    elif head.startswith(b"vdex"):
        verdict = {"format": "vdex", "confidence": "high",
                   "evidence": ["VDEX magic"], "details": {}}
    elif head.startswith(b"\x7fELF"):
        elf_class = {1: "ELF32", 2: "ELF64"}.get(
            head[4] if len(head) > 4 else 0, "ELF?")
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
        tail = _read_tail(path) if size >= 4 else b""
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
    if verdict.get("extension_mismatch"):
        notes.append(
            f"extension {verdict['extension']} does not match the "
            f"identified format {fmt}")
    return notes
