#!/usr/bin/env python3
"""nar-unity.py: Unity deep dive (brief section 5).

For a Unity APK:

- scripting backend verdict (IL2CPP vs Mono) from layout +
  the nar-il2cpp metadata analysis when IL2CPP is present,
- Unity editor version evidence: the version string embedded
  in globalgamemanagers / the UnityFS container header,
- asset inventory: UnityFS bundles (magic-verified), the
  bin/Data layout, Addressables catalog presence,
- first-party UnityFS header inspection (stdlib only):
  the bundle header, the block/directory info and — where
  the compression is one the stdlib can decode (none /
  LZMA) — the first serialized file's header facts. LZ4 /
  LZ4HC blocks are named as the boundary they are, never
  decoded by a dependency this repo does not ship,
- optional UnityPy pass: when the optional UnityPy module is
  importable in the running interpreter, one bundle is loaded
  and its object-type census reported; when it is not, that
  is stated plainly (never faked).

Usage:
    python3 nar-unity.py app.apk [--json] [--work DIR]

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import base64
import json
import lzma
import os
import re
import struct
import subprocess
import sys
import zipfile
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib.hashing import sha256_of  # noqa: E402
from narlib.safearchive import (  # noqa: E402
    MEMBER_READ_CAP_BYTES, read_member_capped)

HERE = os.path.dirname(os.path.abspath(__file__))
UNITY_VERSION_RE = re.compile(rb"(20\d\d\.\d+\.\d+[abfp]\d+)")
MAX_BUNDLE_SCAN = 200

#: No archive member this tool materializes in memory (an
#: Addressables catalog, an inspected bundle, the census
#: bundle) may exceed the shared member read cap: a hostile
#: oversized member was previously decompressed whole by a
#: bare fh.read() / zf.read() with no byte cap at all
#: (certification audit A2-02). Over-cap or unreadable
#: members degrade to a recorded error / skipped census,
#: never a whole-blob read and never a raw decompression
#: traceback.
MEMBER_CAP_BYTES = MEMBER_READ_CAP_BYTES


def parse_addressables_catalog(raw):
    """Parse an Addressables content catalog (catalog.json)
    into an inventory: locations (internal ids), providers,
    resource types, and the entry table.

    The entry table is a base64 blob: an int32 entry count
    followed by count x 28-byte entries of 7 int32 fields.
    Field roles are claimed only where the values validate
    against the catalog's own tables (field 0 indexes the
    internal ids, field 1 the provider ids, field 6 the
    resource types — each verified by range on real
    catalogs); the remaining fields are reported by role
    only in aggregate (dependency / data offsets, key
    index) and never resolved beyond the evidence.
    """
    try:
        doc = json.loads(raw.decode("utf-8", "replace"))
    except ValueError as e:
        return {"parsed": False, "error": f"not JSON: {e}"}
    if not isinstance(doc, dict) or \
            not isinstance(doc.get("m_InternalIds"), list):
        return {"parsed": False,
                "error": "no m_InternalIds list: not an "
                         "Addressables content catalog"}
    internal_ids = doc["m_InternalIds"]
    types = [t.get("m_ClassName")
             for t in doc.get("m_resourceTypes") or []
             if isinstance(t, dict) and t.get("m_ClassName")]
    providers = []
    for key in ("m_InstanceProviderData", "m_SceneProviderData"):
        pd = doc.get(key)
        if isinstance(pd, dict) and pd.get("m_Id"):
            providers.append(pd["m_Id"])
    resource_providers = [
        p["m_Id"] for p in doc.get("m_ResourceProviderData") or []
        if isinstance(p, dict) and p.get("m_Id")]
    provider_ids = [p for p in doc.get("m_ProviderIds") or []
                    if isinstance(p, str)]
    out = {
        "parsed": True,
        "locator_id": doc.get("m_LocatorId"),
        "build_result_hash": doc.get("m_BuildResultHash"),
        "location_count": len(internal_ids),
        "locations_sample": internal_ids[:25],
        "provider_ids": provider_ids,
        "resource_providers": resource_providers,
        "lifecycle_providers": providers,
        "resource_type_count": len(types),
        "resource_types": types[:200],
    }
    blob = None
    if isinstance(doc.get("m_EntryDataString"), str):
        try:
            blob = base64.b64decode(doc["m_EntryDataString"])
        except ValueError:
            blob = None
    if blob is None or len(blob) < 4:
        out["entries"] = {"decoded": False,
                          "note": "no decodable entry-data blob"}
        return out
    count = struct.unpack_from("<i", blob, 0)[0]
    if count < 0 or 4 + count * 28 != len(blob):
        out["entries"] = {
            "decoded": False, "blob_bytes": len(blob),
            "note": "entry blob does not match the validated "
                    "layout (int32 count + count x 28-byte "
                    "entries); reported by size only"}
        return out
    f0, f1, f6 = [], [], []
    for i in range(count):
        vals = struct.unpack_from("<7i", blob, 4 + i * 28)
        f0.append(vals[0])
        f1.append(vals[1])
        f6.append(vals[6])
    validated = []
    by_type = by_provider = None
    if f0 and max(f0) < len(internal_ids) and min(f0) >= 0:
        validated.append("internal_id_index")
    if f6 and types and max(f6) < len(types) and min(f6) >= 0:
        validated.append("resource_type_index")
        by_type = [{"type": types[idx], "entries": n}
                   for idx, n in Counter(f6).most_common(25)]
    if f1 and provider_ids and \
            max(f1) < len(provider_ids) and min(f1) >= 0:
        validated.append("provider_index")
        by_provider = [{"provider": provider_ids[idx],
                        "entries": n}
                       for idx, n in Counter(f1).most_common(10)]
    out["entries"] = {
        "decoded": True, "count": count,
        "layout": "int32 count + 28-byte entries (7 x int32)",
        "fields_validated": validated,
        "by_resource_type": by_type,
        "by_provider": by_provider,
    }
    return out


def run_json_tool(script, args, timeout=1800):
    cmd = [sys.executable, os.path.join(HERE, script)] + args + ["--json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
        return json.loads(proc.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def unitypy_census(data):
    """Object-type census of one bundle via UnityPy.

    Returns (status, census): status is "ok",
    "unavailable" (UnityPy not importable) or
    "load-failed" (UnityPy present but the bundle did
    not load). The pre-audit form returned None for all
    three, so the report claimed "UnityPy is not
    importable" even when it was present and the bundle
    was corrupt (stability audit B-13)."""
    try:
        import UnityPy  # optional dependency
    except ImportError:
        return "unavailable", None
    try:
        env = UnityPy.load(data)
        census = {}
        for obj in env.objects:
            census[obj.type.name] = census.get(obj.type.name, 0) + 1
        return "ok", census
    except Exception:
        return "load-failed", None


class BundleError(Exception):
    """A bundle / serialized file is malformed or hits a
    named format boundary (message says which)."""


# UnityFS block compression types (low 6 bits of the
# archive flags / per-block flags), per the public
# ArchiveFlags layout.
_BUNDLE_COMPRESSION = {0: "none", 1: "lzma", 2: "lz4",
                       3: "lz4hc", 4: "lzham"}
_BUNDLE_FLAG_COMBINED = 0x40        # blocks+directory info combined
_BUNDLE_FLAG_AT_END = 0x80          # blocks info at the end
_NODE_FLAG_SERIALIZED_FILE = 0x04
BUNDLE_INSPECT_CAP = 5
_BUNDLE_DETAIL_CAP = 50
_LZMA_OUTPUT_CEILING = 256 * 1024 * 1024


def _read_cstring(data, pos, what):
    end = data.find(b"\x00", pos)
    if end < 0:
        raise BundleError(f"unterminated {what} string")
    try:
        text = data[pos:end].decode("utf-8")
    except UnicodeDecodeError as e:
        raise BundleError(f"{what} string does not decode: {e}")
    return text, end + 1


def _bundle_decompress(raw, comp_type, expected_size, what):
    """Decompress one UnityFS block with the stdlib only.

    Compression 0 is stored data; 1 is Unity's LZMA1
    stream (5-byte properties header + raw LZMA1, decoded
    with lzma.FORMAT_RAW). LZ4 / LZ4HC / LZHAM have no
    stdlib decoder: they raise a BundleError naming the
    boundary instead of guessing.
    """
    kind = _BUNDLE_COMPRESSION.get(comp_type)
    if kind is None:
        raise BundleError(
            f"{what}: unknown compression type {comp_type}")
    if kind == "none":
        out = bytes(raw)
    elif kind == "lzma":
        if len(raw) < 5:
            raise BundleError(f"{what}: LZMA block too small "
                              "for its properties header")
        if expected_size > _LZMA_OUTPUT_CEILING:
            # The output bound was the attacker-declared
            # expected size itself (a u32), so a crafted
            # block could direct a multi-GiB allocation
            # (stability audit B-21). UnityFS blocks are
            # small by design; refuse absurd promises.
            raise BundleError(
                f"{what}: LZMA block promises "
                f"{expected_size} decompressed bytes, over "
                f"the {_LZMA_OUTPUT_CEILING}-byte ceiling")
        props = raw[0]
        dict_size = struct.unpack_from("<I", raw, 1)[0]
        filters = [{"id": lzma.FILTER_LZMA1,
                    "dict_size": dict_size or (1 << 23),
                    "lc": props % 9,
                    "lp": (props // 9) % 5,
                    "pb": (props // 9) // 5}]
        try:
            dec = lzma.LZMADecompressor(
                format=lzma.FORMAT_RAW, filters=filters)
            out = dec.decompress(bytes(raw[5:]),
                                 expected_size + 1)
        except lzma.LZMAError as e:
            raise BundleError(
                f"{what}: LZMA decompression failed: {e}")
    else:
        raise BundleError(
            f"{what}: compression is {kind}, which has no "
            "decoder in the Python standard library; the "
            "block is inventoried, not decoded")
    if len(out) != expected_size:
        raise BundleError(
            f"{what}: decompressed to {len(out)} bytes, "
            f"the header promises {expected_size}")
    return out


def parse_serialized_file_header(data, name=""):
    """Header facts of one Unity serialized file.

    The header is big-endian up to and including the
    endianness byte: metadata size, file size, format
    version, data offset (all u32), then — format 9+ —
    one endianness byte (0 = little, 1 = big) and three
    reserved bytes. Format 22+ zeroes the classic size
    fields and repeats them after the reserved bytes as
    u32 metadata size + i64 file size + i64 data offset
    + one further i64 whose role the public readers do
    not document (reported as stored). Raises
    BundleError with a named reason on malformed data.
    Object tables and the type tree are NOT parsed:
    that is the boundary of this header-level reader.
    """
    if len(data) < 16:
        raise BundleError(
            f"serialized file too small for a header "
            f"({len(data)} bytes)")
    metadata_size, file_size, version, data_offset = \
        struct.unpack_from(">IIII", data, 0)
    if version == 0:
        raise BundleError(
            "serialized-file format version is 0: not a "
            "serialized file")
    if version > 999:
        raise BundleError(
            f"implausible serialized-file format version "
            f"{version}")
    out = {"format": "serialized-file", "name": name,
           "format_version": version,
           "metadata_size": metadata_size,
           "file_size": file_size,
           "data_offset": data_offset,
           "endianness": None, "reserved": None,
           "header_size": 16}
    notes = []
    if version >= 9:
        if len(data) < 20:
            raise BundleError(
                "serialized file truncated before the "
                "endianness byte")
        endian_byte = data[16]
        if endian_byte not in (0, 1):
            raise BundleError(
                f"invalid serialized-file endianness byte "
                f"{endian_byte} (expected 0 or 1)")
        out["endianness"] = "little" if endian_byte == 0 \
            else "big"
        out["reserved"] = list(data[17:20])
        out["header_size"] = 20
    else:
        notes.append(
            "format < 9 stores the endianness byte at the "
            "tail of the metadata, not in the header; it "
            "is not read at header level")
    if version >= 22:
        if len(data) < 48:
            raise BundleError(
                "serialized file truncated before the "
                "format-22 extended header completes")
        metadata_size, file_size, data_offset, trailing = \
            struct.unpack_from(">Iqqq", data, 20)
        if metadata_size < 0 or file_size < 0 \
                or data_offset < 0:
            raise BundleError(
                "format-22 extended header carries a "
                "negative size/offset field")
        out.update({
            "metadata_size": metadata_size,
            "file_size": file_size,
            "data_offset": data_offset,
            "header_size": 48,
            "extended_trailing_i64": trailing,
        })
    if version > 22:
        notes.append(
            f"format version {version} is newer than 22, "
            "the newest layout this reader documents; "
            "fields above follow the format-22 layout")
    out["file_size_matches_data_length"] = \
        out["file_size"] == len(data)
    if notes:
        out["notes"] = notes
    return out


def _parse_blocks_info(raw, record):
    """Parse decompressed blocks info into the record:
    block table + directory (node) table. Raises
    BundleError on structural nonsense."""
    if len(raw) < 20:
        raise BundleError("blocks info too small for its "
                          "hash + block count")
    pos = 16  # uncompressed-data hash: located, not verified
    block_count = struct.unpack_from(">i", raw, pos)[0]
    pos += 4
    if block_count < 0 or block_count > 1_000_000:
        raise BundleError(
            f"implausible block count {block_count}")
    blocks = []
    for _ in range(block_count):
        if pos + 10 > len(raw):
            raise BundleError("blocks info truncated in "
                              "the block table")
        usize, csize, bflags = struct.unpack_from(
            ">IIH", raw, pos)
        pos += 10
        blocks.append({
            "uncompressed_size": usize,
            "compressed_size": csize,
            "flags": bflags,
            "compression": _BUNDLE_COMPRESSION.get(
                bflags & 0x3F,
                f"unknown ({bflags & 0x3F})"),
        })
    if pos + 4 > len(raw):
        raise BundleError("blocks info truncated before "
                          "the node count")
    node_count = struct.unpack_from(">i", raw, pos)[0]
    pos += 4
    if node_count < 0 or node_count > 1_000_000:
        raise BundleError(
            f"implausible node count {node_count}")
    nodes = []
    for _ in range(node_count):
        if pos + 20 > len(raw):
            raise BundleError("blocks info truncated in "
                              "the node table")
        offset, size, nflags = struct.unpack_from(
            ">QQI", raw, pos)
        pos += 20
        path, pos = _read_cstring(raw, pos, "node path")
        nodes.append({
            "path": path, "offset": offset, "size": size,
            "flags": nflags,
            "is_serialized_file": bool(
                nflags & _NODE_FLAG_SERIALIZED_FILE),
        })
    record["blocks"] = blocks[:_BUNDLE_DETAIL_CAP]
    record["blocks_counts"] = {
        "total": len(blocks), "processed": len(blocks),
        "skipped": 0, "failed": 0}
    record["blocks_detail_truncated"] = \
        len(blocks) > _BUNDLE_DETAIL_CAP
    record["nodes"] = nodes[:_BUNDLE_DETAIL_CAP]
    record["nodes_counts"] = {
        "total": len(nodes), "processed": len(nodes),
        "skipped": 0, "failed": 0}
    record["nodes_detail_truncated"] = \
        len(nodes) > _BUNDLE_DETAIL_CAP
    return blocks, nodes


def _first_serialized_file(data, record, blocks, nodes,
                           stream_start):
    """Locate the first serialized-file node in the
    decompressed block stream and parse its header.
    Fills record["serialized_file"]; boundaries (LZ4
    blocks, out-of-range nodes) are recorded, not raised.
    """
    node = next((n for n in nodes
                 if n["is_serialized_file"]), None)
    if node is None:
        record["serialized_file"] = None
        record.setdefault("limitations", []).append(
            "no directory node is flagged as a serialized "
            "file; no serialized-file header is reported")
        return
    want_end = node["offset"] + node["size"]
    stream = bytearray()
    cursor = stream_start  # compressed offset in the bundle
    covered = 0
    try:
        for block in blocks:
            if covered >= want_end:
                break
            raw = data[cursor:cursor + block["compressed_size"]]
            if len(raw) < block["compressed_size"]:
                raise BundleError(
                    "bundle truncated inside a data block")
            cursor += block["compressed_size"]
            stream += _bundle_decompress(
                raw, block["flags"] & 0x3F,
                block["uncompressed_size"], "data block")
            covered += block["uncompressed_size"]
    except BundleError as e:
        record["serialized_file"] = {
            "node_path": node["path"],
            "status": "unavailable", "reason": str(e)}
        record.setdefault("limitations", []).append(
            f"serialized file {node['path']!r}: {e}")
        return
    if want_end > len(stream):
        record["serialized_file"] = {
            "node_path": node["path"],
            "status": "unavailable",
            "reason": "node range runs past the "
                      "decompressed block stream"}
        return
    blob = bytes(stream[node["offset"]:want_end])
    try:
        header = parse_serialized_file_header(
            blob, node["path"])
    except BundleError as e:
        record["serialized_file"] = {
            "node_path": node["path"],
            "status": "unavailable", "reason": str(e)}
        return
    header["node_path"] = node["path"]
    header["status"] = "parsed"
    record["serialized_file"] = header


def parse_unityfs_bundle(data, name=""):
    """First-party UnityFS bundle header inspection.

    Parses the bundle header (signature, format version,
    player/engine version strings, size fields, archive
    flags), then the block/directory info when its
    compression is stdlib-decodable, then the first
    serialized file's header from the block stream.
    Raises BundleError with a named reason on malformed
    data; format boundaries (LZ4 blocks, UnityWeb /
    UnityRaw layouts) are recorded in the record's
    limitations instead. Full object parsing is out of
    scope for this header-level reader.
    """
    record = {"entry": name, "format": "unityfs-bundle",
              "parsed": False}
    signature, pos = _read_cstring(data, 0, "bundle signature")
    record["signature"] = signature
    if signature == "UnityArchive":
        raise BundleError("UnityArchive bundles use a "
                          "different container layout; only "
                          "the signature is reported")
    if signature not in ("UnityFS", "UnityWeb", "UnityRaw"):
        raise BundleError(
            f"not a Unity bundle (signature {signature!r})")
    if pos + 4 > len(data):
        raise BundleError("bundle truncated before the "
                          "format version")
    version = struct.unpack_from(">I", data, pos)[0]
    pos += 4
    player, pos = _read_cstring(data, pos,
                                "player version string")
    engine, pos = _read_cstring(data, pos,
                                "engine version string")
    record.update({
        "bundle_format_version": version,
        "unity_version_player": player,
        "unity_version_engine": engine,
    })
    if signature != "UnityFS":
        record["parsed"] = True
        record["limitations"] = [
            f"{signature} bundles predate the UnityFS "
            "layout; only the header strings above are "
            "parsed by this reader"]
        return record
    if pos + 20 > len(data):
        raise BundleError("bundle truncated before the "
                          "UnityFS size fields")
    size, csize, usize, flags = struct.unpack_from(
        ">QIII", data, pos)
    pos += 20
    comp_type = flags & 0x3F
    record.update({
        "parsed": True,
        "bundle_size_field": size,
        "bundle_size_matches_data_length": size == len(data),
        "blocks_info": {
            "compressed_size": csize,
            "uncompressed_size": usize,
            "flags": flags,
            "compression_type": comp_type,
            "compression": _BUNDLE_COMPRESSION.get(
                comp_type, f"unknown ({comp_type})"),
            "location": ("end of bundle"
                         if flags & _BUNDLE_FLAG_AT_END
                         else "after the bundle header"),
        },
    })
    if version >= 7:
        pos = (pos + 15) & ~15  # header aligns to 16 bytes
    if flags & _BUNDLE_FLAG_AT_END:
        info_start = len(data) - csize
        if info_start < pos:
            raise BundleError("blocks info at the end of "
                              "the bundle overlaps the header")
    else:
        info_start = pos
    raw_info = data[info_start:info_start + csize]
    if len(raw_info) < csize:
        raise BundleError("bundle truncated inside the "
                          "blocks info")
    try:
        info = _bundle_decompress(raw_info, comp_type, usize,
                                  "blocks info")
    except BundleError as e:
        record["limitations"] = [str(e)]
        return record
    blocks, nodes = _parse_blocks_info(info, record)
    # The data-block stream starts right after the header
    # when the blocks info sits at the end of the bundle,
    # and right after the blocks info when it is combined
    # with the header.
    stream_start = pos if flags & _BUNDLE_FLAG_AT_END \
        else info_start + csize
    if flags & 0x200:
        # BlockInfoNeedPaddingAtStart (current flag
        # generation): the data stream starts on the next
        # 16-byte boundary after the blocks info.
        stream_start = (stream_start + 15) & ~15
    _first_serialized_file(data, record, blocks, nodes,
                           stream_start)
    return record


def analyze(target, work_dir=None):
    report = {"tool": "nar-unity", "version": "3.0.3",
              "target": os.path.abspath(target),
              "target_sha256": sha256_of(target)}
    triage = run_json_tool("nar-triage.py", [target]) or {}
    hints = {h["engine"] for h in triage.get("engine_hints") or []}
    versions = triage.get("engine_versions") or {}
    backend = None
    if "Unity (IL2CPP)" in hints:
        backend = "IL2CPP"
    elif "Unity (Mono)" in hints:
        backend = "Mono"
    bundles, version_strings = [], []
    addressables = False
    catalog = None
    data_files = 0
    with zipfile.ZipFile(target) as zf:
        names = zf.namelist()
        # The catalog is read in its own pass: the bundle walk
        # below stops early at the bundle scan cap and could
        # otherwise never reach a catalog listed late in the
        # archive.
        for name in names:
            if name.endswith("catalog.json") and \
                    ("/aa/" in name or
                     name.startswith("assets/aa/")):
                try:
                    raw_catalog = read_member_capped(
                        zf, name, MEMBER_CAP_BYTES)
                except ValueError:
                    # Over the member read cap, or unreadable /
                    # corrupt: this member is never materialized
                    # whole; keep looking for another catalog
                    # (the pre-cap search skipped over-size
                    # catalogs the same way).
                    continue
                catalog = parse_addressables_catalog(raw_catalog)
                catalog["path"] = name
                break
        bundle_total = 0
        for name in names:
            if name.startswith("assets/bin/Data/"):
                data_files += 1
            if name.startswith("assets/aa/") or \
                    name.endswith("catalog.json"):
                addressables = True
            if name in ("assets/bin/Data/globalgamemanagers",
                        "assets/bin/Data/data.unity3d") or \
                    name.endswith((".unity3d", ".bundle")):
                with zf.open(name) as fh:
                    head = fh.read(4096)
                is_bundle = head.startswith(
                    (b"UnityFS", b"UnityWeb", b"UnityRaw"))
                if name.endswith("globalgamemanagers") or is_bundle:
                    m = UNITY_VERSION_RE.search(head)
                    if m:
                        version_strings.append(
                            m.group(1).decode("ascii", "replace"))
                if is_bundle:
                    bundle_total += 1
                    # Only the deep-scan candidate list is
                    # capped; the counting above (Data
                    # files, Addressables, bundle total)
                    # always covers the whole archive. The
                    # pre-audit loop BROKE at the cap, so a
                    # bundle-heavy archive silently lost
                    # its Data-file and Addressables counts
                    # while the report called the inventory
                    # complete (stability audit B-04).
                    if len(bundles) < MAX_BUNDLE_SCAN:
                        bundles.append(name)
    report.update({
        "verdict": "unity" if backend else "absent",
        "scripting_backend": backend,
        "unity_version_strings": sorted(set(version_strings)),
        "metadata_version": versions.get("unity_metadata_version"),
        "metadata_era": versions.get("unity_metadata_era"),
        "data_file_count": data_files,
        "unityfs_bundles": bundles[:50],
        "unityfs_bundle_count": len(bundles),
        "unityfs_bundle_total": bundle_total,
        "unityfs_bundle_scan_truncated":
            bundle_total > len(bundles),
        "addressables": addressables,
        "inventory_scope": (
            "bundle inventory covers entries named "
            "*.unity3d / *.bundle (magic-verified) plus "
            "the conventional assets/bin/Data paths; "
            "bundles stored under other names are not "
            "inspected (B-14)"),
    })
    if catalog is not None:
        report["addressables_catalog"] = catalog
    # First-party header inspection of the first bundles
    # (independent of the optional UnityPy census below).
    inspections = []
    inspect_names = bundles[:BUNDLE_INSPECT_CAP]
    if inspect_names:
        with zipfile.ZipFile(target) as zf:
            for bname in inspect_names:
                try:
                    blob = read_member_capped(
                        zf, bname, MEMBER_CAP_BYTES)
                except ValueError as e:
                    inspections.append({
                        "entry": bname,
                        "format": "unityfs-bundle",
                        "parsed": False, "error": str(e)})
                    continue
                try:
                    inspections.append(
                        parse_unityfs_bundle(blob, bname))
                except BundleError as e:
                    inspections.append({
                        "entry": bname,
                        "format": "unityfs-bundle",
                        "parsed": False, "error": str(e)})
    report["bundle_inspections"] = inspections
    report["bundle_inspection_counts"] = {
        "total": len(bundles),
        "processed": len(inspections),
        "skipped": len(bundles) - len(inspections),
        "failed": sum(1 for r in inspections
                      if not r.get("parsed")),
    }
    if backend == "IL2CPP":
        il2cpp_args = [target]
        if work_dir:
            # Keep the (large) dumper output in the caller's
            # work dir instead of the tool's /tmp default.
            il2cpp_args += ["--out",
                            os.path.join(work_dir, "il2cpp")]
        il2cpp = run_json_tool("nar-il2cpp.py", il2cpp_args)
        if il2cpp:
            report["il2cpp"] = {k: il2cpp.get(k) for k in
                                ("verdict", "metadata_version",
                                 "dumper") if k in il2cpp}
        else:
            # A failed subprocess was previously
            # indistinguishable from "not IL2CPP" (B-13).
            report["il2cpp"] = {
                "error": "nar-il2cpp.py did not return a "
                         "result; the IL2CPP analysis is "
                         "missing, not negative"}
    # Optional UnityPy census on the first bundle found.
    census_status, census = None, None
    if bundles:
        with zipfile.ZipFile(target) as zf:
            try:
                census_blob = read_member_capped(
                    zf, bundles[0], MEMBER_CAP_BYTES)
            except ValueError:
                census_status, census = "over-cap", None
            else:
                census_status, census = unitypy_census(
                    census_blob)
    if census is not None:
        report["unitypy_census_first_bundle"] = census
    elif census_status == "over-cap":
        report["notes"] = [
            f"the first bundle exceeds the {MEMBER_CAP_BYTES}-"
            "byte member read cap (or is unreadable); bundle "
            "object census skipped."]
    elif census_status == "unavailable":
        report["notes"] = [
            "UnityPy is not importable in this interpreter; "
            "bundle object census skipped."]
    elif census_status == "load-failed":
        report["notes"] = [
            "UnityPy is installed but failed to load the "
            "first bundle; bundle object census skipped."]
    if report.get("unityfs_bundle_scan_truncated"):
        report.setdefault("notes", []).append(
            f"bundle deep-scan list capped at "
            f"{MAX_BUNDLE_SCAN} of "
            f"{report['unityfs_bundle_total']} bundles; "
            "counts cover the whole archive, deep "
            "inspection covers the listed subset")
    return report


def human(report):
    print(f"NAR Unity deep dive: "
          f"{os.path.basename(report['target'])}")
    print("=" * 60)
    print(f"Verdict: {report['verdict']} "
          f"(backend: {report['scripting_backend']})")
    if report["unity_version_strings"]:
        print(f"Unity version strings: "
              f"{report['unity_version_strings']}")
    if report["metadata_version"]:
        print(f"IL2CPP metadata: v{report['metadata_version']} "
              f"({report['metadata_era']})")
    print(f"Data files: {report['data_file_count']}; UnityFS "
          f"bundles: {report['unityfs_bundle_count']}; "
          f"Addressables: {report['addressables']}")
    cat = report.get("addressables_catalog")
    if cat and cat.get("parsed"):
        ent = cat.get("entries") or {}
        print(f"Addressables catalog: {cat['location_count']} "
              f"locations, {cat['resource_type_count']} resource "
              f"types, entries decoded: {ent.get('count')}")
    elif cat:
        print(f"Addressables catalog: not parsed "
              f"({cat.get('error')})")
    for insp in report.get("bundle_inspections", []):
        if not insp.get("parsed"):
            print(f"Bundle {insp['entry']}: header parse "
                  f"failed: {insp.get('error')}")
            continue
        bi = insp.get("blocks_info") or {}
        line = (f"Bundle {insp['entry']}: UnityFS format "
                f"{insp.get('bundle_format_version')}, "
                f"engine {insp.get('unity_version_engine')}, "
                f"blocks info {bi.get('compression')}")
        sf = insp.get("serialized_file")
        if sf and sf.get("status") == "parsed":
            line += (f"; first serialized file "
                     f"{sf.get('node_path')}: format "
                     f"{sf.get('format_version')}, "
                     f"{sf.get('endianness')} endian, "
                     f"metadata {sf.get('metadata_size')} "
                     f"bytes")
        print(line)
        for lim in insp.get("limitations", []):
            print(f"    limitation: {lim}")
    if report.get("unitypy_census_first_bundle"):
        print(f"UnityPy census (first bundle): "
              f"{report['unitypy_census_first_bundle']}")
    for note in report.get("notes", []):
        print(f"note: {note}")


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Unity deep dive: backend, version evidence, "
                    "bundle inventory, optional UnityPy census.")
    p.add_argument("target", help="path to the .apk file")
    p.add_argument("--json", action="store_true")
    p.add_argument("--work", metavar="DIR",
                   help="work dir for the IL2CPP dumper output "
                        "(large; keep it off a small /tmp)")
    args = p.parse_args(argv)
    if os.path.isdir(args.target):
        # Directory targets are an input error (exit 2) on
        # every platform. This cannot be left to the open()
        # below: POSIX raises IsADirectoryError for a
        # directory open (caught under the try), but Windows
        # raises PermissionError instead, which would escape
        # as a traceback and the wrong exit code.
        print(f"nar-unity: is a directory: {args.target}",
              file=sys.stderr)
        return 2
    try:
        report = analyze(args.target, args.work)
    except (FileNotFoundError, zipfile.BadZipFile) as e:
        print(f"nar-unity: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        human(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
