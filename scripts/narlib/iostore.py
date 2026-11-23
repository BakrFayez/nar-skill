"""Pure-Python IoStore (.utoc) container parser.

Implements the public IoStore TOC layout (the same layout
the open-source CUE4Parse reader implements) for the two
eras found in the wild:

- current (UE5-era): 144-byte header carrying an explicit
  TocHeaderSize field, 12-byte chunk IDs, 10-byte
  big-endian offset/length records (40-bit offset + 40-bit
  length), a perfect-hash section (seeds only at TOC v4;
  seeds + without-hash indices at v5+), a 12-byte
  compression-block table, optional encryption IVs (TOC
  v10), compression method names, an optional signature
  section, an optional directory index, and a per-chunk
  meta section (33-byte records: 32-byte chunk hash +
  flags; 24-byte records at TOC v8+: 20-byte hash +
  flags + padding). A TOC v6 container flagged OnDemand
  carries two extra hash arrays after the meta.
- legacy (UE4.26/4.27 experimental IoStore): header
  without the TocHeaderSize field (140 bytes of fields),
  8-byte little-endian packed offset/length records
  (40-bit offset + 24-bit length in one u64), 21-byte
  meta records (SHA-1 + flags).

The parser does not guess: it walks a candidate layout
and accepts it only when the sections consume the file
exactly and the compression-block offsets are ordered.
Anything else raises IoStoreError with the reason.

Chunk payloads are decoded only for the None and Zlib
compression methods; other methods (e.g. Oodle) are
named, never faked. Encrypted containers are inventoried;
their payloads are never decrypted.
"""
import struct
import zlib

MAGIC = b"-==--==--==--==-"
HEADER_SIZE = 144

TOC_VERSIONS = {
    0: "Invalid",
    1: "Initial",
    2: "DirectoryIndex",
    3: "PartitionSize",
    4: "PerfectHash",
    5: "PerfectHashWithOverflow",
    6: "OnDemandMetaData",
    7: "RemovedOnDemandMetaData",
    8: "ReplaceIoChunkHashWithIoHash",
    9: "AddedSourceHashes",
    10: "ContainerEncryptionMethod",
}

CONTAINER_FLAGS = {
    0x01: "Compressed",
    0x02: "Encrypted",
    0x04: "Signed",
    0x08: "Indexed",
    0x10: "OnDemand",
}

# UE5-era chunk types (EIoChunkType5).
CHUNK_TYPES = {
    0: "Invalid",
    1: "ExportBundleData",
    2: "BulkData",
    3: "OptionalBulkData",
    4: "MemoryMappedBulkData",
    5: "ScriptObjects",
    7: "ExternalFile",
    8: "ShaderCodeLibrary",
    9: "ShaderCode",
    10: "PackageStoreEntry",
    11: "DerivedData",
    12: "EditorDerivedData",
    13: "PackageResource",
}

# Classic chunk types (EIoChunkType), kept for comparison:
# the byte predates the UE5 renumbering in legacy files.
CHUNK_TYPES_LEGACY = {
    0: "Invalid",
    1: "InstallManifest",
    2: "ExportBundleData",
    3: "BulkData",
    4: "OptionalBulkData",
    5: "MemoryMappedBulkData",
    6: "LoaderGlobalMeta",
    7: "LoaderInitialLoadMeta",
    8: "LoaderGlobalNames",
    9: "LoaderGlobalNameHashes",
    10: "ContainerHeader",
}

INVALID_INDEX = 0xFFFFFFFF
CHUNK_ID_SIZE = 12
BLOCK_ENTRY_SIZE = 12


class IoStoreError(Exception):
    pass


class _Reader:
    def __init__(self, data, base=0):
        self.data = data
        self.pos = base

    def take(self, n):
        if n < 0 or self.pos + n > len(self.data):
            raise IoStoreError(
                f"unexpected end of .utoc at {self.pos} (+{n})")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return struct.unpack("<H", self.take(2))[0]

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def i32(self):
        return struct.unpack("<i", self.take(4))[0]

    def u64(self):
        return struct.unpack("<Q", self.take(8))[0]


def _read_header(data, legacy=False):
    """Read the TOC header. legacy=True reads the era
    without the TocHeaderSize field (fields shifted by 4,
    140 bytes of fields)."""
    if len(data) < 144:
        raise IoStoreError(
            f".utoc too small for a TOC header ({len(data)} bytes)")
    if data[:16] != MAGIC:
        raise IoStoreError("bad .utoc magic")
    r = _Reader(data, 16)
    version = r.u8()
    r.u8()          # reserved0
    r.u16()         # reserved1
    if legacy:
        toc_header_size = None
    else:
        toc_header_size = r.u32()
    entry_count = r.u32()
    block_count = r.u32()
    block_entry_size = r.u32()
    method_name_count = r.u32()
    method_name_length = r.u32()
    block_size = r.u32()
    dir_index_size = r.u32()
    partition_count = r.u32()
    container_id = r.u64()
    guid = r.take(16)
    flags = r.u8()
    encryption_method = r.u8()
    r.u16()         # reserved4
    seeds_count = r.u32()
    partition_size = r.u64()
    without_count = r.u32()
    if legacy:
        source_hash_count = 0
        iv_count = 0
        r.u32()     # reserved7
        r.take(40)  # reserved8[5]
    elif version >= 10:
        source_hash_count = r.u32()   # reinterprets reserved7
        iv_count = r.u32()            # reinterprets reserved8[0]
        r.u32()
        r.take(32)                    # reserved9[4]
    else:
        source_hash_count = 0
        iv_count = 0
        r.u32()     # reserved7
        r.take(40)  # reserved8[5]
    if block_entry_size != BLOCK_ENTRY_SIZE:
        raise IoStoreError(
            f"unexpected compressed block entry size "
            f"{block_entry_size} (expected {BLOCK_ENTRY_SIZE})")
    if version > max(TOC_VERSIONS):
        raise IoStoreError(f"unknown TOC version {version}")
    return {
        "magic_ok": True,
        "version": version,
        "version_name": TOC_VERSIONS.get(version, f"v{version}"),
        "toc_header_size": toc_header_size,
        "header_size": 140 if legacy else HEADER_SIZE,
        "layout": "legacy" if legacy else "current",
        "toc_entry_count": entry_count,
        "toc_compressed_block_entry_count": block_count,
        "toc_compressed_block_entry_size": block_entry_size,
        "compression_method_name_count": method_name_count,
        "compression_method_name_length": method_name_length,
        "compression_block_size": block_size,
        "directory_index_size": dir_index_size,
        "partition_count": partition_count,
        "container_id": container_id,
        "encryption_key_guid": guid.hex(),
        "encryption_key_guid_zero": guid == b"\x00" * 16,
        "container_flags": flags,
        "container_flag_names": [
            name for bit, name in sorted(CONTAINER_FLAGS.items())
            if flags & bit],
        "encryption_method": encryption_method,
        "toc_chunk_perfect_hash_seeds_count": seeds_count,
        "partition_size": partition_size,
        "toc_chunks_without_perfect_hash_count": without_count,
        "toc_source_hash_count": source_hash_count,
        "encryption_iv_count": iv_count,
    }


def _fstring(r):
    n = r.i32()
    if n == 0:
        return ""
    if n > 0:
        raw = r.take(n)
        return raw.rstrip(b"\x00").decode("utf-8", "replace")
    count = -n
    raw = r.take(count * 2)
    return raw.decode("utf-16-le", "replace").rstrip("\x00")


def parse_directory_index(buf):
    """Parse the directory index buffer: mount point plus
    the directory/file tables, flattened to full paths."""
    r = _Reader(buf)
    mount = _fstring(r)
    dir_count = r.u32()
    dirs = []
    for _ in range(dir_count):
        name = _fstring(r)
        dirs.append({
            "name": name,
            "first_child_index": r.u32(),
            "first_file_index": r.u32(),
            "next_sibling_index": r.u32(),
        })
    file_count = r.u32()
    files = []
    for _ in range(file_count):
        name = _fstring(r)
        files.append({
            "name": name,
            "next_file_index": r.u32(),
            "toc_entry_index": r.u32(),
        })

    def dir_path(idx, guard=0):
        if idx == INVALID_INDEX or idx >= len(dirs) or guard > 64:
            return None
        # A directory's path is built from its parent chain,
        # which the table only exposes via child links from
        # the root; resolve by searching for the parent.
        return dirs[idx]["name"]

    paths = {}
    if dirs:
        # Walk from the root (directory 0) through
        # child/sibling links, accumulating path prefixes.
        def walk(dir_idx, prefix, seen):
            if dir_idx == INVALID_INDEX or dir_idx >= len(dirs):
                return
            if dir_idx in seen:
                return
            seen = seen | {dir_idx}
            d = dirs[dir_idx]
            here = prefix + (d["name"] + "/" if d["name"] else "")
            f = d["first_file_index"]
            steps = 0
            while f != INVALID_INDEX and f < len(files) \
                    and steps <= len(files):
                entry = files[f]
                paths[entry["toc_entry_index"]] = \
                    mount + here + entry["name"]
                f = entry["next_file_index"]
                steps += 1
            walk(d["first_child_index"], here, seen)
            walk(d["next_sibling_index"], prefix, seen)

        walk(0, "", set())
    return {
        "mount_point": mount,
        "directory_count": dir_count,
        "file_count": file_count,
        "files_named": len(paths),
        "paths": paths,
    }


def _parse_block(raw):
    return {
        "offset": int.from_bytes(raw[0:5], "little"),
        "compressed_size": int.from_bytes(raw[5:8], "little"),
        "uncompressed_size": int.from_bytes(raw[8:11], "little"),
        "compression_method_index": raw[11],
    }


def _walk(data, header):
    """Walk one layout candidate end to end. Raises
    IoStoreError unless the sections consume the file
    exactly (modulo the on-demand trailer accounting)."""
    legacy = header["layout"] == "legacy"
    version = header["version"]
    flags = header["container_flags"]
    entry_count = header["toc_entry_count"]
    block_count = header["toc_compressed_block_entry_count"]
    r = _Reader(data, header["header_size"])

    chunk_ids = []
    for _ in range(entry_count):
        raw = r.take(CHUNK_ID_SIZE)
        ctype = raw[11]
        chunk_ids.append({
            "chunk_id": struct.unpack("<Q", raw[:8])[0],
            "chunk_id_hex": raw.hex(),
            "chunk_index": struct.unpack(">H", raw[8:10])[0],
            "chunk_type": ctype,
            "chunk_type_name": CHUNK_TYPES.get(
                ctype, f"Type{ctype}"),
            "chunk_type_name_legacy": CHUNK_TYPES_LEGACY.get(
                ctype, f"Type{ctype}"),
        })

    offsets = []
    for _ in range(entry_count):
        if legacy:
            v = r.u64()
            offsets.append((v & ((1 << 40) - 1), v >> 40))
        else:
            raw = r.take(10)
            offsets.append((
                int.from_bytes(raw[0:5], "big"),
                int.from_bytes(raw[5:10], "big")))

    seeds = without = 0
    if version >= 5:
        seeds = header["toc_chunk_perfect_hash_seeds_count"]
        without = header[
            "toc_chunks_without_perfect_hash_count"]
    elif version >= 4:
        seeds = header["toc_chunk_perfect_hash_seeds_count"]
    r.take(4 * seeds + 4 * without)

    blocks = [_parse_block(r.take(BLOCK_ENTRY_SIZE))
              for _ in range(block_count)]
    for prev, cur in zip(blocks, blocks[1:]):
        if cur["offset"] < prev["offset"]:
            raise IoStoreError(
                "compression block offsets are not ordered")

    iv_count = header["encryption_iv_count"]
    iv_stride = 0
    if iv_count:
        # The IV section's record size is not published in
        # the sources this parser is built from; the walk
        # only succeeds if the common 16-byte stride makes
        # the file consume exactly.
        iv_stride = 16
        r.take(iv_count * iv_stride)

    methods = ["None"]
    for _ in range(header["compression_method_name_count"]):
        raw = r.take(header["compression_method_name_length"])
        name = raw.split(b"\x00")[0].decode("ascii", "replace")
        methods.append(name)

    if flags & 0x04:  # Signed
        hash_size = r.i32()
        if hash_size <= 0:
            raise IoStoreError("signed container with bad hash size")
        r.take(2 * hash_size + 20 * block_count)

    directory_index = None
    if version >= 2 and (flags & 0x08) \
            and header["directory_index_size"] > 0:
        buf = r.take(header["directory_index_size"])
        try:
            directory_index = parse_directory_index(buf)
        except (IoStoreError, struct.error):
            directory_index = None

    # Meta: whatever remains, minus the on-demand trailer
    # for a v6 container flagged OnDemand.
    trailer = 0
    if version == 6 and (flags & 0x10):
        trailer = 20 * (entry_count + block_count)
    remaining = len(data) - r.pos - trailer
    meta_stride = 0
    meta = []
    strides = (21,) if legacy else (33, 24)
    for stride in strides:
        if entry_count and remaining == entry_count * stride:
            meta_stride = stride
            break
    if not meta_stride and remaining != 0:
        raise IoStoreError(
            f"section walk leaves {remaining} bytes for "
            f"{entry_count} meta records (no known stride)")
    for _ in range(entry_count):
        raw = r.take(meta_stride) if meta_stride else b""
        if meta_stride == 21:
            meta.append({"sha1": raw[:20].hex(),
                         "flags": raw[20]})
        elif meta_stride == 33:
            meta.append({"chunk_hash": raw[:32].hex(),
                         "flags": raw[32]})
        elif meta_stride == 24:
            meta.append({"chunk_hash": raw[:20].hex(),
                         "flags": raw[20]})
    r.take(trailer)
    if r.pos != len(data):
        raise IoStoreError(
            f"section walk ended at {r.pos}, file is "
            f"{len(data)} bytes")

    block_size = header["compression_block_size"]
    paths = (directory_index or {}).get("paths", {})
    entries = []
    by_type = {}
    total_len = 0
    total_stored = 0
    for i, cid in enumerate(chunk_ids):
        offset, length = offsets[i]
        first_block = offset // block_size if block_size else 0
        covered = 0
        chunk_blocks = []
        j = first_block
        while covered < length and j < len(blocks):
            chunk_blocks.append(blocks[j])
            covered += blocks[j]["uncompressed_size"]
            j += 1
        stored = sum(b["compressed_size"] for b in chunk_blocks)
        entry = dict(cid)
        entry.update({
            "index": i,
            "offset": offset,
            "length": length,
            "first_block": first_block,
            "block_count": len(chunk_blocks),
            "stored_size": stored,
            "compression_methods": sorted({
                methods[b["compression_method_index"]]
                if b["compression_method_index"] < len(methods)
                else f"method#{b['compression_method_index']}"
                for b in chunk_blocks}),
        })
        if meta:
            entry.update(meta[i])
        if i in paths:
            entry["file"] = paths[i]
        by_type[entry["chunk_type_name"]] = \
            by_type.get(entry["chunk_type_name"], 0) + 1
        total_len += length
        total_stored += stored
        entries.append(entry)

    return {
        "format": "iostore-utoc",
        "size": len(data),
        "header": header,
        "compression_methods": methods,
        "entry_count": entry_count,
        "block_count": block_count,
        "entries_by_type": by_type,
        "total_chunk_bytes": total_len,
        "total_stored_bytes": total_stored,
        "perfect_hash_seed_count": seeds,
        "chunks_without_perfect_hash": without,
        "encryption_iv_count": iv_count,
        "directory_index": (
            {k: v for k, v in directory_index.items()
             if k != "paths"} if directory_index else None),
        "meta_present": bool(meta),
        "meta_entry_size": meta_stride or None,
        "trailing_bytes": len(data) - r.pos,
        "entries": entries,
        "_blocks": blocks,
    }


def parse_utoc(data, name=""):
    """Parse .utoc bytes into a full inventory dict.

    Tries the current layout first, then the legacy one;
    a layout is accepted only when its section walk
    consumes the file exactly.
    """
    errors = []
    for legacy in (False, True):
        try:
            header = _read_header(data, legacy=legacy)
            parsed = _walk(data, header)
            parsed["name"] = name
            return parsed
        except IoStoreError as e:
            errors.append(
                f"{'legacy' if legacy else 'current'}: {e}")
    raise IoStoreError(
        "no IoStore layout fits this file (" +
        "; ".join(errors) + ")")


def _chunk_blocks(parsed, entry):
    blocks = parsed["_blocks"]
    out = []
    covered = 0
    j = entry["first_block"]
    while covered < entry["length"] and j < len(blocks):
        out.append(blocks[j])
        covered += blocks[j]["uncompressed_size"]
        j += 1
    return out


def extract_chunk(parsed, ucas_data, index):
    """Decompress one chunk's payload from .ucas bytes.

    Supports the None and Zlib compression methods; any
    other method raises IoStoreError naming it.
    """
    if "Encrypted" in parsed["header"].get(
            "container_flag_names", []):
        raise IoStoreError(
            "container is flagged Encrypted; chunk payloads "
            "are inventoried, never decrypted")
    entries = parsed["entries"]
    if not 0 <= index < len(entries):
        raise IoStoreError(f"chunk index {index} out of range")
    entry = entries[index]
    methods = parsed["compression_methods"]
    out = bytearray()
    for block in _chunk_blocks(parsed, entry):
        start = block["offset"]
        end = start + block["compressed_size"]
        if end > len(ucas_data):
            raise IoStoreError(
                "compression block extends past the .ucas data")
        raw = ucas_data[start:end]
        method = methods[block["compression_method_index"]] \
            if block["compression_method_index"] < len(methods) \
            else f"method#{block['compression_method_index']}"
        if method == "None":
            chunk = raw
        elif method == "Zlib":
            chunk = zlib.decompress(raw)
        else:
            raise IoStoreError(
                f"compression method {method!r} is named but "
                "not decoded by this parser")
        if len(chunk) != block["uncompressed_size"]:
            raise IoStoreError(
                "decompressed block size mismatch: got "
                f"{len(chunk)}, TOC says "
                f"{block['uncompressed_size']}")
        out += chunk
    if len(out) != entry["length"]:
        raise IoStoreError(
            f"chunk size mismatch: got {len(out)}, TOC says "
            f"{entry['length']}")
    return bytes(out)


def chunk_sha1_ok(parsed, ucas_data, index):
    """Verify a chunk against a legacy 21-byte meta SHA-1.

    Returns True/False when the container carries legacy
    SHA-1 meta, None when it carries no plain SHA-1 to
    check against (current containers store a 32-byte
    chunk hash, a different construction).
    """
    import hashlib
    entry = parsed["entries"][index]
    want = entry.get("sha1")
    if not want:
        return None
    data = extract_chunk(parsed, ucas_data, index)
    return hashlib.sha1(data).hexdigest() == want
