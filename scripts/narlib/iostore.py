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
- directory index in two layouts: the classic inline-
  FString tables, and the pooled name-index tables
  written by UE 5.3-era packagers (fixed-size rows
  referencing a shared string pool). A layout is
  accepted only when it consumes the index buffer
  exactly and its tree walk covers every entry.
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

COMPRESSION_METHODS_DECODED = ["None", "Zlib"]


def capabilities():
    """Structured capability facts for this parser (the
    source nar-unreal composes its IoStore limitations
    from). TOC versions come from TOC_VERSIONS itself so
    the report cannot drift from the parser's table.
    """
    return {
        "module": "narlib.iostore",
        "format": "iostore-utoc",
        "toc_versions": dict(TOC_VERSIONS),
        "toc_version_range": [min(TOC_VERSIONS),
                              max(TOC_VERSIONS)],
        "toc_layouts": [
            {"layout": "current", "status": "implemented"},
            {"layout": "legacy", "status": "implemented"},
        ],
        "directory_index_layouts": [
            {"layout": "classic", "status": "implemented"},
            {"layout": "pooled", "status": "implemented"},
        ],
        "compression_methods_decoded":
            list(COMPRESSION_METHODS_DECODED),
        "compression_methods_named_only": (
            "any other named method (e.g. Oodle) is "
            "named, not decoded"),
        "encrypted": {
            "status": "inventoried-never-decrypted",
            "note": ("containers flagged Encrypted, "
                     "including AES-sealed indexes, are "
                     "inventoried, never decrypted"),
        },
    }


INVALID_INDEX = 0xFFFFFFFF
# Stack-safety cap on directory-index nesting depth. It
# bounds true tree depth only; sibling chains are walked
# iteratively and never count against it.
MAX_DIRECTORY_DEPTH = 256
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
    if version == 0:
        # TOC_VERSIONS[0] is the enum's "Invalid" sentinel;
        # no real container carries it (stability audit B-15).
        raise IoStoreError(
            "TOC version 0 (Invalid) is not a real "
            "container version")
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


def _flatten_directory_index(mount, dir_rows, file_rows):
    """Flatten one directory-index tree to TOC-indexed
    paths. dir_rows are (name, first_child, first_file,
    next_sibling); file_rows are (name, next_file,
    toc_entry_index). Raises IoStoreError unless the
    child/sibling/file chains visit every row exactly
    once — a partial or cyclic tree is not guessed at.

    Sibling chains are walked iteratively and only child
    links add nesting depth. The earlier form recursed
    into siblings with the same depth counter, so it
    measured the longest child+sibling hop chain rather
    than the tree's depth and rejected wide trees: a
    real TOC v8 container whose deepest nesting is 9
    levels chains 87 hops through one directory's many
    subdirectories and was dropped as unreadable.
    Cycles cannot loop regardless of the depth cap:
    every row is marked on entry and a revisit raises,
    so the walk always terminates."""
    paths = {}
    visited_dirs = set()
    visited_files = set()

    def walk(dir_idx, prefix, depth):
        while dir_idx != INVALID_INDEX:
            if dir_idx >= len(dir_rows) \
                    or dir_idx in visited_dirs \
                    or depth > MAX_DIRECTORY_DEPTH:
                raise IoStoreError(
                    "directory index tree walk failed")
            visited_dirs.add(dir_idx)
            name, first_child, first_file, next_sibling = \
                dir_rows[dir_idx]
            here = prefix + (name + "/" if name else "")
            f = first_file
            steps = 0
            while f != INVALID_INDEX:
                if f >= len(file_rows) \
                        or f in visited_files \
                        or steps > len(file_rows):
                    raise IoStoreError(
                        "directory index file chain failed")
                visited_files.add(f)
                fname, next_file, toc_idx = file_rows[f]
                if toc_idx in paths:
                    raise IoStoreError(
                        "directory index names two files "
                        "for one TOC entry")
                paths[toc_idx] = mount + here + fname
                f = next_file
                steps += 1
            walk(first_child, here, depth + 1)
            dir_idx = next_sibling

    if dir_rows:
        walk(0, "", 0)
    if len(visited_dirs) != len(dir_rows) \
            or len(visited_files) != len(file_rows):
        raise IoStoreError(
            "directory index chains do not cover every "
            "directory and file entry")
    return paths


def _parse_directory_index_classic(buf):
    """Classic layout: names inline as FStrings in both
    tables (the layout the original IoStore writers and
    the open-source readers document)."""
    r = _Reader(buf)
    mount = _fstring(r)
    dir_count = r.u32()
    dir_rows = []
    for _ in range(dir_count):
        name = _fstring(r)
        first_child = r.u32()
        first_file = r.u32()
        next_sibling = r.u32()
        dir_rows.append((name, first_child, first_file,
                         next_sibling))
    file_count = r.u32()
    file_rows = []
    for _ in range(file_count):
        name = _fstring(r)
        next_file = r.u32()
        toc_idx = r.u32()
        file_rows.append((name, next_file, toc_idx))
    if r.pos != len(buf):
        raise IoStoreError(
            "classic directory index does not consume "
            "its buffer exactly")
    paths = _flatten_directory_index(mount, dir_rows,
                                     file_rows)
    return {
        "mount_point": mount,
        "directory_count": dir_count,
        "file_count": file_count,
        "files_named": len(paths),
        "paths": paths,
    }


def _parse_directory_index_pooled(buf):
    """Pooled layout (UE 5.3-era writers; TOC v8
    writers ship the same layout unchanged): both tables
    carry name indices into a shared FString pool that
    follows the tables, and a directory row is (name
    index, first child, next sibling, first file) — the
    first-file field sits last, after the sibling link.
    Validated by exact consumption, index ranges, and a
    complete tree walk."""
    r = _Reader(buf)
    mount = _fstring(r)
    dir_count = r.u32()
    raw_dirs = []
    for _ in range(dir_count):
        raw_dirs.append((r.u32(), r.u32(), r.u32(),
                         r.u32()))
    file_count = r.u32()
    raw_files = []
    for _ in range(file_count):
        raw_files.append((r.u32(), r.u32(), r.u32()))
    string_count = r.u32()
    strings = [_fstring(r) for _ in range(string_count)]
    if r.pos != len(buf):
        raise IoStoreError(
            "pooled directory index does not consume "
            "its buffer exactly")

    def pooled_name(idx, allow_invalid=False):
        if idx == INVALID_INDEX and allow_invalid:
            return ""
        if idx >= len(strings):
            raise IoStoreError(
                "pooled directory index name index out "
                "of range")
        return strings[idx]

    dir_rows = []
    for name_idx, first_child, next_sibling, first_file \
            in raw_dirs:
        for link in (first_child, next_sibling):
            if link != INVALID_INDEX and link >= dir_count:
                raise IoStoreError(
                    "pooled directory index directory "
                    "link out of range")
        if first_file != INVALID_INDEX \
                and first_file >= file_count:
            raise IoStoreError(
                "pooled directory index first-file "
                "link out of range")
        dir_rows.append((pooled_name(name_idx, True),
                         first_child, first_file,
                         next_sibling))
    file_rows = []
    for name_idx, next_file, toc_idx in raw_files:
        if next_file != INVALID_INDEX \
                and next_file >= file_count:
            raise IoStoreError(
                "pooled directory index file link out "
                "of range")
        file_rows.append((pooled_name(name_idx),
                          next_file, toc_idx))
    paths = _flatten_directory_index(mount, dir_rows,
                                     file_rows)
    return {
        "mount_point": mount,
        "directory_count": dir_count,
        "file_count": file_count,
        "files_named": len(paths),
        "paths": paths,
    }


def parse_directory_index(buf):
    """Parse the directory index buffer: mount point plus
    the directory/file tables, flattened to full paths.

    Two layouts exist in the wild: the classic inline-
    name layout and the pooled name-index layout written
    by UE 5.3-era packagers and kept by TOC v8 writers.
    Each candidate is accepted
    only when it consumes the buffer exactly and its
    tree walk covers every entry; anything else raises
    IoStoreError."""
    errors = []
    for layout, fn in (("classic",
                        _parse_directory_index_classic),
                       ("pooled",
                        _parse_directory_index_pooled)):
        try:
            parsed = fn(buf)
            parsed["layout"] = layout
            return parsed
        except (IoStoreError, struct.error, IndexError) \
                as e:
            errors.append(f"{layout}: {e}")
    raise IoStoreError(
        "directory index matches no known layout (" +
        "; ".join(errors) + ")")


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
    directory_index_error = None
    if version >= 2 and (flags & 0x08) \
            and header["directory_index_size"] > 0:
        buf = r.take(header["directory_index_size"])
        try:
            directory_index = parse_directory_index(buf)
            # A file row naming a TOC entry outside the
            # table is corrupt, not a name (stability
            # audit B-08): reject the index and record
            # why, instead of silently counting a name
            # no chunk can carry.
            bad_idx = [k for k in directory_index["paths"]
                       if not 0 <= k
                       < header["toc_entry_count"]]
            if bad_idx:
                raise IoStoreError(
                    "directory index names TOC entry "
                    f"{bad_idx[0]}, outside the "
                    f"{header['toc_entry_count']} entries "
                    "in the table")
        except (IoStoreError, struct.error) as e:
            # The failure is recorded on the result
            # (directory_index_error) so an unnamed-chunk
            # container is distinguishable from a
            # container with no index at all (B-08).
            directory_index = None
            directory_index_error = str(e)

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
        "directory_index_error": directory_index_error,
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
            # Capped inflation (stability audit B-01): the
            # TOC promises the block's uncompressed size;
            # never materialize more than that plus one
            # probe byte, so a hostile stream cannot expand
            # unboundedly before the size check below can
            # refuse it (the pak parser's discipline).
            promised = block["uncompressed_size"]
            d = zlib.decompressobj()
            try:
                chunk = d.decompress(raw, promised + 1)
            except zlib.error as e:
                raise IoStoreError(
                    f"zlib block decompression failed: {e}"
                ) from e
            if len(chunk) > promised or d.unconsumed_tail:
                raise IoStoreError(
                    "decompressed block expands past the "
                    f"{promised} bytes the TOC promises; "
                    "refusing to inflate it further")
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
    if not 0 <= index < len(parsed["entries"]):
        raise IoStoreError(f"chunk index {index} out of range")
    entry = parsed["entries"][index]
    want = entry.get("sha1")
    if not want:
        return None
    data = extract_chunk(parsed, ucas_data, index)
    return hashlib.sha1(data).hexdigest() == want
