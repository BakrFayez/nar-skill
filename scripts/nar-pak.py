#!/usr/bin/env python3
"""nar-pak.py: list the contents of an Unreal Engine .pak archive.

Stdlib-only, no pip dependencies. Parses the FPakInfo footer and the
index (mount point + entry records) for the classic pak format
versions 1-7 and prints each entry with its offset, packed and
unpacked sizes, compression method, and encryption flag, plus
grouped totals (by file extension and by top-level folder).
Versions 10+ use a different, encoded index (a path-hash index
plus a full directory index); those are parsed too: entry names
come from the full directory index and the entry records are
decoded from the encoded blob, with the index bytes and the
directory index both verified against their recorded SHA-1
hashes before anything is decoded. Versions 8-9 are reported as
unsupported, plainly: this tool never guesses or invents entries.
For v7+ footers the report also surfaces the footer's
index-encryption flag, so a modern pak whose index is
AES-encrypted says so even before its index is read.

Usage:
    python3 nar-pak.py game.pak [--json] [--limit N]
    python3 nar-pak.py game.pak --extract <name-or-pattern> --out <dir>

The .pak is usually inside the APK (assets or the engine content
directory) or inside an OBB; extract it first, then list it. An
encrypted index cannot be read without the key; the parse then fails
plainly instead of producing garbage.

--extract writes the decompressed bytes of every entry whose name
matches the pattern (exact name or shell-style glob) under --out,
preserving the pak-relative path. Stored entries are copied, zlib and
gzip entries are decompressed block by block. Encrypted entries and
entries compressed with a method that has no standard-library
decoder (LZ4, Oodle, ...) are refused plainly: AES needs the key
and those codecs are not in the Python standard library. For
v10+ entries the extracted bytes are additionally verified
against the SHA-1 of the uncompressed data recorded in the
entry's header.

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import contextlib
import fnmatch
import hashlib
import json
import mmap
import os
import struct
import sys
import zlib

PAK_MAGIC = 0x5A6F12E1
PAK_MAGIC_BYTES = struct.pack("<I", PAK_MAGIC)
FOOTER_SCAN = 1024  # FPakInfo sits at the end of the file.
MAX_ENTRIES = 10_000_000

COMPRESSION = {0: "None", 1: "Zlib", 2: "Gzip", 4: "LZ4"}


class PakError(Exception):
    """Raised when the .pak cannot be parsed as documented."""


class Reader:
    def __init__(self, data, base=0):
        self.data = data
        self.pos = base

    def read(self, n):
        if n < 0 or self.pos + n > len(self.data):
            raise PakError("unexpected end of data while parsing the index")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u32(self):
        return struct.unpack("<I", self.read(4))[0]

    def i32(self):
        return struct.unpack("<i", self.read(4))[0]

    def u64(self):
        return struct.unpack("<Q", self.read(8))[0]

    def fstring(self):
        n = self.i32()
        if n == 0:
            return ""
        if n > 0:
            raw = self.read(n)
            return raw.rstrip(b"\x00").decode("utf-8", "replace")
        raw = self.read(-n * 2)
        return raw.rstrip(b"\x00\x00").decode("utf-16-le", "replace")


def _locate_magic(data):
    """Absolute offset of the FPakInfo magic in the file tail."""
    tail = data[-FOOTER_SCAN:] if len(data) > FOOTER_SCAN else data
    idx = tail.rfind(PAK_MAGIC_BYTES)
    if idx < 0:
        raise PakError("no .pak footer magic found in the last "
                       f"{FOOTER_SCAN} bytes: not an Unreal .pak file "
                       "(or a truncated one)")
    return len(data) - len(tail) + idx


def find_footer(data):
    """Locate FPakInfo: magic, version, index offset, index size."""
    base = _locate_magic(data)
    if base + 24 > len(data):
        raise PakError("footer is truncated")
    version, index_offset, index_size = struct.unpack_from("<IQQ", data, base + 4)
    return version, index_offset, index_size


def index_encrypted(data, version):
    """The footer's index-encryption flag, or None when absent.

    Pak v7+ writes a 16-byte encryption-key GUID and a 1-byte
    bEncryptedIndex flag immediately before the magic. Older
    footers have no such prefix, so the flag does not exist there
    and None is returned rather than a guessed value.
    """
    if version < 7:
        return None
    base = _locate_magic(data)
    if base == 0:
        return None
    return data[base - 1] != 0


def parse_entries(data, version, index_offset, index_size,
                  has_timestamp, trailer):
    """Parse the index with one entry-layout candidate.

    Returns (mount_point, entries, consumed_bytes). Raises PakError on
    any structural problem; the caller compares consumed vs index_size.
    """
    r = Reader(data, index_offset)
    mount = r.fstring()
    count = r.i32()
    if count < 0 or count > MAX_ENTRIES:
        raise PakError(f"implausible entry count in index: {count}")
    entries = []
    for _ in range(count):
        name = r.fstring()
        offset = r.u64()
        size = r.u64()
        uncompressed = r.u64()
        method = r.i32()
        if has_timestamp:  # pak v1 only
            r.read(8)
        r.read(20)  # SHA-1 hash of the entry data
        blocks = 0
        if version >= 3 and method != 0:
            blocks = r.i32()
            if blocks < 0 or blocks > 1_000_000:
                raise PakError(f"implausible compression block count: {blocks}")
            r.read(blocks * 16)
        if offset > len(data) or size > len(data):
            # Classic (v1–7) entry extents were never
            # validated at list time (stability audit
            # B-09): a corrupt or hostile index published
            # offsets/sizes pointing outside the file as
            # inventory fact. The encoded (v10+) path has
            # always range-checked; the classic path now
            # refuses the index instead.
            raise PakError(
                f"entry {name!r} declares offset/size "
                f"({offset}+{size}) outside the "
                f"{len(data)}-byte file")
        encrypted = False
        if trailer:
            # v3+ trailer: a 1-byte encryption flag followed by the
            # compression block size (uint32). Read the flag; do not
            # skip these bytes blind.
            encrypted = r.read(1)[0] != 0
            r.read(trailer - 1)
        entries.append({
            "name": name,
            "offset": offset,
            "size_bytes": size,
            "uncompressed_size_bytes": uncompressed,
            "compression_method": method,
            "compression": COMPRESSION.get(method, f"method {method}"),
            "compression_blocks": blocks,
            "encrypted": encrypted,
        })
    return mount, entries, r.pos - index_offset


def pak_stats(entries):
    """Grouped totals: by file extension and by top-level folder.

    Each group list is sorted by count (name breaks ties) and capped
    at the top 10, so the shape of a big archive is visible at a
    glance without dumping every group.
    """
    by_ext = {}
    by_folder = {}
    for e in entries:
        name = e["name"]
        base = name.rsplit("/", 1)[-1]
        stem, dot, ext = base.rpartition(".")
        ext_key = f".{ext.lower()}" if dot and stem and ext else "(no extension)"
        folder_key = name.split("/", 1)[0] if "/" in name else "(root)"
        for table, key in ((by_ext, ext_key), (by_folder, folder_key)):
            slot = table.setdefault(key, {"count": 0, "packed_bytes": 0,
                                          "uncompressed_bytes": 0})
            slot["count"] += 1
            slot["packed_bytes"] += e["size_bytes"]
            slot["uncompressed_bytes"] += e["uncompressed_size_bytes"]

    def top(table):
        ranked = sorted(table.items(),
                        key=lambda kv: (-kv[1]["count"], kv[0]))
        return [{"name": key, **vals} for key, vals in ranked[:10]]

    return {"by_extension": top(by_ext), "by_folder": top(by_folder)}


def _parse_index(data, version, index_offset, index_size):
    """Parse the index, returning (mount, entries, layout).

    Entry layout candidates: (has_timestamp, per-entry trailer bytes).
    v1 carries a timestamp; v3+ adds a 5-byte trailer (encryption flag
    + compression block size). A candidate is accepted only when it
    consumes the index EXACTLY, so a wrong layout never yields
    plausible-looking garbage. Raises PakError when none fits.
    """
    if version >= 10:
        mount, entries, layout, _deleted = _parse_index_encoded(
            data, version, index_offset, index_size)
        return mount, entries, layout
    if version == 1:
        candidates = [(True, 0)]
    elif version == 2:
        candidates = [(False, 0)]
    else:
        candidates = [(False, 5), (False, 0)]
    last_error = None
    for has_ts, trailer in candidates:
        try:
            mount, entries, consumed = parse_entries(
                data, version, index_offset, index_size, has_ts, trailer)
        except PakError as e:
            last_error = str(e)
            continue
        if consumed == index_size:
            return mount, entries, (has_ts, trailer)
        last_error = (f"index parse consumed {consumed} of {index_size}"
                      " bytes (layout mismatch)")
    raise PakError("could not parse the index exactly: "
                   + (last_error or "unknown")
                   + ". The index may be encrypted, or this is a pak"
                   " layout this lister does not cover. No entries are"
                   " shown rather than guessed ones.")


def footer_compression_methods(data, version):
    """Compression method names from a v10+ footer.

    The modern footer carries five fixed 32-byte name slots after
    the index hash; the slot order defines the compression-method
    indices the encoded index entries reference (as slot + 1, with
    0 meaning stored). Returns [] for older versions or when the
    slots fall outside the file.
    """
    if version < 10:
        return []
    base = _locate_magic(data)
    start = base + 44
    names = []
    for i in range(5):
        raw = data[start + i * 32:start + (i + 1) * 32]
        if len(raw) < 32:
            break
        names.append(raw.split(b"\x00", 1)[0].decode("utf-8", "replace"))
    return names


def _decode_encoded_entry(blob, loc):
    """Decode one entry record from the encoded index blob (v10+).

    The record starts with a 32-bit flags word: bits 0-5 hold the
    compression block size shifted right 11 bits (0x3F means a full
    uint32 block size follows the size fields), bits 6-21 the
    compression block count, bit 22 the encryption flag, bits
    23-28 the compression method (0 = stored, otherwise the footer
    compression-method slot + 1), bit 29 the compressed size is a
    uint32 (else uint64), bit 30 the uncompressed size is a uint32,
    bit 31 the offset is a uint32. Then come the offset, the
    uncompressed size, the compressed size (only when a method is
    set), the escaped block size when flagged, and -- when the
    block count is above one -- one uint32 compressed size per
    block. A single block is synthesized from the compressed size,
    so no per-block sizes are stored for it.

    Returns (fields, consumed_bytes). Raises PakError on any
    structural problem.
    """
    r = Reader(blob, loc)
    flags = r.u32()
    block_size_field = flags & 0x3F
    block_count = (flags >> 6) & 0xFFFF
    encrypted = bool(flags & (1 << 22))
    method = (flags >> 23) & 0x3F
    offset = r.u32() if flags & (1 << 31) else r.u64()
    uncompressed = r.u32() if flags & (1 << 30) else r.u64()
    if method:
        size = r.u32() if flags & (1 << 29) else r.u64()
    else:
        size = uncompressed
    if block_size_field == 0x3F:
        block_size = r.u32()
    else:
        block_size = block_size_field << 11
    block_sizes = []
    if block_count > 1:
        if block_count > 1_000_000:
            raise PakError(f"implausible compression block count "
                           f"in encoded entry: {block_count}")
        block_sizes = [r.u32() for _ in range(block_count)]
    fields = {
        "offset": offset,
        "size": size,
        "uncompressed": uncompressed,
        "method": method,
        "encrypted": encrypted,
        "block_count": block_count if method else 0,
        "block_size": block_size,
        "block_sizes": block_sizes,
    }
    return fields, r.pos - loc


def _parse_index_encoded(data, version, index_offset, index_size):
    """Parse a v10+ (encoded) pak index.

    Index layout: mount point, entry count, path-hash seed, an
    optional path-hash index descriptor and an optional
    full-directory-index descriptor (offset, size and SHA-1 each),
    then the encoded entry blob. Entry names come from the full
    directory index (a directory -> file name -> encoded-entry
    location map stored elsewhere in the file); the path-hash
    index only accelerates name lookups and is skipped. The index
    bytes are verified against the SHA-1 in the footer and the
    directory index against the SHA-1 recorded beside its offset
    before anything is decoded, and both regions must be consumed
    exactly, so a wrong layout never yields plausible-looking
    garbage.

    Returns (mount_point, entries, layout, deleted_count).
    Negative directory-index locations are tombstones left by
    patch paks for deleted files; they are counted, not listed.
    """
    base = _locate_magic(data)
    stored_hash = data[base + 24:base + 44]
    index = data[index_offset:index_offset + index_size]
    if hashlib.sha1(index).digest() != stored_hash:
        raise PakError(
            "the index bytes do not match the SHA-1 recorded in "
            "the footer: the index is corrupt, or it is encrypted "
            "without the footer flag saying so. No entries are "
            "shown rather than guessed ones.")
    r = Reader(data, index_offset)
    mount = r.fstring()
    count = r.i32()
    if count < 0 or count > MAX_ENTRIES:
        raise PakError(f"implausible entry count in index: {count}")
    r.read(8)  # path-hash seed: feeds the path-hash index only

    def _optional_index():
        present = r.i32()
        if not present:
            return None
        off = struct.unpack("<q", r.read(8))[0]
        size = struct.unpack("<q", r.read(8))[0]
        return off, size, r.read(20)

    _path_hash_index = _optional_index()
    fdi = _optional_index()
    if fdi is None:
        raise PakError(
            "the index carries no full directory index, so entry "
            "names cannot be recovered from the index alone. No "
            "entries are shown rather than guessed ones.")
    blob_len = r.i32()
    if blob_len < 0:
        raise PakError("negative encoded entry blob size in the index")
    blob = data[r.pos:r.pos + blob_len]
    r.read(blob_len)
    # Newer writers append one trailing array after the encoded
    # entries (empty in every observed file). Accept the index
    # only when every byte is accounted for: nothing may follow
    # the blob except that array's count, and the count must be
    # zero -- a non-empty trailing array is a layout this parser
    # does not cover, so it is refused rather than guessed at.
    remaining = index_size - (r.pos - index_offset)
    if remaining == 4:
        trailing = r.i32()
        if trailing != 0:
            raise PakError(
                "the index carries a non-empty trailing array "
                f"({trailing} records) after the encoded entries: "
                "a layout this lister does not cover. No entries "
                "are shown rather than guessed ones.")
    elif remaining != 0:
        raise PakError(
            "encoded entry blob size does not exactly fill the "
            "index (layout mismatch). No entries are shown rather "
            "than guessed ones.")

    fdi_offset, fdi_size, fdi_hash = fdi
    fdi_bytes = data[fdi_offset:fdi_offset + fdi_size]
    if len(fdi_bytes) != fdi_size:
        raise PakError("full directory index points outside the file")
    if hashlib.sha1(fdi_bytes).digest() != fdi_hash:
        raise PakError(
            "the full directory index bytes do not match the "
            "SHA-1 recorded in the index: the archive is corrupt. "
            "No entries are shown rather than guessed ones.")
    fr = Reader(fdi_bytes, 0)
    dir_count = fr.i32()
    if dir_count < 0 or dir_count > MAX_ENTRIES:
        raise PakError(f"implausible directory count: {dir_count}")
    located = []
    deleted = 0
    for _ in range(dir_count):
        folder = fr.fstring()
        if folder and not folder.endswith("/"):
            folder += "/"
        file_count = fr.i32()
        if file_count < 0 or file_count > MAX_ENTRIES:
            raise PakError(f"implausible file count: {file_count}")
        for _ in range(file_count):
            filename = fr.fstring()
            location = fr.i32()
            if location < 0:
                deleted += 1
                continue
            located.append((folder + filename, location))
    if fr.pos != fdi_size:
        raise PakError(
            f"directory index parse consumed {fr.pos} of {fdi_size}"
            " bytes (layout mismatch)")

    methods = footer_compression_methods(data, version)
    entries = []
    for name, location in located:
        fields, _consumed = _decode_encoded_entry(blob, location)
        method = fields["method"]
        if method == 0:
            comp_name = "None"
        else:
            slot = method - 1
            comp_name = (methods[slot]
                         if slot < len(methods) and methods[slot]
                         else f"method {method}")
        if fields["offset"] > len(data) or fields["size"] > len(data):
            raise PakError(
                f"encoded entry for {name!r} points outside the file")
        entries.append({
            "name": name,
            "offset": fields["offset"],
            "size_bytes": fields["size"],
            "uncompressed_size_bytes": fields["uncompressed"],
            "compression_method": method,
            "compression": comp_name,
            "compression_blocks": fields["block_count"],
            "compression_block_size": fields["block_size"],
            "compression_block_sizes": fields["block_sizes"],
            "encrypted": fields["encrypted"],
        })
    return mount, entries, (False, 5), deleted


_TINY_BYTES = 64 * 1024


@contextlib.contextmanager
def _mapped(path):
    """Read-only mmap of path (bytes fallback for tiny
    files or when mmap fails). A local, stdlib-only copy
    of the narlib.mmapio idea: this script stays
    standalone by design, so it does not import narlib.
    The index parser and the entry extractors slice only
    the ranges they touch, so a mapped pak is never
    materialized whole."""
    size = os.path.getsize(path)
    if size <= _TINY_BYTES:
        with open(path, "rb") as fh:
            yield fh.read()
        return
    fh = open(path, "rb")
    try:
        try:
            mapping = mmap.mmap(fh.fileno(), 0,
                                access=mmap.ACCESS_READ)
        except (OSError, ValueError):
            fh.seek(0)
            yield fh.read()
            return
        try:
            yield mapping
        finally:
            mapping.close()
    finally:
        fh.close()


def list_pak(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(f"not a file: {path}")
    with _mapped(path) as data:
        return _list_pak_data(path, data)


def _list_pak_data(path, data):
    version, index_offset, index_size = find_footer(data)
    report = {
        "file": os.path.basename(path),
        "path": os.path.abspath(path),
        "size_bytes": len(data),
        "pak_version": version,
        "index_offset": index_offset,
        "index_size_bytes": index_size,
    }
    encrypted = index_encrypted(data, version)
    if encrypted is not None:
        report["index_encrypted"] = encrypted
    if index_offset + index_size > len(data):
        report["supported"] = False
        report["error"] = ("index offset/size in the footer point outside"
                           " the file: corrupt or truncated .pak")
        return report
    if version >= 10:
        if encrypted:
            report["supported"] = False
            report["error"] = (
                f"pak format version {version} uses the encoded index"
                " (path-hash + full directory index), and this index"
                " is flagged encrypted (AES): its entries cannot be"
                " read without the pak encryption key. No entries are"
                " shown rather than guessed ones.")
            return report
        try:
            mount, entries, _layout, deleted = _parse_index_encoded(
                data, version, index_offset, index_size)
        except PakError as e:
            report["supported"] = False
            report["error"] = str(e)
            return report
        report["supported"] = True
        report["mount_point"] = mount
        report["entry_count"] = len(entries)
        report["entries"] = entries
        if deleted:
            report["deleted_entry_count"] = deleted
        report["total_packed_bytes"] = sum(e["size_bytes"] for e in entries)
        report["total_uncompressed_bytes"] = sum(
            e["uncompressed_size_bytes"] for e in entries)
        report["encrypted_entry_count"] = sum(
            1 for e in entries if e["encrypted"])
        report["stats"] = pak_stats(entries)
        return report
    if version >= 8:
        report["supported"] = False
        report["error"] = (
            f"pak format version {version} uses the FName-based index"
            " (path-hash directory), which this stdlib lister does not"
            " parse. No entries are shown rather than guessed ones.")
        if encrypted:
            report["error"] += (
                " The index is additionally flagged encrypted (AES),"
                " so its entries could not be read without the pak"
                " encryption key even if the index layout were parsed.")
        return report
    try:
        mount, entries, _layout = _parse_index(
            data, version, index_offset, index_size)
    except PakError as e:
        report["supported"] = False
        report["error"] = str(e)
        return report
    report["supported"] = True
    report["mount_point"] = mount
    report["entry_count"] = len(entries)
    report["entries"] = entries
    report["total_packed_bytes"] = sum(e["size_bytes"] for e in entries)
    report["total_uncompressed_bytes"] = sum(
        e["uncompressed_size_bytes"] for e in entries)
    report["encrypted_entry_count"] = sum(
        1 for e in entries if e["encrypted"])
    report["stats"] = pak_stats(entries)
    return report


def _decompress_capped(raw, use_gzip, limit, what):
    """Decompress one zlib/gzip stream with an allocation
    bound: at most ``limit`` bytes of output are ever
    materialized (plus one probe byte). The index/header
    already promise the entry's uncompressed size, and the
    extractors verify the result against it afterwards —
    but without a cap, a hostile entry whose stream expands
    far beyond its promised size would be fully inflated
    before that check could refuse it. Raises PakError when
    the stream is corrupt, truncated, or expands past the
    promised size."""
    d = zlib.decompressobj(31 if use_gzip else zlib.MAX_WBITS)
    try:
        out = d.decompress(bytes(raw), limit + 1)
    except zlib.error as e:
        raise PakError(f"decompression failed: {e}") from e
    if len(out) > limit or d.unconsumed_tail:
        raise PakError(
            f"{what} expands past the {limit:,} bytes the "
            "index promises; refusing to inflate it further")
    if not d.eof:
        raise PakError(f"decompression failed: {what} is a "
                       "truncated stream")
    return out


def extract_entry(data, version, layout, entry):
    """Return the decompressed bytes of one entry.

    Every entry's data in the file is preceded by a serialized copy of
    its index record (without the name); compression block offsets in
    that header are absolute file offsets. Raises PakError with a
    plain reason when the entry cannot be extracted.
    """
    if entry["encrypted"]:
        raise PakError(
            "entry is flagged encrypted (AES); extraction needs the"
            " pak encryption key, which this tool does not hold")
    has_ts, trailer = layout
    r = Reader(data, entry["offset"])
    r.u64()  # offset field: serialized as 0 in the file, patched from
    # the index at load time, so it cannot be checked against the index
    size = r.u64()
    uncompressed = r.u64()
    method = r.i32()
    if (size != entry["size_bytes"]
            or uncompressed != entry["uncompressed_size_bytes"]
            or method != entry["compression_method"]):
        raise PakError("entry header in the data region does not match"
                       " the index record; the pak layout differs from"
                       " what this tool parses")
    if has_ts:  # pak v1 only
        r.read(8)
    r.read(20)  # SHA-1 of the entry data
    blocks = []
    if version >= 3 and method != 0:
        count = r.i32()
        if count < 0 or count > 1_000_000:
            raise PakError(f"implausible compression block count: {count}")
        for _ in range(count):
            start = r.u64()
            end = r.u64()
            blocks.append((start, end))
    if trailer:
        r.read(trailer)
    if method == 0:
        out = data[r.pos:r.pos + size]
        if len(out) != size:
            raise PakError("stored entry is truncated in the file")
    elif method in (1, 2) and not blocks:
        # Pak v1/v2 have no block table: one contiguous stream follows
        # the header.
        raw = data[r.pos:r.pos + size]
        if len(raw) != size:
            raise PakError("compressed entry is truncated in the file")
        out = _decompress_capped(raw, method == 2, uncompressed,
                                 "compressed entry")
    elif method in (1, 2):
        chunks = []
        done = 0
        for start, end in blocks:
            raw = data[start:end]
            if len(raw) != end - start:
                raise PakError("compression block is truncated in the file")
            chunk = _decompress_capped(
                raw, method == 2, uncompressed - done,
                "compression block")
            chunks.append(chunk)
            done += len(chunk)
        out = b"".join(chunks)
    else:
        raise PakError(
            f"compression method {entry['compression']} is not supported"
            " by the stdlib extractor (LZ4 is not in the Python"
            " standard library)")
    if len(out) != uncompressed:
        raise PakError(
            f"extracted {len(out):,} bytes but the index promises"
            f" {uncompressed:,}; refusing to write a partial result")
    return out


def extract_entry_encoded(data, entry):
    """Return the decompressed bytes of one v10+ entry.

    The entry's data in the file is preceded by the classic
    serialized header; it is read and cross-checked against the
    encoded index record, the compression blocks are taken from
    the index record (one compressed size per block), and the
    result is verified against the header's SHA-1 of the
    uncompressed data, so a layout misunderstanding cannot
    produce a plausible-looking wrong file. Raises PakError with
    a plain reason when the entry cannot be extracted.
    """
    if entry["encrypted"]:
        raise PakError(
            "entry is flagged encrypted (AES); extraction needs the"
            " pak encryption key, which this tool does not hold")
    r = Reader(data, entry["offset"])
    r.u64()  # offset field: serialized as 0 in the file, patched
    # from the index at load time, so it cannot be checked
    size = r.u64()
    uncompressed = r.u64()
    method = r.i32()
    if (size != entry["size_bytes"]
            or uncompressed != entry["uncompressed_size_bytes"]
            or method != entry["compression_method"]):
        raise PakError("entry header in the data region does not match"
                       " the index record; the pak layout differs from"
                       " what this tool parses")
    digest = r.read(20)  # SHA-1 of the uncompressed data
    if method != 0:
        count = r.i32()
        if count < 0 or count > 1_000_000:
            raise PakError(f"implausible compression block count: {count}")
        if count != entry["compression_blocks"]:
            raise PakError("compression block count in the entry header"
                           " does not match the index record; the pak"
                           " layout differs from what this tool parses")
        r.read(count * 16)  # block offsets: the index record's
        # per-block compressed sizes are used instead
    r.read(5)  # trailer: encryption flag + compression block size
    if method == 0:
        out = data[r.pos:r.pos + size]
        if len(out) != size:
            raise PakError("stored entry is truncated in the file")
    elif entry["compression"].lower() in ("zlib", "gzip"):
        use_gzip = entry["compression"].lower() == "gzip"
        block_sizes = entry["compression_block_sizes"] or [size]
        chunks = []
        done = 0
        pos = r.pos
        for block_size in block_sizes:
            raw = data[pos:pos + block_size]
            if len(raw) != block_size:
                raise PakError("compression block is truncated in "
                               "the file")
            chunk = _decompress_capped(
                raw, use_gzip, uncompressed - done,
                "compression block")
            chunks.append(chunk)
            done += len(chunk)
            pos += block_size
        out = b"".join(chunks)
    else:
        raise PakError(
            f"compression method {entry['compression']} is not "
            "supported by the stdlib extractor (it has no decoder "
            "in the Python standard library)")
    if len(out) != uncompressed:
        raise PakError(
            f"extracted {len(out):,} bytes but the index promises"
            f" {uncompressed:,}; refusing to write a partial result")
    if hashlib.sha1(out).digest() != digest:
        raise PakError(
            "extracted data does not match the SHA-1 recorded in "
            "the entry header; refusing to write a corrupt result")
    return out


def extract_pak(path, pattern, out_dir):
    """Extract every entry matching pattern under out_dir.

    Returns a report dict in the list_pak shape plus "extracted" and
    "extract_errors" lists. Raises FileNotFoundError / PakError for
    file-level problems.
    """
    report = list_pak(path)
    if not report.get("supported"):
        return report
    # Extraction reads only the matched entries' ranges
    # from the mapping (plus their entry headers).
    with _mapped(path) as data:
        _mount, _entries, layout = _parse_index(
            data, report["pak_version"], report["index_offset"],
            report["index_size_bytes"])
        matched = [e for e in report["entries"]
                   if e["name"] == pattern
                   or fnmatch.fnmatchcase(e["name"], pattern)]
        report["extract_pattern"] = pattern
        report["extract_out_dir"] = os.path.abspath(out_dir)
        report["extract_matched"] = len(matched)
        extracted = []
        errors = []
        for entry in matched:
            try:
                if report["pak_version"] >= 10:
                    blob = extract_entry_encoded(data, entry)
                else:
                    blob = extract_entry(
                        data, report["pak_version"], layout, entry)
            except PakError as e:
                errors.append({"name": entry["name"],
                               "error": str(e)})
                continue
            rel = entry["name"].replace("\\", "/").lstrip("/")
            parts = [p for p in rel.split("/")
                     if p not in ("", ".", "..")]
            if not parts:
                errors.append({
                    "name": entry["name"],
                    "error": "entry name has no safe relative path"})
                continue
            dest = os.path.join(out_dir, *parts)
            # The name filter above is lexical only: a
            # pre-existing symlink inside out_dir would
            # still redirect the write outside it. Prove
            # the resolved destination stays inside the
            # resolved root and never write through a
            # symlink at the destination itself (C-01,
            # the same discipline as safearchive).
            root_real = os.path.realpath(out_dir)
            dest_real = os.path.realpath(dest)
            if dest_real != root_real and not dest_real.startswith(
                    root_real + os.sep):
                errors.append({
                    "name": entry["name"],
                    "error": "destination escapes the "
                             "output directory through a "
                             "symlink"})
                continue
            if os.path.islink(dest):
                errors.append({
                    "name": entry["name"],
                    "error": "destination is a pre-existing "
                             "symlink; refusing to write "
                             "through it"})
                continue
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as fh:
                fh.write(blob)
            extracted.append({
                "name": entry["name"],
                "out_path": os.path.abspath(dest),
                "size_bytes": len(blob),
                "sha256": hashlib.sha256(blob).hexdigest(),
            })
        report["extracted"] = extracted
        report["extract_errors"] = errors
    return report


def human(report, limit):
    title = f"NAR pak listing: {report['file']}"
    lines = [title, "=" * len(title)]
    lines.append(f"Size: {report['size_bytes']:,} bytes")
    lines.append(f"Pak format version: {report['pak_version']}")
    if not report.get("supported"):
        if report.get("index_encrypted"):
            lines.append("Index encryption: AES (the index itself is "
                         "flagged encrypted)")
        lines.append(f"UNSUPPORTED: {report.get('error', 'unknown problem')}")
        return "\n".join(lines)
    lines.append(f"Mount point: {report['mount_point']}")
    lines.append(f"Entries: {report['entry_count']:,}")
    enc = report.get("encrypted_entry_count", 0)
    if enc:
        lines.append(f"Encryption: AES ({enc:,} of "
                     f"{report['entry_count']:,} entries flagged)")
    else:
        lines.append("Encryption: none")
    lines.append(f"Total packed: {report['total_packed_bytes']:,} bytes; "
                 f"uncompressed: {report['total_uncompressed_bytes']:,} bytes")
    stats = report.get("stats") or {}
    for label, key in (("extension", "by_extension"),
                       ("top-level folder", "by_folder")):
        groups = stats.get(key) or []
        if not groups:
            continue
        lines.append("")
        lines.append(f"Entries by {label} (top 10 by count):")
        for g in groups:
            lines.append(f"  {g['name']}: {g['count']:,} entries, "
                         f"{g['packed_bytes']:,} packed / "
                         f"{g['uncompressed_bytes']:,} uncompressed bytes")
    lines.append("")
    shown = report["entries"] if limit <= 0 else report["entries"][:limit]
    for e in shown:
        lines.append(f"  {e['name']}  ({e['size_bytes']:,} -> "
                     f"{e['uncompressed_size_bytes']:,} bytes, "
                     f"{e['compression']})")
    if len(shown) < report["entry_count"]:
        lines.append(f"  ... and {report['entry_count'] - len(shown):,} more"
                     " (raise --limit, or use --json for all)")
    return "\n".join(lines)


def human_extract(report):
    lines = [f"NAR pak extract: {report['file']}",
             f"Pattern: {report['extract_pattern']}"]
    if not report.get("supported"):
        lines.append(f"UNSUPPORTED: {report.get('error', 'unknown problem')}")
        return "\n".join(lines)
    lines.append(f"Matched: {report['extract_matched']:,} of "
                 f"{report['entry_count']:,} entries")
    for item in report.get("extracted", []):
        lines.append(f"  OK  {item['name']} -> {item['out_path']}"
                     f" ({item['size_bytes']:,} bytes,"
                     f" sha256 {item['sha256'][:16]}...)")
    for err in report.get("extract_errors", []):
        lines.append(f"  REFUSED  {err['name']}: {err['error']}")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR Unreal .pak lister: footer + index parse for "
                    "pak format versions 1-7 and the encoded 10+ index "
                    "(stdlib only).")
    p.add_argument("pak", help="path to the .pak file")
    p.add_argument("--json", action="store_true",
                   help="machine-readable JSON output")
    p.add_argument("--limit", type=int, default=50,
                   help="max entries to print in human output "
                        "(default 50; 0 = all)")
    p.add_argument("--extract", metavar="PATTERN",
                   help="extract entries whose name matches PATTERN "
                        "(exact name or shell-style glob) instead of "
                        "only listing; requires --out")
    p.add_argument("--out", metavar="DIR",
                   help="directory --extract writes into")
    args = p.parse_args(argv)
    if args.extract and not args.out:
        p.error("--extract requires --out DIR")
    try:
        if args.extract:
            report = extract_pak(args.pak, args.extract, args.out)
        else:
            report = list_pak(args.pak)
    except FileNotFoundError as e:
        print(f"nar-pak: {e}", file=sys.stderr)
        return 2
    except PakError as e:
        print(f"nar-pak: {e}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report, indent=2))
    elif args.extract:
        print(human_extract(report))
    else:
        print(human(report, args.limit))
    if not report.get("supported"):
        return 1
    if args.extract:
        ok = (report.get("extract_matched", 0) > 0
              and not report.get("extract_errors"))
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
