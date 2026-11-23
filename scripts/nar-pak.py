#!/usr/bin/env python3
"""nar-pak.py: list the contents of an Unreal Engine .pak archive.

Stdlib-only, no pip dependencies. Parses the FPakInfo footer and the
index (mount point + entry records) for the classic pak format
versions 1-7 and prints each entry with its offset, packed and
unpacked sizes, compression method, and encryption flag, plus
grouped totals (by file extension and by top-level folder).
Versions 8+ use a different
(FName-based, path-hash) index and are reported as unsupported,
plainly: this tool never guesses or invents entries. For v7+
footers the report also surfaces the footer's index-encryption
flag, so a modern pak whose index is AES-encrypted says so even
though its index layout is not parsed.

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
LZ4 entries are refused plainly: AES needs the key and LZ4 is not in
the Python standard library.

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import fnmatch
import gzip
import hashlib
import json
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


def list_pak(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(f"not a file: {path}")
    with open(path, "rb") as fh:
        data = fh.read()
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
    if index_offset + index_size > len(data):
        report["supported"] = False
        report["error"] = ("index offset/size in the footer point outside"
                           " the file: corrupt or truncated .pak")
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
        try:
            out = (zlib.decompress(raw) if method == 1
                   else gzip.decompress(raw))
        except (zlib.error, OSError, EOFError) as e:
            raise PakError(f"decompression failed: {e}") from e
    elif method in (1, 2):
        chunks = []
        for start, end in blocks:
            raw = data[start:end]
            if len(raw) != end - start:
                raise PakError("compression block is truncated in the file")
            try:
                if method == 1:
                    chunks.append(zlib.decompress(raw))
                else:
                    chunks.append(gzip.decompress(raw))
            except (zlib.error, OSError, EOFError) as e:
                raise PakError(f"decompression failed: {e}") from e
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


def extract_pak(path, pattern, out_dir):
    """Extract every entry matching pattern under out_dir.

    Returns a report dict in the list_pak shape plus "extracted" and
    "extract_errors" lists. Raises FileNotFoundError / PakError for
    file-level problems.
    """
    report = list_pak(path)
    if not report.get("supported"):
        return report
    with open(path, "rb") as fh:
        data = fh.read()
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
            blob = extract_entry(data, report["pak_version"], layout, entry)
        except PakError as e:
            errors.append({"name": entry["name"], "error": str(e)})
            continue
        rel = entry["name"].replace("\\", "/").lstrip("/")
        parts = [p for p in rel.split("/") if p not in ("", ".", "..")]
        if not parts:
            errors.append({"name": entry["name"],
                           "error": "entry name has no safe relative path"})
            continue
        dest = os.path.join(out_dir, *parts)
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
                    "pak format versions 1-7 (stdlib only).")
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
