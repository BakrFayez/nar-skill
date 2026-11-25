"""Pure-Python Unreal .locres (FTextLocalizationResource)
parser.

Implements the public .locres layout (the same layout the
open-source CUE4Parse reader implements):

- 16-byte magic GUID header,
- 1-byte version (ELocResVersion: 0 Initial, 1
  EntryMetaData),
- int64 offset of the localized string array,
- the entry table: int32 namespace count, then per
  namespace an FString name, an int32 entry count, and
  per entry an FString key, a uint32 source-string hash
  (version >= 1 only) and an int32 index into the
  localized string array,
- the localized string array at the recorded offset:
  int32 count, then that many FStrings.

FStrings are the standard Unreal serialization: an int32
length, positive for UTF-8 (count includes the null
terminator), negative for UTF-16LE (count is in code
units, includes the null terminator), zero for empty.

The parser does not guess: it accepts a file only when
the entry table ends exactly at the recorded string-array
offset, the string array ends exactly at end of file,
every entry's string index lands inside the array, and
every string decodes strictly with its terminator
present. Anything else raises LocResError with the
reason.

Validation: four real .locres files extracted from a
real title's .pak (593,599 / 1,073 / 241 / 33 bytes,
including the engine's own 482-namespace, 4,806-entry
Engine.locres) parse end to end under exactly these
rules; version 1 is the real-verified layout, version 0
follows the same public layout minus the per-entry hash
and is synthetic-only.
"""
import struct

MAGIC = bytes.fromhex("0e147475674a03fc4a15909dc3377f1b")

VERSIONS = {
    0: "Initial",
    1: "EntryMetaData",
}


def capabilities():
    """Structured capability facts for this parser (the
    source nar-unreal composes its .locres facts from).
    """
    return {
        "module": "narlib.locres",
        "format": "unreal-locres",
        "versions": dict(VERSIONS),
        "version_range": [min(VERSIONS), max(VERSIONS)],
        "layouts": [
            {"layout": "v1-entry-metadata",
             "status": "implemented",
             "verification": "real"},
            {"layout": "v0-initial",
             "status": "implemented",
             "verification": "synthetic"},
        ],
        "real_files_verified": 4,
        "validation": (
            "entry table must end exactly at the "
            "recorded string-array offset, the string "
            "array must end exactly at end of file, "
            "every string index must land inside the "
            "array, and every string must decode "
            "strictly with its terminator present"),
    }


class LocResError(Exception):
    pass


class _Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, n):
        if n < 0 or self.pos + n > len(self.data):
            raise LocResError(
                f"unexpected end of .locres at {self.pos} (+{n})")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self):
        return self.take(1)[0]

    def i32(self):
        return struct.unpack("<i", self.take(4))[0]

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def i64(self):
        return struct.unpack("<q", self.take(8))[0]

    def fstring(self):
        n = self.i32()
        if n == 0:
            return ""
        if n > 0:
            if n > len(self.data) - self.pos:
                raise LocResError(
                    f"FString byte count {n} runs past "
                    f"end of file at {self.pos}")
            raw = self.take(n)
            if not raw.endswith(b"\x00"):
                raise LocResError(
                    "UTF-8 FString is missing its null "
                    "terminator")
            try:
                return raw[:-1].decode("utf-8")
            except UnicodeDecodeError as e:
                raise LocResError(
                    f"UTF-8 FString does not decode: {e}"
                ) from e
        count = -n
        if count * 2 > len(self.data) - self.pos:
            raise LocResError(
                f"FString char count {count} runs past "
                f"end of file at {self.pos}")
        raw = self.take(count * 2)
        if not raw.endswith(b"\x00\x00"):
            raise LocResError(
                "UTF-16 FString is missing its null "
                "terminator")
        try:
            return raw[:-2].decode("utf-16-le")
        except UnicodeDecodeError as e:
            raise LocResError(
                f"UTF-16 FString does not decode: {e}"
            ) from e


def parse_locres(data, name=""):
    """Parse .locres bytes into a full inventory dict.

    Raises LocResError unless the file validates end to
    end (see the module docstring for the exact rules).
    Entry ``value`` fields resolve each entry's string
    index against the localized string array.
    """
    data = bytes(data)
    r = _Reader(data)
    if r.take(16) != MAGIC:
        raise LocResError("bad .locres magic GUID")
    version = r.u8()
    if version not in VERSIONS:
        raise LocResError(
            f"unsupported .locres version {version} "
            f"(implemented: {sorted(VERSIONS)})")
    string_array_offset = r.i64()
    if not 25 <= string_array_offset <= len(data):
        raise LocResError(
            f"localized string array offset "
            f"{string_array_offset} is outside the "
            f"{len(data)}-byte file")
    namespace_count = r.u32()
    namespaces = []
    entries = []
    for _ in range(namespace_count):
        ns_name = r.fstring()
        entry_count = r.u32()
        keys = []
        for _ in range(entry_count):
            key = r.fstring()
            source_hash = r.u32() if version >= 1 else None
            string_index = r.i32()
            keys.append(key)
            entries.append({
                "namespace": ns_name,
                "key": key,
                "source_string_hash": source_hash,
                "string_index": string_index,
            })
        namespaces.append({
            "name": ns_name,
            "entry_count": entry_count,
            "keys": keys,
        })
    if r.pos != string_array_offset:
        raise LocResError(
            f"entry table ends at {r.pos}, but the "
            f"header records the string array at "
            f"{string_array_offset}")
    string_count = r.u32()
    strings = [r.fstring() for _ in range(string_count)]
    if r.pos != len(data):
        raise LocResError(
            f"string array ends at {r.pos}, file is "
            f"{len(data)} bytes")
    for entry in entries:
        idx = entry["string_index"]
        if not 0 <= idx < string_count:
            raise LocResError(
                f"entry {entry['namespace']!r}/"
                f"{entry['key']!r} names string index "
                f"{idx}, outside the {string_count} "
                "strings in the array")
        entry["value"] = strings[idx]
    return {
        "format": "unreal-locres",
        "name": name,
        "size": len(data),
        "version": version,
        "version_name": VERSIONS[version],
        "string_array_offset": string_array_offset,
        "namespace_count": namespace_count,
        "entry_count": len(entries),
        "string_count": string_count,
        "namespaces": namespaces,
        "entries": entries,
        "strings": strings,
    }
