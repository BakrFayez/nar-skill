"""Pure-Python Zen package inspector.

Implements the publicly documented Zen package format —
the IoStore-native serialized package layout that UE5
cooking writes into ExportBundleData chunks (the layout
the open-source CUE4Parse reader implements in its
IoPackage / FZenPackageSummary code):

- The Zen header: an FZenPackageSummary (a flags word
  whose bit 0 marks versioning info, the header size, the
  package's own name as a mapped name, package flags, the
  cooked header size, and the section offsets), in the
  three shapes found in the wild — the current one
  (UE 5.3 and later, with dependency-bundle and imported-
  package-name offsets), the pre-5.3 one (a graph-data
  offset instead), and the UE5 Early Access legacy one
  (no flags word, no imported-public-export-hashes
  section). A layout candidate is accepted only when
  every section it implies validates end to end.
- The optional FZenPackageVersioningInfo (Zen format
  version, recorded UE4/UE5 object versions, licensee
  version, custom-version container) — the only place a
  Zen header ever records object versions. Most cooked
  Zen packages omit it: their summaries record no
  FileVersionUE4/UE5 at all, and this parser says so
  per field instead of inventing versions.
- The optional Verse cell offsets (two int32 section
  offsets serialized between the versioning info and
  the name map by newer writers), accepted only when
  the name batch validates with them consumed.
- The per-package name map, serialized as a name batch:
  a name count, the total string byte count, a hash
  version word, one 64-bit hash per name, one 2-byte
  serialized-name header per name (a UTF-16 flag and a
  15-bit length), then the name bytes concatenated.
  The batch is accepted only when the name bytes it
  decodes total exactly the recorded string byte count.
- The bulk data map (data-resource table): an int64
  total size followed by 32-byte entries, present only
  when it lands exactly on the imported-public-export-
  hashes section. Newer writers first serialize a
  count-prefixed byte array (an int64 element count and
  that many bytes, all zero in the real packages
  examined) ahead of the map; that variant is accepted
  under the same exact-landing rule, with the array
  reported as located and measured, not decoded.
- The imported public export hashes (one uint64 per
  imported public export), the import map (one 64-bit
  FPackageObjectIndex per import: the top two bits are
  the kind — export, script import, package import,
  null — and the low 62 bits the value), the export map
  (72-byte FExportMapEntry records: cooked serial
  offset/size, object name, outer/class/super/template
  object indices, public export hash, object flags,
  filter flags), and the export bundle entries (a
  create and a serialize command per export).
- Mapped names (FMappedName): a 32-bit word whose low
  30 bits index a name map and whose top two bits say
  which map (this package's, the container's, or the
  global one), plus a number word. Only package-map
  names resolve from a lone chunk; container/global
  references are reported as external, never guessed.

Export payloads are located and measured: an export's
serialized data starts at (header size + cooked serial
offset) in the chunk and runs for its cooked serial
size. Property streams are not decoded for Zen exports
in this build — a package flagged
PKG_UnversionedProperties needs a .usmap mapping file
(same rule as classic packages), and versioned Zen tag
streams use the mapped-name tag layout, which this
parser reports as located-not-decoded rather than
guessing at. The dependency-bundle sections and the
imported-package-names section of the current header
layout are located and measured from the offset table;
no public reader decodes them, and neither does this
one. (The pre-5.3 graph data IS decoded — package ids
plus per-package bundle counts — because its layout is
documented and it must consume its region exactly.)
Encrypted content is never touched: this module parses
plain chunk bytes only.
"""
import struct

from .uasset import OBJECT_FLAGS, PACKAGE_FLAGS, \
    PKG_UNVERSIONED_PROPERTIES

PACKAGE_MAGIC = 0x9E2A83C1
PACKAGE_MAGIC_LE = b"\xc1\x83\x2a\x9e"

EXPORT_MAP_ENTRY_SIZE = 72
OBJECT_INDEX_SIZE = 8
BULK_DATA_MAP_ENTRY_SIZE = 32

MAX_TABLE_ENTRIES = 10_000_000
MAX_NAME_BATCH_BYTES = 1 << 28

# EZenPackageVersion (the Zen format's own versioning,
# recorded only inside FZenPackageVersioningInfo).
ZEN_VERSIONS = {
    0: "Initial",
    1: "DataResourceTable",
    2: "ImportedPackageNames",
    3: "ExportDependencies",
}

# Zen-era package flags: the classic table plus the bits
# the current public EPackageFlags enum documents that
# the classic table predates.
ZEN_PACKAGE_FLAGS = dict(PACKAGE_FLAGS)
ZEN_PACKAGE_FLAGS.update({
    0x00000800: "PKG_NotExternallyReferenceable",
    0x00001000: "PKG_AccessSpecifierEpicInternal",
    0x00008000: "PKG_IsSaving",
    0x00080000: "PKG_LoadUncooked",
    0x08000000: "PKG_CookGenerated",
})

# FMappedName map kinds (top two bits of the index word).
MAPPED_NAME_TYPES = {
    0: "package",
    1: "container",
    2: "global",
    3: "reserved",
}

# FPackageObjectIndex kinds (top two bits of the u64).
OBJECT_INDEX_TYPES = {
    0: "export",
    1: "script-import",
    2: "package-import",
    3: "null",
}
OBJECT_INDEX_INVALID = (1 << 64) - 1

# EExportCommandType.
EXPORT_COMMAND_TYPES = {
    0: "create",
    1: "serialize",
}

VERSIONING_NOTE = (
    "this Zen header carries no versioning info: Zen "
    "summaries record no UE4/UE5 object version — "
    "packages are versioned by the engine build, not "
    "per package")


# Real packages the current (UE 5.3+) layout was verified
# against: the stored Zen packages of the two local
# IoStore corpora (684 + 525). The other two layouts have
# synthetic fixtures only.
ZEN_UE5_3_PLUS_REAL_PACKAGES = 1209


def capabilities():
    """Structured capability facts for this parser (the
    source nar-unreal composes its Zen limitations from).
    """
    return {
        "module": "narlib.zen",
        "format": "zen-package",
        "layouts": [
            {"layout": "ue5_3_plus",
             "status": "implemented",
             "verification": "real",
             "real_packages_verified":
                 ZEN_UE5_3_PLUS_REAL_PACKAGES},
            {"layout": "pre_ue5_3",
             "status": "implemented",
             "verification": "synthetic"},
            {"layout": "ea_legacy",
             "status": "implemented",
             "verification": "synthetic"},
        ],
        "decoded": [
            "Zen header",
            "versioning info when the writer recorded it",
            "per-package name map",
            "bulk data map",
            "imported public export hashes",
            "import map",
            "export map",
            "export bundle entries",
            "pre-5.3 graph data (package ids plus "
            "per-package bundle counts)",
        ],
        "not_decoded": [
            {"item": "dependency-bundle sections",
             "status": "located-and-measured-not-decoded"},
            {"item": "imported-package-name contents",
             "status": "located-and-measured-not-decoded"},
            {"item": "Zen export property streams",
             "status": "located-and-measured-not-decoded"},
            {"item": "Verse cell import/export map "
                     "contents",
             "status": "located-and-measured-not-decoded"},
        ],
        "requires_usmap": {
            "item": ("property streams of Zen packages "
                     "flagged PKG_UnversionedProperties"),
            "requirement": ".usmap",
            "status": "requires-usmap",
        },
    }


class ZenError(Exception):
    pass


def is_zen_package(data):
    """The Zen trait: the chunk does NOT open with the
    classic package magic (a Zen header sits there
    instead) and carries the package magic as its last
    four bytes."""
    return len(data) >= 8 \
        and data[:4] != PACKAGE_MAGIC_LE \
        and data[-4:] == PACKAGE_MAGIC_LE


class _Reader:
    def __init__(self, data, base=0):
        self.data = data
        self.pos = base

    def take(self, n):
        if n < 0 or self.pos + n > len(self.data):
            raise ZenError(
                f"unexpected end of chunk at {self.pos} (+{n})")
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

    def i64(self):
        return struct.unpack("<q", self.take(8))[0]

    def guid(self):
        return self.take(16).hex()


def _flag_names(flags, table):
    return [name for bit, name in sorted(table.items())
            if flags & bit]


def _mapped_name(index_word, number):
    return {
        "index": index_word & 0x3FFFFFFF,
        "map": MAPPED_NAME_TYPES[(index_word >> 30) & 0x3],
        "map_bits": (index_word >> 30) & 0x3,
        "number": number,
    }


def _object_index(value):
    kind = (value >> 62) & 0x3
    return {
        "raw": f"0x{value:016x}",
        "type": OBJECT_INDEX_TYPES[kind],
        "value": value & ((1 << 62) - 1),
    }


class _ZenPackage:
    """One parse in flight: bytes, layout, tables."""

    def __init__(self, data):
        self.data = data
        self.names = []
        self.imports = []
        self.exports = []
        self.hashes = []
        self.bulk_data_map_prefix = None

    # -- name / index resolution ---------------------------------
    def resolve_mapped(self, mapped):
        """Resolve an FMappedName against this package's
        name map. Returns the display string, or None
        when the name lives in a map a lone chunk does
        not carry (container/global) or outside the map."""
        if mapped["map"] != "package":
            return None
        index = mapped["index"]
        if not 0 <= index < len(self.names):
            return None
        base = self.names[index]
        if mapped["number"] > 0:
            return f"{base}_{mapped['number'] - 1}"
        return base

    def mapped_record(self, mapped):
        rec = dict(mapped)
        resolved = self.resolve_mapped(mapped)
        if resolved is not None:
            rec["resolved"] = resolved
        elif mapped["map"] != "package":
            rec["note"] = (
                f"{mapped['map']}-map name: resolves "
                "through a name map a lone package chunk "
                "does not carry")
        else:
            rec["note"] = (
                "name index outside this package's "
                "name map")
        return rec

    def resolve_object_index(self, value):
        """Decode an FPackageObjectIndex and, where the
        chunk itself carries the target, resolve it."""
        rec = _object_index(value)
        kind = rec["type"]
        v = rec["value"]
        if kind == "export":
            index = v & 0xFFFFFFFF
            rec["export_index"] = index
            if index < len(self.exports):
                rec["resolved"] = \
                    self.exports[index].get("object_name")
            else:
                rec["note"] = ("export index outside "
                               "the export map")
        elif kind == "script-import":
            rec["script_object_index"] = v
            rec["note"] = (
                "script imports resolve through the "
                "container's global script-object table, "
                "which a lone package chunk does not "
                "carry")
        elif kind == "package-import":
            rec["imported_package_index"] = v >> 32
            hash_index = v & 0xFFFFFFFF
            rec["public_export_hash_index"] = hash_index
            if hash_index < len(self.hashes):
                rec["public_export_hash"] = \
                    f"0x{self.hashes[hash_index]:016x}"
            else:
                rec["note"] = (
                    "public export hash index outside "
                    "this package's imported-public-"
                    "export-hash table")
            for imp in self.imports:
                if imp["raw_value"] == value:
                    rec["import_map_index"] = imp["index"]
                    break
        else:  # null
            if value != OBJECT_INDEX_INVALID:
                rec["note"] = ("null-typed object index "
                               "with a nonzero payload")
        return rec

    def ref_text(self, value):
        rec = self.resolve_object_index(value)
        kind = rec["type"]
        if kind == "export":
            name = rec.get("resolved")
            return (f"export[{rec['export_index']}] "
                    f"{name}" if name else
                    f"export[{rec['export_index']}] "
                    "(unresolved)")
        if kind == "script-import":
            return f"script-import #{rec['script_object_index']}"
        if kind == "package-import":
            text = (f"package-import "
                    f"(imported package "
                    f"{rec['imported_package_index']}, "
                    f"public export hash "
                    f"#{rec['public_export_hash_index']}")
            if rec.get("public_export_hash"):
                text += f" = {rec['public_export_hash']}"
            return text + ")"
        return "null"

    # -- header ----------------------------------------------------
    def parse_summary(self, layout):
        """Read the FZenPackageSummary in one candidate
        layout. layout is 'ue5_3_plus', 'pre_ue5_3' or
        'ea_legacy'."""
        data = self.data
        if len(data) < 44:
            raise ZenError(
                f"chunk too small for a Zen header "
                f"({len(data)} bytes)")
        r = _Reader(data)
        s = {"layout": layout}
        if layout == "ea_legacy":
            s["has_versioning_info"] = False
            s["header_size"] = r.u32()
            name = _mapped_name(r.u32(), r.u32())
            s["package_flags"] = r.u32()
            s["cooked_header_size"] = r.u32()
            s["import_map_offset"] = r.i32()
            s["export_map_offset"] = r.i32()
            s["export_bundle_entries_offset"] = r.i32()
            s["graph_data_offset"] = r.i32()
            r.i32()  # reserved
            s["imported_public_export_hashes_offset"] = \
                s["import_map_offset"]
        else:
            flags_word = r.u32()
            s["has_versioning_info"] = bool(flags_word & 1)
            s["header_flags_word"] = flags_word
            s["header_size"] = r.u32()
            name = _mapped_name(r.u32(), r.u32())
            s["package_flags"] = r.u32()
            s["cooked_header_size"] = r.u32()
            s["imported_public_export_hashes_offset"] = \
                r.i32()
            s["import_map_offset"] = r.i32()
            s["export_map_offset"] = r.i32()
            s["export_bundle_entries_offset"] = r.i32()
            if layout == "ue5_3_plus":
                s["dependency_bundle_headers_offset"] = \
                    r.i32()
                s["dependency_bundle_entries_offset"] = \
                    r.i32()
                s["imported_package_names_offset"] = \
                    r.i32()
            else:
                s["graph_data_offset"] = r.i32()
        s["package_name_mapped"] = name
        s["package_flag_names"] = _flag_names(
            s["package_flags"], ZEN_PACKAGE_FLAGS)
        s["header_end"] = r.pos
        self.summary = s
        self._validate_summary()
        return s

    def _validate_summary(self):
        s = self.summary
        n = len(self.data)
        hs = s["header_size"]
        if hs <= s["header_end"] or hs > n:
            raise ZenError(
                f"Zen header size {hs} inconsistent with "
                f"the parsed summary (ends at "
                f"{s['header_end']}) and the chunk size {n}")
        chain = [
            s["imported_public_export_hashes_offset"],
            s["import_map_offset"],
            s["export_map_offset"],
            s["export_bundle_entries_offset"],
        ]
        for off in chain:
            if off < s["header_end"] or off > hs:
                raise ZenError(
                    f"section offset {off} outside the "
                    f"Zen header ({hs} bytes)")
        if any(b < a for a, b in zip(chain, chain[1:])):
            raise ZenError(
                "Zen section offsets are not in "
                "increasing order")
        for key in ("dependency_bundle_headers_offset",
                    "dependency_bundle_entries_offset",
                    "imported_package_names_offset",
                    "graph_data_offset"):
            off = s.get(key)
            if off is not None and not (0 <= off <= hs):
                raise ZenError(
                    f"{key} {off} outside the Zen header "
                    f"({hs} bytes)")

    def parse_versioning_info(self):
        r = _Reader(self.data, self.summary["header_end"])
        zen_version = r.u32()
        info = {
            "zen_version": zen_version,
            "zen_version_name": ZEN_VERSIONS.get(
                zen_version, f"v{zen_version}"),
            "file_version_ue4": r.i32(),
            "file_version_ue5": r.i32(),
            "file_version_licensee_ue": r.i32(),
        }
        count = r.i32()
        if count < 0 or count > 100_000:
            raise ZenError(
                f"implausible custom version count {count}")
        info["custom_versions"] = [
            {"guid": r.guid(), "version": r.i32()}
            for _ in range(count)]
        self.versioning_info = info
        return r.pos

    # -- name batch --------------------------------------------------
    def parse_name_batch(self, pos):
        """Parse the name batch at pos; returns the
        position just past it. The batch must account
        for its recorded string byte count exactly."""
        r = _Reader(self.data, pos)
        count = r.i32()
        if count < 0 or count > MAX_TABLE_ENTRIES:
            raise ZenError(
                f"implausible Zen name count {count}")
        # No early return for count == 0 (stability audit
        # B-06): the batch header still carries the string
        # byte count and the hash version, and the exact
        # byte-count check below validates them — returning
        # after the count alone misaligned every following
        # section and rejected valid zero-name packages.
        string_bytes = r.u32()
        if string_bytes > MAX_NAME_BATCH_BYTES:
            raise ZenError(
                f"implausible Zen name batch byte count "
                f"{string_bytes}")
        self.name_hash_version = r.u64()
        self.name_hashes = [r.u64() for _ in range(count)]
        headers = []
        for _ in range(count):
            b0 = r.u8()
            b1 = r.u8()
            headers.append((bool(b0 & 0x80),
                            ((b0 & 0x7F) << 8) | b1))
        names = []
        total = 0
        for utf16, length in headers:
            if utf16:
                raw = r.take(length * 2)
                names.append(raw.decode(
                    "utf-16-le", "replace"))
                total += length * 2
            else:
                raw = r.take(length)
                names.append(raw.decode(
                    "utf-8", "replace"))
                total += length
        if total != string_bytes:
            raise ZenError(
                f"Zen name batch decodes {total} string "
                f"bytes but records {string_bytes}")
        self.names = names
        return r.pos

    # -- offset-addressed sections -----------------------------------
    def _read_bulk_data_map(self, pos, target):
        """One classic bulk data map reading at pos: an
        int64 total size followed by that many bytes of
        32-byte entries, landing exactly on target.
        Returns (entries, end position)."""
        r = _Reader(self.data, pos)
        total_size = r.i64()
        if total_size < 0 or \
                total_size % BULK_DATA_MAP_ENTRY_SIZE:
            raise ZenError(
                f"bulk data map size {total_size} is not "
                f"a whole number of "
                f"{BULK_DATA_MAP_ENTRY_SIZE}-byte entries")
        if pos + 8 + total_size != target:
            raise ZenError(
                "bulk data map does not land exactly on "
                "the imported public export hashes section")
        entries = []
        for _ in range(total_size
                       // BULK_DATA_MAP_ENTRY_SIZE):
            entries.append({
                "serial_offset": r.u64(),
                "duplicate_serial_offset": r.u64(),
                "serial_size": r.u64(),
                "flags": r.u32(),
                "cooked_index": r.u8(),
            })
            r.take(3)  # padding to the 32-byte record
        return entries, r.pos

    def parse_bulk_data_map(self, pos):
        """The bulk data map sits between the name batch
        and the imported-public-export-hashes section.
        Returns (entries, end position). A zero gap
        means the map is absent.

        Newer writers place a count-prefixed byte array
        between the name batch and the map: an int64
        element count followed by that many bytes (all
        zero in every real package examined). That
        variant is accepted only when the classic map
        behind the array lands exactly on the hashes
        section, like every other layout rule here; the
        array itself is recorded on the package as
        located-and-measured, never decoded."""
        target = self.summary[
            "imported_public_export_hashes_offset"]
        if pos == target:
            return [], pos
        if pos > target or target - pos < 8:
            raise ZenError(
                "no room for a bulk data map before the "
                "imported public export hashes section")
        try:
            return self._read_bulk_data_map(pos, target)
        except ZenError as classic_error:
            r = _Reader(self.data, pos)
            count = r.i64()
            if count < 0 or count > MAX_TABLE_ENTRIES \
                    or pos + 8 + count + 8 > target:
                raise classic_error
            try:
                entries, end = self._read_bulk_data_map(
                    pos + 8 + count, target)
            except ZenError:
                raise classic_error
            raw = self.data[pos + 8:pos + 8 + count]
            self.bulk_data_map_prefix = {
                "element_count": count,
                "size_bytes": 8 + count,
                "nonzero_byte_count": sum(
                    1 for b in raw if b),
                "note": "a count-prefixed byte array "
                        "sits between the name batch "
                        "and the bulk data map in this "
                        "writer's Zen layout; it is "
                        "located and measured here, "
                        "its contents are not decoded",
            }
            return entries, end

    def parse_hashes(self):
        s = self.summary
        start = s["imported_public_export_hashes_offset"]
        end = s["import_map_offset"]
        if (end - start) % OBJECT_INDEX_SIZE:
            raise ZenError(
                "imported public export hashes section "
                "is not a whole number of uint64 entries")
        r = _Reader(self.data, start)
        self.hashes = [r.u64()
                       for _ in range((end - start) // 8)]
        return self.hashes

    def parse_imports(self):
        """Decode the import map. Export-typed entries
        are resolved in a post-pass, once the export
        map exists (see resolve_imports)."""
        s = self.summary
        start = s["import_map_offset"]
        end = s["export_map_offset"]
        if (end - start) % OBJECT_INDEX_SIZE:
            raise ZenError(
                "Zen import map is not a whole number "
                "of 64-bit object indices")
        r = _Reader(self.data, start)
        imports = []
        for i in range((end - start) // 8):
            value = r.u64()
            rec = _object_index(value)
            rec["index"] = i
            rec["raw_value"] = value
            kind = rec["type"]
            v = rec["value"]
            if kind == "export":
                rec["export_index"] = v & 0xFFFFFFFF
            elif kind == "script-import":
                rec["script_object_index"] = v
                rec["note"] = (
                    "script imports resolve through the "
                    "container's global script-object "
                    "table, which a lone package chunk "
                    "does not carry")
            elif kind == "package-import":
                rec["imported_package_index"] = v >> 32
                hash_index = v & 0xFFFFFFFF
                rec["public_export_hash_index"] = hash_index
                if hash_index < len(self.hashes):
                    rec["public_export_hash"] = \
                        f"0x{self.hashes[hash_index]:016x}"
                else:
                    rec["note"] = (
                        "public export hash index outside "
                        "this package's imported-public-"
                        "export-hash table")
            elif value != OBJECT_INDEX_INVALID:
                rec["note"] = ("null-typed object index "
                               "with a nonzero payload")
            imports.append(rec)
        self.imports = imports
        return imports

    def resolve_imports(self):
        for imp in self.imports:
            if imp["type"] != "export":
                continue
            index = imp["export_index"]
            if index < len(self.exports):
                imp["resolved"] = \
                    self.exports[index].get("object_name")
            else:
                imp["note"] = ("export index outside "
                               "the export map")

    def parse_exports(self):
        s = self.summary
        start = s["export_map_offset"]
        end = s["export_bundle_entries_offset"]
        if (end - start) % EXPORT_MAP_ENTRY_SIZE:
            raise ZenError(
                "Zen export map is not a whole number of "
                f"{EXPORT_MAP_ENTRY_SIZE}-byte entries")
        r = _Reader(self.data, start)
        exports = []
        for i in range((end - start)
                       // EXPORT_MAP_ENTRY_SIZE):
            entry_start = r.pos
            exp = {"index": i}
            exp["cooked_serial_offset"] = r.u64()
            exp["cooked_serial_size"] = r.u64()
            exp["object_name_mapped"] = _mapped_name(
                r.u32(), r.u32())
            exp["outer_index"] = r.u64()
            exp["class_index"] = r.u64()
            exp["super_index"] = r.u64()
            exp["template_index"] = r.u64()
            exp["public_export_hash"] = \
                f"0x{r.u64():016x}"
            exp["object_flags"] = r.u32()
            exp["object_flag_names"] = _flag_names(
                exp["object_flags"], OBJECT_FLAGS)
            exp["filter_flags"] = r.u8()
            r.take(3)  # padding to the 72-byte record
            if r.pos != entry_start + EXPORT_MAP_ENTRY_SIZE:
                raise ZenError("export map entry mis-sized")
            exports.append(exp)
        self.exports = exports
        # Names first, references second: an export may
        # reference a LATER export (a class or outer
        # defined further down the map), so every
        # object_name must exist before any ref resolves.
        for exp in exports:
            exp["object_name"] = self.resolve_mapped(
                exp["object_name_mapped"])
            if exp["object_name"] is None:
                exp["object_name_note"] = (
                    "object name does not resolve through "
                    "this package's name map")
        for exp in exports:
            for key in ("outer", "class", "super",
                        "template"):
                exp[f"{key}_resolved"] = self.ref_text(
                    exp[f"{key}_index"])
            exp["data_location"] = self.locate_range(
                exp["cooked_serial_offset"],
                exp["cooked_serial_size"])
            exp["properties"] = self.export_properties(exp)
        return exports

    def locate_range(self, cooked_offset, size):
        """An export's serialized data starts at
        (header size + cooked serial offset) in the
        chunk — the cooked offsets count from the end
        of a cooked header of CookedHeaderSize, and the
        Zen header stands in for it inside the chunk."""
        if size == 0:
            return {"file": None, "offset": None,
                    "note": "zero-size export"}
        start = self.summary["header_size"] + cooked_offset
        if 0 <= start and start + size <= len(self.data):
            return {"file": "package", "offset": start}
        return {"file": None, "offset": None,
                "note": "serial range runs past this "
                        "chunk (the export's data "
                        "continues in a linked chunk)"}

    def export_properties(self, exp):
        flags = self.summary["package_flags"]
        if flags & PKG_UNVERSIONED_PROPERTIES:
            return {
                "status": "unversioned",
                "note": "package is flagged "
                        "PKG_UnversionedProperties: "
                        "properties are serialized without "
                        "names or types and need a .usmap "
                        "mapping file, which is out of "
                        "scope",
            }
        if exp["cooked_serial_size"] == 0:
            return {"status": "empty",
                    "note": "export carries no serial data"}
        return {
            "status": "located",
            "note": "export payload located and measured; "
                    "versioned Zen property tag streams "
                    "(mapped-name tags) are not decoded "
                    "by this build",
        }

    def parse_bundle_entries(self, pos):
        count = len(self.exports) * 2
        r = _Reader(self.data, pos)
        entries = []
        for i in range(count):
            local = r.u32()
            command = r.u32()
            if local >= len(self.exports):
                raise ZenError(
                    f"export bundle entry {i} names "
                    f"export {local}, outside the export "
                    f"map ({len(self.exports)} exports)")
            entries.append({
                "local_export_index": local,
                "command_type": command,
                "command_type_name":
                    EXPORT_COMMAND_TYPES.get(
                        command, f"type{command}"),
            })
        return entries, r.pos

    # -- trailing sections -------------------------------------------
    def trailing_sections(self):
        """Sections the offset table locates but whose
        contents no public reader decodes (dependency
        bundles, imported package names), plus the
        pre-5.3 graph data, which IS decoded when it
        consumes its region exactly."""
        s = self.summary
        hs = s["header_size"]
        out = []
        self.imported_package_ids = None
        if s["layout"] == "ue5_3_plus":
            spans = [
                ("dependency bundle headers",
                 s["dependency_bundle_headers_offset"],
                 s["dependency_bundle_entries_offset"]),
                ("dependency bundle entries",
                 s["dependency_bundle_entries_offset"],
                 s["imported_package_names_offset"]),
                ("imported package names",
                 s["imported_package_names_offset"], hs),
            ]
            for label, start, end in spans:
                if end > start:
                    out.append({
                        "section": label,
                        "offset": start,
                        "size": end - start,
                        "note": "located from the Zen "
                                "offset table and "
                                "measured; its layout is "
                                "not decoded by the "
                                "public readers this "
                                "parser is built from, "
                                "and neither is it here",
                    })
            return out
        graph_off = s.get("graph_data_offset")
        if graph_off is not None and graph_off < hs:
            ids = self._try_graph_data(graph_off, hs)
            if ids is not None:
                self.imported_package_ids = ids
            else:
                out.append({
                    "section": "graph data",
                    "offset": graph_off,
                    "size": hs - graph_off,
                    "note": "located from the Zen offset "
                            "table and measured; the "
                            "region does not match the "
                            "documented graph-data layout "
                            "exactly, so its contents are "
                            "not decoded",
                })
        return out

    def _try_graph_data(self, start, end):
        """Documented graph data: an int32 package
        count, then per package a uint64 package id, an
        int32 bundle count, and that many 8-byte arc
        records (skipped). Accepted only on exact
        consumption of the region."""
        try:
            r = _Reader(self.data, start)
            count = r.i32()
            if count < 0 or count > 100_000:
                return None
            ids = []
            for _ in range(count):
                package_id = r.u64()
                bundle_count = r.i32()
                if bundle_count < 0 or bundle_count > 100_000:
                    return None
                r.take(bundle_count * 8)
                ids.append({
                    "package_id": f"0x{package_id:016x}",
                    "bundle_count": bundle_count,
                })
            if r.pos != end:
                return None
            return ids
        except ZenError:
            return None


def _parse_with_layout(data, layout, cells):
    pkg = _ZenPackage(data)
    summary = pkg.parse_summary(layout)
    pos = summary["header_end"]
    if summary["has_versioning_info"]:
        pos = pkg.parse_versioning_info()
    cell_offsets = None
    if cells:
        r = _Reader(data, pos)
        cell_offsets = {
            "cell_import_map_offset": r.i32(),
            "cell_export_map_offset": r.i32(),
        }
        pos = r.pos
        # The cell offsets address the header region; a
        # negative or out-of-header value is corrupt and
        # must fail as ZenError here, not as a bare
        # struct.error from a negatively-based reader
        # downstream (stability audit B-07).
        for key, off in cell_offsets.items():
            if off < 0 or off > summary["header_size"]:
                raise ZenError(
                    f"Verse {key} {off} outside the "
                    f"header (size "
                    f"{summary['header_size']})")
    summary["name_map_offset"] = pos
    pos = pkg.parse_name_batch(pos)
    bulk, pos = pkg.parse_bulk_data_map(pos)
    pkg.parse_hashes()
    pkg.parse_imports()
    pkg.parse_exports()
    pkg.resolve_imports()
    for imp in pkg.imports:
        imp.pop("raw_value", None)
    bundle_start = summary["export_bundle_entries_offset"]
    if cell_offsets is not None:
        bundle_start = cell_offsets["cell_import_map_offset"]
        cell_offsets["note"] = (
            "Verse cell import/export maps are located "
            "through these offsets; their contents are "
            "not decoded by this build")
        summary["cell_offsets"] = cell_offsets
    bundle_entries, bundle_end = pkg.parse_bundle_entries(
        bundle_start)
    # The bundle-entry table must not run past the header
    # (stability audit B-07's safety half). It is NOT
    # required to land exactly on the header size: real
    # packages carry further header content after the
    # entries, so an exact-landing rule here would reject
    # valid packages — the audit's exactness expectation
    # was checked against the corpus and does not hold
    # for this section.
    if bundle_end > summary["header_size"]:
        raise ZenError(
            f"export bundle entries end at {bundle_end}, "
            f"past the header size "
            f"{summary['header_size']}")
    sections = pkg.trailing_sections()
    summary["package_name"] = pkg.resolve_mapped(
        summary["package_name_mapped"])
    if summary["package_name"] is None:
        summary["package_name_note"] = (
            "the package's own name does not resolve "
            "through this package's name map")
    if data[-4:] != PACKAGE_MAGIC_LE:
        raise ZenError(
            "chunk does not carry the package magic "
            "trailer")
    result = {
        "format": "zen-package",
        "size": len(data),
        "summary": summary,
        "names": pkg.names,
        "bulk_data_map": bulk,
        "imported_public_export_hashes": [
            f"0x{h:016x}" for h in pkg.hashes],
        "imports": pkg.imports,
        "exports": pkg.exports,
        "export_bundle_entries": bundle_entries,
        "sections_not_decoded": sections,
        "trailer_magic_ok": True,
        "counts": {
            "names": len(pkg.names),
            "imports": len(pkg.imports),
            "exports": len(pkg.exports),
            "imported_public_export_hashes":
                len(pkg.hashes),
            "bulk_data_map": len(bulk),
            "export_bundle_entries": len(bundle_entries),
        },
    }
    if pkg.bulk_data_map_prefix is not None:
        result["bulk_data_map_prefix"] = \
            pkg.bulk_data_map_prefix
    if pkg.imported_package_ids is not None:
        result["imported_package_ids"] = \
            pkg.imported_package_ids
        result["counts"]["imported_packages"] = \
            len(pkg.imported_package_ids)
    if getattr(pkg, "versioning_info", None) is not None:
        summary["versioning_info"] = pkg.versioning_info
        summary["file_version_ue4"] = \
            pkg.versioning_info["file_version_ue4"]
        summary["file_version_ue5"] = \
            pkg.versioning_info["file_version_ue5"]
    else:
        summary["versioning_note"] = VERSIONING_NOTE
    return result


def parse_zen_package(data, name=""):
    """Parse Zen package chunk bytes into a full
    inspection dict.

    Layout candidates (current, pre-5.3, Early Access
    legacy; each with and without Verse cell offsets)
    are tried in order and accepted only when every
    section validates end to end; anything else raises
    ZenError with the reasons.
    """
    if len(data) < 8:
        raise ZenError(
            f"chunk too small for a Zen package "
            f"({len(data)} bytes)")
    if data[:4] == PACKAGE_MAGIC_LE:
        raise ZenError(
            "chunk opens with the classic package magic: "
            "it is a classic package, not a Zen package")
    errors = []
    for layout in ("ue5_3_plus", "pre_ue5_3", "ea_legacy"):
        for cells in (False, True):
            if layout == "ea_legacy" and cells:
                continue
            try:
                result = _parse_with_layout(
                    data, layout, cells)
                result["name"] = name
                return result
            except ZenError as e:
                errors.append(
                    f"{layout}"
                    f"{' +cells' if cells else ''}: {e}")
    raise ZenError(
        "no Zen layout fits this chunk (" +
        "; ".join(errors) + ")")
