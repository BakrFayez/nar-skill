"""Pure-Python Unreal package (.uasset / .umap) inspector.

Implements the publicly documented Unreal package format
(the layout the open-source UAssetAPI and CUE4Parse readers
implement) for cooked and uncooked packages:

- FPackageFileSummary with version gating across the UE4
  object versions (434, the oldest loadable, through 522)
  and the UE5 object versions (1000+): magic, legacy file
  version, custom-version container, package flags, total
  header size, and every table count/offset pair, including
  the UE5-only fields (saved hash, soft object path list,
  Verse cell tables, metadata offset, payload TOC, data
  resources, import type hierarchies).
- The name table (FString entries plus the two 16-bit name
  hashes serialized from UE4 object version 504), the
  import map, the export map, the per-export depends map,
  soft package references, the UE5 soft object path list,
  and the searchable-names map. Package indices and FNames
  are resolved to readable object references.
- Cooked-package awareness: an export's serial range is
  located in the package file itself or in the sibling
  .uexp (serial offsets count across the virtual
  concatenation of the two), and bulk data is reported as
  living in the .ubulk when BulkDataStartOffset runs past
  the package bytes.
- A best-effort FPropertyTag stream reader for versioned
  properties: tag name/type/size/array index, the stable
  tag-header extras (struct name + GUID, bool value, enum
  names, array inner type, the property-GUID field),
  scalar value decoding for
  the primitive property types, and recursion into struct
  values and struct arrays. Every property result carries
  an explicit confidence note; anything the bytes do not
  support is reported, never invented.

Unversioned packages (both object versions zero, the
usual IoStore-era cooking) are parsed under a stated
assumption and accepted only when the structure
validates end to end; the assumption is recorded in the
result. The assumption is the final UE4 table layout,
plus -- when the summary carries the UE5 version field
(legacy file version -8), marking the package as a UE5
one -- the UE5 1010 table layout. Packages flagged
PKG_UnversionedProperties carry no tag stream to read
(their properties need a .usmap mapping file, which is
out of scope). The UE5 tag-extension layouts are parsed
for versioned packages: object version 1011 (property
tag extensions: a trailing extension byte, plus an
overridable-serialization payload when its flag is set)
and 1012+ (complete type names: the type FName is
replaced by an FPropertyTypeName node tree, the array
index / GUID / extensions move behind a flags byte, and
the bool value rides in that byte). No real package
with a recorded UE5 object version >= 1011 exists in
the corpus (shipped UE5 titles strip versions or use
Zen), so those two layouts are verified against
SYNTHETIC packages built to the documented format and
are labeled synthetic wherever they are reported.
Encrypted content is never touched: this module parses
plain package bytes only.
"""
import struct

MAGIC = 0x9E2A83C1
OLDEST_LOADABLE_UE4 = 434
FINAL_UE4 = 522
# Assumed UE5 object version for an unversioned package whose
# summary carries the UE5 version field (legacy file version
# -8): the newest UE5 table layout this parser reads end to
# end. (Versioned packages recorded at 1011+ take the
# tag-extension layouts in the property reader instead.)
ASSUMED_UE5_FOR_UNVERSIONED = 1010

# EPackageFlags (only the bits with a documented name).
PACKAGE_FLAGS = {
    0x00000001: "PKG_NewlyCreated",
    0x00000002: "PKG_ClientOptional",
    0x00000004: "PKG_ServerSideOnly",
    0x00000010: "PKG_CompiledIn",
    0x00000020: "PKG_ForDiffing",
    0x00000040: "PKG_EditorOnly",
    0x00000080: "PKG_Developer",
    0x00000100: "PKG_UncookedOnly",
    0x00000200: "PKG_Cooked",
    0x00000400: "PKG_ContainsNoAsset",
    0x00002000: "PKG_UnversionedProperties",
    0x00004000: "PKG_ContainsMapData",
    0x00010000: "PKG_Compiling",
    0x00020000: "PKG_ContainsMap",
    0x00040000: "PKG_RequiresLocalizationGather",
    0x00100000: "PKG_PlayInEditor",
    0x00200000: "PKG_ContainsScript",
    0x00400000: "PKG_DisallowExport",
    0x10000000: "PKG_DynamicImports",
    0x20000000: "PKG_RuntimeGenerated",
    0x40000000: "PKG_ReloadingForCooker",
    0x80000000: "PKG_FilterEditorOnly",
}
PKG_UNVERSIONED_PROPERTIES = 0x00002000
PKG_FILTER_EDITOR_ONLY = 0x80000000

# EObjectFlags (RF_*), documented names only.
OBJECT_FLAGS = {
    0x00000001: "RF_Public",
    0x00000002: "RF_Standalone",
    0x00000004: "RF_MarkAsNative",
    0x00000008: "RF_Transactional",
    0x00000010: "RF_ClassDefaultObject",
    0x00000020: "RF_ArchetypeObject",
    0x00000040: "RF_Transient",
    0x00000080: "RF_MarkAsRootSet",
    0x00000100: "RF_TagGarbageTemp",
    0x00000200: "RF_NeedInitialization",
    0x00000400: "RF_NeedLoad",
    0x00000800: "RF_KeepForCooker",
    0x00001000: "RF_NeedPostLoad",
    0x00002000: "RF_NeedPostLoadSubobjects",
    0x00004000: "RF_NewerVersionExists",
    0x00008000: "RF_BeginDestroyed",
    0x00010000: "RF_FinishDestroyed",
    0x00020000: "RF_BeingRegenerated",
    0x00040000: "RF_DefaultSubObject",
    0x00080000: "RF_WasLoaded",
    0x00100000: "RF_TextExportTransient",
    0x00200000: "RF_LoadCompleted",
    0x00400000: "RF_InheritableComponentTemplate",
    0x00800000: "RF_DuplicateTransient",
    0x01000000: "RF_StrongRefOnFrame",
    0x02000000: "RF_NonPIEDuplicateTransient",
    0x04000000: "RF_Dynamic",
    0x08000000: "RF_WillBeLoaded",
    0x10000000: "RF_HasExternalPackage",
}

MAX_TABLE_ENTRIES = 10_000_000
MAX_TAGS_PER_EXPORT = 512
MAX_TAG_DEPTH = 4

PROPERTY_CONFIDENCE = (
    "best-effort: versioned FPropertyTag layout with the "
    "documented tag-header extras; values are decoded only "
    "for primitive types whose encoding is version-stable, "
    "and any stream inconsistency stops the parse of that "
    "export instead of emitting guessed data")


class UAssetError(Exception):
    pass


class _Reader:
    def __init__(self, data, base=0):
        self.data = data
        self.pos = base

    def take(self, n):
        if n < 0 or self.pos + n > len(self.data):
            raise UAssetError(
                f"unexpected end of package at {self.pos} (+{n})")
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

    def i64(self):
        return struct.unpack("<q", self.take(8))[0]

    def guid(self):
        return self.take(16).hex()

    def fstring(self):
        n = self.i32()
        if n == 0:
            return ""
        if n > 0:
            if n > len(self.data):
                raise UAssetError(f"implausible FString length {n}")
            return self.take(n).rstrip(b"\x00").decode(
                "utf-8", "replace")
        count = -n
        if count * 2 > len(self.data):
            raise UAssetError(f"implausible FString length {n}")
        return self.take(count * 2).decode(
            "utf-16-le", "replace").rstrip("\x00")


def _flag_names(flags, table):
    return [name for bit, name in sorted(table.items())
            if flags & bit]


def _engine_version(r):
    return {
        "major": r.u16(),
        "minor": r.u16(),
        "patch": r.u16(),
        "changelist": r.u32(),
        "branch": r.fstring(),
    }


class _Package:
    """One parse in flight: bytes, versions, tables."""

    def __init__(self, data, uexp_data):
        self.data = data
        self.uexp = uexp_data
        self.names = []
        self.imports = []
        self.exports = []

    # -- name / index resolution ------------------------------------
    def fname(self, r):
        index = r.i32()
        number = r.i32()
        return self._fname_pair(index, number)

    def _fname_pair(self, index, number):
        if not 0 <= index < len(self.names):
            raise UAssetError(
                f"FName index {index} outside the name table "
                f"({len(self.names)} names)")
        base = self.names[index]
        if number > 0:
            return f"{base}_{number - 1}"
        return base

    def fname_soft(self, index, number):
        """Resolve without raising (property stream use)."""
        if not 0 <= index < len(self.names):
            return None
        base = self.names[index]
        if number > 0:
            return f"{base}_{number - 1}"
        return base

    def resolve_index(self, index):
        """Resolve a package index to a readable reference."""
        if index == 0:
            return {"kind": "none", "index": None}
        if index > 0:
            if index - 1 < len(self.exports):
                exp = self.exports[index - 1]
                return {"kind": "export", "index": index - 1,
                        "object_name": exp["object_name"],
                        "class_name": exp.get("class_resolved")}
            return {"kind": "export", "index": index - 1,
                    "object_name": None,
                    "note": "export index outside the export map"}
        imp_i = -index - 1
        if imp_i < len(self.imports):
            imp = self.imports[imp_i]
            return {"kind": "import", "index": imp_i,
                    "object_name": imp["object_name"],
                    "class_name": imp["class_name"],
                    "class_package": imp["class_package"]}
        return {"kind": "import", "index": imp_i,
                "object_name": None,
                "note": "import index outside the import map"}

    def ref_text(self, index):
        ref = self.resolve_index(index)
        if ref["kind"] == "none":
            return None
        if ref.get("object_name"):
            return (f"{ref['kind']}[{ref['index']}] "
                    f"{ref['object_name']}")
        return f"{ref['kind']}[{ref['index']}] (unresolved)"

    # -- summary ------------------------------------------------------
    def parse_summary(self):
        data = self.data
        if len(data) < 28:
            raise UAssetError(
                f"package too small for a summary ({len(data)} bytes)")
        r = _Reader(data)
        tag = r.u32()
        if tag != MAGIC:
            raise UAssetError(
                f"bad package magic 0x{tag:08X} "
                f"(expected 0x{MAGIC:08X})")
        legacy = r.i32()
        if legacy > 0 or legacy < -8:
            raise UAssetError(
                f"unsupported legacy file version {legacy} "
                "(this parser covers UE4/UE5 packages, legacy "
                "file versions -1 to -8)")
        s = {"legacy_file_version": legacy}
        if legacy != -4:
            s["legacy_ue3_version"] = r.i32()
        s["file_version_ue4"] = r.i32()
        s["file_version_ue5"] = None
        if legacy <= -8:
            s["file_version_ue5"] = r.i32()
        s["file_version_licensee_ue"] = r.i32()
        raw4 = s["file_version_ue4"]
        raw5 = s["file_version_ue5"] or 0
        self.unversioned = (raw4 == 0 and raw5 == 0)
        if raw4 != 0 and raw4 < OLDEST_LOADABLE_UE4:
            raise UAssetError(
                f"UE4 object version {raw4} predates the oldest "
                f"loadable package version ({OLDEST_LOADABLE_UE4})")
        # Effective versions drive every gate below. A real
        # UE5 package carries UE4 version 522 itself; an
        # unversioned package is read under the stated
        # final-UE4 assumption and must validate structurally.
        self.eff4 = raw4 if raw4 else FINAL_UE4
        self.eff5 = raw5
        if self.unversioned and legacy <= -8:
            # A legacy -8 summary carries the UE5 object
            # version field; finding it zero means a UE5
            # package whose versions were stripped at cook
            # time (the unversioned-content path). Its tables
            # follow the UE5 layout, so the UE5 gates need an
            # assumed version too, exactly as the real loader
            # substitutes its own current version when loading
            # unversioned content. The assumption is the
            # newest UE5 layout this parser reads end to end;
            # a package cooked by a newer engine will fail
            # the structural validation below rather than
            # parse into garbage.
            self.eff5 = ASSUMED_UE5_FOR_UNVERSIONED
        s["unversioned"] = self.unversioned
        if self.unversioned:
            if legacy <= -8:
                s["version_assumption"] = (
                    "package carries no object versions; "
                    "tables were read with the final UE4 (522) "
                    "layout and the UE5 1010 layout, and "
                    "accepted only because the structure "
                    "validates end to end")
            else:
                s["version_assumption"] = (
                    "package carries no object versions; tables "
                    "were read with the final UE4 (522) layout "
                    "and accepted only because the structure "
                    "validates end to end")
        if self.eff5 >= 1016:
            s["saved_hash"] = r.take(20).hex()
            s["total_header_size"] = r.i32()
        if legacy <= -2:
            if legacy == -2:
                raise UAssetError(
                    "legacy file version -2 stores custom "
                    "versions as enums; that form is not "
                    "supported by this parser")
            count = r.i32()
            if count < 0 or count > 100_000:
                raise UAssetError(
                    f"implausible custom version count {count}")
            custom = []
            for _ in range(count):
                entry = {"guid": r.guid(), "version": r.i32()}
                if -5 <= legacy <= -3:
                    entry["friendly_name"] = r.fstring()
                custom.append(entry)
            s["custom_versions"] = custom
        if self.eff5 < 1016:
            s["total_header_size"] = r.i32()
        s["folder_name"] = r.fstring()
        s["package_flags"] = r.u32()
        s["package_flag_names"] = _flag_names(
            s["package_flags"], PACKAGE_FLAGS)
        self.package_flags = s["package_flags"]
        s["name_count"] = r.i32()
        s["name_offset"] = r.i32()
        if self.eff5 >= 1008:
            s["soft_object_paths_count"] = r.i32()
            s["soft_object_paths_offset"] = r.i32()
        filter_editor_only = bool(
            s["package_flags"] & PKG_FILTER_EDITOR_ONLY)
        if self.eff4 >= 516 and not filter_editor_only:
            s["localization_id"] = r.fstring()
        if self.eff4 >= 459:
            s["gatherable_text_data_count"] = r.i32()
            s["gatherable_text_data_offset"] = r.i32()
        s["export_count"] = r.i32()
        s["export_offset"] = r.i32()
        s["import_count"] = r.i32()
        s["import_offset"] = r.i32()
        if self.eff5 >= 1015:
            s["cell_export_count"] = r.i32()
            s["cell_export_offset"] = r.i32()
            s["cell_import_count"] = r.i32()
            s["cell_import_offset"] = r.i32()
        if self.eff5 >= 1014:
            s["meta_data_offset"] = r.i32()
        s["depends_offset"] = r.i32()
        if self.eff4 >= 384:
            s["soft_package_references_count"] = r.i32()
            s["soft_package_references_offset"] = r.i32()
        if self.eff4 >= 510:
            s["searchable_names_offset"] = r.i32()
        s["thumbnail_table_offset"] = r.i32()
        if self.eff5 >= 1018:
            s["import_type_hierarchies_count"] = r.i32()
            s["import_type_hierarchies_offset"] = r.i32()
        if self.eff5 < 1016:
            s["guid"] = r.guid()
        if self.eff4 >= 518 and not filter_editor_only:
            s["persistent_guid"] = r.guid()
            if self.eff4 in (518, 519):
                # An owner GUID was serialized in exactly
                # these two versions and removed in 520.
                s["owner_guid_removed_in_520"] = r.guid()
        gen_count = r.i32()
        if gen_count < 0 or gen_count > 100_000:
            raise UAssetError(
                f"implausible generation count {gen_count}")
        s["generations"] = [
            {"export_count": r.i32(), "name_count": r.i32()}
            for _ in range(gen_count)]
        if self.eff4 >= 336:
            s["saved_by_engine_version"] = _engine_version(r)
        else:
            s["saved_by_changelist"] = r.u32()
        if self.eff4 >= 444:
            s["compatible_with_engine_version"] = \
                _engine_version(r)
        s["compression_flags"] = r.u32()
        chunk_count = r.i32()
        if chunk_count < 0 or chunk_count > 100_000:
            raise UAssetError(
                f"implausible compressed chunk count {chunk_count}")
        s["compressed_chunks"] = [
            {"uncompressed_offset": r.i64(),
             "compressed_offset": r.i64()}
            for _ in range(chunk_count)]
        if chunk_count:
            s["compression_note"] = (
                "package-level compressed chunks are "
                "inventoried; this parser reads uncompressed "
                "packages")
        s["package_source"] = r.u32()
        cook_count = r.i32()
        if cook_count < 0 or cook_count > 100_000:
            raise UAssetError(
                "implausible additional-packages-to-cook "
                f"count {cook_count}")
        s["additional_packages_to_cook"] = [
            r.fstring() for _ in range(cook_count)]
        if -6 <= legacy <= -2:
            s["num_texture_allocations"] = r.i32()
        s["asset_registry_data_offset"] = r.i32()
        s["bulk_data_start_offset"] = r.i64()
        if self.eff4 >= 224:
            s["world_tile_info_data_offset"] = r.i32()
        if self.eff4 >= 326:
            n = r.i32()
            if n < 0 or n > 100_000:
                raise UAssetError(f"implausible chunk id count {n}")
            s["chunk_ids"] = [r.i32() for _ in range(n)]
        elif self.eff4 >= 278:
            s["chunk_ids"] = [r.i32()]
        if self.eff4 >= 507:
            s["preload_dependency_count"] = r.i32()
            s["preload_dependency_offset"] = r.i32()
        if self.eff5 >= 1001:
            s["names_referenced_from_export_data_count"] = r.i32()
        if self.eff5 >= 1002:
            s["payload_toc_offset"] = r.i64()
        if self.eff5 >= 1009:
            s["data_resource_offset"] = r.i32()
        s["header_end"] = r.pos
        self.summary = s
        self._validate_summary()
        return s

    def _validate_summary(self):
        s = self.summary
        n = len(self.data)
        for key in ("name_count", "export_count", "import_count"):
            v = s[key]
            if v < 0 or v > MAX_TABLE_ENTRIES:
                raise UAssetError(f"implausible {key} {v}")
        for count_key, off_key in (
                ("name_count", "name_offset"),
                ("export_count", "export_offset"),
                ("import_count", "import_offset")):
            if s[count_key] and not (0 < s[off_key] < n):
                raise UAssetError(
                    f"{off_key} {s[off_key]} outside the "
                    f"package ({n} bytes) with {s[count_key]} "
                    "entries promised")
        ths = s["total_header_size"]
        if ths < s["header_end"] or ths > n:
            raise UAssetError(
                f"total header size {ths} inconsistent with "
                f"the parsed summary (ends at "
                f"{s['header_end']}) and the package size {n}")

    # -- tables ---------------------------------------------------------
    def parse_names(self):
        s = self.summary
        r = _Reader(self.data, s["name_offset"])
        names = []
        hashed = self.eff4 >= 504
        for _ in range(s["name_count"]):
            names.append(r.fstring())
            if hashed:
                r.u16()  # case-insensitive hash (not verified)
                r.u16()  # case-sensitive hash (not verified)
        self.names = names
        return names

    def parse_imports(self):
        s = self.summary
        if not s["import_count"]:
            self.imports = []
            return self.imports
        r = _Reader(self.data, s["import_offset"])
        filter_editor_only = bool(
            s["package_flags"] & PKG_FILTER_EDITOR_ONLY)
        imports = []
        for i in range(s["import_count"]):
            imp = {
                "index": i,
                "class_package": self.fname(r),
                "class_name": self.fname(r),
                "outer_index": r.i32(),
                "object_name": self.fname(r),
            }
            if self.eff4 >= 520 and not filter_editor_only:
                imp["package_name"] = self.fname(r)
            if self.eff5 >= 1003:
                imp["import_optional"] = bool(r.i32())
            imports.append(imp)
        self.imports = imports
        for imp in imports:
            imp["outer_resolved"] = self.ref_text(
                imp["outer_index"])
        return imports

    def parse_exports(self):
        s = self.summary
        if not s["export_count"]:
            self.exports = []
            return self.exports
        r = _Reader(self.data, s["export_offset"])
        wide = self.eff4 >= 511
        exports = []
        for i in range(s["export_count"]):
            exp = {"index": i}
            exp["class_index"] = r.i32()
            exp["super_index"] = r.i32()
            if self.eff4 >= 508:
                exp["template_index"] = r.i32()
            exp["outer_index"] = r.i32()
            exp["object_name"] = self.fname(r)
            exp["object_flags"] = r.u32()
            exp["object_flag_names"] = _flag_names(
                exp["object_flags"], OBJECT_FLAGS)
            exp["serial_size"] = r.i64() if wide else r.i32()
            exp["serial_offset"] = r.i64() if wide else r.i32()
            exp["forced_export"] = bool(r.i32())
            exp["not_for_client"] = bool(r.i32())
            exp["not_for_server"] = bool(r.i32())
            if self.eff5 < 1005:
                exp["package_guid"] = r.guid()
            if self.eff5 >= 1006:
                exp["is_inherited_instance"] = bool(r.i32())
            exp["package_flags"] = r.u32()
            if self.eff4 >= 365:
                exp["not_always_loaded_for_editor_game"] = \
                    bool(r.i32())
            if self.eff4 >= 485:
                exp["is_asset"] = bool(r.i32())
            if self.eff5 >= 1003:
                exp["generate_public_hash"] = bool(r.i32())
            if self.eff4 >= 507:
                exp["preload"] = {
                    "first_export_dependency_offset": r.i32(),
                    "serialization_before_serialization": r.i32(),
                    "create_before_serialization": r.i32(),
                    "serialization_before_create": r.i32(),
                    "create_before_create": r.i32(),
                }
            if self.eff5 >= 1010 and not (
                    s["package_flags"]
                    & PKG_UNVERSIONED_PROPERTIES):
                exp["script_serialization_start"] = r.i64()
                exp["script_serialization_end"] = r.i64()
            exports.append(exp)
        self.exports = exports
        for exp in exports:
            exp["class_resolved"] = self.ref_text(
                exp["class_index"])
            exp["super_resolved"] = self.ref_text(
                exp["super_index"])
            exp["outer_resolved"] = self.ref_text(
                exp["outer_index"])
            if "template_index" in exp:
                exp["template_resolved"] = self.ref_text(
                    exp["template_index"])
        self._resolve_preload_dependencies()
        return exports

    def _resolve_preload_dependencies(self):
        s = self.summary
        base = s.get("preload_dependency_offset") or 0
        if not base or base >= len(self.data):
            return
        cats = ("serialization_before_serialization",
                "create_before_serialization",
                "serialization_before_create",
                "create_before_create")
        for exp in self.exports:
            pre = exp.get("preload")
            if not pre:
                continue
            first = pre["first_export_dependency_offset"]
            total = sum(pre[c] for c in cats)
            if first < 0 or total < 0:
                continue
            pos = base + 4 * first
            if pos + 4 * total > len(self.data):
                pre["indices_note"] = (
                    "dependency indices run past the package; "
                    "counts kept, indices not resolved")
                continue
            r = _Reader(self.data, pos)
            indices = {}
            flat = []
            for c in cats:
                vals = [r.i32() for _ in range(pre[c])]
                indices[c] = vals
                flat.extend(vals)
            pre["indices"] = indices
            pre["indices_resolved"] = [
                self.ref_text(v) for v in flat]

    def parse_depends(self):
        s = self.summary
        off = s["depends_offset"]
        depends = []
        if not self.exports:
            self.depends = depends
            return depends
        if not off:
            self.depends = depends
            return depends
        r = _Reader(self.data, off)
        for _ in range(len(self.exports)):
            count = r.i32()
            if count < 0 or count > MAX_TABLE_ENTRIES:
                raise UAssetError(
                    f"implausible depends count {count}")
            idx = [r.i32() for _ in range(count)]
            depends.append({
                "indices": idx,
                "resolved": [self.ref_text(v) for v in idx],
            })
        self.depends = depends
        return depends

    def parse_soft_package_references(self):
        s = self.summary
        count = s.get("soft_package_references_count") or 0
        off = s.get("soft_package_references_offset") or 0
        refs = []
        if count and off:
            r = _Reader(self.data, off)
            refs = [r.fstring() for _ in range(count)]
        self.soft_package_references = refs
        return refs

    def parse_soft_object_paths(self):
        s = self.summary
        count = s.get("soft_object_paths_count") or 0
        off = s.get("soft_object_paths_offset") or 0
        paths = []
        if count and off:
            r = _Reader(self.data, off)
            for _ in range(count):
                if self.eff5 >= 1007:
                    asset_path = r.fstring()
                else:
                    asset_path = self.fname(r)
                paths.append({
                    "asset_path": asset_path,
                    "sub_path": r.fstring(),
                })
        self.soft_object_paths = paths
        return paths

    def parse_searchable_names(self):
        s = self.summary
        off = s.get("searchable_names_offset") or 0
        out = {}
        if not off:
            self.searchable_names = out
            return out
        r = _Reader(self.data, off)
        count = r.i32()
        if count < 0 or count > MAX_TABLE_ENTRIES:
            raise UAssetError(
                f"implausible searchable-names count {count}")
        for _ in range(count):
            key = self.fname(r)
            n = r.i32()
            if n < 0 or n > MAX_TABLE_ENTRIES:
                raise UAssetError(
                    f"implausible searchable-names value "
                    f"count {n}")
            out[key] = [r.i32() for _ in range(n)]
        self.searchable_names = out
        return out


    # -- export data location -------------------------------------------
    def locate_range(self, offset, size):
        """Map a virtual serial range to real bytes.

        Serial offsets count across the virtual
        concatenation of the package and its .uexp: a range
        fully inside the package bytes lives here; a range
        starting at or past TotalHeaderSize lives in the
        .uexp at (offset - TotalHeaderSize).
        """
        if size == 0:
            return {"file": None, "offset": None,
                    "note": "zero-size range"}
        if 0 <= offset and offset + size <= len(self.data):
            return {"file": "package", "offset": offset}
        ths = self.summary["total_header_size"]
        if self.uexp is not None and offset >= ths:
            adj = offset - ths
            if adj + size <= len(self.uexp):
                return {"file": "uexp", "offset": adj}
        return {"file": None, "offset": None,
                "note": "serial range runs past the package "
                        "and .uexp bytes available"}

    def range_bytes(self, offset, size):
        loc = self.locate_range(offset, size)
        if loc["file"] == "package":
            return self.data[offset:offset + size], loc
        if loc["file"] == "uexp":
            start = loc["offset"]
            return self.uexp[start:start + size], loc
        return None, loc

    # -- property stream (best effort) -----------------------------------
    def parse_properties(self, exp):
        """Parse one export's FPropertyTag stream.

        Returns a result dict; failures are captured in the
        result, never raised, and no value is emitted that
        the bytes did not support.
        """
        result = {"confidence": PROPERTY_CONFIDENCE}
        flags = self.summary["package_flags"]
        if flags & PKG_UNVERSIONED_PROPERTIES:
            result.update({
                "status": "unversioned",
                "note": "package is flagged "
                        "PKG_UnversionedProperties: properties "
                        "are serialized without names or types "
                        "and need a .usmap mapping file, which "
                        "is out of scope",
            })
            return result
        if self.eff5 >= 1012:
            result["tag_layout"] = "ue5-complete-type-name"
            result["verification"] = (
                "synthetic fixtures only: no real package "
                "with a recorded UE5 object version >= 1011 "
                "is available in the corpus, so this layout "
                "is verified against synthetic packages built "
                "to the documented format, not a real sample")
        elif self.eff5 == 1011:
            result["tag_layout"] = "ue5-tag-extension"
            result["verification"] = (
                "synthetic fixtures only: no real package "
                "with a recorded UE5 object version >= 1011 "
                "is available in the corpus, so this layout "
                "is verified against synthetic packages built "
                "to the documented format, not a real sample")
        else:
            result["tag_layout"] = "classic"
        size = exp["serial_size"]
        if size == 0:
            result.update({"status": "empty",
                           "note": "export carries no serial data"})
            return result
        start = exp["serial_offset"]
        end = start + size
        if self.eff5 >= 1010:
            ss = exp.get("script_serialization_start")
            se = exp.get("script_serialization_end")
            if ss is not None and start <= ss < end:
                start = ss
            if se is not None and start < se <= end:
                end = se
        blob, loc = self.range_bytes(start, end - start)
        if blob is None:
            result.update({
                "status": "unavailable",
                "note": "export data not present in the "
                        "package or .uexp bytes available",
            })
            return result
        result["data_file"] = loc["file"]
        try:
            tags, consumed = self._tag_stream(blob, 0, len(blob), 0)
            result.update({
                "status": "parsed",
                "tags": tags,
                "tag_count": len(tags),
                "consumed_bytes": consumed,
                "data_bytes": len(blob),
            })
            if consumed < len(blob):
                result["trailing_note"] = (
                    f"{len(blob) - consumed} bytes after the "
                    "tag stream are class-specific data, which "
                    "this parser does not decode")
        except UAssetError as e:
            result.update({
                "status": "failed",
                "note": f"tag stream stopped: {e}",
            })
        return result

    def _read_fname_soft(self, r):
        index = r.i32()
        number = r.i32()
        return self.fname_soft(index, number)

    def _tag_stream(self, blob, start, end, depth):
        """Parse tags in blob[start:end]; returns (tags,
        bytes consumed including the terminating None)."""
        r = _Reader(blob, start)
        tags = []
        while r.pos < end:
            if len(tags) >= MAX_TAGS_PER_EXPORT:
                raise UAssetError(
                    f"tag cap of {MAX_TAGS_PER_EXPORT} reached")
            name = self._read_fname_soft(r)
            if name is None:
                raise UAssetError(
                    "tag name index outside the name table")
            if name == "None":
                return tags, r.pos - start
            tags.append(self._one_tag(r, blob, name, end, depth))
        raise UAssetError("tag stream ended without a None tag")

    # -- UE5 tag-extension layouts (1011 / 1012+) ----------------------
    # Layouts per the publicly documented format (the layout
    # the open-source UAssetAPI reader implements). Verified
    # on synthetic packages only — see the module docstring.

    def _read_type_name(self, r):
        """FPropertyTypeName: a flat node list; each node is
        an FName plus an int32 inner (parameter) count, and
        reading continues until the accumulated node budget
        (1 + sum of inner counts) is consumed."""
        nodes = []
        total = 1
        while len(nodes) < total:
            nm = self._read_fname_soft(r)
            if nm is None:
                raise UAssetError(
                    "type-name node outside the name table")
            inner = r.i32()
            if inner < 0 or inner > 64:
                raise UAssetError(
                    f"implausible type-name inner count {inner}")
            nodes.append((nm, inner))
            total += inner
            if len(nodes) > 256:
                raise UAssetError("type-name node cap reached")
        return nodes

    @staticmethod
    def _type_name_subtree(nodes, i):
        """Render the subtree rooted at nodes[i] as
        Name<Param, ...>; returns (rendered, next index)."""
        nm, inner = nodes[i]
        parts = []
        j = i + 1
        for _ in range(inner):
            sub, j = _Package._type_name_subtree(nodes, j)
            parts.append(sub)
        if parts:
            return f"{nm}<{', '.join(parts)}>", j
        return nm, j

    @staticmethod
    def _type_name_param_root(nodes, idx):
        """Root name of the idx-th parameter of the root
        node, or None when the root has fewer parameters."""
        if not nodes or idx >= nodes[0][1]:
            return None
        j = 1
        for k in range(nodes[0][1]):
            if k == idx:
                return nodes[j][0]
            _, j = _Package._type_name_subtree(nodes, j)
        return None

    def _read_tag_extensions(self, r, tag):
        """The 1011+ extension tail: one extension-mask
        byte; when the overridable-information bit (0x02)
        is set, an operation byte and a 4-byte boolean
        follow."""
        ext = r.u8()
        tag["tag_extensions"] = ext
        if ext & 0x02:
            tag["override_operation"] = r.u8()
            tag["experimental_overridable_logic"] = bool(r.i32())

    def _one_tag_ctn(self, r, blob, name, end, depth):
        """One tag in the >= 1012 complete-type-name layout:
        FPropertyTypeName tree instead of the type FName,
        then size, then a flags byte carrying the optional
        array index / GUID / extensions, with the bool
        value riding in the flags."""
        nodes = self._read_type_name(r)
        tname = nodes[0][0]
        rendered, _ = self._type_name_subtree(nodes, 0)
        size = r.i32()
        if size < 0 or r.pos + size > end:
            raise UAssetError(
                f"tag {name!r} declares size {size} past the "
                "export data")
        flags = r.u8()
        tag = {"name": name, "type": tname,
               "type_name": rendered, "size": size,
               "tag_flags": flags,
               "array_index": r.i32() if flags & 0x01 else 0}
        if tname == "StructProperty":
            struct_name = self._type_name_param_root(nodes, 0)
            if struct_name is None:
                raise UAssetError(
                    "struct tag carries no struct type name")
            tag["struct_name"] = struct_name
        elif tname == "BoolProperty":
            tag["bool_value"] = bool(flags & 0x10)
        elif tname in ("ByteProperty", "EnumProperty"):
            enum_name = self._type_name_param_root(nodes, 0)
            if enum_name is not None:
                tag["enum_name"] = enum_name
        elif tname == "ArrayProperty":
            if nodes[0][1] >= 1:
                inner, _ = self._type_name_subtree(nodes, 1)
                tag["inner_type"] = inner
        if flags & 0x08:
            tag["binary_or_native_serialize"] = True
        if flags & 0x20:
            tag["skipped_serialize"] = True
        if flags & 0x02:
            tag["property_guid"] = r.take(16).hex()
        if flags & 0x04:
            self._read_tag_extensions(r, tag)
        data_start = r.pos
        data_end = data_start + size
        value = self._decode_value(tag, blob, data_start, size)
        if value is not _UNSET:
            tag["value"] = value
        if depth < MAX_TAG_DEPTH and size > 0:
            children = self._nested_tags(tag, blob, data_start,
                                         data_end, depth)
            if children is not None:
                tag["children"] = children
        r.pos = data_end
        return tag

    def _one_tag(self, r, blob, name, end, depth):
        if self.eff5 >= 1012:
            return self._one_tag_ctn(r, blob, name, end, depth)
        tname = self._read_fname_soft(r)
        if tname is None:
            raise UAssetError(
                "tag type index outside the name table")
        size = r.i32()
        if size < 0 or r.pos + size > end:
            raise UAssetError(
                f"tag {name!r} declares size {size} past the "
                "export data")
        tag = {"name": name, "type": tname, "size": size,
               "array_index": r.i32()}
        if tname == "StructProperty":
            struct_name = self._read_fname_soft(r)
            if struct_name is None:
                raise UAssetError("struct name index invalid")
            tag["struct_name"] = struct_name
            if self.eff4 >= 441:
                tag["struct_guid"] = r.take(16).hex()
        elif tname == "BoolProperty":
            tag["bool_value"] = bool(r.u8())
        elif tname in ("ByteProperty", "EnumProperty"):
            enum_name = self._read_fname_soft(r)
            if enum_name is None:
                raise UAssetError("enum name index invalid")
            tag["enum_name"] = enum_name
        elif tname == "ArrayProperty" and \
                (self.eff4 >= 500 or self.eff5 >= 1000):
            inner = self._read_fname_soft(r)
            if inner is None:
                raise UAssetError("array inner type index invalid")
            tag["inner_type"] = inner
        if self.eff4 >= 503:
            # VER_UE4_PROPERTY_GUID_IN_PROPERTY_TAG: a
            # has-GUID flag byte follows the type extras,
            # then the 16-byte GUID itself when flagged.
            if r.u8():
                tag["property_guid"] = r.take(16).hex()
        if self.eff5 == 1011:
            # VER_UE5_PROPERTY_TAG_EXTENSION: at exactly
            # 1011 the extension tail is unconditional
            # (from 1012 on it sits behind the flags byte's
            # HasPropertyExtensions bit instead).
            self._read_tag_extensions(r, tag)
        data_start = r.pos
        data_end = data_start + size
        value = self._decode_value(tag, blob, data_start, size)
        if value is not _UNSET:
            tag["value"] = value
        if depth < MAX_TAG_DEPTH and size > 0:
            children = self._nested_tags(tag, blob, data_start,
                                         data_end, depth)
            if children is not None:
                tag["children"] = children
        r.pos = data_end
        return tag

    def _nested_tags(self, tag, blob, start, end, depth):
        """Recurse into struct values / struct arrays.

        Returns the child tag list, or None when the nested
        bytes do not form a clean tag stream (the value is
        then reported by size only).
        """
        try:
            if tag["type"] == "StructProperty":
                tags, consumed = self._tag_stream(
                    blob, start, end, depth + 1)
                if consumed == end - start:
                    return tags
                return None
            if tag["type"] == "ArrayProperty" and \
                    tag.get("inner_type") == "StructProperty":
                r = _Reader(blob, start)
                count = r.i32()
                if count < 0 or count > 100_000:
                    return None
                out = []
                for _ in range(count):
                    tags, consumed = self._tag_stream(
                        blob, r.pos, end, depth + 1)
                    r.pos += consumed
                    out.append(tags)
                if r.pos == end:
                    return out
                return None
        except UAssetError:
            return None
        return None

    def _decode_value(self, tag, blob, start, size):
        """Decode primitive values whose encoding is
        version-stable; _UNSET for everything else."""
        tname = tag["type"]
        try:
            if tname == "IntProperty" and size == 4:
                return struct.unpack_from("<i", blob, start)[0]
            if tname == "Int64Property" and size == 8:
                return struct.unpack_from("<q", blob, start)[0]
            if tname == "Int16Property" and size == 2:
                return struct.unpack_from("<h", blob, start)[0]
            if tname == "Int8Property" and size == 1:
                return struct.unpack_from("<b", blob, start)[0]
            if tname == "UInt16Property" and size == 2:
                return struct.unpack_from("<H", blob, start)[0]
            if tname == "UInt32Property" and size == 4:
                return struct.unpack_from("<I", blob, start)[0]
            if tname == "UInt64Property" and size == 8:
                return struct.unpack_from("<Q", blob, start)[0]
            if tname == "FloatProperty" and size == 4:
                return struct.unpack_from("<f", blob, start)[0]
            if tname == "DoubleProperty" and size == 8:
                return struct.unpack_from("<d", blob, start)[0]
            if tname == "StrProperty":
                return _Reader(blob, start).fstring()
            if tname == "NameProperty" and size == 8:
                r = _Reader(blob, start)
                return self.fname(r)
            if tname == "ByteProperty":
                if size == 1:
                    return blob[start]
                if size == 8:
                    r = _Reader(blob, start)
                    return self.fname(r)
            if tname == "EnumProperty" and size == 8:
                r = _Reader(blob, start)
                return self.fname(r)
            if tname in ("ObjectProperty", "InterfaceProperty",
                         "ClassProperty") and size == 4:
                idx = struct.unpack_from("<i", blob, start)[0]
                return self.ref_text(idx)
            if tname == "SoftObjectProperty":
                r = _Reader(blob, start)
                if self.eff5 >= 1007:
                    path = r.fstring()
                else:
                    path = self.fname(r)
                return {"asset_path": path,
                        "sub_path": r.fstring()}
        except (UAssetError, struct.error, IndexError):
            return _UNSET
        return _UNSET


class _Unset:
    pass


_UNSET = _Unset()


def parse_package(data, name="", uexp_data=None):
    """Parse .uasset/.umap bytes into a full inspection dict.

    uexp_data is the sibling .uexp content when available.
    Raises UAssetError with a plain reason for anything
    structurally unsupported; per-export property failures
    are captured in each export's "properties" record.
    """
    pkg = _Package(data, uexp_data)
    summary = pkg.parse_summary()
    pkg.parse_names()
    pkg.parse_imports()
    pkg.parse_exports()
    depends = pkg.parse_depends()
    soft_refs = pkg.parse_soft_package_references()
    soft_paths = pkg.parse_soft_object_paths()
    searchable = pkg.parse_searchable_names()
    bulk_offset = summary.get("bulk_data_start_offset")
    bulk = None
    if bulk_offset is not None:
        if bulk_offset == 0:
            bulk = "none recorded"
        elif bulk_offset < len(data):
            bulk = "inside the package file"
        else:
            bulk = "in the sibling .ubulk file"
    for exp in pkg.exports:
        loc = pkg.locate_range(exp["serial_offset"],
                               exp["serial_size"])
        exp["data_location"] = loc
        exp["properties"] = pkg.parse_properties(exp)
    return {
        "format": "unreal-package",
        "name": name,
        "size": len(data),
        "uexp_size": len(uexp_data) if uexp_data is not None
                     else None,
        "summary": summary,
        "names": pkg.names,
        "imports": pkg.imports,
        "exports": pkg.exports,
        "depends": depends,
        "soft_package_references": soft_refs,
        "soft_object_paths": soft_paths,
        "searchable_names": searchable,
        "bulk_data_location": bulk,
        "counts": {
            "names": len(pkg.names),
            "imports": len(pkg.imports),
            "exports": len(pkg.exports),
            "soft_package_references": len(soft_refs),
            "soft_object_paths": len(soft_paths),
            "searchable_names": len(searchable),
        },
    }
