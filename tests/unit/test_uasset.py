"""Unit tests for narlib.uasset on synthetic packages.

Three builders construct small Unreal packages byte-exactly
per the publicly documented package layout (the layout the
open-source UAssetAPI / CUE4Parse readers implement):

- UE4-era: legacy file version -6, UE4 object version 513
  (name hashes, template index, 64-bit serial fields,
  searchable names, preload dependencies);
- UE5-era: legacy file version -8, UE4 object version 522,
  UE5 object version 1010 (soft object path list, import
  package names + optional flag, export script
  serialization offsets, payload TOC / data resource
  fields);
- unversioned: legacy file version -7 with both object
  versions zero, read under the parser's stated final-UE4
  assumption.

No external fixtures, no app data.
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]
                       / "scripts"))

from narlib.uasset import UAssetError, parse_package  # noqa: E402

MAGIC = 0x9E2A83C1


class _B:
    """Byte builder with named i32/i64 patch slots."""

    def __init__(self):
        self.buf = bytearray()
        self.slots = {}

    def pos(self):
        return len(self.buf)

    def raw(self, data):
        self.buf += data
        return self

    def u8(self, v):
        return self.raw(bytes([v]))

    def u16(self, v):
        return self.raw(struct.pack("<H", v))

    def u32(self, v):
        return self.raw(struct.pack("<I", v))

    def i32(self, v):
        return self.raw(struct.pack("<i", v))

    def i64(self, v):
        return self.raw(struct.pack("<q", v))

    def guid(self, seed):
        return self.raw(bytes([seed]) * 16)

    def fstring(self, s):
        if s == "":
            return self.i32(0)
        raw = s.encode("utf-8") + b"\x00"
        self.i32(len(raw))
        return self.raw(raw)

    def fname(self, index, number=0):
        self.i32(index)
        return self.i32(number)

    def mark32(self, key):
        self.slots[key] = self.pos()
        return self.i32(0)

    def mark64(self, key):
        self.slots[key] = self.pos()
        return self.i64(0)

    def patch32(self, key, value):
        struct.pack_into("<i", self.buf, self.slots[key], value)

    def patch64(self, key, value):
        struct.pack_into("<q", self.buf, self.slots[key], value)

    def engine_version(self, major, minor, patch, changelist,
                       branch):
        self.u16(major)
        self.u16(minor)
        self.u16(patch)
        self.u32(changelist)
        return self.fstring(branch)

    def bytes(self):
        return bytes(self.buf)


def _name_table(b, names, hashed=True):
    for n in names:
        b.fstring(n)
        if hashed:
            b.u16(0x1234)
            b.u16(0x5678)


def _tag(b, name_idx, type_idx, data, array_index=0, extra=None,
         guid_seed=None):
    b.fname(name_idx)
    b.fname(type_idx)
    b.i32(len(data))
    b.i32(array_index)
    if extra:
        extra()
    # VER_UE4_PROPERTY_GUID_IN_PROPERTY_TAG (503): every
    # fixture package sits at an effective version >= 503,
    # so the has-GUID flag byte is always serialized.
    if guid_seed is None:
        b.u8(0)
    else:
        b.u8(1)
        b.guid(guid_seed)
    return b.raw(data)


UE4_NAMES = [
    "None", "/Script/Engine", "Package", "StaticMesh",
    "TestMesh", "/Game/Materials/TestMat", "TestMat",
    "Material", "RelativeLocation", "Vector", "X", "Y", "Z",
    "MaxHealth", "IntProperty", "StructProperty",
    "FloatProperty", "BoolProperty", "bVisible",
    "EnumProperty", "CollisionEnabled", "ECollisionEnabled",
    "QueryAndPhysics", "DisplayName", "StrProperty",
    "NameProperty", "InternalName", "ObjectProperty",
    "MaterialSlot", "ByteProperty", "Channel",
    "ECollisionChannel", "WorldStatic",
]
# indices used below
(N_NONE, N_ENGINE, N_PACKAGE, N_SM, N_TESTMESH, N_MATPATH,
 N_TESTMAT, N_MATERIAL, N_RELLOC, N_VECTOR, N_X, N_Y, N_Z,
 N_MAXHEALTH, N_INT, N_STRUCT, N_FLOAT, N_BOOL, N_BVISIBLE,
 N_ENUM, N_COLL, N_ECOLL, N_QAP, N_DISP, N_STR, N_NAMEPROP,
 N_INTNAME, N_OBJ, N_MATSLOT, N_BYTE, N_CHANNEL, N_ECHANNEL,
 N_WORLDSTATIC) = range(len(UE4_NAMES))


def _ue4_export_data():
    """Property stream for the main export + trailing bytes."""
    inner = _B()
    for idx, val in ((N_X, 1.5), (N_Y, -2.5), (N_Z, 3.25)):
        _tag(inner, idx, N_FLOAT, struct.pack("<f", val))
    inner.fname(N_NONE)
    d = _B()
    _tag(d, N_MAXHEALTH, N_INT, struct.pack("<i", 250),
         guid_seed=0xCD)
    _tag(d, N_RELLOC, N_STRUCT, inner.bytes(),
         extra=lambda: (d.fname(N_VECTOR), d.guid(0xAB)))
    _tag(d, N_BVISIBLE, N_BOOL, b"",
         extra=lambda: d.u8(1))
    _tag(d, N_COLL, N_ENUM,
         struct.pack("<ii", N_QAP, 0),
         extra=lambda: d.fname(N_ECOLL))
    disp = _B()
    disp.fstring("Hello")
    _tag(d, N_DISP, N_STR, disp.bytes())
    _tag(d, N_INTNAME, N_NAMEPROP, struct.pack("<ii", N_TESTMESH, 0))
    _tag(d, N_MATSLOT, N_OBJ, struct.pack("<i", -2))
    _tag(d, N_CHANNEL, N_BYTE,
         struct.pack("<ii", N_WORLDSTATIC, 0),
         extra=lambda: d.fname(N_ECHANNEL))
    d.fname(N_NONE)
    return d.bytes() + b"\xde\xad\xbe\xef"  # class-specific tail


def build_ue4():
    """UE4-era package: legacy -6, object version 513."""
    data0 = _ue4_export_data()
    b = _B()
    b.u32(MAGIC)
    b.i32(-6)                       # legacy file version
    b.i32(864)                      # legacy UE3 version
    b.i32(513)                      # UE4 object version
    b.i32(0)                        # licensee version
    b.i32(1)                        # custom versions (GUID+ver)
    b.guid(0x11)
    b.i32(3)
    b.mark32("ths")
    b.fstring("/Game/Synthetic")
    b.u32(0x200)                    # PKG_Cooked
    b.i32(len(UE4_NAMES))
    b.mark32("name_off")
    b.i32(0)                        # gatherable count
    b.i32(0)                        # gatherable offset
    b.i32(2)                        # export count
    b.mark32("export_off")
    b.i32(3)                        # import count
    b.mark32("import_off")
    b.mark32("depends_off")
    b.i32(1)                        # soft package references
    b.mark32("softref_off")
    b.mark32("searchable_off")
    b.i32(0)                        # thumbnail table offset
    b.guid(0x22)                    # package GUID
    b.i32(1)                        # generations
    b.i32(2)
    b.i32(len(UE4_NAMES))
    b.engine_version(4, 16, 0, 1234567, "++UE4+Release-4.16")
    b.engine_version(4, 16, 0, 0, "")
    b.u32(0)                        # compression flags
    b.i32(0)                        # compressed chunks
    b.u32(0)                        # package source
    b.i32(0)                        # additional packages to cook
    b.i32(0)                        # num texture allocations
    b.i32(0)                        # asset registry offset
    b.mark64("bulk_off")
    b.i32(0)                        # world tile info offset
    b.i32(1)                        # chunk ids
    b.i32(7)
    b.i32(1)                        # preload dependency count
    b.mark32("preload_off")
    header_end = b.pos()

    b.patch32("name_off", b.pos())
    _name_table(b, UE4_NAMES)

    b.patch32("import_off", b.pos())
    for cp, cn, outer, name in (
            (N_ENGINE, N_PACKAGE, 0, N_MATPATH),
            (N_ENGINE, N_MATERIAL, -1, N_TESTMAT),
            (N_ENGINE, N_SM, 0, N_ENGINE)):
        b.fname(cp)
        b.fname(cn)
        b.i32(outer)
        b.fname(name)

    # Export data is placed after every table; the export
    # map needs its offsets, so reserve and patch.
    export_map_pos = b.pos()
    b.patch32("export_off", export_map_pos)
    b.raw(b"\x00" * (2 * 104))      # two 104-byte entries

    b.patch32("depends_off", b.pos())
    b.i32(1)
    b.i32(-2)                       # export 0 depends on import 1
    b.i32(1)
    b.i32(1)                        # export 1 depends on export 0

    b.patch32("softref_off", b.pos())
    b.fstring("/Game/Other/Thing")

    b.patch32("searchable_off", b.pos())
    b.i32(1)
    b.fname(N_TESTMESH)
    b.i32(1)
    b.i32(0)

    b.patch32("preload_off", b.pos())
    b.i32(-3)                       # export 0: one SerBeforeSer dep

    data_offset = b.pos()
    b.raw(data0)
    b.patch32("ths", data_offset)
    total = b.pos()
    b.patch64("bulk_off", total)

    # Patch the export map in place.
    m = _B()
    m.i32(-3)                       # class: import 2 (StaticMesh)
    m.i32(0)                        # super
    m.i32(0)                        # template
    m.i32(0)                        # outer
    m.fname(N_TESTMESH)
    m.u32(0x3)                      # RF_Public | RF_Standalone
    m.i64(len(data0))               # serial size
    m.i64(data_offset)              # serial offset
    m.i32(0)
    m.i32(0)
    m.i32(0)                        # forced / not-client / not-server
    m.guid(0x33)                    # package GUID
    m.u32(0x200)                    # package flags
    m.i32(0)                        # not always loaded
    m.i32(1)                        # is asset
    m.i32(0)                        # preload: first offset
    m.i32(1)                        #   SerBeforeSer count
    m.i32(0)
    m.i32(0)
    m.i32(0)
    m.i32(0)                        # class: export 0
    m.i32(0)
    m.i32(0)
    m.i32(0)
    m.fname(N_TESTMESH, 2)          # "TestMesh_1"
    m.u32(0x1)
    m.i64(0)                        # serial size 0
    m.i64(0)
    m.i32(0)
    m.i32(0)
    m.i32(0)
    m.guid(0x44)
    m.u32(0x200)
    m.i32(0)
    m.i32(0)
    m.i32(1)                        # preload first offset (past end)
    m.i32(0)
    m.i32(0)
    m.i32(0)
    m.i32(0)
    assert len(m.bytes()) == 2 * 104, len(m.bytes())
    b.buf[export_map_pos:export_map_pos + 2 * 104] = m.bytes()
    assert header_end <= data_offset
    return b.bytes()


UE5_NAMES = [
    "None", "/Script/Engine", "Package", "Texture2D",
    "TestTexture", "Width", "IntProperty", "ArrayProperty",
    "Tags", "NameProperty", "Alpha", "Beta",
    "FloatProperty", "BoolProperty", "bEnabled",
    "StructProperty", "Vector", "Pos", "X", "Y", "Health",
]
(V_NONE, V_ENGINE, V_PACKAGE, V_TEX2D, V_TESTTEX, V_WIDTH,
 V_INT, V_ARRAY, V_TAGS, V_NAMEPROP, V_ALPHA,
 V_BETA, V_FLOAT, V_BOOL, V_BENABLED, V_STRUCT, V_VECTOR,
 V_POS, V_X, V_Y, V_HEALTH) = range(len(UE5_NAMES))


def _ue5_export_data():
    d = _B()
    _tag(d, V_WIDTH, V_INT, struct.pack("<i", 1024))
    arr = _B()
    arr.i32(2)
    arr.fname(V_ALPHA)
    arr.fname(V_BETA)
    _tag(d, V_TAGS, V_ARRAY, arr.bytes(),
         extra=lambda: d.fname(V_NAMEPROP))
    d.fname(V_NONE)
    return d.bytes()


def build_ue5(ue5_version=1010, data0=None):
    """UE5-era package: legacy -8, UE4 522, UE5 1010."""
    if data0 is None:
        data0 = _ue5_export_data()
    b = _B()
    b.u32(MAGIC)
    b.i32(-8)
    b.i32(864)
    b.i32(522)
    b.i32(ue5_version)              # UE5 object version
    b.i32(0)
    b.i32(1)                        # custom versions
    b.guid(0x55)
    b.i32(5)
    b.mark32("ths")
    b.fstring("/Game/Synthetic5")
    b.u32(0x200)
    b.i32(len(UE5_NAMES))
    b.mark32("name_off")
    b.i32(1)                        # soft object paths
    b.mark32("softpath_off")
    b.fstring("TestLocId")          # localization id
    b.i32(0)
    b.i32(0)                        # gatherable
    b.i32(1)                        # exports
    b.mark32("export_off")
    b.i32(1)                        # imports
    b.mark32("import_off")
    b.mark32("depends_off")
    b.i32(1)                        # soft package references
    b.mark32("softref_off")
    b.mark32("searchable_off")
    b.i32(0)                        # thumbnails
    b.guid(0x66)                    # package GUID
    b.guid(0x77)                    # persistent GUID
    b.i32(1)                        # generations
    b.i32(1)
    b.i32(len(UE5_NAMES))
    b.engine_version(5, 3, 2, 29314046, "++UE5+Release-5.3")
    b.engine_version(5, 3, 2, 0, "")
    b.u32(0)
    b.i32(0)
    b.u32(0)
    b.i32(0)
    b.i32(0)                        # asset registry offset
    b.mark64("bulk_off")
    b.i32(0)                        # world tile info
    b.i32(1)
    b.i32(3)                        # chunk ids
    b.i32(0)                        # preload count
    b.i32(0)                        # preload offset
    b.i32(5)                        # names referenced from data
    b.i64(-1)                       # payload TOC offset
    b.i32(-1)                       # data resource offset

    b.patch32("name_off", b.pos())
    _name_table(b, UE5_NAMES)

    b.patch32("import_off", b.pos())
    b.fname(V_ENGINE)               # class package
    b.fname(V_TEX2D)                # class name
    b.i32(0)                        # outer
    b.fname(V_TEX2D)                # object name
    b.fname(V_ENGINE)               # package name (UE4 >= 520)
    b.i32(0)                        # import optional (UE5 >= 1003)

    export_map_pos = b.pos()
    b.patch32("export_off", export_map_pos)
    export_entry_size = (4 * 4 + 8 + 4 + 8 + 8 + 3 * 4 + 4 + 4
                         + 4 + 4 + 4 + 5 * 4 + 8 + 8)
    b.raw(b"\x00" * export_entry_size)

    b.patch32("depends_off", b.pos())
    b.i32(1)
    b.i32(-1)

    b.patch32("softref_off", b.pos())
    b.fstring("/Game/Other/UE5Thing")

    b.patch32("softpath_off", b.pos())
    b.fstring("/Game/UI/TestWidget")
    b.fstring("")

    b.patch32("searchable_off", b.pos())
    b.i32(1)
    b.fname(V_TESTTEX)
    b.i32(1)
    b.i32(0)

    data_offset = b.pos()
    b.raw(data0)
    b.patch32("ths", data_offset)
    b.patch64("bulk_off", b.pos())

    m = _B()
    m.i32(-1)                       # class: import 0
    m.i32(0)
    m.i32(0)
    m.i32(0)
    m.fname(V_TESTTEX)
    m.u32(0x1)
    m.i64(len(data0))
    m.i64(data_offset)
    m.i32(0)
    m.i32(0)
    m.i32(0)
    m.i32(0)                        # is inherited instance
    m.u32(0x200)
    m.i32(0)                        # not always loaded
    m.i32(1)                        # is asset
    m.i32(0)                        # generate public hash
    for _ in range(5):
        m.i32(0)                    # preload fields
    m.i64(data_offset)              # script serialization start
    m.i64(data_offset + len(data0))  # script serialization end
    assert len(m.bytes()) == export_entry_size, (
        len(m.bytes()), export_entry_size)
    b.buf[export_map_pos:export_map_pos + export_entry_size] = \
        m.bytes()
    return b.bytes()


UNV_NAMES = ["None", "/Script/Engine", "Package", "Thing",
             "Count", "IntProperty"]
(U_NONE, U_ENGINE, U_PACKAGE, U_THING, U_COUNT,
 U_INT) = range(len(UNV_NAMES))


def build_unversioned():
    """Unversioned package: legacy -7, object versions 0."""
    d = _B()
    _tag(d, U_COUNT, U_INT, struct.pack("<i", 42))
    d.fname(U_NONE)
    data0 = d.bytes()
    b = _B()
    b.u32(MAGIC)
    b.i32(-7)
    b.i32(864)
    b.i32(0)                        # UE4 object version: none
    b.i32(0)                        # licensee
    b.i32(0)                        # custom versions
    b.mark32("ths")
    b.fstring("/Game/Unversioned")
    b.u32(0x200)
    b.i32(len(UNV_NAMES))
    b.mark32("name_off")
    b.fstring("")                   # localization id (assumed)
    b.i32(0)
    b.i32(0)                        # gatherable
    b.i32(1)
    b.mark32("export_off")
    b.i32(1)
    b.mark32("import_off")
    b.mark32("depends_off")
    b.i32(0)                        # soft package references
    b.i32(0)
    b.mark32("searchable_off")      # value patched to 0 below
    b.i32(0)                        # thumbnails
    b.guid(0x88)
    b.guid(0x99)                    # persistent GUID (assumed)
    b.i32(1)
    b.i32(1)
    b.i32(len(UNV_NAMES))
    b.engine_version(5, 0, 0, 0, "")
    b.engine_version(5, 0, 0, 0, "")
    b.u32(0)
    b.i32(0)
    b.u32(0)
    b.i32(0)
    b.i32(0)                        # asset registry offset
    b.mark64("bulk_off")
    b.i32(0)                        # world tile info
    b.i32(0)                        # chunk ids: none
    b.i32(0)                        # preload count
    b.i32(0)                        # preload offset
    b.patch32("searchable_off", 0)

    b.patch32("name_off", b.pos())
    _name_table(b, UNV_NAMES)

    b.patch32("import_off", b.pos())
    b.fname(U_ENGINE)
    b.fname(U_THING)
    b.i32(0)
    b.fname(U_THING)
    b.fname(U_ENGINE)               # package name (assumed 520)

    export_map_pos = b.pos()
    b.patch32("export_off", export_map_pos)
    entry_size = (4 * 4 + 8 + 4 + 8 + 8 + 3 * 4 + 16 + 4 + 4
                  + 4 + 5 * 4)
    b.raw(b"\x00" * entry_size)

    b.patch32("depends_off", b.pos())
    b.i32(0)                        # export 0 depends on nothing

    data_offset = b.pos()
    b.raw(data0)
    b.patch32("ths", data_offset)
    b.patch64("bulk_off", b.pos())

    m = _B()
    m.i32(-1)
    m.i32(0)
    m.i32(0)
    m.i32(0)
    m.fname(U_THING)
    m.u32(0x1)
    m.i64(len(data0))
    m.i64(data_offset)
    m.i32(0)
    m.i32(0)
    m.i32(0)
    m.guid(0xAA)                    # package GUID (UE5 < 1005)
    m.u32(0x200)
    m.i32(0)
    m.i32(1)
    for _ in range(5):
        m.i32(0)
    assert len(m.bytes()) == entry_size, (
        len(m.bytes()), entry_size)
    b.buf[export_map_pos:export_map_pos + entry_size] = m.bytes()
    return b.bytes()


# Unversioned UE5 package: the layout a real UE5-era cook
# ships -- legacy version -8 (the summary variant that
# carries a UE5 object-version field) with every recorded
# object version stripped to zero, FilterEditorOnly set
# (no localization id, no persistent GUID, no package-name
# FName in imports), UnversionedProperties set, zeroed
# saved-by engine versions, one soft object path entry,
# and the UE5 summary tail fields (names referenced,
# payload TOC, data resource) present.
UE5U_NAMES = ["None", "/Script/CoreUObject", "/Script/Engine",
              "Class", "Package", "Widget", "Default__Widget",
              "MyWidget"]
(U5_NONE, U5_CORE, U5_ENGINE, U5_CLASS, U5_PACKAGE, U5_WIDGET,
 U5_DEFAULT_WIDGET, U5_MY_WIDGET) = range(len(UE5U_NAMES))


def build_unversioned_ue5():
    b = _B()
    b.u32(MAGIC)
    b.i32(-8)           # legacy: -8 summary carries a UE5 field
    b.i32(0)            # UE3 version
    b.i32(0)            # file version UE4 (stripped at cook time)
    b.i32(0)            # file version UE5 (stripped at cook time)
    b.i32(0)            # licensee version
    b.i32(0)            # custom versions
    b.mark32("ths")
    b.fstring("/Game/UnversionedUE5")
    # PKG_FilterEditorOnly | PKG_UnversionedProperties | 0x200
    b.u32(0x80002200)
    b.i32(len(UE5U_NAMES))
    b.mark32("name_off")
    b.i32(1)                            # soft object paths
    b.mark32("softpaths_off")
    # FilterEditorOnly: no localization id string.
    b.i32(0)                            # gatherable text data
    b.i32(0)
    b.i32(1)                            # exports
    b.mark32("export_off")
    b.i32(3)                            # imports
    b.mark32("import_off")
    b.mark32("depends_off")
    b.i32(0)                            # soft package references
    b.i32(0)
    b.i32(0)                            # searchable names offset
    b.i32(0)                            # thumbnail table offset
    b.guid(0x77)                        # package GUID (< 1016)
    # FilterEditorOnly: no persistent GUID.
    b.i32(1)                            # generations
    b.i32(1)
    b.i32(len(UE5U_NAMES))
    b.engine_version(0, 0, 0, 0, "")    # saved by (zeroed)
    b.engine_version(0, 0, 0, 0, "")    # compatible with
    b.u32(0)                            # compression flags
    b.i32(0)                            # compressed chunks
    b.u32(0)                            # package source
    b.i32(0)                            # additional packages to cook
    b.i32(0)                            # asset registry data offset
    b.mark64("bulk_off")
    b.i32(0)                            # world tile info offset
    b.i32(0)                            # chunk IDs
    b.i32(0)                            # preload dependencies
    b.i32(0)
    b.i32(2)                # names referenced from export data
    b.i64(-1)               # payload TOC offset: none
    b.i32(-1)               # data resource offset: none

    b.patch32("name_off", b.pos())
    _name_table(b, UE5U_NAMES)

    b.patch32("softpaths_off", b.pos())
    # UE5 >= 1007 layout: asset path and sub path are FStrings.
    b.fstring("/Game/Other/Thing.Thing")
    b.fstring("")

    b.patch32("import_off", b.pos())
    # FilterEditorOnly: no package-name FName; UE5 >= 1003
    # adds the import-optional flag.
    b.fname(U5_CORE)
    b.fname(U5_CLASS)
    b.i32(-2)
    b.fname(U5_WIDGET)
    b.i32(0)
    b.fname(U5_CORE)
    b.fname(U5_PACKAGE)
    b.i32(0)
    b.fname(U5_ENGINE)
    b.i32(0)
    b.fname(U5_ENGINE)
    b.fname(U5_WIDGET)
    b.i32(-2)
    b.fname(U5_DEFAULT_WIDGET)
    b.i32(0)

    export_map_pos = b.pos()
    b.patch32("export_off", export_map_pos)
    # class/super/template/outer + name + flags + serial
    # size/offset + 3 bools + inherited-instance + package
    # flags + not-always-loaded + is-asset + generated hash
    # + 5 preload deps; NO package GUID (UE5 >= 1005) and
    # NO script serialization offsets (UnversionedProperties).
    entry_size = 4 * 4 + 8 + 4 + 8 + 8 + 3 * 4 + 4 + 4 + 4 \
        + 4 + 4 + 5 * 4
    b.raw(b"\x00" * entry_size)

    b.patch32("depends_off", b.pos())
    b.i32(0)                        # export 0 depends on nothing

    data_offset = b.pos()
    b.raw(b"\x00" * 4)              # export serial data
    b.patch32("ths", data_offset)
    b.patch64("bulk_off", b.pos())

    m = _B()
    m.i32(-1)                       # class -> import 0
    m.i32(0)                        # super
    m.i32(-3)                       # template -> import 2
    m.i32(0)                        # outer
    m.fname(U5_MY_WIDGET)
    m.u32(0x1)                      # RF_Public
    m.i64(4)                        # serial size
    m.i64(data_offset)              # serial offset
    m.i32(0)
    m.i32(0)
    m.i32(0)
    m.i32(0)                        # is inherited instance
    m.u32(0x200)                    # package flags
    m.i32(0)                        # not always loaded
    m.i32(1)                        # is asset
    m.i32(0)                        # generate public hash
    for _ in range(5):
        m.i32(0)                    # preload dependencies
    assert len(m.bytes()) == entry_size, (
        len(m.bytes()), entry_size)
    b.buf[export_map_pos:export_map_pos + entry_size] = m.bytes()
    return b.bytes()


# ---------------------------------------------------------------- tests

def test_ue4_summary():
    r = parse_package(build_ue4(), "synthetic-ue4.uasset")
    s = r["summary"]
    assert s["legacy_file_version"] == -6
    assert s["file_version_ue4"] == 513
    assert s["file_version_ue5"] is None
    assert s["folder_name"] == "/Game/Synthetic"
    assert "PKG_Cooked" in s["package_flag_names"]
    assert s["saved_by_engine_version"]["major"] == 4
    assert s["saved_by_engine_version"]["minor"] == 16
    assert s["saved_by_engine_version"]["branch"] == \
        "++UE4+Release-4.16"
    assert s["custom_versions"][0]["version"] == 3
    assert s["chunk_ids"] == [7]
    assert r["counts"] == {"names": len(UE4_NAMES), "imports": 3,
                           "exports": 2,
                           "soft_package_references": 1,
                           "soft_object_paths": 0,
                           "searchable_names": 1}
    assert r["names"][N_TESTMESH] == "TestMesh"
    assert r["soft_package_references"] == ["/Game/Other/Thing"]
    assert r["searchable_names"] == {"TestMesh": [0]}
    assert r["bulk_data_location"] == "in the sibling .ubulk file" \
        or r["bulk_data_location"] == "inside the package file"


def test_ue4_imports_exports_resolution():
    r = parse_package(build_ue4(), "synthetic-ue4.uasset")
    imp = r["imports"][1]
    assert imp["class_name"] == "Material"
    assert imp["object_name"] == "TestMat"
    assert imp["outer_resolved"] == "import[0] /Game/Materials/TestMat"
    exp = r["exports"][0]
    assert exp["object_name"] == "TestMesh"
    assert exp["class_resolved"] == "import[2] /Script/Engine"
    assert exp["is_asset"] is True
    assert exp["data_location"]["file"] == "package"
    assert r["exports"][1]["object_name"] == "TestMesh_1"
    assert r["exports"][1]["properties"]["status"] == "empty"
    dep = r["depends"]
    assert dep[0]["resolved"] == ["import[1] TestMat"]
    assert dep[1]["resolved"] == ["export[0] TestMesh"]
    pre = exp["preload"]
    assert pre["indices"]["serialization_before_serialization"] \
        == [-3]
    assert pre["indices_resolved"] == ["import[2] /Script/Engine"]


def test_ue4_properties():
    r = parse_package(build_ue4(), "synthetic-ue4.uasset")
    props = r["exports"][0]["properties"]
    assert props["status"] == "parsed", props
    tags = {t["name"]: t for t in props["tags"]}
    assert tags["MaxHealth"]["value"] == 250
    assert tags["MaxHealth"]["property_guid"] == "cd" * 16
    loc = tags["RelativeLocation"]
    assert loc["struct_name"] == "Vector"
    kids = {t["name"]: t for t in loc["children"]}
    assert kids["X"]["value"] == 1.5
    assert kids["Y"]["value"] == -2.5
    assert kids["Z"]["value"] == 3.25
    assert tags["bVisible"]["bool_value"] is True
    coll = tags["CollisionEnabled"]
    assert coll["enum_name"] == "ECollisionEnabled"
    assert coll["value"] == "QueryAndPhysics"
    assert tags["DisplayName"]["value"] == "Hello"
    assert tags["InternalName"]["value"] == "TestMesh"
    assert tags["MaterialSlot"]["value"] == "import[1] TestMat"
    chan = tags["Channel"]
    assert chan["enum_name"] == "ECollisionChannel"
    assert chan["value"] == "WorldStatic"
    assert props["trailing_note"].startswith("4 bytes")


def test_ue4_split_uexp():
    full = build_ue4()
    head = parse_package(full, "split.uasset")
    ths = head["summary"]["total_header_size"]
    r = parse_package(full[:ths], "split.uasset",
                      uexp_data=full[ths:])
    exp = r["exports"][0]
    assert exp["data_location"]["file"] == "uexp"
    assert exp["data_location"]["offset"] == 0
    assert exp["properties"]["status"] == "parsed"
    assert exp["properties"]["data_file"] == "uexp"


def test_ue5_package():
    r = parse_package(build_ue5(), "synthetic-ue5.uasset")
    s = r["summary"]
    assert s["legacy_file_version"] == -8
    assert s["file_version_ue4"] == 522
    assert s["file_version_ue5"] == 1010
    assert s["localization_id"] == "TestLocId"
    assert s["names_referenced_from_export_data_count"] == 5
    assert s["payload_toc_offset"] == -1
    assert s["data_resource_offset"] == -1
    assert s["persistent_guid"] == "77" * 16
    assert r["soft_object_paths"] == [
        {"asset_path": "/Game/UI/TestWidget", "sub_path": ""}]
    imp = r["imports"][0]
    assert imp["package_name"] == "/Script/Engine"
    assert imp["import_optional"] is False
    exp = r["exports"][0]
    assert exp["class_resolved"] == "import[0] Texture2D"
    assert "package_guid" not in exp
    assert exp["script_serialization_start"] == exp["serial_offset"]
    props = exp["properties"]
    assert props["status"] == "parsed", props
    tags = {t["name"]: t for t in props["tags"]}
    assert tags["Width"]["value"] == 1024
    assert tags["Tags"]["inner_type"] == "NameProperty"
    assert r["depends"][0]["resolved"] == ["import[0] Texture2D"]


def test_unversioned_package():
    r = parse_package(build_unversioned(), "unversioned.uasset")
    s = r["summary"]
    assert s["unversioned"] is True
    assert "version_assumption" in s
    assert r["counts"]["names"] == len(UNV_NAMES)
    exp = r["exports"][0]
    assert exp["class_resolved"] == "import[0] Thing"
    props = exp["properties"]
    assert props["status"] == "parsed", props
    assert props["tags"][0]["value"] == 42


def test_unversioned_ue5_package():
    # A legacy -8 summary with both object versions zero is
    # a UE5 package whose versions were stripped at cook
    # time (that legacy variant exists to carry the UE5
    # field): it must be read with the UE5 summary layout,
    # not the UE4-only one -- otherwise the reader lands
    # eight bytes behind and fails on the package GUID.
    r = parse_package(build_unversioned_ue5(),
                      "unversioned-ue5.uasset")
    s = r["summary"]
    assert s["unversioned"] is True
    assert s["legacy_file_version"] == -8
    assert s["file_version_ue4"] == 0
    assert s["file_version_ue5"] == 0
    assert "1010" in s["version_assumption"]
    assert "PKG_UnversionedProperties" in s["package_flag_names"]
    assert "PKG_FilterEditorOnly" in s["package_flag_names"]
    assert s["names_referenced_from_export_data_count"] == 2
    assert s["payload_toc_offset"] == -1
    assert s["data_resource_offset"] == -1
    assert r["counts"] == {"names": len(UE5U_NAMES), "imports": 3,
                           "exports": 1,
                           "soft_package_references": 0,
                           "soft_object_paths": 1,
                           "searchable_names": 0}
    assert r["soft_object_paths"] == [{
        "asset_path": "/Game/Other/Thing.Thing", "sub_path": ""}]
    imp = r["imports"][0]
    assert imp["class_package"] == "/Script/CoreUObject"
    assert imp["class_name"] == "Class"
    assert imp["object_name"] == "Widget"
    assert imp["import_optional"] is False
    exp = r["exports"][0]
    assert exp["object_name"] == "MyWidget"
    assert exp["class_resolved"] == "import[0] Widget"
    assert exp["template_resolved"] == \
        "import[2] Default__Widget"
    # Properties are unversioned by design: reported, not read.
    assert exp["properties"]["status"] == "unversioned"


def test_bad_magic():
    try:
        parse_package(b"\x00" * 64, "junk.uasset")
    except UAssetError as e:
        assert "magic" in str(e)
    else:
        raise AssertionError("bad magic accepted")


def test_legacy_minus_two_rejected():
    b = _B()
    b.u32(MAGIC)
    b.i32(-2)
    b.i32(864)
    b.i32(513)
    b.i32(0)
    b.raw(b"\x00" * 16)
    try:
        parse_package(b.bytes(), "old.uasset")
    except UAssetError as e:
        assert "-2" in str(e)
    else:
        raise AssertionError("legacy -2 accepted")


def test_ancient_ue4_version_rejected():
    b = _B()
    b.u32(MAGIC)
    b.i32(-6)
    b.i32(864)
    b.i32(400)
    b.i32(0)
    b.raw(b"\x00" * 16)
    try:
        parse_package(b.bytes(), "ancient.uasset")
    except UAssetError as e:
        assert "oldest loadable" in str(e)
    else:
        raise AssertionError("UE4 version 400 accepted")


def test_truncated_package():
    full = build_ue4()
    try:
        parse_package(full[:100], "cut.uasset")
    except UAssetError:
        pass
    else:
        raise AssertionError("truncated package accepted")


# ---------------------------------------------------------------------
# UE5 tag-extension layouts (1011 / 1012+): SYNTHETIC packages
# built to the documented format. No real package with a
# recorded UE5 object version >= 1011 exists in the corpus
# (shipped UE5 titles strip versions or use Zen), so these
# layouts are verified synthetically and labeled as such —
# the parser reports the same labeling in its output.
# ---------------------------------------------------------------------

def _tag1011(b, name_idx, type_idx, data, ext=0, op=0,
             xlogic=0):
    """Classic tag + the 1011 extension tail (extension
    byte after the GUID flag byte; overridable payload
    when the 0x02 bit is set)."""
    b.fname(name_idx)
    b.fname(type_idx)
    b.i32(len(data))
    b.i32(0)
    b.u8(0)                         # no property GUID
    b.u8(ext)
    if ext & 0x02:
        b.u8(op)
        b.i32(xlogic)
    return b.raw(data)


def _ue5_1011_export_data():
    d = _B()
    _tag1011(d, V_WIDTH, V_INT, struct.pack("<i", 1024), ext=0)
    _tag1011(d, V_HEALTH, V_INT, struct.pack("<i", 77),
             ext=2, op=3, xlogic=1)
    d.fname(V_NONE)
    return d.bytes()


def test_ue5_1011_tag_extension_synthetic():
    r = parse_package(build_ue5(1011, _ue5_1011_export_data()),
                      "synthetic-ue5-1011.uasset")
    props = r["exports"][0]["properties"]
    assert props["status"] == "parsed", props
    assert props["tag_layout"] == "ue5-tag-extension"
    assert "synthetic" in props["verification"]
    tags = {t["name"]: t for t in props["tags"]}
    assert tags["Width"]["value"] == 1024
    assert tags["Width"]["tag_extensions"] == 0
    assert tags["Health"]["value"] == 77
    assert tags["Health"]["tag_extensions"] == 2
    assert tags["Health"]["override_operation"] == 3
    assert tags["Health"]["experimental_overridable_logic"] \
        is True


def _ctn_tag(b, name_idx, nodes, data, flags=0, ext=None):
    """One >= 1012 complete-type-name tag: name FName,
    type-name node list, size, flags byte, then the
    flag-gated array index / GUID / extension tail."""
    b.fname(name_idx)
    for idx, inner in nodes:
        b.fname(idx)
        b.i32(inner)
    b.i32(len(data))
    b.u8(flags)
    if flags & 0x01:
        b.i32(0)                    # array index
    if flags & 0x02:
        b.guid(0x42)                # property GUID
    if flags & 0x04:
        e, op, xl = ext
        b.u8(e)
        if e & 0x02:
            b.u8(op)
            b.i32(xl)
    return b.raw(data)


def _ue5_1012_export_data():
    d = _B()
    _ctn_tag(d, V_WIDTH, [(V_INT, 0)], struct.pack("<i", 1024))
    _ctn_tag(d, V_BENABLED, [(V_BOOL, 0)], b"", flags=0x10)
    arr = _B()
    arr.i32(2)
    arr.fname(V_ALPHA)
    arr.fname(V_BETA)
    _ctn_tag(d, V_TAGS, [(V_ARRAY, 1), (V_NAMEPROP, 0)],
             arr.bytes())
    inner = _B()
    _ctn_tag(inner, V_X, [(V_FLOAT, 0)], struct.pack("<f", 1.5))
    _ctn_tag(inner, V_Y, [(V_FLOAT, 0)], struct.pack("<f", 2.5))
    inner.fname(V_NONE)
    _ctn_tag(d, V_POS, [(V_STRUCT, 1), (V_VECTOR, 0)],
             inner.bytes())
    _ctn_tag(d, V_HEALTH, [(V_INT, 0)], struct.pack("<i", 77),
             flags=0x02 | 0x04, ext=(2, 1, 0))
    d.fname(V_NONE)
    return d.bytes()


def test_ue5_1012_complete_type_name_synthetic():
    r = parse_package(build_ue5(1012, _ue5_1012_export_data()),
                      "synthetic-ue5-1012.uasset")
    props = r["exports"][0]["properties"]
    assert props["status"] == "parsed", props
    assert props["tag_layout"] == "ue5-complete-type-name"
    assert "synthetic" in props["verification"]
    tags = {t["name"]: t for t in props["tags"]}
    assert tags["Width"]["value"] == 1024
    assert tags["Width"]["type_name"] == "IntProperty"
    assert tags["bEnabled"]["bool_value"] is True
    assert tags["bEnabled"]["size"] == 0
    assert tags["Tags"]["type_name"] == \
        "ArrayProperty<NameProperty>"
    assert tags["Tags"]["inner_type"] == "NameProperty"
    assert tags["Pos"]["struct_name"] == "Vector"
    children = {c["name"]: c for c in tags["Pos"]["children"]}
    assert children["X"]["value"] == 1.5
    assert children["Y"]["value"] == 2.5
    assert tags["Health"]["value"] == 77
    assert tags["Health"]["property_guid"] == "42" * 16
    assert tags["Health"]["override_operation"] == 1
    assert tags["Health"]["experimental_overridable_logic"] \
        is False
