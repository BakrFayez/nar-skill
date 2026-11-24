"""Synthetic fixture builders for the NAR test suite (W5).

This module is the single library behind
``tests/generate_fixtures.py`` and
``tests/unit/test_synthetic_fixtures.py``. It produces
minimal-but-valid synthetic samples on disk, in a
caller-chosen directory, for every binary format whose
parser already had a synthetic builder somewhere in the
unit suite:

- a DEX and an ELF shared object,
- a classic (encoded-index v11) Unreal pak,
- an IoStore .utoc/.ucas pair,
- a Zen package chunk,
- classic UAsset packages (UE4-versioned, unversioned,
  and UE5 at object versions 1010, 1011 and 1012+),
- a Godot .pck (format 2).

MANIFEST DESIGN (read this before trusting the numbers):
``tests/expected_outputs.json`` records the BUILDER's
intended facts for each fixture -- the counts, versions
and names the builder deliberately constructed -- and
nothing else. The facts are NOT measured from the parsers
at generation time: a manifest filled in by running the
parsers over the generated files would be circular (it
could never catch a parser regression, because the
expected values would move with the parser). Instead the
regression tests assert

    parser output == builder intent (the manifest),

so a parser change that alters any recorded fact fails
loudly until a human updates the builder intent here.

BUILDER PROVENANCE: where a builder already existed inside
a test file and is cleanly importable under a bare
``python3`` (the documented runtime of the generator CLI),
this module IMPORTS it from that test file instead of
copying it:

- DEX / ELF ......... tests/unit/test_dex_elf.py
- pak ............... tests/unit/test_pak.py
  (``build_v11_encoded``)
- IoStore ........... tests/unit/test_iostore.py
  (``build_current``)
- UAsset ............ tests/unit/test_uasset.py
  (``build_ue4`` / ``build_unversioned`` / ``build_ue5``
  plus its 1011/1012 export-data builders)
- Godot .pck ........ tests/unit/test_godot.py
  (``build_v2``)

One exception, noted honestly: the Zen builder is a
minimal equivalent implemented below, not an import.
``tests/unit/test_zen.py`` imports ``pytest`` at module
level, so it is not importable under the bare ``python3``
that runs the generator CLI (pytest is a test-only extra).
The Zen code below reproduces that module's
``current_fixture()`` shape exactly -- same name batch,
same import/export/bulk/bundle construction, same
UE 5.3+ 52-byte summary layout -- and the regression tests
pin its output against the real Zen parser, so any drift
between the two builders that changes a recorded fact is
caught by the manifest assertions.

No private files are read or written: every byte here is
constructed from constants in this repo.
"""
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve()
UNIT = HERE.parent / "unit"
ROOT = HERE.parents[1]

# ------------------------------------------------------------------
# Imported builders (see provenance note in the docstring)
# ------------------------------------------------------------------

_module_cache = {}


def _load_unit_module(name):
    """Load tests/unit/<name>.py under a private module
    name (never registered in sys.modules, so it cannot
    collide with pytest's own collection of that file)."""
    if name not in _module_cache:
        spec = importlib.util.spec_from_file_location(
            "_nar_synfix_" + name, UNIT / (name + ".py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _module_cache[name] = module
    return _module_cache[name]


# ------------------------------------------------------------------
# Zen builder: minimal equivalent of
# tests/unit/test_zen.py's current_fixture() (see docstring
# for why this one is not imported).
# ------------------------------------------------------------------

_ZEN_MAGIC = b"\xc1\x83\x2a\x9e"
_OI_NULL = (1 << 64) - 1


def _zen_oi_script(index):
    return (1 << 62) | index


def _zen_oi_package(package_index, hash_index):
    return (2 << 62) | (package_index << 32) | hash_index


def _zen_name_batch(names):
    headers = b""
    body = b""
    total = 0
    for entry in names:
        raw = entry.encode("utf-8")
        headers += bytes([((len(entry) >> 8) & 0x7F),
                          len(entry) & 0xFF])
        body += raw
        total += len(raw)
    return b"".join([
        struct.pack("<i", len(names)),
        struct.pack("<I", total),
        struct.pack("<Q", 0),                # hash version
        b"\x00" * (8 * len(names)),          # name hashes
        headers, body,
    ])


def _zen_export_entry(cooked_offset, cooked_size, name_index,
                      outer, klass, super_, template,
                      public_hash, object_flags):
    return b"".join([
        struct.pack("<Q", cooked_offset),
        struct.pack("<Q", cooked_size),
        struct.pack("<I", name_index),       # FMappedName
        struct.pack("<I", 0),                # name number
        struct.pack("<Q", outer),
        struct.pack("<Q", klass),
        struct.pack("<Q", super_),
        struct.pack("<Q", template),
        struct.pack("<Q", public_hash),
        struct.pack("<I", object_flags),
        b"\x00",                             # filter flags
        b"\x00" * 3,                         # padding
    ])


def _build_zen_current(names, package_name_index, package_flags,
                       hashes, imports, exports, bundle,
                       bulk_entries=(), payload=b"PAYLOAD!",
                       dep_headers=20, dep_entries=4,
                       imported_names=11):
    """UE 5.3+ Zen layout (52-byte summary); mirrors
    build_current() in tests/unit/test_zen.py."""
    batch = _zen_name_batch(names)
    bulk = b""
    if bulk_entries:
        body = b"".join(
            struct.pack("<QQQI", off, dup, size, flags)
            + bytes([cooked]) + b"\x00" * 3
            for off, dup, size, flags, cooked
            in bulk_entries)
        bulk = struct.pack("<q", len(body)) + body
    hashes_b = b"".join(struct.pack("<Q", h) for h in hashes)
    imports_b = b"".join(struct.pack("<Q", v) for v in imports)
    exports_b = b"".join(exports)
    bundle_b = b"".join(
        struct.pack("<II", local, command)
        for local, command in bundle)
    header_size = (52 + len(batch) + len(bulk)
                   + len(hashes_b) + len(imports_b)
                   + len(exports_b) + len(bundle_b)
                   + dep_headers + dep_entries
                   + imported_names)
    pos = 52 + len(batch) + len(bulk)
    ipeh_off = pos
    import_off = ipeh_off + len(hashes_b)
    export_off = import_off + len(imports_b)
    bundle_off = export_off + len(exports_b)
    deph_off = bundle_off + len(bundle_b)
    depe_off = deph_off + dep_headers
    impn_off = depe_off + dep_entries
    summary = b"".join([
        struct.pack("<I", 0),                # no versioning
        struct.pack("<I", header_size),
        struct.pack("<I", package_name_index),
        struct.pack("<I", 0),                # name number
        struct.pack("<I", package_flags),
        struct.pack("<I", header_size + len(payload)),
        struct.pack("<i", ipeh_off),
        struct.pack("<i", import_off),
        struct.pack("<i", export_off),
        struct.pack("<i", bundle_off),
        struct.pack("<i", deph_off),
        struct.pack("<i", depe_off),
        struct.pack("<i", impn_off),
    ])
    assert len(summary) == 52
    return b"".join([
        summary, batch, bulk, hashes_b, imports_b,
        exports_b, bundle_b,
        b"H" * dep_headers, b"E" * dep_entries,
        b"N" * imported_names, payload, _ZEN_MAGIC,
    ])


ZEN_NAMES = ["None", "/Script/CoreUObject", "Class",
             "MyPackage", "MyObject", "MyClass", "Object"]
ZEN_PAYLOAD = b"PAYLOAD!"


def build_zen():
    """The Zen package chunk: one package import, one
    script import, one null import, one export, one
    bulk-data-map entry, two export bundle entries."""
    return _build_zen_current(
        names=ZEN_NAMES,
        package_name_index=3,
        package_flags=0x80002200,
        hashes=[0xAABBCCDDEEFF0011],
        imports=[_zen_oi_package(0, 0), _zen_oi_script(42),
                 _OI_NULL],
        exports=[_zen_export_entry(
            0, len(ZEN_PAYLOAD), 4, _OI_NULL,
            _zen_oi_package(0, 0), _OI_NULL,
            _zen_oi_script(42), 0x1122334455667788, 3)],
        bundle=[(0, 0), (0, 1)],
        bulk_entries=[(0x1000, 0x1000, 0x40, 0, 1)],
        payload=ZEN_PAYLOAD,
    )


# ------------------------------------------------------------------
# Fixture definitions: builder intent (the manifest facts)
# ------------------------------------------------------------------

def _fixture_dex():
    mod = _load_unit_module("test_dex_elf")
    blob = mod.build_dex()
    return {"synthetic.dex": blob}, {
        "dex_version": "039",
        "string_count": 2,
        "strings": ["LFoo;", "hello"],
        "type_count": 1,
        "types": ["LFoo;"],
        "proto_count": 1,
        "field_count": 0,
        "method_id_count": 1,
        "class_def_count": 0,
        "method_ref": ["LFoo;", "hello"],
    }


def _fixture_elf():
    mod = _load_unit_module("test_dex_elf")
    blob = mod.build_elf64()
    return {"libsynthetic.so": blob}, {
        "elf_class": "ELF64",
        "arch": "AArch64",
        "type": "ET_DYN",
        "soname": "libfoo.so",
        "needed": ["libbar.so"],
        "program_header_count": 2,
        "section_count": 0,
        "section_names": [],
    }


def _fixture_pak():
    mod = _load_unit_module("test_pak")
    blob = mod.build_v11_encoded()
    return {"synthetic.pak": blob}, {
        "pak_version": 11,
        "supported": True,
        "index_encrypted": False,
        "mount_point": "../../../",
        "entry_count": 4,
        "entry_names": [
            "Game/Content/stored.uasset",
            "Game/Content/zlib1.uasset",
            "Game/Content/zlib2.uasset",
            "Game/Content/oodle.uasset",
        ],
        "compression_by_entry": {
            "Game/Content/stored.uasset": "None",
            "Game/Content/zlib1.uasset": "Zlib",
            "Game/Content/zlib2.uasset": "Zlib",
            "Game/Content/oodle.uasset": "Oodle",
        },
    }


def _fixture_iostore():
    mod = _load_unit_module("test_iostore")
    utoc, ucas = mod.build_current()
    return {"synthetic.utoc": utoc, "synthetic.ucas": ucas}, {
        "layout": "current",
        "toc_version": 6,
        "toc_version_name": "OnDemandMetaData",
        "chunk_count": 3,
        "compressed_block_count": 4,
        "compression_methods": ["None", "Zlib"],
        "entries_by_type": {
            "ExportBundleData": 1,
            "BulkData": 1,
            "PackageStoreEntry": 1,
        },
        "chunk_type_names": [
            "ExportBundleData", "BulkData",
            "PackageStoreEntry",
        ],
        "total_chunk_bytes": (
            len(mod.CHUNK_A) + len(mod.CHUNK_B)
            + len(mod.CHUNK_C)),
        "directory_index": {
            "layout": "classic",
            "mount_point": "../../../SyntheticGame/",
            "directory_count": 2,
            "file_count": 3,
            "file_paths": [
                "../../../SyntheticGame/Content/ChunkA.uasset",
                "../../../SyntheticGame/Content/ChunkB.ubulk",
                "../../../SyntheticGame/global_names.bin",
            ],
        },
    }


def _fixture_zen():
    blob = build_zen()
    return {"synthetic_zen.uasset": blob}, {
        "format": "zen-package",
        "layout": "ue5_3_plus",
        "package_name": "MyPackage",
        "names": list(ZEN_NAMES),
        "counts": {
            "names": 7,
            "imports": 3,
            "exports": 1,
            "imported_public_export_hashes": 1,
            "bulk_data_map": 1,
            "export_bundle_entries": 2,
        },
        "trailer_magic_ok": True,
    }


def _uasset_facts(summary, counts, tag_layout=None):
    facts = {
        "legacy_file_version": summary[0],
        "file_version_ue4": summary[1],
        "file_version_ue5": summary[2],
        "folder_name": summary[3],
        "unversioned": summary[4],
        "counts": counts,
    }
    if tag_layout is not None:
        facts["export_tag_layout"] = tag_layout
        facts["export_properties_status"] = "parsed"
    return facts


def _fixture_uasset_ue4():
    mod = _load_unit_module("test_uasset")
    blob = mod.build_ue4()
    return {"synthetic_ue4.uasset": blob}, _uasset_facts(
        (-6, 513, None, "/Game/Synthetic", False),
        {"names": 33, "imports": 3, "exports": 2,
         "soft_package_references": 1, "soft_object_paths": 0,
         "searchable_names": 1})


def _fixture_uasset_unversioned():
    mod = _load_unit_module("test_uasset")
    blob = mod.build_unversioned()
    return {"synthetic_unversioned.uasset": blob}, \
        _uasset_facts(
            (-7, 0, None, "/Game/Unversioned", True),
            {"names": 6, "imports": 1, "exports": 1,
             "soft_package_references": 0,
             "soft_object_paths": 0, "searchable_names": 0})


_UE5_COUNTS = {"names": 21, "imports": 1, "exports": 1,
               "soft_package_references": 1,
               "soft_object_paths": 1, "searchable_names": 1}


def _fixture_uasset_ue5_1010():
    mod = _load_unit_module("test_uasset")
    blob = mod.build_ue5(1010)
    return {"synthetic_ue5_1010.uasset": blob}, _uasset_facts(
        (-8, 522, 1010, "/Game/Synthetic5", False),
        dict(_UE5_COUNTS), tag_layout="classic")


def _fixture_uasset_ue5_1011():
    mod = _load_unit_module("test_uasset")
    blob = mod.build_ue5(1011, mod._ue5_1011_export_data())
    return {"synthetic_ue5_1011.uasset": blob}, _uasset_facts(
        (-8, 522, 1011, "/Game/Synthetic5", False),
        dict(_UE5_COUNTS), tag_layout="ue5-tag-extension")


def _fixture_uasset_ue5_1012():
    mod = _load_unit_module("test_uasset")
    blob = mod.build_ue5(1012, mod._ue5_1012_export_data())
    return {"synthetic_ue5_1012.uasset": blob}, _uasset_facts(
        (-8, 522, 1012, "/Game/Synthetic5", False),
        dict(_UE5_COUNTS),
        tag_layout="ue5-complete-type-name")


def _fixture_godot():
    mod = _load_unit_module("test_godot")
    blob = mod.build_v2()
    return {"synthetic.pck": blob}, {
        "format_version": 2,
        "engine_version": "4.3.0",
        "encrypted": False,
        "file_count": 2,
        "file_paths": ["res://hello.txt",
                       "res://project.godot"],
        "total_content_bytes": sum(
            len(data) for _, data in mod.FILES),
    }


BUILDERS = {
    "dex": _fixture_dex,
    "elf": _fixture_elf,
    "pak": _fixture_pak,
    "iostore": _fixture_iostore,
    "zen": _fixture_zen,
    "uasset_ue4": _fixture_uasset_ue4,
    "uasset_unversioned": _fixture_uasset_unversioned,
    "uasset_ue5_1010": _fixture_uasset_ue5_1010,
    "uasset_ue5_1011": _fixture_uasset_ue5_1011,
    "uasset_ue5_1012": _fixture_uasset_ue5_1012,
    "godot_pck": _fixture_godot,
}

FIXTURE_IDS = list(BUILDERS)


def build_fixture(fixture_id):
    """Return (files, facts): files maps a relative file
    name to its bytes; facts is the builder intent."""
    files, facts = BUILDERS[fixture_id]()
    return files, facts


def expected_outputs():
    """The manifest dict: builder intent for every fixture,
    plus each generated file's builder-known size. No parser
    is consulted to build this dict (see module docstring).
    """
    fixtures = {}
    for fixture_id in FIXTURE_IDS:
        files, facts = build_fixture(fixture_id)
        fixtures[fixture_id] = {
            "files": sorted(files),
            "file_sizes": {
                name: len(blob)
                for name, blob in sorted(files.items())},
            "facts": facts,
        }
    return {
        "schema": 1,
        "design": (
            "Builder intent, not parser measurement: each "
            "entry records the facts the fixture builder "
            "deliberately constructed. The regression tests "
            "in tests/unit/test_synthetic_fixtures.py assert "
            "that the real parsers report exactly these "
            "facts for the generated files."),
        "generated_by": "tests/generate_fixtures.py",
        "fixtures": fixtures,
    }


def generate(out_dir):
    """Write every fixture file into out_dir and the
    manifest to out_dir/expected_outputs.json. Returns the
    manifest dict."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for fixture_id in FIXTURE_IDS:
        files, _facts = build_fixture(fixture_id)
        for name, blob in files.items():
            (out / name).write_bytes(blob)
    manifest = expected_outputs()
    (out / "expected_outputs.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    return manifest
