"""narlib.zen tests on synthetic Zen packages built
byte-exact from the publicly documented Zen layout
(FZenPackageSummary + name batch + bulk data map +
imported public export hashes + import/export maps +
export bundle entries + package-magic trailer), plus
nar-unreal integration: a fully parseable Zen package
is reported as a real parse, and a Zen-shaped chunk
whose header does not validate keeps its identification
record (never a misleading corruption error).

The fixtures are synthetic: names, hashes and payloads
are invented here, and no real package bytes are used.
"""
import json
import struct
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[2] / "scripts"))

from narlib.zen import ZenError, is_zen_package, \
    parse_zen_package  # noqa: E402

MAGIC = b"\xc1\x83\x2a\x9e"
OI_NULL = (1 << 64) - 1


def oi_export(index):
    return index


def oi_script(index):
    return (1 << 62) | index


def oi_package(package_index, hash_index):
    return (2 << 62) | (package_index << 32) | hash_index


def name_batch(names, string_bytes_delta=0):
    """names: str (UTF-8) or ("utf16", str) entries."""
    headers = b""
    body = b""
    total = 0
    for entry in names:
        if isinstance(entry, tuple):
            raw = entry[1].encode("utf-16-le")
            headers += bytes(
                [0x80 | ((len(entry[1]) >> 8) & 0x7F),
                 len(entry[1]) & 0xFF])
        else:
            raw = entry.encode("utf-8")
            headers += bytes(
                [((len(entry) >> 8) & 0x7F),
                 len(entry) & 0xFF])
        body += raw
        total += len(raw)
    return b"".join([
        struct.pack("<i", len(names)),
        struct.pack("<I", total + string_bytes_delta),
        struct.pack("<Q", 0),                # hash version
        b"\x00" * (8 * len(names)),          # name hashes
        headers, body,
    ])


def export_entry(cooked_offset, cooked_size, name_index,
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


def versioning_block(zen_version=3, ue4=522, ue5=1009,
                     licensee=0, customs=()):
    out = struct.pack("<Iiii", zen_version, ue4, ue5,
                      licensee)
    out += struct.pack("<i", len(customs))
    for guid, version in customs:
        out += guid + struct.pack("<i", version)
    return out


def build_current(names, package_name_index, package_flags,
                  hashes, imports, exports, bundle,
                  bulk_entries=(), payload=b"PAYLOAD!",
                  versioning=None, dep_headers=20,
                  dep_entries=4, imported_names=11,
                  string_bytes_delta=0, export_span_extra=0,
                  bulk_prefix_count=None,
                  bulk_prefix_bytes=None):
    """UE 5.3+ Zen layout (52-byte summary)."""
    batch = name_batch(names, string_bytes_delta)
    bulk = b""
    if bulk_entries:
        body = b"".join(
            struct.pack("<QQQI", off, dup, size, flags)
            + bytes([cooked]) + b"\x00" * 3
            for off, dup, size, flags, cooked
            in bulk_entries)
        bulk = struct.pack("<q", len(body)) + body
    if bulk_prefix_count is not None:
        if not bulk:
            bulk = struct.pack("<q", 0)
        raw = bulk_prefix_bytes
        if raw is None:
            raw = b"\x00" * bulk_prefix_count
        bulk = struct.pack("<q", bulk_prefix_count) \
            + raw + bulk
    hashes_b = b"".join(struct.pack("<Q", h) for h in hashes)
    imports_b = b"".join(struct.pack("<Q", v) for v in imports)
    exports_b = b"".join(exports) + b"\x00" * export_span_extra
    bundle_b = b"".join(
        struct.pack("<II", local, command)
        for local, command in bundle)
    ver = versioning or b""
    header_size = (52 + len(ver) + len(batch) + len(bulk)
                   + len(hashes_b) + len(imports_b)
                   + len(exports_b) + len(bundle_b)
                   + dep_headers + dep_entries
                   + imported_names)
    pos = 52 + len(ver) + len(batch) + len(bulk)
    ipeh_off = pos
    import_off = ipeh_off + len(hashes_b)
    export_off = import_off + len(imports_b)
    bundle_off = export_off + len(exports_b)
    deph_off = bundle_off + len(bundle_b)
    depe_off = deph_off + dep_headers
    impn_off = depe_off + dep_entries
    summary = b"".join([
        struct.pack("<I", 1 if versioning else 0),
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
        summary, ver, batch, bulk, hashes_b, imports_b,
        exports_b, bundle_b,
        b"H" * dep_headers, b"E" * dep_entries,
        b"N" * imported_names, payload, MAGIC,
    ])


def build_pre_ue5_3(names, package_name_index, imports,
                    exports, bundle, graph_packages,
                    payload=b"OLDATA!!"):
    """Pre-5.3 Zen layout (44-byte summary, graph data
    instead of dependency-bundle offsets)."""
    batch = name_batch(names)
    imports_b = b"".join(struct.pack("<Q", v) for v in imports)
    exports_b = b"".join(exports)
    bundle_b = b"".join(
        struct.pack("<II", local, command)
        for local, command in bundle)
    graph = struct.pack("<i", len(graph_packages))
    for package_id, bundle_count in graph_packages:
        graph += struct.pack("<Qi", package_id, bundle_count)
        graph += b"A" * (8 * bundle_count)
    header_size = (44 + len(batch) + len(imports_b)
                   + len(exports_b) + len(bundle_b)
                   + len(graph))
    pos = 44 + len(batch)
    import_off = pos            # no hashes section: the
    export_off = import_off + len(imports_b)   # IPEH offset
    bundle_off = export_off + len(exports_b)   # equals the
    graph_off = bundle_off + len(bundle_b)     # import one
    summary = b"".join([
        struct.pack("<I", 0),                # flags word
        struct.pack("<I", header_size),
        struct.pack("<I", package_name_index),
        struct.pack("<I", 0),
        struct.pack("<I", 0x80000200),       # FilterEditor
        struct.pack("<I", header_size + len(payload)),
        struct.pack("<i", import_off),       # IPEH offset
        struct.pack("<i", import_off),
        struct.pack("<i", export_off),
        struct.pack("<i", bundle_off),
        struct.pack("<i", graph_off),
    ])
    assert len(summary) == 44
    return b"".join([
        summary, batch, imports_b, exports_b, bundle_b,
        graph, payload, MAGIC,
    ])


NAMES = ["None", "/Script/CoreUObject", "Class",
         "MyPackage", "MyObject", "MyClass", "Object"]
PAYLOAD = b"PAYLOAD!"


def current_fixture(**overrides):
    args = dict(
        names=NAMES,
        package_name_index=3,
        package_flags=0x80002200,
        hashes=[0xAABBCCDDEEFF0011],
        imports=[oi_package(0, 0), oi_script(42), OI_NULL],
        exports=[export_entry(
            0, len(PAYLOAD), 4, OI_NULL, oi_package(0, 0),
            OI_NULL, oi_script(42), 0x1122334455667788, 3)],
        bundle=[(0, 0), (0, 1)],
        bulk_entries=[(0x1000, 0x1000, 0x40, 0, 1)],
        payload=PAYLOAD,
    )
    args.update(overrides)
    return build_current(**args)


# ------------------------------------------------ parser: current layout

def test_current_layout_full_parse():
    chunk = current_fixture()
    assert is_zen_package(chunk)
    rec = parse_zen_package(chunk, "Content/MyPackage")
    assert rec["format"] == "zen-package"
    assert rec["trailer_magic_ok"] is True
    header_size = len(chunk) - len(PAYLOAD) - 4
    s = rec["summary"]
    assert s["layout"] == "ue5_3_plus"
    assert s["has_versioning_info"] is False
    assert s["header_size"] == header_size
    assert s["package_name"] == "MyPackage"
    assert s["package_flag_names"] == [
        "PKG_Cooked", "PKG_UnversionedProperties",
        "PKG_FilterEditorOnly"]
    assert "versioning_info" not in s
    assert "no UE4/UE5 object version" in s[
        "versioning_note"]
    assert rec["names"] == NAMES
    assert rec["counts"] == {
        "names": 7, "imports": 3, "exports": 1,
        "imported_public_export_hashes": 1,
        "bulk_data_map": 1, "export_bundle_entries": 2}
    assert rec["imported_public_export_hashes"] == [
        "0xaabbccddeeff0011"]
    imp_pkg, imp_script, imp_null = rec["imports"]
    assert imp_pkg["type"] == "package-import"
    assert imp_pkg["imported_package_index"] == 0
    assert imp_pkg["public_export_hash"] == \
        "0xaabbccddeeff0011"
    assert imp_script["type"] == "script-import"
    assert imp_script["script_object_index"] == 42
    assert imp_null["type"] == "null"
    (exp,) = rec["exports"]
    assert exp["object_name"] == "MyObject"
    assert exp["object_flag_names"] == [
        "RF_Public", "RF_Standalone"]
    assert exp["public_export_hash"] == \
        "0x1122334455667788"
    assert exp["outer_resolved"] == "null"
    assert "package-import" in exp["class_resolved"]
    assert "0xaabbccddeeff0011" in exp["class_resolved"]
    assert exp["template_resolved"] == "script-import #42"
    assert exp["data_location"] == {
        "file": "package", "offset": header_size}
    assert exp["properties"]["status"] == "unversioned"
    (bulk,) = rec["bulk_data_map"]
    assert bulk["serial_offset"] == 0x1000
    assert bulk["serial_size"] == 0x40
    assert bulk["cooked_index"] == 1
    assert rec["export_bundle_entries"] == [
        {"local_export_index": 0, "command_type": 0,
         "command_type_name": "create"},
        {"local_export_index": 0, "command_type": 1,
         "command_type_name": "serialize"}]
    sections = rec["sections_not_decoded"]
    assert [x["section"] for x in sections] == [
        "dependency bundle headers",
        "dependency bundle entries",
        "imported package names"]
    assert [x["size"] for x in sections] == [20, 4, 11]


def test_forward_export_reference_resolves():
    # Export 0's class is export 1: a reference to a
    # LATER export. Every object_name must be assigned
    # before any reference resolves, or the forward
    # reference reads a name that does not exist yet
    # (real-corpus regression: cooked packages whose
    # first export is an instance of a class exported
    # after it).
    chunk = current_fixture(
        exports=[
            export_entry(
                0, len(PAYLOAD), 4, OI_NULL, oi_export(1),
                OI_NULL, OI_NULL, 0x1122334455667788, 3),
            export_entry(
                len(PAYLOAD), 0, 5, OI_NULL,
                oi_package(0, 0), OI_NULL, OI_NULL,
                0x99AABBCCDDEEFF00, 3)],
        bundle=[(0, 0), (0, 1), (1, 0), (1, 1)])
    rec = parse_zen_package(chunk, "Content/MyPackage")
    assert rec["counts"]["exports"] == 2
    first, second = rec["exports"]
    assert first["object_name"] == "MyObject"
    assert second["object_name"] == "MyClass"
    assert first["class_resolved"] == "export[1] MyClass"
    assert second["outer_resolved"] == "null"


def test_versioning_info_recorded():
    chunk = current_fixture(
        package_flags=0x80000200,
        versioning=versioning_block(
            customs=[(bytes(range(16)), 7)]))
    rec = parse_zen_package(chunk)
    s = rec["summary"]
    assert s["has_versioning_info"] is True
    info = s["versioning_info"]
    assert info["zen_version"] == 3
    assert info["zen_version_name"] == "ExportDependencies"
    assert info["file_version_ue4"] == 522
    assert info["file_version_ue5"] == 1009
    assert info["custom_versions"] == [
        {"guid": bytes(range(16)).hex(), "version": 7}]
    assert s["file_version_ue5"] == 1009
    assert "versioning_note" not in s
    # no PKG_UnversionedProperties: payload located only
    assert rec["exports"][0]["properties"]["status"] == \
        "located"


def test_utf16_names():
    chunk = current_fixture(
        names=["None", ("utf16", "Utf16Name"), "Pkg"],
        package_name_index=2)
    rec = parse_zen_package(chunk)
    assert rec["names"] == ["None", "Utf16Name", "Pkg"]
    assert rec["summary"]["package_name"] == "Pkg"


def test_summary_name_out_of_range_is_a_note():
    chunk = current_fixture(package_name_index=99)
    rec = parse_zen_package(chunk)
    assert rec["summary"]["package_name"] is None
    assert "package_name_note" in rec["summary"]


def test_bulk_data_map_prefix_variant_parses():
    # Newer writers place a count-prefixed byte array
    # between the name batch and the bulk data map; the
    # classic map behind it must still decode, and the
    # array is reported located-and-measured.
    chunk = current_fixture(bulk_prefix_count=3)
    rec = parse_zen_package(chunk)
    prefix = rec["bulk_data_map_prefix"]
    assert prefix["element_count"] == 3
    assert prefix["size_bytes"] == 11
    assert prefix["nonzero_byte_count"] == 0
    assert rec["counts"]["bulk_data_map"] == 1
    assert rec["bulk_data_map"][0]["serial_offset"] == \
        0x1000


def test_bulk_data_map_prefix_without_map_parses():
    # The array can also precede an empty (size-0) map.
    chunk = current_fixture(bulk_entries=(),
                            bulk_prefix_count=5)
    rec = parse_zen_package(chunk)
    assert rec["bulk_data_map_prefix"]["element_count"] \
        == 5
    assert rec["bulk_data_map"] == []


def test_bulk_data_map_prefix_bad_landing_rejected():
    # A prefix whose count disagrees with its byte span
    # leaves the map behind it misaligned: no layout may
    # accept the chunk.
    chunk = current_fixture(
        bulk_prefix_count=3,
        bulk_prefix_bytes=b"\x00" * 2)
    with pytest.raises(ZenError):
        parse_zen_package(chunk)


# ------------------------------------------------ parser: pre-5.3 layout

def test_pre_ue5_3_graph_data():
    chunk = build_pre_ue5_3(
        names=["None", "OldPackage", "OldObject"],
        package_name_index=1,
        imports=[oi_export(0)],
        exports=[export_entry(
            0, 8, 2, OI_NULL, oi_export(0), OI_NULL,
            OI_NULL, 0x42, 1)],
        bundle=[(0, 0), (0, 1)],
        graph_packages=[(0x0102030405060708, 2)],
    )
    rec = parse_zen_package(chunk)
    s = rec["summary"]
    assert s["layout"] == "pre_ue5_3"
    assert s["package_name"] == "OldPackage"
    assert rec["imported_package_ids"] == [
        {"package_id": "0x0102030405060708",
         "bundle_count": 2}]
    assert rec["counts"]["imported_packages"] == 1
    assert rec["sections_not_decoded"] == []
    # export-typed imports resolve once exports exist
    assert rec["imports"][0]["resolved"] == "OldObject"
    assert rec["exports"][0]["class_resolved"] == \
        "export[0] OldObject"


# ------------------------------------------------ parser: refusals

def test_classic_package_is_not_zen():
    classic = MAGIC + b"\x00" * 64
    assert not is_zen_package(classic)
    with pytest.raises(ZenError):
        parse_zen_package(classic)


def test_bad_trailer_rejected():
    chunk = bytearray(current_fixture())
    chunk[-1] ^= 0xFF
    with pytest.raises(ZenError):
        parse_zen_package(bytes(chunk))


def test_name_batch_byte_count_mismatch_rejected():
    chunk = current_fixture(string_bytes_delta=1)
    with pytest.raises(ZenError):
        parse_zen_package(chunk)


def test_export_map_span_not_whole_entries_rejected():
    chunk = current_fixture(export_span_extra=1)
    with pytest.raises(ZenError):
        parse_zen_package(chunk)


def test_truncated_chunk_rejected():
    with pytest.raises(ZenError):
        parse_zen_package(current_fixture()[:100])


# ------------------------------------------------ nar-unreal integration

def _run_unreal(tmp_path, data, filename):
    target = tmp_path / filename
    target.write_bytes(data)
    script = HERE.parents[2] / "scripts" / "nar-unreal.py"
    proc = subprocess.run(
        [sys.executable, str(script), str(target), "--json"],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_unreal_reports_full_zen_parse(tmp_path):
    report = _run_unreal(tmp_path, current_fixture(),
                         "zenpkg.uasset")
    (pkg,) = report["packages"]
    assert "error" not in pkg
    assert pkg["format"] == "zen-package"
    assert pkg["counts"]["names"] == 7
    assert pkg["counts"]["exports"] == 1
    assert pkg["summary"]["package_name"] == "MyPackage"
    assert report["generation"].startswith(
        "UE5-era (IoStore/Zen packaging")


def test_unreal_unparseable_zen_chunk_identified(tmp_path):
    filler = (b"\x00\x00\x00\x00" + struct.pack("<I", 64)
              + b"zen synthetic payload " * 3 + MAGIC)
    report = _run_unreal(tmp_path, filler, "filler.uasset")
    (pkg,) = report["packages"]
    assert pkg["format"] == "zen-package"
    assert pkg["zen_header_size"] == 64
    assert "error" not in pkg
    assert "full Zen parse was attempted" in pkg["note"]
