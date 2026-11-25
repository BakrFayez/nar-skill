"""UObject relationship extraction tests (nar-unreal).

The edges are assembled from the import/export/depends
maps the parsers already decode, so the synthetic
builders are the existing ones: the UE4 package builder
(test_uasset) plants known package-index references —
export 0's class is import 2, export 0 depends on
import 1, export 1 depends on export 0 — and the Zen
builder (test_zen) plants export 0 with a package-import
class reference and a script-import template reference.
The exact edge lists are asserted.
"""
import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parents[2] / "scripts"))

import test_uasset  # noqa: E402
import test_zen  # noqa: E402


def _load_nar_unreal():
    spec = importlib.util.spec_from_file_location(
        "nar_unreal_rel", HERE.parents[2] / "scripts"
        / "nar-unreal.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


nar_unreal = _load_nar_unreal()


def test_classic_relationships_exact_edges():
    pkg = nar_unreal.package_summary(
        test_uasset.build_ue4(), "synthetic.uasset")
    rel = pkg["relationships"]
    assert rel["counts"] == {"total": 3, "processed": 3,
                             "skipped": 0, "failed": 0}
    assert "table-derived" in rel["evidence"]
    edges = rel["edges"]
    # Export 0 (TestMesh): class -> import 2 (StaticMesh).
    assert edges[0]["kind"] == "class"
    assert edges[0]["from"] == {
        "kind": "export", "index": 0,
        "object_name": "TestMesh"}
    assert edges[0]["to"]["kind"] == "import"
    assert edges[0]["to"]["index"] == 2
    assert edges[0]["to"]["class_name"] == "StaticMesh"
    assert edges[0]["to"]["class_package"] == "/Script/Engine"
    assert "package-index" in edges[0]["evidence"]
    # Depends map: export 0 -> import 1 (TestMat/Material).
    assert edges[1]["kind"] == "depends"
    assert edges[1]["from"]["index"] == 0
    assert edges[1]["to"]["kind"] == "import"
    assert edges[1]["to"]["index"] == 1
    assert edges[1]["to"]["object_name"] == "TestMat"
    assert edges[1]["to"]["class_name"] == "Material"
    # Depends map: export 1 -> export 0.
    assert edges[2]["kind"] == "depends"
    assert edges[2]["from"]["index"] == 1
    assert edges[2]["to"] == {
        "kind": "export", "index": 0,
        "object_name": "TestMesh",
        "class_name": "import[2] /Script/Engine"}


def test_classic_relationships_none_indices_carry_no_edge():
    # In the UE4 builder every other class/super/outer/
    # template index is 0 (none): exactly the 3 edges
    # above exist, so no none-index produced an edge.
    pkg = nar_unreal.package_summary(
        test_uasset.build_ue4(), "synthetic.uasset")
    kinds = [e["kind"] for e in pkg["relationships"]["edges"]]
    assert kinds == ["class", "depends", "depends"]


def test_zen_relationships_exact_edges():
    pkg = nar_unreal.zen_package_summary(
        test_zen.current_fixture(), "synthetic-chunk")
    rel = pkg["relationships"]
    assert rel["counts"]["total"] == 2
    assert "table-derived" in rel["evidence"]
    edges = rel["edges"]
    # Export 0 (MyObject): class -> package-import,
    # template -> script-import; outer/super are null
    # and carry no edge.
    assert [e["kind"] for e in edges] == ["class", "template"]
    assert edges[0]["from"] == {
        "kind": "export", "index": 0,
        "object_name": "MyObject"}
    assert edges[0]["to"]["kind"] == "package-import"
    assert "package-import" in edges[0]["to"]["resolved"]
    assert edges[1]["to"]["kind"] == "script-import"
    assert edges[1]["to"]["resolved"] == "script-import #42"
    assert all("FPackageObjectIndex" in e["evidence"]
               for e in edges)


def test_zen_relationships_export_target_outside_map_is_noted():
    # One export whose outer is export 9: the target is
    # outside the export map, so the relationship target
    # must carry the same unresolved note the classic
    # path records ("export index outside the export
    # map") — without it the graph join cannot tell the
    # reference is unresolved and would upgrade it to a
    # high-confidence resolved edge. (Real-corpus audit:
    # no stored Zen package in the corpora on hand has
    # such a target, so this stays synthetic coverage of
    # a boundary the real sets do not exercise.)
    chunk = test_zen.current_fixture(exports=[
        test_zen.export_entry(
            0, len(test_zen.PAYLOAD), 4, test_zen.oi_export(9),
            test_zen.oi_package(0, 0), test_zen.OI_NULL,
            test_zen.OI_NULL, 0x1122334455667788, 3)],
        bundle=[(0, 0), (0, 1)])
    pkg = nar_unreal.zen_package_summary(chunk, "synthetic-chunk")
    edges = pkg["relationships"]["edges"]
    outer = [e for e in edges if e["kind"] == "outer"]
    assert len(outer) == 1
    assert outer[0]["to"]["kind"] == "export"
    assert outer[0]["to"]["index"] == 9
    assert outer[0]["to"]["note"] == \
        "export index outside the export map"
    # The resolved class target (package-import) is a
    # cross-package reference and carries no such note.
    klass = [e for e in edges if e["kind"] == "class"]
    assert len(klass) == 1
    assert "note" not in klass[0]["to"]


def test_zen_relationships_export_target_unnamed_is_noted():
    # Export 1's name index is outside the package name
    # map, so its object name does not resolve; export
    # 0's outer reference to it must be noted as
    # unresolved rather than presented as resolved.
    chunk = test_zen.current_fixture(exports=[
        test_zen.export_entry(
            0, len(test_zen.PAYLOAD), 4, test_zen.oi_export(1),
            test_zen.oi_package(0, 0), test_zen.OI_NULL,
            test_zen.OI_NULL, 0x1122334455667788, 3),
        test_zen.export_entry(
            len(test_zen.PAYLOAD), 0, 99, test_zen.OI_NULL,
            test_zen.oi_package(0, 0), test_zen.OI_NULL,
            test_zen.OI_NULL, 0x99AABBCCDDEEFF00, 3)],
        bundle=[(0, 0), (0, 1), (1, 0), (1, 1)])
    pkg = nar_unreal.zen_package_summary(chunk, "synthetic-chunk")
    outer = [e for e in pkg["relationships"]["edges"]
             if e["kind"] == "outer"]
    assert len(outer) == 1
    assert outer[0]["to"]["index"] == 1
    assert "does not resolve" in outer[0]["to"]["note"]


def test_zen_relationships_export_target_in_map_has_no_note():
    # A forward reference to a later, named export (the
    # shape the real corpora do contain) resolves and
    # carries no note.
    chunk = test_zen.current_fixture(exports=[
        test_zen.export_entry(
            0, len(test_zen.PAYLOAD), 4, test_zen.OI_NULL,
            test_zen.oi_export(1), test_zen.OI_NULL,
            test_zen.OI_NULL, 0x1122334455667788, 3),
        test_zen.export_entry(
            len(test_zen.PAYLOAD), 0, 5, test_zen.OI_NULL,
            test_zen.oi_package(0, 0), test_zen.OI_NULL,
            test_zen.OI_NULL, 0x99AABBCCDDEEFF00, 3)],
        bundle=[(0, 0), (0, 1), (1, 0), (1, 1)])
    pkg = nar_unreal.zen_package_summary(chunk, "synthetic-chunk")
    klass = [e for e in pkg["relationships"]["edges"]
             if e["kind"] == "class"
             and e["from"]["index"] == 0]
    assert len(klass) == 1
    assert klass[0]["to"]["kind"] == "export"
    assert klass[0]["to"]["index"] == 1
    assert "note" not in klass[0]["to"]


def test_relationships_present_on_bare_package_report(
        tmp_path):
    target = tmp_path / "synthetic.uasset"
    target.write_bytes(test_uasset.build_ue4())
    report = nar_unreal.analyze(str(target))
    assert report["verdict"] == "package"
    rel = report["packages"][0]["relationships"]
    assert rel["counts"]["total"] == 3
