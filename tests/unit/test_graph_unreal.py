"""Unit tests: Unreal package relationships joined into
the unified graph (2.6.1 verification round, closing the
R-008 remainder recorded in 2.6.0).

- Classic + Zen nar-unreal relationship records become
  unreal_package / unreal_object nodes and unreal_*
  edges under the graph's provenance/confidence
  discipline: table-resolved references are direct
  evidence, Zen cross-package resolution text is medium,
  unresolvable references stay explicitly unresolved
  with low confidence — never dropped, never upgraded.
- Counts reconcile with nar-unreal's own accounting,
  including the cap note when a package's relationship
  list was capped upstream.
- Without Unreal input the graph output is byte-identical
  to the pre-integration builder (the integration is
  additive only), and standalone nar-unreal records are
  untouched.
- nar-analyze's assembly helper picks exactly the
  packages that carry a relationships record, with
  report field paths.
"""
import importlib.util
import json
import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", ".."))
SCRIPTS = os.path.join(ROOT, "scripts")
sys.path.insert(0, SCRIPTS)

from narlib import evidence, graph  # noqa: E402


def _schema(name):
    with open(os.path.join(ROOT, "schemas", name),
              encoding="utf-8") as fh:
        return json.load(fh)


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(SCRIPTS, filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FINGERPRINT = {"properties": {
    "package": {"value": "com.example.game"}}}

CLASSIC_PKG = {
    "entry": "Game/Content/Maps/MapA.uasset",
    "exports": [{"index": 0, "object_name": "MapA"},
                {"index": 1, "object_name": "Thing"}],
    "relationships": {
        "edges": [
            {"from": {"kind": "export", "index": 0,
                      "object_name": "MapA"},
             "to": {"kind": "import", "index": 2,
                    "object_name": "World",
                    "class_name": "Class",
                    "class_package": "/Script/Engine"},
             "kind": "class",
             "evidence": "export map class_index "
                         "(package-index resolution)"},
            {"from": {"kind": "export", "index": 1,
                      "object_name": "Thing"},
             "to": {"kind": "export", "index": 0,
                    "object_name": "MapA",
                    "class_name": "World"},
             "kind": "outer",
             "evidence": "export map outer_index "
                         "(package-index resolution)"},
            {"from": {"kind": "export", "index": 1,
                      "object_name": "Thing"},
             "to": {"kind": "export", "index": 9,
                    "note": "export index outside the "
                            "export map"},
             "kind": "super",
             "evidence": "export map super_index "
                         "(package-index resolution)"},
            {"from": {"kind": "export", "index": 0,
                      "object_name": "MapA"},
             "to": {"kind": "import", "index": 3,
                    "note": "import index outside the "
                            "import map"},
             "kind": "depends",
             "evidence": "depends map entry "
                         "(package-index resolution)"},
        ],
        "counts": {"total": 4, "processed": 4,
                   "skipped": 0, "failed": 0},
        "evidence": "table-derived: assembled from the "
                    "parsed import/export/depends maps only",
    },
}

ZEN_PKG = {
    "entry": "Game/Content/Zen/ZenPkg.uasset",
    "exports": [{"index": 0, "object_name": "ZenThing"}],
    "relationships": {
        "edges": [
            {"from": {"kind": "export", "index": 0,
                      "object_name": "ZenThing"},
             "to": {"kind": "script-import",
                    "resolved": "/Script/Engine.Actor"},
             "kind": "class",
             "evidence": "export map class object index "
                         "(FPackageObjectIndex)"},
            {"from": {"kind": "export", "index": 0,
                      "object_name": "ZenThing"},
             "to": {"kind": "export", "resolved": None,
                    "index": 0},
             "kind": "outer",
             "evidence": "export map outer object index "
                         "(FPackageObjectIndex)"},
            {"from": {"kind": "export", "index": 0,
                      "object_name": "ZenThing"},
             "to": {"kind": "package-import",
                    "resolved": None},
             "kind": "super",
             "evidence": "export map super object index "
                         "(FPackageObjectIndex)"},
        ],
        "counts": {"total": 3, "processed": 3,
                   "skipped": 0, "failed": 0},
        "evidence": "table-derived: assembled from the "
                    "parsed Zen export map only",
    },
}

CAPPED_PKG = {
    "entry": "Game/Content/Big/BigPkg.uasset",
    "exports": [{"index": 0, "object_name": "Big"}],
    "relationships": {
        "edges": [
            {"from": {"kind": "export", "index": 0,
                      "object_name": "Big"},
             "to": {"kind": "import", "index": 0,
                    "object_name": "Object",
                    "class_name": "Class",
                    "class_package": "/Script/CoreUObject"},
             "kind": "class",
             "evidence": "export map class_index "
                         "(package-index resolution)"},
        ],
        "counts": {"total": 900, "processed": 1,
                   "skipped": 899, "failed": 0},
        "evidence": "table-derived",
    },
}


def _items(*pkgs):
    return [{"field_path": f"engines.unreal_packages[{i}]",
             "record": pkg} for i, pkg in enumerate(pkgs)]


def _unreal_edges(doc):
    return [e for e in doc["edges"]
            if e["kind"].startswith("unreal_")]


class TestGraphUnreal(unittest.TestCase):

    def _build(self, items):
        return graph.build_graph(
            fingerprint_data=FINGERPRINT,
            unreal_data=items, version="2.6.1")

    def test_classic_relationships_join_with_discipline(self):
        doc = self._build(_items(CLASSIC_PKG))
        self.assertEqual(
            evidence.validate(
                doc, _schema("graph.schema.json")), [])
        kinds = {n["id"]: n for n in doc["nodes"]}
        pkg_id = "unreal_package:Game/Content/Maps/MapA.uasset"
        self.assertIn(pkg_id, kinds)
        # app -> package containment
        self.assertTrue(any(
            e["source"] == "application:com.example.game"
            and e["target"] == pkg_id
            and e["kind"] == "contains"
            for e in doc["edges"]))
        edges = _unreal_edges(doc)
        # every relationship edge in the record joined
        self.assertEqual(len(edges), 4)
        by_kind = {}
        for e in edges:
            by_kind.setdefault(e["kind"], []).append(e)
        self.assertEqual(len(by_kind["unreal_class"]), 1)
        self.assertEqual(by_kind["unreal_class"][0]
                         ["confidence"], "high")
        self.assertEqual(by_kind["unreal_outer"][0]
                         ["confidence"], "high")
        # out-of-map targets stay unresolved + low
        sup = by_kind["unreal_super"][0]
        self.assertEqual(sup["confidence"], "low")
        target = kinds[sup["target"]]
        self.assertEqual(target["status"], "unresolved")
        dep = by_kind["unreal_depends"][0]
        self.assertEqual(dep["confidence"], "low")
        self.assertEqual(kinds[dep["target"]]["status"],
                         "unresolved")
        # provenance points at the report field path
        self.assertEqual(
            sup["evidence"]["document"], "report.json")
        self.assertTrue(sup["evidence"]["field_path"]
                        .endswith("relationships.edges[2]"))
        self.assertIn("unreal", doc["contributing_stages"])
        # counts reconcile with the record's accounting
        total_unreal_nodes = sum(
            1 for n in doc["nodes"]
            if n["kind"] in ("unreal_package",
                             "unreal_object"))
        self.assertEqual(
            doc["counts"]["nodes_by_kind"]
            ["unreal_package"], 1)
        self.assertEqual(total_unreal_nodes,
                         doc["counts"]["nodes_by_kind"]
                         ["unreal_package"]
                         + doc["counts"]["nodes_by_kind"]
                         ["unreal_object"])

    def test_zen_relationships_join_with_discipline(self):
        doc = self._build(_items(ZEN_PKG))
        self.assertEqual(
            evidence.validate(
                doc, _schema("graph.schema.json")), [])
        edges = _unreal_edges(doc)
        self.assertEqual(len(edges), 3)
        by_kind = {e["kind"]: e for e in edges}
        # script-import with resolution text: medium
        self.assertEqual(by_kind["unreal_class"]
                         ["confidence"], "medium")
        # same-package export target by index: high
        self.assertEqual(by_kind["unreal_outer"]
                         ["confidence"], "high")
        # package-import without resolution: unresolved
        sup = by_kind["unreal_super"]
        self.assertEqual(sup["confidence"], "low")
        kinds = {n["id"]: n for n in doc["nodes"]}
        self.assertEqual(kinds[sup["target"]]["status"],
                         "unresolved")

    def test_capped_relationships_record_the_cap(self):
        doc = self._build(_items(CAPPED_PKG))
        self.assertEqual(len(_unreal_edges(doc)), 1)
        self.assertTrue(any(
            "BigPkg" in note and "900" in note
            for note in doc["notes"]))

    def test_no_unreal_input_is_byte_identical(self):
        plain = graph.build_graph(
            fingerprint_data=FINGERPRINT, version="2.6.1")
        with_none = graph.build_graph(
            fingerprint_data=FINGERPRINT, unreal_data=None,
            version="2.6.1")
        with_empty = graph.build_graph(
            fingerprint_data=FINGERPRINT, unreal_data=[],
            version="2.6.1")
        enc = lambda d: json.dumps(d, sort_keys=True)
        self.assertEqual(enc(plain), enc(with_none))
        self.assertEqual(enc(plain), enc(with_empty))
        self.assertFalse(any(
            n["kind"].startswith("unreal")
            for n in plain["nodes"]))

    def test_record_without_relationships_is_skipped(self):
        bare = {"entry": "Game/Content/Bare.uasset",
                "exports": []}
        doc = self._build(_items(bare))
        self.assertFalse(any(
            n["kind"] == "unreal_package"
            for n in doc["nodes"]))

    def test_analyze_assembly_helper(self):
        az = _load("nar_analyze_unreal_test",
                   "nar-analyze.py")
        report = {"engines": {
            "unreal_packages": [CLASSIC_PKG,
                                {"entry": "x.uasset"}],
            "unreal_iostore_packages": [ZEN_PKG],
            "unreal_pak_packages": [],
            "flutter": {"some": "thing"}}}
        items = az._unreal_graph_input(report)
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["field_path"],
                         "engines.unreal_packages[0]")
        self.assertEqual(items[1]["field_path"],
                         "engines.unreal_iostore_packages[0]")
        self.assertEqual(az._unreal_graph_input({}), [])
        self.assertEqual(
            az._unreal_graph_input({"engines": {}}), [])


if __name__ == "__main__":
    unittest.main()
