"""Unit tests: formats.json registry + coverage (Part 16 + 1).

Pins the single-source-of-truth migration:

- the loader validates formats.json (a supported entry with
  no test_ref, or a non-supported entry with no reason/probe,
  is a hard error — Part 1: no silent omission);
- the derived views reproduce the historical consumer tables
  (26 engines, 18 JNI families, 19 triage signatures, 13
  engine DEX markers);
- the asset-format inventory in formats.json is exactly
  nar-assets' EXT_TYPES extension set (no drift either way);
- scripts/coverage.json is fresh: it equals the projection
  regenerated from formats.json, and it validates against
  schemas/coverage.schema.json;
- the migrated consumers (nar-engines, nar-triage,
  nar-analyze, narlib/graph) carry none of the migrated
  marker literals — the data lives in formats.json only.
"""
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from narlib import evidence, formats_registry  # noqa: E402


def _load_script(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_registry_loads_and_validates():
    doc = formats_registry.load_formats()
    assert doc["version"] == "1"
    for section in formats_registry.SECTIONS:
        assert doc.get(section), section


def test_supported_entries_have_test_refs():
    coverage = formats_registry.build_coverage()
    for section in formats_registry.SECTIONS:
        for entry in coverage[section]:
            if entry["status"] == "supported":
                assert entry["test_ref"], (section, entry["id"])
            else:
                assert entry["reason"], (section, entry["id"])
                assert entry["probe"], (section, entry["id"])


def test_validation_rejects_supported_without_test_ref():
    doc = json.loads(json.dumps(formats_registry.load_formats()))
    doc["engines"]["godot"]["test_ref"] = None
    try:
        formats_registry.validate_formats(doc)
    except ValueError:
        return
    raise AssertionError("supported entry without test_ref accepted")


def test_derived_views_match_historical_tables():
    assert len(formats_registry.engines_table()) == 26
    assert len(formats_registry.jni_markers()) == 18
    assert len(formats_registry.triage_signatures()) == 19
    assert len(formats_registry.engine_dex_markers()) == 13


def test_asset_formats_match_ext_types():
    assets = _load_script("nar_assets_for_registry", "nar-assets.py")
    formats = formats_registry.load_formats()
    in_registry = set()
    for entry in formats["asset_formats"].values():
        in_registry.update(entry["ext"])
    assert in_registry == set(assets.EXT_TYPES)


def test_coverage_json_is_fresh():
    committed = json.loads(
        (SCRIPTS / "coverage.json").read_text(encoding="utf-8"))
    assert committed == formats_registry.build_coverage()


def test_coverage_validates_against_schema():
    schema = json.loads(
        (ROOT / "schemas" / "coverage.schema.json").read_text(
            encoding="utf-8"))
    doc = formats_registry.build_coverage()
    assert evidence.validate(doc, schema) == []


def test_no_marker_literals_in_consumers():
    samples = [
        "Java_org_cocos2dx", "libcocos2dcpp", "Java_com_unity3d",
        "Java_org_godotengine", "Java_com_epicgames",
        "libil2cpp.so", "global-metadata.dat", "org/cocos2dx",
        "com/unity3d/player", "libflutter.so",
    ]
    consumers = ["nar-engines.py", "nar-triage.py",
                 "nar-analyze.py", "narlib/graph.py"]
    for rel in consumers:
        text = (SCRIPTS / rel).read_text(encoding="utf-8")
        for sample in samples:
            assert sample not in text, (rel, sample)
