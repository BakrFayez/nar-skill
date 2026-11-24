"""Evolution Phase 4 tests: engine intelligence depth.

- Unity Addressables catalog parsing (synthetic catalog +
  the real bundles fixture when present);
- React Native source-map detection + native-module
  inventory from a planted text bundle (Hermes name
  attribution stays honestly off — covered by the marker
  assertions on the real fixture in the e2e matrix);
- Flutter real asset inventory from a planted APK;
- Godot pack resource-type classification (header magic
  beats extension; encrypted entries are never typed).

No app data: planted bundles/catalogs are synthetic.
"""
import base64
import importlib.util
import json
import os
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
FIXTURES = Path(os.environ.get(
    "NAR_FIXTURES", "~/workspace/nar-e2e-fixtures")).expanduser()

_spec = importlib.util.spec_from_file_location(
    "nar_godot", SCRIPTS / "nar-godot.py")
nar_godot = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nar_godot)


def _run(script, *args):
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / script), *args],
        capture_output=True, text=True, timeout=600)
    assert proc.returncode == 0, proc.stderr[-500:]
    return json.loads(proc.stdout)


def _apk(path, entries):
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return str(path)


# ---------------------------------------------------------------- Unity

def _synthetic_catalog():
    entries = b""
    # (internal_id, provider, dep_off, dep_hash, data_off,
    #  key, resource_type)
    rows = [(0, 0, -1, 0, -1, 0, 1),
            (1, 1, -1, 0, -1, 1, 0),
            (1, 0, -1, 0, -1, 2, 1)]
    blob = struct.pack("<i", len(rows)) + b"".join(
        struct.pack("<7i", *r) for r in rows)
    return json.dumps({
        "m_LocatorId": "SyntheticCatalog",
        "m_BuildResultHash": "ab12",
        "m_InstanceProviderData": {
            "m_Id": "InstanceProvider",
            "m_ObjectType": {"m_ClassName": "InstanceProvider"}},
        "m_SceneProviderData": {
            "m_Id": "SceneProvider",
            "m_ObjectType": {"m_ClassName": "SceneProvider"}},
        "m_ResourceProviderData": [
            {"m_Id": "AssetBundleProvider",
             "m_ObjectType": {"m_ClassName": "ABP"}}],
        "m_ProviderIds": ["AssetBundleProvider",
                          "BundledAssetProvider"],
        "m_InternalIds": ["loc/level1", "loc/tex"],
        "m_resourceTypes": [
            {"m_AssemblyName": "A", "m_ClassName": "GameObject"},
            {"m_AssemblyName": "A", "m_ClassName": "Texture2D"}],
        "m_EntryDataString": base64.b64encode(blob).decode(),
    }).encode()


def test_unity_catalog_synthetic(tmp_path):
    apk = _apk(tmp_path / "cat.apk", {
        "assets/aa/catalog.json": _synthetic_catalog(),
        "assets/aa/x.bundle": b"UnityFS synthetic",
    })
    report = _run("nar-unity.py", apk, "--json")
    cat = report["addressables_catalog"]
    assert cat["parsed"] is True
    assert cat["location_count"] == 2
    assert cat["resource_type_count"] == 2
    ent = cat["entries"]
    assert ent["decoded"] is True and ent["count"] == 3
    assert set(ent["fields_validated"]) == {
        "internal_id_index", "resource_type_index",
        "provider_index"}
    by_type = {e["type"]: e["entries"]
               for e in ent["by_resource_type"]}
    assert by_type == {"Texture2D": 2, "GameObject": 1}
    by_provider = {e["provider"]: e["entries"]
                   for e in ent["by_provider"]}
    assert by_provider == {"AssetBundleProvider": 2,
                           "BundledAssetProvider": 1}


def test_unity_catalog_real_fixture():
    fixture = FIXTURES / "games" / "unity-bundles.apk"
    if not fixture.is_file():
        import pytest
        pytest.skip("unity bundles fixture absent")
    report = _run("nar-unity.py", str(fixture), "--json")
    cat = report["addressables_catalog"]
    assert cat["parsed"] is True
    assert cat["location_count"] == 6798
    assert cat["entries"]["count"] == 24820
    assert cat["entries"]["decoded"] is True


# ------------------------------------------------------- React Native

def test_rn_text_bundle_inventory(tmp_path):
    bundle = (
        "var TurboModuleRegistry = require('tm');\n"
        "var cam = TurboModuleRegistry.getEnforcing("
        "'NativeCamera');\n"
        "var loc = TurboModuleRegistry.get('NativeLocation');\n"
        "var VideoView = codegenNativeComponent('VideoView');\n"
        "var settings = NativeModules.Settings;\n"
        "//# sourceMappingURL=index.android.bundle.map\n"
    ).encode()
    apk = _apk(tmp_path / "rn.apk", {
        "assets/index.android.bundle": bundle,
        "assets/index.android.bundle.map": b"{}",
    })
    report = _run("nar-rn.py", apk, "--json",
                  "--work", str(tmp_path / "work"))
    assert report["is_react_native"] is True
    assert report["source_maps"] == [
        "assets/index.android.bundle.map"]
    nm = report["native_modules"]
    assert nm["module_names_extracted"] is True
    assert nm["turbomodules"] == ["NativeCamera",
                                  "NativeLocation"]
    assert nm["fabric_components"] == ["VideoView"]
    assert nm["native_modules_referenced"] == ["Settings"]
    assert nm["bundle_source_mapping_url"] == \
        "index.android.bundle.map"


# ------------------------------------------------------------- Flutter

def test_flutter_asset_inventory(tmp_path):
    apk = _apk(tmp_path / "fl.apk", {
        "lib/arm64-v8a/libflutter.so": b"\x7fELF synthetic",
        "lib/arm64-v8a/libapp.so": b"\x7fELF synthetic",
        "assets/flutter_assets/AssetManifest.json":
            json.dumps({"assets/a.png": ["assets/a.png"],
                        "assets/b.ttf": ["assets/b.ttf"]}),
        "assets/flutter_assets/assets/a.png": b"\x89PNG",
        "assets/flutter_assets/assets/b.ttf": b"\x00\x01\x00\x00",
        "assets/flutter_assets/FontManifest.json": b"[]",
        "assets/flutter_assets/shaders/ink_sparkle.frag":
            b"#version 320 es",
    })
    report = _run("nar-flutter.py", apk, "--json")
    inv = report["flutter_assets"]
    assert inv["entry_count"] == 5
    assert inv["by_type"]["image"] == 1
    assert inv["by_type"]["font"] == 1
    assert inv["by_type"]["shader"] == 1
    assert inv["asset_manifest"]["json_present"] is True
    assert inv["asset_manifest"]["declared_assets"] == 2


# --------------------------------------------------------------- Godot

def _build_pack(files):
    """Minimal format-2 pack. files: (path, content, flags)."""
    header = (b"GDPC" + struct.pack("<IIII", 2, 4, 3, 0)
              + struct.pack("<IQ", 0, 0) + b"\x00" * 64)
    data = bytearray()
    entries = bytearray()
    base = len(header)
    # Directory size must be known before offsets; entries
    # have fixed-size tails, so compute it up front.
    dir_size = 4 + sum(
        4 + ((len(p) + 3) & ~3) + 16 + 16 + 4
        for p, _, _ in files)
    offset = base + dir_size
    for path, content, flags in files:
        raw = path.encode()
        entries += struct.pack("<I", len(raw)) + raw
        entries += b"\x00" * ((4 - len(raw) % 4) % 4)
        entries += struct.pack("<QQ", offset, len(content))
        entries += b"\x00" * 16
        entries += struct.pack("<I", flags)
        data += content
        offset += len(content)
    return header + struct.pack("<I", len(files)) + entries \
        + bytes(data)


def test_godot_resource_classification():
    rsrc = (b"RSRC" + struct.pack("<III", 4, 3, 0)
            + struct.pack("<I", 11) + b"PackedScene")
    pack = _build_pack([
        ("res://level.tscn", b"[gd_scene load_steps=2]\n", 0),
        ("res://icon.png", b"\x89PNG\r\n\x1a\n....", 0),
        ("res://data.bin", rsrc, 0),
        ("res://main.gd", b"extends Node\n", 0),
        ("res://secret.png", b"\x89PNG\r\n\x1a\n....", 1),
    ])
    report = nar_godot.parse_pck(pack)
    files = {f["path"]: f for f in report["files"]}
    assert files["res://level.tscn"]["resource_type"] == \
        "scene"
    assert files["res://level.tscn"]["type_evidence"] == \
        "header"
    assert files["res://icon.png"]["resource_type"] == \
        "texture"
    assert files["res://icon.png"]["type_evidence"] == \
        "header"
    assert files["res://data.bin"]["resource_type"] == \
        "binary resource"
    assert files["res://data.bin"]["type_detail"] == \
        "PackedScene"
    assert files["res://main.gd"]["resource_type"] == "script"
    assert files["res://main.gd"]["type_evidence"] == \
        "extension"
    # Encrypted entries are never typed by guess.
    assert files["res://secret.png"]["resource_type"] is None
    assert report["file_types"]["scene"] == 1
    assert report["file_types"][
        "encrypted (unclassified)"] == 1
