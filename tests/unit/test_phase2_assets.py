"""Unit tests: Phase 2 assets fix round (M2-11).

Pins the corrected inventory scope and the content-evidence
classification discipline in nar-assets:

- scope: the assets/ and res/ trees of every archive root
  (base, merged splits, bundle module roots), engine
  containers by extension wherever they sit, and every
  member of an OBB payload archive; DEX / lib/ / manifest /
  resources.arsc / META-INF members stay out (other stages'
  scope);
- classification: magic first (SVG, gzip, WOFF/WOFF2, BMF,
  bplist, sfnt, AXML, Unreal package/locres, Lua, Rive,
  Aseprite signatures), extension second, content evidence
  third — an extension never commits a text/data-family
  category on binary content with no recognized signature,
  and readable text with no signature/extension rule is
  reported as text data instead of unknown.
"""
import gzip
import importlib.util
import io
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))


def _load():
    spec = importlib.util.spec_from_file_location(
        "nar_assets_p2", SCRIPTS / "nar-assets.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


nar_assets = _load()

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
AXML = b"\x03\x00\x08\x00" + b"\x78\x01\x00\x00" + b"\x00" * 24
TTF = b"\x00\x01\x00\x00" + b"\x00" * 28
BINARY = bytes(range(256)) * 2
MANIFEST = b"\x03\x00\x08\x00" + b"\x00" * 12


def _zip_bytes(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def _apk(tmp_path, name, members, manifest=True):
    entries = []
    if manifest:
        entries += [("AndroidManifest.xml", MANIFEST),
                    ("classes.dex", b"dex\n035\x00" + b"\x00" * 24)]
    entries += members
    path = tmp_path / name
    path.write_bytes(_zip_bytes(entries))
    return str(path)


def _by_path(report):
    return {a["path"]: a for a in report["assets"]}


def _cat(report, path):
    entry = _by_path(report)[path]
    return entry["type"], entry["category"]


# ------------------------------------------------------------------
# scope
# ------------------------------------------------------------------

def test_res_tree_inventoried_and_scope_exclusions(tmp_path):
    apk = _apk(tmp_path, "a.apk", [
        ("assets/notes.txt", b"hello"),
        ("res/drawable/icon.png", PNG),
        ("res/layout/main.xml", AXML),
        ("res/font/app.ttf", TTF),
        ("res/raw/beep.wav", b"RIFF" + b"\x00" * 32),
        ("lib/arm64-v8a/libx.so", b"\x7fELF" + b"\x00" * 24),
        ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
        ("resources.arsc", b"\x02\x00\x08\x00" + b"\x00" * 24),
        ("kotlin/collections/collections.kotlin_builtins",
         b"\x00" * 16),
    ])
    report = nar_assets.inventory(apk)
    paths = set(_by_path(report))
    assert "assets/notes.txt" in paths
    assert "res/drawable/icon.png" in paths
    assert "res/layout/main.xml" in paths
    assert "res/font/app.ttf" in paths
    assert "res/raw/beep.wav" in paths
    # Other stages' scope: never inventoried here.
    assert "classes.dex" not in paths
    assert "lib/arm64-v8a/libx.so" not in paths
    assert "META-INF/MANIFEST.MF" not in paths
    assert "resources.arsc" not in paths
    assert not any(p.startswith("kotlin/") for p in paths)
    assert _cat(report, "res/drawable/icon.png") == \
        ("png-image", "texture")
    assert _cat(report, "res/layout/main.xml") == ("xml", "data")
    assert _cat(report, "res/font/app.ttf") == ("ttf-font", "font")


def test_bundle_module_roots_inventoried(tmp_path):
    aab = tmp_path / "app.aab"
    aab.write_bytes(_zip_bytes([
        ("base/manifest/AndroidManifest.xml", MANIFEST),
        ("base/dex/classes.dex", b"dex\n035\x00" + b"\x00" * 24),
        ("base/assets/intro.txt", b"intro"),
        ("base/res/drawable/icon.png", PNG),
        ("feature1/assets/level.json", b"{}"),
    ]))
    report = nar_assets.inventory(str(aab))
    paths = set(_by_path(report))
    assert "base/assets/intro.txt" in paths
    assert "base/res/drawable/icon.png" in paths
    assert "feature1/assets/level.json" in paths
    assert "base/dex/classes.dex" not in paths


def test_merged_split_res_members_inventoried(tmp_path):
    base = _zip_bytes([
        ("AndroidManifest.xml", MANIFEST),
        ("classes.dex", b"dex\n035\x00" + b"\x00" * 24),
        ("assets/base.txt", b"base")])
    split = _zip_bytes([
        ("AndroidManifest.xml", MANIFEST),
        ("classes.dex", b"dex\n035\x00" + b"\x00" * 24),
        ("assets/split.txt", b"split"),
        ("res/drawable/split.png", PNG)])
    manifest = json.dumps({
        "package_name": "com.example.game",
        "split_apks": [
            {"file": "com.example.game.apk", "id": "base"},
            {"file": "config.en.apk", "id": "config.en"}]})
    xapk = tmp_path / "game.xapk"
    xapk.write_bytes(_zip_bytes([
        ("manifest.json", manifest),
        ("com.example.game.apk", base),
        ("config.en.apk", split)]))
    report = nar_assets.inventory(str(xapk))
    paths = set(_by_path(report))
    assert "assets/base.txt" in paths
    assert "assets/split.txt" in paths
    assert "res/drawable/split.png" in paths
    assert report["assets_by_split"]["config.en.apk"] == 2


def test_obb_payload_fully_inventoried(tmp_path):
    apk = _apk(tmp_path, "a.apk", [("assets/a.txt", b"a")])
    obb = tmp_path / "main.1.com.example.game.obb"
    obb.write_bytes(_zip_bytes([
        ("payload.bin", BINARY),
        ("media/intro.txt", b"intro text")]))
    report = nar_assets.inventory(apk)
    by_path = _by_path(report)
    assert "payload.bin" in by_path
    assert "media/intro.txt" in by_path
    assert by_path["payload.bin"]["source_split"] == \
        "main.1.com.example.game.obb"
    assert report["assets_by_split"][
        "main.1.com.example.game.obb"] == 2


# ------------------------------------------------------------------
# classification: signatures
# ------------------------------------------------------------------

def test_svg_detection(tmp_path):
    apk = _apk(tmp_path, "a.apk", [
        ("assets/plain.svg",
         b'<svg xmlns="http://www.w3.org/2000/svg"></svg>'),
        ("assets/decl.svg",
         b'<?xml version="1.0"?>\n<svg width="4"></svg>'),
        ("assets/noext_icon",
         b'<svg width="2" height="2"></svg>'),
        ("assets/fake.svg", BINARY),
    ])
    report = nar_assets.inventory(apk)
    assert _cat(report, "assets/plain.svg") == \
        ("svg-image", "texture")
    assert _cat(report, "assets/decl.svg") == \
        ("svg-image", "texture")
    assert _cat(report, "assets/noext_icon") == \
        ("svg-image", "texture")
    # Extension alone never commits on binary content.
    assert _cat(report, "assets/fake.svg") == ("unknown", "other")


def test_bitmap_font_detection(tmp_path):
    apk = _apk(tmp_path, "a.apk", [
        ("assets/text.fnt",
         b'info face="Arial" size=32 bold=0\ncommon lineHeight=32'),
        ("assets/xml.fnt",
         b'<?xml version="1.0"?>\n<font><common lineHeight="1"/></font>'),
        ("assets/binary.fnt", b"BMF\x03" + b"\x00" * 28),
        ("assets/garbage.fnt", BINARY),
    ])
    report = nar_assets.inventory(apk)
    assert _cat(report, "assets/text.fnt") == \
        ("bitmap-font", "font")
    assert _cat(report, "assets/xml.fnt") == ("bitmap-font", "font")
    assert _cat(report, "assets/binary.fnt") == \
        ("bitmap-font", "font")
    assert _cat(report, "assets/garbage.fnt") == \
        ("unknown", "other")


def test_woff_magics(tmp_path):
    apk = _apk(tmp_path, "a.apk", [
        ("assets/a.woff2", b"wOF2" + b"\x00" * 28),
        ("assets/b.woff", b"wOFF" + b"\x00" * 28),
        ("assets/noext_font", b"wOF2" + b"\x00" * 28),
    ])
    report = nar_assets.inventory(apk)
    assert _cat(report, "assets/a.woff2") == ("woff2-font", "font")
    assert _cat(report, "assets/b.woff") == ("woff-font", "font")
    assert _cat(report, "assets/noext_font") == \
        ("woff2-font", "font")


def test_gzip_magic_and_extension(tmp_path):
    gz = gzip.compress(b'{"a": 1}')
    apk = _apk(tmp_path, "a.apk", [
        ("assets/data.json.gz", gz),
        ("assets/blob_noext", gz),
    ])
    report = nar_assets.inventory(apk)
    assert _cat(report, "assets/data.json.gz") == \
        ("gzip-archive", "container")
    assert _cat(report, "assets/blob_noext") == \
        ("gzip-archive", "container")


def test_axml_and_ttf_magics_beat_discipline(tmp_path):
    apk = _apk(tmp_path, "a.apk", [
        ("assets/compiled.xml", AXML),
        ("assets/real.ttf", TTF),
        ("assets/fake.ttf", BINARY),
        ("assets/real.otf", b"OTTO" + b"\x00" * 28),
    ])
    report = nar_assets.inventory(apk)
    assert _cat(report, "assets/compiled.xml") == ("xml", "data")
    assert _cat(report, "assets/real.ttf") == ("ttf-font", "font")
    assert _cat(report, "assets/real.otf") == ("otf-font", "font")
    assert _cat(report, "assets/fake.ttf") == ("unknown", "other")


# ------------------------------------------------------------------
# classification: content-evidence discipline + text fallback
# ------------------------------------------------------------------

def test_binary_content_discipline(tmp_path):
    apk = _apk(tmp_path, "a.apk", [
        ("assets/blob.dat", BINARY),
        ("assets/text.dat", b"key=value\nplain text payload\n"),
        ("assets/blob.json", BINARY),
        ("assets/real.json", b'{"key": "value"}'),
        ("assets/bone.skel", BINARY),
        ("assets/bone_json.skel", b'{"skeleton": {}, "bones": []}'),
        ("assets/scene.xml", b"BIN1Scene\x00\x00\x00id\x00abc\x00"),
        ("assets/plain.xml", b"<root><child/></root>"),
        ("assets/blob.bin", BINARY),
    ])
    report = nar_assets.inventory(apk)
    assert _cat(report, "assets/blob.dat") == ("unknown", "other")
    assert _cat(report, "assets/text.dat") == ("binary", "data")
    assert _cat(report, "assets/blob.json") == ("unknown", "other")
    assert _cat(report, "assets/real.json") == ("json", "data")
    assert _cat(report, "assets/bone.skel") == ("unknown", "other")
    assert _cat(report, "assets/bone_json.skel") == \
        ("spine-skeleton", "animation")
    assert _cat(report, "assets/scene.xml") == ("unknown", "other")
    assert _cat(report, "assets/plain.xml") == ("xml", "data")
    assert _cat(report, "assets/blob.bin") == ("unknown", "other")


def test_text_content_fallback(tmp_path):
    apk = _apk(tmp_path, "a.apk", [
        ("assets/IconList", b"one.png\r\ntwo.png\r\n"),
        ("assets/pkg.manifest", b'{"dependencies": []}'),
        ("assets/shader.fsh", b"void main() { gl_FragColor = vec4(1.0); }"),
        ("assets/tool.py", b"import os\nprint(os.name)\n"),
        ("assets/app.prop", b"server.host example.invalid\n"),
        ("assets/bin/Data/0123456789abcdef0123456789abcdef",
         BINARY),
        ("assets/rawblob", BINARY),
    ])
    report = nar_assets.inventory(apk)
    assert _cat(report, "assets/IconList") == ("text", "data")
    assert _cat(report, "assets/pkg.manifest") == ("text", "data")
    assert _cat(report, "assets/shader.fsh") == ("text", "data")
    assert _cat(report, "assets/rawblob") == ("unknown", "other")
    # No location-based commitment for extensionless binary
    # members (the Unity Data layout included).
    assert _cat(
        report, "assets/bin/Data/0123456789abcdef0123456789abcdef"
    ) == ("unknown", "other")


def test_python_source_extension(tmp_path):
    apk = _apk(tmp_path, "a.apk", [
        ("assets/tool.py", b"import os\nprint(os.name)\n"),
        ("assets/compiled.py", BINARY),
    ])
    report = nar_assets.inventory(apk)
    assert _cat(report, "assets/tool.py") == ("python", "code")
    assert _cat(report, "assets/compiled.py") == \
        ("unknown", "other")


def test_prop_extension(tmp_path):
    apk = _apk(tmp_path, "a.apk", [
        ("assets/app.prop", b"server.host example.invalid\n"),
    ])
    report = nar_assets.inventory(apk)
    assert _cat(report, "assets/app.prop") == \
        ("properties", "config")


def test_classify_window_utf8_edge(tmp_path):
    # A multi-byte character split by the classification
    # window edge must not make a text member read binary.
    text = b"a" * 8191 + "é".encode("utf-8") + b" tail\n"
    apk = _apk(tmp_path, "a.apk", [
        ("assets/long_text", text),
        ("assets/long_binary", b"a" * 8000 + b"\x00" + b"b" * 400),
    ])
    report = nar_assets.inventory(apk)
    assert _cat(report, "assets/long_text") == ("text", "data")
    assert _cat(report, "assets/long_binary") == \
        ("unknown", "other")
