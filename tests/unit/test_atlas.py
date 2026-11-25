"""Unit tests: texture atlas parsers, part grouping and
composition inference (Part 4 section 4.1).

All fixtures are synthetic with invented generic names.
Pins: the uniform atlas record across Cocos plist (XML and
binary), TexturePacker JSON (hash / array), Phaser
multi-texture JSON, Starling XML, TexturePacker XML, libGDX
text, Godot .tres and Unity .spriteatlas (GUID-only
fidelity); strict JSON classification (Lottie-shaped and
arbitrary JSON must NOT classify as atlases); Cocos particle
plist records; vehicle / ui grouping and composition
records; and an end-to-end nar-atlas run on a tiny synthetic
APK validated against schemas/atlas.schema.json and
schemas/composition.schema.json.
"""
import importlib.util
import json
import os
import plistlib
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from narlib import atlas as atlas_mod  # noqa: E402
from narlib import composition as comp_mod  # noqa: E402
from narlib import evidence  # noqa: E402


def _schema(name):
    with open(os.path.join(ROOT, "schemas", name),
              encoding="utf-8") as fh:
        return json.load(fh)


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "nar_atlas_tool", os.path.join(ROOT, "scripts",
                                       "nar-atlas.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cocos_doc():
    return {
        "frames": {
            "rig-van-chassis.png": {
                "frame": "{{2,2},{120,60}}", "rotated": False,
                "offset": "{0,0}", "sourceSize": "{128,64}",
                "sourceColorRect": "{{4,2},{120,60}}"},
            "rig-van-wheel-front.png": {
                "frame": "{{124,2},{32,32}}", "rotated": True,
                "offset": "{1,1}", "sourceSize": "{36,36}"},
            "rig-van-wheel-back.png": {
                "frame": "{{158,2},{32,32}}", "rotated": False,
                "offset": "{1,1}", "sourceSize": "{36,36}"},
            "rig-van-spring.png": {
                "frame": "{{192,2},{10,40}}", "rotated": False,
                "offset": "{0,0}", "sourceSize": "{10,40}"},
            "rig-van-cabin.png": {
                "frame": "{{204,2},{48,30}}", "rotated": False,
                "offset": "{0,0}", "sourceSize": "{48,30}"},
        },
        "metadata": {
            "format": 2, "size": "{256,128}",
            "textureFileName": "rig-sheet.png",
            "realTextureFileName": "rig-sheet.png",
        },
    }


def particle_doc():
    return {
        "maxParticles": 80, "particleLifespan": 1.5,
        "particleLifespanVariance": 0.4,
        "startParticleSize": 12, "finishParticleSize": 2,
        "gravityx": 0, "gravityy": -40,
        "radialAccel": 5, "tangentialAccel": 0,
        "emitterType": 0, "angle": 90, "speed": 30,
        "duration": -1,
    }


class CocosPlistTest(unittest.TestCase):
    def _assert_rig(self, rec):
        self.assertIsNone(rec["error"])
        self.assertEqual(rec["format"], "cocos-plist")
        self.assertEqual(rec["texture"], "rig-sheet.png")
        self.assertEqual(rec["page_width"], 256)
        self.assertEqual(rec["page_height"], 128)
        self.assertEqual(rec["page_area"], 256 * 128)
        self.assertEqual(rec["frame_count"], 5)
        self.assertEqual(rec["rotated_count"], 1)
        self.assertEqual(rec["packed_area"],
                         120 * 60 + 32 * 32 + 32 * 32
                         + 10 * 40 + 48 * 30)
        by_name = {f["name"]: f for f in rec["frames"]}
        chassis = by_name["rig-van-chassis.png"]
        self.assertEqual(
            (chassis["x"], chassis["y"], chassis["w"],
             chassis["h"]), (2, 2, 120, 60))
        self.assertEqual(
            (chassis["source_w"], chassis["source_h"]),
            (128, 64))
        wheel = by_name["rig-van-wheel-front.png"]
        self.assertTrue(wheel["rotated"])
        self.assertEqual((wheel["offset_x"], wheel["offset_y"]),
                         (1, 1))

    def test_xml_plist(self):
        data = plistlib.dumps(cocos_doc())
        self._assert_rig(atlas_mod.parse_cocos_plist(data))

    def test_binary_plist(self):
        data = plistlib.dumps(cocos_doc(),
                              fmt=plistlib.FMT_BINARY)
        self._assert_rig(atlas_mod.parse_cocos_plist(data))

    def test_format3_and_dict_rect_styles(self):
        doc = {
            "frames": {
                "sprite-a": {
                    "textureRect": "{{5,6},{20,10}}",
                    "textureRotated": True,
                    "spriteOffset": "{2,3}",
                    "spriteSourceSize": "{24,16}"},
                "sprite-b": {
                    "frame": {"x": 30, "y": 6, "w": 8,
                              "h": 8},
                    "rotated": False},
            },
            "metadata": {"size": "{64,64}",
                         "textureFileName": "sheet.png"},
        }
        rec = atlas_mod.parse_cocos_plist(plistlib.dumps(doc))
        self.assertIsNone(rec["error"])
        self.assertEqual(rec["frame_count"], 2)
        by_name = {f["name"]: f for f in rec["frames"]}
        a = by_name["sprite-a"]
        self.assertEqual((a["x"], a["y"], a["w"], a["h"]),
                         (5, 6, 20, 10))
        self.assertTrue(a["rotated"])
        self.assertEqual((a["source_w"], a["source_h"]),
                         (24, 16))
        b = by_name["sprite-b"]
        self.assertEqual((b["x"], b["y"], b["w"], b["h"]),
                         (30, 6, 8, 8))

    def test_particle_plist(self):
        rec = atlas_mod.parse_cocos_plist(
            plistlib.dumps(particle_doc()))
        self.assertEqual(rec["format"], "cocos-particle-plist")
        p = rec["particle"]
        self.assertEqual(p["max_particles"], 80)
        self.assertEqual(p["lifespan"], 1.5)
        self.assertEqual(p["start_size"], 12)
        self.assertEqual(p["end_size"], 2)
        self.assertEqual(p["gravity"]["y"], -40)
        self.assertTrue(p["has_radial_accel"])
        self.assertTrue(p["has_tangential_accel"])

    def test_malformed_plist_is_error_record(self):
        rec = atlas_mod.parse_cocos_plist(b"this is not a plist")
        self.assertIsNotNone(rec["error"])
        self.assertEqual(rec["frame_count"], 0)


class TexturePackerJsonTest(unittest.TestCase):
    def test_hash_variant(self):
        doc = {
            "frames": {
                "hero-torso.png": {
                    "frame": {"x": 0, "y": 0, "w": 40, "h": 60},
                    "rotated": False, "trimmed": True,
                    "spriteSourceSize": {"x": 4, "y": 2, "w": 40,
                                         "h": 60},
                    "sourceSize": {"w": 48, "h": 64}},
                "hero-head.png": {
                    "frame": {"x": 42, "y": 0, "w": 20, "h": 20},
                    "rotated": True, "trimmed": False,
                    "spriteSourceSize": {"x": 0, "y": 0, "w": 20,
                                         "h": 20},
                    "sourceSize": {"w": 20, "h": 20}},
            },
            "meta": {"app": "https://www.codeandweb.com/"
                            "texturepacker",
                     "image": "hero.png",
                     "size": {"w": 128, "h": 128}},
        }
        self.assertEqual(atlas_mod.classify_json_atlas(doc),
                         "texturepacker-json-hash")
        (rec,) = atlas_mod.parse_texturepacker_json(doc)
        self.assertEqual(rec["texture"], "hero.png")
        self.assertEqual((rec["page_width"], rec["page_height"]),
                         (128, 128))
        self.assertEqual(rec["frame_count"], 2)
        self.assertEqual(rec["rotated_count"], 1)
        by_name = {f["name"]: f for f in rec["frames"]}
        torso = by_name["hero-torso.png"]
        self.assertEqual((torso["offset_x"], torso["offset_y"]),
                         (4, 2))
        self.assertEqual((torso["source_w"], torso["source_h"]),
                         (48, 64))

    def test_array_variant(self):
        doc = {
            "frames": [
                {"filename": "tile-a.png",
                 "frame": {"x": 0, "y": 0, "w": 16, "h": 16},
                 "rotated": False,
                 "spriteSourceSize": {"x": 0, "y": 0, "w": 16,
                                      "h": 16},
                 "sourceSize": {"w": 16, "h": 16}},
                {"filename": "tile-b.png",
                 "frame": {"x": 18, "y": 0, "w": 16, "h": 16},
                 "rotated": False,
                 "spriteSourceSize": {"x": 0, "y": 0, "w": 16,
                                      "h": 16},
                 "sourceSize": {"w": 16, "h": 16}},
            ],
            "meta": {"image": "tiles.png",
                     "size": {"w": 64, "h": 32}},
        }
        self.assertEqual(atlas_mod.classify_json_atlas(doc),
                         "texturepacker-json-array")
        (rec,) = atlas_mod.parse_texturepacker_json(doc)
        self.assertEqual(rec["frame_count"], 2)
        self.assertEqual(rec["packed_area"], 2 * 16 * 16)

    def test_phaser_multi_texture_variant(self):
        page = lambda img, name: {  # noqa: E731
            "image": img, "size": {"w": 64, "h": 64},
            "frames": [
                {"filename": name,
                 "frame": {"x": 0, "y": 0, "w": 10, "h": 10},
                 "rotated": False,
                 "spriteSourceSize": {"x": 0, "y": 0, "w": 10,
                                      "h": 10},
                 "sourceSize": {"w": 10, "h": 10}}]}
        doc = {"textures": [page("page-one.png", "spr-a.png"),
                            page("page-two.png", "spr-b.png")]}
        self.assertEqual(atlas_mod.classify_json_atlas(doc),
                         "phaser-json")
        records = atlas_mod.parse_texturepacker_json(doc)
        self.assertEqual(len(records), 2)
        self.assertEqual([r["texture"] for r in records],
                         ["page-one.png", "page-two.png"])
        self.assertTrue(all(r["frame_count"] == 1
                            for r in records))

    def test_non_atlas_json_never_classifies(self):
        lottie = {"v": "5.7.4", "fr": 30, "ip": 0, "op": 60,
                  "w": 100, "h": 100, "layers": [{"ty": 4}],
                  "assets": []}
        self.assertIsNone(atlas_mod.classify_json_atlas(lottie))
        spine = {"bones": [{"name": "root"}], "slots": [],
                 "skins": {}}
        self.assertIsNone(atlas_mod.classify_json_atlas(spine))
        random_doc = {"hello": "world",
                      "frames": {"a": {"x": 1, "y": 2}}}
        self.assertIsNone(
            atlas_mod.classify_json_atlas(random_doc))
        broken_rect = {"frames": {
            "a.png": {"frame": {"x": 0, "y": 0, "w": 10}}}}
        self.assertIsNone(
            atlas_mod.classify_json_atlas(broken_rect))
        (rec,) = atlas_mod.parse_texturepacker_json(lottie)
        self.assertIsNotNone(rec["error"])


class XmlAtlasTest(unittest.TestCase):
    def test_starling_xml(self):
        xml = """<TextureAtlas imagePath="hero-sheet.png">
          <SubTexture name="hero-torso" x="0" y="0" width="40"
            height="60" frameX="-4" frameY="-2"
            frameWidth="48" frameHeight="64"/>
          <SubTexture name="hero-arm" x="48" y="0" width="12"
            height="40" rotated="true"/>
        </TextureAtlas>"""
        rec = atlas_mod.parse_xml_atlas(xml.encode())
        self.assertIsNone(rec["error"])
        self.assertEqual(rec["format"], "starling-xml")
        self.assertEqual(rec["texture"], "hero-sheet.png")
        self.assertEqual(rec["frame_count"], 2)
        self.assertEqual(rec["rotated_count"], 1)
        by_name = {f["name"]: f for f in rec["frames"]}
        torso = by_name["hero-torso"]
        self.assertEqual((torso["source_w"], torso["source_h"]),
                         (48, 64))
        self.assertEqual((torso["offset_x"], torso["offset_y"]),
                         (4, 2))

    def test_texturepacker_xml(self):
        xml = """<TextureAtlas imagePath="ui-sheet.png">
          <sprite n="btn-play" x="0" y="0" w="80" h="30" r="0"
            oX="2" oY="3" oW="84" oH="36"/>
          <sprite n="btn-close" x="82" y="0" w="30" h="30"
            r="1" oX="0" oY="0" oW="30" oH="30"/>
        </TextureAtlas>"""
        rec = atlas_mod.parse_xml_atlas(xml)
        self.assertIsNone(rec["error"])
        self.assertEqual(rec["format"], "texturepacker-xml")
        self.assertEqual(rec["frame_count"], 2)
        self.assertEqual(rec["rotated_count"], 1)
        by_name = {f["name"]: f for f in rec["frames"]}
        play = by_name["btn-play"]
        self.assertEqual((play["offset_x"], play["offset_y"]),
                         (2, 3))
        self.assertEqual((play["source_w"], play["source_h"]),
                         (84, 36))

    def test_malformed_xml_is_error_record(self):
        rec = atlas_mod.parse_xml_atlas(b"<TextureAtlas><oops")
        self.assertIsNotNone(rec["error"])


class LibGdxTest(unittest.TestCase):
    TEXT = """page-one.png
size: 256,256
format: RGBA8888
filter: Linear,Linear
repeat: none
rig-van-chassis
  rotate: false
  xy: 2, 2
  size: 120, 60
  orig: 128, 64
  offset: 4, 2
  index: -1
rig-van-wheel
  rotate: true
  xy: 124, 2
  size: 32, 32
  orig: 32, 32
  offset: 0, 0
  index: -1

page-two.png
size: 128,128
format: RGBA8888
filter: Linear,Linear
repeat: none
tile-ground
  rotate: 90
  bounds: 2, 2, 40, 20
  offsets: 1, 1, 44, 24
  index: -1
"""

    def test_two_pages_both_region_styles(self):
        records = atlas_mod.parse_libgdx_atlas(self.TEXT)
        self.assertEqual(len(records), 2)
        one, two = records
        self.assertEqual(one["texture"], "page-one.png")
        self.assertEqual((one["page_width"], one["page_height"]),
                         (256, 256))
        self.assertEqual(one["frame_count"], 2)
        self.assertEqual(one["rotated_count"], 1)
        by_name = {f["name"]: f for f in one["frames"]}
        chassis = by_name["rig-van-chassis"]
        self.assertEqual(
            (chassis["x"], chassis["y"], chassis["w"],
             chassis["h"]), (2, 2, 120, 60))
        self.assertEqual(
            (chassis["source_w"], chassis["source_h"]),
            (128, 64))
        self.assertEqual(
            (chassis["offset_x"], chassis["offset_y"]), (4, 2))
        self.assertTrue(by_name["rig-van-wheel"]["rotated"])
        self.assertEqual(two["texture"], "page-two.png")
        (tile,) = two["frames"]
        self.assertTrue(tile["rotated"])
        self.assertEqual((tile["w"], tile["h"]), (40, 20))
        self.assertEqual((tile["source_w"], tile["source_h"]),
                         (44, 24))
        self.assertEqual((tile["offset_x"], tile["offset_y"]),
                         (1, 1))


class GodotTresTest(unittest.TestCase):
    TEXT = """[gd_resource type="AtlasTexture" load_steps=2 format=3 uid="uid://synthetic1"]

[ext_resource type="Texture2D" path="res://art/sheet.png" id="1_abcd"]

[resource]
atlas = ExtResource("1_abcd")
region = Rect2(10, 20, 100, 50)
margin = Rect2(1, 2, 0, 0)
filter_clip = true
"""

    def test_atlas_texture_region(self):
        rec = atlas_mod.parse_godot_tres(
            self.TEXT, resource_path="res://sprites/hero-part.tres")
        self.assertIsNone(rec["error"])
        self.assertEqual(rec["format"], "godot-atlas-texture")
        self.assertEqual(rec["texture"], "sheet.png")
        self.assertIsNone(rec["page_width"])
        self.assertEqual(rec["frame_count"], 1)
        (frame,) = rec["frames"]
        self.assertEqual(frame["name"], "hero-part")
        self.assertEqual(
            (frame["x"], frame["y"], frame["w"], frame["h"]),
            (10, 20, 100, 50))
        self.assertEqual((frame["offset_x"], frame["offset_y"]),
                         (1, 2))

    def test_non_atlas_tres_is_error_record(self):
        rec = atlas_mod.parse_godot_tres(
            '[gd_resource type="Resource" format=3]\n')
        self.assertIsNotNone(rec["error"])


class UnitySpriteAtlasTest(unittest.TestCase):
    TEXT = """%YAML 1.1
%TAG !u! tag:unity3d.com,2011:
--- !u!687078895 &4343727234628468602
SpriteAtlas:
  m_ObjectHideFlags: 0
  m_CorrespondingSourceObject: {fileID: 0}
  m_Name: SyntheticAtlas
  m_PackedSprites:
  - {fileID: 21300000, guid: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, type: 3}
  - {fileID: 21300002, guid: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb, type: 3}
  - {fileID: 21300004, guid: cccccccccccccccccccccccccccccccc, type: 3}
  m_PackedAtlasRenderDataKeys:
  - {fileID: 1, guid: dddddddddddddddddddddddddddddddd, type: 3}
  - {fileID: 2, guid: eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee, type: 3}
  m_Tag: SyntheticAtlas
"""

    def test_guid_only_fidelity(self):
        rec = atlas_mod.parse_unity_spriteatlas(self.TEXT)
        self.assertIsNone(rec["error"])
        self.assertEqual(rec["format"], "unity-spriteatlas")
        self.assertEqual(rec["atlas_name"], "SyntheticAtlas")
        self.assertEqual(rec["frames"], [])
        self.assertEqual(rec["frame_count"], 3)
        self.assertEqual(rec["packed_sprite_count"], 3)
        self.assertEqual(rec["render_data_key_count"], 2)
        self.assertFalse(rec["names_recoverable"])
        self.assertIsNone(rec["packed_area"])


class CompositionTest(unittest.TestCase):
    VEHICLE = ["rig-van-chassis", "rig-van-wheel-front",
               "rig-van-wheel-back", "rig-van-spring"]

    def test_vehicle_grouping_and_composition(self):
        frames = [{"name": n} for n in self.VEHICLE]
        groups = comp_mod.group_frames(frames)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["key"], "rig-van")
        self.assertEqual(comp_mod.classify_group(groups[0]),
                         "vehicle")
        rec = comp_mod.composition_record(groups[0])
        self.assertEqual(rec["object"], "rig-van")
        self.assertEqual(rec["classification"], "vehicle")
        self.assertEqual(rec["classification_label"],
                         "inferred")
        self.assertEqual(rec["driver"], "unknown")
        self.assertTrue(rec["driver_reason"])
        self.assertEqual(rec["attachment_points"], [])
        self.assertEqual(rec["naming_pattern"],
                         "<group>-<part>")
        roles = {p["name"]: p["role"] for p in rec["parts"]}
        self.assertEqual(roles["rig-van-chassis"], "body")
        self.assertEqual(roles["rig-van-wheel-front"], "wheel")
        self.assertEqual(roles["rig-van-spring"], "suspension")
        self.assertEqual(
            evidence.validate(
                rec, _schema("composition.schema.json")), [])

    def test_character_grouping(self):
        frames = [{"name": n} for n in (
            "hero-torso", "hero-head", "hero-arm-left",
            "hero-leg-right")]
        groups = comp_mod.group_frames(frames)
        self.assertEqual(len(groups), 1)
        self.assertEqual(comp_mod.classify_group(groups[0]),
                         "character")

    def test_ui_grouping(self):
        frames = [{"name": n} for n in (
            "ui-button-play", "ui-button-close", "ui-panel-main")]
        groups = comp_mod.group_frames(frames)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["key"], "ui")
        self.assertEqual(comp_mod.classify_group(groups[0]),
                         "ui")

    def test_environment_grouping(self):
        frames = [{"name": n} for n in (
            "env-tree-oak", "env-rock-large", "env-cloud-far")]
        groups = comp_mod.group_frames(frames)
        self.assertEqual(len(groups), 1)
        self.assertEqual(comp_mod.classify_group(groups[0]),
                         "environment")

    def test_single_frame_forms_no_group(self):
        self.assertEqual(
            comp_mod.group_frames([{"name": "solo-thing"}]), [])
        self.assertEqual(
            comp_mod.group_frames(
                [{"name": "alpha-one"}, {"name": "beta-two"}]),
            [])
        self.assertEqual(
            comp_mod.compositions_from_frames(
                [{"name": "solo-thing"}]), [])

    def test_anim_style_record_also_validates(self):
        # The schema is shared with the animation side: a
        # driver-known, classification-null record must pass.
        rec = {
            "object": "hero",
            "classification": None,
            "parts": [{"name": "hero-torso", "role": "body"}],
            "naming_pattern": "<group>-<part>",
            "attachment_points": [{"name": "neck", "x": 1,
                                   "y": 2}],
            "driver": "skeletal",
            "driver_label": "inferred",
            "evidence": ["skeleton file present"],
            "confidence": "medium",
        }
        self.assertEqual(
            evidence.validate(
                rec, _schema("composition.schema.json")), [])


class EndToEndTest(unittest.TestCase):
    def test_tiny_apk_run_and_schema(self):
        with tempfile.TemporaryDirectory() as td:
            apk = os.path.join(td, "synthetic.apk")
            with zipfile.ZipFile(apk, "w") as zf:
                zf.writestr("AndroidManifest.xml",
                            b"\x03\x00\x08\x00" + b"\x00" * 32)
                zf.writestr("classes.dex",
                            b"dex\n035\x00" + b"\x00" * 64)
                zf.writestr("assets/rig.plist",
                            plistlib.dumps(cocos_doc()))
                zf.writestr("assets/fx.plist",
                            plistlib.dumps(particle_doc()))
                zf.writestr("assets/anim.json", json.dumps(
                    {"v": "5.7.4", "layers": [], "assets": []}))
                zf.writestr("assets/broken.plist",
                            b"\x00\x01not-a-plist")
            proc = subprocess.run(
                [sys.executable,
                 os.path.join(ROOT, "scripts", "nar-atlas.py"),
                 apk, "--json"],
                capture_output=True, text=True, timeout=300)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = json.loads(proc.stdout)
        self.assertEqual(report["version"], "3.0.0")
        self.assertEqual(report["totals"]["atlas_count"], 2)
        self.assertEqual(report["totals"]["frame_count"], 5)
        self.assertEqual(report["totals"]["particle_count"], 1)
        errors = [a for a in report["atlases"] if a["error"]]
        self.assertEqual(len(errors), 1)  # broken.plist record
        comps = {c["object"]: c
                 for c in report["compositions"]}
        self.assertIn("rig-van", comps)
        self.assertEqual(comps["rig-van"]["classification"],
                         "vehicle")
        self.assertEqual(
            evidence.validate(
                report, _schema("atlas.schema.json")), [])
        for comp in report["compositions"]:
            self.assertEqual(
                evidence.validate(
                    comp, _schema("composition.schema.json")),
                [])

    def test_human_output_runs(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as td:
            apk = os.path.join(td, "synthetic.apk")
            with zipfile.ZipFile(apk, "w") as zf:
                zf.writestr("AndroidManifest.xml",
                            b"\x03\x00\x08\x00" + b"\x00" * 32)
                zf.writestr("classes.dex",
                            b"dex\n035\x00" + b"\x00" * 64)
                zf.writestr("assets/rig.plist",
                            plistlib.dumps(cocos_doc()))
            report = tool.scan_target(apk)
        self.assertEqual(report["totals"]["atlas_count"], 1)
        self.assertEqual(report["container"]["input_kind"],
                         "apk")


if __name__ == "__main__":
    unittest.main()
