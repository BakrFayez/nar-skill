"""Unit tests: animation-system parsers (Part 4, 4.2).

Synthetic fixtures per parser with counts asserted, built
in-file (no external data): Spine JSON + .skel header,
DragonBones ske/tex, Lottie, a hand-built Aseprite binary,
a Godot .tscn, Spriter .scml, a Rive header, Unity YAML
.anim/.controller, a binary-plist .ccb, Creature JSON, and
a physics rig (Box2D symbol cluster in a byte-built ELF64
— the approach of test_engines_jni_symbols.py — plus
sprite part naming). Negative controls: random JSON is
not Lottie/Spine/Creature; a truncated Aseprite degrades
to identified_only. End-to-end: a tiny APK carrying a
Spine JSON + a Lottie JSON under assets/, decoded by
nar-anim.py --json and validated against
schemas/animation.schema.json.

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import io
import json
import os
import plistlib
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from narlib import anim, evidence  # noqa: E402


def parse(name, data):
    if isinstance(data, (dict, list)):
        data = json.dumps(data).encode()
    if isinstance(data, str):
        data = data.encode()
    return anim.classify_and_parse(name, data, "test.apk")


# ------------------------------------------------------------- Spine

SPINE = {
    "skeleton": {"hash": "abc123", "spine": "4.2.36",
                 "x": 0, "y": 0, "width": 100, "height": 80},
    "bones": [{"name": "root"}, {"name": "spine"},
              {"name": "head"}],
    "slots": [{"name": "body", "bone": "spine"},
              {"name": "head_slot", "bone": "head"}],
    "skins": [{"name": "default", "attachments": {}}],
    "ik": [{"name": "aim"}],
    "transform": [{"name": "tilt"}],
    "path": [],
    "events": {"hit": {"int": 1}},
    "animations": {
        "walk": {"bones": {
            "spine": {"rotate": [{"time": 0}, {"time": 0.5}],
                      "translate": [{"time": 1.25}]},
            "root": {"rotate": [{"time": 0.25}]}},
                 "slots": {"body": {"attachment": []}}},
        "idle": {"bones": {
            "head": {"rotate": [{"time": 0.75}]}}},
    },
}


def test_spine_json_counts():
    rec = parse("assets/hero.json", SPINE)
    assert rec["system"] == "spine"
    assert rec["status"] == "decoded"
    facts = rec["facts"]
    assert facts["bones_count"] == 3
    assert facts["bone_names_sample"] == ["root", "spine",
                                          "head"]
    assert facts["slots_count"] == 2
    assert facts["skins_count"] == 1
    assert facts["skin_names"] == ["default"]
    assert facts["version"] == "4.2.36"
    assert facts["skeleton_hash"] == "abc123"
    assert facts["ik_constraints_count"] == 1
    assert facts["transform_constraints_count"] == 1
    assert facts["path_constraints_count"] == 0
    assert facts["events"] == ["hit"]
    assert facts["animation_count"] == 2
    walk = facts["animations"]["walk"]
    assert walk["duration_estimate"] == 1.25
    assert "estimate" in walk["duration_basis"]
    assert "bones" in walk["timeline_groups"]
    assert "slots" in walk["timeline_groups"]
    assert facts["animations"]["idle"]["duration_estimate"] \
        == 0.75


def test_spine_json_dict_form_skins():
    obj = dict(SPINE)
    obj["skins"] = {"default": {}, "red": {}}
    rec = parse("assets/hero.json", obj)
    assert rec["facts"]["skins_count"] == 2
    assert sorted(rec["facts"]["skin_names"]) == ["default",
                                                  "red"]


def _spine_string(text):
    raw = text.encode()
    return bytes([len(raw) + 1]) + raw


def test_spine_skel_header_only():
    data = _spine_string("deadbeef") + _spine_string("4.2.36") \
        + struct.pack(">ffff", 1.0, 2.0, 200.0, 100.0) \
        + b"\x00" * 32
    rec = parse("assets/hero.skel", data)
    assert rec["system"] == "spine"
    assert rec["status"] == "identified_only"
    assert rec["facts"]["version"] == "4.2.36"
    assert rec["facts"]["skeleton_hash"] == "deadbeef"
    assert rec["facts"]["width"] == 200.0
    assert rec["facts"]["height"] == 100.0
    assert "version-sensitive" in rec["reason"]


def test_spine_skel_garbage_no_counts():
    rec = parse("assets/hero.skel", b"\xff" * 64)
    assert rec["status"] == "identified_only"
    assert "bones_count" not in rec["facts"]


# ------------------------------------------------------- DragonBones

DRAGON_SKE = {
    "frameRate": 24, "version": "5.6",
    "armature": [{
        "name": "hero",
        "bone": [{"name": "root"}, {"name": "spine"},
                 {"name": "head"}],
        "slot": [{"name": "body", "parent": "root"},
                 {"name": "hat", "parent": "head"}],
        "skin": [{"name": "default"}],
        "ik": [{"name": "aim"}],
        "animation": [{"name": "walk", "duration": 24,
                       "playTimes": 0},
                      {"name": "idle", "duration": 12,
                       "playTimes": -1}],
    }],
}

DRAGON_TEX = {
    "imagePath": "hero_tex.png", "width": 256, "height": 128,
    "SubTexture": [{"name": "body"}, {"name": "hat"},
                   {"name": "arm"}],
}


def test_dragonbones_ske_and_tex():
    rec = parse("assets/hero_ske.json", DRAGON_SKE)
    assert rec["system"] == "dragonbones"
    assert rec["status"] == "decoded"
    assert rec["facts"]["frame_rate"] == 24
    arm = rec["facts"]["armatures"][0]
    assert arm["name"] == "hero"
    assert arm["bones_count"] == 3
    assert arm["slots_count"] == 2
    assert arm["animation_count"] == 2
    assert arm["animations"][0] == {
        "name": "walk", "duration": 24, "play_times": 0}
    assert arm["slots_detail"][1] == {"name": "hat",
                                      "parent": "head"}
    tex = parse("assets/hero_tex.json", DRAGON_TEX)
    assert tex["system"] == "dragonbones"
    assert tex["facts"]["frame_count"] == 3
    assert tex["facts"]["frame_names_sample"] == [
        "body", "hat", "arm"]
    assert tex["facts"]["image_path"] == "hero_tex.png"


def test_dragonbones_structure_detection_without_suffix():
    rec = parse("assets/armature.json", DRAGON_SKE)
    assert rec["system"] == "dragonbones"


# ------------------------------------------------------------ Lottie

LOTTIE = {
    "v": "5.7.4", "fr": 30, "ip": 0, "op": 90,
    "w": 200, "h": 200, "nm": "loading",
    "assets": [
        {"id": "comp_1", "layers": [{"ty": 4}]},
        {"id": "img_1", "w": 10, "h": 10, "p": "img.png"},
    ],
    "layers": [
        {"ty": 4, "nm": "shape",
         "ks": {"o": {"a": 1, "k": [{"t": 0, "s": [0]},
                                    {"t": 10, "s": [100]}]},
                "p": {"a": 0, "k": [0, 0, 0]}},
         "shapes": [
             {"ty": "gr", "it": [{"ty": "rc"},
                                  {"ty": "fl"}]},
             {"ty": "el"}]},
        {"ty": 0, "nm": "precomp", "refId": "comp_1"},
        {"ty": 2, "nm": "image", "refId": "img_1"},
    ],
}


def test_lottie_counts():
    rec = parse("assets/loading.json", LOTTIE)
    assert rec["system"] == "lottie"
    assert rec["status"] == "decoded"
    facts = rec["facts"]
    assert facts["layers_count"] == 3
    assert facts["layer_type_counts"] == {"4": 1, "0": 1,
                                           "2": 1}
    assert facts["precomp_count"] == 1
    assert facts["precomp_ids"] == ["comp_1"]
    assert facts["shapes_count"] == 4
    assert facts["keyframed_properties_count"] == 1
    assert "approximate" in facts[
        "keyframed_properties_basis"]
    assert facts["frame_rate"] == 30
    assert facts["duration_s"] == 3.0


# ---------------------------------------------------------- Creature

CREATURE = {
    "mesh": {"points": [0, 0, 1, 0, 1, 1, 0, 1],
             "regions": [{"name": "body"}, {"name": "head"}]},
    "animation": {"walk": {"length": 1.5},
                  "idle": {"start_time": 0.0,
                           "end_time": 2.0}},
}


def test_creature_counts():
    rec = parse("assets/blob.json", CREATURE)
    assert rec["system"] == "creature"
    assert rec["status"] == "decoded"
    facts = rec["facts"]
    assert facts["mesh_points_count"] == 8
    assert facts["mesh_regions_count"] == 2
    assert facts["animations"]["walk"]["length"] == 1.5
    assert facts["animations"]["idle"]["length"] == 2.0
    assert facts["animation_count"] == 2


# ------------------------------------------------------ negative JSON

def test_random_json_is_not_classified():
    assert parse("assets/data.json",
                 {"foo": 1, "layers": "nope"}) is None
    assert parse("assets/data.json",
                 {"v": "1.0", "fr": 30,
                  "layers": [{"nm": "no ty field"}]}) is None
    assert parse("assets/data.json",
                 {"bones": "not-a-list"}) is None
    assert parse("assets/data.json",
                 {"mesh": {"points": []}}) is None
    assert parse("assets/data.json",
                 b"{not json at all") is None


# ---------------------------------------------------------- Aseprite

def _ase_string(text):
    raw = text.encode()
    return struct.pack("<H", len(raw)) + raw


def _ase_chunk(chunk_type, payload):
    return struct.pack("<IH", 6 + len(payload),
                       chunk_type) + payload


def _ase_layer_chunk(name):
    payload = struct.pack("<HHHHHHB", 0, 0, 0, 0, 0, 0, 255)
    payload += b"\x00" * 3 + _ase_string(name)
    return _ase_chunk(0x2004, payload)


def _ase_cel_chunk(layer_index=0):
    payload = struct.pack("<HhhBHh", layer_index, 0, 0, 255,
                          0, 0) + b"\x00" * 5
    return _ase_chunk(0x2005, payload)


def _ase_tags_chunk():
    tag = struct.pack("<HHBH", 0, 1, 0, 0) + b"\x00" * 6 \
        + b"\x00" * 3 + b"\x00" + _ase_string("walk")
    payload = struct.pack("<H", 1) + b"\x00" * 8 + tag
    return _ase_chunk(0x2018, payload)


def _ase_frame(chunks):
    body = b"".join(chunks)
    header = struct.pack("<IHHH", 16 + len(body), 0xF1FA,
                         len(chunks), 100) + b"\x00" * 2 \
        + struct.pack("<I", len(chunks))
    return header + body


def _aseprite_bytes():
    frame1 = _ase_frame([_ase_layer_chunk("body"),
                         _ase_layer_chunk("head"),
                         _ase_cel_chunk(0)])
    frame2 = _ase_frame([_ase_cel_chunk(1),
                         _ase_tags_chunk()])
    frames = frame1 + frame2
    header = bytearray(128)
    struct.pack_into("<I", header, 0, 128 + len(frames))
    struct.pack_into("<H", header, 4, 0xA5E0)
    struct.pack_into("<H", header, 6, 2)     # frames
    struct.pack_into("<H", header, 8, 32)    # width
    struct.pack_into("<H", header, 10, 48)   # height
    struct.pack_into("<H", header, 12, 32)   # colour depth
    struct.pack_into("<I", header, 14, 1)    # flags
    return bytes(header) + frames


def test_aseprite_counts():
    rec = parse("assets/sprite.aseprite", _aseprite_bytes())
    assert rec["system"] == "aseprite"
    assert rec["status"] == "decoded", rec
    facts = rec["facts"]
    assert facts["frames_parsed"] == 2
    assert facts["width"] == 32 and facts["height"] == 48
    assert facts["color_depth"] == 32
    assert facts["layers"] == ["body", "head"]
    assert facts["layer_count"] == 2
    assert facts["cel_count"] == 2
    assert facts["tags"] == ["walk"]
    assert facts["tag_count"] == 1


def test_aseprite_truncated_is_identified_only():
    data = _aseprite_bytes()
    rec = parse("assets/sprite.ase", data[:140])
    assert rec["system"] == "aseprite"
    assert rec["status"] == "identified_only"
    assert rec["reason"]
    rec = parse("assets/sprite.ase", data[:100])
    assert rec["status"] == "identified_only"


# ------------------------------------------------------------- Godot

GODOT_TSCN = """[gd_scene load_steps=5 format=3 uid="uid://test"]

[ext_resource type="Texture2D" path="res://hero.png" id="1_ab"]

[sub_resource type="Animation" id="Animation_1"]
resource_name = "walk"
length = 1.5
tracks/0/type = "value"
tracks/0/path = NodePath("Sprite2D:frame")
tracks/0/keys = {
"times": PackedFloat32Array(0, 0.5, 1.5),
"transitions": PackedFloat32Array(1, 1, 1),
"values": [0, 1, 2]
}
tracks/1/type = "value"
tracks/1/path = NodePath(".:position")
tracks/1/keys = {
"times": PackedFloat32Array(0, 1.5),
"transitions": PackedFloat32Array(1, 1),
"values": [Vector2(0, 0), Vector2(4, 0)]
}

[sub_resource type="AnimationLibrary" id="AnimationLibrary_1"]
_data = {
"walk": SubResource("Animation_1")
}

[sub_resource type="AnimationNodeStateMachine" id="StateMachine_1"]
states/walk/node = SubResource("AnimationNode_1")
states/idle/node = SubResource("AnimationNode_2")
transitions = ["walk", "idle", SubResource("Transition_1")]

[node name="Hero" type="CharacterBody2D"]

[node name="AnimationPlayer" type="AnimationPlayer" parent="."]
libraries = {
"": SubResource("AnimationLibrary_1")
}
autoplay = "walk"

[node name="AnimationTree" type="AnimationTree" parent="."]
tree_root = SubResource("StateMachine_1")
"""


def test_godot_animationplayer_and_tree():
    rec = parse("assets/hero.tscn", GODOT_TSCN)
    assert rec["system"] == "godot-animationplayer"
    assert rec["status"] == "decoded"
    facts = rec["facts"]
    assert facts["animation_count"] == 1
    animation = facts["animations"][0]
    assert animation["name"] == "walk"
    assert animation["length"] == 1.5
    assert animation["tracks"] == 2
    assert animation["keys"] == 5
    assert "PackedFloat32Array" in animation["keys_basis"]
    assert animation["track_paths_sample"] == [
        "Sprite2D:frame", ".:position"]
    assert facts["player_count"] == 1
    player = facts["players"][0]
    assert player["name"] == "AnimationPlayer"
    assert player["autoplay"] == "walk"
    assert player["libraries"] == ["AnimationLibrary_1"]
    assert facts["tree_count"] == 1
    tree = facts["trees"][0]
    assert tree["tree_root"] == "StateMachine_1"
    machine = tree["state_machines"][0]
    assert machine["states"] == ["walk", "idle"]
    assert machine["transitions_count"] == 1


def test_godot_scene_without_animation_is_none():
    assert parse("assets/plain.tscn",
                 '[gd_scene format=3]\n\n'
                 '[node name="Root" type="Node2D"]\n') is None


# ------------------------------------------------------------ Spriter

SPRITER = """<?xml version="1.0" encoding="UTF-8"?>
<spriter_data scml_version="1.0" generator="Spriter"
              generator_version="r11">
  <entity id="0" name="hero">
    <animation id="0" name="walk" length="1000">
      <timeline id="0" name="body" object_type="sprite">
        <key id="0"><object folder="0" file="0"/></key>
        <key id="1"><object folder="0" file="1"/></key>
      </timeline>
      <timeline id="1" name="root" object_type="bone">
        <key id="0"><object folder="0" file="0"/></key>
      </timeline>
    </animation>
    <animation id="1" name="idle" length="500">
      <timeline id="0" name="body" object_type="sprite">
        <key id="0"><object folder="0" file="0"/></key>
      </timeline>
    </animation>
  </entity>
</spriter_data>
"""


def test_spriter_counts():
    rec = parse("assets/hero.scml", SPRITER)
    assert rec["system"] == "spriter"
    assert rec["status"] == "decoded"
    facts = rec["facts"]
    assert facts["entity_count"] == 1
    entity = facts["entities"][0]
    assert entity["name"] == "hero"
    assert entity["animation_count"] == 2
    assert entity["animations"][0]["length"] == 1000
    assert facts["timelines_count"] == 3
    assert facts["keyframe_count"] == 4
    assert entity["object_types"] == ["bone", "sprite"]


# --------------------------------------------------------------- Rive

def _varint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def test_rive_header_only():
    data = b"RIVE" + _varint(7) + _varint(0) + _varint(12345) \
        + b"\x00" * 16
    rec = parse("assets/intro.riv", data)
    assert rec["system"] == "rive"
    assert rec["status"] == "identified_only"
    assert rec["facts"] == {"major_version": 7,
                            "minor_version": 0,
                            "file_id": 12345}
    assert "property-stream" in rec["reason"]
    assert parse("assets/intro.riv", b"RIFX" + data[4:]) is None


# --------------------------------------------------------------- Unity

UNITY_ANIM = """%YAML 1.1
%TAG !u! tag:unity3d.com,2011:
--- !u!74 &7400000
AnimationClip:
  m_ObjectHideFlags: 0
  m_Name: Walk
  m_Legacy: 0
  m_RotationCurves:
  - curve:
      serializedVersion: 2
      path: bone
  - curve:
      serializedVersion: 2
      path: bone2
  m_PositionCurves:
  - curve:
      serializedVersion: 2
      path: bone
  m_ScaleCurves: []
  m_FloatCurves:
  - curve:
      serializedVersion: 2
      attribute: m_Material._Color
  m_AnimationClipSettings:
    m_StartTime: 0
    m_StopTime: 1.5
  m_SampleRate: 30
"""

UNITY_CONTROLLER = """%YAML 1.1
%TAG !u! tag:unity3d.com,2011:
--- !u!91 &9100000
AnimatorController:
  m_ObjectHideFlags: 0
  m_Name: HeroController
  m_AnimatorParameters:
  - m_Name: Speed
    m_Type: 1
    m_DefaultFloat: 0
  - m_Name: Grounded
    m_Type: 4
    m_DefaultFloat: 0
  m_AnimatorLayers:
  - serializedVersion: 5
    m_StateMachine: {fileID: 110700000}
--- !u!1107 &110700000
AnimatorStateMachine:
  m_ObjectHideFlags: 1
  m_Name: Base Layer
  m_ChildStates:
  - serializedVersion: 1
    m_State: {fileID: 110200000}
    m_Position: {x: 10, y: 10, z: 0}
  - serializedVersion: 1
    m_State: {fileID: 110200001}
    m_Position: {x: 20, y: 10, z: 0}
  m_AnyStateTransitions:
  - {fileID: 110100000}
  m_EntryTransitions: []
--- !u!1102 &110200000
AnimatorState:
  m_ObjectHideFlags: 1
  m_Name: Idle
--- !u!1102 &110200001
AnimatorState:
  m_ObjectHideFlags: 1
  m_Name: Walk
"""


def test_unity_anim_clip_textual_curves():
    rec = parse("assets/Walk.anim", UNITY_ANIM)
    assert rec["system"] == "unity-animator"
    assert rec["status"] == "decoded"
    facts = rec["facts"]
    assert facts["clip_count"] == 1
    doc = facts["documents"][0]
    assert doc["name"] == "Walk"
    assert doc["legacy"] == 0
    assert doc["stop_time"] == 1.5
    assert doc["sample_rate"] == 30.0
    assert doc["curve_counts"] == {
        "m_RotationCurves": 2, "m_PositionCurves": 1,
        "m_FloatCurves": 1}
    assert doc["curve_count_total"] == 4
    assert "textual" in doc["curve_count_basis"]


def test_unity_controller_parameters_and_states():
    rec = parse("assets/Hero.controller", UNITY_CONTROLLER)
    assert rec["system"] == "unity-animator"
    assert rec["status"] == "decoded"
    facts = rec["facts"]
    assert facts["controller_count"] == 1
    assert facts["parameters"] == [
        {"name": "Speed", "type": 1},
        {"name": "Grounded", "type": 4}]
    machine = facts["state_machines"][0]
    assert machine["name"] == "Base Layer"
    assert machine["child_states"] == ["Idle", "Walk"]
    assert machine["any_state_transitions_count"] == 1


def test_unity_bundle_member_identified_only():
    rec = anim.parse_unity_bundle_member(
        b"UnityFS\x00padding AnimationClip padding",
        "assets/bundle.bundle", "test.apk")
    assert rec["status"] == "identified_only"
    assert rec["facts"]["embedded_types"] == ["AnimationClip"]
    assert "UnityPy" in rec["probe"]


# --------------------------------------------------------------- Cocos

def test_ccb_binary_plist():
    doc = {"nodeGraph": {"children": [
               {"children": []},
               {"children": [{"children": []}]}]},
           "sequences": [{"name": "run", "length": 1.2},
                         {"name": "idle", "length": 2.0}],
           "resolutions": [{"name": "phone"}]}
    data = plistlib.dumps(doc, fmt=plistlib.FMT_BINARY)
    rec = parse("assets/scene.ccb", data)
    assert rec["system"] == "cocos-ccb"
    assert rec["status"] == "decoded"
    facts = rec["facts"]
    assert facts["node_count"] == 4
    assert facts["sequence_count"] == 2
    assert facts["sequences"][0] == {"name": "run",
                                     "length": 1.2}
    assert facts["resolutions_count"] == 1


def test_ccb_non_plist_identified_only():
    rec = parse("assets/scene.ccb", b"\x00\x01not a plist")
    assert rec["status"] == "identified_only"
    assert rec["reason"]


def test_csb_identified_only():
    rec = parse("assets/scene.csb", b"CSB\x00\x01\x02\x03")
    assert rec["system"] == "cocos-ccb"
    assert rec["status"] == "identified_only"
    assert rec["facts"]["first_bytes_hex"].startswith("435342")


# ------------------------------------------------------------- Physics

def _elf64_with_exports(names):
    """Minimal ELF64 (LE, ET_DYN) whose .dynsym exports
    exactly `names` (the test_engines_jni_symbols.py
    approach, byte-built in-file)."""
    dynstr = b"\x00"
    offsets = {}
    for name in names:
        offsets[name] = len(dynstr)
        dynstr += name.encode() + b"\x00"
    dynsym = b"\x00" * 24
    for name in names:
        dynsym += struct.pack(
            "<IBBHQQ", offsets[name], 0x12, 0, 1, 0, 0)
    shstrtab = b"\x00.dynsym\x00.dynstr\x00.shstrtab\x00"
    sh_name = {".dynsym": 1, ".dynstr": 9, ".shstrtab": 17}
    ehsize = 64
    off_dynsym = ehsize
    off_dynstr = off_dynsym + len(dynsym)
    off_shstr = off_dynstr + len(dynstr)
    shoff = off_shstr + len(shstrtab)

    def sh(name, shtype, offset, size, link, info, entsize):
        return struct.pack(
            "<IIQQQQIIQQ", sh_name.get(name, 0), shtype, 0, 0,
            offset, size, link, info, 8, entsize)

    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8,
        3, 0xB7, 1, 0, 0, shoff, 0, ehsize, 0, 0, 64, 4, 3)
    sections = b"\x00" * 64
    sections += sh(".dynsym", 11, off_dynsym, len(dynsym),
                   2, 1, 24)
    sections += sh(".dynstr", 3, off_dynstr, len(dynstr),
                   0, 0, 0)
    sections += sh(".shstrtab", 3, off_shstr, len(shstrtab),
                   0, 0, 0)
    return header + dynsym + dynstr + shstrtab + sections


BOX2D_SYMBOLS = [
    "_ZN5b2World6StepExfi",
    "_ZN5b2Body13CreateFixtureEv",
    "_ZN9b2Fixture8GetShapeEv",
    "_ZN6b2Joint6CreateEPv",
    "plain_helper",
]

CAR_PARTS = ["assets/sprites/car_wheel.png",
             "assets/sprites/car_chassis.png",
             "assets/sprites/car_spring.png",
             "assets/sprites/car_door.png"]


def test_physics_cluster_and_part_naming():
    so = _elf64_with_exports(BOX2D_SYMBOLS)
    rigs, groups = anim.detect_physics(
        [("lib/arm64-v8a/libgame.so", so)],
        ["lib/arm64-v8a/libgame.so"] + CAR_PARTS)
    assert len(rigs) == 1
    rig = rigs[0]
    assert rig["engine_guess"] == "Box2D"
    assert rig["symbol_count"] == 4
    assert rig["confidence"] == "inferred"
    assert rig["naming_evidence_present"] is True
    assert len(groups) == 1
    assert groups[0]["prefix"] == "car"
    assert set(groups[0]["part_tokens"]) >= {
        "wheel", "chassis", "spring"}
    compositions = anim.build_compositions([], rigs, groups)
    assert len(compositions) == 1
    comp = compositions[0]
    assert comp["object"] == "car"
    assert comp["driver"] == "physics"
    assert comp["driver_label"] == "inferred"
    assert comp["confidence"] == "inferred"
    assert comp["attachment_points"] == []
    assert "car" in comp["naming_pattern"]


def test_physics_symbols_only_no_composition():
    so = _elf64_with_exports(BOX2D_SYMBOLS)
    rigs, groups = anim.detect_physics(
        [("lib/arm64-v8a/libgame.so", so)],
        ["lib/arm64-v8a/libgame.so",
         "assets/sprites/hero.png"])
    assert len(rigs) == 1
    assert groups == []
    assert rigs[0]["naming_evidence_present"] is False
    assert "no sprite part-naming" in rigs[0]["note"]
    assert anim.build_compositions([], rigs, groups) == []


def test_physics_below_cluster_threshold():
    so = _elf64_with_exports(["_ZN5b2World6StepExfi",
                              "plain_helper"])
    rigs, _groups = anim.detect_physics(
        [("lib/arm64-v8a/libgame.so", so)], [])
    assert rigs == []


# --------------------------------------------------------- Compositions

def test_spine_and_dragonbones_compositions():
    systems = [parse("assets/hero.json", SPINE),
               parse("assets/hero_ske.json", DRAGON_SKE)]
    compositions = anim.build_compositions(systems, [], [])
    assert len(compositions) == 2
    spine_comp = compositions[0]
    assert spine_comp["driver"] == "skeletal"
    assert spine_comp["driver_label"] == "observed"
    assert spine_comp["confidence"] == "strongly-indicated"
    assert spine_comp["classification"] is None
    assert spine_comp["naming_pattern"] is None
    assert spine_comp["parts"][0] == {
        "name": "body", "role": "attachment", "bone": "spine"}
    assert spine_comp["attachment_points"][1] == {
        "slot": "head_slot", "bone": "head"}
    dragon_comp = compositions[1]
    assert dragon_comp["object"] == "hero"
    assert dragon_comp["attachment_points"][0] == {
        "slot": "body", "bone": "root"}


# ------------------------------------------------------------ End-to-end

def _apk_bytes(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def test_end_to_end_apk_validates_against_schema(tmp_path):
    apk = tmp_path / "anim.apk"
    apk.write_bytes(_apk_bytes([
        ("AndroidManifest.xml", b"\x03\x00\x08\x00"),
        ("classes.dex", b"dex\n039\x00" + b"\x00" * 32),
        ("assets/anim/hero.json", json.dumps(SPINE).encode()),
        ("assets/anim/loading.json",
         json.dumps(LOTTIE).encode()),
        ("assets/anim/readme.json",
         json.dumps({"unrelated": True}).encode()),
    ]))
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "nar-anim.py"),
         str(apk), "--json"],
        capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    schema = json.loads(
        (ROOT / "schemas" / "animation.schema.json")
        .read_text(encoding="utf-8"))
    assert evidence.validate(report, schema) == []
    assert report["version"] == "3.0.2"
    systems = {rec["system"]: rec for rec in report["systems"]}
    assert set(systems) == {"spine", "lottie"}
    assert systems["spine"]["facts"]["bones_count"] == 3
    assert systems["spine"]["source_split"] == "anim.apk"
    assert systems["lottie"]["facts"]["layers_count"] == 3
    assert len(report["compositions"]) == 1
    assert report["compositions"][0]["driver"] == "skeletal"
    assert report["physics_rigs"] == []


def test_scan_target_loose_rive_file(tmp_path):
    riv = tmp_path / "intro.riv"
    riv.write_bytes(b"RIVE" + _varint(7) + _varint(0)
                    + _varint(9) + b"\x00" * 8)
    report = anim.scan_target(str(riv))
    assert len(report["systems"]) == 1
    assert report["systems"][0]["system"] == "rive"
    assert report["limitations"]
