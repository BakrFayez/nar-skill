"""Unit tests: nar-ask animation wiring (Part 4, 4.2).

Reuses the synthetic mini-case helper from test_ask.py
(loaded by file location). The mini case's dummy target is
then overwritten with a real tiny APK carrying a Spine
JSON, so build_animation's nar-anim deep scan fires: the
answer must cite decoded counts and a skeletal
composition, at strongly-indicated confidence, and its
BOUNDARY must name what remains undecoded instead of
claiming composition is unbuilt. A target carrying only
atlas data (no animation-system files) deepens through
the nar-atlas branch instead: compositions inferred
from frame naming are cited at inferred confidence.
With the dummy (non-archive) target neither deep scan
finds data and the identification behaviour is
preserved, with the BOUNDARY scoped to this target's
evidence (the fallback pinned by test_ask.py).

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import importlib.util
import io
import json
import os
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

_spec = importlib.util.spec_from_file_location(
    "test_ask_helpers", ROOT / "tests" / "unit" / "test_ask.py")
_helpers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_helpers)
ask = _helpers.ask
make_mini_case = _helpers.make_mini_case

SPINE = {
    "skeleton": {"hash": "abc123", "spine": "4.2.36"},
    "bones": [{"name": "root"}, {"name": "spine"},
              {"name": "head"}],
    "slots": [{"name": "body", "bone": "spine"},
              {"name": "head_slot", "bone": "head"}],
    "skins": [{"name": "default"}],
    "animations": {
        "walk": {"bones": {
            "spine": {"rotate": [{"time": 0},
                                 {"time": 1.25}]}}},
        "idle": {"bones": {
            "head": {"rotate": [{"time": 0.5}]}}},
    },
}


def _write_apk(path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
        zf.writestr("classes.dex",
                    b"dex\n039\x00" + b"\x00" * 32)
        zf.writestr("assets/anim/hero.json",
                    json.dumps(SPINE).encode())
    path.write_bytes(buf.getvalue())


def test_animation_answer_deepened_by_nar_anim(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    target = tmp_path / "target.apk"
    make_mini_case(str(case_dir), str(target))
    _write_apk(target)
    doc = ask.answer_question("How is the hero animated?",
                              str(target), str(case_dir))
    assert doc["intent"] == "animation"
    assert doc["confidence"] == "strongly-indicated"
    assert "bones_count=3" in doc["answer"]
    assert "slots_count=2" in doc["answer"]
    assert "animation_count=2" in doc["answer"]
    assert "skeletal" in doc["answer"]
    assert any("nar-anim" in e for e in doc["evidence"])
    assert any("attachment_points" in e
               for e in doc["evidence"])
    assert "not built yet" not in doc["boundary"]
    assert "Part 4" not in doc["boundary"]
    for phrase in ask.FORBIDDEN_ANSWER_PHRASES:
        assert phrase not in doc["answer"].lower()


def _write_idonly_apk(path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
        zf.writestr("classes.dex",
                    b"dex\n039\x00" + b"\x00" * 32)
        zf.writestr("assets/anim/hero_tex.json",
                    json.dumps({"name": "hero"}).encode())
    path.write_bytes(buf.getvalue())


def test_animation_answer_identified_only_not_claimed_decoded(
        tmp_path):
    """Regression: when every system nar-anim finds is
    identified_only, the ANSWER lead and the WHY block must
    not claim the systems were decoded (the per-system
    status and the BOUNDARY already said identified_only;
    the lead/why contradicted them)."""
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    target = tmp_path / "target.apk"
    make_mini_case(str(case_dir), str(target))
    _write_idonly_apk(target)
    doc = ask.answer_question("How are the characters "
                              "animated?", str(target),
                              str(case_dir))
    assert doc["intent"] == "animation"
    assert "none decoded" in doc["answer"]
    assert "identified_only" in doc["answer"]
    assert "systems decoded by nar-anim" not in \
        doc["answer"].lower()
    why_text = " ".join(doc["why"]).lower()
    assert "identified only" in why_text
    assert "decoded the listed systems" not in why_text
    assert "decoded at structural level: none" in \
        doc["boundary"]


def test_animation_fallback_unchanged_without_anim_systems(
        tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    target = tmp_path / "target.apk"
    make_mini_case(str(case_dir), str(target))
    doc = ask.answer_question("How is the hero animated?",
                              str(target), str(case_dir))
    assert doc["confidence"] == "inferred"
    assert "not built yet" not in doc["boundary"]
    assert "Part 4" in doc["boundary"]


def _write_atlas_apk(path):
    import plistlib
    frames = {}
    for name in ("rig-van-chassis", "rig-van-tire",
                 "rig-van-tire2", "rig-van-spring",
                 "rig-van-roof"):
        frames[name] = {
            "frame": "{{0,0},{64,32}}", "rotated": False,
            "sourceSize": "{64,32}",
            "sourceColorRect": "{{0,0},{64,32}}"}
    plist = {"frames": frames,
             "metadata": {"format": 2,
                          "size": "{256,256}",
                          "textureFileName": "rig-van.png"}}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml",
                    b"\x03\x00\x08\x00")
        zf.writestr("classes.dex",
                    b"dex\n039\x00" + b"\x00" * 32)
        zf.writestr("assets/atlas/rig-van.plist",
                    plistlib.dumps(plist))
    path.write_bytes(buf.getvalue())


def test_animation_answer_deepened_by_nar_atlas(tmp_path):
    """Atlas-only target: no animation-system files, so
    the nar-anim branch stays silent and the nar-atlas
    branch cites decoded atlases + the inferred vehicle
    composition (coordinator integration, Part 4)."""
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    target = tmp_path / "target.apk"
    make_mini_case(str(case_dir), str(target))
    _write_atlas_apk(target)
    doc = ask.answer_question("How is the van animated?",
                              str(target), str(case_dir))
    assert doc["intent"] == "animation"
    assert doc["confidence"] == "inferred"
    assert "nar-atlas" in doc["answer"]
    assert "vehicle" in doc["answer"]
    assert any("nar-atlas composition rig-van" in e
               for e in doc["evidence"])
    assert "not built yet" not in doc["boundary"]
    for phrase in ask.FORBIDDEN_ANSWER_PHRASES:
        assert phrase not in doc["answer"].lower()
