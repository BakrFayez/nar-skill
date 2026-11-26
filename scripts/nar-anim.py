#!/usr/bin/env python3
"""nar-anim.py: animation-system analysis (Part 4, 4.2).

    python3 nar-anim.py <target> [--json]

Decodes the animation systems a target ships — Spine,
DragonBones, Lottie, Aseprite, Godot AnimationPlayer /
AnimationTree, Spriter, Unity Animator/AnimationClip,
Creature and Cocos .ccb — from structural parsers in
narlib/anim, identifies the systems this rung does not
decode (Spine .skel timelines, Rive property streams,
.csb, bundle-embedded Unity clips) with a reason and a
probe for each, and emits composition records (skeletal
slot->bone attachments decoded from the format; physics
compositions only where a physics symbol cluster AND
sprite part-naming evidence agree).

Output (--json, schemas/animation.schema.json):
{version, target, container, systems[], compositions[],
physics_rigs[], limitations[]}. Only systems FOUND are
listed; the coverage registry's job is the full matrix.

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from narlib import anim  # noqa: E402

VERSION = "3.0.1"

_COUNT_KEYS = ("bones_count", "slots_count",
               "animation_count", "layers_count",
               "layer_count", "cel_count", "frame_count",
               "frames_parsed", "entity_count",
               "clip_count", "controller_count",
               "node_count", "armature_count",
               "precomp_count", "mesh_points_count",
               "element_count")


def human(report):
    lines = [f"NAR animation analysis: "
             f"{os.path.basename(report['target'])}"]
    lines.append("=" * 60)
    systems = report["systems"]
    if not systems:
        lines.append("No animation systems found.")
    for rec in systems:
        facts = rec.get("facts") or {}
        counts = ", ".join(f"{k}={facts[k]}" for k in
                           _COUNT_KEYS if k in facts)
        lines.append(f"[{rec['system']}] {rec['file']} "
                     f"({rec['status']})"
                     + (f" — {counts}" if counts else ""))
        if facts.get("version") is not None:
            lines.append(f"    version: {facts['version']}")
        anims = facts.get("animations")
        if isinstance(anims, dict) and anims:
            lines.append(f"    animations: "
                         f"{', '.join(anims)}")
        elif isinstance(anims, list) and anims:
            lines.append(f"    animations: "
                         f"{len(anims)} recorded")
        if rec["status"] == "identified_only":
            lines.append(f"    reason: {rec.get('reason')}")
            lines.append(f"    probe: {rec.get('probe')}")
    for comp in report["compositions"]:
        lines.append(
            f"Composition: {comp['object']} — driver "
            f"{comp['driver']} ({comp['driver_label']}), "
            f"{len(comp['parts'])} parts, confidence "
            f"{comp['confidence']}")
    for rig in report["physics_rigs"]:
        lines.append(
            f"Physics rig: {rig['engine_guess']} — "
            f"{rig['symbol_count']} symbols in "
            f"{', '.join(rig['libraries'])} "
            f"({rig['confidence']}); {rig['note']}")
    if report["limitations"]:
        lines.append("Limitations:")
        for lim in report["limitations"]:
            lines.append(f"  - {lim}")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Animation-system analysis: structural "
                    "parsers for Spine, DragonBones, "
                    "Lottie, Aseprite, Godot, Spriter, "
                    "Unity, Creature and Cocos animation "
                    "assets, plus physics-rig detection.")
    parser.add_argument("target",
                        help="path to an APK/AAB/container "
                             "target (or a loose animation "
                             "file)")
    parser.add_argument("--json", action="store_true",
                        help="emit the report as JSON "
                             "(schemas/animation.schema.json)")
    args = parser.parse_args(argv)
    if not os.path.isfile(args.target):
        print(f"nar-anim: target not found: {args.target}",
              file=sys.stderr)
        return 2
    try:
        report = anim.scan_target(args.target)
    except Exception as exc:
        print(f"nar-anim: scan failed: {exc}",
              file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(human(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
