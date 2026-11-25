# Animation systems

Every system in `scripts/formats.json` `animation_systems`, with detection rules. Parser for all except spriteatlas: `narlib/anim (nar-anim)`.

## spine

Status: **partial** · Fidelity: structural-summary · Test: `tests/unit/test_anim.py::test_spine_json_counts`

Spine JSON exports decode fully (bones, slots with slot-to-bone attachment data, skins, constraint counts, events, per-animation timeline groups and duration estimates). The .skel binary is header-only: hash, version and skeleton dimensions are emitted when the guarded header walk stays consistent; binary timeline decode is version-sensitive and not implemented.

Detection: structural shape check by `nar-anim`; see the status/reason above for the honest decode boundary.

```bash
python3 scripts/nar-anim.py <target>
```

## dragonbones

Status: **supported** · Fidelity: structural-summary · Test: `tests/unit/test_anim.py::test_dragonbones_ske_and_tex`

Detection: file shape/extension as registered for this system, confirmed by the structural parser (a random JSON with the same keys is rejected).

```bash
python3 scripts/nar-anim.py <synthetic-fixture.apk>
```

```text
[dragonbones] assets/hero_ske.json (decoded) — bones_count=2, slots_count=1, animation_count=1, armature_count=1
```

## lottie

Status: **supported** · Fidelity: structural-summary · Test: `tests/unit/test_anim.py::test_lottie_counts`

Detection: file shape/extension as registered for this system, confirmed by the structural parser (a random JSON with the same keys is rejected).

```bash
python3 scripts/nar-anim.py <synthetic-fixture.apk>
```

```text
[lottie] assets/anim.json (decoded) — layers_count=1, precomp_count=0
```

## rive

Status: **partial** · Fidelity: identified-only · Test: `tests/unit/test_anim.py::test_rive_header_only`

Header facts only: RIVE magic, major/minor version varints and the file id varint are parsed; the property-stream decode is not implemented.

Detection: structural shape check by `nar-anim`; see the status/reason above for the honest decode boundary.

```bash
python3 scripts/nar-anim.py <target>
```

## aseprite

Status: **supported** · Fidelity: structural-summary · Test: `tests/unit/test_anim.py::test_aseprite_counts`

Detection: file shape/extension as registered for this system, confirmed by the structural parser (a random JSON with the same keys is rejected).

```bash
python3 scripts/nar-anim.py <synthetic-fixture-2.apk>
```

```text
[aseprite] assets/f.ase (identified_only)
    reason: file is 11 bytes, shorter than the 128-byte Aseprite header; identified by extension only
```

Note: the synthetic fixture's `.ase` member is a placeholder, so this run shows the identified-only shape; the decoded shape (frames, layers, tags) is pinned by the registry test reference above. See the manifest NOT RUN list.

## unity-animator

Status: **partial** · Fidelity: structural-summary · Test: `tests/unit/test_anim.py::test_unity_anim_clip_textual_curves`

Loose .anim/.controller/.overrideController files are Unity YAML text and decode textually (document class ids 74/91/221/1107/1102, m_Name, clip m_Legacy/m_StopTime/m_SampleRate, curve-block counts labelled as a bounded textual count, controller parameters with types, state-machine child-state names resolved through AnimatorState documents, AnyStateTransitions count). Clips/controllers embedded inside Unity bundles/.assets members are identification only (bounded member content scan for AnimationClip/AnimatorController type names).

Detection: structural shape check by `nar-anim`; see the status/reason above for the honest decode boundary.

```bash
python3 scripts/nar-anim.py <target>
```

## godot-animationplayer

Status: **supported** · Fidelity: structural-summary · Test: `tests/unit/test_anim.py::test_godot_animationplayer_and_tree`

Detection: file shape/extension as registered for this system, confirmed by the structural parser (a random JSON with the same keys is rejected).

```bash
python3 scripts/nar-anim.py <synthetic-fixture.apk>
```

```text
[godot-animationplayer] assets/scene.tscn (decoded) — animation_count=1
```

## spriteatlas

Status: **partial** · Fidelity: identified-only · Test: `tests/unit/test_atlas.py::UnitySpriteAtlasTest`

nar-atlas recovers the atlas name and packed-sprite count from the .spriteatlas text YAML; packed sprites are referenced by GUID only, so frame names and rects are not recoverable from the file alone.

Detection: structural shape check by `nar-anim`; see the status/reason above for the honest decode boundary.

```bash
python3 scripts/nar-anim.py <target>
```

## cocos-ccb

Status: **partial** · Fidelity: structural-summary · Test: `tests/unit/test_anim.py::test_ccb_binary_plist`

.ccb decodes when it is a plist (binary or XML, via plistlib): recursive nodeGraph node count (capped), sequence names and lengths, resolutions count; a non-plist .ccb degrades to identified_only. .csb is identification plus first-bytes facts only: it is a custom FlatBuffers-based binary (Cocos Studio) and its node-graph decode is not implemented.

Detection: structural shape check by `nar-anim`; see the status/reason above for the honest decode boundary.

```bash
python3 scripts/nar-anim.py <target>
```

## creature

Status: **supported** · Fidelity: structural-summary · Test: `tests/unit/test_anim.py::test_creature_counts`

Detection: file shape/extension as registered for this system, confirmed by the structural parser (a random JSON with the same keys is rejected).

```bash
python3 scripts/nar-anim.py <synthetic-fixture.apk>
```

```text
[creature] assets/blob.json (decoded) — animation_count=1, mesh_points_count=8
```

## spriter

Status: **supported** · Fidelity: structural-summary · Test: `tests/unit/test_anim.py::test_spriter_counts`

Detection: file shape/extension as registered for this system, confirmed by the structural parser (a random JSON with the same keys is rejected).

```bash
python3 scripts/nar-anim.py spriter.scml
```

```text
[spriter] spriter.scml (decoded) — entity_count=1
```
