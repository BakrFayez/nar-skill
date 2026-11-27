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

## gif

Status: **supported** · Fidelity: structural-summary · Test: `tests/unit/test_phase2_anim.py::test_gif_decoded_frame_walk`

Detection: GIF87a/GIF89a magic at the member start, then a structural block walk (logical screen descriptor, image descriptors, graphic-control extensions, the NETSCAPE2.0 looping extension) that must reach the trailer byte before a frame count is claimed; a member whose walk falls short degrades to identified-only with the header facts.

```bash
python3 scripts/nar-anim.py <target>
```

```text
[gif] assets/loading.gif (decoded) — frame_count=12
```

## pag

Status: **partial** · Fidelity: identified-only · Test: `tests/unit/test_phase2_anim.py::test_pag_member_identified_only`

Identification only: a .pag member is recognised by its extension and size/header facts are emitted; the PAG tag-stream decode is not implemented.

Detection: extension plus header facts by `nar-anim`; see the status/reason above for the honest decode boundary.

```bash
python3 scripts/nar-anim.py <target>
```

## android-view

Status: **supported** · Fidelity: structural-summary · Test: `tests/unit/test_phase2_anim.py::test_android_view_axml_decoded`

Detection: members under `res/anim`/`res/animator` directories (including qualifier variants) whose XML root is an animation element (`set`, `objectAnimator`, `animator`, the transform/alpha leaf elements); binary AXML and text XML are both parsed, and a member that fails to parse degrades to identified-only. `animated-vector` roots are deliberately not claimed.

```bash
python3 scripts/nar-anim.py <target>
```

```text
[android-view] res/anim/fade_in.xml (decoded) — element_count=1
```
