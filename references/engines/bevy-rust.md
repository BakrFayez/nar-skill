# Bevy / Rust — engine guide

Registry id: `bevy-rust` · Status: **partial** · Fidelity: structural-summary · Deep module: `scripts/nar-bevy.py`
Test reference: `tests/unit/test_deep_runtime.py::test_bevy_ron_and_rust_evidence`

## Packaging

assets/ census with .ron / .scn.ron scene data, rustc version string in the largest native lib, winit / rust_begin_unwind markers.

Registry path markers: JNI/symbol markers (see registry).

## Serialisation

RON facts are a labelled textual approximation (depth-1 identifiers), not a RON parse.

## Common protections

Crate-name strings (bevy_ecs, bevy_render...) are occurrence counts, labelled string evidence.

## Rebuild pitfalls

The verdict requires RON assets or at least two distinct crate strings; one string is not Bevy.

## Honest boundary (registry reason)

The assets census is structural (member count, by-extension census, .ron and .scn.ron counts) and the rustc version is extracted from the 'rustc version ' string in the largest native library when present; Bevy crate presence is occurrence counts of the bevy_ecs / bevy_render / bevy_asset / bevy_winit / winit name strings, labelled string evidence, with the verdict requiring RON assets or at least two distinct crate strings.

## Detection

```bash
python3 scripts/nar-engines.py <target> --json
```

No local fixture run is claimed in this guide for this family; the registry reason above states the verified boundary.
