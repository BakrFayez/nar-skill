# Rebuild playbook — evidence → implementation plan

`nar blueprint` turns a verified case (from `nar analyze`) into a
9-file rebuild specification. Every claim in `features.md` carries a
machine-checkable evidence citation; anything not in evidence lands in
`unrecoverable.md` / `unknowns.json` instead of being invented.

```bash
python3 scripts/nar-blueprint.py <target> --out spec/
```

Real run on the demo fixture:

```text
nar-blueprint: wrote 9 files to <out> (case: <per-target cache case built by nar-analyze>; unknowns: 20)
  features.md  architecture.md  data-model.md  flows.md  assets.md
  network.md  build-order.md  unrecoverable.md  unknowns.json
```

## The 9 files and how they map to implementation order

`build-order.md` is the implementation plan. Its steps, and the spec
sections that feed each one:

| Step | Plan item | Fed by |
|---|---|---|
| 1 | Foundation: project shell + manifest surface (component counts, launcher) | architecture.md, flows.md |
| 2 | Application layer: engine/framework structure the evidence shows | architecture.md |
| 3 | Data layer: storage mechanisms in evidence — or a runtime storage probe first when none are | data-model.md |
| 4 | Features, in features.md order (security/network facts last, behind their own layers) | features.md |
| 5 | Network layer: typed clients for the recorded endpoints, grouped by classification | network.md |
| 6 | Asset pipeline: recreate (do not copy) the asset inventory by category | assets.md |
| 7 | Verification: re-run the full analysis on the rebuilt app and diff the two specifications | all files + unknowns.json |

Real excerpt from the demo fixture's `build-order.md`:

```text
- **Step 1.** Foundation: project shell and manifest surface ({'activity': 2, 'activity-alias': 0, 'service': 0, 'receiver': 0, 'provider': 0, 'total': 2} components; launcher com.example.nardemo.MainActivity). Acceptance: the built app declares the same component counts and cold-starts to the launcher component (evidence: permissions.json — component_counts = {...}, launcher_activity = com.example.nardemo.MainActivity)
- **Step 4.** Features: implement the 5 verified features in features.md order (security and network facts last, behind their own layers). Acceptance: each feature demonstrably produces the effect its features.md entry records (evidence: investigation.json — verified_facts = 5)
- **Step 7.** Verification: re-run the full analysis on the rebuilt app and diff the two specifications. Acceptance: the rebuilt app's blueprint shows no feature from features.md missing and no new unrecoverable category (evidence: case.json — case_id present for both runs)
```

## Reading the other sections

- `features.md` — every feature: trigger, effect, implementing
  components, each cited `(evidence: <companion> — <item>)`; a claim
  marked `inferred` is a derivation, not a direct observation.
- `architecture.md` — engine/framework verdicts and structure the case
  proves; where app evidence exists, the screen map and data-flow edges
  deepen flows/data-model instead of leaving NOT RECOVERABLE fallbacks.
- `data-model.md` — shipped-database schemas, SharedPreferences
  candidates, token storage locations (mechanisms only, never values).
- `flows.md` — component/screen flow and deep-link routes.
- `assets.md` — inventory by category; recreate assets, never copy
  proprietary art/audio out of the target.
- `network.md` — recorded endpoints by classification; no client ships
  a value copied from the artifact.
- `unrecoverable.md` — what static evidence cannot rebuild (server-side
  logic, runtime-generated data, encrypted payloads). Non-empty and
  accurate is a passing state, not a failure.
- `unknowns.json` — validates against `schemas/blueprint.schema.json`;
  each unknown names the probe that would resolve it.

## Rules of the road

1. Implement in build-order; do not start with features.
2. A step is done when its acceptance check passes against evidence,
   not when the code merely exists.
3. Anything you cannot cite stays an unknown — name the probe
   (runtime capture, a labelled fixture, a server contract) instead of
   guessing.
4. The spec describes behaviour and architecture so you can implement
   your own original work; it does not license copying proprietary
   assets, art, audio, trademarks, or code.
