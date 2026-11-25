# Defold — engine guide

Registry id: `defold` · Status: **partial** · Fidelity: structural-summary · Deep module: `scripts/nar-defold.py`
Test reference: `tests/unit/test_deep_archives.py::TestDefold`

## Packaging

.arci index + .arcd data pair, canonically assets/game.arci/.arcd; libdmengine.so.

Registry path markers: libdmengine.so.

## Serialisation

Index entries carry MurmurHash64 hashes, offsets, sizes and compressed/encrypted flags; entry paths are NOT recoverable from the index.

## Common protections

Entries may be compressed and/or encrypted (flag bits reported).

## Rebuild pitfalls

Hash-only entries are the family's structural boundary: report counts and largest entries, never invented paths.

## Honest boundary (registry reason)

Deep dive parses the .arci index (public Defold engine source layout) with a fully validated entry walk (count/offset/size/hash checks) and reports entry counts, payload totals, compressed/encrypted flag counts and largest entries by hash; entry paths are NOT recoverable from the index (MurmurHash64 hashes only) — that is the family's structural boundary, stated in the report. No real Defold corpus locally; layout from public format documentation, synthetic-fixture verified.

## Detection

```bash
python3 scripts/nar-engines.py <target> --json
```

No local fixture run is claimed in this guide for this family; the registry reason above states the verified boundary.
