# Unreal Engine — engine guide

Registry id: `unreal` · Status: **partial** · Fidelity: structural-summary · Deep module: `scripts/nar-unreal.py`
Test reference: `tests/unit/test_unreal.py::test_capabilities_match_parser_constants`

## Packaging

.pak / IoStore (.utoc+.ucas) containers, libUE4.so/libUnreal.so, .uasset/.umap payloads.

Registry path markers: libue4.so, libunreal.so, .pak.

## Serialisation

Packages are binary serialized object graphs; .locres holds localization string tables.

## Common protections

Pak AES encryption and Oodle compression exist; encrypted/Oodle members are named, never decoded.

## Rebuild pitfalls

Kismet/Blueprint bytecode is not decoded; do not claim gameplay logic from a package census.

## Honest boundary (registry reason)

Deep dive parses pak/IoStore/Zen/classic packages at structural level, decodes .locres string tables (v1 EntryMetaData layout verified end-to-end on real samples; v0 Initial layout implemented from the public format, synthetic-verified only) and attaches Wwise bank header facts for readable .bnk/.wem members (Oodle/encrypted members are named, never decoded). Kismet/Blueprint decoding, Oodle and AES decryption are unsupported by design (capability matrix).

## Detection

```bash
python3 scripts/nar-engines.py <target> --json
```

No local fixture run is claimed in this guide for this family; the registry reason above states the verified boundary.
