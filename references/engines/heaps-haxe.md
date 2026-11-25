# Heaps / Haxe — engine guide

Registry id: `heaps-haxe` · Status: **partial** · Fidelity: identified-only · Deep module: `scripts/nar-heaps.py`
Test reference: `tests/unit/test_deep_archives.py::TestHeaps`

## Packaging

hlboot.dat / *.hl HashLink bytecode, Java_com_haxe_ JNI prefix, hl_ weak symbols.

Registry path markers: JNI/symbol markers (see registry).

## Serialisation

HLB magic + uindex-encoded version and flags are decoded; deeper section counts are deliberately NOT named (unvalidated).

## Common protections

None standard beyond stripped natives.

## Rebuild pitfalls

Do not invent section counts: section_counts stays null with the reason recorded.

## Honest boundary (registry reason)

Deep dive verifies the HLB magic and decodes the version and flags uindex values (documented HashLink uindex encoding, including multi-byte values) plus a sibling .hl/.dat census. Section counts after version/flags are deliberately NOT named: the deeper header walk could not be validated, so section_counts is null with the reason recorded — no counts are invented. No real HashLink corpus locally; layout from public format documentation, synthetic-fixture verified.

## Detection

```bash
python3 scripts/nar-engines.py <target> --json
```

No local fixture run is claimed in this guide for this family; the registry reason above states the verified boundary.
