# Ren'Py — engine guide

Registry id: `renpy` · Status: **partial** · Fidelity: structural-summary · Deep module: `scripts/nar-renpy.py`
Test reference: `tests/unit/test_deep_archives.py::TestRenPy`

## Packaging

.rpa archives (RPA-1.0/2.0/3.0), .rpyc compiled scripts, librenpython.so.

Registry path markers: .rpyc, librenpython.so.

## Serialisation

RPA index is a pickle after a header line; RPA-3.0 XORs index offsets with the header key.

## Common protections

SECURITY: the index pickle is never plain-loaded; a pre-scan refuses code-execution opcodes and a restricted unpickler raises on any class lookup.

## Rebuild pitfalls

.rpyc is identification + zlib slot census only, no decompilation; reduce-encoded indexes are refused by design.

## Honest boundary (registry reason)

Deep dive parses RPA-1.0/2.0/3.0 headers and index listings (file count, total bytes, by-extension census, sample names) with RPA-3.0 key XOR deobfuscation. SECURITY: the index pickle is never loaded with plain pickle.loads — a pickletools pre-scan refuses GLOBAL/STACK_GLOBAL/REDUCE/OBJ/INST/NEWOBJ (and NEWOBJ_EX/EXT) opcodes and the load uses a RestrictedUnpickler whose find_class always raises; a hostile reduce-based fixture is refused and never executes (test-pinned). Consequence: indexes whose bytes objects are encoded via a reduce (protocol < 3 style) are refused by design rather than executed. .rpyc is identification + length-prefixed zlib slot census only, no decompilation. No real Ren'Py corpus locally; layout from public format documentation, synthetic-fixture verified.

## Detection

```bash
python3 scripts/nar-engines.py <target> --json
```

No local fixture run is claimed in this guide for this family; the registry reason above states the verified boundary.
