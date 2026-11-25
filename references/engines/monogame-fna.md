# MonoGame / FNA — engine guide

Registry id: `monogame-fna` · Status: **partial** · Fidelity: structural-summary · Deep module: `scripts/nar-monogame.py`
Test reference: `tests/unit/test_deep_runtime.py::test_monogame_xnb_census_and_framework`

## Packaging

MonoGame.Framework.dll loose or carved from assemblies.blob; FNA markers (FNA.dll, FAudio, libtheorafile); .xnb content files.

Registry path markers: JNI/symbol markers (see registry).

## Serialisation

XNB headers parse fully (platform, version, HiDef/compressed flags, validated declared size); uncompressed XNBs give the full type-reader table.

## Common protections

Compressed XNBs (flag 0x80) are LZX: counted, never decoded (no stdlib LZX).

## Rebuild pitfalls

Framework identification is by the assembly Module-table name, not the file name.

## Honest boundary (registry reason)

MonoGame.Framework.dll is found loose or carved from assemblies.blob (identified by its Module-table name) and summarized via narlib.dotnetmeta; FNA markers (FNA.dll, FAudio, libtheorafile) are a presence list. XNB headers parse fully (platform byte, version, HiDef/compressed flags, declared size validated against the member size) and uncompressed XNBs get their whole type-reader table parsed, with the census grouped by primary reader short name.

## Detection

```bash
python3 scripts/nar-engines.py <target> --json
```

No local fixture run is claimed in this guide for this family; the registry reason above states the verified boundary.
