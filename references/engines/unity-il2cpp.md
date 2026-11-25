# Unity (IL2CPP) — engine guide

Registry id: `unity-il2cpp` · Status: **partial** · Fidelity: structural-summary · Deep module: `scripts/nar-il2cpp.py`
Test reference: `tests/unit/test_il2cpp.py::test_found_binary_only`

## Packaging

Code ships as native libil2cpp.so plus global-metadata.dat under assets/bin/Data/Managed/Metadata/; assets under assets/bin/Data/ and Addressables catalogs.

Registry path markers: libil2cpp.so, global-metadata.dat.

## Serialisation

Metadata is a binary header (magic 0xFAB11BAF) + tables; game assemblies are native, not DLLs.

## Common protections

Metadata may be encrypted/packed; library is stripped and may be protected (dumper warnings).

## Rebuild pitfalls

Pick one ABI and stay with it; a Mono sibling (Assembly-CSharp.dll + libmono.so) means this guide does not apply.

## Honest boundary (registry reason)

Deep dive locates the IL2CPP pair and summarizes metadata; Mono-side inventory and scene/prefab semantics are not reconstructed (capability matrix: Unity analysis is partially supported).

## Detection run

```bash
python3 scripts/nar-engines.py <target> --json
```

See `references/unity-il2cpp.md` for the full IL2CPP workflow.
