# Xamarin / .NET — engine guide

Registry id: `xamarin-dotnet` · Status: **partial** · Fidelity: structural-summary · Deep module: `scripts/nar-xamarin.py`
Test reference: `tests/unit/test_deep_runtime.py::test_xamarin_loose_and_blob_assemblies`

## Packaging

libmonodroid.so / libxamarin-app.so, assemblies/ directory or assemblies.blob AssemblyStore.

Registry path markers: libmonodroid.so, libxamarin-app.so, libmonosgen, assemblies/.

## Serialisation

Loose .dll or blob-carved assemblies parsed via ECMA-335 metadata (TypeDef/MethodDef counts, Module names).

## Common protections

XALZ AssemblyStore blocks are LZ4-compressed: counted by magic only, never decoded (no stdlib LZ4).

## Rebuild pitfalls

A blob over the 32 MiB member-read cap is skipped whole and reported as such.

## Honest boundary (registry reason)

Deep dive parses loose *.dll members and assemblies carved from uncompressed assemblies.blob spans through narlib.dotnetmeta (typedef/methoddef counts, Module-table names) and censuses the native runtime libraries and AssemblyStore markers. XALZ blocks — the default AssemblyStore compression in current Xamarin/MAUI builds — are counted by magic only: they are LZ4-compressed payloads and the stdlib has no LZ4 decoder, so assemblies inside XALZ stores are identified, not parsed.

## Detection

```bash
python3 scripts/nar-engines.py <target> --json
```

No local fixture run is claimed in this guide for this family; the registry reason above states the verified boundary.
