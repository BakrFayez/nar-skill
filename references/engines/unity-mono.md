# Unity (Mono) — engine guide

Registry id: `unity-mono` · Status: **supported** · Fidelity: structural-summary · Deep module: `scripts/nar-mono.py`
Test reference: `tests/unit/test_deep_runtime.py::test_mono_managed_census_and_indicator`

## Packaging

Managed DLLs under */bin/Data/Managed/ (Assembly-CSharp.dll is the game) plus libmono.so.

Registry path markers: assembly-csharp.dll, libmono.so.

## Serialisation

Plain .NET assemblies (ECMA-335 metadata); nar-mono censuses them via the .NET metadata reader.

## Common protections

Assemblies may be obfuscated; names then describe nothing.

## Rebuild pitfalls

Do not confuse with IL2CPP: if libil2cpp.so is present and no Managed DLLs ship, the Mono verdict is absent.

## Real run

```bash
python3 scripts/nar-mono.py <fixture:engines/unity.apk (an IL2CPP fixture, so the Mono verdict is a true absent)>
```

```text
NAR Unity Mono deep dive: /home/hatch/workspace/nar-e2e-fixtures/engines/unity.apk
Verdict: absent
Managed assemblies parsed: 0 (0 unparseable)
Assembly-CSharp: present=False
libmono: []; libil2cpp: ['lib/arm64-v8a/libil2cpp.so']
```
