# Godot — engine guide

Registry id: `godot` · Status: **supported** · Fidelity: structural-summary · Deep module: `scripts/nar-godot.py`
Test reference: `tests/unit/test_godot.py::TestPlainListing`

## Packaging

A .pck pack (GDPC) standalone or embedded, or loose project files under assets/ in Android exports.

Registry path markers: libgodot.

## Serialisation

PCK directory lists paths, offsets, sizes; resources are .tscn/.tres text or binary .scn/.res.

## Common protections

Pack encryption flag exists (format 2+); encrypted packs are reported, not decrypted.

## Rebuild pitfalls

Format 3 (Godot 4.5+) moves the directory to the end of the pack; loose-file exports have no pack directory to list.

## Real run

```bash
python3 scripts/nar-godot.py <fixture:engines/godot.pck>
```

```text
NAR Godot pack inspection: /home/hatch/workspace/nar-e2e-fixtures/engines/godot.pck
Pack: godot.pck (format 2, engine 4.4.1, 12,308,656 bytes)
Encryption: no (pack flag clear)
Files: 392 (listed via stdlib), 12,270,136 content bytes
```
