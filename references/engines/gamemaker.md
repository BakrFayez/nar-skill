# GameMaker — engine guide

Registry id: `gamemaker` · Status: **partial** · Fidelity: structural-summary · Deep module: `scripts/nar-gamemaker.py`
Test reference: `tests/unit/test_deep_archives.py::TestGameMaker`

## Packaging

assets/data.win (FORM container), Java_com_yoyogames_ JNI prefix.

Registry path markers: JNI/symbol markers (see registry).

## Serialisation

data.win chunk table (GEN8, STRG, TXTR, AUDO, SPRT...); GEN8 carries the game name via candidate string-offset fields.

## Common protections

String table is censused (count, sample, total chars); room/object semantics need a validated real corpus.

## Rebuild pitfalls

GEN8 name-field position is reported with its basis; do not treat it as certain on unvalidated layouts.

## Honest boundary (registry reason)

Deep dive walks the data.win FORM chunk table with validated sizes, resolves the GEN8 game name via candidate string-offset fields (+4/+8/+12, basis reported), censuses the STRG string table (count, sample, total chars) and reads TXTR/AUDO/SPRT count fields. No real GameMaker corpus locally; layout from public format documentation, synthetic-fixture verified.

## Detection

```bash
python3 scripts/nar-engines.py <target> --json
```

No local fixture run is claimed in this guide for this family; the registry reason above states the verified boundary.
