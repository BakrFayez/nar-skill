# RPG Maker (web export) — engine guide

Registry id: `rpg-maker` · Status: **supported** · Fidelity: structural-summary · Deep module: `scripts/nar-rpgmaker.py`
Test reference: `tests/unit/test_deep_web.py::test_rpgmaker_mv_census`

## Packaging

Web export under assets/www/ (MV: rpg_core.js; MZ: rmmz_core.js), data/*.json databases, Game.rpgproject anchor.

Registry path markers: rpg_core.js, rmmz_core.js.

## Serialisation

Game data is plain JSON arrays (actors, items, maps); nar-rpgmaker censuses the standard database files.

## Common protections

Some exports encrypt images/audio (.rpgmvp/.rpgmvo); those are inventoried, not decrypted.

## Rebuild pitfalls

Without a Game.rpgproject / data anchor / package.json anchor the verdict is absent even if rpg_core.js ships.

## Real run

```bash
python3 scripts/nar-rpgmaker.py <fixture:frameworks/rpgmaker.apk>
```

```text
NAR RPG Maker deep dive: /home/hatch/workspace/nar-e2e-fixtures/frameworks/rpgmaker.apk
ABSENT: no RPG Maker web export found
  note: no RPG Maker export root found (no Game.rpgproject, data/*.json database or package.json anchor)
```
