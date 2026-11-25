# Solar2D — engine guide

Registry id: `solar2d` · Status: **partial** · Fidelity: structural-summary · Deep module: `scripts/nar-solar2d.py`
Test reference: `tests/unit/test_deep_archives.py::TestSolar2D`

## Packaging

resource.car (plain ZIP in many builds), config.lua / build.settings, libcorona.so-era markers, .luac members.

Registry path markers: JNI/symbol markers (see registry).

## Serialisation

ZIP-car listings give count, by-extension census and bytes; config facts are bounded-regex textual extracts, labelled as such.

## Common protections

Non-ZIP car variants degrade to identification + header facts.

## Rebuild pitfalls

Compiled Lua (.luac + extensionless Lua-magic members) is censused, not decompiled.

## Honest boundary (registry reason)

Deep dive lists resource.car when it is a plain ZIP (count, by-extension census, total bytes), extracts labelled textual facts from config.lua/build.settings (orientation.default, content scale/fps via bounded regex) and censuses compiled Lua (.luac + extensionless Lua-magic members); non-ZIP car variants degrade to identification + header facts. Corona markers (assets/*.luac, libcorona.so paths) are censused in the surrounding APK. No real Solar2D corpus locally; behaviour from public format documentation, synthetic-fixture verified.

## Detection

```bash
python3 scripts/nar-engines.py <target> --json
```

No local fixture run is claimed in this guide for this family; the registry reason above states the verified boundary.
