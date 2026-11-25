# Cocos2d-x — engine guide

Registry id: `cocos2d-x` · Status: **supported** · Fidelity: structural-summary · Deep module: `scripts/nar-cocos.py`
Test reference: `tests/unit/test_deep_runtime.py::test_cocos_atlas_particles_jsc`

## Packaging

libcocos2dcpp.so / libcocos2djs.so, assets/res + assets/src layout, .plist atlases and particle plists, .ccb/.csb UI files.

Registry path markers: libcocos2dcpp.so, libcocos2djs.so.

## Serialisation

Plists are XML/binary plist; compiled JS ships as .jsc SpiderMonkey bytecode (identification only).

## Common protections

.jsc is a custom-VM presentation: detected and named, never decoded.

## Rebuild pitfalls

A bare .plist is not proof of Cocos; require the native lib or layout evidence too.

## Real run

```bash
python3 scripts/nar-cocos.py <fixture:demo/NarDemo.apk>
```

```text
NAR Cocos deep dive: /home/hatch/workspace/nar-e2e-fixtures/demo/NarDemo.apk
Verdict: absent
Plist atlases: 0 (0 frames total)
Particle plists: 0
CocosBuilder/Studio files: 0 (0 bytes)
Compiled JS (.jsc, SpiderMonkey bytecode, identification only): 0 (0 bytes)
Asset layout: assets/ 0, assets/res/ 0, assets/src/ 0
```
