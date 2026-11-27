# Cocos2d-x — engine guide

Registry id: `cocos2d-x` · Status: **supported** · Fidelity: structural-summary · Deep module: `scripts/nar-cocos.py`
Test reference: `tests/unit/test_deep_runtime.py::test_cocos_atlas_particles_jsc`

## Packaging

libcocos2dcpp.so / libcocos2djs.so, assets/res + assets/src layout, .plist atlases and particle plists, .ccb/.csb UI files.

Registry path markers: libcocos2dcpp.so, libcocos2djs.so.

## Version scope

- **2.x (legacy):** recognised. The `cocos2d-x 2.` version string is scanned for by `nar-cocos.py`, and the generic `cocos2d-x ` banner token in `nar-engines.py` covers 2.x banners as well. 2.x-era builds are the ones most likely to use the static-linking profile below: the engine compiled into the game library is the norm for that era, not the exception.
- **3.x:** recognised. `cocos2d-x 3.` version strings, the canonical library names, the `Java_org_cocos2dx_` JNI surface and the `org/cocos2dx/lib` DEX wrapper are all live channels.
- **4.x:** recognised on the same channels as 3.x (`cocos2d-x 4.` version strings in `nar-cocos.py`; banner, path, JNI and DEX channels in `nar-engines.py`).
- **Cocos Creator:** recognised only to the extent the shipped build exposes the same evidence: `nar-cocos.py` scans for the `Cocos Creator` string, and Creator builds that ship .plist atlases, .ccb/.csb files or .jsc payloads are counted by the deep dive. There is no Creator-project parser: Creator scene/asset formats as such are not decoded, and a Creator build that exposes none of the above evidence is not identified as Cocos.

In all cases a version string is labelled string evidence, not a parsed version field: the `nar-engines.py` verdict carries `version: null` for this family, and the banner text appears in the indicator / `version_evidence` entries instead.

## Profiles

### Canonical layout

`libcocos2dcpp.so` (C++ games) or `libcocos2djs.so` (JS games) under `lib/<abi>/`, content under `assets/res/` and `assets/src/`, .plist atlases and particle plists, .ccb/.csb UI files, compiled scripts as .jsc. Every channel fires on this shape: path signature, JNI exports, DEX wrapper, payload census in the deep dive.

### Legacy 2.x

Same family, older packaging habits: content layouts vary more, scripts may ship uncompiled, and the native library is frequently the game library itself rather than a separately named engine library (see Static-linking). Detection leans on the `cocos2d-x 2.` version string, the DEX wrapper where present, and whatever payload files survive. Do not require the canonical library name or the `assets/res` + `assets/src` layout before considering this family for a 2.x-era target.

### Static-linking

The engine is compiled into a single, generically-named library (for example `libgame.so`), often with the JNI surface registered dynamically or stripped, so neither the filename channel nor the exported-symbol channel sees anything. The surviving trace is strings in the library's read-only data. `nar-engines.py` scans the raw bytes of every `lib/**/*.so` for this family's string signatures: the strong `cocos2d-x ` version banner scores as a detection on its own (medium confidence), while the weak tokens `cocos2d::`, `CCDirector` and `CocosDenshion` are recorded as indicators but, on their own, stay below the detection threshold — weak strings alone make a candidate, not a verdict. Every string hit is reported as a `native-strings` indicator naming the token and the library that carried it. `nar-cocos.py` independently counts a version string in any `lib/*.so`, whatever its name, toward its own verdict (see the fallback path below).

### Custom content pipeline

The build ships its content under nonstandard paths (for example a single `assets/<custom>/` tree) or in bespoke pack files, with no .plist/.ccb/.csb/.jsc payload at all. Path- and payload-based evidence is then absent by construction. What still works: the native-strings channel in `nar-engines.py` (it scans libraries, not asset paths), the DEX wrapper marker where present, and a manual `nar-cocos.py` run — its .plist scan is path-independent, so an atlas under a custom path is still found, and its version-string scan does not care about the library's name.

## Fallback analysis path

When the layout matches no profile above — `nar-engines.py` reports no Cocos verdict, or no verdict at all:

1. Check the native libraries' strings yourself (or read the `native-strings` indicators): a `cocos2d-x <version>` banner inside a generically-named library is near-conclusive evidence; `cocos2d::` / `CCDirector` strings alone are a lead, not a proof.
2. Run `nar-cocos.py` manually on the target, even though `nar-engines.py` found nothing. Its .plist scan is path-independent and its version-string scan is name-independent, so it can return `present` on custom-pipeline and renamed-library builds. If its verdict rests on version strings alone, the report's notes say so explicitly.
3. Know the routing caveat: `nar-engines.py --deep` runs the deep dive only for a family that is already detected, so a strings-only or payload-only build that the shallow pass missed is never routed automatically — the manual run in step 2 is the rescue.
4. If there are no payload files, no exported family symbols and no surviving engine strings, see the honest boundary below: the build is not statically attributable, and a multi-library native target is reported as an unknown / custom engine with its native evidence, not as Cocos.

## Serialisation

Plists are XML/binary plist; compiled JS ships as .jsc SpiderMonkey bytecode (identification only).

## Common protections

.jsc is a custom-VM presentation: detected and named, never decoded.

## Rebuild pitfalls

A bare .plist is not proof of Cocos; require the native lib or layout evidence too.

## Honest boundary

Detection is evidence-bound. A build that is fully stripped, registers its JNI dynamically, ships no Cocos payload files and retains no engine strings carries no static trace this toolset can attribute — that shape is a known limitation, not a negative result: `nar-engines.py` reports substantial multi-library native targets of that kind as `Unknown / custom engine` with the library inventory as evidence, and never upgrades weak string tokens (`cocos2d::`, `CCDirector`, `CocosDenshion`) alone into a detection. `nar-cocos.py` reporting `absent` means no atlas, .ccb/.csb, .jsc or version-string evidence was found; it is not proof the engine is absent from a stripped build. .jsc bytecode is identified and measured, never decoded, and no Cocos Creator project parsing is performed.

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
