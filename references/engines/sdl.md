# SDL — engine guide

Registry id: `sdl` · Status: **supported** · Fidelity: structural-summary · Deep module: `scripts/nar-sdl.py`
Test reference: `tests/unit/test_deep_runtime.py::test_sdl_dynsym_census`

## Packaging

Native-only family: libSDL2*.so / libSDL*.so plus satellite libs, JNI prefix Java_org_libsdl_, SDL_main export.

Registry path markers: JNI/symbol markers (see registry).

## Serialisation

No managed payload; evidence is the ELF dynsym census and library layout.

## Common protections

Stripped libraries shrink the symbol census; absence of exports is not absence of SDL.

## Rebuild pitfalls

SDL alone is a library, not an engine verdict about gameplay; pair it with the asset census.

## Real run

```bash
python3 scripts/nar-sdl.py <fixture:demo/NarDemo.apk>
```

```text
NAR SDL deep dive: /home/hatch/workspace/nar-e2e-fixtures/demo/NarDemo.apk
Verdict: absent
Satellite libraries: []
Revision (string evidence): None
```
