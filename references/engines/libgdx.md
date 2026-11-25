# libGDX — engine guide

Registry id: `libgdx` · Status: **supported** · Fidelity: structural-summary · Deep module: `scripts/nar-libgdx.py`
Test reference: `tests/unit/test_deep_runtime.py::test_libgdx_atlas_and_tmx`

## Packaging

libgdx.so (+ freetype/bullet satellites), .atlas/.pack texture atlases, .tmx tile maps, jars in assets/.

Registry path markers: libgdx.so, libgdx-freetype.so, libgdx-bullet.so.

## Serialisation

Atlas text format: page header then region blocks (xy/size/orig/offset/index).

## Common protections

Little standard protection; assets are usually plain.

## Rebuild pitfalls

GWT HTML5 artifacts (*.nocache.js) can appear in Android wrappers and are inventoried, not treated as the game.

## Real run

```bash
python3 scripts/nar-libgdx.py <fixture:demo/NarDemo.apk>
```

```text
NAR libGDX deep dive: /home/hatch/workspace/nar-e2e-fixtures/demo/NarDemo.apk
Verdict: absent
Atlases: 0 files, 0 pages, 0 regions
Tile maps (.tmx): 0
GWT: 0 *.nocache.js, 0 *.gwt.xml
RoboVM libraries: []
Jars in assets/: []
libGDX native libraries: []
Version (string evidence): None
```
