# Asset formats

Every texture/atlas/audio/video/model/container/code/data format in `scripts/formats.json`. Status and parser are the registry's. Excerpts are from real runs on synthetic fixtures built for this guide (file names genericised; shapes are the tools' real output).

## binary

Extensions: `.bin, .bytes, .dat` · Category: data · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.bin", "type": "binary", "category": "data", "size_bytes": 11}
```

## bmp-image

Extensions: `.bmp` · Category: texture · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.bmp", "type": "bmp-image", "category": "texture", "size_bytes": 11}
```

## bundle

Extensions: `.bundle` · Category: container · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.bundle", "type": "bundle", "category": "container", "size_bytes": 11}
```

## css

Extensions: `.css` · Category: data · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.css", "type": "css", "category": "data", "size_bytes": 11}
```

## csv

Extensions: `.csv` · Category: data · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.csv", "type": "csv", "category": "data", "size_bytes": 11}
```

## dex

Extensions: `.dex` · Category: code · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.dex", "type": "dex", "category": "code", "size_bytes": 11}
```

## elf

Extensions: `.so` · Category: code · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.so", "type": "elf", "category": "code", "size_bytes": 11}
```

## fbx-model

Extensions: `.fbx` · Category: model · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.fbx", "type": "fbx-model", "category": "model", "size_bytes": 11}
```

## flac-audio

Extensions: `.flac` · Category: audio · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.flac", "type": "flac-audio", "category": "audio", "size_bytes": 11}
```

## gettext-mo

Extensions: `.mo` · Category: data · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

Compiled gettext message catalog. A shipped catalog is a development artifact: nar-assets also lists it in the report's `development_artifacts` section.

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.mo", "type": "gettext-mo", "category": "data", "size_bytes": 11}
```

## gettext-po

Extensions: `.po` · Category: data · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

Portable gettext message catalog (source form). Its `#:` source references are source-tree evidence: nar-assets collects them in the report's `development_artifacts` section.

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.po", "type": "gettext-po", "category": "data", "size_bytes": 11}
```

## gettext-pot

Extensions: `.pot` · Category: data · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

Portable gettext message template (extraction source form) — a build-pipeline artifact when shipped; listed in the report's `development_artifacts` section.

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.pot", "type": "gettext-pot", "category": "data", "size_bytes": 11}
```

## gif-image

Extensions: `.gif` · Category: texture · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.gif", "type": "gif-image", "category": "texture", "size_bytes": 11}
```

## glb-model

Extensions: `.glb` · Category: model · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.glb", "type": "glb-model", "category": "model", "size_bytes": 11}
```

## gltf-model

Extensions: `.gltf` · Category: model · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.gltf", "type": "gltf-model", "category": "model", "size_bytes": 11}
```

## godot-pck

Extensions: `.pck` · Category: container · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.pck", "type": "godot-pck", "category": "container", "size_bytes": 11}
```

## hermes-bytecode

Extensions: `.hbc` · Category: code · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.hbc", "type": "hermes-bytecode", "category": "code", "size_bytes": 11}
```

## html

Extensions: `.html` · Category: data · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.html", "type": "html", "category": "data", "size_bytes": 11}
```

## ini-config

Extensions: `.ini` · Category: config · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.ini", "type": "ini-config", "category": "config", "size_bytes": 11}
```

## javascript

Extensions: `.js` · Category: code · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.js", "type": "javascript", "category": "code", "size_bytes": 11}
```

## jpeg-image

Extensions: `.jpeg, .jpg` · Category: texture · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.jpeg", "type": "jpeg-image", "category": "texture", "size_bytes": 11}
```

## json

Extensions: `.json` · Category: data · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.json", "type": "json", "category": "data", "size_bytes": 11}
```

## m4a-audio

Extensions: `.m4a` · Category: audio · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.m4a", "type": "m4a-audio", "category": "audio", "size_bytes": 11}
```

## mkv-video

Extensions: `.mkv` · Category: video · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.mkv", "type": "mkv-video", "category": "video", "size_bytes": 11}
```

## mp3-audio

Extensions: `.mp3` · Category: audio · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.mp3", "type": "mp3-audio", "category": "audio", "size_bytes": 11}
```

## mp4-video

Extensions: `.mp4` · Category: video · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.mp4", "type": "mp4-video", "category": "video", "size_bytes": 11}
```

## obj-model

Extensions: `.obj` · Category: model · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.obj", "type": "obj-model", "category": "model", "size_bytes": 11}
```

## ogg-audio

Extensions: `.ogg` · Category: audio · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.ogg", "type": "ogg-audio", "category": "audio", "size_bytes": 11}
```

## otf-font

Extensions: `.otf` · Category: font · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.otf", "type": "otf-font", "category": "font", "size_bytes": 11}
```

## png-image

Extensions: `.png` · Category: texture · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.png", "type": "png-image", "category": "texture", "size_bytes": 11}
```

## properties

Extensions: `.properties, .prop` · Category: config · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.properties", "type": "properties", "category": "config", "size_bytes": 11}
```

## protobuf-schema

Extensions: `.proto` · Category: data · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.proto", "type": "protobuf-schema", "category": "data", "size_bytes": 11}
```

## text

Extensions: `.txt` · Category: data · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.txt", "type": "text", "category": "data", "size_bytes": 11}
```

## ttf-font

Extensions: `.ttf` · Category: font · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.ttf", "type": "ttf-font", "category": "font", "size_bytes": 11}
```

## unityfs

Extensions: `.unity3d` · Category: container · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.unity3d", "type": "unityfs", "category": "container", "size_bytes": 11}
```

## unreal-iostore

Extensions: `.ucas, .utoc` · Category: container · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.ucas", "type": "unreal-iostore", "category": "container", "size_bytes": 11}
```

## unreal-pak

Extensions: `.pak` · Category: container · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.pak", "type": "unreal-pak", "category": "container", "size_bytes": 11}
```

## wav-audio

Extensions: `.wav` · Category: audio · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.wav", "type": "wav-audio", "category": "audio", "size_bytes": 11}
```

## webm-video

Extensions: `.webm` · Category: video · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.webm", "type": "webm-video", "category": "video", "size_bytes": 11}
```

## webp-image

Extensions: `.webp` · Category: texture · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.webp", "type": "webp-image", "category": "texture", "size_bytes": 11}
```

## xml

Extensions: `.xml` · Category: data · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.xml", "type": "xml", "category": "data", "size_bytes": 11}
```

## yaml

Extensions: `.yaml, .yml` · Category: config · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.yaml", "type": "yaml", "category": "config", "size_bytes": 11}
```

## plist

Extensions: `.plist` · Category: data · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.plist", "type": "plist", "category": "data", "size_bytes": 11}
```

## spine-skeleton

Extensions: `.skel` · Category: animation · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.skel", "type": "spine-skeleton", "category": "animation", "size_bytes": 11}
```

## godot-resource

Extensions: `.tres` · Category: data · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.tres", "type": "godot-resource", "category": "data", "size_bytes": 11}
```

## godot-scene

Extensions: `.tscn` · Category: data · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.tscn", "type": "godot-scene", "category": "data", "size_bytes": 11}
```

## godot-project

Extensions: `.godot` · Category: config · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.godot", "type": "godot-project", "category": "config", "size_bytes": 11}
```

## godot-import

Extensions: `.import` · Category: config · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.import", "type": "godot-import", "category": "config", "size_bytes": 11}
```

## unreal-asset

Extensions: `.uasset` · Category: data · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.uasset", "type": "unreal-asset", "category": "data", "size_bytes": 11}
```

## unreal-map

Extensions: `.umap` · Category: data · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.umap", "type": "unreal-map", "category": "data", "size_bytes": 11}
```

## wwise-audio

Extensions: `.wem` · Category: audio · Parser: `nar-assets + nar-unreal (narlib/mediainfo)` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.wem", "type": "wwise-audio", "category": "audio", "size_bytes": 11}
```

## wwise-bank

Extensions: `.bnk` · Category: audio · Parser: `nar-assets + nar-unreal (narlib/mediainfo)` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.bnk", "type": "wwise-bank", "category": "audio", "size_bytes": 11}
```

## fmod-bank

Extensions: `.bank` · Category: audio · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.bank", "type": "fmod-bank", "category": "audio", "size_bytes": 11}
```

## astc-texture

Extensions: `.astc` · Category: texture · Parser: `nar-assets + narlib/textures` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.astc", "type": "astc-texture", "category": "texture", "size_bytes": 11}
```

## ktx-texture

Extensions: `.ktx` · Category: texture · Parser: `nar-assets + narlib/textures` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.ktx", "type": "ktx-texture", "category": "texture", "size_bytes": 11}
```

## ktx2-texture

Extensions: `.ktx2` · Category: texture · Parser: `nar-assets + narlib/textures` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.ktx2", "type": "ktx2-texture", "category": "texture", "size_bytes": 11}
```

## pvr-texture

Extensions: `.pvr` · Category: texture · Parser: `nar-assets + narlib/textures` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.pvr", "type": "pvr-texture", "category": "texture", "size_bytes": 11}
```

## dds-texture

Extensions: `.dds` · Category: texture · Parser: `nar-assets + narlib/textures` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.dds", "type": "dds-texture", "category": "texture", "size_bytes": 11}
```

## pkm-texture

Extensions: `.pkm` · Category: texture · Parser: `nar-assets + narlib/textures` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.pkm", "type": "pkm-texture", "category": "texture", "size_bytes": 11}
```

## tga-image

Extensions: `.tga` · Category: texture · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.tga", "type": "tga-image", "category": "texture", "size_bytes": 11}
```

## psd-image

Extensions: `.psd` · Category: texture · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.psd", "type": "psd-image", "category": "texture", "size_bytes": 11}
```

## lua-script

Extensions: `.lua` · Category: code · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.lua", "type": "lua-script", "category": "code", "size_bytes": 11}
```

## gdscript

Extensions: `.gd` · Category: code · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.gd", "type": "gdscript", "category": "code", "size_bytes": 11}
```

## dart-source

Extensions: `.dart` · Category: code · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.dart", "type": "dart-source", "category": "code", "size_bytes": 11}
```

## wasm

Extensions: `.wasm` · Category: code · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.wasm", "type": "wasm", "category": "code", "size_bytes": 11}
```

## obb

Extensions: `.obb` · Category: container · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.obb", "type": "obb", "category": "container", "size_bytes": 11}
```

## zip

Extensions: `.zip` · Category: container · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.zip", "type": "zip", "category": "container", "size_bytes": 11}
```

## 7z-archive

Extensions: `.7z` · Category: container · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.7z", "type": "7z-archive", "category": "container", "size_bytes": 11}
```

## aseprite

Extensions: `.ase, .aseprite` · Category: animation · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.ase", "type": "aseprite", "category": "animation", "size_bytes": 11}
```

## rive-animation

Extensions: `.riv` · Category: animation · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.riv", "type": "rive-animation", "category": "animation", "size_bytes": 11}
```

## spriter

Extensions: `.scml` · Category: animation · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.scml", "type": "spriter", "category": "animation", "size_bytes": 11}
```

## javascript-compiled

Extensions: `.jsc` · Category: code · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.jsc", "type": "javascript-compiled", "category": "code", "size_bytes": 11}
```

## python-bytecode

Extensions: `.pyc` · Category: code · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.pyc", "type": "python-bytecode", "category": "code", "size_bytes": 11}
```

## cocos-ccb

Extensions: `.ccb` · Category: data · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.ccb", "type": "cocos-ccb", "category": "data", "size_bytes": 11}
```

## cocos-csb

Extensions: `.csb` · Category: data · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.csb", "type": "cocos-csb", "category": "data", "size_bytes": 11}
```

## unreal-locres

Extensions: `.locres` · Category: data · Parser: `nar-assets + nar-unreal (narlib/locres)` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.locres", "type": "unreal-locres", "category": "data", "size_bytes": 11}
```

## ron-data

Extensions: `.ron` · Category: data · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.ron", "type": "ron-data", "category": "data", "size_bytes": 11}
```

## kivy-layout

Extensions: `.kv` · Category: data · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.kv", "type": "kivy-layout", "category": "data", "size_bytes": 11}
```

## renpy-archive

Extensions: `.rpa` · Category: container · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.rpa", "type": "renpy-archive", "category": "container", "size_bytes": 11}
```

## love-package

Extensions: `.love` · Category: container · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.love", "type": "love-package", "category": "container", "size_bytes": 11}
```

## qt-resource

Extensions: `.rcc` · Category: container · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.rcc", "type": "qt-resource", "category": "container", "size_bytes": 11}
```

## solar2d-car

Extensions: `.car` · Category: container · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.car", "type": "solar2d-car", "category": "container", "size_bytes": 11}
```

## cocos-particle-plist

Extensions: `.plist` · Category: data · Parser: `nar-atlas` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-atlas.py atlas.apk
```

```text
[cocos-particle-plist] assets/particles.plist — max_particles 50, lifespan 1
```

## cocos-plist-atlas

Extensions: `.plist` · Category: data · Parser: `nar-atlas` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-atlas.py atlas.apk
```

```text
[cocos-plist] assets/atlas.plist — texture None, page size n/a, 1 frames, 0 rotated
```

## godot-atlas-texture

Extensions: `.tres` · Category: data · Parser: `nar-atlas` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-atlas.py atlas.apk
```

```text
[godot-atlas-texture] assets/atlas.tres — texture page.png, page size n/a, 1 frames, 0 rotated
```

## libgdx-atlas

Extensions: `.atlas, .pack` · Category: data · Parser: `nar-atlas` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-atlas.py synth2.apk
```

```text
[libgdx-atlas] assets/pack.atlas — texture page.png, 64x64, 1 frames, 0 rotated
```

## phaser-json

Extensions: `.json` · Category: data · Parser: `nar-atlas` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-atlas.py atlas.apk
```

```text
[texturepacker-json-hash] assets/tp.json — texture tp.png, 64x64, 1 frames, 0 rotated (output label was texturepacker-json-hash; see manifest mismatch note)
```

## starling-xml

Extensions: `.xml` · Category: data · Parser: `nar-atlas` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-atlas.py atlas.apk
```

```text
[starling-xml] assets/star.xml — texture star.png, page size n/a, 1 frames, 0 rotated
```

## texturepacker-json

Extensions: `.json` · Category: data · Parser: `nar-atlas` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-atlas.py atlas.apk
```

```text
[texturepacker-json-hash] assets/tp.json — texture tp.png, 64x64, 1 frames, 0 rotated
```

## texturepacker-xml

Extensions: `.xml` · Category: data · Parser: `nar-atlas` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-atlas.py <synthetic-atlas-fixture.apk>
```

```text
  [texturepacker-xml] assets/tp.xml — texture tp.png, 64x64, 1 frames, 0 rotated
```

## unity-spriteatlas

Extensions: `.spriteatlas` · Category: data · Parser: `nar-atlas` · Status: **partial** · Fidelity: identified-only

Honest status: **partial**. Text YAML references packed sprites by GUID only: nar-atlas recovers the atlas name and packed-sprite count; frame names and rects are not recoverable from the .spriteatlas file alone.

## svg-image

Extensions: `.svg` · Category: texture · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.svg", "type": "svg-image", "category": "texture", "size_bytes": 11}
```

## bitmap-font

Extensions: `.fnt` · Category: font · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.fnt", "type": "bitmap-font", "category": "font", "size_bytes": 11}
```

## woff-font

Extensions: `.woff` · Category: font · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.woff", "type": "woff-font", "category": "font", "size_bytes": 11}
```

## woff2-font

Extensions: `.woff2` · Category: font · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.woff2", "type": "woff2-font", "category": "font", "size_bytes": 11}
```

## python

Extensions: `.py` · Category: code · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.py", "type": "python", "category": "code", "size_bytes": 11}
```

## gzip-archive

Extensions: `.gz` · Category: container · Parser: `nar-assets` · Status: **supported** · Fidelity: structural-summary

```bash
python3 scripts/nar-assets.py <synthetic-fixture.apk> --json
```

```json
{"path": "assets/f.gz", "type": "gzip-archive", "category": "container", "size_bytes": 11}
```
