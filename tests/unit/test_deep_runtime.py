"""Unit tests for the Part 3.2 runtime/native deep dives:
nar-cocos, nar-libgdx, nar-xamarin, nar-monogame, nar-mono,
nar-python, nar-sdl, nar-ebiten, nar-bevy.

All fixtures are synthetic and built in this file: the tiny
.NET assembly comes from test_dotnetmeta's builder (3 TypeDef
rows including <Module> -> 2 types, 5 MethodDef rows, module
name "Test.dll", namespaces NS.One / NS.Two); the ELF builder
mirrors tests/unit/test_engines_jni_symbols.py. Invented
names only; no app data.
"""
import importlib.util
import io
import json
import marshal
import plistlib
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import test_dotnetmeta  # noqa: E402  (sibling fixture builder)

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"

TOOLS = ["cocos", "libgdx", "xamarin", "monogame", "mono",
         "python", "sdl", "ebiten", "bevy"]


def _load(name):
    spec = importlib.util.spec_from_file_location(
        f"nar_{name}", SCRIPTS / f"nar-{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _apk(tmp_path, name, members):
    path = tmp_path / name
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for member, data in members:
            zf.writestr(member, data)
    path.write_bytes(buf.getvalue())
    return path


def _run(tool, apk, *extra):
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / f"nar-{tool}.py"),
         str(apk), "--json", *extra],
        capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, (tool, proc.stderr)
    return json.loads(proc.stdout)


def _dll_bytes(tmp_path):
    path = test_dotnetmeta.build_assembly(tmp_path)
    return Path(path).read_bytes()


def _elf64_with_exports(names):
    """Minimal ELF64 (LE, ET_DYN) whose .dynsym exports
    exactly `names` as defined GLOBAL FUNC symbols (the
    builder approach of test_engines_jni_symbols.py)."""
    dynstr = b"\x00"
    offsets = {}
    for name in names:
        offsets[name] = len(dynstr)
        dynstr += name.encode() + b"\x00"
    dynsym = b"\x00" * 24  # null symbol
    for name in names:
        dynsym += struct.pack(
            "<IBBHQQ", offsets[name], 0x12, 0, 1, 0, 0)
    shstrtab = b"\x00.dynsym\x00.dynstr\x00.shstrtab\x00"
    sh_name = {".dynsym": 1, ".dynstr": 9, ".shstrtab": 17}
    ehsize = 64
    off_dynsym = ehsize
    off_dynstr = off_dynsym + len(dynsym)
    off_shstr = off_dynstr + len(dynstr)
    shoff = off_shstr + len(shstrtab)

    def sh(name, shtype, offset, size, link, info, entsize):
        return struct.pack(
            "<IIQQQQIIQQ", sh_name.get(name, 0), shtype, 0, 0,
            offset, size, link, info, 8, entsize)

    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8,
        3, 0xB7, 1, 0, 0, shoff, 0, ehsize, 0, 0, 64, 4, 3)
    sections = b"\x00" * 64
    sections += sh(".dynsym", 11, off_dynsym, len(dynsym),
                   2, 1, 24)
    sections += sh(".dynstr", 3, off_dynstr, len(dynstr),
                   0, 0, 0)
    sections += sh(".shstrtab", 3, off_shstr, len(shstrtab),
                   0, 0, 0)
    return header + dynsym + dynstr + shstrtab + sections


# ---------------------------------------------------------- cocos

def test_cocos_atlas_particles_jsc(tmp_path):
    atlas_plist = plistlib.dumps({
        "frames": {
            "hero.png": {"frame": "{{0,0},{32,32}}",
                         "rotated": False,
                         "offset": "{0,0}",
                         "sourceSize": "{32,32}"},
            "enemy.png": {"frame": "{{32,0},{16,16}}",
                          "rotated": True,
                          "offset": "{0,0}",
                          "sourceSize": "{16,16}"},
        },
        "metadata": {"format": 2,
                     "realTextureFileName": "ui.png",
                     "size": "{256,256}"},
    })
    particle_plist = plistlib.dumps({
        "maxParticles": 80, "particleLifespan": 1.5,
        "emitterType": 0, "duration": -1,
        "startParticleSize": 12.0, "finishParticleSize": 2.0,
    })
    apk = _apk(tmp_path, "cocos.apk", [
        ("assets/res/ui.plist", atlas_plist),
        ("assets/res/boom.plist", particle_plist),
        ("assets/src/main.jsc", b"\x00\x01\x02spidermonkey"),
        ("assets/scene.csb", b"csb-bytes-here"),
        ("lib/arm64-v8a/libcocos2dcpp.so",
         b"\x7fELF" + b"\x00" * 32 + b"cocos2d-x 3.17.2\x00"),
    ])
    report = _run("cocos", apk)
    assert report["verdict"] == "present"
    assert report["atlases"]["count"] == 1
    assert report["atlases"]["total_frames"] == 2
    assert report["particles"]["count"] == 1
    assert report["jsc"]["count"] == 1
    assert report["jsc"]["total_bytes"] == 15
    assert report["cocos_files"]["count"] == 1
    assert report["asset_layout"]["assets_res"] == 2
    assert any(ev["match"].startswith("cocos2d-x 3.")
               for ev in report["version_evidence"])


# ---------------------------------------------------------- libgdx

_GDX_ATLAS = b"""ui.png
size: 256, 256
format: RGBA8888
filter: Linear, Linear
repeat: none
button
  xy: 0, 0
  size: 64, 32
  orig: 64, 32
  offset: 0, 0
  index: -1
panel
  xy: 64, 0
  size: 32, 32
  orig: 32, 32
  offset: 0, 0
  index: -1
"""

_TMX = b"""<?xml version="1.0" encoding="UTF-8"?>
<map version="1.10" orientation="orthogonal" width="20"
     height="15" tilewidth="32" tileheight="32">
 <tileset firstgid="1" name="ground" tilecount="48"
          tilewidth="32" tileheight="32"/>
 <tileset firstgid="49" name="props"/>
 <layer name="Ground" width="20" height="15">
  <data encoding="csv">0,0,0</data>
 </layer>
 <objectgroup name="Spawns"/>
</map>
"""


def test_libgdx_atlas_and_tmx(tmp_path):
    apk = _apk(tmp_path, "gdx.apk", [
        ("assets/ui.atlas", _GDX_ATLAS),
        ("assets/maps/level1.tmx", _TMX),
        ("assets/game.nocache.js", b"// gwt bootstrap"),
        ("assets/gdx.jar", b"PK\x03\x04"),
        ("lib/arm64-v8a/libgdx.so",
         b"\x7fELF" + b"\x00" * 16 + b"libGDX 1.12.1\x00"),
    ])
    report = _run("libgdx", apk)
    assert report["verdict"] == "present"
    assert report["atlases"]["count"] == 1
    assert report["atlases"]["pages"] == 1
    assert report["atlases"]["regions_total"] == 2
    assert report["tile_maps"]["count"] == 1
    mp = report["tile_maps"]["maps"][0]
    assert mp["orientation"] == "orthogonal"
    assert mp["width"] == 20 and mp["height"] == 15
    assert mp["tilewidth"] == 32 and mp["tileheight"] == 32
    assert mp["tilesets"][0] == {"name": "ground",
                                 "firstgid": 1,
                                 "tilecount": 48}
    assert mp["tilesets"][1]["name"] == "props"
    assert mp["tilesets"][1]["tilecount"] is None
    assert [layer["kind"] for layer in mp["layers"]] == \
        ["tilelayer", "objectgroup"]
    assert mp["data_encodings"] == ["csv"]
    assert report["gwt"]["nocache_js_count"] == 1
    assert report["asset_jars"]["names"] == ["gdx.jar"]
    assert report["libgdx_version"] == "1.12.1"


# ---------------------------------------------------------- xamarin

def test_xamarin_loose_and_blob_assemblies(tmp_path):
    dll = _dll_bytes(tmp_path)
    blob = b"\x00" * 16 + dll + b"XALZ" + b"\x00" * 32
    apk = _apk(tmp_path, "xam.apk", [
        ("assets/assemblies/Synthetic.dll", dll),
        ("assets/assemblies/assemblies.blob", blob),
        ("assets/assemblies/assemblies.manifest",
         b"Synthetic.dll\n"),
        ("lib/arm64-v8a/libmonosgen-2.0.so", b"\x7fELF"),
    ])
    report = _run("xamarin", apk)
    assert report["verdict"] == "present"
    assert report["assemblies"]["count"] == 2
    for item in report["assemblies"]["items"]:
        assert item["name"] == "Test.dll"
        assert item["typedef_count"] == 2
        assert item["methoddef_count"] == 5
    sources = {item["source"]
               for item in report["assemblies"]["items"]}
    assert any("assemblies.blob@" in s for s in sources)
    assert report["xalz"]["xalz_blocks"] == 1
    assert report["assembly_store"]["manifest_present"] is True
    assert report["assembly_store"]["assemblies_dir_dlls"] == 1
    assert report["native_runtime"][0]["path"].endswith(
        "libmonosgen-2.0.so")


def test_xamarin_garbage_dll_degrades(tmp_path):
    apk = _apk(tmp_path, "bad.apk", [
        ("assets/assemblies/Broken.dll", b"not a PE at all"),
    ])
    report = _run("xamarin", apk)
    assert report["verdict"] == "absent"
    assert report["assemblies"]["count"] == 0
    assert report["assemblies"]["unparseable"] == 1


# ---------------------------------------------------------- monogame

def _7bit(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _xnb(readers=(), compressed=False):
    body = bytearray()
    if not compressed:
        body += _7bit(len(readers))
        for name, ver in readers:
            raw = name.encode()
            body += _7bit(len(raw)) + raw
            body += struct.pack("<I", ver)
        body += _7bit(0)  # shared-resource count
    flags = 0x80 if compressed else 0x00
    header = b"XNB" + b"a" + bytes([5, flags]) \
        + struct.pack("<I", 10 + len(body))
    return header + bytes(body)


def test_monogame_xnb_census_and_framework(tmp_path):
    dll = _dll_bytes(tmp_path)
    plain = _xnb(readers=[
        ("Microsoft.Xna.Framework.Content.Texture2DReader", 0),
        ("Microsoft.Xna.Framework.Content.SpriteFontReader", 0),
    ])
    packed = _xnb(compressed=True)
    apk = _apk(tmp_path, "mg.apk", [
        ("assets/assemblies/MonoGame.Framework.dll", dll),
        ("assets/Content/hero.xnb", plain),
        ("assets/Content/music.xnb", packed),
    ])
    report = _run("monogame", apk)
    assert report["verdict"] == "present"
    assert report["framework"]["present"] is True
    assert report["framework"]["typedef_count"] == 2
    xnb = report["xnb"]
    assert xnb["count"] == 2
    assert xnb["by_reader"] == {"Texture2DReader": 1}
    assert xnb["compressed_count"] == 1
    assert xnb["invalid_count"] == 0
    hero = next(f for f in xnb["files"]
                if f["file"].endswith("hero.xnb"))
    assert hero["platform"] == "a"
    assert hero["platform_name"] == "Android"
    assert hero["reader_count"] == 2
    assert hero["size_valid"] is True


# ---------------------------------------------------------- mono

def test_mono_managed_census_and_indicator(tmp_path):
    dll = _dll_bytes(tmp_path)
    apk = _apk(tmp_path, "mono.apk", [
        ("assets/bin/Data/Managed/Assembly-CSharp.dll", dll),
        ("assets/bin/Data/Managed/UnityEngine.dll", dll),
        ("lib/arm64-v8a/libmono.so", b"\x7fELF"),
    ])
    report = _run("mono", apk)
    assert report["verdict"] == "present"
    assert report["managed"]["count"] == 2
    cs = report["assembly_csharp"]
    assert cs["present"] is True
    assert cs["typedef_count"] == 2
    ind = cs["obfuscation_indicator"]
    assert ind["total_types"] == 2
    assert ind["short_or_invalid_names"] == 0
    assert ind["ratio"] == 0.0
    assert ind["basis"].startswith("heuristic")
    entry = next(a for a in report["managed"]["assemblies"]
                 if a["name"] == "Assembly-CSharp.dll")
    assert "NS.One" in entry["namespaces_sample"]
    assert report["backend_crosscheck"]["libmono"] == [
        "lib/arm64-v8a/libmono.so"]
    assert report["backend_crosscheck"]["libil2cpp"] == []


# ---------------------------------------------------------- python

def test_python_pyc_census_and_kivy(tmp_path):
    src = ("import os\n\n"
           "def alpha(x):\n    return x + 1\n\n"
           "def beta():\n    return alpha(2)\n")
    code = compile(src, "main.py", "exec")
    header = importlib.util.MAGIC_NUMBER \
        + struct.pack("<I", 0) + b"\x00" * 8
    pyc = header + marshal.dumps(code)
    apk = _apk(tmp_path, "py.apk", [
        ("assets/main.pyc", pyc),
        ("assets/ui.kv", b"<Label>: text: 'hi'\n"),
        ("lib/arm64-v8a/libpython3.11.so", b"\x7fELF"),
    ])
    report = _run("python", apk)
    assert report["verdict"] == "present"
    assert report["pyc_totals"] == {"count": 1, "parsed": 1,
                                    "listed": 1}
    rec = report["pyc"][0]
    magic = int.from_bytes(importlib.util.MAGIC_NUMBER,
                           "little")
    assert rec["magic"] == magic
    module = _load("python")
    assert rec["python_version"] == \
        module.MAGIC_VERSIONS.get(magic)
    assert rec["header_size"] == 16
    assert rec["code_objects"] == 3   # module + alpha + beta
    assert rec["functions"] == 2
    assert "alpha" in rec["module_names_sample"]
    assert report["libpython"][0]["version"] == "3.11"
    assert report["kivy"]["kv_count"] == 1
    assert report["kivy"]["main_pyc"] is True
    assert report["kivy"]["kivy_version"] is None


# ---------------------------------------------------------- sdl

def test_sdl_dynsym_census(tmp_path):
    elf = _elf64_with_exports(
        ["SDL_Init", "SDL_CreateWindow", "SDL_main",
         "SDL_Quit", "plain_helper"])
    apk = _apk(tmp_path, "sdl.apk", [
        ("lib/arm64-v8a/libSDL2.so", elf),
        ("lib/arm64-v8a/libSDL2_mixer.so", b"\x7fELF dummy"),
    ])
    report = _run("sdl", apk)
    assert report["verdict"] == "present"
    entry = report["libraries"][0]
    assert entry["defined_exports"] == 5
    assert entry["sdl_exports"] == 4
    assert entry["has_sdl_main"] is True
    assert entry["has_sdl_init"] is True
    assert entry["has_sdl_create_window"] is True
    assert "SDL_Init" in entry["sdl_export_sample"]
    assert report["satellites"] == [
        "lib/arm64-v8a/libSDL2_mixer.so"]
    assert report["revision"] is None


def test_sdl_name_only_is_absent(tmp_path):
    apk = _apk(tmp_path, "sdlname.apk", [
        ("lib/arm64-v8a/libSDL2.so", b"not an ELF at all"),
    ])
    report = _run("sdl", apk)
    assert report["verdict"] == "absent"
    assert "error" in report["libraries"][0]


# ---------------------------------------------------------- ebiten

def _uvarint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _go_lib(flags=2):
    version = b"go1.21.0"
    modinfo = (b"path\texample.com/gadget\n"
               b"mod\texample.com/gadget\tv1.2.3\t\n"
               b"build\t-compiler=gc\n"
               b"build\tGOOS=android\n"
               b"build\tGOARCH=arm64\n")
    blob = b"\xff Go buildinf:" + bytes([8, flags])
    if flags & 2:
        blob += _uvarint(len(version)) + version
        blob += _uvarint(len(modinfo)) + modinfo
    return b"\x7fELF" + b"\x00" * 64 + blob + b"\x00" * 16


def test_ebiten_buildinf_string_form(tmp_path):
    apk = _apk(tmp_path, "eb.apk", [
        ("lib/arm64-v8a/libgame.so", _go_lib()),
        ("assets/a.png", b"png"),
        ("assets/b.png", b"png"),
        ("assets/c.txt", b"txt"),
    ])
    report = _run("ebiten", apk)
    assert report["verdict"] == "present"
    build = report["go_builds"][0]
    assert build["go_version"] == "go1.21.0"
    assert build["module_path"] == "example.com/gadget"
    assert build["module_version"] == "v1.2.3"
    assert build["settings"]["GOOS"] == "android"
    assert build["settings"]["GOARCH"] == "arm64"
    assert report["embedded_assets"]["count"] == 3
    assert report["embedded_assets"]["by_ext_top5"][".png"] \
        == 2


def test_ebiten_buildinf_pointer_form(tmp_path):
    apk = _apk(tmp_path, "ebp.apk", [
        ("lib/arm64-v8a/libgame.so", _go_lib(flags=0)),
    ])
    report = _run("ebiten", apk)
    assert report["verdict"] == "present"
    build = report["go_builds"][0]
    assert build["buildinf"] == "pointer-form"
    assert build["go_version"] is None


# ---------------------------------------------------------- bevy

_BEVY_RON = b"""(
    entities: [
        (
            components: {
                "example::Health": (value: 10),
            },
        ),
    ],
    resources: (
        score: 3,
    ),
)
"""


def test_bevy_ron_and_rust_evidence(tmp_path):
    lib = (b"\x7fELF" + b"\x00" * 32
           + b"rustc version 1.75.0\x00"
           + b"bevy_ecs bevy_render bevy_asset winit\x00")
    apk = _apk(tmp_path, "bevy.apk", [
        ("assets/scene.scn.ron", _BEVY_RON),
        ("assets/config.ron",
         b"(window: (width: 800), sound: true)"),
        ("lib/arm64-v8a/libgame.so", lib),
    ])
    report = _run("bevy", apk)
    assert report["verdict"] == "present"
    assert report["assets"]["count"] == 2
    assert report["assets"]["ron_count"] == 2
    assert report["assets"]["scn_ron_count"] == 1
    assert report["assets"]["by_ext"][".ron"] == 2
    facts = {f["file"]: f for f in report["ron"]["files"]}
    scene = facts["assets/scene.scn.ron"]
    assert scene["top_level_keys"] == ["entities",
                                       "resources"]
    config = facts["assets/config.ron"]
    assert config["top_level_keys"] == ["window", "sound"]
    rust = report["rust_evidence"]
    assert rust["rustc_version"] == "1.75.0"
    assert rust["crate_hits"]["bevy_ecs"] >= 1
    assert rust["crate_hits"]["bevy_render"] >= 1


# ---------------------------------------------------------- controls

def test_absent_controls_and_exit_codes(tmp_path):
    empty = _apk(tmp_path, "empty.apk", [
        ("AndroidManifest.xml", b"\x00\x01"),
    ])
    for tool in TOOLS:
        report = _run(tool, empty)
        assert report["verdict"] == "absent", tool
        assert report["version"] == "3.0.1", tool
        assert report["container"]["input_kind"] == "apk", tool
    missing = tmp_path / "nope.apk"
    for tool in TOOLS:
        proc = subprocess.run(
            [sys.executable, str(SCRIPTS / f"nar-{tool}.py"),
             str(missing), "--json"],
            capture_output=True, text=True, timeout=60)
        assert proc.returncode == 2, tool


def test_human_output_smoke(tmp_path):
    apk = _apk(tmp_path, "smoke.apk", [
        ("assets/src/main.jsc", b"\x00\x01"),
    ])
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / "nar-cocos.py"),
         str(apk)],
        capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0
    assert "Verdict: present" in proc.stdout
