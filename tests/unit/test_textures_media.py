"""Unit tests: compressed texture headers (narlib/textures),
media header facts (narlib/mediainfo, brief section 4.3)
and the nar-assets extension/magic/texture-facts wiring
(Part 4, Group 4 Worker A).

All fixtures are synthetic, built in-test with struct-pack
to the documented header layouts; expected values are the
exact values packed in.
"""
import importlib.util
import json
import os
import struct
import sys
import zipfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from narlib import mediainfo, textures  # noqa: E402


def _load_assets():
    spec = importlib.util.spec_from_file_location(
        "nar_assets_for_g4", os.path.join(ROOT, "scripts",
                                          "nar-assets.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ----------------------------------------------------------------
# Texture fixtures


def _u24(v):
    return bytes([v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF])


def make_astc(bx=4, by=4, bz=1, w=256, h=128, d=1):
    return (b"\x13\xab\xa1\x5c" + bytes([bx, by, bz])
            + _u24(w) + _u24(h) + _u24(d))


def make_ktx1(internal=0x9278, w=128, h=64, mips=5):
    ident = b"\xabKTX 11\xbb\r\n\x1a\n"
    fields = struct.pack(
        "<13I", 0x04030201, 0, 1, 0, internal, 0x1908,
        w, h, 0, 0, 1, mips, 0)
    return ident + fields


def make_ktx2(vk=157, w=256, h=256, levels=7, supercomp=0):
    ident = b"\xabKTX 20\xbb\r\n\x1a\n"
    fields = struct.pack("<9I", vk, 1, w, h, 0, 0, 1,
                         levels, supercomp)
    rest = struct.pack("<4I", 0, 0, 0, 0) \
        + struct.pack("<2Q", 0, 0)
    return ident + fields + rest


def make_pvr(pf=9, w=128, h=64, mips=4):
    return (struct.pack("<IIQ", 0x03525650, 0, pf)
            + struct.pack("<9I", 0, 0, h, w, 1, 1, 1,
                          mips, 0))


def make_dds(fourcc=b"DXT5", w=128, h=64, mips=3, dxgi=None):
    header = (struct.pack("<I", 124)
              + struct.pack("<I", 0x21007)
              + struct.pack("<II", h, w)
              + struct.pack("<III", 0, 0, mips)
              + b"\x00" * 44)
    pixel_format = struct.pack("<II", 32, 0x4) + fourcc \
        + b"\x00" * 20
    caps = struct.pack("<5I", 0x1000, 0, 0, 0, 0)
    data = b"DDS " + header + pixel_format + caps
    if dxgi is not None:
        data += struct.pack("<5I", dxgi, 3, 0, 1, 0)
    return data


def make_pkm20(fmt=1, ext_w=256, ext_h=128, w=250, h=120):
    return b"PKM 20" + struct.pack(">5H", fmt, ext_w,
                                   ext_h, w, h)


# ----------------------------------------------------------------
# Texture tests


def test_astc_dims_and_block():
    r = textures.parse_texture_header(make_astc(), ".astc")
    assert r["error"] is None
    assert r["format"] == "ASTC 4x4"
    assert r["width"] == 256 and r["height"] == 128
    assert r["depth"] == 1
    assert r["block_width"] == 4 and r["block_height"] == 4
    assert r["block_bytes"] == 16
    assert r["mip_count"] is None
    assert r["mip_count_basis"] == "not stored in header"


def test_ktx1_etc2_mapping_and_mips():
    r = textures.parse_texture_header(make_ktx1(), ".ktx")
    assert r["error"] is None
    assert r["format"] == "ETC2 RGBA"
    assert r["width"] == 128 and r["height"] == 64
    assert r["block_width"] == 4 and r["block_height"] == 4
    assert r["block_bytes"] == 16
    assert r["mip_count"] == 5
    assert r["faces"] == 1
    assert r["gl_internal_format"] == 0x9278


def test_ktx1_unknown_internal_format():
    r = textures.parse_texture_header(
        make_ktx1(internal=0x9999), ".ktx")
    assert r["error"] is None
    assert r["format"] == "gl-internal-0x9999"
    assert r["block_width"] is None
    assert r["block_bytes"] is None


def test_ktx2_astc_vkformat_and_levels():
    r = textures.parse_texture_header(make_ktx2(), ".ktx2")
    assert r["error"] is None
    assert r["format"] == "ASTC 4x4 (UNORM)"
    assert r["vk_format"] == 157
    assert r["width"] == 256 and r["height"] == 256
    assert r["mip_count"] == 7
    assert r["faces"] == 1
    assert r["supercompression"] == "none"
    assert r["block_bytes"] == 16


def test_pvr_bc3_and_mips():
    r = textures.parse_texture_header(make_pvr(), ".pvr")
    assert r["error"] is None
    assert r["format"] == "BC3 (DXT5)"
    assert r["width"] == 128 and r["height"] == 64
    assert r["mip_count"] == 4
    assert r["block_bytes"] == 16


def test_dds_dxt5_and_dx10_bc7():
    r = textures.parse_texture_header(make_dds(), ".dds")
    assert r["error"] is None
    assert r["format"] == "BC3 (DXT5)"
    assert r["width"] == 128 and r["height"] == 64
    assert r["mip_count"] == 3
    assert r["block_bytes"] == 16
    r2 = textures.parse_texture_header(
        make_dds(fourcc=b"DX10", dxgi=98), ".dds")
    assert r2["error"] is None
    assert r2["format"] == "BC7 (UNORM)"
    assert r2["dxgi_format"] == 98
    assert r2["block_bytes"] == 16


def test_pkm20_dims():
    r = textures.parse_texture_header(make_pkm20(), ".pkm")
    assert r["error"] is None
    assert r["format"] == "ETC2 RGBA"
    assert r["width"] == 250 and r["height"] == 120
    assert r["padded_width"] == 256
    assert r["padded_height"] == 128
    assert r["mip_count"] is None


def test_texture_malformed_degrades():
    r = textures.parse_texture_header(b"\x00" * 4, ".ktx2")
    assert r["format"] is None
    assert r["error"] is not None
    r = textures.parse_texture_header(b"", ".astc")
    assert r["error"] is not None


# ----------------------------------------------------------------
# Wwise fixtures/tests


def make_bnk():
    bkhd_body = struct.pack("<5I", 140, 0x11223344, 0, 0, 0)
    bkhd = b"BKHD" + struct.pack("<I", len(bkhd_body)) \
        + bkhd_body
    didx = b"DIDX" + struct.pack("<I", 12) + b"\x00" * 12
    hirc = b"HIRC" + struct.pack("<I", 4) \
        + struct.pack("<I", 1)
    return bkhd + didx + hirc


def make_wem():
    fmt_body = struct.pack("<HHIIHH", 0xFFFF, 2, 48000,
                           192000, 0, 16)
    chunks = b"fmt " + struct.pack("<I", len(fmt_body)) \
        + fmt_body
    chunks += b"fact" + struct.pack("<I", 4) \
        + struct.pack("<I", 12345)
    chunks += b"data" + struct.pack("<I", 96000) \
        + b"\x00" * 16
    return b"RIFF" + struct.pack("<I", 4 + len(chunks)) \
        + b"WAVE" + chunks


def test_bnk_bkhd_and_sections():
    r = mediainfo.wwise_bank_facts(make_bnk(), ".bnk")
    assert r["error"] is None
    assert r["is_wem"] is False
    assert r["version"] == 140
    assert r["bank_id"] == 0x11223344
    assert r["section_ids"] == ["BKHD", "DIDX", "HIRC"]
    assert r["sections_present"]["DIDX"] is True
    assert r["sections_present"]["HIRC"] is True
    assert r["sections_present"]["DATA"] is False
    assert r["sections_present"]["STID"] is False


def test_wem_riff_fmt_facts():
    r = mediainfo.wwise_bank_facts(make_wem(), ".wem")
    assert r["error"] is None
    assert r["is_wem"] is True
    assert r["audio_format"] == 0xFFFF
    assert r["channels"] == 2
    assert r["sample_rate_hz"] == 48000
    assert r["byte_rate"] == 192000
    assert r["data_size"] == 96000
    assert r["fact_size"] == 4


# ----------------------------------------------------------------
# Video fixtures/tests


def _box(btype, payload):
    return struct.pack(">I", 8 + len(payload)) + btype \
        + payload


def make_mp4():
    avcc = bytes([1, 100, 0, 40]) + b"\x00" * 8
    avcc_box = _box(b"avcC", avcc)
    visual_entry = (struct.pack(">I", 8 + 78
                                + len(avcc_box))
                    + b"avc1" + b"\x00" * 78 + avcc_box)
    stsd = _box(b"stsd", struct.pack(">II", 0, 1)
                + visual_entry)
    mdia = _box(b"mdia", _box(b"minf", _box(b"stbl", stsd)))
    tkhd_body = (
        b"\x00" * 24 + b"\x00" * 8
        + struct.pack(">HHHH", 0, 0, 0, 0)
        + b"\x00" * 36
        + struct.pack(">II", 1920 << 16, 1080 << 16))
    trak = _box(b"trak", _box(b"tkhd", tkhd_body) + mdia)
    mvhd_body = (
        b"\x00" * 12 + struct.pack(">II", 1000, 5000)
        + b"\x00" * 80)
    moov = _box(b"moov", _box(b"mvhd", mvhd_body) + trak)
    ftyp = _box(b"ftyp", b"isom" + struct.pack(">I", 512)
                + b"isomiso2")
    return ftyp + moov


def test_mp4_avc1_profile():
    r = mediainfo.video_facts(make_mp4(), ".mp4")
    assert r["error"] is None
    assert r["major_brand"] == "isom"
    assert r["timescale"] == 1000
    assert r["duration"] == 5000
    assert r["duration_seconds"] == 5.0
    assert r["width"] == 1920 and r["height"] == 1080
    assert r["codec"] == "avc1"
    assert r["codec_profile"] == 100
    assert r["codec_profile_name"] == "High"
    assert r["codec_level"] == 40
    assert r["b_frames"] is None
    assert "not derivable" in r["b_frames_basis"]


def _ebml_size(n):
    assert n < 127
    return bytes([0x80 | n])


def _elem(eid, payload):
    return eid + _ebml_size(len(payload)) + payload


def make_mkv():
    entry = _elem(b"\xae",
                  _elem(b"\xd7", b"\x01")
                  + _elem(b"\x83", b"\x01")
                  + _elem(b"\x86", b"V_VP9"))
    tracks = _elem(b"\x16\x54\xae\x6b", entry)
    segment = _elem(b"\x18\x53\x80\x67", tracks)
    ebml = _elem(b"\x1a\x45\xdf\xa3",
                 _elem(b"\x42\x82", b"webm")
                 + _elem(b"\x42\x87", b"\x04"))
    return ebml + segment


def test_mkv_codec_id():
    r = mediainfo.video_facts(make_mkv(), ".webm")
    assert r["error"] is None
    assert r["format"] == "webm"
    assert r["doc_type"] == "webm"
    assert r["codec"] == "V_VP9"
    assert r["tracks"][0]["track_type"] == 1
    assert r["b_frames"] is None


# ----------------------------------------------------------------
# Font fixture/tests


def make_font(num_glyphs=1234, family="TestFamily",
              post_format=3.0):
    strings = b""
    records = []

    def add(name_id, text):
        nonlocal strings
        encoded = text.encode("utf-16-be")
        records.append((3, 1, 0x409, name_id,
                        len(encoded), len(strings)))
        strings += encoded

    add(1, family)
    add(2, "Regular")
    add(4, family + " Regular")
    name_table = struct.pack(">HHH", 0, len(records),
                             6 + 12 * len(records))
    for rec in records:
        name_table += struct.pack(">HHHHHH", *rec)
    name_table += strings
    maxp = (struct.pack(">I", 0x00010000)
            + struct.pack(">H", num_glyphs) + b"\x00" * 26)
    post = (struct.pack(">I", int(post_format * 65536))
            + b"\x00" * 28)
    tables = [(b"maxp", maxp), (b"name", name_table),
              (b"post", post)]
    header = struct.pack(">IHHHH", 0x00010000,
                         len(tables), 0, 0, 0)
    offset = 12 + 16 * len(tables)
    directory = b""
    body = b""
    for tag, blob in tables:
        directory += tag + struct.pack(
            ">III", 0, offset + len(body), len(blob))
        body += blob
    return header + directory + body


def test_font_sfnt_glyphs_name_subset():
    r = mediainfo.font_facts(make_font())
    assert r["error"] is None
    assert r["format"] == "ttf"
    assert r["num_glyphs"] == 1234
    assert r["family_name"] == "TestFamily"
    assert r["subfamily"] == "Regular"
    assert r["full_name"] == "TestFamily Regular"
    assert r["post_format"] == 3.0
    assert any("post format 3.0" in s for s in r["signals"])
    assert r["subset_suspected"] is True
    assert "heuristic" in r["basis"]
    r2 = mediainfo.font_facts(make_font(post_format=2.0))
    assert r2["subset_suspected"] is False
    assert r2["num_glyphs"] == 1234


# ----------------------------------------------------------------
# Model fixtures/tests


def make_glb():
    doc = {
        "asset": {"version": "2.0"},
        "meshes": [{"primitives": [
            {"attributes": {"POSITION": 0}},
            {"attributes": {"POSITION": 1}}]}],
        "accessors": [{"count": 100}, {"count": 50}],
        "materials": [{}, {}],
        "skins": [{"joints": [0, 1, 2]}],
        "animations": [{}],
        "nodes": [{}, {}, {}],
    }
    js = json.dumps(doc).encode()
    js += b" " * ((4 - len(js) % 4) % 4)
    chunk = struct.pack("<I", len(js)) + b"JSON" + js
    return struct.pack("<III", 0x46546C67, 2,
                       12 + len(chunk)) + chunk


def test_glb_counts():
    r = mediainfo.model_facts(make_glb(), ".glb")
    assert r["error"] is None
    assert r["meshes"] == 1
    assert r["primitives"] == 2
    assert r["vertex_count"] == 150
    assert r["materials"] == 2
    assert r["skins"] == 1
    assert r["joints"] == 3
    assert r["animations"] == 1


def test_obj_counts():
    obj = (
        "mtllib test.mtl\n"
        "v 0 0 0\nv 1 0 0\nv 0 1 0\n"
        "vt 0 0\nvt 1 0\n"
        "vn 0 0 1\n"
        "usemtl MatA\n"
        "f 1/1/1 2/2/1 3/1/1\n"
        "usemtl MatB\n"
        "f 1/1/1 3/1/1 2/2/1\n"
        "usemtl MatA\n")
    r = mediainfo.model_facts(obj.encode(), ".obj")
    assert r["error"] is None
    assert r["vertices"] == 3
    assert r["texcoords"] == 2
    assert r["normals"] == 1
    assert r["faces"] == 2
    assert r["material_count"] == 2
    assert r["materials_used"] == ["MatA", "MatB"]
    assert r["mtllib"] == ["test.mtl"]


def test_fbx_binary_version_and_note():
    data = (b"Kaydara FBX Binary  \x00\x1a\x00"
            + struct.pack("<I", 7400) + b"\x00" * 32)
    r = mediainfo.model_facts(data, ".fbx")
    assert r["error"] is None
    assert r["format"] == "fbx-binary"
    assert r["version"] == 7400
    assert r["meshes"] is None
    assert r["note"] is not None


def test_media_malformed_degrades():
    assert mediainfo.font_facts(b"\x00" * 8)["error"]
    assert mediainfo.video_facts(b"\x00" * 8, ".mp4")["error"]
    assert mediainfo.model_facts(
        b"\x00" * 8, ".xyz")["error"]


# ----------------------------------------------------------------
# nar-assets integration


def test_assets_inventory_new_kinds_and_texture_facts():
    import tempfile
    assets = _load_assets()
    # Magic signatures classify extension-less-style content.
    assert assets.magic_type(make_ktx2()) == (
        "ktx2-texture", "texture")
    assert assets.magic_type(make_astc()) == (
        "astc-texture", "texture")
    assert assets.magic_type(make_dds()) == (
        "dds-texture", "texture")
    assert assets.magic_type(make_pkm20()) == (
        "pkm-texture", "texture")
    with tempfile.TemporaryDirectory() as td:
        apk = os.path.join(td, "g4.apk")
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("assets/tex.ktx2", make_ktx2())
            zf.writestr("assets/script.lua",
                        "print('hello')\n")
            zf.writestr("assets/anim.skel",
                        b"\x00" * 16 + b"spine-fixture")
        for report in (assets.inventory(apk),
                       assets.inventory(apk,
                                        merge_splits=False)):
            by_path = {a["path"]: a
                       for a in report["assets"]}
            tex = by_path["assets/tex.ktx2"]
            assert tex["type"] == "ktx2-texture"
            assert tex["category"] == "texture"
            assert tex["texture"]["error"] is None
            assert tex["texture"]["format"] == \
                "ASTC 4x4 (UNORM)"
            assert tex["texture"]["width"] == 256
            assert tex["texture"]["mip_count"] == 7
            lua = by_path["assets/script.lua"]
            assert lua["type"] == "lua-script"
            assert lua["category"] == "code"
            assert "texture" not in lua
            skel = by_path["assets/anim.skel"]
            assert skel["type"] == "spine-skeleton"
            assert skel["category"] == "animation"


def test_assets_inventory_media_facts():
    """Coordinator wiring (Part 4 integration): font, model
    and bank entries carry narlib.mediainfo facts in both
    inventory paths; unrelated kinds gain no media keys."""
    import tempfile
    assets = _load_assets()
    with tempfile.TemporaryDirectory() as td:
        apk = os.path.join(td, "g4media.apk")
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("assets/font.ttf", make_font())
            zf.writestr("assets/model.glb", make_glb())
            zf.writestr("assets/bank.bnk", make_bnk())
            zf.writestr("assets/sound.wem", make_wem())
            zf.writestr("assets/readme.txt", "plain\n")
        for report in (assets.inventory(apk),
                       assets.inventory(apk,
                                        merge_splits=False)):
            by_path = {a["path"]: a
                       for a in report["assets"]}
            font = by_path["assets/font.ttf"]
            assert font["font"]["num_glyphs"] == 1234
            bank = by_path["assets/bank.bnk"]
            assert "bank" in bank
            wem = by_path["assets/sound.wem"]
            assert wem["bank"]["is_wem"] is True
            model = by_path["assets/model.glb"]
            assert model["model"]["meshes"] == 1
            plain = by_path["assets/readme.txt"]
            assert "font" not in plain and "model" not in plain
            assert "bank" not in plain
