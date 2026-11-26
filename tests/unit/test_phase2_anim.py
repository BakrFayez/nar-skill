"""Unit tests: Phase 2 animation fix round (finding M2-10).

Synthetic fixtures per new detection surface, built in-file
(no external data): GIF header/block-walk decode, PAG
identification, Android view-animation AXML/text-XML decode,
and Unity serialized-data member identification. Negative
controls pin the honesty boundaries: no record is emitted
from a name alone where a structural surface is required,
and identification-only surfaces never claim decoded facts.

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import struct
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from narlib import anim  # noqa: E402


def parse(name, data):
    if isinstance(data, str):
        data = data.encode()
    return anim.classify_and_parse(name, data, "test.apk")


# ------------------------------------------------------------- GIF

def _gif_frame(delay_cs=None):
    out = b""
    if delay_cs is not None:
        out += b"\x21\xf9\x04\x00" \
            + struct.pack("<H", delay_cs) + b"\x00\x00"
    # Image descriptor: 9 bytes after the separator, no
    # local colour table; then the LZW minimum code size
    # and one data sub-block closed by a zero length.
    out += b"\x2c" + struct.pack("<HHHHB", 0, 0, 2, 2, 0)
    out += b"\x02\x02\x4c\x01\x00"
    return out


def _gif(frames, version=b"GIF89a", loop=None):
    # Logical screen descriptor: 2x2, global colour table
    # of 2 entries (packed 0x80), background 0, aspect 0.
    data = version + struct.pack("<HHBBB", 2, 2, 0x80, 0, 0)
    data += b"\x00\x00\x00\xff\xff\xff"
    if loop is not None:
        data += b"\x21\xff\x0bNETSCAPE2.0\x03\x01" \
            + struct.pack("<H", loop) + b"\x00"
    for delay in frames:
        data += _gif_frame(delay)
    return data + b"\x3b"


def test_gif_decoded_frame_walk():
    rec = parse("assets/intro.gif", _gif([10, 20, None]))
    assert rec["system"] == "gif"
    assert rec["status"] == "decoded"
    facts = rec["facts"]
    assert facts["version"] == "GIF89a"
    assert facts["width"] == 2
    assert facts["height"] == 2
    assert facts["frame_count"] == 3
    assert facts["animated"] is True
    assert facts["frame_delays_cs"] == [10, 20]
    assert facts["loop_count"] is None


def test_gif_loop_extension_and_single_frame():
    rec = parse("assets/badge.gif", _gif([5], loop=0))
    assert rec["status"] == "decoded"
    assert rec["facts"]["frame_count"] == 1
    assert rec["facts"]["animated"] is False
    assert rec["facts"]["loop_count"] == 0
    rec87 = parse("assets/old.gif",
                  _gif([None, None], version=b"GIF87a"))
    assert rec87["facts"]["version"] == "GIF87a"
    assert rec87["facts"]["frame_count"] == 2


def test_gif_bad_magic_identified_only():
    rec = parse("assets/fake.gif", b"NOTGIF" + b"\x00" * 32)
    assert rec["system"] == "gif"
    assert rec["status"] == "identified_only"
    assert "frame_count" not in rec["facts"]


def test_gif_truncated_walk_identified_only():
    data = _gif([10, 10])[:-3]  # trailer + block tail cut
    rec = parse("assets/cut.gif", data)
    assert rec["status"] == "identified_only"
    assert rec["facts"]["width"] == 2
    assert "frame_count" not in rec["facts"]


# ------------------------------------------------------------- PAG

def test_pag_member_identified_only():
    rec = parse("assets/intro.pag",
                b"\x00\x01\x02\x03pag-bytes" + b"\x00" * 24)
    assert rec["system"] == "pag"
    assert rec["status"] == "identified_only"
    assert rec["facts"]["size_bytes"] == 37
    assert rec["facts"]["first_bytes_hex"].startswith(
        "00010203")
    assert rec["reason"] and rec["probe"]


def test_pag_substring_names_are_not_pag():
    # A version file of an unrelated paging library: the
    # name contains the substring but is not a .pag member.
    assert parse(
        "META-INF/androidx.paging_paging-runtime.version",
        b"version=3.2") is None
    # A native library whose name embeds the substring is
    # not an animation file either.
    assert parse("lib/arm64-v8a/libpagelike.so",
                 b"\x7fELF" + b"\x00" * 32) is None


def test_pag_scan_target_end_to_end(tmp_path):
    apk = tmp_path / "pag.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("assets/intro.pag", b"\x01\x02" * 16)
        zf.writestr(
            "META-INF/androidx.paging_paging-runtime.version",
            b"version=3.2")
    report = anim.scan_target(str(apk))
    pags = [r for r in report["systems"]
            if r["system"] == "pag"]
    assert len(pags) == 1
    assert pags[0]["file"] == "assets/intro.pag"
    assert pags[0]["status"] == "identified_only"


# ------------------------------------------------- android-view

def _axml_pool(strings):
    offsets = []
    blob = b""
    for s in strings:
        raw = s.encode()
        offsets.append(len(blob))
        blob += bytes([len(raw), len(raw)]) + raw + b"\x00"
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    size = strings_start + len(blob)
    out = struct.pack("<HHI", 0x0001, header_size, size)
    out += struct.pack("<IIIII", len(strings), 0, 0x100,
                       strings_start, 0)
    for off in offsets:
        out += struct.pack("<I", off)
    return out + blob


def _axml_start(name_idx, attrs=(), ns_idx=0xFFFFFFFF):
    size = 36 + 20 * len(attrs)
    out = struct.pack("<HHI", 0x0102, 16, size)
    out += struct.pack("<II", 0, 0xFFFFFFFF)
    out += struct.pack("<II", ns_idx, name_idx)
    out += struct.pack("<HHHHHH", 20, 20, len(attrs), 0, 0, 0)
    for a_ns, a_name, a_type, a_data in attrs:
        out += struct.pack("<IIIHBBI", a_ns, a_name,
                           0xFFFFFFFF, 8, 0, a_type, a_data)
    return out


def _axml_end(name_idx):
    out = struct.pack("<HHI", 0x0103, 16, 24)
    out += struct.pack("<II", 0, 0xFFFFFFFF)
    out += struct.pack("<II", 0xFFFFFFFF, name_idx)
    return out


def _axml_set_doc():
    # strings: 0=set 1=alpha 2=duration 3=<android ns uri>
    strings = ["set", "alpha", "duration",
               "http://schemas.android.com/apk/res/android"]
    body = _axml_pool(strings)
    body += _axml_start(0)
    body += _axml_start(1, attrs=[(3, 2, 0x10, 300)])
    body += _axml_end(1)
    body += _axml_end(0)
    return struct.pack("<II", 0x00080003, 8 + len(body)) \
        + body


def test_android_view_axml_decoded():
    rec = parse("res/anim/fade.xml", _axml_set_doc())
    assert rec["system"] == "android-view"
    assert rec["status"] == "decoded"
    facts = rec["facts"]
    assert facts["root"] == "set"
    assert facts["resource_kind"] == "anim"
    assert facts["element_count"] == 2
    assert facts["element_kinds"] == {"alpha": 1, "set": 1}
    assert facts["durations_ms"] == [300]


def test_android_view_axml_qualifier_directory():
    rec = parse("res/anim-v21/fade.xml", _axml_set_doc())
    assert rec["status"] == "decoded"
    assert rec["facts"]["resource_kind"] == "anim"


def test_android_view_text_xml_decoded():
    text = ('<objectAnimator '
            'xmlns:android="http://schemas.android.com/'
            'apk/res/android" '
            'android:propertyName="translationX" '
            'android:duration="400"/>')
    rec = parse("res/animator/slide.xml", text)
    assert rec["system"] == "android-view"
    assert rec["status"] == "decoded"
    assert rec["facts"]["resource_kind"] == "animator"
    assert rec["facts"]["property_names"] == ["translationX"]
    assert rec["facts"]["durations_ms"] == [400]


def test_android_view_selector_with_animator_child():
    text = ('<selector '
            'xmlns:android="http://schemas.android.com/'
            'apk/res/android"><item>'
            '<objectAnimator android:duration="120"/>'
            '</item></selector>')
    rec = parse("res/animator/state.xml", text)
    assert rec is not None
    assert rec["status"] == "decoded"
    assert rec["facts"]["root"] == "selector"


def test_android_view_negatives():
    # A layout root is not an animation, wherever it sits.
    layout = ('<LinearLayout '
              'xmlns:android="http://schemas.android.com/'
              'apk/res/android"/>')
    assert parse("res/layout/main.xml", layout) is None
    assert parse("main.xml", layout) is None
    # A selector without animator children is not claimed.
    sel = ('<selector '
           'xmlns:android="http://schemas.android.com/'
           'apk/res/android"><item/></selector>')
    assert parse("res/animator/state.xml", sel) is None
    # Layout members are never scan candidates.
    assert not anim.is_candidate("res/layout/main.xml")
    assert not anim.is_candidate("assets/data.xml")
    assert anim.is_candidate("res/anim/fade.xml")
    assert anim.is_candidate("res/animator-v21/slide.xml")


def test_android_view_broken_axml_identified_only():
    rec = parse("res/anim/broken.xml",
                b"\x03\x00\x08\x00" + b"\xff" * 40)
    assert rec["system"] == "android-view"
    assert rec["status"] == "identified_only"


def test_android_view_scan_target_end_to_end(tmp_path):
    apk = tmp_path / "view.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("res/anim/fade.xml", _axml_set_doc())
        zf.writestr(
            "res/animator/slide.xml",
            '<objectAnimator '
            'xmlns:android="http://schemas.android.com/'
            'apk/res/android" android:duration="400"/>')
        zf.writestr(
            "res/layout/main.xml",
            '<LinearLayout '
            'xmlns:android="http://schemas.android.com/'
            'apk/res/android"/>')
    report = anim.scan_target(str(apk))
    views = [r for r in report["systems"]
             if r["system"] == "android-view"]
    assert len(views) == 2
    assert all(r["status"] == "decoded" for r in views)


# ------------------------------------------------------- unity

_CLIP_BYTES = b"\x00\x16\x00\x00serialized AnimationClip data"
_CTRL_BYTES = b"\x00\x16\x00\x00serialized AnimatorController"


def test_unity_bindata_extensionless_member():
    rec = parse("assets/bin/Data/0781ba87d78f19641800002a",
                _CLIP_BYTES)
    assert rec["system"] == "unity-animator"
    assert rec["status"] == "identified_only"
    assert rec["facts"]["embedded_types"] == ["AnimationClip"]


def test_unity_assets_split_part_member():
    rec = parse("assets/bin/Data/sharedassets3.assets.split4",
                _CTRL_BYTES)
    assert rec["system"] == "unity-animator"
    assert rec["status"] == "identified_only"
    assert rec["facts"]["embedded_types"] == [
        "AnimatorController"]


def test_unity_level_split_part_member():
    rec = parse("assets/bin/Data/level2.split0", _CLIP_BYTES)
    assert rec["system"] == "unity-animator"
    assert rec["status"] == "identified_only"


def test_unity_excluded_members():
    # Raw .resource payloads are not serialized data.
    assert parse("assets/bin/Data/sharedassets0.resource",
                 _CLIP_BYTES) is None
    # IL2CPP metadata carries engine type tables whether or
    # not the game ships animation; it is not evidence.
    assert parse(
        "assets/bin/Data/Managed/Metadata/global-metadata.dat",
        _CLIP_BYTES + _CTRL_BYTES) is None
    # A serialized-data member without the type names is
    # not an animation record.
    assert parse("assets/bin/Data/0123abcd",
                 b"\x00\x16\x00\x00plain serialized data") \
        is None


def test_unity_scan_target_end_to_end(tmp_path):
    apk = tmp_path / "unity.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("assets/bin/Data/0781ba87d78f19641800002a",
                    _CLIP_BYTES)
        zf.writestr("assets/bin/Data/sharedassets0.resource",
                    _CLIP_BYTES)
        zf.writestr("assets/bin/Data/0123abcd",
                    b"plain serialized data")
    report = anim.scan_target(str(apk))
    unity = [r for r in report["systems"]
             if r["system"] == "unity-animator"]
    assert len(unity) == 1
    assert unity[0]["file"] == \
        "assets/bin/Data/0781ba87d78f19641800002a"
    assert unity[0]["status"] == "identified_only"


def test_gif_scan_target_end_to_end(tmp_path):
    apk = tmp_path / "gif.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("assets/intro.gif", _gif([10, 10]))
        zf.writestr("assets/readme.txt", b"not an image")
    report = anim.scan_target(str(apk))
    gifs = [r for r in report["systems"]
            if r["system"] == "gif"]
    assert len(gifs) == 1
    assert gifs[0]["status"] == "decoded"
    assert gifs[0]["facts"]["frame_count"] == 2
