"""Unit tests: field round P1, Area 5 (native analysis depth).

Pins the Area 5 wiring / coverage work:

- physics detection (narlib/anim.detect_physics) gathers
  evidence from THREE channels — defined dynsym exports,
  defined SHT_SYMTAB symbols, and raw printable-string token
  hits — so a statically-linked / hidden-visibility build is
  still identified, and each rig record names the channels
  that contributed ("evidence_sources");
- nar-native surfaces the same detection as
  report["physics_detections"] plus a per-library
  "physics_families" label;
- nar-assets classifies gettext files (.po/.mo/.pot) and
  reports shipped development artifacts in
  report["development_artifacts"]: gettext files,
  embedded source-path references, and physics-scene editor
  (R.U.B.E.-shaped) JSON exports.

Synthetic fixtures only, byte-built in-file (the ELF builder
generalises the test_anim.py approach with an optional
SHT_SYMTAB). No external data, no app data.

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import importlib.util
import io
import json
import struct
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from narlib import anim  # noqa: E402


def _load_script(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


NATIVE = _load_script("nar_native_field_p1", "nar-native.py")
ASSETS = _load_script("nar_assets_field_p1", "nar-assets.py")


# ------------------------------------------------------------------ ELF

def _elf64(dynsym_names=(), symtab_names=(), extra=b""):
    """Minimal ELF64 (LE, ET_DYN).

    .dynsym exports exactly ``dynsym_names`` (defined GLOBAL
    FUNC symbols); when ``symtab_names`` is non-empty a
    SHT_SYMTAB carrying exactly those defined symbols is
    emitted too. ``extra`` raw bytes are appended after the
    section headers (unreferenced payload, e.g. string data).
    """
    def _symtab(names):
        strtab = b"\x00"
        offsets = {}
        for n in names:
            offsets[n] = len(strtab)
            strtab += n.encode() + b"\x00"
        blob = b"\x00" * 24  # null symbol
        for n in names:
            blob += struct.pack(
                "<IBBHQQ", offsets[n], 0x12, 0, 1, 0, 0)
        return blob, strtab

    dynsym, dynstr = _symtab(list(dynsym_names))
    symtab = strtab = b""
    if symtab_names:
        symtab, strtab = _symtab(list(symtab_names))

    # Section plan: 0 null, 1 .dynsym, 2 .dynstr,
    # [3 .symtab, 4 .strtab], last .shstrtab.
    names = [".dynsym", ".dynstr"]
    if symtab_names:
        names += [".symtab", ".strtab"]
    names += [".shstrtab"]
    shstrtab = b"\x00"
    sh_name = {}
    for n in names:
        sh_name[n] = len(shstrtab)
        shstrtab += n.encode() + b"\x00"
    idx = {n: i + 1 for i, n in enumerate(names)}

    ehsize = 64
    off = ehsize
    layout = {}
    for key, blob in (("dynsym", dynsym), ("dynstr", dynstr),
                      ("symtab", symtab), ("strtab", strtab),
                      ("shstrtab", shstrtab)):
        layout[key] = (off, len(blob))
        off += len(blob)
    shoff = off

    def sh(name, shtype, offset, size, link, entsize):
        return struct.pack(
            "<IIQQQQIIQQ", sh_name.get(name, 0), shtype, 0, 0,
            offset, size, link, 1, 8, entsize)

    sections = b"\x00" * 64
    sections += sh(".dynsym", 11, *layout["dynsym"],
                   idx[".dynstr"], 24)
    sections += sh(".dynstr", 3, *layout["dynstr"], 0, 0)
    if symtab_names:
        sections += sh(".symtab", 2, *layout["symtab"],
                       idx[".strtab"], 24)
        sections += sh(".strtab", 3, *layout["strtab"], 0, 0)
    sections += sh(".shstrtab", 3, *layout["shstrtab"], 0, 0)

    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8,
        3, 0xB7, 1, 0, 0, shoff, 0, ehsize, 0, 0, 64,
        len(names) + 1, idx[".shstrtab"])
    body = dynsym + dynstr
    if symtab_names:
        body += symtab + strtab
    body += shstrtab
    return header + body + sections + extra


BOX2D_SYMBOLS = [
    "_ZN5b2World6StepExfi",
    "_ZN5b2Body13CreateFixtureEv",
    "_ZN9b2Fixture8GetShapeEv",
    "_ZN6b2Joint6CreateEPv",
    "plain_helper",
]


def _apk(tmp_path, name, members):
    path = tmp_path / name
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for member, data in members:
            zf.writestr(member, data)
    path.write_bytes(buf.getvalue())
    return path


# ------------------------------------------------------- physics channels

def test_physics_symtab_only_box2d():
    """Box2D symbols living only in SHT_SYMTAB (dynsym
    tokenless) are still detected, with the symtab channel
    named in evidence_sources."""
    so = _elf64(dynsym_names=["plain_helper"],
                symtab_names=BOX2D_SYMBOLS)
    rigs, _groups = anim.detect_physics(
        [("lib/arm64-v8a/libgame.so", so)], [])
    box2d = [r for r in rigs if r["family"] == "box2d"]
    assert len(box2d) == 1
    rig = box2d[0]
    assert rig["engine_guess"] == "Box2D"
    assert rig["symbol_count"] >= 3
    assert "symtab" in rig["evidence_sources"]


def test_physics_strings_only_box2d():
    """No matching symbols anywhere; >= 3 distinct Box2D
    tokens present as raw strings in the library bytes."""
    extra = (b"b2World\x00b2Body\x00b2Fixture\x00"
             b"b2PolygonShape\x00unrelated string\x00")
    so = _elf64(dynsym_names=["plain_helper"], extra=extra)
    rigs, _groups = anim.detect_physics(
        [("lib/arm64-v8a/libgame.so", so)], [])
    box2d = [r for r in rigs if r["family"] == "box2d"]
    assert len(box2d) == 1
    rig = box2d[0]
    assert "strings" in rig["evidence_sources"]
    assert "dynsym" not in rig["evidence_sources"]
    assert "b2World" in rig["string_tokens"]
    assert len(rig["string_tokens"]) >= 3


def test_native_end_to_end_symtab_box2d(tmp_path, capsys):
    """nar-native on an APK whose library carries symtab-only
    Box2D: report-level physics_detections + per-library
    physics_families label + a human() line."""
    so = _elf64(dynsym_names=["plain_helper"],
                symtab_names=BOX2D_SYMBOLS)
    apk = _apk(tmp_path, "phys.apk", [
        ("lib/arm64-v8a/libgame.so", so),
        ("classes.dex", b"dex\n039\x00" + b"\x00" * 64),
    ])
    report = NATIVE.analyze(str(apk))
    detections = report["physics_detections"]
    box2d = [d for d in detections if d["family"] == "box2d"]
    assert len(box2d) == 1
    det = box2d[0]
    assert det["engine_guess"] == "Box2D"
    assert det["confidence"] == "inferred"
    assert det["symbol_count"] >= 3
    assert "symtab" in det["evidence_sources"]
    assert det["libraries"] == ["arm64-v8a/libgame.so"]
    lib = report["libraries"][0]
    assert "box2d" in lib["physics_families"]
    NATIVE.human(report)
    out = capsys.readouterr().out
    assert "Box2D" in out


# ------------------------------------------------------- dev artifacts

PO_CONTENT = (
    'msgid ""\nmsgstr ""\n'
    '"Content-Type: text/plain; charset=UTF-8\\n"\n\n'
    '#: src/game/level.cpp:12\n'
    '#: src/ui/menu.cpp:3\n'
    'msgid "Start"\nmsgstr "Start"\n'
).encode()

RUBE_SCENE = json.dumps({
    "body": [{"name": "hero",
              "fixture": [{"density": 1.0}]}],
    "joint": [{"type": "revolute"}],
    "image": [],
}).encode()

EMBEDDED_SOURCE_PATH = b"/home/dev/work/project/src/engine/render.cpp"


def _dev_apk(tmp_path):
    so = _elf64(dynsym_names=["plain_helper"],
                extra=EMBEDDED_SOURCE_PATH + b"\x00")
    return _apk(tmp_path, "dev.apk", [
        ("assets/locale/messages.po", PO_CONTENT),
        ("assets/scenes/level1.json", RUBE_SCENE),
        ("lib/arm64-v8a/libgame.so", so),
        ("classes.dex", b"dex\n039\x00" + b"\x00" * 64),
    ])


def test_development_artifacts(tmp_path, capsys):
    apk = _dev_apk(tmp_path)
    for kwargs in ({}, {"merge_splits": False}):
        report = ASSETS.inventory(str(apk), **kwargs)
        po = [a for a in report["assets"]
              if a["path"].endswith(".po")]
        assert len(po) == 1
        assert po[0]["type"] == "gettext-po"
        dev = report["development_artifacts"]
        assert "assets/locale/messages.po" in \
            dev["gettext_files"]
        refs = dev["source_path_references"]
        assert refs["count"] >= 1
        assert any("src/" in ex and ex.endswith(
            (".cpp", ".c", ".h", ".java", ".kt"))
            for ex in refs["examples"])
        assert dev["rube_scenes"] == [{
            "member": "assets/scenes/level1.json",
            "marker": "rube-physics-scene"}]
        assert dev["counts"]["gettext_files"] == 1
        assert dev["counts"]["rube_scenes"] == 1
        assert dev["counts"]["source_path_references"] == \
            refs["count"]
    report = ASSETS.inventory(str(apk))
    ASSETS.human(report)
    out = capsys.readouterr().out
    assert "Development artifacts" in out


def test_negative_control_clean_apk(tmp_path):
    so = _elf64(dynsym_names=["plain_helper"])
    apk = _apk(tmp_path, "clean.apk", [
        ("assets/data.json", b'{"a": 1}'),
        ("assets/readme.txt", b"hello world\n"),
        ("lib/arm64-v8a/libgame.so", so),
        ("classes.dex", b"dex\n039\x00" + b"\x00" * 64),
    ])
    assets_report = ASSETS.inventory(str(apk))
    dev = assets_report["development_artifacts"]
    assert dev["gettext_files"] == []
    assert dev["source_path_references"] == \
        {"count": 0, "examples": []}
    assert dev["rube_scenes"] == []
    assert dev["counts"] == {"gettext_files": 0,
                              "source_path_references": 0,
                              "rube_scenes": 0}
    native_report = NATIVE.analyze(str(apk))
    assert native_report["physics_detections"] == []
    assert "physics_families" not in \
        native_report["libraries"][0]
