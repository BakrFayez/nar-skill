"""Phase 2 fix round (M2-02, pipeline routing): nar-analyze
hands nar-il2cpp the container target itself when the
IL2CPP pair is split across merged members.

Before the fix, the stage received the single root that
carries libil2cpp.so; the global-metadata.dat living in a
sibling asset-pack split was invisible to that call, and
the stage ended degraded on exactly the targets whose pair
is split. The synthetic container below mirrors that
shape: the native library in the base member, the metadata
in an asset-pack member.
"""
import io
import json
import os
import struct
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
SCRIPTS = os.path.join(ROOT, "scripts")


def _zip_bytes(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def _metadata_bytes(version=29):
    return struct.pack("<II", 0xFAB11BAF, version) + b"\x00" * 64


def _split_pair_xapk(tmp_path):
    base = _zip_bytes([
        ("AndroidManifest.xml", b"<manifest/>"),
        ("lib/arm64-v8a/libil2cpp.so", b"\x7fELF" + b"\x00" * 60)])
    pack = _zip_bytes([
        ("assets/bin/Data/Managed/Metadata/global-metadata.dat",
         _metadata_bytes())])
    manifest = {"package_name": "com.example.game",
                "split_apks": [
                    {"file": "com.example.game.apk", "id": "base"},
                    {"file": "asset_pack.apk", "id": "asset_pack"}]}
    path = tmp_path / "set.xapk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("manifest.json", json.dumps(manifest))
        zf.writestr("com.example.game.apk", base)
        zf.writestr("asset_pack.apk", pack)
    return str(path)


def test_analyze_il2cpp_stage_spans_split_pair(tmp_path):
    target = _split_pair_xapk(tmp_path)
    out = tmp_path / "case"
    proc = subprocess.run(
        [sys.executable, os.path.join(SCRIPTS, "nar-analyze.py"),
         target, "--out", str(out)],
        capture_output=True, text=True, timeout=900)
    assert proc.returncode == 0, proc.stderr[-500:]
    with open(out / "case.json", encoding="utf-8") as fh:
        case = json.load(fh)
    stage = (case.get("stages") or {}).get("nar-il2cpp.py") or {}
    assert stage.get("status") == "ok", stage
    with open(out / "report.json", encoding="utf-8") as fh:
        report = json.load(fh)
    section = (report.get("engines") or {}).get("unity_il2cpp") or {}
    assert section.get("is_il2cpp") is True, section
    assert (section.get("metadata") or {}).get("version") == 29
