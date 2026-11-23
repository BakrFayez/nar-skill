"""Unit tests for nar-il2cpp.py pair location / found reporting.

Regression coverage: for a ZIP target holding only ONE half of
the IL2CPP pair (the split-APK layout: metadata in the base,
libil2cpp.so in a config split), the report's "found" flags must
name the piece that is actually present. Previously the flags
were derived from the extraction paths, which are only set when
both entries exist, so a lone libil2cpp.so reported
found={metadata: False, binary: False}.
Synthetic inputs only: no external fixtures, no app data.
"""
import importlib.util
import io
import struct
import sys
import zipfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))

_spec = importlib.util.spec_from_file_location(
    "nar_il2cpp", SCRIPTS / "nar-il2cpp.py")
nar_il2cpp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nar_il2cpp)

META = "assets/bin/Data/Managed/Metadata/global-metadata.dat"
SO = "lib/arm64-v8a/libil2cpp.so"


def _zip_bytes(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def _metadata_blob():
    return struct.pack("<II", 0xFAB11BAF, 31) + b"\x00" * 64


def test_found_binary_only(tmp_path):
    apk = tmp_path / "config.apk"
    apk.write_bytes(_zip_bytes([(SO, b"\x7fELF" + b"\x00" * 60)]))
    report = nar_il2cpp.analyze(str(apk), str(tmp_path / "out"))
    assert report["is_il2cpp"] is False
    assert report["found"] == {"metadata": False, "binary": True}


def test_found_metadata_only(tmp_path):
    apk = tmp_path / "base.apk"
    apk.write_bytes(_zip_bytes([(META, _metadata_blob())]))
    report = nar_il2cpp.analyze(str(apk), str(tmp_path / "out"))
    assert report["is_il2cpp"] is False
    assert report["found"] == {"metadata": True, "binary": False}


def test_found_neither(tmp_path):
    apk = tmp_path / "plain.apk"
    apk.write_bytes(_zip_bytes([("classes.dex", b"dex\n039\x00")]))
    report = nar_il2cpp.analyze(str(apk), str(tmp_path / "out"))
    assert report["found"] == {"metadata": False, "binary": False}
