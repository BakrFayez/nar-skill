"""Regression tests: bundletool .apks sets are containers.

An .apks file (ZIP of split APKs under splits/, plus toc.pb)
was classified as a plain APK: triage reported no container,
nar-analyze triaged the ZIP itself and produced an empty
identity with no steps on any real APK. XAPK/APKM sets already
routed through the container path; .apks now does too, and the
base pick prefers the canonical base-master.apk over a merely
larger sibling.
Synthetic inputs only: no external fixtures, no app data.
"""
import importlib.util
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))

_spec = importlib.util.spec_from_file_location(
    "nar_analyze", SCRIPTS / "nar-analyze.py")
nar_analyze = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nar_analyze)


def _zip(tmp_path, name, members):
    path = tmp_path / name
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for member, data in members:
            zf.writestr(member, data)
    path.write_bytes(buf.getvalue())
    return path


def _triage(apk):
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / "nar-triage.py"),
         str(apk), "--json"],
        capture_output=True, text=True, timeout=120)
    return json.loads(proc.stdout)


def test_apks_classified_as_container(tmp_path):
    apks = _zip(tmp_path, "set.apks", [
        ("toc.pb", b"\x00"),
        ("splits/base-master.apk", b"PK\x03\x04"),
        ("splits/split_config.en.apk", b"PK\x03\x04"),
    ])
    data = _triage(apks)
    assert data["is_apks"] is True
    assert data["is_container"] is True
    names = [c["name"] for c in data["contained_apks"]]
    assert "splits/base-master.apk" in names


def test_xapk_still_container_not_apks(tmp_path):
    xapk = _zip(tmp_path, "set.xapk", [
        ("manifest.json", b"{}"),
        ("com.example.app.apk", b"PK\x03\x04"),
    ])
    data = _triage(xapk)
    assert data["is_container"] is True
    assert data["is_apks"] is False


def test_pick_base_prefers_base_master_over_larger_sibling():
    triage = {"contained_apks": [
        {"name": "splits/base-master.apk", "size_bytes": 100},
        {"name": "splits/base-master_2.apk", "size_bytes": 200},
        {"name": "splits/split_config.en.apk", "size_bytes": 300},
    ], "container_manifest": None}
    names = [c["name"] for c in triage["contained_apks"]]
    assert nar_analyze.pick_base_apk(triage, names) == \
        "splits/base-master.apk"


def test_pick_base_package_name_still_wins():
    triage = {"contained_apks": [
        {"name": "splits/base-master.apk", "size_bytes": 100},
        {"name": "com.example.app.apk", "size_bytes": 50},
    ], "container_manifest": {"package": "com.example.app"}}
    names = [c["name"] for c in triage["contained_apks"]]
    assert nar_analyze.pick_base_apk(triage, names) == \
        "com.example.app.apk"
