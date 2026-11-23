"""Regression tests: legacy Cordova / PhoneGap runtime filenames.

Pre-3.0 Cordova shipped its runtime as assets/www/cordova-<ver>.js
(and PhoneGap as phonegap-<ver>.js / phonegap.js). nar-triage's
engine signature only listed the modern exact name cordova.js,
so a legacy hybrid app produced no Cordova hint at all and
nar-engines scored it "not detected" despite the DEX marker.
Synthetic zips only: no external fixtures, no app data.
"""
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"


def _apk(tmp_path, name, members):
    path = tmp_path / name
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for member, data in members:
            zf.writestr(member, data)
    path.write_bytes(buf.getvalue())
    return path


def _hints(apk):
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / "nar-triage.py"),
         str(apk), "--json"],
        capture_output=True, text=True, timeout=120)
    data = json.loads(proc.stdout)
    return {h["engine"] for h in data.get("engine_hints") or []}


def test_versioned_cordova_runtime_detected(tmp_path):
    apk = _apk(tmp_path, "legacy.apk", [
        ("assets/www/cordova-2.5.0.js", b"// cordova"),
        ("assets/www/index.html", b"<html></html>"),
    ])
    assert "Cordova (hybrid)" in _hints(apk)


def test_phonegap_runtime_detected(tmp_path):
    apk = _apk(tmp_path, "phonegap.apk", [
        ("assets/www/phonegap-1.4.1.js", b"// phonegap"),
        ("assets/www/index.html", b"<html></html>"),
    ])
    assert "Cordova (hybrid)" in _hints(apk)


def test_modern_cordova_still_detected(tmp_path):
    apk = _apk(tmp_path, "modern.apk", [
        ("assets/www/cordova.js", b"// cordova"),
        ("assets/www/index.html", b"<html></html>"),
    ])
    assert "Cordova (hybrid)" in _hints(apk)


def test_unrelated_www_content_not_cordova(tmp_path):
    apk = _apk(tmp_path, "plain.apk", [
        ("assets/www/cordova-notes.txt", b"release notes"),
        ("assets/www/index.html", b"<html></html>"),
    ])
    assert "Cordova (hybrid)" not in _hints(apk)
