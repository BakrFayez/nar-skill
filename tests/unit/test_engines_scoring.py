"""Regression tests: nar-engines scoring of unique payload names.

A single engine-unique payload (a compiled Ren'Py script, an
RPG Maker core runtime script) must score as STRONG evidence:
previously these markers were scored as weak path hints
(25 + 2 = 27, below the 40 detection threshold), so the engines
verdict reported "not detected" for packages whose only — and
conclusive — evidence was that one file, while nar-triage did
report the hint.
Synthetic inputs only: no external fixtures, no app data.
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


def _verdicts(apk):
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / "nar-engines.py"),
         str(apk), "--json"],
        capture_output=True, text=True, timeout=300)
    data = json.loads(proc.stdout)
    return {v["engine"]: v for v in data.get("verdicts") or []}


def test_renpy_rpyc_detected(tmp_path):
    apk = _apk(tmp_path, "renpy.apk", [
        ("assets/game/script.rpyc", b"RENPY RPC2"),
        ("classes.dex", b"dex\n039\x00"),
    ])
    verdicts = _verdicts(apk)
    assert verdicts["Ren'Py"]["detected"] is True


def test_rpgmaker_core_detected(tmp_path):
    apk = _apk(tmp_path, "rpg.apk", [
        ("assets/www/js/rpg_core.js", b"// RPG Maker MV"),
        ("classes.dex", b"dex\n039\x00"),
    ])
    verdicts = _verdicts(apk)
    assert verdicts["RPG Maker (web export)"]["detected"] is True


def test_generic_www_stays_undetected(tmp_path):
    apk = _apk(tmp_path, "plain.apk", [
        ("assets/www/js/app.js", b"// generic web app"),
        ("classes.dex", b"dex\n039\x00"),
    ])
    verdicts = _verdicts(apk)
    assert verdicts["Web assets (assets/www)"]["detected"] is False
