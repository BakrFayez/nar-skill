"""Certification B-02 (Accuracy Defect, P2): nar-input validate
must not vacuously pass an unidentifiable file.

Before the fix, `validate --json` on random bytes, an empty
file, or random bytes named *.apk returned format "unknown",
valid=true, empty notes, exit 0 — nothing was validated, yet
the verdict asserted validity. Validation must judge real
container structure, not names or emptiness: when no format
is identified, validate returns valid=false with a note
naming that no format was identified, and a nonzero exit.

Controls that must keep their behaviour: a valid container
passes (valid=true, exit 0), a truncated real container
fails (valid=false, exit 1), and `identify` on an unknown
file still answers "unknown" with exit 0 (that honest answer
is not part of this defect).
"""
import json
import random
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NAR_INPUT = ROOT / "scripts" / "nar-input.py"


def _run(*args):
    return subprocess.run(
        [sys.executable, str(NAR_INPUT), *args],
        capture_output=True, text=True, timeout=120)


def _validate_json(path):
    proc = _run("validate", "--json", str(path))
    assert proc.stdout.strip(), proc.stderr
    return proc, json.loads(proc.stdout)


def _random_bytes(n=4096):
    # Deterministic "random" bytes: no known signature at the
    # head and no pak footer magic in the tail.
    return random.Random(20261126).randbytes(n)


def _assert_unidentifiable(path):
    proc, data = _validate_json(path)
    assert data["format"] == "unknown"
    assert data["valid"] is False
    assert proc.returncode != 0
    notes = " ".join(data["notes"]).lower()
    assert "unidentifiable" in notes
    assert "no format was identified" in notes


def _write_valid_apk(path):
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 100)
        zf.writestr("resources.arsc", b"\x02\x00")
    return path


def test_validate_random_bytes_fails_unidentifiable(tmp_path):
    target = tmp_path / "blob.bin"
    target.write_bytes(_random_bytes())
    _assert_unidentifiable(target)


def test_validate_empty_file_fails_unidentifiable(tmp_path):
    target = tmp_path / "empty.bin"
    target.write_bytes(b"")
    _assert_unidentifiable(target)


def test_validate_random_bytes_named_apk_fails_unidentifiable(tmp_path):
    target = tmp_path / "fake.apk"
    target.write_bytes(_random_bytes())
    _assert_unidentifiable(target)


def test_validate_valid_container_still_passes(tmp_path):
    apk = _write_valid_apk(tmp_path / "real.apk")
    proc, data = _validate_json(apk)
    assert data["format"] == "apk"
    assert data["valid"] is True
    assert proc.returncode == 0


def test_validate_truncated_real_container_still_fails(tmp_path):
    apk = _write_valid_apk(tmp_path / "real.apk")
    blob = apk.read_bytes()
    truncated = tmp_path / "truncated.apk"
    truncated.write_bytes(blob[: len(blob) // 2])
    proc, data = _validate_json(truncated)
    assert data["valid"] is False
    assert data["notes"]
    assert proc.returncode == 1


def test_identify_unknown_still_exit_zero(tmp_path):
    target = tmp_path / "blob.bin"
    target.write_bytes(_random_bytes())
    proc = _run("identify", "--json", str(target))
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["format"] == "unknown"
