"""Certification regression tests for nar-fingerprint.py.

Wave 1 of the 3.0.1 certification fix round:

- B-06 (Confirmed Bug, P3): a directory (or nonexistent)
  target exited 2 but blamed a JSON decode error read off
  the triage subprocess's empty stdout ("Expecting value:
  line 1 column 1 (char 0)") instead of the real boundary:
  the target is not a file. The error must name the input
  problem.
- A2-07 (Accuracy Defect, P3): an unparseable target
  (8 KiB of random bytes) produced a fingerprint whose null
  core fields (dex_count, dex_versions, ...) were labelled
  "confidence high; observed; verification CONFIRMED" --
  the strongest verification label on a null parse. A null
  value is the absence of an observation and must be
  labelled unknown / UNVERIFIED, never CONFIRMED/high.
  Genuinely parsed targets keep their normal labels.
"""
import json
import os
import random
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]
FINGERPRINT = ROOT / "scripts" / "nar-fingerprint.py"


def run_fingerprint(target, *extra):
    return subprocess.run(
        [sys.executable, str(FINGERPRINT), str(target), *extra],
        capture_output=True, text=True, timeout=600)


def demo_apk():
    fixtures = os.environ.get(
        "NAR_FIXTURES",
        os.path.expanduser("~/workspace/nar-e2e-fixtures"))
    return Path(fixtures) / "demo" / "NarDemo.apk"


# ---------------------------------------------------- B-06

def test_b06_directory_target_names_input_problem(tmp_path):
    proc = run_fingerprint(tmp_path)
    assert proc.returncode == 2
    err = proc.stderr
    assert "not a file" in err
    assert "Expecting value" not in err
    assert "json" not in err.lower()


def test_b06_nonexistent_target_names_input_problem(tmp_path):
    proc = run_fingerprint(tmp_path / "missing.apk")
    assert proc.returncode == 2
    err = proc.stderr
    assert ("not a file" in err) or ("not found" in err)
    assert "Expecting value" not in err
    assert "json" not in err.lower()


# ---------------------------------------------------- A2-07

def test_a207_null_parse_never_confirmed_or_high(tmp_path):
    blob = tmp_path / "blob.bin"
    blob.write_bytes(random.Random(20261126).randbytes(8192))
    proc = run_fingerprint(blob, "--json")
    assert proc.returncode == 0, proc.stderr
    fp = json.loads(proc.stdout)
    props = fp["properties"]
    # Precondition: the container did not parse, so the core
    # DEX fields really are null in this fingerprint.
    assert props["dex_count"]["value"] is None
    assert props["dex_versions"]["value"] is None
    for name in ("dex_count", "dex_versions"):
        p = props[name]
        assert p["verification_status"] != "CONFIRMED", name
        assert p["verification_status"] == "UNVERIFIED", name
        assert p["confidence"] != "high", name
    # No null-valued property anywhere may carry the
    # strongest labels.
    for name, p in props.items():
        if p["value"] is None:
            assert p["verification_status"] != "CONFIRMED", name
            assert p["confidence"] != "high", name


def test_a207_valid_fixture_keeps_normal_labels():
    demo = demo_apk()
    if not demo.is_file():
        pytest.skip("demo fixture absent")
    proc = run_fingerprint(demo, "--json")
    assert proc.returncode == 0, proc.stderr
    fp = json.loads(proc.stdout)
    dex = fp["properties"]["dex_count"]
    assert isinstance(dex["value"], int) and dex["value"] >= 1
    assert dex["confidence"] == "high"
    assert dex["fact_class"] == "observed"
    assert dex["verification_status"] == "CONFIRMED"
