"""Unit tests: no hardcoded real targets (Part 16.3).

Greps scripts/ (Python + JSON, formats.json included),
references/, schemas/ and tests/ for real package/game identifiers
and fails on any hit. The banned strings are built from
parts so this guard file never contains them literally.
No pre-existing guard test covered this list (the Phase 0
verification ran the grep by hand); this test makes it a
standing CI guard.
"""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Built from parts on purpose (see module docstring).
BANNED = [
    "com." + "fingersoft",
    "hill" + "climb",
    "hill " + "climb " + "racing",
    "spi" + "xel",
]

SCAN_DIRS = ["scripts", "references", "schemas", "tests"]
SUFFIXES = (".py", ".json", ".md", ".sh")


def _hits():
    found = []
    for rel in SCAN_DIRS:
        base = ROOT / rel
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames
                           if d != "__pycache__"]
            for name in filenames:
                if not name.endswith(SUFFIXES):
                    continue
                path = Path(dirpath) / name
                text = path.read_text(
                    encoding="utf-8", errors="ignore").lower()
                for banned in BANNED:
                    if banned in text:
                        found.append(
                            f"{path.relative_to(ROOT)}: {banned!r}")
    return found


def test_no_hardcoded_target_identifiers():
    assert _hits() == []
