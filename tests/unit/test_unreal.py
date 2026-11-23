"""nar-unreal presentation tests on synthetic IoStore
containers (builders imported from test_iostore, the
same pattern the e2e harness uses).

Covered here: a UE5 IoStore-native (Zen) package chunk
— package magic as a trailer, Zen header first — is
identified as a Zen package in the container package
report instead of being fed to the classic
FPackageFileSummary parser, which would misreport it
as a corrupt package.
"""
import json
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parents[2] / "scripts"))

import test_iostore  # noqa: E402

PACKAGE_MAGIC_LE = b"\xc1\x83\x2a\x9e"

# Minimal Zen-shaped chunk: header-size field at +4,
# filler where the rest of the Zen header and the
# package body would sit, package magic as the last
# four bytes (the trailer trait).
ZEN_CHUNK = (b"\x00\x00\x00\x00" + struct.pack("<I", 64)
             + b"zen synthetic payload " * 3
             + PACKAGE_MAGIC_LE)


def test_iostore_zen_package_identified(tmp_path):
    utoc, ucas = test_iostore.build_current(chunk_a=ZEN_CHUNK)
    (tmp_path / "case.utoc").write_bytes(utoc)
    (tmp_path / "case.ucas").write_bytes(ucas)
    script = HERE.parents[2] / "scripts" / "nar-unreal.py"
    proc = subprocess.run(
        [sys.executable, str(script),
         str(tmp_path / "case.utoc"), "--json"],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    packages = report["iostore_packages"]
    assert len(packages) == 1
    record = packages[0]
    assert record["entry"].endswith("Content/ChunkA.uasset")
    assert record["format"] == "zen-package"
    assert record["size"] == len(ZEN_CHUNK)
    assert record["zen_header_size"] == 64
    assert "error" not in record
