"""Certification B-01 regression: directory targets for
nar-unity / nar-unreal.

Confirmed Bug (P2, Phase 1 audit ANNEX_B B-01): both CLIs
crashed with an unhandled IsADirectoryError traceback
(exit 1) when handed a directory, in text and --json
modes. Root cause: each tool's analyze() calls the shared
narlib hashing helper (sha256_of) on the target before
any is-a-file guard, and main() did not catch
IsADirectoryError.

Every sibling CLI (nar-dex, nar-native, nar-assets --
fixed in commit 5700fc9) rejects a directory with a named
error on stderr and exit 2, in BOTH modes (the guard runs
before the --json branch, so no JSON is emitted). These
tests pin nar-unity and nar-unreal to that exact
established behaviour.
"""
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"

TOOLS = ["nar-unity.py", "nar-unreal.py"]


def _run_cli(script, target, *extra):
    return subprocess.run(
        [sys.executable, str(SCRIPTS / script), str(target),
         *extra],
        capture_output=True, text=True, timeout=300)


@pytest.mark.parametrize("script", TOOLS)
@pytest.mark.parametrize("extra", [[], ["--json"]],
                         ids=["text", "json"])
def test_directory_target_is_named_exit2_no_traceback(
        script, extra, tmp_path):
    target_dir = tmp_path / "a_directory"
    target_dir.mkdir()
    proc = _run_cli(script, target_dir, *extra)
    combined = proc.stdout + proc.stderr
    assert proc.returncode == 2, (script, extra, proc.returncode,
                                  combined)
    assert "Traceback" not in combined
    # Named not-a-file / is-a-directory boundary, matching
    # the sibling tools' exact wording:
    # "nar-<tool>: is a directory: <target>".
    tool_name = script[:-3]  # strip ".py"
    assert f"{tool_name}: is a directory:" in proc.stderr
    assert str(target_dir) in proc.stderr
