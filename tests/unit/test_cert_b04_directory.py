"""Regression tests: certification finding B-04 (Confirmed Bug, P3).

The ten engine deep-dive tools (nar-atlas, nar-bevy, nar-cocos,
nar-ebiten, nar-libgdx, nar-mono, nar-monogame, nar-python,
nar-sdl, nar-xamarin) accepted a DIRECTORY target and exited 0
with an empty inventory / "Verdict: absent". A directory was
never scanned, so "absent" is unsupported for that input. The
surface norm (nar-dex, nar-native, nar-assets, ...) is exit 2
with a named not-a-file boundary:

    nar-<tool>: is a directory: <target>

pinned here for every one of the ten tools, in text and --json
modes. The same tools' exit-0 "absent" verdict on a
random-bytes FILE is a defensible detector answer and must
keep working; that is pinned too for a representative subset.
"""
import os
import random
import subprocess
import sys

import pytest

ROOT = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", ".."))
SCRIPTS = os.path.join(ROOT, "scripts")

TOOLS = ["atlas", "bevy", "cocos", "ebiten", "libgdx", "mono",
         "monogame", "python", "sdl", "xamarin"]

# Representative subset whose text output carries the literal
# "Verdict: absent" line on a non-matching file.
ABSENT_VERDICT_TOOLS = ["bevy", "cocos", "python", "sdl"]


def _run(tool, target, *extra):
    return subprocess.run(
        [sys.executable,
         os.path.join(SCRIPTS, f"nar-{tool}.py"),
         str(target), *extra],
        capture_output=True, text=True, timeout=300)


def _assert_directory_boundary(tool, proc):
    assert proc.returncode == 2, (
        tool, proc.returncode, proc.stdout, proc.stderr)
    # Named not-a-file boundary, matching the sibling tools
    # (nar-dex / nar-native / nar-assets): the tool names
    # itself and states the target is a directory.
    assert f"nar-{tool}: is a directory:" in proc.stderr, (
        tool, proc.stderr)
    assert "Traceback" not in proc.stderr
    assert "Traceback" not in proc.stdout
    # No unsupported "absent" verdict may be emitted.
    assert "Verdict: absent" not in proc.stdout


@pytest.mark.parametrize("tool", TOOLS)
def test_directory_target_text_mode(tool, tmp_path):
    target = tmp_path / "a_directory"
    target.mkdir()
    _assert_directory_boundary(tool, _run(tool, target))


@pytest.mark.parametrize("tool", TOOLS)
def test_directory_target_json_mode(tool, tmp_path):
    target = tmp_path / "a_directory"
    target.mkdir()
    _assert_directory_boundary(tool, _run(tool, target, "--json"))


@pytest.fixture(scope="module")
def random_bytes_file(tmp_path_factory):
    path = tmp_path_factory.mktemp("b04") / "random.bin"
    rng = random.Random(20261126)
    path.write_bytes(
        b"\x89NAR-random-not-a-container\x00"
        + bytes(rng.getrandbits(8) for _ in range(4096)))
    return path


@pytest.mark.parametrize("tool", ABSENT_VERDICT_TOOLS)
def test_random_bytes_file_still_absent(tool, random_bytes_file):
    proc = _run(tool, random_bytes_file)
    assert proc.returncode == 0, (tool, proc.stderr)
    assert "Verdict: absent" in proc.stdout, (tool, proc.stdout)
    assert "Traceback" not in proc.stderr


def test_random_bytes_file_atlas_still_empty_inventory(
        random_bytes_file):
    proc = _run("atlas", random_bytes_file)
    assert proc.returncode == 0, proc.stderr
    assert "Atlases: 0" in proc.stdout, proc.stdout
    assert "Traceback" not in proc.stderr
