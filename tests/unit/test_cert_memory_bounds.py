"""Certification D-01 — automated peak-memory proof.

The Phase 1 audit (finding D-01) found that every huge-input
proof in this suite worked by shrinking a cap constant and
asserting refusal, while the headline peak-RSS figures were
manual records only: a parser quietly returning to whole-blob
reads UNDER its cap would fail no test. These tests close
that gap. Each one runs a heavy parsing path in a fresh
subprocess on an adversarial oversized input and asserts the
child process tree's peak RSS (resource.getrusage
RUSAGE_CHILDREN ru_maxrss, which the kernel reports as the
largest waited-for process peak in the tree) stays within a
stated bound, AND that the resource cap fires BY NAME where
a cap is the defence.

How the bounds were set (measured 2026-11-26 on this tree,
1.5-CPU shared VM, python 3.12 venv interpreter):

- A bare interpreter importing narlib peaks at ~13 MB; the
  nar-unity CLI (which also spawns its triage child) peaks
  at ~48 MB on a refused input. The sharp bound used for
  the small-input parser tests is therefore 96 MiB: roughly
  2-7x the measured refusal-path peak, and far below the
  whole-blob signature each test discriminates against
  (stated per test).
- nar-unity on a 320 MiB bundle member, BEFORE the A2-02
  fix: 979.2 MB peak. After the fix (member read cap):
  47.5 MB. Bound: 160 MiB.
- nar-dex on a 320 MiB declared dex member: 21.1 MB peak,
  cap refusal by name. Bound: 96 MiB.
- The .NET metadata reader's defence IS its 512 MiB
  structural-read cap (audit A1-07: cap-bounded whole-file
  read, accepted as the bound). Reading a sparse file one
  byte over the cap peaked at ~528 MB (the cap plus the
  interpreter baseline). Bound: 768 MiB, plus a named
  DotNetMetaError; a second run under a reduced cap proves
  the read is governed by the cap value itself.
- Largest retained fixture (the biggest file under
  $NAR_FIXTURES, 261 MB at measurement time): nar-dex tree
  peak 980.5 MB, nar-native 191.8 MB, nar-unity 922.6 MB
  (its IL2CPP sub-stage measured 913.9 MB and 1132 MB
  standalone across two runs — the recovered-program
  working set, not a member read). Envelope bounds are set
  at roughly 1.5x the highest measured peak per stage:
  dex 1536 MiB, native 512 MiB, unity 1792 MiB. These are
  regression envelopes, not tightness claims: a return to
  unbounded reads on hostile members is caught by the
  sharp tests above, and a blow-up beyond the recorded
  envelope on real input fails here.
- nar-analyze on the synthetic oversized container:
  65.1 MB tree peak. Bound: 256 MiB.

ru_maxrss is Linux/macOS semantics; on platforms without
it these tests skip rather than guess.
"""
import io
import json
import os
import random
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
FIXTURES = os.environ.get(
    "NAR_FIXTURES",
    os.path.expanduser("~/workspace/nar-e2e-fixtures"))

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="peak-RSS proof uses POSIX rusage semantics")

MIB = 1024 * 1024

# Sharp bound for refusal-path parser tests (see docstring).
SHARP_BOUND_MB = 96
# nar-unity CLI refusal path (spawns a triage child).
UNITY_BOUND_MB = 160
# dotnetmeta: the 512 MiB cap plus baseline and slack.
DOTNET_BOUND_MB = 768
# Largest-fixture envelopes (see docstring).
FIXTURE_BOUNDS_MB = {"nar-dex.py": 1536, "nar-native.py": 512,
                     "nar-unity.py": 1792}
ANALYZE_BOUND_MB = 256


_RUNNER = r"""
import json, resource, subprocess, sys
spec = json.loads(sys.argv[1])
out_path = spec.get("stdout_path")
try:
    if out_path:
        with open(out_path, "wb") as fh:
            proc = subprocess.run(spec["cmd"], stdout=fh,
                                  stderr=subprocess.PIPE,
                                  timeout=spec["timeout"])
        out = b""
        err = proc.stderr
    else:
        proc = subprocess.run(spec["cmd"], capture_output=True,
                              timeout=spec["timeout"])
        out, err = proc.stdout, proc.stderr
    rc = proc.returncode
except subprocess.TimeoutExpired:
    print(json.dumps({"timeout": True}))
    sys.exit(0)
peak_kb = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
print(json.dumps({
    "rc": rc, "peak_mb": peak_kb / 1024.0,
    "out": out.decode("utf-8", "replace")[-4000:],
    "err": err.decode("utf-8", "replace")[-2000:]}))
"""


def _run_peak(cmd, timeout=600, stdout_path=None):
    """Run cmd under a fresh intermediate process and return
    {rc, peak_mb, out, err}: peak_mb is the largest process
    peak in the child's waited-for tree."""
    spec = {"cmd": [str(c) for c in cmd], "timeout": timeout,
            "stdout_path": str(stdout_path) if stdout_path else None}
    proc = subprocess.run(
        [sys.executable, "-c", _RUNNER, json.dumps(spec)],
        capture_output=True, text=True, timeout=timeout + 120)
    result = json.loads(proc.stdout.strip().splitlines()[-1])
    assert "timeout" not in result, f"child timed out: {cmd}"
    return result


def _run_snippet(snippet, timeout=600):
    return _run_peak([sys.executable, "-c", snippet],
                     timeout=timeout)


def _largest_fixture():
    """The largest retained fixture file (following links),
    or None when the private fixture tree is absent."""
    if not os.path.isdir(FIXTURES):
        return None
    best = None
    for dirpath, _dirs, names in os.walk(FIXTURES):
        for name in names:
            path = os.path.join(dirpath, name)
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if best is None or size > best[1]:
                best = (path, size)
    if best is None or best[1] < 16 * MIB:
        return None
    return best[0]


def _write_oversized_member_apk(path, member, size):
    """An APK-shaped zip whose one member decompresses to
    `size` bytes (a format-plausible head, then zeros) while
    the archive itself stays small on disk."""
    head = b"UnityFS\x00" + b"8\x00" + b"2021.3.1f1\x00" * 2
    if member.endswith(".dex"):
        head = b"dex\n039\x00"
    head = head + b"\x00" * (4096 - len(head))
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo(member)
        info.compress_type = zipfile.ZIP_DEFLATED
        with zf.open(info, "w", force_zip64=True) as fh:
            fh.write(head)
            remaining = size - len(head)
            chunk = b"\x00" * (1 << 20)
            while remaining > 0:
                n = min(remaining, len(chunk))
                fh.write(chunk[:n])
                remaining -= n
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
    return path


# ----------------------------------------------------------
# (b) DEX parser: absurd header counts fail fast, bounded
# ----------------------------------------------------------

_DEX_SNIPPET = r"""
import struct, sys
sys.path.insert(0, {scripts!r})
from narlib.dex import Dex, DexError

def uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        if n: out.append(b | 0x80)
        else: out.append(b); break
    return bytes(out)

# Header declares absurd counts for every table, tiny file.
out = bytearray(0x70)
out[0:8] = b"dex\n039\x00"
struct.pack_into("<I", out, 32, 0x70)
struct.pack_into("<I", out, 36, 0x70)
struct.pack_into("<I", out, 40, 0x12345678)
for off in (0x38, 0x40, 0x48, 0x50, 0x58, 0x60):
    struct.pack_into("<II", out, off, 0x3FFFFFFF, 0x70)
try:
    Dex(bytes(out), "absurd.dex")
    print("RESULT no-error")
except DexError as e:
    print("RESULT header:", e)

# Valid header, one class def whose class_data declares an
# absurd static-field count: the walk must fail fast on the
# buffer bound, never iterate the declared count.
hdr = 0x70
str_ids_off = hdr
sdata = uleb(5) + b"LFoo;" + b"\x00"
str_data_off = str_ids_off + 4
type_ids_off = str_data_off + len(sdata)
class_defs_off = type_ids_off + 4
class_data_off = class_defs_off + 32
cdata = uleb(0xFFFFFFFF) + uleb(0) + uleb(0) + uleb(0)
out = bytearray(class_data_off + len(cdata))
out[0:8] = b"dex\n039\x00"
struct.pack_into("<I", out, 32, len(out))
struct.pack_into("<I", out, 36, hdr)
struct.pack_into("<I", out, 40, 0x12345678)
struct.pack_into("<II", out, 0x38, 1, str_ids_off)
struct.pack_into("<II", out, 0x40, 1, type_ids_off)
struct.pack_into("<II", out, 0x60, 1, class_defs_off)
struct.pack_into("<I", out, str_ids_off, str_data_off)
out[str_data_off:str_data_off + len(sdata)] = sdata
struct.pack_into("<I", out, type_ids_off, 0)
struct.pack_into("<IIIIIIII", out, class_defs_off,
                 0, 0, 0xFFFFFFFF, 0, 0, 0, class_data_off, 0)
out[class_data_off:class_data_off + len(cdata)] = cdata
try:
    dex = Dex(bytes(out), "blast.dex")
    list(dex.class_fields(class_data_off))
    print("RESULT no-error")
except DexError as e:
    print("RESULT classdata:", e)
"""


def test_dex_absurd_counts_fail_fast_bounded():
    result = _run_snippet(_DEX_SNIPPET.format(scripts=str(SCRIPTS)))
    assert result["rc"] == 0, result["err"]
    assert "RESULT header:" in result["out"], result["out"]
    assert "extends past end of file" in result["out"]
    assert "RESULT classdata:" in result["out"], result["out"]
    assert "no-error" not in result["out"]
    assert result["peak_mb"] <= SHARP_BOUND_MB, result["peak_mb"]


def test_dex_tool_oversized_member_cap_by_name(tmp_path):
    """nar-dex on a container whose dex member declares
    320 MiB: the member read cap fires by name and the blob
    is never materialized (pre-cap behaviour peaked at the
    member size and beyond)."""
    apk = _write_oversized_member_apk(
        tmp_path / "hostile.apk", "classes.dex", 320 * MIB)
    out_path = tmp_path / "dex.json"
    result = _run_peak(
        [sys.executable, str(SCRIPTS / "nar-dex.py"),
         str(apk), "--json"],
        timeout=300, stdout_path=out_path)
    assert result["rc"] == 0, result["err"]
    doc = json.loads(out_path.read_text())
    errors = [f.get("error", "") for f in doc["dex_files"]]
    assert any("read cap" in e for e in errors), errors
    assert result["peak_mb"] <= SHARP_BOUND_MB, result["peak_mb"]


# ----------------------------------------------------------
# (c) ELF parser: absurd section / symbol counts
# ----------------------------------------------------------

_ELF_SNIPPET = r"""
import struct, sys
sys.path.insert(0, {scripts!r})
from narlib.elf import Elf, ElfError

def header(phnum, shnum):
    out = bytearray(64)
    out[0:4] = b"\x7fELF"; out[4] = 2; out[5] = 1
    struct.pack_into("<H", out, 16, 3)
    struct.pack_into("<H", out, 18, 183)
    struct.pack_into("<Q", out, 32, 64)
    struct.pack_into("<Q", out, 40, 64)
    struct.pack_into("<H", out, 52, 64)
    struct.pack_into("<H", out, 54, 56)
    struct.pack_into("<H", out, 56, phnum)
    struct.pack_into("<H", out, 58, 64)
    struct.pack_into("<H", out, 60, shnum)
    struct.pack_into("<H", out, 62, 0)
    return bytes(out)

for label, fn in (("sections", lambda e: e.sections()),
                  ("phdrs", lambda e: e.program_headers())):
    try:
        fn(Elf(header(0xFFFF, 0xFFFF), "absurd.so"))
        print("RESULT no-error", label)
    except ElfError as e:
        print("RESULT", label, ":", e)

# A symtab section declaring ~32 GiB of symbols in a
# 192-byte file: the section-data extent check fires.
out = bytearray(64 + 2 * 64)
out[0:4] = b"\x7fELF"; out[4] = 2; out[5] = 1
struct.pack_into("<H", out, 16, 3)
struct.pack_into("<H", out, 18, 183)
struct.pack_into("<Q", out, 40, 64)
struct.pack_into("<H", out, 52, 64)
struct.pack_into("<H", out, 58, 64)
struct.pack_into("<H", out, 60, 2)
struct.pack_into("<H", out, 62, 0)
struct.pack_into("<IIQQQQIIQQ", out, 128,
                 0, 2, 0, 0, 192, 0x7FFFFFFF0, 0, 0, 0, 24)
try:
    Elf(bytes(out), "symblast.so").symbols(2)
    print("RESULT no-error symtab")
except ElfError as e:
    print("RESULT symtab :", e)
"""


def test_elf_absurd_counts_fail_fast_bounded():
    result = _run_snippet(_ELF_SNIPPET.format(scripts=str(SCRIPTS)))
    assert result["rc"] == 0, result["err"]
    assert "RESULT sections :" in result["out"], result["out"]
    assert "RESULT phdrs :" in result["out"], result["out"]
    assert "RESULT symtab :" in result["out"], result["out"]
    assert "past end of file" in result["out"] or \
        "past the end of the file" in result["out"]
    assert "no-error" not in result["out"]
    assert result["peak_mb"] <= SHARP_BOUND_MB, result["peak_mb"]


# ----------------------------------------------------------
# (d) safe_extract: declared lie, ratio bomb, streamed write
# ----------------------------------------------------------

def _safe_snippet(body):
    header = r"""
import io, os, struct, sys, zipfile
sys.path.insert(0, {scripts!r})
from narlib.safearchive import safe_extract
work = sys.argv[1] if len(sys.argv) > 1 else "."
""".format(scripts=str(SCRIPTS))
    return header + body


def test_safe_extract_declared_size_lie_rejected_by_name(tmp_path):
    """Central directory declares 2 GiB for a 32 KiB member.
    With the ratio limits relaxed to their validated ceiling
    (the declared/stored ratio here is ~65536, under it), the
    per-file declared-size check is the defence that must
    fire, by name, before any decompression."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("small.txt", b"A" * (32 * 1024))
    raw = bytearray(buf.getvalue())
    cen = raw.find(b"PK\x01\x02")
    assert cen > 0
    struct.pack_into("<I", raw, cen + 24, 2 * 1024 * 1024 * 1024)
    src = tmp_path / "lying.zip"
    src.write_bytes(bytes(raw))
    snippet = _safe_snippet(r"""
rep = safe_extract(os.path.join(work, "lying.zip"),
                   os.path.join(work, "out"),
                   limits={"max_ratio": 100000.0,
                           "max_total_ratio": 100000.0})
print("RESULT rejected:", rep["rejected"])
print("RESULT extracted:", rep["extracted"])
""")
    result = _run_peak([sys.executable, "-c", snippet,
                        str(tmp_path)], timeout=300)
    assert result["rc"] == 0, result["err"]
    assert "file exceeds per-file size limit" in result["out"], \
        result["out"]
    assert "RESULT extracted: []" in result["out"]
    assert result["peak_mb"] <= SHARP_BOUND_MB, result["peak_mb"]


def test_safe_extract_ratio_bomb_rejected_by_name(tmp_path):
    """A real high-ratio bomb: 48 MiB of zeros in a ~49 KB
    archive. The compression-ratio defence fires by name;
    nothing is extracted; the payload is never inflated."""
    src = tmp_path / "bomb.zip"
    with zipfile.ZipFile(src, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.bin", b"\x00" * (48 * MIB))
    assert src.stat().st_size < MIB
    snippet = _safe_snippet(r"""
rep = safe_extract(os.path.join(work, "bomb.zip"),
                   os.path.join(work, "out"))
print("RESULT rejected:", rep["rejected"])
print("RESULT extracted:", rep["extracted"])
""")
    result = _run_peak([sys.executable, "-c", snippet,
                        str(tmp_path)], timeout=300)
    assert result["rc"] == 0, result["err"]
    assert "compression ratio" in result["out"], result["out"]
    assert "RESULT extracted: []" in result["out"]
    assert not (tmp_path / "out" / "bomb.bin").exists()
    assert result["peak_mb"] <= SHARP_BOUND_MB, result["peak_mb"]


def test_safe_extract_large_member_is_streamed(tmp_path):
    """A legitimate 128 MiB incompressible member extracts
    fully while the extractor's peak stays at the sharp
    bound: extraction is chunked, never a whole-blob read
    (a whole-blob extractor would peak above 140 MB here)."""
    src = tmp_path / "large.zip"
    rng = random.Random(20261126)
    with zipfile.ZipFile(src, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo("large.bin")
        info.compress_type = zipfile.ZIP_DEFLATED
        with zf.open(info, "w", force_zip64=True) as fh:
            remaining = 128 * MIB
            while remaining > 0:
                n = min(remaining, 4 * MIB)
                fh.write(rng.randbytes(n))
                remaining -= n
    snippet = _safe_snippet(r"""
rep = safe_extract(os.path.join(work, "large.zip"),
                   os.path.join(work, "out"))
print("RESULT extracted:", rep["extracted"])
print("RESULT rejected:", rep["rejected"])
""")
    result = _run_peak([sys.executable, "-c", snippet,
                        str(tmp_path)], timeout=600)
    assert result["rc"] == 0, result["err"]
    assert "RESULT rejected: []" in result["out"], result["out"]
    written = tmp_path / "out" / "large.bin"
    assert written.stat().st_size == 128 * MIB
    assert result["peak_mb"] <= SHARP_BOUND_MB, result["peak_mb"]


# ----------------------------------------------------------
# Audit suspects at their current state
# ----------------------------------------------------------

def test_unity_oversized_bundle_member_cap_by_name(tmp_path):
    """A2-02 regression: nar-unity's bundle inspection and
    census reads were unbounded whole-member reads (peak
    979.2 MB on this exact input before the fix). The member
    read cap must now fire by name in the inspection record
    and the census note, at a bounded peak."""
    apk = _write_oversized_member_apk(
        tmp_path / "hostile.apk", "assets/aa/big.bundle",
        320 * MIB)
    out_path = tmp_path / "unity.json"
    result = _run_peak(
        [sys.executable, str(SCRIPTS / "nar-unity.py"),
         str(apk), "--json"],
        timeout=600, stdout_path=out_path)
    assert result["rc"] == 0, result["err"]
    doc = json.loads(out_path.read_text())
    inspections = doc["bundle_inspections"]
    assert len(inspections) == 1, inspections
    assert inspections[0]["parsed"] is False
    assert "member read cap" in inspections[0]["error"], \
        inspections
    notes = " ".join(doc.get("notes") or [])
    assert "member read cap" in notes, notes
    assert result["peak_mb"] <= UNITY_BOUND_MB, result["peak_mb"]


_GODOT_SNIPPET = r"""
import importlib.util, io, os, struct, sys, zipfile
spec = importlib.util.spec_from_file_location(
    "nar_godot_mem", "__GODOT_PATH__")
godot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(godot)
work = sys.argv[1]

# Standalone scene one byte over the 64 MiB scene cap
# (sparse: the size check must fire before any read).
p = os.path.join(work, "big.tscn")
with open(p, "wb") as fh:
    fh.write(b"[gd_scene load_steps=2]\n")
    fh.truncate(godot.MAX_SCENE_BYTES + 1)
print("RESULT scene:", godot.inspect(p).get("error"))

# Standalone pack one byte over the 512 MiB pack cap.
p = os.path.join(work, "big.pck")
with open(p, "wb") as fh:
    fh.write(b"GDPC")
    fh.truncate(godot.MAX_PCK_BYTES + 1)
rep = godot.inspect(p)
print("RESULT pck:", (rep.get("pck") or {}).get("parse_error"))

# Embedded pack whose central directory declares a size
# over the cap (the member itself is tiny): the declared
# check must refuse before decompression.
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as zf:
    zf.writestr("assets/game.pck", b"GDPC" + b"\x00" * 256)
    zf.writestr("lib/arm64-v8a/libgodot_android.so", b"\x7fELF")
raw = bytearray(buf.getvalue())
cen = raw.find(b"PK\x01\x02")
struct.pack_into("<I", raw, cen + 24, godot.MAX_PCK_BYTES + 1)
apk = os.path.join(work, "lie.apk")
with open(apk, "wb") as fh:
    fh.write(bytes(raw))
rep = godot.inspect(apk)
print("RESULT embedded:", (rep.get("pck") or {}).get(
    "parse_error"))
"""


def test_godot_member_reads_cap_bounded_by_name(tmp_path):
    """A2-02, Godot half, at its current state: the scene,
    standalone-pack and embedded-pack reads are all governed
    by the parser read caps (the audit's bare fh.read() lines
    now sit behind getsize / declared-size checks). Each cap
    fires by name at the REAL cap value, on sparse or
    header-lying inputs, at a bounded peak."""
    result = _run_peak(
        [sys.executable, "-c",
         _GODOT_SNIPPET.replace(
             "__GODOT_PATH__", str(SCRIPTS / "nar-godot.py")),
         str(tmp_path)], timeout=600)
    assert result["rc"] == 0, result["err"]
    assert "RESULT scene: scene file exceeds the parser " \
        "read cap" in result["out"], result["out"]
    assert "RESULT pck: pack file exceeds the parser " \
        "read cap" in result["out"], result["out"]
    assert "RESULT embedded: embedded pack declares" in \
        result["out"], result["out"]
    assert "not decompressed" in result["out"]
    assert result["peak_mb"] <= SHARP_BOUND_MB, result["peak_mb"]


_DOTNET_SNIPPET = r"""
import os, sys
sys.path.insert(0, {scripts!r})
from narlib import dotnetmeta
work = sys.argv[1]
{setup}
path = os.path.join(work, "big.dll")
with open(path, "wb") as fh:
    fh.write(b"MZ")
    fh.truncate(size)
try:
    dotnetmeta.count_assembly(path)
    print("RESULT no-error")
except dotnetmeta.DotNetMetaError as e:
    print("RESULT error:", e)
"""


def test_dotnetmeta_cap_is_the_bound_at_real_cap(tmp_path):
    """A1-07: count_assembly's whole-file read is bounded by
    its 512 MiB structural-read cap, accepted and pinned as
    the bound. A sparse file one byte over the real cap is
    refused by name; the child's peak is the cap plus the
    interpreter baseline, inside the stated 768 MiB bound."""
    snippet = _DOTNET_SNIPPET.format(
        scripts=str(SCRIPTS),
        setup="size = dotnetmeta.MAX_ASSEMBLY_BYTES + 1")
    result = _run_peak([sys.executable, "-c", snippet,
                        str(tmp_path)], timeout=600)
    assert result["rc"] == 0, result["err"]
    assert "RESULT error:" in result["out"], result["out"]
    assert "structural-read cap" in result["out"]
    assert result["peak_mb"] <= DOTNET_BOUND_MB, result["peak_mb"]


def test_dotnetmeta_read_is_governed_by_the_cap(tmp_path):
    """The read is governed by the cap VALUE, not by the file
    size: under a cap reduced to 4 MiB, an 8 MiB sparse file
    is refused by name at a sharp peak (the reader materializes
    at most cap+1 bytes)."""
    snippet = _DOTNET_SNIPPET.format(
        scripts=str(SCRIPTS),
        setup=("dotnetmeta.MAX_ASSEMBLY_BYTES = 4 * 1024 * 1024\n"
               "size = 8 * 1024 * 1024"))
    result = _run_peak([sys.executable, "-c", snippet,
                        str(tmp_path)], timeout=300)
    assert result["rc"] == 0, result["err"]
    assert "RESULT error:" in result["out"], result["out"]
    assert "structural-read cap" in result["out"]
    assert result["peak_mb"] <= SHARP_BOUND_MB, result["peak_mb"]


# ----------------------------------------------------------
# (a) Heaviest stages on the largest retained fixture,
#     and nar-analyze on a synthetic oversized container
# ----------------------------------------------------------

@pytest.mark.parametrize("tool", ["nar-dex.py", "nar-native.py",
                                  "nar-unity.py"])
def test_heaviest_stages_largest_fixture_envelope(tool, tmp_path):
    fixture = _largest_fixture()
    if fixture is None:
        pytest.skip("no retained fixture tree")
    out_path = tmp_path / f"{tool}.json"
    result = _run_peak(
        [sys.executable, str(SCRIPTS / tool), fixture, "--json"],
        timeout=1800, stdout_path=out_path)
    assert result["rc"] == 0, result["err"]
    assert out_path.stat().st_size > 0
    bound = FIXTURE_BOUNDS_MB[tool]
    assert result["peak_mb"] <= bound, (
        f"{tool} peak {result['peak_mb']:.1f} MB over the "
        f"{bound} MB envelope on the largest fixture")


def test_analyze_synthetic_oversized_container(tmp_path):
    """Full nar-analyze on a synthetic container carrying a
    320 MiB bundle member (319 KB on disk): the run completes,
    writes its report, and the whole process tree stays
    inside the stated bound."""
    apk = _write_oversized_member_apk(
        tmp_path / "hostile.apk", "assets/aa/big.bundle",
        320 * MIB)
    case_dir = tmp_path / "case"
    result = _run_peak(
        [sys.executable, str(SCRIPTS / "nar-analyze.py"),
         "--out", str(case_dir), str(apk)],
        timeout=1200)
    assert result["rc"] == 0, result["err"][-1000:]
    assert (case_dir / "report.json").is_file()
    assert result["peak_mb"] <= ANALYZE_BOUND_MB, result["peak_mb"]
