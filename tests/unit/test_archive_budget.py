"""2.6.2 Workstream A1: ResourceBudget + safearchive hardening.

Covers the narlib.budget abstraction (validation, safearchive
mapping), the safearchive refactor onto it (public behavior
unchanged), and the archive attack surface in one place:
traversal variants, symlinks, duplicates, malformed central
directories, declared-size lies, compression bombs, nesting,
interrupted extraction, and budget exhaustion. Crafted archives
only; all small and fast.

Duplicate-member behavior (documented, not silently assumed):
both entries are processed in central-directory order and both
appear in ``extracted``; the second write lands on the same
contained target and replaces the first file's contents. That is
deterministic and stays inside the destination; callers needing
first-wins semantics must dedupe themselves.
"""
import io
import os
import struct
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from narlib import safearchive  # noqa: E402
from narlib.budget import BudgetError, ResourceBudget  # noqa: E402


def _verbatim_info(name, compression=zipfile.ZIP_DEFLATED):
    """ZipInfo that stores ``name`` byte-for-byte.

    ZipInfo.__init__ sanitises the name at construction
    (on Windows, _sanitize_filename replaces os.sep '\\'
    with '/'), and writestr stores the sanitised filename
    — so a fixture built from a plain string silently
    stores a DIFFERENT name on Windows ('../evil.txt')
    than the test asserts ('..\\evil.txt'). Assigning
    ``filename`` after construction is what both the
    local header and the central directory are written
    from, so the archive stores the name verbatim on
    every platform.
    """
    info = zipfile.ZipInfo(name)
    info.filename = name
    info.compress_type = compression
    return info


def _zip_bytes(entries, compression=zipfile.ZIP_DEFLATED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, data in entries:
            if isinstance(data, zipfile.ZipInfo):
                # Pre-built ZipInfo as the payload slot:
                # restore its verbatim (pre-sanitisation)
                # name, keep every other attribute.
                data.filename = data.orig_filename
                zf.writestr(data, b"payload")
            elif isinstance(name, zipfile.ZipInfo):
                # Pre-built ZipInfo (e.g. _symlink_info):
                # same verbatim restore; its attributes
                # (external_attr, compress_type) are kept.
                name.filename = name.orig_filename
                zf.writestr(name, data)
            else:
                zf.writestr(_verbatim_info(name, compression),
                            data)
    return buf.getvalue()


def _symlink_info(name, target):
    info = zipfile.ZipInfo(name)
    info.external_attr = (0o120777 << 16)
    info.compress_type = zipfile.ZIP_STORED
    return info, target.encode()


# ----------------------------------------------------------
# ResourceBudget validation + mapping
# ----------------------------------------------------------

def test_default_budget_matches_safearchive_limits():
    budget = ResourceBudget()
    assert budget.to_safearchive_limits() == \
        safearchive.DEFAULT_LIMITS


def test_budget_rejects_negative_and_zero():
    for kwargs in ({"max_entries": 0}, {"max_entries": -1},
                   {"max_file_bytes": 0},
                   {"max_total_bytes": -100},
                   {"max_nesting_depth": -1}):
        with pytest.raises(BudgetError):
            ResourceBudget(**kwargs)


def test_budget_rejects_absurd_values():
    for kwargs in ({"max_entries": 10 ** 9},
                   {"max_file_bytes": 10 ** 15},
                   {"max_total_bytes": 10 ** 15},
                   {"max_compression_ratio": 10 ** 9},
                   {"max_total_ratio": 10 ** 9},
                   {"max_nesting_depth": 1000},
                   {"max_elapsed_seconds": 10 ** 9}):
        with pytest.raises(BudgetError):
            ResourceBudget(**kwargs)


def test_budget_rejects_bad_types_and_elapsed():
    for kwargs in ({"max_entries": "many"},
                   {"max_file_bytes": 1.5},
                   {"max_compression_ratio": "high"},
                   {"max_elapsed_seconds": 0},
                   {"max_elapsed_seconds": -5},
                   {"max_elapsed_seconds": "soon"}):
        with pytest.raises(BudgetError):
            ResourceBudget(**kwargs)


def test_budget_accepts_elapsed_and_partial_mapping():
    budget = ResourceBudget(max_elapsed_seconds=30)
    assert budget.max_elapsed_seconds == 30.0
    rebuilt = ResourceBudget.from_safearchive_limits(
        {"max_ratio": 50.0, "max_nesting": 1})
    assert rebuilt.max_compression_ratio == 50.0
    assert rebuilt.max_nesting_depth == 1
    assert rebuilt.max_entries == ResourceBudget().max_entries
    assert ResourceBudget.from_safearchive_limits(None) == \
        ResourceBudget()
    with pytest.raises(BudgetError):
        ResourceBudget.from_safearchive_limits("not-a-dict")


def test_safe_extract_accepts_budget_object(tmp_path):
    src = tmp_path / "in.zip"
    src.write_bytes(_zip_bytes([("ok.txt", b"hello")]))
    report = safearchive.safe_extract(
        str(src), str(tmp_path / "out"),
        limits=ResourceBudget(max_file_bytes=4))
    assert len(report["rejected"]) == 1
    assert "per-file size limit" in report["rejected"][0]["reason"]
    report = safearchive.safe_extract(
        str(src), str(tmp_path / "out2"),
        limits=ResourceBudget())
    assert report["rejected"] == []
    assert len(report["extracted"]) == 1


# ----------------------------------------------------------
# Traversal / symlink surface
# ----------------------------------------------------------

@pytest.mark.parametrize("name", [
    "../evil.txt", "a/../../evil.txt", "/abs.txt",
    "..\\evil.txt", "a\\..\\evil.txt",
    "C:/evil.txt", "C:\\evil.txt", "D:evil.txt",
])
def test_traversal_variants_rejected(tmp_path, name):
    src = tmp_path / "in.zip"
    src.write_bytes(_zip_bytes([(name, b"x"), ("ok.txt", b"y")]))
    out = tmp_path / "out"
    report = safearchive.safe_extract(str(src), str(out))
    assert len(report["extracted"]) == 1
    rejected = {r["entry"]: r["reason"] for r in report["rejected"]}
    assert name in rejected
    assert not (tmp_path / "evil.txt").exists()
    assert not (tmp_path / "abs.txt").exists()
    assert (out / "ok.txt").read_bytes() == b"y"


def test_symlink_entry_rejected(tmp_path):
    info, target = _symlink_info("link", "/etc/passwd")
    src = tmp_path / "in.zip"
    src.write_bytes(_zip_bytes([(info, target),
                                ("real.txt", b"data")]))
    out = tmp_path / "out"
    report = safearchive.safe_extract(str(src), str(out))
    assert any("symlink" in r["reason"]
               for r in report["rejected"])
    assert not os.path.islink(out / "link")
    assert (out / "real.txt").read_bytes() == b"data"


def test_symlink_dir_escape_rejected(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    dest = tmp_path / "dest"
    dest.mkdir()
    os.symlink(outside, dest / "linkdir")
    src = tmp_path / "in.zip"
    src.write_bytes(_zip_bytes([("linkdir/evil.txt", b"x"),
                                ("ok.txt", b"y")]))
    report = safearchive.safe_extract(str(src), str(dest))
    assert not (outside / "evil.txt").exists()
    assert any("escapes" in r["reason"]
               for r in report["rejected"])
    assert len(report["extracted"]) == 1


def test_duplicate_member_names_deterministic(tmp_path):
    src = tmp_path / "in.zip"
    src.write_bytes(_zip_bytes([("dup.txt", b"first"),
                                ("dup.txt", b"second")]))
    out = tmp_path / "out"
    report = safearchive.safe_extract(str(src), str(out))
    # Documented behavior: both entries are reported extracted,
    # in order, on the same contained target; the second write
    # replaces the first file's contents. Nothing escapes.
    assert [e["entry"] for e in report["extracted"]] == \
        ["dup.txt", "dup.txt"]
    assert report["rejected"] == []
    assert (out / "dup.txt").read_bytes() == b"second"
    assert not (tmp_path / "dup.txt").exists()


# ----------------------------------------------------------
# Malformed / lying archives
# ----------------------------------------------------------

def test_malformed_central_directory_named_error(tmp_path):
    good = _zip_bytes([("ok.txt", b"hello")])
    # Corrupt the central-directory signature so ZipFile
    # cannot open the archive at all.
    bad = bytearray(good)
    cen = bad.find(b"PK\x01\x02")
    assert cen > 0
    bad[cen:cen + 4] = b"PK\xff\xff"
    src = tmp_path / "bad.zip"
    src.write_bytes(bytes(bad))
    with pytest.raises(zipfile.BadZipFile):
        safearchive.safe_extract(str(src), str(tmp_path / "out"))


def test_declared_size_lies_small_stream_runs_long(tmp_path):
    """Central directory understates the entry: the stored
    stream carries more than the header claims. The entry
    must be rejected (CRC / stream mismatch) and no partial
    file left behind."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("small.txt", b"A" * 64)
        zf.writestr("ok.txt", b"y")
    raw = bytearray(buf.getvalue())
    cen = raw.find(b"PK\x01\x02")
    assert cen > 0
    # Central header: compress_size +20, file_size +24.
    struct.pack_into("<I", raw, cen + 20, 8)
    struct.pack_into("<I", raw, cen + 24, 8)
    src = tmp_path / "lying.zip"
    src.write_bytes(bytes(raw))
    out = tmp_path / "out"
    report = safearchive.safe_extract(str(src), str(out))
    rejected = {r["entry"] for r in report["rejected"]}
    assert "small.txt" in rejected
    assert not (out / "small.txt").exists()
    assert (out / "ok.txt").read_bytes() == b"y"


def test_truncated_stream_mid_entry_removes_partial(tmp_path):
    """A deflated entry whose compressed stream is cut short:
    the entry rejects alone, the partial file is removed, and
    the other entry still extracts."""
    import random
    payload = random.Random(42).randbytes(100_000)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.txt", payload)
        zf.writestr("ok.txt", b"y")
    raw = bytearray(buf.getvalue())
    # Corrupt big.txt's data by zeroing part of its deflate
    # stream (local header + name, then the stream).
    loc = raw.find(b"PK\x03\x04")
    assert loc >= 0
    name_len = struct.unpack_from("<H", raw, loc + 26)[0]
    extra_len = struct.unpack_from("<H", raw, loc + 28)[0]
    stream_off = loc + 30 + name_len + extra_len
    raw[stream_off + 10:stream_off + 60] = b"\x00" * 50
    src = tmp_path / "trunc.zip"
    src.write_bytes(bytes(raw))
    out = tmp_path / "out"
    report = safearchive.safe_extract(str(src), str(out))
    rejected = {r["entry"] for r in report["rejected"]}
    assert "big.txt" in rejected
    assert not (out / "big.txt").exists()
    assert (out / "ok.txt").read_bytes() == b"y"


# ----------------------------------------------------------
# Bombs, nesting, budget exhaustion, elapsed
# ----------------------------------------------------------

def test_compression_bomb_per_entry_and_total(tmp_path):
    big = b"\x00" * (512 * 1024)
    src = tmp_path / "bomb.zip"
    src.write_bytes(_zip_bytes([("bomb.bin", big)]))
    report = safearchive.safe_extract(
        str(src), str(tmp_path / "out"),
        limits={"max_ratio": 50.0})
    assert len(report["extracted"]) == 0
    assert any("ratio" in r["reason"]
               for r in report["rejected"])
    # Whole-archive ratio: two modest-ratio entries whose
    # combined ratio still exceeds a tiny total cap.
    src2 = tmp_path / "bomb2.zip"
    src2.write_bytes(_zip_bytes([("a.bin", big), ("b.bin", big)]))
    report = safearchive.safe_extract(
        str(src2), str(tmp_path / "out2"),
        limits={"max_total_ratio": 10.0,
                "max_ratio": 10_000.0})
    assert report["extracted"] == []
    assert report["rejected"][0]["entry"] == "(whole archive)"
    assert "total compression ratio" in \
        report["rejected"][0]["reason"]


def test_nested_archive_beyond_depth_flagged(tmp_path):
    inner = _zip_bytes([("inner.txt", b"deep")])
    src = tmp_path / "outer.zip"
    src.write_bytes(_zip_bytes([("inner.zip", inner)]))
    report = safearchive.safe_extract(
        str(src), str(tmp_path / "out"), _depth=2)
    assert report["nested_archives"] == ["inner.zip"]
    assert report.get("nesting_limit_reached") is True
    report = safearchive.safe_extract(
        str(src), str(tmp_path / "out2"), _depth=0)
    assert report.get("nesting_limit_reached") is not True


def test_budget_exhaustion_per_file_total_and_count(tmp_path):
    src = tmp_path / "in.zip"
    src.write_bytes(_zip_bytes([("a.bin", b"x" * 10),
                                ("b.bin", b"y" * 10)]))
    report = safearchive.safe_extract(
        str(src), str(tmp_path / "o1"),
        limits=ResourceBudget(max_file_bytes=5))
    assert len(report["extracted"]) == 0
    assert all("per-file size limit" in r["reason"]
               for r in report["rejected"])
    report = safearchive.safe_extract(
        str(src), str(tmp_path / "o2"),
        limits=ResourceBudget(max_total_bytes=15))
    assert len(report["extracted"]) == 1
    assert len(report["rejected"]) == 1
    assert "total size limit" in report["rejected"][0]["reason"]
    report = safearchive.safe_extract(
        str(src), str(tmp_path / "o3"),
        limits=ResourceBudget(max_entries=1))
    assert report["extracted"] == []
    assert report["rejected"][0]["entry"] == "(whole archive)"
    assert "entry count 2 exceeds limit 1" in \
        report["rejected"][0]["reason"]


def test_elapsed_budget_rejects_remaining_entries(tmp_path,
                                                  monkeypatch):
    """Deterministic elapsed test: the wall clock is faked
    (safearchive.time swapped for a stub whose monotonic()
    advances past the budget after the first entry)."""
    src = tmp_path / "in.zip"
    src.write_bytes(_zip_bytes([("a.txt", b"1"), ("b.txt", b"2"),
                                ("c.txt", b"3")]))
    calls = {"n": 0}

    class FakeTime:
        def monotonic(self):
            calls["n"] += 1
            # Calls 1-2 (the started stamp and the first
            # entry's check) are inside the budget; every
            # later call is past a 1-second budget.
            return 0.0 if calls["n"] <= 2 else 5.0

    monkeypatch.setattr(safearchive, "time", FakeTime())
    report = safearchive.safe_extract(
        str(src), str(tmp_path / "out"),
        limits=ResourceBudget(max_elapsed_seconds=1))
    assert [e["entry"] for e in report["extracted"]] == ["a.txt"]
    assert [r["entry"] for r in report["rejected"]] == \
        ["b.txt", "c.txt"]
    assert all("elapsed time budget" in r["reason"]
               for r in report["rejected"])


# ----------------------------------------------------------
# nar-analyze structured rejection record
# ----------------------------------------------------------

def test_analyze_extract_entry_record(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "nar_analyze_budget", str(SCRIPTS / "nar-analyze.py"))
    az = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(az)
    root = tmp_path / "case"
    root.mkdir()
    zpath = tmp_path / "in.zip"
    zpath.write_bytes(_zip_bytes([("base.apk", b"payload")]))
    with zipfile.ZipFile(zpath) as zf:
        dest, rejection = az.extract_entry_record(
            zf, "base.apk", str(root), "container",
            "../../../evil.apk")
        assert dest is None
        assert rejection == {
            "entry": "base.apk",
            "reason": rejection["reason"]}
        assert "escapes" in rejection["reason"]
        dest, rejection = az.extract_entry_record(
            zf, "base.apk", str(root), "container", "base.apk")
        assert rejection is None
        assert Path(dest).read_bytes() == b"payload"
    assert az.ANALYZE_EXTRACT_BUDGET.max_file_bytes == \
        4 * 1024 * 1024 * 1024
    assert az.ANALYZE_EXTRACT_BUDGET.max_total_bytes == \
        8 * 1024 * 1024 * 1024
