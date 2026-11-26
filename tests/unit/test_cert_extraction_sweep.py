"""NAR 3.0.1 certification — extraction-safety sweep
(Phase 3, Workstream FUZZ / Task C).

Every code path that writes archive-derived bytes to disk,
driven with the same attack matrix:

  - traversal spellings: ``../``, ``a/../../``, absolute
    paths, backslash traversal, drive-letter paths;
  - a symlink entry inside the archive;
  - a pre-existing symlink DIRECTORY at the destination
    (the write would be redirected outside through it);
  - a pre-existing symlink FILE at the exact target;
  - a decompression bomb: a header size lie (declared
    small, stream expands huge) and a plain
    declared-huge compressible payload.

Paths under sweep:

  1. narlib.safearchive.safe_extract -- the sanctioned
     extractor behind nar-input's extract command,
     narlib.container target resolution, nar-analyze's
     container handling and the case-import path.
  2. nar-analyze's own extract_entry /
     extract_entry_record (contained join + budget).
  3. nar-pak's extract_pak (the disk-writing half of the
     pak tool; entry names come from the pak index).
  4. The case-import path (nar-analyze import_case),
     which extracts through safearchive into a staging
     directory and must abort on any rejection.
  5. nar-rn's bundle write: the bundle entry name is
     archive-controlled, the write must stay basename-only
     inside the work directory.

narlib.iostore and narlib.zen are NOT disk writers: a
source audit (pinned by test_iostore_zen_write_nothing_to_disk
below) shows neither module opens a file for writing --
their extract-shaped helpers return bytes in memory.
They are enumerated here so the enumeration is complete,
with the audit as the evidence.

Hardlink entries: the ZIP container cannot express a
hardlink (there is no link-target field; a unix-mode entry
is a regular file, a symlink, or another special file --
all non-regular modes are refused by safearchive), and
the PAK container cannot express links of any kind (its
index carries names and data ranges only). There is
therefore no hardlink shape to drive at paths 1-5; the
symlink shapes above cover the link family both formats
CAN express.

Assertion discipline per path: containment (nothing is
written outside the destination -- checked against a
sentinel outside directory) AND a named refusal (a
rejection record, a ValueError, or an extract error
entry) for every hostile shape. Sanitizing paths (pak)
may instead land the payload at a contained sanitized
name; the sweep accepts exactly one of {named refusal,
contained sanitized write} per shape and asserts the
sentinel is untouched either way.
"""
import hashlib
import importlib.util
import io
import json
import os
import struct
import sys
import zipfile
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_pak  # noqa: E402
from narlib import safearchive  # noqa: E402

nar_pak = test_pak.nar_pak


def _load_tool(name, fname):
    spec = importlib.util.spec_from_file_location(
        name, SCRIPTS / fname)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


nar_analyze = _load_tool("nar_analyze_sweep", "nar-analyze.py")
nar_rn = _load_tool("nar_rn_sweep", "nar-rn.py")


# ------------------------------------------------------------ helpers

def _zip_bytes(entries, compression=zipfile.ZIP_DEFLATED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


def _symlink_zip(link_name, target, extra=()):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo(link_name)
        info.external_attr = 0o120777 << 16  # symlink mode
        zf.writestr(info, target)
        for name, data in extra:
            zf.writestr(name, data)
    return buf.getvalue()


def _corrupt_deflate_zip(name="a.bin", payload=b"A" * 1000):
    raw = bytearray(_zip_bytes([(name, payload)]))
    pos = raw.find(name.encode()) + len(name)
    for j in range(pos, min(pos + 10, len(raw))):
        raw[j] ^= 0xFF
    return bytes(raw)


def _size_lie_zip(name="lie.bin", payload=b"B" * 100_000,
                  declared=10):
    """A zip whose central directory understates one
    entry's uncompressed size: the entry declares
    ``declared`` bytes, its stream expands to the full
    payload."""
    raw = bytearray(_zip_bytes([(name, payload)]))
    cen = raw.rfind(b"PK\x01\x02")
    assert cen > 0
    struct.pack_into("<I", raw, cen + 24, declared)
    return bytes(raw)


def _outside_sentinel(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_bytes(b"untouched")
    return outside


def _assert_sentinel_untouched(outside):
    assert sorted(p.name for p in outside.iterdir()) == ["keep.txt"]
    assert (outside / "keep.txt").read_bytes() == b"untouched"


TRAVERSAL_NAMES = [
    "../evil.txt",
    "a/../../evil.txt",
    "/abs.txt",
    "..\\evil.txt",
    "a\\..\\..\\evil.txt",
    "C:/evil.txt",
    "C:\\evil.txt",
]


# ------------------------------------------- 1. safearchive.safe_extract

@pytest.mark.parametrize("evil", TRAVERSAL_NAMES)
def test_sweep_safearchive_traversal_spellings(tmp_path, evil):
    outside = _outside_sentinel(tmp_path)
    src = tmp_path / "in.zip"
    src.write_bytes(_zip_bytes([(evil, b"x"), ("ok.txt", b"y")]))
    dest = tmp_path / "dest"
    report = safearchive.safe_extract(str(src), str(dest))
    assert [e["entry"] for e in report["extracted"]] == ["ok.txt"]
    assert len(report["rejected"]) == 1
    assert report["rejected"][0]["entry"] == evil
    assert report["rejected"][0]["reason"]  # named refusal
    assert not (tmp_path / "evil.txt").exists()
    _assert_sentinel_untouched(outside)


def test_sweep_safearchive_symlink_entry(tmp_path):
    src = tmp_path / "in.zip"
    src.write_bytes(_symlink_zip("link", "/etc/passwd",
                                  [("real.txt", b"data")]))
    dest = tmp_path / "dest"
    report = safearchive.safe_extract(str(src), str(dest))
    assert [e["entry"] for e in report["extracted"]] == ["real.txt"]
    assert any("symlink" in r["reason"]
               for r in report["rejected"])
    assert not os.path.islink(dest / "link")


def test_sweep_safearchive_symlink_directory_at_dest(tmp_path):
    outside = _outside_sentinel(tmp_path)
    dest = tmp_path / "dest"
    dest.mkdir()
    os.symlink(outside, dest / "sub")
    src = tmp_path / "in.zip"
    src.write_bytes(_zip_bytes([("sub/evil.txt", b"x")]))
    report = safearchive.safe_extract(str(src), str(dest))
    assert report["extracted"] == []
    assert len(report["rejected"]) == 1
    assert "escapes destination" in report["rejected"][0]["reason"]
    _assert_sentinel_untouched(outside)


def test_sweep_safearchive_symlink_file_at_target(tmp_path):
    outside = _outside_sentinel(tmp_path)
    dest = tmp_path / "dest"
    dest.mkdir()
    os.symlink(outside / "keep.txt", dest / "ok.txt")
    src = tmp_path / "in.zip"
    src.write_bytes(_zip_bytes([("ok.txt", b"OVERWRITTEN")]))
    report = safearchive.safe_extract(str(src), str(dest))
    assert report["extracted"] == []
    # The realpath containment proof fires first here (the
    # link target is outside the destination); either named
    # refusal is the invariant.
    assert any("symlink" in r["reason"] or "escapes" in r["reason"]
               for r in report["rejected"])
    _assert_sentinel_untouched(outside)


def test_sweep_safearchive_bomb_declared_huge(tmp_path):
    src = tmp_path / "in.zip"
    src.write_bytes(_zip_bytes([("bomb.bin", b"\x00" * (2 << 20))]))
    dest = tmp_path / "dest"
    report = safearchive.safe_extract(
        str(src), str(dest), limits={"max_ratio": 50.0})
    assert report["extracted"] == []
    assert any("ratio" in r["reason"] for r in report["rejected"])


def test_sweep_safearchive_bomb_size_lie(tmp_path):
    src = tmp_path / "in.zip"
    src.write_bytes(_size_lie_zip())
    dest = tmp_path / "dest"
    report = safearchive.safe_extract(
        str(src), str(dest), limits={"max_file_bytes": 50_000})
    assert report["extracted"] == []
    assert len(report["rejected"]) == 1
    assert report["rejected"][0]["reason"]
    # No partial/oversized file is left behind.
    assert not (dest / "lie.bin").exists()


# --------------------------------------- 2. nar-analyze extract_entry

@pytest.fixture()
def analyze_budget():
    """Reset nar-analyze's run-global extraction budget
    around each case (it accumulates across calls)."""
    nar_analyze._EXTRACT_BUDGET["used"] = 0
    yield
    nar_analyze._EXTRACT_BUDGET["used"] = 0


def _analyze_zip(tmp_path, entries, name="in.zip"):
    src = tmp_path / name
    src.write_bytes(_zip_bytes(entries))
    return src


@pytest.mark.parametrize("parts", [
    ("../evil.txt",),
    ("a", "..", "..", "evil.txt"),
    ("/abs.txt",),
    ("..", "evil.txt"),
])
def test_sweep_analyze_traversal_parts(tmp_path, analyze_budget,
                                       parts):
    outside = _outside_sentinel(tmp_path)
    root = tmp_path / "root"
    root.mkdir()
    src = _analyze_zip(tmp_path, [("payload.bin", b"data")])
    with zipfile.ZipFile(src) as zf:
        dest, rejection = nar_analyze.extract_entry_record(
            zf, "payload.bin", str(root), *parts)
    assert dest is None
    assert rejection is not None
    assert "escapes the work directory" in rejection["reason"]
    assert not (tmp_path / "evil.txt").exists()
    _assert_sentinel_untouched(outside)


def test_sweep_analyze_backslash_name_stays_contained(
        tmp_path, analyze_budget):
    """On POSIX a backslash is a filename character, not a
    separator: the write must land INSIDE root under the
    literal name, never outside it."""
    root = tmp_path / "root"
    root.mkdir()
    src = _analyze_zip(tmp_path, [("payload.bin", b"data")])
    with zipfile.ZipFile(src) as zf:
        dest, rejection = nar_analyze.extract_entry_record(
            zf, "payload.bin", str(root), "..\\evil.txt")
    assert rejection is None
    assert Path(dest).parent == Path(os.path.realpath(root))
    assert not (tmp_path / "evil.txt").exists()


def test_sweep_analyze_symlink_directory_at_dest(
        tmp_path, analyze_budget):
    outside = _outside_sentinel(tmp_path)
    root = tmp_path / "root"
    root.mkdir()
    os.symlink(outside, root / "sub")
    src = _analyze_zip(tmp_path, [("payload.bin", b"data")])
    with zipfile.ZipFile(src) as zf:
        dest, rejection = nar_analyze.extract_entry_record(
            zf, "payload.bin", str(root), "sub", "evil.txt")
    assert dest is None
    assert "symlink" in rejection["reason"]
    _assert_sentinel_untouched(outside)


def test_sweep_analyze_symlink_file_at_target(
        tmp_path, analyze_budget):
    outside = _outside_sentinel(tmp_path)
    root = tmp_path / "root"
    root.mkdir()
    os.symlink(outside / "keep.txt", root / "payload.bin")
    src = _analyze_zip(tmp_path, [("payload.bin", b"OVERWRITE")])
    with zipfile.ZipFile(src) as zf:
        dest, rejection = nar_analyze.extract_entry_record(
            zf, "payload.bin", str(root), "payload.bin")
    assert dest is None
    # _contained_join's realpath proof fires before the
    # islink guard when the link target is outside root;
    # both are named symlink refusals.
    assert "symlink" in rejection["reason"]
    _assert_sentinel_untouched(outside)


def test_sweep_analyze_bomb_declared_huge(
        tmp_path, analyze_budget, monkeypatch):
    monkeypatch.setattr(nar_analyze, "MAX_EXTRACT_ENTRY_BYTES",
                        1024)
    monkeypatch.setattr(nar_analyze, "MAX_EXTRACT_TOTAL_BYTES",
                        4096)
    root = tmp_path / "root"
    root.mkdir()
    src = _analyze_zip(tmp_path,
                       [("big.bin", b"\x00" * 100_000)])
    with zipfile.ZipFile(src) as zf:
        dest, rejection = nar_analyze.extract_entry_record(
            zf, "big.bin", str(root), "big.bin")
    assert dest is None
    assert "extraction cap" in rejection["reason"]
    assert not (root / "big.bin").exists()


def test_sweep_analyze_bomb_size_lie_streaming(
        tmp_path, analyze_budget, monkeypatch):
    """Declared 10 bytes (passes the declared-size check),
    stream expands to 100,000: the streaming budget must
    cut it off, remove the partial, and refuse by name."""
    monkeypatch.setattr(nar_analyze, "MAX_EXTRACT_ENTRY_BYTES",
                        50_000)
    monkeypatch.setattr(nar_analyze, "MAX_EXTRACT_TOTAL_BYTES",
                        60_000)
    root = tmp_path / "root"
    root.mkdir()
    src = tmp_path / "lie.zip"
    src.write_bytes(_size_lie_zip(name="big.bin"))
    with zipfile.ZipFile(src) as zf:
        dest, rejection = nar_analyze.extract_entry_record(
            zf, "big.bin", str(root), "big.bin")
    assert dest is None
    assert rejection is not None and rejection["reason"]
    assert not (root / "big.bin").exists()


def test_sweep_analyze_corrupt_deflate_refused_by_name(
        tmp_path, analyze_budget):
    """A deflate-corrupt member is a refusal (ValueError
    via the record form), never a raw zlib.error escape --
    the NF-02 family at this extractor's own read loop."""
    root = tmp_path / "root"
    root.mkdir()
    src = tmp_path / "corrupt.zip"
    src.write_bytes(_corrupt_deflate_zip())
    with zipfile.ZipFile(src) as zf:
        dest, rejection = nar_analyze.extract_entry_record(
            zf, "a.bin", str(root), "a.bin")
    assert dest is None
    assert rejection is not None
    assert "unreadable" in rejection["reason"]
    assert not (root / "a.bin").exists()


# ------------------------------------------------ 3. nar-pak extract

def _pak_with(dir_name, file_name, payload=b"DATA" * 8,
              usize=None):
    """A complete v11 encoded pak carrying ONE stored entry
    whose directory / file names are caller-chosen (the
    assembly mirrors tests/unit/test_pak.build_v11_encoded).
    ``usize`` lets the index+header understate the payload
    size consistently (the size-lie shape)."""
    raw = payload
    declared_usize = len(raw) if usize is None else usize
    data_region = test_pak._entry_header(
        len(raw), declared_usize, 0, raw) + raw
    blob = test_pak._encoded_record(0, declared_usize,
                                    len(raw), 0, ())
    mount = "../../../"
    fdi = struct.pack("<i", 1)
    fdi += test_pak._fstring(dir_name)
    fdi += struct.pack("<i", 1)
    fdi += test_pak._fstring(file_name)
    fdi += struct.pack("<i", 0)
    ph_region = struct.pack("<Q", 0x1234) + struct.pack("<i", 0)
    index_offset = len(data_region)
    idx_len = (len(test_pak._fstring(mount)) + 4 + 8 + 4 + 36
               + 4 + 36 + 4 + len(blob) + 4)
    ph_offset = index_offset + idx_len
    fdi_offset = ph_offset + len(ph_region)
    index = test_pak._fstring(mount)
    index += struct.pack("<i", 1)
    index += struct.pack("<Q", 0x66AA1351)
    index += struct.pack("<i", 1)
    index += struct.pack("<q", ph_offset)
    index += struct.pack("<q", len(ph_region))
    index += hashlib.sha1(ph_region).digest()
    index += struct.pack("<i", 1)
    index += struct.pack("<q", fdi_offset)
    index += struct.pack("<q", len(fdi))
    index += hashlib.sha1(fdi).digest()
    index += struct.pack("<i", len(blob)) + blob
    index += struct.pack("<i", 0)
    assert len(index) == idx_len
    slots = (b"Zlib".ljust(32, b"\x00")
             + b"Oodle".ljust(32, b"\x00") + b"\x00" * 96)
    footer = (b"\x00" * 16 + b"\x00" + test_pak.MAGIC
              + struct.pack("<IQQ", 11, index_offset, len(index))
              + hashlib.sha1(index).digest() + slots)
    return data_region + index + ph_region + fdi + footer


def _pak_extract(tmp_path, blob, out_name="out"):
    src = tmp_path / "sweep.pak"
    src.write_bytes(blob)
    out = tmp_path / out_name
    report = nar_pak.extract_pak(str(src), "*", str(out))
    return report, out


@pytest.mark.parametrize("dir_name,file_name", [
    ("Game/Content/", "../../evil.txt"),
    ("/abs/", "evil.txt"),
    ("Game/Content/", "..\\..\\evil.txt"),
    ("Game/Content/", "C:\\evil.txt"),
    ("../", "evil.txt"),
])
def test_sweep_pak_traversal_names_contained(
        tmp_path, dir_name, file_name):
    outside = _outside_sentinel(tmp_path)
    report, out = _pak_extract(
        tmp_path, _pak_with(dir_name, file_name))
    # Contained: either a named refusal, or a sanitized
    # write strictly inside the output directory.
    assert report["extract_errors"] or report["extracted"]
    for item in report["extracted"]:
        assert Path(item["out_path"]).is_relative_to(
            Path(os.path.realpath(out)))
    assert not (tmp_path / "evil.txt").exists()
    _assert_sentinel_untouched(outside)


def test_sweep_pak_symlink_directory_at_dest(tmp_path):
    outside = _outside_sentinel(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    os.symlink(outside, out / "Game")
    src = tmp_path / "sweep.pak"
    src.write_bytes(_pak_with("Game/Content/", "stored.uasset"))
    report = nar_pak.extract_pak(str(src), "*", str(out))
    assert report["extracted"] == []
    assert len(report["extract_errors"]) == 1
    assert "symlink" in report["extract_errors"][0]["error"]
    _assert_sentinel_untouched(outside)


def test_sweep_pak_symlink_file_at_target(tmp_path):
    outside = _outside_sentinel(tmp_path)
    out = tmp_path / "out"
    (out / "Game" / "Content").mkdir(parents=True)
    os.symlink(outside / "keep.txt",
               out / "Game" / "Content" / "stored.uasset")
    src = tmp_path / "sweep.pak"
    src.write_bytes(_pak_with("Game/Content/", "stored.uasset"))
    report = nar_pak.extract_pak(str(src), "*", str(out))
    assert report["extracted"] == []
    assert len(report["extract_errors"]) == 1
    assert "symlink" in report["extract_errors"][0]["error"]
    _assert_sentinel_untouched(outside)


def test_sweep_pak_size_lie_refused(tmp_path):
    """Index and header agree the entry is 10 bytes; the
    stored payload is 32: the size cross-check refuses it
    by name and writes nothing."""
    report, out = _pak_extract(
        tmp_path, _pak_with("Game/Content/", "lie.uasset",
                            payload=b"L" * 32, usize=10))
    assert report["extracted"] == []
    assert len(report["extract_errors"]) == 1
    assert "does not match" in report["extract_errors"][0]["error"]
    assert not (out / "Game" / "Content" / "lie.uasset").exists()


# ------------------------------------------------- 4. case import

def _case_bundle(entries):
    manifest = {"case_id": "sweep", "files": []}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(nar_analyze.BUNDLE_MANIFEST,
                    json.dumps(manifest))
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


def test_sweep_import_case_traversal_aborts(tmp_path):
    outside = _outside_sentinel(tmp_path)
    bundle = tmp_path / "case.zip"
    bundle.write_bytes(_case_bundle([("../evil.txt", b"x")]))
    out_dir = tmp_path / "imported"
    with pytest.raises(ValueError, match="unsafe entries"):
        nar_analyze.import_case(str(bundle), str(out_dir))
    assert not out_dir.exists()
    assert not (tmp_path / "evil.txt").exists()
    _assert_sentinel_untouched(outside)


def test_sweep_import_case_symlink_entry_aborts(tmp_path):
    bundle = tmp_path / "case.zip"
    manifest = {"case_id": "sweep", "files": []}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(nar_analyze.BUNDLE_MANIFEST,
                    json.dumps(manifest))
        info = zipfile.ZipInfo("link")
        info.external_attr = 0o120777 << 16
        zf.writestr(info, "/etc/passwd")
    bundle.write_bytes(buf.getvalue())
    out_dir = tmp_path / "imported"
    with pytest.raises(ValueError, match="unsafe entries"):
        nar_analyze.import_case(str(bundle), str(out_dir))
    assert not out_dir.exists()


def test_sweep_import_case_ratio_bomb_aborts(tmp_path):
    bundle = tmp_path / "case.zip"
    bundle.write_bytes(_case_bundle(
        [("bomb.bin", b"\x00" * (20 << 20))]))
    out_dir = tmp_path / "imported"
    with pytest.raises(ValueError, match="unsafe entries"):
        nar_analyze.import_case(str(bundle), str(out_dir))
    assert not out_dir.exists()


# ---------------------------------------------------- 5. nar-rn write

JS_PAYLOAD = b"var answer = 42;\nconsole.log(answer);\n" * 4


def _rn_apk(tmp_path, entry_name, payload=JS_PAYLOAD):
    apk = tmp_path / "app.apk"
    apk.write_bytes(_zip_bytes([(entry_name, payload)],
                               compression=zipfile.ZIP_STORED))
    return apk


def test_sweep_rn_traversal_bundle_name_basename_only(tmp_path):
    work = tmp_path / "work"
    apk = _rn_apk(tmp_path, "assets/../../evil.bundle")
    report = nar_rn.inspect(str(apk), str(work))
    assert report["is_react_native"] is True
    bundle_path = Path(report["bundle_path"])
    assert bundle_path.parent == work
    assert bundle_path.name == "evil.bundle"
    assert bundle_path.read_bytes() == JS_PAYLOAD
    assert not (tmp_path / "evil.bundle").exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == \
        ["app.apk", "work"]


def test_sweep_rn_contract_bundle_contained(tmp_path):
    work = tmp_path / "work"
    apk = _rn_apk(tmp_path, "assets/index.android.bundle")
    report = nar_rn.inspect(str(apk), str(work))
    assert report["is_react_native"] is True
    assert Path(report["bundle_path"]).parent == work
    assert Path(report["bundle_path"]).name == \
        "index.android.bundle"


# --------------------------------- 6. iostore / zen: no disk writes

def test_sweep_iostore_zen_write_nothing_to_disk():
    """Enumeration completeness: the IoStore and Zen
    helpers return extracted bytes in memory and never
    open a file for writing -- pinned by a source audit so
    a future disk-writing helper cannot slip into the
    enumeration unnoticed."""
    for fname in ("iostore.py", "zen.py"):
        text = (SCRIPTS / "narlib" / fname).read_text(
            encoding="utf-8")
        assert '"wb"' not in text and "'wb'" not in text, fname
        assert '"ab"' not in text and "'ab'" not in text, fname
        assert "makedirs" not in text, fname
        assert "safe_extract" not in text, fname
