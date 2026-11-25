"""Raw archive-name keying for rejection reports (Windows
CI clusters B1-B4).

Root cause: CPython's zipfile normalises ``ZipInfo.filename``
on Windows (os.sep / os.altsep become '/') both when writing
and when reading the central directory, while
``ZipInfo.orig_filename`` preserves the name as stored in
the archive. Producers that keyed rejection / extracted
reports by ``info.filename`` therefore emitted the
NORMALISED name ('../evil.txt') on Windows for an entry the
archive actually stores as '..\\evil.txt'. Reports are
evidence: they must cite the raw stored name on every
platform. Containment decisions keep using the normalised
name, unchanged.

Fixture strategy: zipfile's WRITER normalises too (it
stores ZipInfo.filename), so a plain writestr(raw_name)
cannot be trusted to store a backslash name on a Windows
host. These fixtures are built at the byte level: each
entry is written under a same-length placeholder name
(backslashes replaced by '/'), then the placeholder name
bytes are patched to the raw name bytes in both the local
and central headers. Name lengths do not change and entry
CRCs cover data only, so the archive stays valid, and the
stored name is the raw backslash name on EVERY platform --
including this Linux host, where the byte patch is what
guarantees the fixture means the same thing it would mean
on Windows. (Real Windows execution is NOT RUN here; these
byte-level fixtures are the local proof.)
"""
import importlib.util
import io
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from narlib import container, safearchive  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, str(SCRIPTS / filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


triage = _load("nar_triage_rawname", "nar-triage.py")
az = _load("nar_analyze_rawname", "nar-analyze.py")
nar_input = _load("nar_input_rawname", "nar-input.py")


def _zip_raw(entries):
    """Build a ZIP whose stored names are EXACTLY the raw
    names given. ``entries`` is a list of
    (raw_name, data_bytes, external_attr_or_None)."""
    buf = io.BytesIO()
    patches = []
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for raw, data, ext_attr in entries:
            placeholder = raw.replace("\\", "/")
            info = zipfile.ZipInfo(placeholder)
            info.compress_type = zipfile.ZIP_STORED
            if ext_attr is not None:
                info.external_attr = ext_attr
            zf.writestr(info, data)
            if placeholder != raw:
                patches.append((placeholder.encode(),
                                raw.encode()))
    blob = buf.getvalue()
    for placeholder_b, raw_b in patches:
        assert len(placeholder_b) == len(raw_b)
        # Local header + central directory header, and the
        # placeholder must not occur anywhere else (payloads
        # in these fixtures never contain a name).
        assert blob.count(placeholder_b) == 2, placeholder_b
        blob = blob.replace(placeholder_b, raw_b)
    # The fixture must read back with the raw names as the
    # stored (orig_filename) names, on any platform.
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        assert [i.orig_filename for i in zf.infolist()] == \
            [raw for raw, _d, _a in entries]
    return blob


def _entries(*pairs):
    return [(name, data, None) for name, data in pairs]


# ----------------------------------------------------------
# safearchive: backslash traversal rejected, keyed RAW
# ----------------------------------------------------------

@pytest.mark.parametrize("raw,reason_part", [
    ("..\\evil.txt", "path traversal (..)"),
    ("a\\..\\evil.txt", "path traversal (..)"),
    ("C:\\evil.txt", "drive-letter path"),
    ("\\abs.txt", "absolute path"),
])
def test_safearchive_backslash_variants_rejected_raw(
        tmp_path, raw, reason_part):
    src = tmp_path / "in.zip"
    src.write_bytes(_zip_raw(_entries(
        (raw, b"x"), ("ok.txt", b"y"))))
    out = tmp_path / "out"
    report = safearchive.safe_extract(str(src), str(out))
    # The rejection still happens (security behaviour
    # unchanged) and its key is the RAW stored name.
    rejected = {r["entry"]: r["reason"]
                for r in report["rejected"]}
    assert rejected == {raw: reason_part}
    assert [e["entry"] for e in report["extracted"]] == \
        ["ok.txt"]
    assert (out / "ok.txt").read_bytes() == b"y"
    # Nothing was written outside the destination.
    assert list(tmp_path.rglob("evil.txt")) == []
    assert list(tmp_path.rglob("abs.txt")) == []


def test_safearchive_backslash_extracted_entry_cites_raw(
        tmp_path):
    src = tmp_path / "in.zip"
    src.write_bytes(_zip_raw(_entries(
        ("sub\\file.txt", b"data"))))
    out = tmp_path / "out"
    report = safearchive.safe_extract(str(src), str(out))
    assert report["rejected"] == []
    assert len(report["extracted"]) == 1
    entry = report["extracted"][0]
    # The citation is the raw stored name; the on-disk path
    # is the real contained path.
    assert entry["entry"] == "sub\\file.txt"
    assert Path(entry["path"]) == out / "sub" / "file.txt"
    assert Path(entry["path"]).read_bytes() == b"data"


def test_safearchive_symlink_entries_backslash_raw(tmp_path):
    symlink_attr = 0o120777 << 16
    # A symlink entry under a backslash name (main path).
    src = tmp_path / "in.zip"
    src.write_bytes(_zip_raw([
        ("bad\\link", b"/etc/passwd", symlink_attr),
        ("ok.txt", b"y", None)]))
    out = tmp_path / "out"
    report = safearchive.safe_extract(str(src), str(out))
    assert {r["entry"]: r["reason"]
            for r in report["rejected"]} == \
        {"bad\\link": "symlink entry"}
    assert [e["entry"] for e in report["extracted"]] == \
        ["ok.txt"]
    # A symlink DIRECTORY entry (the C-14 branch): the raw
    # name mixes a backslash with the trailing slash.
    src2 = tmp_path / "in2.zip"
    src2.write_bytes(_zip_raw([
        ("bad\\link/", b"/etc/passwd", symlink_attr)]))
    report = safearchive.safe_extract(
        str(src2), str(tmp_path / "out2"))
    assert report["extracted"] == []
    assert report["rejected"] == [
        {"entry": "bad\\link/", "reason": "symlink entry"}]


def test_safearchive_forward_slash_behaviour_unchanged(
        tmp_path):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("inner.txt", b"deep")
    src = tmp_path / "in.zip"
    src.write_bytes(_zip_raw(_entries(
        ("../evil.txt", b"x"),
        ("ok.txt", b"y"),
        ("inner.zip", inner.getvalue()))))
    out = tmp_path / "out"
    report = safearchive.safe_extract(str(src), str(out))
    assert {r["entry"] for r in report["rejected"]} == \
        {"../evil.txt"}
    assert [e["entry"] for e in report["extracted"]] == \
        ["ok.txt", "inner.zip"]
    assert report["nested_archives"] == ["inner.zip"]
    assert not (tmp_path / "evil.txt").exists()


def test_nar_input_extract_report_keys_raw(tmp_path):
    src = tmp_path / "in.zip"
    src.write_bytes(_zip_raw(_entries(
        ("..\\evil.txt", b"x"), ("ok.txt", b"y"))))
    out = tmp_path / "out"
    data = nar_input.cmd_extract(SimpleNamespace(
        target=str(src), out=str(out)))
    assert {r["entry"] for r in data["rejected"]} == \
        {"..\\evil.txt"}
    assert [e["entry"] for e in data["extracted"]] == \
        ["ok.txt"]
    assert list(tmp_path.rglob("evil.txt")) == []


# ----------------------------------------------------------
# nar-triage: contained APK/OBB rejection lists keyed RAW
# ----------------------------------------------------------

def test_triage_rejects_backslash_traversal_raw(tmp_path):
    target = tmp_path / "container.xapk"
    target.write_bytes(_zip_raw(_entries(
        ("../../outside.apk", b"x"),
        ("/abs.apk", b"x"),
        ("..\\win.apk", b"x"),
        ("base.apk", b"x"),
        ("../main.obb", b"x"),
        ("main.obb", b"x"))))
    report = triage.triage(str(target))
    assert [a["name"] for a in report["contained_apks"]] == \
        ["base.apk"]
    rejected = report["contained_apks_rejected"]
    assert [r["name"] for r in rejected] == [
        "../../outside.apk", "..\\win.apk", "/abs.apk"]
    assert all("travers" in r["reason"] for r in rejected)
    assert [o["name"] for o in report["contained_obbs"]] == \
        ["main.obb"]
    assert [r["name"] for r in
            report["contained_obbs_rejected"]] == \
        ["../main.obb"]


# ----------------------------------------------------------
# narlib.container: split_skipped / inventory keyed RAW
# ----------------------------------------------------------

def test_container_resolve_backslash_traversal_raw(tmp_path):
    target = tmp_path / "container.zip"
    target.write_bytes(_zip_raw(_entries(
        ("..\\evil.apk", b"x"),
        ("base.apk", b"base-payload"))))
    with container.resolve_target(str(target)) as resolved:
        assert resolved.base_entry == "base.apk"
        assert Path(resolved.base).read_bytes() == \
            b"base-payload"
        skipped = {s["name"]: s["reason"]
                   for s in resolved.split_skipped}
        assert "..\\evil.apk" in skipped
        assert "traverses" in skipped["..\\evil.apk"]
    assert list(tmp_path.rglob("evil.apk")) == []


def test_container_inventory_duplicates_raw_member(tmp_path):
    one = tmp_path / "one.zip"
    one.write_bytes(_zip_raw(_entries(
        ("dup\\same.bin", b"same-content"),
        ("big\\file.bin", b"0123456789" * 2))))
    two = tmp_path / "two.zip"
    two.write_bytes(_zip_raw(_entries(
        ("dup\\same.bin", b"same-content"))))
    result = container.inventory_duplicates(
        [str(one), str(two)], cap_bytes=16)
    # Oversized members are skipped-and-noted under the raw
    # stored name; duplicate locations cite it too.
    assert [s["member"] for s in
            result["skipped_oversized"]] == ["big\\file.bin"]
    groups = result["duplicate_groups"]
    assert len(groups) == 1
    assert [loc["member"] for loc in groups[0]["locations"]] \
        == ["dup\\same.bin", "dup\\same.bin"]


# ----------------------------------------------------------
# nar-analyze: extract_entry_record cites the RAW name
# ----------------------------------------------------------

def test_analyze_extract_entry_record_raw(tmp_path):
    root = tmp_path / "case"
    root.mkdir()
    zpath = tmp_path / "in.zip"
    zpath.write_bytes(_zip_raw(_entries(
        ("sub\\base.apk", b"payload"))))
    with zipfile.ZipFile(zpath) as zf:
        info = zf.infolist()[0]
        # The caller-side lookup name is the normalised
        # filename; the refusal record must still cite the
        # raw stored name.
        dest, rejection = az.extract_entry_record(
            zf, info.filename, str(root), "container",
            "../../../evil.apk")
        assert dest is None
        assert rejection["entry"] == "sub\\base.apk"
        assert "escapes" in rejection["reason"]
    assert not (tmp_path / "evil.apk").exists()
