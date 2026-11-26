"""Certification A1-05 (Confirmed Bug, P3): the container
manifest read must be capped.

narlib.container.container_manifest_of read manifest.json
with a bare ``zf.read()`` -- an unbounded whole-member
decompression that bypassed the capped-reader / budget
discipline used everywhere else (narlib.safearchive's
``read_member_capped`` under the shared ResourceBudget).
A hostile container whose manifest.json inflates enormously
was fully materialised in memory during resolution, before
any budget check applied.

Regression shape: a container whose manifest.json member's
decompressed size exceeds the member cap must be REFUSED
with a NAMED record (a ``manifest.json`` entry in
``split_skipped`` whose reason names the cap), the manifest
identity must not be used (package falls back to the
no-manifest base pick), and the member must never be
materialised whole. A normal small manifest must resolve
byte-for-byte identically to before.

The fixture stays just over a small cap (driven through the
pre-existing ResourceBudget surface and the module cap
constant) so the unfixed failure is a clean assertion
failure, not an OOM.

Synthetic inputs only: tiny ZIP/XAPK fixtures built in-test.
"""
import io
import json
import sys
import zipfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from narlib import container as C  # noqa: E402
from narlib.budget import ResourceBudget  # noqa: E402

PACKAGE = "com.example.oversize"
SMALL_CAP = 1024


def _zip_bytes(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def _apk(payload=b""):
    return _zip_bytes([
        ("AndroidManifest.xml", b"<manifest/>"),
        ("resources.arsc", b"\x02\x00\x0c\x00"),
        ("assets/payload.bin", payload)])


def _manifest(padding=0):
    doc = {"package_name": PACKAGE,
           "version_name": "1.0",
           "split_apks": [
               {"file": f"{PACKAGE}.apk", "id": "base"},
               {"file": "zzz-large.apk", "id": "other"}]}
    if padding:
        doc["padding"] = "x" * padding
    return json.dumps(doc).encode()


def _xapk(tmp_path, manifest):
    """XAPK whose base pick DEPENDS on the manifest: the
    container stem ("bundle") matches no member and there is
    no canonical base name, so with the manifest the package
    rule picks the small PACKAGE apk, and without it the
    fallback picks the largest non-config apk."""
    path = tmp_path / "bundle.xapk"
    path.write_bytes(_zip_bytes([
        ("manifest.json", manifest),
        (f"{PACKAGE}.apk", _apk()),
        ("zzz-large.apk", _apk(b"z" * 4096)),
    ]))
    return str(path)


def _manifest_records(resolved):
    return [s for s in resolved.split_skipped
            if s["name"] == "manifest.json"]


# ------------------------------------------------------------------
# oversized manifest: refused with a named record

def test_oversized_manifest_refused_via_module_cap(tmp_path,
                                                  monkeypatch):
    # Just over the cap: ~6 KB manifest against a 1 KB cap.
    xapk = _xapk(tmp_path, _manifest(padding=6000))
    monkeypatch.setattr(C, "MANIFEST_READ_CAP_BYTES",
                        SMALL_CAP, raising=False)
    with C.resolve_target(xapk) as r:
        # The manifest identity was NOT used.
        assert r.package is None
        assert r.base_entry == "zzz-large.apk"
        # A named refusal record exists and names the cap.
        records = _manifest_records(r)
        assert len(records) == 1
        assert "cap" in records[0]["reason"]
        assert "manifest" in records[0]["reason"]


def test_oversized_manifest_refused_via_budget(tmp_path):
    # Same refusal driven through the shared ResourceBudget
    # (the budget's per-member cap), the surface
    # resolve_target already accepted before the fix.
    xapk = _xapk(tmp_path, _manifest(padding=6000))
    budget = ResourceBudget(max_file_bytes=SMALL_CAP)
    with C.resolve_target(xapk, budget=budget) as r:
        assert r.package is None
        assert r.base_entry == "zzz-large.apk"
        records = _manifest_records(r)
        assert len(records) == 1
        assert "cap" in records[0]["reason"]


def test_oversized_manifest_helper_returns_none(tmp_path,
                                                monkeypatch):
    xapk = _xapk(tmp_path, _manifest(padding=6000))
    monkeypatch.setattr(C, "MANIFEST_READ_CAP_BYTES",
                        SMALL_CAP, raising=False)
    with zipfile.ZipFile(xapk) as zf:
        assert C.container_manifest_of(zf) is None


def test_oversized_manifest_resolution_block_records(tmp_path,
                                                     monkeypatch):
    xapk = _xapk(tmp_path, _manifest(padding=6000))
    monkeypatch.setattr(C, "MANIFEST_READ_CAP_BYTES",
                        SMALL_CAP, raising=False)
    block = C.resolution_block(xapk)
    assert block is not None
    assert block["base_entry"] == "zzz-large.apk"
    records = [s for s in block["split_skipped"]
               if s["name"] == "manifest.json"]
    assert len(records) == 1
    assert "cap" in records[0]["reason"]


# ------------------------------------------------------------------
# normal manifest: unchanged behaviour

def test_normal_manifest_resolves_identically(tmp_path):
    xapk = _xapk(tmp_path, _manifest())
    with zipfile.ZipFile(xapk) as zf:
        info = C.container_manifest_of(zf)
    assert info == {
        "package": PACKAGE,
        "version_name": "1.0",
        "split_apks": [
            {"file": f"{PACKAGE}.apk", "id": "base"},
            {"file": "zzz-large.apk", "id": "other"}]}
    with C.resolve_target(xapk) as r:
        assert r.package == PACKAGE
        assert r.base_entry == f"{PACKAGE}.apk"
        assert r.base.endswith(f"{PACKAGE}.apk")
        assert _manifest_records(r) == []
        assert [s["name"] for s in r.splits] == ["zzz-large.apk"]
    block = C.resolution_block(xapk)
    assert block["base_entry"] == f"{PACKAGE}.apk"
    assert block["split_skipped"] == []


# ------------------------------------------------------------------
# sibling location: nar-triage fallback copy (A1-05 follow-up)
#
# scripts/nar-triage.py carries a FALLBACK copy of
# container_manifest_of, used only when the narlib import
# fails (_container_mod is None). It cannot import
# narlib.safearchive, so it must enforce the same 256 MiB
# discipline locally under its own cap constant
# (MANIFEST_READ_CAP_BYTES in the triage module): check the
# member's declared ZipInfo.file_size before reading, and
# read in bounded chunks stopping at the cap when the
# streamed size exceeds it (declared size understated).
# Refusal behaves exactly as the fallback does for an
# absent/corrupt manifest: return None.

import importlib.util  # noqa: E402


def _load_triage_fallback():
    spec = importlib.util.spec_from_file_location(
        "nar_triage_a105_fallback", SCRIPTS / "nar-triage.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


nar_triage = _load_triage_fallback()


class _LyingZip:
    """Minimal ZipFile stand-in whose manifest member
    DECLARES a small size but streams far more (the
    declared-size-lie case the streamed cap exists for).
    ``read`` is provided so the unfixed fallback, which
    uses bare ``zf.read()``, runs against it too."""

    def __init__(self, payload, declared_size):
        self._payload = payload
        self._declared = declared_size

    def namelist(self):
        return ["manifest.json"]

    def getinfo(self, name):
        assert name == "manifest.json"
        return type("Info", (), {"file_size": self._declared,
                                 "filename": name})()

    def open(self, name):
        assert name == "manifest.json"
        return io.BytesIO(self._payload)

    def read(self, name):
        assert name == "manifest.json"
        return self._payload


class TestTriageFallbackManifestCap:

    def _force_fallback(self, monkeypatch, cap=SMALL_CAP):
        monkeypatch.setattr(nar_triage, "_container_mod", None)
        monkeypatch.setattr(nar_triage,
                            "MANIFEST_READ_CAP_BYTES", cap,
                            raising=False)

    def test_fallback_oversized_manifest_refused(self, tmp_path,
                                                 monkeypatch):
        # Declared size just over the driven-down cap:
        # ~6 KB manifest against a 1 KB cap.
        self._force_fallback(monkeypatch)
        xapk = _xapk(tmp_path, _manifest(padding=6000))
        with zipfile.ZipFile(xapk) as zf:
            assert nar_triage.container_manifest_of(zf) is None

    def test_fallback_streamed_oversize_refused(self, monkeypatch):
        # Declared size lies (10 bytes, under the cap) but
        # the member streams ~6 KB: the bounded-chunk read
        # must stop at the cap and refuse, not materialise
        # and parse the whole member.
        self._force_fallback(monkeypatch)
        lying = _LyingZip(_manifest(padding=6000),
                          declared_size=10)
        assert nar_triage.container_manifest_of(lying) is None

    def test_fallback_normal_manifest_identical(self, tmp_path,
                                                monkeypatch):
        self._force_fallback(monkeypatch,
                             cap=256 * 1024 * 1024)
        xapk = _xapk(tmp_path, _manifest())
        with zipfile.ZipFile(xapk) as zf:
            info = nar_triage.container_manifest_of(zf)
        assert info == {
            "package": PACKAGE,
            "version_name": "1.0",
            "split_apks": [
                {"file": f"{PACKAGE}.apk", "id": "base"},
                {"file": "zzz-large.apk", "id": "other"}]}

    def test_fallback_absent_and_corrupt_unchanged(self, tmp_path,
                                                   monkeypatch):
        self._force_fallback(monkeypatch)
        absent = tmp_path / "absent.xapk"
        absent.write_bytes(_zip_bytes(
            [(f"{PACKAGE}.apk", _apk())]))
        with zipfile.ZipFile(str(absent)) as zf:
            assert nar_triage.container_manifest_of(zf) is None
        corrupt = tmp_path / "corrupt.xapk"
        corrupt.write_bytes(_zip_bytes(
            [("manifest.json", b"{not json"),
             (f"{PACKAGE}.apk", _apk())]))
        with zipfile.ZipFile(str(corrupt)) as zf:
            assert nar_triage.container_manifest_of(zf) is None
