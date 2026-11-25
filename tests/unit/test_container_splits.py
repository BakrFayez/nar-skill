"""Unit tests: container layer + split merge (3.0 Part 2).

narlib.container is the shared home of container detection,
the base-APK selection rule and split-set resolution; the
asset/native/dex stages consume the ResolvedTarget with
split merging on by default and byte-identical legacy
behaviour under --no-merge-splits.

Synthetic inputs only: tiny ZIP/XAPK fixtures built in-test,
no external fixtures, no app data.
"""
import importlib.util
import io
import json
import struct
import sys
import zipfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from narlib import container as C  # noqa: E402
from narlib.budget import ResourceBudget  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


nar_assets = _load("nar_assets_ct", "nar-assets.py")
nar_native = _load("nar_native_ct", "nar-native.py")
nar_dex = _load("nar_dex_ct", "nar-dex.py")
nar_triage = _load("nar_triage_ct", "nar-triage.py")


def _uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def build_dex():
    """Minimal DEX (same shape as test_dex_elf's builder)."""
    strings = [b"LFoo;", b"hello"]
    header_size = 0x70
    string_ids_off = header_size
    string_data_off = string_ids_off + 4 * len(strings)
    data = bytearray()
    offsets = []
    for s in strings:
        offsets.append(string_data_off + len(data))
        data += _uleb(len(s)) + s + b"\x00"
    type_ids_off = string_data_off + len(data)
    proto_ids_off = type_ids_off + 4
    method_ids_off = proto_ids_off + 12
    file_size = method_ids_off + 8
    out = bytearray(file_size)
    out[0:8] = b"dex\n039\x00"
    struct.pack_into("<I", out, 32, file_size)
    struct.pack_into("<I", out, 36, header_size)
    struct.pack_into("<I", out, 40, 0x12345678)
    struct.pack_into("<I", out, 56, len(strings))
    struct.pack_into("<I", out, 60, string_ids_off)
    struct.pack_into("<I", out, 64, 1)
    struct.pack_into("<I", out, 68, type_ids_off)
    struct.pack_into("<I", out, 72, 1)
    struct.pack_into("<I", out, 76, proto_ids_off)
    struct.pack_into("<I", out, 88, 1)
    struct.pack_into("<I", out, 92, method_ids_off)
    for i, off in enumerate(offsets):
        struct.pack_into("<I", out, string_ids_off + 4 * i, off)
    out[string_data_off:string_data_off + len(data)] = data
    struct.pack_into("<I", out, type_ids_off, 0)
    struct.pack_into("<III", out, proto_ids_off, 1, 0, 0)
    struct.pack_into("<HHI", out, method_ids_off, 0, 0, 1)
    return bytes(out)


def build_elf64(soname=b"libfoo.so", needed=b"libbar.so"):
    """Minimal ELF64 (same shape as test_native's builder)."""
    dynstr = b"\x00" + soname + b"\x00" + needed + b"\x00"
    ehdr_size, phdr_size = 64, 56
    phoff = ehdr_size
    dyn_off = phoff + 2 * phdr_size
    dynstr_off = dyn_off + 5 * 16
    file_size = dynstr_off + len(dynstr)
    base = 0x10000
    out = bytearray(file_size)
    out[0:4] = b"\x7fELF"
    out[4] = 2
    out[5] = 1
    struct.pack_into("<H", out, 16, 3)
    struct.pack_into("<H", out, 18, 183)
    struct.pack_into("<Q", out, 32, phoff)
    struct.pack_into("<H", out, 52, ehdr_size)
    struct.pack_into("<H", out, 54, phdr_size)
    struct.pack_into("<H", out, 56, 2)
    struct.pack_into("<IIQQQQQQ", out, phoff, 1, 5, 0, base,
                     base, file_size, file_size, 0x1000)
    struct.pack_into("<IIQQQQQQ", out, phoff + phdr_size, 2, 4,
                     dyn_off, base + dyn_off, base + dyn_off,
                     5 * 16, 5 * 16, 8)
    entries = [(14, 1), (1, 1 + len(soname) + 1),
               (5, base + dynstr_off), (10, len(dynstr)), (0, 0)]
    for i, (tag, val) in enumerate(entries):
        struct.pack_into("<qQ", out, dyn_off + i * 16, tag, val)
    out[dynstr_off:dynstr_off + len(dynstr)] = dynstr
    return bytes(out)


def _zip_bytes(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def _write(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def _apk(members):
    return _zip_bytes(members)


def _base_apk(extra=()):
    return _apk([("AndroidManifest.xml", b"<manifest/>"),
                 ("classes.dex", build_dex()),
                 ("resources.arsc", b"\x02\x00\x0c\x00"),
                 ("assets/base.txt", b"base asset")] + list(extra))


def _abi_split(extra=()):
    return _apk([("AndroidManifest.xml", b"<manifest/>"),
                 ("classes.dex", build_dex()),
                 ("assets/shared.txt", b"base asset"),
                 ("lib/armeabi-v7a/libfoo.so", build_elf64())]
                + list(extra))


def _xapk(tmp_path, name="set.xapk", manifest_extra=None,
          members_extra=()):
    manifest = {"package_name": "com.example.game",
                "split_apks": [
                    {"file": "com.example.game.apk",
                     "id": "base"},
                    {"file": "config.armeabi_v7a.apk",
                     "id": "config.armeabi_v7a"}]}
    if manifest_extra:
        manifest.update(manifest_extra)
    return _write(tmp_path, name, _zip_bytes([
        ("manifest.json", json.dumps(manifest).encode()),
        ("com.example.game.apk", _base_apk()),
        ("config.armeabi_v7a.apk", _abi_split()),
    ] + list(members_extra)))


# ------------------------------------------------------------------
# detection

def test_detect_each_kind(tmp_path):
    plain = _write(tmp_path, "app.apk", _base_apk())
    assert C.detect_container(plain) == "apk"
    aab = _write(tmp_path, "app.aab", _zip_bytes([
        ("base/manifest/AndroidManifest.xml", b"<m/>"),
        ("base/dex/classes.dex", build_dex())]))
    assert C.detect_container(aab) == "aab"
    apks = _write(tmp_path, "set.apks", _zip_bytes([
        ("toc.pb", b"\x00"),
        ("splits/base-master.apk", _base_apk()),
        ("splits/split_config.en.apk", _abi_split())]))
    assert C.detect_container(apks) == "apks"
    xapk = _xapk(tmp_path)
    assert C.detect_container(xapk) == "xapk"
    apkm = _xapk(tmp_path, name="set.apkm")
    assert C.detect_container(apkm) == "apkm"
    obb = _write(tmp_path, "main.1.com.example.game.obb",
                 _zip_bytes([("data.bin", b"x")]))
    assert C.detect_container(obb) == "obb"
    wrapper = _write(tmp_path, "bundle.zip", _zip_bytes([
        ("inner.apk", _base_apk()), ("readme.txt", b"hi")]))
    assert C.detect_container(wrapper) == "zip"
    unknown = _write(tmp_path, "blob.bin", b"not a zip at all")
    assert C.detect_container(unknown) == "unknown"


def test_detect_content_wins_over_extension(tmp_path):
    # A .zip holding an XAPK-shaped set is an XAPK container.
    disguised = _xapk(tmp_path, name="actually.zip")
    assert C.detect_container(disguised) == "xapk"
    # A .xapk holding a single plain APK layout is an APK.
    plain = _write(tmp_path, "actually.xapk", _base_apk())
    assert C.detect_container(plain) == "apk"


# ------------------------------------------------------------------
# base-selection rule

def test_pick_base_package_wins():
    contained = [{"name": "splits/base-master.apk",
                  "size_bytes": 100},
                 {"name": "com.example.game.apk",
                  "size_bytes": 50}]
    assert C.pick_base_apk(
        contained, package="com.example.game") == \
        "com.example.game.apk"


def test_pick_base_canonical_wins_over_larger_config():
    contained = [{"name": "splits/base-master.apk",
                  "size_bytes": 100},
                 {"name": "splits/split_config.en.apk",
                  "size_bytes": 300}]
    assert C.pick_base_apk(contained) == "splits/base-master.apk"


def test_pick_base_largest_non_config():
    contained = [{"name": "config.armeabi_v7a.apk",
                  "size_bytes": 900},
                 {"name": "game.apk", "size_bytes": 200},
                 {"name": "other.apk", "size_bytes": 100}]
    assert C.pick_base_apk(contained) == "game.apk"


def test_pick_base_container_stem_wins():
    contained = [{"name": "set.apk", "size_bytes": 10},
                 {"name": "com.example.game.apk",
                  "size_bytes": 50}]
    assert C.pick_base_apk(
        contained, package="com.example.game",
        container_stem="set") == "set.apk"


# ------------------------------------------------------------------
# resolution + merge behaviour

def test_resolve_xapk_merges_split(tmp_path):
    xapk = _xapk(tmp_path)
    with C.resolve_target(xapk) as r:
        assert r.input_kind == "xapk"
        assert r.base.endswith("com.example.game.apk")
        assert [s["name"] for s in r.splits] == \
            ["config.armeabi_v7a.apk"]
        assert r.splits[0]["kind"] == "config-abi"
        assert [m["name"] for m in r.splits_merged] == \
            ["config.armeabi_v7a.apk"]
        assert r.split_skipped == []
        assert len(r.assets_roots) == 2
        assert r.assets_roots[0] == r.base


def test_resolve_no_merge_records_skipped(tmp_path):
    xapk = _xapk(tmp_path)
    with C.resolve_target(xapk, merge_splits=False) as r:
        assert r.splits == []
        assert r.assets_roots == [r.base]
        assert len(r.split_skipped) == 1
        assert "merge disabled" in r.split_skipped[0]["reason"]


def test_resolve_missing_declared_split_is_named(tmp_path):
    xapk = _xapk(tmp_path, manifest_extra={
        "split_apks": [
            {"file": "com.example.game.apk", "id": "base"},
            {"file": "config.armeabi_v7a.apk",
             "id": "config.armeabi_v7a"},
            {"file": "config.xxhdpi.apk", "id": "config.xxhdpi"}]})
    with C.resolve_target(xapk) as r:
        skipped = {s["name"]: s["reason"]
                   for s in r.split_skipped}
        assert "config.xxhdpi.apk" in skipped
        assert "absent" in skipped["config.xxhdpi.apk"]


def test_three_level_nesting_resolves(tmp_path):
    xapk = _xapk(tmp_path, name="inner.xapk")
    outer = _write(tmp_path, "outer.zip", _zip_bytes([
        ("inner.xapk", Path(xapk).read_bytes()),
        ("readme.txt", b"hi")]))
    with C.resolve_target(outer) as r:
        assert r.input_kind == "zip"
        assert r.base.endswith("com.example.game.apk")
        assert [s["name"] for s in r.splits] == \
            ["config.armeabi_v7a.apk"]
    # The merged stages see the split's members through the
    # outer wrapper.
    assets = nar_assets.inventory(outer)
    assert assets["total_assets"] == 2
    assert assets["assets_by_split"][
        "config.armeabi_v7a.apk"] == 1
    native = nar_native.analyze(outer)
    assert native["native_library_count"] == 1
    assert native["libraries"][0]["source_split"] == \
        "config.armeabi_v7a.apk"


def test_obb_beside_target_inventoried(tmp_path):
    xapk = _xapk(tmp_path)
    (tmp_path / "main.7.com.example.game.obb").write_bytes(
        _zip_bytes([("data.bin", b"x")]))
    with C.resolve_target(xapk) as r:
        names = [o["name"] for o in r.obbs]
        assert "main.7.com.example.game.obb" in names


# ------------------------------------------------------------------
# consumers

def test_assets_merge_counts_and_provenance(tmp_path):
    xapk = _xapk(tmp_path)
    merged = nar_assets.inventory(xapk)
    assert merged["total_assets"] == 2
    assert merged["assets_by_split"] == {
        "com.example.game.apk": 1, "config.armeabi_v7a.apk": 1}
    by_split = {a["path"]: a["source_split"]
                for a in merged["assets"]}
    assert by_split["assets/base.txt"] == "com.example.game.apk"
    assert by_split["assets/shared.txt"] == \
        "config.armeabi_v7a.apk"
    assert merged["container"]["input_kind"] == "xapk"
    assert merged["container"]["splits_merged"][0]["name"] == \
        "config.armeabi_v7a.apk"
    # Same bytes in base and split: one duplicate group, two
    # locations (the delta detection).
    assert len(merged["duplicates"]) == 1
    dup = merged["duplicates"][0]
    assert dup["count"] == 2
    assert {loc["archive"] for loc in dup["locations"]} == {
        "com.example.game.apk", "config.armeabi_v7a.apk"}

    legacy = nar_assets.inventory(xapk, merge_splits=False)
    assert legacy["total_assets"] == 0
    assert "assets_by_split" not in legacy
    assert "container" not in legacy
    assert all("source_split" not in a for a in legacy["assets"])


def test_native_merge_counts_and_provenance(tmp_path):
    xapk = _xapk(tmp_path)
    merged = nar_native.analyze(xapk)
    assert merged["native_library_count"] == 1
    lib = merged["libraries"][0]
    assert lib["source_split"] == "config.armeabi_v7a.apk"
    assert merged["container"]["splits_merged"][0]["name"] == \
        "config.armeabi_v7a.apk"
    legacy = nar_native.analyze(xapk, merge_splits=False)
    assert len(legacy["libraries"]) == 0
    assert "native_library_count" not in legacy
    assert "container" not in legacy


def test_dex_includes_split_dexes(tmp_path):
    xapk = _xapk(tmp_path)
    report = nar_dex.analyze(xapk)
    names = [d["name"] for d in report["dex_files"]]
    assert "classes.dex" in names
    assert "config.armeabi_v7a.apk:classes.dex" in names
    assert report["container"]["input_kind"] == "xapk"


def test_triage_records_container_block(tmp_path):
    xapk = _xapk(tmp_path)
    report = nar_triage.triage(xapk)
    assert report["is_container"] is True
    block = report["container"]
    assert block["input_kind"] == "xapk"
    assert block["base"] == "com.example.game.apk"
    assert [s["name"] for s in block["splits_merged"]] == \
        ["config.armeabi_v7a.apk"]


def test_duplicate_detection_groups_once(tmp_path):
    xapk = _xapk(tmp_path)
    with C.resolve_target(xapk) as r:
        dup = C.inventory_duplicates(r.assets_roots)
    groups = {g["sha256"]: g for g in dup["duplicate_groups"]}
    # assets/shared.txt == assets/base.txt bytes, the two
    # manifests, the two DEXes and the two resources files
    # repeat across base+split; each group lists both
    # locations exactly once.
    assert dup["members_hashed"] > 0
    for g in groups.values():
        assert len(g["locations"]) == 2
        assert {loc["archive"] for loc in g["locations"]} == {
            "com.example.game.apk", "config.armeabi_v7a.apk"}
    shared = [g for g in groups.values()
              if any(loc["member"] == "assets/shared.txt"
                     for loc in g["locations"])]
    assert len(shared) == 1


def test_duplicate_detection_skips_oversized(tmp_path):
    big = _write(tmp_path, "big.apk", _apk([
        ("AndroidManifest.xml", b"<manifest/>"),
        ("classes.dex", build_dex()),
        ("assets/big.bin", b"\x00" * 2048)]))
    dup = C.inventory_duplicates([big], cap_bytes=1024)
    assert dup["skipped_oversized"]
    assert dup["skipped_oversized"][0]["member"] == \
        "assets/big.bin"


# ------------------------------------------------------------------
# hostile containers

def test_hostile_traversal_split_refused(tmp_path):
    evil = _write(tmp_path, "evil.xapk", _zip_bytes([
        ("manifest.json", json.dumps(
            {"package_name": "com.example.game"}).encode()),
        ("com.example.game.apk", _base_apk()),
        ("../evil.apk", _abi_split()),
        ("config.armeabi_v7a.apk", _abi_split())]))
    with C.resolve_target(evil) as r:
        skipped = {s["name"]: s["reason"]
                   for s in r.split_skipped}
        assert "../evil.apk" in skipped
        assert "traverses" in skipped["../evil.apk"]
        assert [s["name"] for s in r.splits] == \
            ["config.armeabi_v7a.apk"]


def test_hostile_oversized_split_refused_by_budget(tmp_path):
    xapk = _xapk(tmp_path)
    budget = ResourceBudget(max_file_bytes=256)
    with C.resolve_target(xapk, budget=budget) as r:
        # The base APK itself exceeds the tiny budget: the
        # resolution degrades to named skips, never a crash
        # and never a silent partial merge.
        assert r.splits == []
        assert r.split_skipped
        assert any("refused" in s["reason"]
                   for s in r.split_skipped)
