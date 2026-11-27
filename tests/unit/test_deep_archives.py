"""Unit tests for the Part 3.2 binary-archive deep dives:
nar-defold, nar-gamemaker, nar-renpy, nar-solar2d,
nar-heaps and nar-qt.

Every fixture is synthetic, built in-test byte-by-byte to
the layout each tool implements (the layouts come from
public format documentation; no real corpus files and no
real app/game names are used — all names are invented).
Golden assertions pin the parsed counts/facts; corrupt
variants pin the degrade-to-identification behaviour, and
a hostile Ren'Py pickle pins the restricted-unpickler
refusal (the payload must never execute).
"""
import importlib.util
import io
import json
import os
import pickle
import struct
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"


def _load(name):
    spec = importlib.util.spec_from_file_location(
        name.replace("-", "_"), SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


nar_defold = _load("nar-defold")
nar_gamemaker = _load("nar-gamemaker")
nar_renpy = _load("nar-renpy")
nar_solar2d = _load("nar-solar2d")
nar_heaps = _load("nar-heaps")
nar_qt = _load("nar-qt")

ALL_TOOLS = (nar_defold, nar_gamemaker, nar_renpy,
             nar_solar2d, nar_heaps, nar_qt)


def make_apk(members):
    """Write a temp APK (zip) from {member: bytes}; returns path."""
    fh = tempfile.NamedTemporaryFile(suffix=".apk", delete=False)
    fh.close()
    with zipfile.ZipFile(fh.name, "w") as zf:
        for name, blob in members.items():
            zf.writestr(name, blob)
    return fh.name


def make_file(suffix, blob):
    fh = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    fh.write(blob)
    fh.close()
    return fh.name


EMPTY_APK_MEMBERS = {
    "AndroidManifest.xml": b"\x03\x00\x08\x00" + b"\x00" * 32,
    "classes.dex": b"dex\n035\x00" + b"\x00" * 32,
}


# ------------------------------------------------------------------
# Defold

def build_arci(entries, version=6):
    header = struct.pack("<IIQI", version, 0, 0, len(entries))
    body = b"".join(struct.pack("<QIII", *e) for e in entries)
    return header + body


DEFOLD_ENTRIES = [
    (0x1111, 0, 50, 0),
    (0x2222, 50, 30, 1),   # compressed flag bit
    (0x3333, 80, 20, 2),   # encrypted flag bit
]


class TestDefold(unittest.TestCase):
    def test_valid_pair_counts(self):
        arcd = b"\xAB" * 200
        apk = make_apk({
            "assets/game.arci": build_arci(DEFOLD_ENTRIES),
            "assets/game.arcd": arcd,
            "assets/game.projectc": b"compiled project",
            "assets/game.dmanifest": b"manifest",
            "assets/liveupdate/pack.zip": b"PK\x03\x04",
        })
        report = nar_defold.inspect(apk)
        self.assertEqual(report["verdict"], "present")
        arch = report["archive"]
        self.assertEqual(arch["version"], 6)
        self.assertEqual(arch["arcd_size"], 200)
        entries = arch["entries"]
        self.assertIsNotNone(entries)
        self.assertEqual(entries["count"], 3)
        self.assertEqual(entries["total_payload_bytes"], 100)
        self.assertEqual(entries["compressed_count"], 1)
        self.assertEqual(entries["encrypted_count"], 1)
        self.assertEqual(entries["largest"][0]["size"], 50)
        self.assertEqual(entries["largest"][0]["hash"],
                         "0000000000001111")
        pf = report["project_files"]
        self.assertEqual(pf["game_projectc"],
                         ["assets/game.projectc"])
        self.assertEqual(pf["game_dmanifest"],
                         ["assets/game.dmanifest"])
        self.assertEqual(pf["liveupdate_members"],
                         ["assets/liveupdate/pack.zip"])
        self.assertIn("NOT recoverable", report["boundary"])

    def test_bare_arci_with_sibling_arcd(self):
        with tempfile.TemporaryDirectory() as td:
            arci = os.path.join(td, "game.arci")
            with open(arci, "wb") as fh:
                fh.write(build_arci(DEFOLD_ENTRIES))
            with open(os.path.join(td, "game.arcd"), "wb") as fh:
                fh.write(b"\x00" * 200)
            report = nar_defold.inspect(arci)
        self.assertEqual(report["verdict"], "present")
        self.assertEqual(report["archive"]["entries"]["count"], 3)

    def test_corrupt_offset_walk_fails_without_crash(self):
        bad = [(0x1111, 0, 50, 0), (0x2222, 10000, 50, 0)]
        apk = make_apk({
            "assets/game.arci": build_arci(bad),
            "assets/game.arcd": b"\x00" * 200,
        })
        report = nar_defold.inspect(apk)
        arch = report["archive"]
        self.assertEqual(report["verdict"], "present")
        self.assertIsNone(arch["entries"])
        self.assertIn("exceeds", arch["walk_failed"])
        self.assertEqual(arch["version"], 6)


# ------------------------------------------------------------------
# GameMaker

def build_data_win():
    strings = [b"Alpha Quest", b"hello world", b"score!"]
    gen8_content_len = 24
    gen8_total = 8 + gen8_content_len
    strg_chunk_at = 8 + gen8_total
    strg_data = strg_chunk_at + 8
    cursor = strg_data + 4 + 4 * len(strings)
    offsets = []
    blob = bytearray()
    for s in strings:
        offsets.append(cursor)
        enc = struct.pack("<I", len(s)) + s
        enc += b"\x00" * ((4 - len(enc) % 4) % 4)
        blob += enc
        cursor += len(enc)
    strg_content = struct.pack("<I", len(strings)) + b"".join(
        struct.pack("<I", o) for o in offsets) + bytes(blob)
    strg_chunk = (b"STRG" + struct.pack("<I", 8 + len(strg_content))
                  + strg_content)
    gen8_content = struct.pack("<III", 0, 0, offsets[0]) + \
        b"\x00" * (gen8_content_len - 12)
    gen8_chunk = (b"GEN8" + struct.pack("<I", 8 + len(gen8_content))
                  + gen8_content)
    txtr = b"TXTR" + struct.pack("<I", 20) + struct.pack("<I", 2) \
        + b"\x00" * 8
    audo = b"AUDO" + struct.pack("<I", 16) + struct.pack("<I", 1) \
        + b"\x00" * 4
    sprt = b"SPRT" + struct.pack("<I", 16) + struct.pack("<I", 4) \
        + b"\x00" * 4
    body = gen8_chunk + strg_chunk + txtr + audo + sprt
    return b"FORM" + struct.pack("<I", len(body)) + body


class TestGameMaker(unittest.TestCase):
    def test_form_gen8_strg_counts(self):
        apk = make_apk({"assets/data.win": build_data_win()})
        report = nar_gamemaker.inspect(apk)
        self.assertEqual(report["verdict"], "present")
        self.assertEqual([c["name"] for c in report["chunks"]],
                         ["GEN8", "STRG", "TXTR", "AUDO", "SPRT"])
        self.assertEqual(report["gen8"]["game_name"], "Alpha Quest")
        self.assertIn("+8", report["gen8"]["name_basis"])
        self.assertEqual(report["strings"]["count"], 3)
        self.assertEqual(report["strings"]["sample"],
                         ["Alpha Quest", "hello world", "score!"])
        self.assertEqual(report["strings"]["total_chars"], 28)
        self.assertEqual(report["counts"],
                         {"textures": 2, "audio": 1, "sprites": 4})

    def test_bare_data_win(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "data.win")
            with open(path, "wb") as fh:
                fh.write(build_data_win())
            report = nar_gamemaker.inspect(path)
        self.assertEqual(report["verdict"], "present")
        self.assertEqual(report["gen8"]["game_name"], "Alpha Quest")


# ------------------------------------------------------------------
# Ren'Py

def build_rpa(index_obj, key=0x12345678, version="3.0",
              index_offset=256):
    # Protocol 4 encodes bytes natively (BINBYTES), so the
    # benign fixture carries no GLOBAL/REDUCE opcodes; the
    # hostile fixture below deliberately uses a reduce-based
    # pickle, which the tool must refuse.
    comp = zlib.compress(pickle.dumps(index_obj, protocol=4))
    if version == "3.0":
        header = f"RPA-3.0 {index_offset:016x} {key:08x}\n"
    else:
        header = f"RPA-{version} {index_offset:016x}\n"
    blob = bytearray(b"\x00" * index_offset)
    blob[:len(header)] = header.encode("ascii")
    return bytes(blob) + comp


class TestRenPy(unittest.TestCase):
    def test_rpa3_listing_with_key_xor(self):
        key = 0x12345678
        index = {
            "a.txt": [(100 ^ key, 11 ^ key, b"")],
            "dir/b.png": [(120 ^ key, 7 ^ key, b"")],
        }
        apk = make_apk({"assets/archive.rpa": build_rpa(index, key)})
        report = nar_renpy.inspect(apk)
        self.assertEqual(report["verdict"], "present")
        self.assertEqual(report["archive"]["version"], "3.0")
        self.assertTrue(report["archive"]["key_present"])
        self.assertEqual(report["archive"]["index_offset"], 256)
        files = report["files"]
        self.assertEqual(files["count"], 2)
        self.assertEqual(files["total_bytes"], 18)
        self.assertEqual(files["by_ext"], {".png": 1, ".txt": 1})
        self.assertEqual(files["sample"], ["a.txt", "dir/b.png"])

    def test_hostile_pickle_refused_and_never_executed(self):
        with tempfile.TemporaryDirectory() as td:
            sentinel = os.path.join(td, "pwned.txt")

            class Evil:
                def __reduce__(self):
                    return (os.system, (f"touch {sentinel}",))

            blob = build_rpa_raw_pickle(
                pickle.dumps(Evil(), protocol=2))
            path = make_file(".rpa", blob)
            report = nar_renpy.inspect(path)
            self.assertEqual(report["verdict"], "present")
            self.assertIsNone(report["files"])
            error = report["archives"][0]["error"]
            self.assertIn("pickle refused", error)
            self.assertIn("GLOBAL", error)
            self.assertFalse(os.path.exists(sentinel))

    def test_rpyc_identification_and_slots(self):
        s1 = zlib.compress(b"slot-one")
        s2 = zlib.compress(b"slot-two-data")
        blob = (b"RENPY RPC2" + struct.pack("<I", len(s1)) + s1
                + struct.pack("<I", len(s2)) + s2)
        path = make_file(".rpyc", blob)
        report = nar_renpy.inspect(path)
        self.assertEqual(report["verdict"], "present")
        rec = report["rpyc"][0]
        self.assertTrue(rec["magic_ok"])
        self.assertEqual(rec["slot_count"], 2)
        self.assertEqual(rec["slot_sizes"], [len(s1), len(s2)])
        self.assertIn("not decompiled", rec["note"])


def build_rpa_raw_pickle(pickled, index_offset=256):
    comp = zlib.compress(pickled)
    header = f"RPA-3.0 {index_offset:016x} {0:08x}\n"
    blob = bytearray(b"\x00" * index_offset)
    blob[:len(header)] = header.encode("ascii")
    return bytes(blob) + comp


# ------------------------------------------------------------------
# Solar2D

def build_car_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "config.lua",
            'application = { content = { scale = "letterbox", '
            'fps = 60 } }\n'
            'orientation = { default = "portrait" }\n')
        zf.writestr("build.settings", "settings = {}\n")
        zf.writestr("main.lua", "print('hi')\n")
        zf.writestr("level1.luac", b"\x1bLua\x51\x00fakebytecode")
        zf.writestr("module", b"\x1bLua\x51\x00morebytecode")
        zf.writestr("img.png", b"\x89PNG\r\n\x1a\n....")
    return buf.getvalue()


class TestSolar2D(unittest.TestCase):
    def test_zip_car_census_and_textual_facts(self):
        apk = make_apk({
            "assets/resource.car": build_car_zip(),
            "lib/armeabi-v7a/libcorona.so": b"\x7fELF fake",
        })
        report = nar_solar2d.inspect(apk)
        self.assertEqual(report["verdict"], "present")
        self.assertTrue(report["cars"][0]["is_zip"])
        listing = report["listing"]
        self.assertEqual(listing["count"], 6)
        self.assertEqual(listing["by_ext"][".lua"], 2)
        self.assertEqual(listing["by_ext"][".luac"], 1)
        self.assertEqual(listing["by_ext"]["(none)"], 1)
        facts = report["config"]["config.lua"]
        self.assertEqual(facts["orientation_default"], "portrait")
        self.assertEqual(facts["content_scale"], "letterbox")
        self.assertEqual(facts["content_fps"], 60)
        self.assertEqual(report["compiled_lua"]["luac_count"], 1)
        self.assertEqual(
            report["compiled_lua"]["extensionless_bytecode_count"], 1)
        self.assertEqual(report["compiled_lua"]["total"], 2)
        self.assertTrue(report["markers"]["libcorona_present"])
        self.assertEqual(report["markers"]["libcorona_so"],
                         ["lib/armeabi-v7a/libcorona.so"])

    def test_non_zip_car_is_identification_only(self):
        blob = bytes(range(64))
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "resource.car")
            with open(path, "wb") as fh:
                fh.write(blob)
            report = nar_solar2d.inspect(path)
        self.assertEqual(report["verdict"], "present")
        car = report["cars"][0]
        self.assertFalse(car["is_zip"])
        self.assertEqual(car["header_hex"], blob[:16].hex())
        self.assertIn("non-ZIP car variant", car["note"])


# ------------------------------------------------------------------
# Heaps / HashLink

def uindex(value):
    """Independent uindex encoder (documented encoding):
    base-128 big-endian groups, high bit on all but the
    last byte."""
    groups = []
    v = value
    while True:
        groups.append(v & 0x7F)
        v >>= 7
        if not v:
            break
    groups.reverse()
    out = bytearray()
    for i, g in enumerate(groups):
        out.append(g | 0x80 if i < len(groups) - 1 else g)
    if len(out) > 1:
        out[0] |= 0x80
    return bytes(out)


class TestHeaps(unittest.TestCase):
    def test_hlb_header_multibyte_uindex(self):
        blob = b"HLB" + uindex(291) + uindex(1) + b"\x00" * 8
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "hlboot.dat")
            with open(path, "wb") as fh:
                fh.write(blob)
            report = nar_heaps.inspect(path)
        self.assertEqual(report["verdict"], "present")
        self.assertEqual(report["header"]["version"], 291)
        self.assertEqual(report["header"]["flags"], 1)
        self.assertIsNone(report["header"]["section_counts"])
        self.assertIn("not validated",
                      report["header"]["section_counts_reason"])

    def test_hlb_header_in_apk(self):
        blob = b"HLB" + uindex(4) + uindex(300) + b"\x00" * 8
        apk = make_apk({"assets/hlboot.dat": blob})
        report = nar_heaps.inspect(apk)
        self.assertEqual(report["verdict"], "present")
        self.assertEqual(report["files"][0]["version"], 4)
        self.assertEqual(report["files"][0]["flags"], 300)
        census = [c["member"] for c in report["census"]]
        self.assertIn("assets/hlboot.dat", census)


# ------------------------------------------------------------------
# Qt RCC

def build_rcc():
    def name_entry(s):
        return struct.pack(">HI", len(s), 0) + s.encode("utf-16-be")

    names = {}
    names_blob = bytearray()
    for nm in ("", "mydir", "a.txt", "b.bin"):
        names[nm] = len(names_blob)
        names_blob += name_entry(nm)
    a_payload = b"hello qt"
    a_entry = struct.pack(">I", len(a_payload)) + a_payload
    b_raw = b"compressed-payload-data"
    b_inner = struct.pack(">I", len(b_raw)) + zlib.compress(b_raw)
    b_entry = struct.pack(">I", len(b_inner)) + b_inner
    data_blob = a_entry + b_entry

    def node(name, flags, data_off, child_count, first_child):
        return struct.pack(">IHHHIII", names[name], flags, 0, 0,
                           data_off, child_count, first_child)

    tree = b"".join([
        node("", 0x01, 0, 2, 1),          # root dir
        node("mydir", 0x01, 0, 1, 3),     # directory
        node("a.txt", 0x00, 0, 0, 0),     # plain file
        node("b.bin", 0x02, len(a_entry), 0, 0),  # compressed
    ])
    tree_off = 20
    names_off = tree_off + len(tree)
    data_off = names_off + len(names_blob)
    header = struct.pack(">IIIII", 0x71726573, 1, tree_off,
                         data_off, names_off)
    return header + tree + bytes(names_blob) + data_blob, {
        "a_size": len(a_payload), "b_size": len(b_inner),
        "b_raw_size": len(b_raw)}


class TestQt(unittest.TestCase):
    def test_rcc_tree_walk(self):
        blob, sizes = build_rcc()
        apk = make_apk({
            "assets/resources.rcc": blob,
            "assets/main.qmlc": b"\x00\x01\x02\x03\x04\x05\x06\x07"
                                b"extra",
        })
        report = nar_qt.inspect(apk)
        self.assertEqual(report["verdict"], "present")
        arch = report["archives"][0]
        self.assertTrue(arch["header"]["magic_ok"])
        self.assertEqual(arch["header"]["version"], 1)
        self.assertIsNone(arch["walk_failed"])
        by_path = {r["path"]: r for r in report["resources"]}
        self.assertEqual(set(by_path), {"a.txt", "mydir/b.bin"})
        self.assertEqual(by_path["a.txt"]["size"], sizes["a_size"])
        self.assertFalse(by_path["a.txt"]["compressed"])
        self.assertEqual(by_path["mydir/b.bin"]["size"],
                         sizes["b_size"])
        self.assertTrue(by_path["mydir/b.bin"]["compressed"])
        self.assertEqual(
            by_path["mydir/b.bin"]["uncompressed_size"],
            sizes["b_raw_size"])
        self.assertEqual(report["totals"]["resource_count"], 2)
        identified = report["identified"]
        self.assertEqual(len(identified), 1)
        self.assertEqual(identified[0]["kind"], "qmlc")
        self.assertEqual(identified[0]["first8_hex"],
                         "0001020304050607")

    def test_bare_rcc(self):
        blob, _sizes = build_rcc()
        path = make_file(".rcc", blob)
        report = nar_qt.inspect(path)
        self.assertEqual(report["verdict"], "present")
        self.assertEqual(report["totals"]["resource_count"], 2)


# ------------------------------------------------------------------
# Absent controls + CLI contract

class TestAbsentAndCli(unittest.TestCase):
    def test_absent_controls(self):
        apk = make_apk(EMPTY_APK_MEMBERS)
        for mod in ALL_TOOLS:
            with self.subTest(tool=mod.__name__):
                report = mod.inspect(apk)
                self.assertEqual(report["verdict"], "absent")
                self.assertEqual(report["version"], "3.0.2")
                self.assertIn("container", report)

    def test_nonexistent_target_exit_2(self):
        missing = os.path.join(tempfile.gettempdir(),
                               "nar-definitely-missing-target.apk")
        self.assertFalse(os.path.exists(missing))
        for mod in ALL_TOOLS:
            with self.subTest(tool=mod.__name__):
                self.assertEqual(mod.main([missing, "--json"]), 2)

    def test_json_cli_shape(self):
        import contextlib
        apk = make_apk(EMPTY_APK_MEMBERS)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = nar_qt.main([apk, "--json"])
        self.assertEqual(rc, 0)
        doc = json.loads(buf.getvalue())
        self.assertEqual(doc["tool"], "nar-qt")
        self.assertEqual(doc["verdict"], "absent")


if __name__ == "__main__":
    unittest.main()
