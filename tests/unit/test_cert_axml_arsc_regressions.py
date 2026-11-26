"""Regression tests for the Phase 3 AXML/ARSC fuzz findings.

The ARSC finding (tests/fuzz/axml_fuzz.py, seed 11): the
resources.arsc string lookup in nar-app read the package
chunk's fixed fields (type/key string-pool offsets at
+268/+276) and the type chunk's entry-offset table without
bounds discipline, so a truncated or offset-blasted blob
leaked a bare struct.error out of _arsc_lookup instead of
honouring its string-or-None contract (111 distinct
artifacts in the pre-fix sweep, one root cause; repro
artifacts preserved with the Phase 3 evidence). The lookup
now skips a malformed package by name (internally) and
returns None / another package's string.

The cases below construct the failing shapes synthetically
from the repo's own ARSC builder -- no fuzz artifacts are
loaded.
"""
import importlib.util
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


nar_app = _load("nar_app_regr", ROOT / "scripts" / "nar-app.py")
_phase2_app = _load("phase2_app_regr",
                    ROOT / "tests" / "unit" / "test_phase2_app.py")
make_arsc = _phase2_app.make_arsc

PROBE_IDS = (0x7F010000, 0x7F020000, 0x7F01FFFF, 0xFFFFFFFF, 0)


def test_arsc_control_still_resolves():
    data = make_arsc("Synthetic App")
    assert nar_app._arsc_lookup(data, 0x7F010000) == "Synthetic App"


def test_arsc_every_truncation_is_named_none_or_string():
    """The pre-fix sweep's dominant shape: every prefix of
    the valid blob must come back as a string or None,
    never a struct.error / IndexError escape."""
    data = make_arsc("Synthetic App")
    for cut in range(len(data) + 1):
        for res_id in PROBE_IDS:
            out = nar_app._arsc_lookup(data[:cut], res_id)
            assert out is None or isinstance(out, str), \
                (cut, res_id, out)


def test_arsc_package_field_blasts_do_not_escape():
    """Offset/count blasts at the package chunk's fixed
    fields and the type chunk's entry table."""
    data = make_arsc("Synthetic App")
    # Locate the package chunk (type 0x0200) and its type
    # chunk (0x0201) by walking the chunk table.
    pkg_off = None
    off = struct.unpack_from("<H", data, 2)[0]
    end = struct.unpack_from("<I", data, 4)[0]
    while off + 8 <= end:
        ctype, _h, csize = struct.unpack_from("<HHI", data, off)
        if ctype == 0x0200:
            pkg_off = off
            break
        off += csize
    assert pkg_off is not None
    phdr = struct.unpack_from("<H", data, pkg_off + 2)[0]
    type_off = pkg_off + phdr
    blasts = []
    for field in (268, 276, 284):  # type/key pools, id offset
        for value in (0, 0x7FFFFFFF, 0xFFFFFFFF):
            buf = bytearray(data)
            struct.pack_into("<I", buf, pkg_off + field, value)
            blasts.append(bytes(buf))
    for field, fmt, value in (
            (12, "<I", 0xFFFFFFFF),   # type entry count
            (12, "<I", 0x7FFFFFFF),
            (16, "<I", 0xFFFFFFFF),   # type entries start
            (20, "<I", 0xFFFFFFFF)):  # config size
        buf = bytearray(data)
        struct.pack_into(fmt, buf, type_off + field, value)
        blasts.append(bytes(buf))
    # Entry-offset table entry blasted past the file end.
    chdr = struct.unpack_from("<H", data, type_off + 2)[0]
    buf = bytearray(data)
    struct.pack_into("<I", buf, type_off + chdr, 0xFFFFFFF0)
    blasts.append(bytes(buf))
    for mutant in blasts:
        for res_id in PROBE_IDS:
            out = nar_app._arsc_lookup(mutant, res_id)
            assert out is None or isinstance(out, str)
