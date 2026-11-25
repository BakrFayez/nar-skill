"""2.6.2 Workstream A2: DEX fuzz regressions.

Every test here pins a distinct failure class found by the
mutation harness (tests/fuzz/dex_fuzz.py) or by the offset
audit that accompanied it. The invariant: malformed input
raises DexError (or, in dexdis, a per-method failed listing),
never IndexError / struct.error / ValueError / RecursionError
leaks, never an unbounded loop or allocation.

Synthetic inputs only, built from the repo's own builders.
"""
import importlib.util
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_dex_elf  # noqa: E402
from narlib import dexdis  # noqa: E402
from narlib.dex import Dex, DexError, _uleb128  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, str(Path(__file__).resolve().parent / filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


remed = _load("remed_for_fuzz_reg", "test_deep_audit_remediation.py")


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


def _with_class_and_annotation(encoded_annotation_body):
    """with-class DEX + an annotation directory whose single
    class annotation item carries the given encoded bytes."""
    good, cd_off, _if, _pa, _pr = remed.build_dex_with_class()
    data = bytearray(good)
    ann_dir_off = len(data)
    class_set_off = ann_dir_off + 16
    item_off = class_set_off + 8
    data += struct.pack("<IIII", class_set_off, 0, 0, 0)
    data += struct.pack("<II", 1, item_off)
    data += bytes([1]) + encoded_annotation_body
    struct.pack_into("<I", data, cd_off + 20, ann_dir_off)
    struct.pack_into("<I", data, 32, len(data))
    return bytes(data), cd_off


# ----------------------------------------------------------
# Fuzz finding F1: class_annotations struct.error leak
# ----------------------------------------------------------

def test_annotation_set_size_beyond_file_is_truncated_not_error():
    """The set size claims far more entries than the file can
    hold offset words for. Before the fix this leaked a bare
    struct.error from the offset-table walk."""
    good, cd_off, _if, _pa, _pr = remed.build_dex_with_class()
    data = bytearray(good)
    ann_dir_off = len(data)
    class_set_off = ann_dir_off + 16
    data += struct.pack("<IIII", class_set_off, 0, 0, 0)
    data += struct.pack("<II", 0x00FFFFFF, 0)  # absurd size
    struct.pack_into("<I", data, cd_off + 20, ann_dir_off)
    struct.pack_into("<I", data, 32, len(data))
    dex = Dex(bytes(data))
    out = dex.class_annotations(dex.class_defs()[0])
    assert out == [{"type": "?", "visibility": 0,
                    "elements": {}, "truncated": True}]


# ----------------------------------------------------------
# Audit finding A-DEX-1: encoded-value recursion depth
# ----------------------------------------------------------

def test_deeply_nested_encoded_array_raises_dexerror():
    """Thousands of nested encoded arrays (0x1C, size 1) in a
    few KB: the recursive decoder must stop at the depth cap
    with DexError, never RecursionError."""
    depth = 5000
    body = _uleb(0) + _uleb(1) + _uleb(1)  # type, size, name
    body += bytes([0x1C]) + _uleb(1)
    body *= 1
    payload = (bytes([0x1C]) + _uleb(1)) * depth + \
        bytes([0x1E])  # innermost: null
    body = _uleb(0) + _uleb(1) + _uleb(1) + payload
    data, _cd = _with_class_and_annotation(body)
    dex = Dex(data)
    out = dex.class_annotations(dex.class_defs()[0])
    # The malformed annotation surfaces as a truncated entry,
    # exactly like other unparseable annotation items.
    assert out and out[0].get("truncated") is True


def test_moderately_nested_encoded_array_still_parses():
    depth = 8
    payload = (bytes([0x1C]) + _uleb(1)) * depth + bytes([0x1E])
    body = _uleb(0) + _uleb(1) + _uleb(1) + payload
    data, _cd = _with_class_and_annotation(body)
    dex = Dex(data)
    out = dex.class_annotations(dex.class_defs()[0])
    assert len(out) == 1 and not out[0].get("truncated")
    value = out[0]["elements"]["hello"]
    for _ in range(depth):
        assert isinstance(value, list) and len(value) == 1
        value = value[0]
    assert value is None


# ----------------------------------------------------------
# Audit: offsets validated before access (targeted)
# ----------------------------------------------------------

def test_class_data_off_at_and_past_eof_raise_dexerror():
    good, cd_off, _if, _pa, _pr = remed.build_dex_with_class()
    for bad_off in (len(good), len(good) + 4096, 0x00FFFFFF):
        dex = Dex(good)
        with pytest.raises(DexError):
            list(dex.class_methods(bad_off))
        with pytest.raises(DexError):
            list(dex.class_fields(bad_off))
        with pytest.raises(DexError):
            list(dex.class_methods_indexed(bad_off))


def test_huge_class_data_counts_fail_at_eof_not_loop():
    """Class-data counts of 0xFFFFFFFF: each field/method step
    consumes at least one ULEB byte, so the walk must hit the
    end of the buffer and raise DexError promptly."""
    good, cd_off, _if, _pa, _pr = remed.build_dex_with_class()
    dex = Dex(good)
    defs = dex.class_defs()
    data_off = defs[0]["class_data_off"]
    data = bytearray(good)
    # class_data starts with four ULEB counts; blast the
    # first (static field count) to a 5-byte huge value.
    data[data_off:data_off + 1] = b"\xff\xff\xff\xff\x7f"
    dex = Dex(bytes(data))
    with pytest.raises(DexError):
        list(dex.class_fields(data_off))


def test_code_item_info_tries_beyond_file_is_truncated():
    """A code item whose try table runs past EOF is reported
    truncated by code_item_info, not raised as struct.error."""
    good = bytearray(test_dex_elf.build_dex())
    code_off = len(good)
    # regs, ins, outs, tries=4, debug=0, insns=0 -> the try
    # table would start at code_off+16 with no room for it.
    good += struct.pack("<HHHHII", 1, 0, 0, 4, 0, 0)
    dex = Dex(bytes(good))
    info = dex.code_item_info(code_off)
    assert info is not None
    assert info.get("tries_truncated") is True


def test_header_count_blast_rejected_at_construction():
    good = test_dex_elf.build_dex()
    for off, label in ((56, "string_ids"), (64, "type_ids"),
                       (72, "proto_ids"), (88, "method_ids")):
        data = bytearray(good)
        struct.pack_into("<I", data, off, 0x3FFFFFFF)
        with pytest.raises(DexError, match=label):
            Dex(bytes(data))


def test_dexdis_call_site_deep_nesting_fails_listing_not_crash():
    """dexdis encoded-value recursion gets the same depth cap:
    exercised directly through the resolver's decoder via a
    crafted call-site-free path -- the decoder itself must
    raise its _Fail, which call_site converts to a listing
    failure rather than a RecursionError."""
    dex = Dex(test_dex_elf.build_dex())
    resolver = dexdis._Resolver(dex)
    payload = (bytes([0x1C]) + _uleb(1)) * 5000 + bytes([0x1E])
    with pytest.raises(dexdis._Fail):
        resolver._enc_value(payload, 0)


def test_dexdis_enc_value_truncated_index_raises_fail():
    dex = Dex(test_dex_elf.build_dex())
    resolver = dexdis._Resolver(dex)
    # String index value claiming 4 bytes (arg=3) with only 1
    # byte present in the buffer.
    with pytest.raises(dexdis._Fail):
        resolver._enc_value(bytes([0x17 | (3 << 5), 0x01]), 0)


def test_uleb128_five_byte_cap_still_enforced():
    assert _uleb128(b"\xe5\x8e\x26", 0) == (624485, 3)
    with pytest.raises(DexError):
        _uleb128(b"\x80\x80\x80\x80\x80\x80", 0)
    with pytest.raises(DexError):
        _uleb128(b"\x80", 0)
