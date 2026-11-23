"""Unit tests for nar-native.py's report assembly.

Regression coverage: an APK that bundles non-ELF payloads under
.so names (ZIP archives shipped as *.zip.so) produces per-library
error entries; building the dependency graph / JNI map over the
mixed entry list must not crash with KeyError: 'display_name'.
Synthetic inputs only: no external fixtures, no app data.
"""
import importlib.util
import io
import struct
import sys
import zipfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))

_spec = importlib.util.spec_from_file_location(
    "nar_native", SCRIPTS / "nar-native.py")
nar_native = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nar_native)


def build_elf64(soname=b"libfoo.so", needed=b"libbar.so"):
    """Minimal ELF64 LE AArch64 with SONAME + one DT_NEEDED."""
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
    struct.pack_into("<IIQQQQQQ", out, phoff, 1, 5, 0, base, base,
                     file_size, file_size, 0x1000)
    struct.pack_into("<IIQQQQQQ", out, phoff + phdr_size, 2, 4,
                     dyn_off, base + dyn_off, base + dyn_off,
                     5 * 16, 5 * 16, 8)
    entries = [(14, 1), (1, 1 + len(soname) + 1),
               (5, base + dynstr_off), (10, len(dynstr)), (0, 0)]
    for i, (tag, val) in enumerate(entries):
        struct.pack_into("<qQ", out, dyn_off + i * 16, tag, val)
    out[dynstr_off:dynstr_off + len(dynstr)] = dynstr
    return bytes(out)


def _apk_bytes(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def test_native_mixed_elf_and_zip_so(tmp_path):
    apk = tmp_path / "mixed.apk"
    apk.write_bytes(_apk_bytes([
        ("lib/arm64-v8a/libfoo.so", build_elf64()),
        ("lib/arm64-v8a/libpayload.zip.so",
         _apk_bytes([("inner.txt", b"payload")])),
    ]))
    report = nar_native.analyze(str(apk))
    names = [(lib.get("display_name") or lib.get("name"))
             for lib in report["libraries"]]
    assert "arm64-v8a/libfoo.so" in names
    assert "arm64-v8a/libpayload.zip.so" in names
    errs = [lib for lib in report["libraries"] if lib.get("error")]
    assert len(errs) == 1 and "not an ELF" in errs[0]["error"]
    assert report["dependency_graph"] == {}
    assert report["jni_map"] == {}


def test_native_dependency_graph_still_built(tmp_path):
    apk = tmp_path / "graph.apk"
    apk.write_bytes(_apk_bytes([
        ("lib/arm64-v8a/libfoo.so",
         build_elf64(b"libfoo.so", b"libbar.so")),
        ("lib/arm64-v8a/libbar.so",
         build_elf64(b"libbar.so", b"libfoo.so")),
        ("lib/arm64-v8a/libpayload.zip.so",
         _apk_bytes([("inner.txt", b"payload")])),
    ]))
    report = nar_native.analyze(str(apk))
    graph = report["dependency_graph"]
    assert graph["arm64-v8a/libfoo.so"] == ["arm64-v8a/libbar.so"]
    assert graph["arm64-v8a/libbar.so"] == ["arm64-v8a/libfoo.so"]
