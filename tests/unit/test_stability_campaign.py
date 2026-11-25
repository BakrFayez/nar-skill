"""Stability & certification campaign: regression tests.

One test (or pair) per audit fix that shipped on the
stability-certification branch, each built to fail on the
pre-fix code and pass on the fixed tree. Finding ids refer
to the campaign register (docs/NAR_STABILITY_AUDIT.md). All
inputs are synthetic and generic; no fixture corpus is
required, so these run identically in the clean-extraction
CI shape.
"""
import importlib.util
import json
import os
import struct
import subprocess
import sys
import zipfile
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from narlib import registry  # noqa: E402
from narlib.elf import Elf, ElfError, SHT_DYNSYM  # noqa: E402
from narlib.iostore import IoStoreError, extract_chunk  # noqa: E402
from narlib.safearchive import read_member_capped  # noqa: E402

import test_case_evidence_integrity as casebuild  # noqa: E402
import test_pak  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def az():
    return _load("nar_analyze_stab", "nar-analyze.py")


@pytest.fixture(scope="module")
def nar_network():
    return _load("nar_network_stab", "nar-network.py")


@pytest.fixture(scope="module")
def nar_security():
    return _load("nar_security_stab", "nar-security.py")


@pytest.fixture(scope="module")
def nar_engines():
    return _load("nar_engines_stab", "nar-engines.py")


@pytest.fixture(scope="module")
def nar_compare():
    return _load("nar_compare_stab", "nar-compare.py")


@pytest.fixture(scope="module")
def nar_runtime():
    return _load("nar_runtime_stab", "nar-runtime.py")


@pytest.fixture(scope="module")
def nar_unity():
    return _load("nar_unity_stab", "nar-unity.py")


@pytest.fixture(scope="module")
def nar_pak():
    return test_pak.nar_pak


# ----------------------------------------------------------
# B-01 (P0): IoStore zlib blocks inflate only up to the
# TOC-promised size; a hostile stream is refused, an honest
# one round-trips.
# ----------------------------------------------------------

def _iostore_parsed(payload, promised):
    comp = zlib.compress(payload)
    return {
        "header": {"container_flag_names": []},
        "compression_methods": ["Zlib"],
        "entries": [{"length": promised, "first_block": 0}],
        "_blocks": [{"offset": 0, "compressed_size": len(comp),
                     "uncompressed_size": promised,
                     "compression_method_index": 0}],
    }, comp


def test_b01_zlib_bomb_refused():
    payload = b"A" * 100000
    parsed, comp = _iostore_parsed(payload, promised=64)
    with pytest.raises(IoStoreError, match="expands past"):
        extract_chunk(parsed, comp, 0)


def test_b01_honest_zlib_chunk_round_trips():
    payload = b"honest chunk payload " * 10
    parsed, comp = _iostore_parsed(payload, promised=len(payload))
    assert extract_chunk(parsed, comp, 0) == payload


# ----------------------------------------------------------
# A-04 (P1): ELF section contents are extent-validated; an
# inflated .dynsym raises ElfError instead of yielding
# fabricated symbols.
# ----------------------------------------------------------

def _build_elf_with_dynsym(inflate_symbols=0):
    dynstr = b"\x00real_symbol\x00"
    shstr = b"\x00.dynsym\x00.dynstr\x00.shstrtab\x00"
    sym = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
    sym += struct.pack("<IBBHQQ", 1, 0x12, 0, 1, 0x1000, 16)
    ehdr = 64
    dynsym_off = ehdr
    dynstr_off = dynsym_off + len(sym)
    shstr_off = dynstr_off + len(dynstr)
    shoff = shstr_off + len(shstr)
    shentsize = 64

    def shdr(name, typ, off, size, link=0, entsize=0):
        return struct.pack("<IIQQQQIIQQ", name, typ, 0, 0,
                           off, size, link, 0, 8, entsize)

    out = bytearray(shoff + 4 * shentsize)
    out[0:4] = b"\x7fELF"
    out[4] = 2  # ELFCLASS64
    out[5] = 1  # little endian
    struct.pack_into("<H", out, 16, 3)       # ET_DYN
    struct.pack_into("<H", out, 18, 183)     # AArch64
    struct.pack_into("<Q", out, 40, shoff)   # e_shoff
    struct.pack_into("<H", out, 52, ehdr)
    struct.pack_into("<H", out, 58, shentsize)
    struct.pack_into("<H", out, 60, 4)       # e_shnum
    struct.pack_into("<H", out, 62, 3)       # e_shstrndx
    out[dynsym_off:dynsym_off + len(sym)] = sym
    out[dynstr_off:dynstr_off + len(dynstr)] = dynstr
    out[shstr_off:shstr_off + len(shstr)] = shstr
    dynsym_size = len(sym) + inflate_symbols * 24
    out[shoff + shentsize:shoff + 2 * shentsize] = shdr(
        1, 11, dynsym_off, dynsym_size, link=2, entsize=24)
    out[shoff + 2 * shentsize:shoff + 3 * shentsize] = shdr(
        9, 3, dynstr_off, len(dynstr))
    out[shoff + 3 * shentsize:shoff + 4 * shentsize] = shdr(
        17, 3, shstr_off, len(shstr))
    return bytes(out)


def test_a04_honest_dynsym_reads_real_symbol_only():
    elf = Elf(_build_elf_with_dynsym())
    names = [s["name"] for s in elf.symbols(SHT_DYNSYM)]
    # Index 0 is the mandatory null symbol (empty name).
    assert names == ["", "real_symbol"]


def test_a04_inflated_dynsym_raises_instead_of_fabricating():
    elf = Elf(_build_elf_with_dynsym(inflate_symbols=100))
    with pytest.raises(ElfError, match="past the end"):
        elf.symbols(SHT_DYNSYM)


# ----------------------------------------------------------
# B-09 (P2): classic pak entry extents are validated at
# parse time; an index pointing outside the file is refused.
# ----------------------------------------------------------

def _fstring(s):
    raw = s.encode() + b"\x00"
    return struct.pack("<i", len(raw)) + raw


def _classic_index(offset, size):
    index = _fstring("../../../")
    index += struct.pack("<i", 1)
    index += _fstring("Content/a.uasset")
    index += struct.pack("<QQQ", offset, size, size)
    index += struct.pack("<i", 0)          # method: stored
    index += b"\x00" * 20                  # SHA-1 slot
    return index


def test_b09_classic_entry_outside_file_refused(nar_pak):
    index = _classic_index(offset=10 ** 9, size=128)
    with pytest.raises(nar_pak.PakError, match="outside"):
        nar_pak.parse_entries(index, 5, 0, len(index), False, 0)


def test_b09_classic_entry_inside_file_parses(nar_pak):
    index = _classic_index(offset=0, size=8)
    _mount, entries, consumed = nar_pak.parse_entries(
        index, 5, 0, len(index), False, 0)
    assert consumed == len(index)
    assert entries[0]["name"] == "Content/a.uasset"


# ----------------------------------------------------------
# B-04 (P1): Unity bundle inventory counts past the
# deep-scan cap; only the scan list is capped, and
# Addressables detection still sees entries after the cap.
# ----------------------------------------------------------

def test_b04_bundle_counting_past_scan_cap(tmp_path, nar_unity):
    target = tmp_path / "game.apk"
    with zipfile.ZipFile(target, "w") as zf:
        for i in range(205):
            zf.writestr(f"assets/b{i}.bundle",
                        b"UnityFS\x00" + b"\x00" * 64)
        zf.writestr("assets/aa/catalog.json", "{}")
    report = nar_unity.analyze(str(target))
    assert report["unityfs_bundle_total"] == 205
    assert report["unityfs_bundle_count"] == \
        nar_unity.MAX_BUNDLE_SCAN
    assert report["unityfs_bundle_scan_truncated"] is True
    assert report["addressables"] is True


# ----------------------------------------------------------
# D-01 (P0): nar-network redaction covers prefixed
# credential names, fragment credentials, and path
# ;-parameters; benign parameters are preserved exactly.
# ----------------------------------------------------------

D01_CASES = [
    ("https://api.example.com/x?client_secret=CS123&ok=1",
     "https://api.example.com/x?client_secret=REDACTED&ok=1", 1),
    ("https://api.example.com/x?refresh_token=RT123",
     "https://api.example.com/x?refresh_token=RT123".replace(
         "RT123", "REDACTED"), 1),
    ("https://example.com/cb#access_token=AT123&state=ok",
     "https://example.com/cb#access_token=REDACTED&state=ok", 1),
    ("https://example.com/a;jsessionid=JS123/b",
     "https://example.com/a;jsessionid=REDACTED/b", 1),
    ("https://example.com/x?AWS_SECRET_ACCESS_KEY=AK123",
     "https://example.com/x?AWS_SECRET_ACCESS_KEY=REDACTED", 1),
    ("https://example.com/x?private_key=PK123&monkey=banana",
     "https://example.com/x?private_key=REDACTED&monkey=banana", 1),
    ("https://example.com/x?foo=bar&monkey=banana",
     "https://example.com/x?foo=bar&monkey=banana", 0),
    # A benign matrix parameter mid-path, and a credential
    # one followed by more path: the path tail after the
    # value is structure, never part of the value.
    ("https://example.com/a;foo=bar/b?x=1",
     "https://example.com/a;foo=bar/b?x=1", 0),
    ("https://example.com/a;session=S123/b/c",
     "https://example.com/a;session=REDACTED/b/c", 1),
]


def test_d01_redaction_shapes(nar_network):
    for url, want_url, want_count in D01_CASES:
        out, count = nar_network.redact_url(url)
        assert out == want_url, url
        assert count == want_count, url
        for secret in ("CS123", "RT123", "AT123", "JS123",
                       "AK123", "PK123"):
            assert secret not in out


# ----------------------------------------------------------
# D-02 (P1): run_json_tool wrappers return None when the
# child exits non-zero, even if stdout is parseable JSON.
# ----------------------------------------------------------

class _FakeProc:
    def __init__(self, returncode, stdout):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


def _patch_run(monkeypatch, module, proc):
    monkeypatch.setattr(
        module.subprocess, "run", lambda *a, **k: proc)


def test_d02_wrappers_honor_exit_codes(monkeypatch, nar_network,
                                      nar_security, nar_engines,
                                      nar_compare):
    wrappers = [(nar_network, "run_json_tool"),
                (nar_security, "run_json_tool"),
                (nar_engines, "run_json_tool"),
                (nar_compare, "_run_json_tool")]
    for module, attr in wrappers:
        fn = getattr(module, attr)
        _patch_run(monkeypatch, module,
                   _FakeProc(2, '{"error": "bad target"}'))
        assert fn("nar-triage.py", ["x"]) is None, attr
        _patch_run(monkeypatch, module,
                   _FakeProc(0, '{"ok": true}'))
        assert fn("nar-triage.py", ["x"]) == {"ok": True}, attr


# ----------------------------------------------------------
# D-03 (P1): the registry probe counts a tool available
# only when its version command really runs and exits 0;
# an error banner is not a version.
# ----------------------------------------------------------

def _fake_tool(tmp_path, text, exit_code=0, name="faketool-bin"):
    """A fake tool the host platform can genuinely execute.

    POSIX: an extensionless #!/bin/sh script, chmod 755 —
    the platform's real execution mechanism, unchanged.

    Windows: Windows cannot execute an extensionless shell
    script at all (no shebang, no execute bit), so the old
    fixture encoded Unix semantics and could never run
    there. The genuinely-executable script form on Windows
    is a .bat shim: .bat is in PATHEXT (so shutil.which
    resolves it, exactly as the probe now requires) and the
    registry's version run invokes .bat/.cmd through
    COMSPEC /c, which is how Windows itself starts the real
    .bat tool launchers in the registry (jadx, apktool).
    A .py fixture was rejected: .py is not in the default
    PATHEXT and subprocess does not start files through
    shell file-associations, so the probe could not
    genuinely run it. The echoed text is plain
    [A-Za-z0-9 .:;-], safe unquoted in both shells."""
    if sys.platform == "win32":
        path = tmp_path / (name + ".bat")
        body = "@echo off\necho " + text + "\n"
        if exit_code:
            body += "exit /b %d\n" % exit_code
        path.write_text(body)
        return path
    path = tmp_path / name
    body = "#!/bin/sh\necho '" + text + "'\n"
    if exit_code:
        body += "exit %d\n" % exit_code
    path.write_text(body)
    path.chmod(0o755)
    return path


def _d03_entry():
    return {"name": "faketoolx", "kind": "executable",
            "required": "optional",
            "candidates": ["faketoolx-not-on-path"],
            "version_argv": ["--version"]}


def test_d03_run_version_requires_exit_zero(tmp_path):
    banner = _fake_tool(
        tmp_path, "ERROR: fake banner not a version",
        exit_code=3)
    assert registry._run_version([str(banner)]) is None
    good = _fake_tool(tmp_path, "faketool 1.2.3",
                      name="goodtool-bin")
    assert registry._run_version([str(good)]) == "faketool 1.2.3"


def test_d03_probe_rejects_failing_tool(tmp_path, monkeypatch):
    banner = _fake_tool(tmp_path, "ERROR: banner", exit_code=3)
    monkeypatch.setenv("NAR_FAKETOOLX_PATH", str(banner))
    result = registry.probe(_d03_entry())
    assert result["available"] is False
    assert result["version"] is None


def test_d03_probe_accepts_working_tool(tmp_path, monkeypatch):
    good = _fake_tool(tmp_path, "faketool 2.0")
    monkeypatch.setenv("NAR_FAKETOOLX_PATH", str(good))
    result = registry.probe(_d03_entry())
    assert result["available"] is True
    assert result["version"] == "faketool 2.0"


def test_d03_probe_ignores_non_executable_override(
        tmp_path, monkeypatch):
    if sys.platform == "win32":
        # A file Windows genuinely cannot execute: a plain
        # text file whose extension is not in PATHEXT, so
        # PATHEXT resolution refuses it no matter its name
        # or contents.
        plain = tmp_path / "not-executable.txt"
        plain.write_text("just text")
    else:
        plain = tmp_path / "not-executable"
        plain.write_text("just text")
        plain.chmod(0o644)
    monkeypatch.setenv("NAR_FAKETOOLX_PATH", str(plain))
    result = registry.probe(_d03_entry())
    assert result["available"] is False
    assert result["path"] is None


def test_d03_win32_probe_uses_which_not_access_xok(
        tmp_path, monkeypatch):
    """Simulated win32 branch, runnable on any host: with
    sys.platform patched to win32 and shutil.which faked to
    PATHEXT-resolve a .bat candidate, the probe must accept
    that candidate even though os.access(X_OK) — patched to
    record-and-deny — says no, and must never consult it.
    On the pre-fix code this fails: the override was gated
    on os.access(X_OK) alone."""
    good = tmp_path / "faketool.bat"
    good.write_text("@echo off\necho faketool 9.9\n")
    good.chmod(0o644)  # not executable by POSIX semantics
    access_calls = []

    def fake_access(path, mode, *args, **kwargs):
        access_calls.append((str(path), mode))
        return False

    def fake_which(cmd, mode=0, path=None):
        return str(good) if str(cmd) == str(good) else None

    def fake_run_version(argv, timeout=20):
        assert argv[0] == str(good)  # the resolved path runs
        return "faketool 9.9"

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(registry.shutil, "which", fake_which)
    monkeypatch.setattr(registry.os, "access", fake_access)
    monkeypatch.setattr(registry, "_run_version",
                        fake_run_version)
    monkeypatch.setenv("NAR_FAKETOOLX_PATH", str(good))
    result = registry.probe(_d03_entry())
    assert result["available"] is True
    assert result["path"] == str(good)
    assert result["version"] == "faketool 9.9"
    assert access_calls == []


def test_d03_win32_probe_rejects_file_which_cannot_resolve(
        tmp_path, monkeypatch):
    """Simulated win32, the other direction: a file that
    POSIX os.access(X_OK) calls executable (chmod 755) but
    that PATHEXT resolution (faked which) refuses — a .txt
    file — must be ignored as an override. Executability
    on win32 is which's verdict, never the X_OK bit."""
    plain = tmp_path / "not-executable.txt"
    plain.write_text("just text")
    plain.chmod(0o755)
    assert os.access(str(plain), os.X_OK)  # POSIX says yes
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(registry.shutil, "which",
                        lambda cmd, mode=0, path=None: None)
    monkeypatch.setenv("NAR_FAKETOOLX_PATH", str(plain))
    result = registry.probe(_d03_entry())
    assert result["available"] is False
    assert result["path"] is None


def test_d03_win32_run_version_invokes_batch_via_comspec(
        monkeypatch):
    """Simulated win32 invocation: a .bat candidate is run
    through COMSPEC /c (the only way Windows starts batch
    shims), a native .exe candidate runs directly, and a
    non-zero exit still yields no version on either form."""
    calls = []

    class _Proc:
        def __init__(self, returncode, stdout):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = ""

    def fake_run(argv, **kwargs):
        calls.append(list(argv))
        if any("fail" in str(a) for a in argv):
            return _Proc(3, "ERROR: banner\n")
        return _Proc(0, "faketool 3.0\n")

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("COMSPEC", "cmd.exe")
    monkeypatch.setattr(registry.subprocess, "run", fake_run)
    bat = r"C:\tools\faketool.bat"
    assert registry._run_version([bat, "--version"]) == \
        "faketool 3.0"
    assert calls[-1] == ["cmd.exe", "/c", bat, "--version"]
    exe = r"C:\tools\faketool.exe"
    assert registry._run_version([exe, "--version"]) == \
        "faketool 3.0"
    assert calls[-1] == [exe, "--version"]
    fail = r"C:\tools\failtool.bat"
    assert registry._run_version([fail, "--version"]) is None
    assert calls[-1] == ["cmd.exe", "/c", fail, "--version"]


# ----------------------------------------------------------
# D-05 (P1): the shared capped member reader refuses
# over-cap members before and during decompression.
# ----------------------------------------------------------

def test_d05_member_cap(tmp_path):
    target = tmp_path / "m.apk"
    payload = b"M" * 4096
    with zipfile.ZipFile(target, "w",
                         zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("classes.dex", payload)
    with zipfile.ZipFile(target) as zf:
        assert read_member_capped(zf, "classes.dex",
                                  cap_bytes=8192) == payload
        with pytest.raises(ValueError, match="member read cap"):
            read_member_capped(zf, "classes.dex", cap_bytes=1024)


# ----------------------------------------------------------
# D-06 (P1): frida-server presence means a binary candidate,
# never a sidecar log file with the same prefix.
# D-11 (P2): device classification never calls a sparse
# property set "physical"; "intel" hardware is weak only.
# ----------------------------------------------------------

_GETPROP = (
    "[ro.product.model]: [Pixel 8]\n"
    "[ro.product.brand]: [google]\n"
    "[ro.product.manufacturer]: [Google]\n"
    "[ro.product.device]: [panther]\n"
    "[ro.build.fingerprint]: "
    "[google/panther/panther:14/UP1A/1:user/release-keys]\n"
    "[ro.hardware]: [panther]\n"
    "[ro.build.version.release]: [14]\n"
    "[ro.build.version.sdk]: [34]\n"
    "[ro.product.cpu.abi]: [arm64-v8a]\n"
    "[sys.boot_completed]: [1]\n")


class _Proc:
    def __init__(self, stdout):
        self.stdout = stdout


def _fake_runner(listing, version_out=""):
    def runner(cmd, timeout=None):
        if "getprop" in cmd:
            return _Proc(_GETPROP)
        if "id" in cmd:
            return _Proc("uid=2000(shell) gid=2000(shell)\n")
        if "--version" in cmd:
            return _Proc(version_out)
        if "ls" in cmd:
            return _Proc(listing)
        return _Proc("")
    return runner


def test_d06_log_file_alone_is_not_a_server(nar_runtime):
    caps = nar_runtime.device_capabilities(
        "adb", "R5CT1234567",
        runner=_fake_runner("frida-server.log\n"))
    assert caps["frida_server"]["present"] is False
    assert caps["frida_server"]["files"] == ["frida-server.log"]


def test_d06_binary_candidate_is_present(nar_runtime):
    caps = nar_runtime.device_capabilities(
        "adb", "R5CT1234567",
        runner=_fake_runner("frida-server\nfrida-server.log\n",
                            version_out="17.27.4\n"))
    assert caps["frida_server"]["present"] is True
    assert caps["frida_server"]["version"] == "17.27.4"


_PHYSICAL_PROPS = {
    "ro.product.model": "Acme Phone",
    "ro.product.brand": "acme",
    "ro.product.manufacturer": "Acme",
    "ro.product.device": "acme1",
    "ro.build.fingerprint":
        "acme/acme1/acme1:14/UP1A/1:user/release-keys",
    "ro.hardware": "panther",
}


def test_d11_sparse_property_set_is_unknown(nar_runtime):
    assert nar_runtime.classify_device({})["kind"] == "unknown"
    sparse = {"ro.product.brand": "acme"}
    assert nar_runtime.classify_device(sparse)["kind"] == \
        "unknown"


def test_d11_intel_hardware_is_weak_only(nar_runtime):
    props = dict(_PHYSICAL_PROPS, **{"ro.hardware": "intel"})
    result = nar_runtime.classify_device(props)
    assert result["kind"] == "unknown"
    assert result["evidence"][0]["strength"] == "weak"


def test_d11_populated_set_without_markers_is_physical(
        nar_runtime):
    assert nar_runtime.classify_device(
        _PHYSICAL_PROPS)["kind"] == "physical"
    qemu = {"ro.kernel.qemu": "1"}
    assert nar_runtime.classify_device(qemu)["kind"] == \
        "emulator"


# ----------------------------------------------------------
# C-01 (P0): extraction containment is proven with
# realpath — a pre-existing symlink inside the root cannot
# redirect a write outside it (nar-analyze and nar-pak).
# C-09 (P2): a relative work root works (is absolutized).
# ----------------------------------------------------------

def test_c01_analyze_extract_refuses_symlink_escape(
        tmp_path, az):
    root = tmp_path / "work"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    os.symlink(outside, root / "sub")
    src = tmp_path / "in.zip"
    with zipfile.ZipFile(src, "w") as zf:
        zf.writestr("payload.bin", b"payload")
    with zipfile.ZipFile(src) as zf:
        with pytest.raises(ValueError, match="symlink"):
            az.extract_entry(zf, "payload.bin", str(root),
                             "sub", "evil.bin")
    assert not (outside / "evil.bin").exists()
    with pytest.raises(ValueError, match="escapes"):
        az._contained_join(str(root), "..", "escape.bin")


def test_c01_analyze_extract_inside_root_works(tmp_path, az):
    root = tmp_path / "work"
    root.mkdir()
    src = tmp_path / "in.zip"
    with zipfile.ZipFile(src, "w") as zf:
        zf.writestr("payload.bin", b"payload")
    with zipfile.ZipFile(src) as zf:
        dest = az.extract_entry(zf, "payload.bin", str(root),
                                "ok.bin")
    assert Path(dest).read_bytes() == b"payload"


def test_c09_relative_root_is_absolutized(tmp_path, az,
                                          monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "relwork").mkdir()
    dest = az._contained_join("relwork", "a.bin")
    assert os.path.isabs(dest)
    assert dest.startswith(
        os.path.realpath("relwork") + os.sep)


def test_c01_pak_extract_refuses_symlink_escape(
        tmp_path, nar_pak):
    pak_path = test_pak.write(tmp_path, "enc.pak",
                              test_pak.build_v11_encoded())
    out = tmp_path / "out"
    outside = tmp_path / "outside"
    out.mkdir()
    outside.mkdir()
    os.symlink(outside, out / "Game")
    report = nar_pak.extract_pak(pak_path, "*.uasset", str(out))
    assert report["extracted"] == []
    assert report["extract_errors"]
    assert any("symlink" in e["error"]
               for e in report["extract_errors"])
    assert not (outside / "Content").exists()


# ----------------------------------------------------------
# C-03 (P1): a bundle that fails verification never touches
# the import destination (staging + verify first).
# C-10 (P2): export refuses non-cases and in-case bundles.
# ----------------------------------------------------------

def test_c10_export_refusals(tmp_path, az):
    case_dir = casebuild.make_case(str(tmp_path / "mk"))
    with pytest.raises(ValueError, match="not a case"):
        az.export_case(str(tmp_path / "nope"),
                       str(tmp_path / "b.zip"))
    with pytest.raises(ValueError, match="outside the case"):
        az.export_case(case_dir,
                       os.path.join(case_dir, "bundle.zip"))


def test_c03_failed_import_leaves_destination_untouched(
        tmp_path, az):
    case_dir = casebuild.make_case(str(tmp_path / "mk"))
    bundle = str(tmp_path / "case.zip")
    az.export_case(case_dir, bundle)
    # Tamper: same manifest, different report.json bytes.
    tampered = str(tmp_path / "tampered.zip")
    with zipfile.ZipFile(bundle) as zin, \
            zipfile.ZipFile(tampered, "w") as zout:
        for item in zin.namelist():
            data = zin.read(item)
            if item == "report.json":
                data = b'{"tool": "nar-analyze", "tampered": 1}'
            zout.writestr(item, data)
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "keep.txt").write_text("sentinel")
    (dest / "report.json").write_text("original report")
    with pytest.raises(ValueError):
        az.import_case(tampered, str(dest))
    assert (dest / "keep.txt").read_text() == "sentinel"
    assert (dest / "report.json").read_text() == \
        "original report"


def test_c03_valid_import_succeeds(tmp_path, az):
    case_dir = casebuild.make_case(str(tmp_path / "mk"))
    bundle = str(tmp_path / "case.zip")
    az.export_case(case_dir, bundle)
    dest = tmp_path / "dest"
    result = az.import_case(bundle, str(dest))
    assert result["ok"] is True
    assert (dest / "case.json").is_file()


# ----------------------------------------------------------
# C-05 (P1): a corrupt stage-cache pair is a cache MISS
# (pair dropped, stage re-run), never a traceback.
# ----------------------------------------------------------

def _seed_cache(az, out_dir, stage, doc_bytes, key):
    cache_dir = os.path.join(out_dir, "cache")
    os.makedirs(cache_dir, exist_ok=True)
    with open(os.path.join(cache_dir, f"{stage}.json"),
              "wb") as fh:
        fh.write(doc_bytes)
    with open(os.path.join(cache_dir, f"{stage}.json.key"),
              "w") as fh:
        fh.write(key)


def test_c05_corrupt_cache_is_a_miss(tmp_path, az, monkeypatch):
    out_dir = str(tmp_path / "case")
    _seed_cache(az, out_dir, "dex", b"{not json", "KEY1")
    monkeypatch.setattr(
        az, "run_json_tool",
        lambda script, args: ({"fresh": True}, None))
    doc, err, cached = az.run_cached_stage(
        "dex", "nar-dex.py", ["x"], "KEY1", out_dir)
    assert doc == {"fresh": True}
    assert err is None
    assert cached is False


def test_c05_wrong_shape_cache_is_a_miss(tmp_path, az,
                                         monkeypatch):
    out_dir = str(tmp_path / "case")
    _seed_cache(az, out_dir, "dex", b"[1, 2]", "KEY1")
    monkeypatch.setattr(
        az, "run_json_tool",
        lambda script, args: ({"fresh": True}, None))
    doc, _err, cached = az.run_cached_stage(
        "dex", "nar-dex.py", ["x"], "KEY1", out_dir)
    assert doc == {"fresh": True}
    assert cached is False


def test_c05_valid_cache_still_hits(tmp_path, az, monkeypatch):
    out_dir = str(tmp_path / "case")
    _seed_cache(az, out_dir, "dex", b'{"doc": 1}', "KEY1")

    def _boom(script, args):
        raise AssertionError("tool must not run on a hit")

    monkeypatch.setattr(az, "run_json_tool", _boom)
    doc, _err, cached = az.run_cached_stage(
        "dex", "nar-dex.py", ["x"], "KEY1", out_dir)
    assert doc == {"doc": 1}
    assert cached is True


# ----------------------------------------------------------
# S-01 (P1): pre-2.6.2 CONTAINER cases carry stage cache
# keys derived from the extracted base APK — unverifiable
# from case data, so a mismatch is a warning, not a
# failure. The same mismatch in any other era still fails,
# and unparsable cache JSON fails in every era.
# S-02 (P1): pre-2.6.2 endpoints carrying the retired
# 'confirmed' label validate under the era mapping to
# 'dex-string'; the label in a 2.6.2 case still fails.
# ----------------------------------------------------------

def _add_cache_entry(case_dir, stage, key, doc=b"{}"):
    cache_dir = os.path.join(case_dir, "cache")
    os.makedirs(cache_dir, exist_ok=True)
    with open(os.path.join(cache_dir, f"{stage}.json"),
              "wb") as fh:
        fh.write(doc)
    with open(os.path.join(cache_dir, f"{stage}.json.key"),
              "w") as fh:
        fh.write(key)


def _set_input_path(case_dir, path):
    doc = casebuild._read(case_dir, "case.json")
    doc["input"]["path"] = path
    casebuild._write(case_dir, "case.json", doc)


def test_s01_legacy_container_key_mismatch_warns(az, tmp_path):
    case_dir = casebuild.make_case(str(tmp_path / "mk"),
                                   version="2.6.1")
    _set_input_path(case_dir, "/nonexistent/role-target.xapk")
    _add_cache_entry(case_dir, "dex", "0" * 64)
    result = az.verify_case(case_dir)
    assert not any("stage cache integrity keys" in f
                   for f in result["failures"])
    assert any("stage cache" in w and "2.6.2" in w
               for w in result["warnings"])


def test_s01_plain_apk_key_mismatch_still_fails(az, tmp_path):
    case_dir = casebuild.make_case(str(tmp_path / "mk"),
                                   version="2.6.1")
    _add_cache_entry(case_dir, "dex", "0" * 64)
    result = az.verify_case(case_dir)
    assert any("stage cache integrity keys" in f
               for f in result["failures"])


def test_s01_unparsable_cache_json_fails_every_era(
        az, tmp_path):
    case_dir = casebuild.make_case(str(tmp_path / "mk"),
                                   version="2.6.1")
    _set_input_path(case_dir, "/nonexistent/role-target.xapk")
    _add_cache_entry(case_dir, "dex", "0" * 64, doc=b"{broken")
    result = az.verify_case(case_dir)
    assert any("stage cache integrity keys" in f
               for f in result["failures"])


def _register_network_companion(case_dir):
    # The real pipeline registers the network stage's
    # endpoints.json in report.json companions (the shape
    # verify's schema loop iterates); casebuild's stub
    # report lists only four companions, so register it
    # the producer's way.
    report = casebuild._read(case_dir, "report.json")
    report["companions"]["network"] = {
        "file": "endpoints.json", "cached": False}
    casebuild._write(case_dir, "report.json", report)


def test_s02_legacy_confirmed_endpoints_validate(az, tmp_path):
    # casebuild's NETWORK document carries the retired
    # 'confirmed' label, exactly as pre-2.6.2 cases do.
    case_dir = casebuild.make_case(str(tmp_path / "mk"),
                                   version="2.6.1")
    _register_network_companion(case_dir)
    result = az.verify_case(case_dir)
    assert result["ok"], result["failures"]
    assert "era mapping" in json.dumps(result)


def test_s02_confirmed_label_fails_in_current_era(
        az, tmp_path):
    case_dir = casebuild.make_case(str(tmp_path / "mk"),
                                   version="2.6.2")
    _register_network_companion(case_dir)
    result = az.verify_case(case_dir)
    section = result["evidence_integrity"]
    failed = {c["check"] for c in section["checks"]
              if c["status"] == "fail"}
    assert "companion schema validity" in failed


# ----------------------------------------------------------
# S-03 (P1, found by this campaign's regression phase):
# nar-network emits endpoints' network_libraries as label
# strings; correlations._library_correlations called
# .get() on each item, crashing on any real target with a
# detected network library. Both shapes now correlate.
# ----------------------------------------------------------

def test_s03_library_correlations_accept_producer_strings():
    from narlib import correlations
    dex = {"dex_files": [{"classes": [
        {"class": "Lokhttp3/OkHttpClient;"},
        {"class": "Lokhttp3/Request;"},
        {"class": "Lcom/example/App;"}]}]}
    network = {"network_libraries": ["OkHttp"],
               "endpoints": []}
    doc = correlations.build_correlations(
        dex, None, None, network, "2.6.2")
    libs = doc["network_libraries"]
    assert len(libs) == 1
    assert libs[0]["library"] == "OkHttp"
    assert libs[0]["status"] == "matched"
    assert libs[0]["classes_found"] == 2
    assert libs[0]["verification_status"] == "CONFIRMED"
    assert doc["counts"]["network_libraries_matched"] == 1


def test_s03_library_correlations_accept_object_shape():
    from narlib import correlations
    dex = {"dex_files": [{"classes": [
        {"class": "Lcom/example/App;"}]}]}
    network = {"network_libraries": [
        {"library": "OkHttp", "evidence": "stub"}],
        "endpoints": []}
    doc = correlations.build_correlations(
        dex, None, None, network, "2.6.2")
    libs = doc["network_libraries"]
    assert len(libs) == 1
    assert libs[0]["library"] == "OkHttp"
    assert libs[0]["status"] == "library-only"


# ----------------------------------------------------------
# C-13 / D-10 / D-15: CLI exit-code discipline — bad
# targets are exit 2 (never a traceback, never exit 0),
# an extract that rejects every entry is exit 1, and the
# doctor's --help is a usage exit 0.
# ----------------------------------------------------------

def _run_cli(*args):
    return subprocess.run(
        [sys.executable] + [str(a) for a in args],
        capture_output=True, text=True, timeout=120)


def test_exit2_directory_targets(tmp_path):
    for script in ("nar-dex.py", "nar-native.py",
                   "nar-assets.py"):
        proc = _run_cli(SCRIPTS / script, tmp_path)
        assert proc.returncode == 2, (script, proc.stdout,
                                      proc.stderr)
        assert "Traceback" not in proc.stderr


def test_exit2_non_archive_extract(tmp_path):
    plain = tmp_path / "plain.txt"
    plain.write_text("not an archive")
    proc = _run_cli(SCRIPTS / "nar-input.py", "extract",
                    plain, "--out", tmp_path / "out")
    assert proc.returncode == 2
    assert "Traceback" not in proc.stderr


def test_exit1_extract_rejects_every_entry(tmp_path):
    hostile = tmp_path / "hostile.zip"
    with zipfile.ZipFile(hostile, "w") as zf:
        zf.writestr("../evil.txt", b"evil")
    proc = _run_cli(SCRIPTS / "nar-input.py", "extract",
                    hostile, "--out", tmp_path / "out")
    assert proc.returncode == 1
    assert not (tmp_path / "evil.txt").exists()


def test_exit2_duplicates_missing_dir(tmp_path):
    proc = _run_cli(SCRIPTS / "nar-input.py", "duplicates",
                    "--dir", tmp_path / "missing")
    assert proc.returncode == 2
    assert "Traceback" not in proc.stderr


def test_doctor_help_is_usage_exit_zero():
    proc = subprocess.run(
        ["bash", str(SCRIPTS / "nar-doctor.sh"), "--help"],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0
    assert "usage" in proc.stdout.lower()
