"""Generality test (Part 16.2): a new engine is data, not code.

Injects a synthetic "FakeEngine" row into a temporary
formats.json overlay (env override NAR_FORMATS_JSON — test
plumbing only; default behaviour reads the in-tree file),
builds a tiny synthetic APK carrying its library, and asserts
with ZERO code changes:

1. nar-engines detects FakeEngine (detected: true);
2. nar-triage lists its engine hint;
3. nar coverage shows FakeEngine with its declared status;
4. nar-analyze builds a complete case whose frameworks.json
   and graph.json include FakeEngine;
5. with the pristine formats.json, FakeEngine is absent
   everywhere (no residue).

The ELF is built byte-by-byte (hermetic dynsym builder in the
style of test_engines_jni_symbols.py); no real app data.
"""
import io
import json
import os
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"

FAKE_ROW = {
    "name": "FakeEngine",
    "jni": {"prefixes": ["Java_com_fake_"], "exact": [],
            "substrings": [], "weak_prefixes": [],
            "weak_substrings": []},
    "paths": ["libfakeengine.so"],
    "signatures": [{"hint": "FakeEngine",
                    "paths": ["libfakeengine.so"], "order": 900}],
    "dex_markers": [],
    "hints": ["FakeEngine"],
    "version_keys": [],
    "deep": None,
    "guides": [],
    "fixtures": [],
    "status": "identified_only",
    "fidelity": "identified-only",
    "chains": [],
    "reason": "Synthetic generality-test engine; no deep dive.",
    "probe": "Remove the row; it exists only for this test.",
}


def _elf64_with_exports(names):
    dynstr = b"\x00"
    offsets = {}
    for name in names:
        offsets[name] = len(dynstr)
        dynstr += name.encode() + b"\x00"
    dynsym = b"\x00" * 24
    for name in names:
        dynsym += struct.pack(
            "<IBBHQQ", offsets[name], 0x12, 0, 1, 0, 0)
    shstrtab = b"\x00.dynsym\x00.dynstr\x00.shstrtab\x00"
    sh_name = {".dynsym": 1, ".dynstr": 9, ".shstrtab": 17}
    ehsize = 64
    off_dynsym = ehsize
    off_dynstr = off_dynsym + len(dynsym)
    off_shstr = off_dynstr + len(dynstr)
    shoff = off_shstr + len(shstrtab)

    def sh(name, shtype, offset, size, link, info, entsize):
        return struct.pack(
            "<IIQQQQIIQQ", sh_name.get(name, 0), shtype, 0, 0,
            offset, size, link, info, 8, entsize)

    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8,
        3, 0xB7, 1, 0, 0, shoff, 0, ehsize, 0, 0, 64, 4, 3)
    sections = b"\x00" * 64
    sections += sh(".dynsym", 11, off_dynsym, len(dynsym), 2, 1, 24)
    sections += sh(".dynstr", 3, off_dynstr, len(dynstr), 0, 0, 0)
    sections += sh(".shstrtab", 3, off_shstr, len(shstrtab), 0, 0, 0)
    return header + dynsym + dynstr + shstrtab + sections


def _fake_apk(tmp_path):
    apk = tmp_path / "fake.apk"
    elf = _elf64_with_exports(
        ["Java_com_fake_engine_Main_nativeInit",
         "Java_com_fake_engine_Main_nativeRender"])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lib/arm64-v8a/libfakeengine.so", elf)
        zf.writestr("classes.dex", b"dex\n039\x00" + b"\x00" * 64)
        zf.writestr("AndroidManifest.xml", b"\x00" * 16)
    apk.write_bytes(buf.getvalue())
    return apk


def _overlay(tmp_path):
    doc = json.loads(
        (SCRIPTS / "formats.json").read_text(encoding="utf-8"))
    doc["engines"]["fakeengine"] = FAKE_ROW
    path = tmp_path / "formats-overlay.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _run(script, args, env_extra, timeout=900):
    env = dict(os.environ)
    env.update(env_extra)
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / script)] + args,
        capture_output=True, text=True, timeout=timeout, env=env)
    assert proc.returncode == 0, (script, proc.stderr[-2000:])
    return proc


def test_fake_engine_is_data_not_code(tmp_path):
    apk = _fake_apk(tmp_path)
    overlay = _overlay(tmp_path)
    env = {"NAR_FORMATS_JSON": str(overlay)}

    # 1. nar-engines detects it.
    engines = json.loads(_run(
        "nar-engines.py", [str(apk), "--json"], env).stdout)
    verdicts = {v["engine"]: v for v in engines["verdicts"]}
    assert verdicts["FakeEngine"]["detected"] is True

    # 2. nar-triage lists its hint.
    triage = json.loads(_run(
        "nar-triage.py", [str(apk), "--json"], env).stdout)
    hints = {h["engine"] for h in triage.get("engine_hints") or []}
    assert "FakeEngine" in hints

    # 3. nar coverage shows it with its declared status.
    coverage = json.loads(_run(
        "nar.py", ["coverage", "--json"], env).stdout)
    fake = [e for e in coverage["engines"]
            if e["name"] == "FakeEngine"]
    assert fake and fake[0]["status"] == "identified_only"

    # 4. nar-analyze: frameworks.json + graph.json include it.
    case_dir = tmp_path / "case"
    _run("nar-analyze.py",
         [str(apk), "--out", str(case_dir)], env)
    frameworks = json.loads(
        (case_dir / "frameworks.json").read_text(encoding="utf-8"))
    assert any(v.get("engine") == "FakeEngine"
               for v in frameworks.get("verdicts") or [])
    graph = json.loads(
        (case_dir / "graph.json").read_text(encoding="utf-8"))
    assert any(n.get("kind") == "engine"
               and n.get("label") == "FakeEngine"
               for n in graph.get("nodes") or [])

    # 5. Pristine registry: absent everywhere.
    pristine = {"NAR_FORMATS_JSON": str(SCRIPTS / "formats.json")}
    engines = json.loads(_run(
        "nar-engines.py", [str(apk), "--json"], pristine).stdout)
    assert all(v["engine"] != "FakeEngine"
               for v in engines["verdicts"])
    triage = json.loads(_run(
        "nar-triage.py", [str(apk), "--json"], pristine).stdout)
    assert all(h["engine"] != "FakeEngine"
               for h in triage.get("engine_hints") or [])
    coverage = json.loads(_run(
        "nar.py", ["coverage", "--json"], pristine).stdout)
    assert all(e["name"] != "FakeEngine"
               for e in coverage["engines"])
