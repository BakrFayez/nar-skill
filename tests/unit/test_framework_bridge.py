"""Phase 6 framework-intelligence tests: Flutter plugin /
platform-channel evidence (nar-flutter) and the React
Native DEX<->bundle bridge mapping (nar-rn).

Everything is synthetic: a minimal DEX builder (string /
type / class-def tables with interface lists, the only
tables the evidence pass reads), a minimal binary
AndroidManifest.xml builder (string pool + one meta-data
start element), and planted APKs. Real-fixture cases
resolve targets through the fixture manifest's role
bindings (FIX_FLUTTER / FIX_RN) and skip when absent.
"""
import importlib.util
import json
import os
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, SCRIPTS / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


nar_flutter = _load("nar_flutter", "nar-flutter.py")
nar_rn = _load("nar_rn", "nar-rn.py")


def _fixture_path(role):
    env = os.environ.get("NAR_FIXTURES")
    if not env:
        return None
    manifest = Path(env) / "manifest.env"
    if not manifest.is_file():
        return None
    for line in manifest.read_text().splitlines():
        if line.startswith(role + "="):
            raw = line.split("=", 1)[1].strip().strip('"')
            raw = raw.replace("${NAR_FIXTURES}", env)
            path = Path(raw)
            return path if path.is_file() else None
    return None


# ------------------------------------------------------------ DEX builder

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


def build_dex(classes, extra_strings=()):
    """Minimal DEX. classes: (descriptor, superclass
    descriptor or None, [interface descriptors])."""
    strings = []
    seen = set()

    def add_string(s):
        if s not in seen:
            seen.add(s)
            strings.append(s)
        return strings.index(s)

    types = []
    for desc, sup, ifaces in classes:
        for d in [desc, sup] + list(ifaces):
            if d is not None and d not in types:
                types.append(d)
    for d in types:
        add_string(d)
    for s in extra_strings:
        add_string(s)
    type_index = {d: i for i, d in enumerate(types)}

    header_size = 0x70
    string_ids_off = header_size
    string_data_off = string_ids_off + 4 * len(strings)
    data = bytearray()
    offsets = []
    for s in strings:
        offsets.append(string_data_off + len(data))
        raw = s.encode()
        data += _uleb(len(raw)) + raw + b"\x00"
    type_ids_off = string_data_off + len(data)
    class_defs_off = type_ids_off + 4 * len(types)
    iface_blobs = {}
    pos = class_defs_off + 32 * len(classes)
    for desc, sup, ifaces in classes:
        if ifaces:
            blob = struct.pack("<I", len(ifaces)) + b"".join(
                struct.pack("<H", type_index[i]) for i in ifaces)
            iface_blobs[desc] = (pos, blob)
            pos += len(blob)
    file_size = pos

    out = bytearray(file_size)
    out[0:8] = b"dex\n039\x00"
    struct.pack_into("<I", out, 32, file_size)
    struct.pack_into("<I", out, 36, header_size)
    struct.pack_into("<I", out, 40, 0x12345678)
    struct.pack_into("<II", out, 56, len(strings),
                     string_ids_off)
    struct.pack_into("<II", out, 64, len(types), type_ids_off)
    struct.pack_into("<II", out, 96, len(classes),
                     class_defs_off)
    for i, off in enumerate(offsets):
        struct.pack_into("<I", out, string_ids_off + 4 * i, off)
    out[string_data_off:string_data_off + len(data)] = data
    for i, d in enumerate(types):
        struct.pack_into("<I", out, type_ids_off + 4 * i,
                         strings.index(d))
    for i, (desc, sup, ifaces) in enumerate(classes):
        iface_off = iface_blobs.get(desc, (0, b""))[0]
        struct.pack_into(
            "<IIIIIIII", out, class_defs_off + 32 * i,
            type_index[desc], 0x1,
            type_index[sup] if sup else 0xFFFFFFFF,
            iface_off, 0xFFFFFFFF, 0, 0, 0)
    for desc, (off, blob) in iface_blobs.items():
        out[off:off + len(blob)] = blob
    return bytes(out)


# ------------------------------------------------------------ AXML builder

def build_axml(embedding_value="2", typed=False):
    """Minimal binary AndroidManifest.xml: string pool +
    one <meta-data name="flutterEmbedding" ...> element.
    typed=False stores the value as a raw string; typed
    stores it as a typed integer attribute."""
    strings = ["http://schemas.android.com/apk/res/android",
               "meta-data", "name", "value",
               "flutterEmbedding", embedding_value]
    pool = bytearray()
    offsets = []
    body = bytearray()
    for s in strings:
        offsets.append(len(body))
        raw = s.encode("utf-16-le")
        body += struct.pack("<H", len(s)) + raw + b"\x00\x00"
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    pool += struct.pack("<HHIIIIII", 0x0001, header_size,
                        strings_start + len(body),
                        len(strings), 0, 0, strings_start, 0)
    for off in offsets:
        pool += struct.pack("<I", off)
    pool += body

    def attr(name_idx, raw_idx, data_type, data):
        return struct.pack("<IIIHBBI", 0, name_idx, raw_idx,
                           8, 0, data_type, data)

    if typed:
        value_attr = attr(3, 0xFFFFFFFF, 0x10,
                          int(embedding_value))
    else:
        value_attr = attr(3, 5, 0x03, 5)
    attrs = attr(2, 4, 0x03, 4) + value_attr
    elem_size = 16 + 20 + len(attrs)
    elem = struct.pack("<HHI", 0x0102, 16, elem_size)
    elem += struct.pack("<II", 0, 0)          # line, comment
    elem += struct.pack("<IIHHH", 0, 1, 20, 20, 2)
    elem += b"\x00" * 6                        # id/class/style
    elem += attrs
    total = 8 + len(pool) + len(elem)
    return struct.pack("<HHI", 0x0003, 8, total) \
        + bytes(pool) + elem


def _apk(path, entries):
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return str(path)


def _run(script, *args):
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / script), *args],
        capture_output=True, text=True, timeout=900)
    assert proc.returncode == 0, proc.stderr[-500:]
    return json.loads(proc.stdout)


# ------------------------------------------------------------ Flutter

FLU_CLASSES = [
    ("Lio/flutter/plugins/GeneratedPluginRegistrant;",
     "Ljava/lang/Object;", []),
    ("Lio/flutter/plugins/pathprovider/PathProviderPlugin;",
     "Ljava/lang/Object;",
     ["Lio/flutter/embedding/engine/plugins/FlutterPlugin;"]),
    ("Lcom/example/app/CustomPlugin;", "Ljava/lang/Object;",
     ["Lio/flutter/embedding/engine/plugins/FlutterPlugin;"]),
    ("Lcom/example/app/MainActivity;",
     "Lio/flutter/embedding/android/FlutterActivity;", []),
]


def _flutter_apk(tmp_path, manifest=None):
    dex = build_dex(
        FLU_CLASSES,
        extra_strings=["flutter/platform",
                       "com.example.app/main_channel",
                       "not a channel"])
    entries = {
        "lib/arm64-v8a/libflutter.so": b"\x7fELF synthetic",
        "lib/arm64-v8a/libapp.so":
            b"\x7fELF\x00com.example.plugins/sample_channel"
            b"\x00pad",
        "classes.dex": dex,
    }
    if manifest is not None:
        entries["AndroidManifest.xml"] = manifest
    return _apk(tmp_path / "flu.apk", entries)


def test_flutter_plugin_inventory(tmp_path):
    report = _run("nar-flutter.py",
                  _flutter_apk(tmp_path, build_axml("2")),
                  "--json")
    assert report["is_flutter"] is True
    pinv = report["plugin_inventory"]
    reg = pinv["generated_plugin_registrant"]
    assert reg["present"] is True
    assert reg["dex"] == "classes.dex"
    impl = {c["class"] for c in
            pinv["flutter_plugin_implementations"]["classes"]}
    assert impl == {
        "Lio/flutter/plugins/pathprovider/PathProviderPlugin;",
        "Lcom/example/app/CustomPlugin;"}
    fw = {c["class"] for c in
          pinv["framework_plugin_classes"]["classes"]}
    assert fw == {
        "Lio/flutter/plugins/pathprovider/PathProviderPlugin;"}
    channels = {(c["name"], c["source"]) for c in
                pinv["platform_channels"]["candidates"]}
    assert ("flutter/platform", "classes.dex string table") \
        in channels
    assert ("com.example.app/main_channel",
            "classes.dex string table") in channels
    assert ("com.example.plugins/sample_channel",
            "lib/arm64-v8a/libapp.so ASCII string scan") \
        in channels
    assert all(c["evidence"] == "string"
               for c in pinv["platform_channels"]["candidates"])
    assert pinv["platform_channels"]["confidence"] == \
        "candidate"
    emb = pinv["manifest_embedding"]
    assert emb["present"] is True
    assert emb["value"] == "2"


def test_flutter_minified_note_when_no_interface_hits(
        tmp_path):
    # Registrant present but no class declares the
    # FlutterPlugin interface under its framework name
    # (the minified-build shape): the inventory says why
    # instead of silently reporting zero.
    dex = build_dex([
        ("Lio/flutter/plugins/GeneratedPluginRegistrant;",
         "Ljava/lang/Object;", []),
        ("Lio/flutter/plugins/pathprovider/a;",
         "Ljava/lang/Object;", []),
    ])
    apk = _apk(tmp_path / "min.apk", {
        "lib/arm64-v8a/libflutter.so": b"\x7fELF synthetic",
        "lib/arm64-v8a/libapp.so": b"\x7fELF synthetic",
        "classes.dex": dex,
    })
    report = _run("nar-flutter.py", apk, "--json")
    impl = report["plugin_inventory"][
        "flutter_plugin_implementations"]
    assert impl["counts"]["total"] == 0
    assert "minified" in impl["note"]
    fw = report["plugin_inventory"]["framework_plugin_classes"]
    assert fw["counts"]["total"] == 1


def test_flutter_manifest_typed_value_and_absence(tmp_path):
    report = _run("nar-flutter.py",
                  _flutter_apk(tmp_path,
                               build_axml("2", typed=True)),
                  "--json")
    emb = report["plugin_inventory"]["manifest_embedding"]
    assert emb["present"] is True and emb["value"] == "2"
    # No manifest entry at all: recorded as None, not faked.
    report = _run("nar-flutter.py", _flutter_apk(tmp_path),
                  "--json")
    assert report["plugin_inventory"]["manifest_embedding"] \
        is None


def test_flutter_manifest_embedding_unit():
    rec = nar_flutter.manifest_embedding(build_axml("2"))
    assert rec["present"] is True and rec["value"] == "2"
    rec = nar_flutter.manifest_embedding(b"not axml")
    assert rec["present"] is None and "error" in rec


def test_flutter_real_fixture_by_role():
    fixture = _fixture_path("FIX_FLUTTER")
    if fixture is None:
        pytest.skip("FIX_FLUTTER fixture absent")
    report = _run("nar-flutter.py", str(fixture), "--json")
    assert report["is_flutter"] is True
    pinv = report["plugin_inventory"]
    # A release Flutter build registers its plugins through
    # the generated registrant in the DEX class table.
    assert pinv["generated_plugin_registrant"]["present"] \
        is True
    assert pinv["dex_class_count"] > 0
    emb = pinv["manifest_embedding"]
    assert emb is not None and emb["present"] is True
    assert emb["value"] == "2"


# ------------------------------------------------------------ React Native

RN_CLASSES = [
    ("Lcom/facebook/react/ReactPackage;",
     "Ljava/lang/Object;", []),
    ("Lcom/facebook/react/bridge/NativeModule;",
     "Ljava/lang/Object;", []),
    ("Lcom/facebook/react/bridge/BaseJavaModule;",
     "Ljava/lang/Object;",
     ["Lcom/facebook/react/bridge/NativeModule;"]),
    ("Lcom/example/app/MainPackage;", "Ljava/lang/Object;",
     ["Lcom/facebook/react/ReactPackage;"]),
    ("Lcom/facebook/react/viewmanagers/RNCSliderManagerInterface;",
     "Ljava/lang/Object;", []),
    ("Lcom/example/app/MyViewManagerDelegate;",
     "Ljava/lang/Object;", []),
    ("Lcom/facebook/fbreact/specs/NativeCameraSpec;",
     "Ljava/lang/Object;", []),
    ("Lcom/facebook/react/internal/turbomodule/core/"
     "TurboModuleManagerDelegate;", "Ljava/lang/Object;", []),
]

RN_BUNDLE = (
    "var cam = TurboModuleRegistry.getEnforcing("
    "'NativeCamera');\n"
    "var settings = NativeModules.Settings;\n"
).encode()


def _rn_apk(tmp_path, bundle=RN_BUNDLE, dex_strings=()):
    dex = build_dex(RN_CLASSES, extra_strings=dex_strings)
    return _apk(tmp_path / "rn.apk", {
        "assets/index.android.bundle": bundle,
        "classes.dex": dex,
    })


def test_rn_bridge_mapping_and_join(tmp_path):
    apk = _rn_apk(tmp_path, dex_strings=["NativeCamera"])
    report = _run("nar-rn.py", apk, "--json",
                  "--work", str(tmp_path / "work"))
    assert report["is_react_native"] is True
    bm = report["bridge_mapping"]
    present = {c["class"]: c["present"] for c in
               bm["framework_bridge_classes"]}
    assert present["Lcom/facebook/react/ReactPackage;"] \
        is True
    assert present["Lcom/facebook/react/bridge/NativeModule;"] \
        is True
    assert present["Lcom/facebook/react/bridge/BaseJavaModule;"] \
        is True
    assert present["Lcom/facebook/react/TurboReactPackage;"] \
        is False
    pkgs = {c["class"] for c in bm["react_packages"]["classes"]}
    assert pkgs == {"Lcom/example/app/MainPackage;"}
    cg = bm["codegen_markers"]
    assert cg["viewmanager_classes"]["counts"]["total"] == 1
    # The TurboModuleManagerDelegate bridge class is NOT a
    # view-manager delegate and must not be counted as one.
    assert cg["manager_delegate_classes"]["counts"]["total"] \
        == 1
    assert cg["manager_delegate_classes"]["classes"][0][
        "class"] == "Lcom/example/app/MyViewManagerDelegate;"
    assert cg["turbomodule_spec_classes"]["counts"]["total"] \
        == 1
    assert cg["turbomodule_spec_classes"]["classes"][0][
        "class"] == "Lcom/facebook/fbreact/specs/" \
                    "NativeCameraSpec;"
    join = bm["module_name_join"]
    assert join["status"] == "joined"
    assert join["matched"] == ["NativeCamera"]
    assert join["bundle_only"] == ["Settings"]


def test_rn_hermes_join_unavailable(tmp_path):
    # Minimal Hermes-shaped bundle: magic + header fields
    # the parser reads (version at 8, ten u32 at 32).
    hermes = nar_rn.HERMES_MAGIC + struct.pack("<I", 96)
    hermes += b"\x00" * 20
    hermes += struct.pack("<10I", 200, 0, 3, 1, 4, 5, 0, 16,
                          0, 0)
    hermes += b"\x00" * 64
    apk = _rn_apk(tmp_path, bundle=hermes)
    report = _run("nar-rn.py", apk, "--json",
                  "--work", str(tmp_path / "work"))
    assert report["engine"] == "Hermes"
    join = report["bridge_mapping"]["module_name_join"]
    assert join["status"] == "unavailable"
    assert "Hermes" in join["reason"]
    # DEX-side evidence still stands alone.
    assert report["bridge_mapping"]["react_packages"][
        "counts"]["total"] == 1


def test_rn_real_fixture_by_role(tmp_path):
    fixture = _fixture_path("FIX_RN")
    if fixture is None:
        pytest.skip("FIX_RN fixture absent")
    report = _run("nar-rn.py", str(fixture), "--json",
                  "--work", str(tmp_path / "work"))
    assert report["is_react_native"] is True
    bm = report["bridge_mapping"]
    assert bm["dex_files"], "RN fixture carries DEX files"
    present = [c for c in bm["framework_bridge_classes"]
               if c["present"]]
    assert present, "framework bridge classes in DEX"
    # This fixture is a minified new-architecture build:
    # its DEX carries codegen Native<Module>Spec classes
    # (the DEX-side TurboModule evidence), and its bundle
    # is Hermes, so the name join is honestly unavailable.
    assert bm["codegen_markers"]["turbomodule_spec_classes"][
        "counts"]["total"] > 0
    assert bm["module_name_join"]["status"] == "unavailable"
