"""Unit tests: Phase 2 app-intelligence fix round (M2-12).

Covers the app.json surfaces added so labeled app-intelligence
claims are asserted in app.json itself, with deterministic
evidence only:

- identity: package / label (manifest literal and
  resources.arsc resolution) / versions / SDK levels /
  native ABIs / signer subject from the shipped signing
  certificates (stdlib DER parse of v1 PKCS#7 + APK Signing
  Block), with cross-source conflicts surfaced;
- behaviour: <application>-element attributes asserted as
  declared-with-value or explicitly not declared, plus the
  bundled network-security-config resource census;
- components: the full manifest component census (all four
  component types + aliases, counts, explicit and effective
  exported counts, inventories) and the DEX *Activity class
  census reported alongside the manifest inventory;
- SDK census additions: vendor package-prefix / native
  library / shipped-asset signatures, each firing only on
  its documented evidence channel;
- storage: library-level Room presence (a lone
  MultiInstanceInvalidationService manifest artifact does
  not assert Room) and the MMKV signal (DEX /mmkv/ classes
  and/or an mmkv-named native library).

Fixtures are synthetic with invented names only: DER
certificates, a PKCS#7 blob, an APK Signing Block and a
resources.arsc are all built byte-by-byte below, and the
end-to-end scans run over a hand-built synthetic APK.

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import importlib.util
import io
import struct
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))


def _load_tool(name, fname):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "scripts" / fname)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


nar_app = _load_tool("nar_app_phase2", "nar-app.py")

_spec = importlib.util.spec_from_file_location(
    "test_app_builders", ROOT / "tests" / "unit" / "test_app.py")
_app_tests = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_app_tests)
build_axml = _app_tests.build_axml


# ------------------------------------------------------------------
# DER builder (synthetic certificates)
# ------------------------------------------------------------------

def _der(tag, content):
    size = len(content)
    if size < 0x80:
        head = bytes([tag, size])
    elif size < 0x100:
        head = bytes([tag, 0x81, size])
    else:
        head = bytes([tag, 0x82, size >> 8, size & 0xFF])
    return head + content


def _seq(*parts):
    return _der(0x30, b"".join(parts))


def _setof(*parts):
    return _der(0x31, b"".join(parts))


def _oid(arcs):
    body = bytes([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        stack = [arc & 0x7F]
        arc >>= 7
        while arc:
            stack.append(0x80 | (arc & 0x7F))
            arc >>= 7
        body += bytes(reversed(stack))
    return _der(0x06, body)


def _utf8(text):
    return _der(0x0C, text.encode("utf-8"))


def _name(rdns):
    return _seq(*[_setof(_seq(_oid(arcs), _utf8(value)))
                  for arcs, value in rdns])


CN = (2, 5, 4, 3)
O = (2, 5, 4, 10)
OU = (2, 5, 4, 11)
L = (2, 5, 4, 7)
ST = (2, 5, 4, 8)
C = (2, 5, 4, 6)


def make_cert(subject, issuer=None):
    issuer = issuer if issuer is not None else subject
    alg = _seq(_oid((1, 2, 840, 113549, 1, 1, 11)), _der(0x05, b""))
    validity = _seq(_der(0x17, b"250101000000Z"),
                    _der(0x17, b"350101000000Z"))
    spki = _seq(_seq(_oid((1, 2, 840, 113549, 1, 1, 1)),
                     _der(0x05, b"")),
                _der(0x03, b"\x00\x01\x02"))
    tbs = _seq(
        _der(0xA0, _der(0x02, b"\x02")),
        _der(0x02, b"\x01"),
        alg,
        _name(issuer),
        validity,
        _name(subject),
        spki,
    )
    return _seq(tbs, alg, _der(0x03, b"\x00\xaa\xbb"))


def make_pkcs7(cert_der):
    signed_data = _seq(
        _der(0x02, b"\x01"),
        _setof(),
        _seq(_oid((1, 2, 840, 113549, 1, 7, 1)), _der(0x05, b"")),
        _der(0xA0, cert_der),
        _setof(),
    )
    return _seq(
        _oid((1, 2, 840, 113549, 1, 7, 2)),
        _der(0xA0, signed_data),
    )


def _lp(blob):
    return struct.pack("<I", len(blob)) + blob


def signing_block_bytes(cert_ders, block_id=0x7109871A):
    certs_blob = b"".join(_lp(c) for c in cert_ders)
    signed_data = _lp(b"") + _lp(certs_blob) + _lp(b"")
    signer = _lp(signed_data) + _lp(b"") + _lp(b"")
    value = _lp(_lp(signer))
    pair_body = struct.pack("<I", block_id) + value
    pair = struct.pack("<Q", len(pair_body)) + pair_body
    block_size = len(pair) + 8 + 16
    return (struct.pack("<Q", block_size) + pair
            + struct.pack("<Q", block_size)
            + b"APK Sig Block 42")


def insert_signing_block(zip_bytes, cert_ders):
    """Splice a v2 signing block before the zip central
    directory and fix the EOCD offset, exactly where a real
    signer puts it."""
    eocd = zip_bytes.rfind(b"PK\x05\x06")
    assert eocd >= 0
    cd_off = struct.unpack_from("<I", zip_bytes, eocd + 16)[0]
    block = signing_block_bytes(cert_ders)
    out = zip_bytes[:cd_off] + block + zip_bytes[cd_off:]
    new_eocd = eocd + len(block)
    out = (out[:new_eocd + 16]
           + struct.pack("<I", cd_off + len(block))
           + out[new_eocd + 20:])
    return out


# ------------------------------------------------------------------
# resources.arsc builder
# ------------------------------------------------------------------

def _string_pool(strings):
    offsets = []
    body = bytearray()
    for text in strings:
        offsets.append(len(body))
        raw = text.encode("utf-16-le")
        body += struct.pack("<H", len(text)) + raw + b"\x00\x00"
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    pool = bytearray()
    pool += struct.pack("<HHIIIII", 0x0001, header_size,
                        strings_start + len(body), len(strings),
                        0, 0, strings_start)
    # struct above packs type/headerSize/size then 5 u32s from
    # stringCount onward; rebuild explicitly to be safe.
    pool = bytearray()
    pool += struct.pack("<HHI", 0x0001, header_size,
                        strings_start + len(body))
    pool += struct.pack("<IIIII", len(strings), 0, 0,
                        strings_start, 0)
    for off in offsets:
        pool += struct.pack("<I", off)
    pool += body
    return bytes(pool)


def make_arsc(label_text):
    global_pool = _string_pool([label_text, "other"])
    type_pool = _string_pool(["string"])
    key_pool = _string_pool(["app_name"])
    entry = struct.pack("<HHI", 8, 0, 0) \
        + struct.pack("<HBBI", 8, 0, 0x03, 0)
    config_size = 16
    type_header = 20 + config_size
    entries_start = type_header + 4
    type_chunk = bytearray()
    type_chunk += struct.pack("<HHI", 0x0201, type_header,
                              entries_start + len(entry))
    type_chunk += struct.pack("<BBHII", 1, 0, 0, 1, entries_start)
    type_chunk += struct.pack("<I", config_size) + b"\x00" * 12
    type_chunk += struct.pack("<I", 0)
    type_chunk += entry
    package_header = 288
    type_off = package_header
    key_off = type_off + len(type_pool)
    types_start = key_off + len(key_pool)
    package_size = types_start + len(type_chunk)
    package = bytearray()
    package += struct.pack("<HHII", 0x0200, package_header,
                           package_size, 0x7F)
    package += b"\x00" * 256
    package += struct.pack("<IIIII", type_off, 1, key_off, 1, 0)
    assert len(package) == package_header, len(package)
    package += type_pool + key_pool + type_chunk
    total = 12 + len(global_pool) + len(package)
    header = struct.pack("<HHII", 0x0002, 12, total, 1)
    return header + global_pool + bytes(package)


# ------------------------------------------------------------------
# Signer parsing
# ------------------------------------------------------------------

# DER sequence order is country-first; the printed DN
# reverses it (RFC 4519), as keytool/apksigner do.
SUBJECT = [(C, "EG"), (O, "Example Org"), (CN, "Maker")]
SUBJECT_DN = "CN=Maker, O=Example Org, C=EG"


def test_cert_subject_parsed_from_der():
    info = nar_app._cert_info(make_cert(SUBJECT), "test")
    assert info["subject"] == SUBJECT_DN
    assert info["issuer"] == SUBJECT_DN
    assert len(info["sha256"]) == 64


def test_certs_from_pkcs7_roundtrip():
    cert = make_cert(SUBJECT)
    blob = make_pkcs7(cert)
    found = nar_app._certs_from_pkcs7(blob)
    assert found == [cert]
    assert nar_app._cert_info(found[0], "x")["subject"] == SUBJECT_DN


def test_certs_from_signing_block(tmp_path):
    cert = make_cert(SUBJECT)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("classes.dex", b"dex\n035\x00")
    apk = insert_signing_block(buf.getvalue(), [cert])
    path = tmp_path / "signed.apk"
    path.write_bytes(apk)
    found = nar_app._certs_from_signing_block(str(path))
    assert found == [(cert, "v2")]
    # The spliced file is still a readable zip.
    with zipfile.ZipFile(path) as zf:
        assert zf.namelist() == ["classes.dex"]


def test_arsc_string_resolution():
    data = make_arsc("Synthetic App")
    assert nar_app._arsc_lookup(data, 0x7F010000) == "Synthetic App"
    assert nar_app._arsc_lookup(data, 0x7F020000) is None
    assert nar_app._arsc_lookup(b"not an arsc", 0x7F010000) is None


# ------------------------------------------------------------------
# End-to-end synthetic APK: identity + behaviour
# ------------------------------------------------------------------

def synthetic_identity_apk(tmp_path, label_attr="@0x7f010000",
                           extra_certs=()):
    a = "android:"
    manifest = build_axml("manifest", [
        ("package", "com.example.synthetic"),
        (a + "versionCode", 94),
        (a + "versionName", "1.2.3"),
        (a + "compileSdkVersion", 34),
        (a + "installLocation", 1),
    ], [
        ("uses-sdk", [(a + "minSdkVersion", 24),
                      (a + "targetSdkVersion", 36)], []),
        ("uses-feature", [(a + "glEsVersion", 0x30002)], []),
        ("application", [
            (a + "name", ".App"),
            (a + "label", label_attr),
            (a + "debuggable", False),
            (a + "allowBackup", True),
            (a + "networkSecurityConfig", "@0x7f150005"),
            (a + "extractNativeLibs", False),
        ], [
            ("activity", [(a + "name", ".MainActivity"),
                          (a + "exported", True)], [
                ("intent-filter", [], [
                    ("action", [(a + "name",
                                 "android.intent.action.MAIN")], []),
                    ("category", [(a + "name",
                                   "android.intent.category."
                                   "LAUNCHER")], []),
                ]),
            ]),
            ("service", [(a + "name", ".SyncService"),
                         (a + "exported", False)], []),
            ("receiver", [(a + "name", ".BootReceiver")], []),
            ("provider", [(a + "name", ".DataProvider"),
                          (a + "exported", True)], []),
        ]),
    ])
    cert = make_cert(SUBJECT)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("resources.arsc", make_arsc("Synthetic App"))
        zf.writestr("lib/arm64-v8a/libgame.so", b"\x7fELF")
        zf.writestr("lib/armeabi-v7a/libgame.so", b"\x7fELF")
        zf.writestr("res/xml/network_security_config.xml",
                    b"<network-security-config/>")
        zf.writestr("META-INF/CERT.RSA", make_pkcs7(cert))
    data = buf.getvalue()
    if extra_certs:
        data = insert_signing_block(data, list(extra_certs))
    path = tmp_path / "synthetic.apk"
    path.write_bytes(data)
    return path


def test_identity_section_end_to_end(tmp_path):
    path = synthetic_identity_apk(tmp_path)
    report = nar_app.scan_target(str(path))
    identity = report["identity"]
    assert identity["package"] == "com.example.synthetic"
    assert identity["app_label"] == "Synthetic App"
    assert identity["app_label_raw"] == "@0x7f010000"
    assert "resources.arsc" in identity["app_label_source"]
    assert identity["version_name"] == "1.2.3"
    assert identity["version_code"] == 94
    assert identity["compile_sdk_version"] == 34
    assert identity["min_sdk"] == 24
    assert identity["target_sdk"] == 36
    assert identity["native_abis"] == ["arm64-v8a", "armeabi-v7a"]
    signer = identity["signer"]
    assert signer["found"] is True
    assert signer["subject"] == SUBJECT_DN
    assert signer["certificates"][0]["subject"] == SUBJECT_DN
    assert "CERT.RSA" in signer["certificates"][0]["source"]


def test_identity_literal_label(tmp_path):
    path = synthetic_identity_apk(tmp_path,
                                  label_attr="Literal Label")
    report = nar_app.scan_target(str(path))
    identity = report["identity"]
    assert identity["app_label"] == "Literal Label"
    assert identity["app_label_source"].endswith("literal")


def test_signer_conflict_is_surfaced_not_picked(tmp_path):
    other = make_cert([(O, "Other Org"), (CN, "Other")])
    path = synthetic_identity_apk(tmp_path, extra_certs=(other,))
    report = nar_app.scan_target(str(path))
    signer = report["identity"]["signer"]
    assert signer["found"] is True
    assert signer["subject"] is None
    assert sorted(signer["conflicting_subjects"]) == [
        "CN=Maker, O=Example Org, C=EG",
        "CN=Other, O=Other Org"]
    assert "conflict_note" in signer
    subjects = {c["subject"] for c in signer["certificates"]}
    assert subjects == set(signer["conflicting_subjects"])


# ------------------------------------------------------------------
# Components census + DEX activity census
# ------------------------------------------------------------------

def test_components_section_end_to_end(tmp_path):
    path = synthetic_identity_apk(tmp_path)
    report = nar_app.scan_target(str(path))
    section = report["components"]
    assert section["counts"] == {
        "activity": 1, "activity-alias": 0, "service": 1,
        "receiver": 1, "provider": 1, "total": 4}
    # Explicit android:exported=true: the activity and the
    # provider. The service declares exported=false; the
    # receiver declares nothing and has no intent filter, so
    # it is not effectively exported either.
    assert section["per_type"]["activity"][
        "exported_explicit_true"] == 1
    assert section["per_type"]["provider"][
        "exported_explicit_true"] == 1
    assert section["per_type"]["service"][
        "exported_explicit_true"] == 0
    assert section["per_type"]["receiver"][
        "exported_effective"] == 0
    assert section["exported_explicit_true_total"] == 2
    assert section["exported_attribute_declared_total"] == 3
    assert section["application_class"] == \
        "com.example.synthetic.App"
    assert section["launcher_activity"] == \
        "com.example.synthetic.MainActivity"
    names = {c["name"] for c in
             section["inventories"]["service"]}
    assert names == {"com.example.synthetic.SyncService"}
    totals = report["totals"]
    assert totals["services"] == 1
    assert totals["receivers"] == 1
    assert totals["providers"] == 1
    assert totals["exported_components_explicit"] == 2


def test_dex_activity_census_unit():
    class FakeFacts:
        # The census basis is the DEX type-descriptor list
        # (defined + referenced types), not class definitions.
        type_refs = {
            "Lcom/example/MainActivity;",
            "Lcom/example/DetailActivity;",
            "Lcom/example/MainActivity$InnerActivity;",
            "Lcom/example/Helper;",
            "Lorg/lib/SdkActivity;",
            "Lorg/lib/NotScreen;",
            # a referenced-only type still counts (it is in
            # the type list although no class_def defines it)
            "Lcom/example/ReferencedOnlyActivity;",
        }
        classes = []
    census = nar_app._dex_activity_census(
        FakeFacts(), "com.example")
    assert census["activity_named_class_count"] == 5
    assert census["app_package_activity_named_class_count"] == 4
    assert census["app_package_top_level_activity_count"] == 3
    assert census["app_package_top_level_activities"] == [
        "com.example.DetailActivity", "com.example.MainActivity",
        "com.example.ReferencedOnlyActivity"]
    assert census["basis"] == "DEX type-descriptor census"


def test_dex_activity_census_launcher_root():
    # applicationId carries a suffix the code root does not:
    # the launcher activity's package supplies the code root.
    class FakeFacts:
        type_refs = {
            "Lcom/applylabs/whatsmock/SplashScreenActivity;",
            "Lcom/applylabs/whatsmock/ChatActivity;",
            "Lorg/lib/SdkActivity;",
        }
        classes = []
    census = nar_app._dex_activity_census(
        FakeFacts(), "com.applylabs.whatsmock.free",
        "com.applylabs.whatsmock.SplashScreenActivity")
    assert census["app_package_activity_named_class_count"] == 2
    assert census["app_package_roots"] == [
        "com.applylabs.whatsmock", "com.applylabs.whatsmock.free"]


# ------------------------------------------------------------------
# SDK census additions
# ------------------------------------------------------------------

class _FakeFacts:
    def __init__(self, classes, type_refs=()):
        self.classes = [(d, "Ljava/lang/Object;")
                        for d in classes]
        self.type_refs = set(type_refs)


def test_sdk_census_new_families_and_channels():
    facts = _FakeFacts(
        classes=[
            "Lcom/vungle/ads/VungleAds;",
            "Lcom/vungle/ads/internal/AdLoader;",
            "Lcom/beetalk/sdk/PluginManager;",
            "Lcom/revenuecat/purchases/Purchases;",
        ],
        type_refs=[
            "Lcom/chartboost/sdk/Chartboost;",
            "Lcom/chartboost/sdk/CBImpressionActivity;",
        ])
    sdks = {s["id"]: s for s in nar_app._sdk_inventory(
        facts, {},
        native_libs=["libtapjoy.so", "libGGP.so", "libother.so"],
        member_names=[
            "assets/flutter_assets/packages/purchases_flutter/"
            "assets/web/purchases_js.js",
            "classes.dex"])}
    # DEX defined-class channel.
    assert sdks["vungle"]["defined_class_count"] == 2
    assert sdks["garena"]["defined_class_count"] == 1
    # Referenced-only channel: Chartboost is asserted with the
    # referenced-only basis stated in its evidence.
    assert sdks["chartboost"]["defined_class_count"] == 0
    assert sdks["chartboost"]["referenced_type_count"] == 2
    assert "referenced-only" in sdks["chartboost"]["evidence"]
    # Native-carried channel: Tapjoy has no DEX classes here;
    # the native library alone carries the entry.
    assert sdks["tapjoy"]["defined_class_count"] == 0
    assert sdks["tapjoy"]["native_libraries"] == ["libtapjoy.so"]
    assert "libtapjoy.so" in sdks["tapjoy"]["evidence"]
    assert sdks["garena"]["native_libraries"] == ["libGGP.so"]
    # Shipped-member channel: the purchases plugin asset.
    assert "purchases_flutter" in \
        sdks["revenuecat"]["member_evidence"][0]
    # Absent families stay absent: no signature, no entry.
    for absent in ("adcolony", "inmobi", "mintegral", "fyber",
                   "moloco", "deltadna", "bidstack", "pangle"):
        assert absent not in sdks


def test_sdk_census_prefixes_do_not_cross_fire():
    facts = _FakeFacts(classes=[
        "Lcom/vungleextra/NotVungle;",
        "Lcom/molocorp/NotMoloco;",
        "Lcom/inmobiles/NotInMobi;",
    ])
    ids = {s["id"] for s in nar_app._sdk_inventory(facts, {})}
    assert "vungle" not in ids
    assert "moloco" not in ids
    assert "inmobi" not in ids


# ------------------------------------------------------------------
# Storage signals: library-level Room + MMKV
# ------------------------------------------------------------------

def _storage_apk(tmp_path, dex_classes, native_libs=()):
    """Synthetic APK whose DEX is built by the test_app DEX
    builder with the given (desc, super) classes."""
    a = "android:"
    manifest = build_axml("manifest", [
        ("package", "com.example.synthetic"),
        (a + "versionCode", 3),
        (a + "versionName", "0.3"),
    ], [
        ("uses-sdk", [(a + "minSdkVersion", 24),
                      (a + "targetSdkVersion", 36)], []),
        ("application", [(a + "name", ".App")], []),
    ])
    dex = _app_tests.build_dex([
        {"desc": desc, "super": sup}
        for desc, sup in dex_classes])
    path = tmp_path / "storage.apk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", dex)
        for lib in native_libs:
            zf.writestr(f"lib/arm64-v8a/{lib}", b"\x7fELF")
    return path


def test_room_library_level_presence(tmp_path):
    path = _storage_apk(tmp_path, [
        ("Landroidx/room/RoomDatabase;", "Ljava/lang/Object;"),
        ("Landroidx/room/Room;", "Ljava/lang/Object;"),
        ("Landroidx/room/MultiInstanceInvalidationService;",
         "Landroid/app/Service;"),
        ("Lcom/example/Main;", "Ljava/lang/Object;"),
    ])
    report = nar_app.scan_target(str(path))
    room = report["storage"]["room_sqlite"]["room_library"]
    assert room["present"] is True
    assert room["defined_class_count"] == 3
    assert room["defined_class_count_excluding_service"] == 2
    # No RoomDatabase subclass exists in this fixture: the
    # library signal is independent of database classes.
    assert report["storage"]["room_sqlite"][
        "room_database_classes"] == []


def test_room_service_artifact_alone_is_not_presence(tmp_path):
    path = _storage_apk(tmp_path, [
        ("Landroidx/room/MultiInstanceInvalidationService;",
         "Landroid/app/Service;"),
        ("Lcom/example/Main;", "Ljava/lang/Object;"),
    ])
    report = nar_app.scan_target(str(path))
    room = report["storage"]["room_sqlite"]["room_library"]
    assert room["present"] is False
    assert room["defined_class_count"] == 1
    assert room["defined_class_count_excluding_service"] == 0


def test_mmkv_signal_dex_and_native(tmp_path):
    path = _storage_apk(tmp_path, [
        ("Lcom/vendor/mmkv/MMKV;", "Ljava/lang/Object;"),
        ("Lcom/example/Main;", "Ljava/lang/Object;"),
    ], native_libs=["libmeemo_mmkv.so"])
    report = nar_app.scan_target(str(path))
    mmkv = report["storage"]["mmkv"]
    assert mmkv["present"] is True
    assert mmkv["dex_class_count"] == 1
    assert mmkv["native_libraries"] == ["libmeemo_mmkv.so"]
    assert "MMKV" in report["auth"]["token_storage_locations"]


def test_mmkv_absent_without_signal(tmp_path):
    path = _storage_apk(tmp_path, [
        ("Lcom/example/Main;", "Ljava/lang/Object;"),
    ])
    report = nar_app.scan_target(str(path))
    assert report["storage"]["mmkv"]["present"] is False
    assert report["storage"]["mmkv"]["dex_class_count"] == 0


def test_behaviour_section_end_to_end(tmp_path):
    path = synthetic_identity_apk(tmp_path)
    report = nar_app.scan_target(str(path))
    behaviour = report["behaviour"]
    attrs = behaviour["attributes"]
    assert attrs["debuggable"] == {"declared": True, "value": False}
    assert attrs["allowBackup"] == {"declared": True, "value": True}
    assert attrs["networkSecurityConfig"] == {
        "declared": True, "value": "@0x7f150005"}
    assert attrs["extractNativeLibs"] == {
        "declared": True, "value": False}
    # Absence is a parse result, asserted explicitly.
    assert attrs["fullBackupContent"] == {
        "declared": False, "value": None}
    assert attrs["usesCleartextTraffic"] == {
        "declared": False, "value": None}
    assert behaviour["application_class"] == \
        "com.example.synthetic.App"
    nsc = behaviour["network_security_config_resource"]
    assert nsc["present"] is True
    assert nsc["members"] == ["res/xml/network_security_config.xml"]
    assert behaviour["install_location"] == 1
    assert behaviour["install_location_name"] == "preferExternal"
    assert behaviour["gl_es_versions"] == ["0x30002"]
