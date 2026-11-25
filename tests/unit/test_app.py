"""Unit tests: the non-game app universe (Part 6).

Covers narlib.sqlite + nar-app.py + the nar-ask /
nar-blueprint deepenings from app.json. Fixtures are
synthetic with invented names only:

- a hand-built binary AXML manifest (string pool + start/
  end element chunks, the layout nar-perms parses) with a
  launcher activity, a deep-linked activity, a foreground
  service and three declared permissions;
- a hand-built DEX (strings/types/protos/fields/methods/
  class_defs + class_data + code items + annotation
  directories) carrying a @Composable method, a
  @JavascriptInterface method, Room/SQLiteOpenHelper/
  Fragment/Worker/JobService subclasses, an
  addJavascriptInterface + getSharedPreferences call site,
  permission string + field references, tracker/OAuth URL
  strings, and a PLANTED SYNTHETIC JWT;
- a REAL SQLite database built with python3's sqlite3
  module at fixture-build time only (the shipped parser
  under test parses bytes and never imports sqlite3);
- the JWT leak scan: the raw planted token must appear in
  NO output — nar-app JSON, nar-app human text, nar-ask
  answers, nar-blueprint documents — while its STRUCTURE
  (alg + claim names) is reported.

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import base64
import importlib.util
import json
import os
import sqlite3
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from narlib import evidence  # noqa: E402
from narlib import sqlite as sqlite_mod  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "test_ask_helpers_app", ROOT / "tests" / "unit" / "test_ask.py")
_helpers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_helpers)
ask = _helpers.ask
make_mini_case = _helpers.make_mini_case


def _load_tool(name, fname):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "scripts" / fname)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


nar_app = _load_tool("nar_app_tool", "nar-app.py")
blueprint = _load_tool("nar_blueprint_tool", "nar-blueprint.py")


def _schema(name):
    with open(ROOT / "schemas" / name, encoding="utf-8") as fh:
        return json.load(fh)


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


# ------------------------------------------------------------------
# JWT fixture (synthetic, invented claims)
# ------------------------------------------------------------------

def _b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


JWT_TOKEN = (
    _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    + "." + _b64u(json.dumps(
        {"sub": "user-123", "iss": "https://issuer.example",
         "exp": 1893456000, "scope": "read"}).encode())
    + "." + _b64u(b"synthetic-signature-bytes"))


# ------------------------------------------------------------------
# AXML builder
# ------------------------------------------------------------------

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def build_axml(tag, attrs, children):
    """Minimal binary AXML for one element tree. attrs is a
    list of (name, value) where name may carry the
    'android:' prefix; values are str (string attr), bool
    or int."""
    strings = []
    index = {}

    def sidx(s):
        if s not in index:
            index[s] = len(strings)
            strings.append(s)
        return index[s]

    sidx(ANDROID_NS)

    def collect(node):
        t, at, kids = node
        sidx(t)
        for name, value in at:
            sidx(name.split(":", 1)[-1])
            if isinstance(value, str):
                sidx(value)
        for k in kids:
            collect(k)

    collect((tag, attrs, children))
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
                        strings_start + len(body), len(strings),
                        0, 0, strings_start, 0)
    for off in offsets:
        pool += struct.pack("<I", off)
    pool += body

    def attr_bytes(at):
        out = bytearray()
        for name, value in at:
            prefixed = name.startswith("android:")
            ns = index[ANDROID_NS] if prefixed else 0xFFFFFFFF
            nm = index[name.split(":", 1)[-1]]
            if isinstance(value, bool):
                out += struct.pack("<IIIHBBI", ns, nm,
                                   0xFFFFFFFF, 8, 0, 0x12,
                                   0xFFFFFFFF if value else 0)
            elif isinstance(value, int):
                out += struct.pack("<IIIHBBI", ns, nm,
                                   0xFFFFFFFF, 8, 0, 0x10, value)
            else:
                vi = index[value]
                out += struct.pack("<IIIHBBI", ns, nm, vi, 8, 0,
                                   0x03, vi)
        return bytes(out)

    def elem_bytes(node):
        t, at, kids = node
        ab = attr_bytes(at)
        size = 36 + len(ab)
        out = bytearray()
        out += struct.pack("<HHI", 0x0102, 16, size)
        out += struct.pack("<II", 0, 0xFFFFFFFF)
        out += struct.pack("<II", 0xFFFFFFFF, index[t])
        out += struct.pack("<HHH", 20, 20, len(at))
        out += b"\x00" * 6
        out += ab
        for k in kids:
            out += elem_bytes(k)
        out += struct.pack("<HHI", 0x0103, 16, 24)
        out += struct.pack("<II", 0, 0xFFFFFFFF)
        out += struct.pack("<II", 0xFFFFFFFF, index[t])
        return bytes(out)

    root_bytes = elem_bytes((tag, attrs, children))
    total = 8 + len(pool) + len(root_bytes)
    return struct.pack("<HHI", 0x0003, 8, total) \
        + bytes(pool) + root_bytes


def manifest_axml():
    a = "android:"
    return build_axml("manifest", [
        ("package", "com.example.synthetic"),
        (a + "versionCode", 7),
        (a + "versionName", "1.0"),
    ], [
        ("uses-sdk", [], []),
        ("uses-permission",
         [(a + "name", "android.permission.INTERNET")], []),
        ("uses-permission",
         [(a + "name", "android.permission.CAMERA")], []),
        ("uses-permission",
         [(a + "name", "android.permission.RECORD_AUDIO")], []),
        ("application", [], [
            ("activity", [(a + "name", ".MainActivity"),
                          (a + "exported", True)], [
                ("intent-filter", [], [
                    ("action", [(a + "name",
                                 "android.intent.action.MAIN")],
                     []),
                    ("category", [(a + "name",
                                   "android.intent.category."
                                   "LAUNCHER")], []),
                ]),
            ]),
            ("activity", [(a + "name", ".DetailActivity"),
                          (a + "exported", True)], [
                ("intent-filter", [], [
                    ("action", [(a + "name",
                                 "android.intent.action.VIEW")],
                     []),
                    ("category", [(a + "name",
                                   "android.intent.category."
                                   "DEFAULT")], []),
                    ("data", [(a + "scheme", "exampleapp"),
                              (a + "host", "detail")], []),
                ]),
            ]),
            ("service", [(a + "name", ".SyncService"),
                         (a + "exported", False),
                         (a + "foregroundServiceType",
                          "dataSync")], []),
        ]),
    ])


def layout_axml(root_tag):
    return build_axml(root_tag, [], [])


# ------------------------------------------------------------------
# DEX builder
# ------------------------------------------------------------------

COMPOSABLE = "Landroidx/compose/runtime/Composable;"
JSIFACE = "Landroid/webkit/JavascriptInterface;"


def build_dex(classes, extra_strings=(), extra_method_refs=(),
              extra_field_refs=()):
    """classes: [{desc, super, class_annotations, methods:
    [{name, annotations, code: [units]}]}]. Method refs are
    collected from code via ('invoke', owner, name) markers
    pre-translated by the caller into unit lists using the
    returned builder state — instead, code is given as a
    list of ops: ("cs", string) | ("invoke", owner, name) |
    ("ret",)."""
    strings = set()
    types = set()

    def add_type(d):
        types.add(d)
        strings.add(d)

    def add_string(s):
        strings.add(s)

    all_methods = set(extra_method_refs)
    all_fields = set(extra_field_refs)
    for s in extra_strings:
        add_string(s)
    add_string("V")
    add_type("V")
    add_type("Ljava/lang/Object;")
    add_type("Ljava/lang/String;")
    for cls in classes:
        add_type(cls["desc"])
        if cls.get("super"):
            add_type(cls["super"])
        for ann in cls.get("class_annotations", []):
            add_type(ann)
        for m in cls.get("methods", []):
            add_string(m["name"])
            all_methods.add((cls["desc"], m["name"]))
            for ann in m.get("annotations", []):
                add_type(ann)
            for op in m.get("code", []):
                if op[0] == "cs":
                    add_string(op[1])
                elif op[0] == "invoke":
                    add_type(op[1])
                    add_string(op[2])
                    all_methods.add((op[1], op[2]))
    for owner, name in all_methods:
        add_type(owner)
        add_string(name)
    for owner, ftype, name in all_fields:
        add_type(owner)
        add_type(ftype)
        add_string(name)

    string_list = sorted(strings)
    sidx = {s: i for i, s in enumerate(string_list)}
    type_list = sorted(types)
    tidx = {t: i for i, t in enumerate(type_list)}
    proto = (sidx["V"], tidx["V"], 0)
    method_list = sorted(
        all_methods, key=lambda mn: (tidx[mn[0]], sidx[mn[1]]))
    midx = {mn: i for i, mn in enumerate(method_list)}
    field_list = sorted(
        all_fields,
        key=lambda f: (tidx[f[0]], tidx[f[1]], sidx[f[2]]))
    class_list = sorted(classes, key=lambda c: tidx[c["desc"]])

    header_size = 0x70
    string_ids_off = header_size
    # string data follows the ids table
    sdata = bytearray()
    soffsets = []
    string_data_off = string_ids_off + 4 * len(string_list)
    for s in string_list:
        soffsets.append(string_data_off + len(sdata))
        raw = s.encode("utf-8")
        sdata += _uleb(len(raw)) + raw + b"\x00"
    type_ids_off = string_data_off + len(sdata)
    proto_ids_off = type_ids_off + 4 * len(type_list)
    field_ids_off = proto_ids_off + 12
    method_ids_off = field_ids_off + 8 * len(field_list)
    class_defs_off = method_ids_off + 8 * len(method_list)
    data_start = class_defs_off + 32 * len(class_list)

    data_sec = bytearray()

    def emit(blob):
        off = data_start + len(data_sec)
        data_sec.extend(blob)
        return off

    class_records = []
    for cls in class_list:
        methods = sorted(
            cls.get("methods", []),
            key=lambda m: midx[(cls["desc"], m["name"])])
        # code items first
        code_offs = {}
        for m in methods:
            ops = m.get("code")
            if not ops:
                code_offs[m["name"]] = 0
                continue
            units = []
            for op in ops:
                if op[0] == "cs":
                    units += [0x001A, sidx[op[1]]]
                elif op[0] == "invoke":
                    units += [0x016E, midx[(op[1], op[2])], 0]
                elif op[0] == "ret":
                    units += [0x000E]
            blob = struct.pack("<HHHHII", 2, 1, 2, 0, 0,
                               len(units))
            blob += b"".join(struct.pack("<H", u) for u in units)
            code_offs[m["name"]] = emit(blob)
        # class_data
        cd = bytearray()
        cd += _uleb(0) + _uleb(0) + _uleb(len(methods)) + _uleb(0)
        prev = 0
        for m in methods:
            mi = midx[(cls["desc"], m["name"])]
            cd += _uleb(mi - prev) + _uleb(0x1) \
                + _uleb(code_offs[m["name"]])
            prev = mi
        class_data_off = emit(bytes(cd)) if methods else 0
        # annotations
        ann_off = 0
        class_ann = cls.get("class_annotations", [])
        method_anns = {m["name"]: m.get("annotations", [])
                       for m in methods
                       if m.get("annotations")}

        def ann_set(ann_types):
            item_offs = []
            for t in ann_types:
                item = bytes([1]) + _uleb(tidx[t]) + _uleb(0)
                item_offs.append(emit(item))
            blob = struct.pack("<I", len(item_offs)) + b"".join(
                struct.pack("<I", o) for o in item_offs)
            return emit(blob)

        if class_ann or method_anns:
            class_set = ann_set(class_ann) if class_ann else 0
            entries = []
            for mname, anns in sorted(
                    method_anns.items(),
                    key=lambda kv: midx[(cls["desc"], kv[0])]):
                entries.append(
                    (midx[(cls["desc"], mname)], ann_set(anns)))
            directory = struct.pack(
                "<IIII", class_set, 0, len(entries), 0)
            for mi, soff in entries:
                directory += struct.pack("<II", mi, soff)
            ann_off = emit(directory)
        class_records.append((cls, class_data_off, ann_off))

    file_size = data_start + len(data_sec)
    out = bytearray(file_size)
    out[0:8] = b"dex\n039\x00"
    struct.pack_into("<I", out, 32, file_size)
    struct.pack_into("<I", out, 36, header_size)
    struct.pack_into("<I", out, 40, 0x12345678)
    struct.pack_into("<II", out, 56, len(string_list),
                     string_ids_off)
    struct.pack_into("<II", out, 64, len(type_list), type_ids_off)
    struct.pack_into("<II", out, 72, 1, proto_ids_off)
    struct.pack_into("<II", out, 80, len(field_list),
                     field_ids_off)
    struct.pack_into("<II", out, 88, len(method_list),
                     method_ids_off)
    struct.pack_into("<II", out, 96, len(class_list),
                     class_defs_off)
    for i, off in enumerate(soffsets):
        struct.pack_into("<I", out, string_ids_off + 4 * i, off)
    out[string_data_off:string_data_off + len(sdata)] = sdata
    for i, t in enumerate(type_list):
        struct.pack_into("<I", out, type_ids_off + 4 * i, sidx[t])
    struct.pack_into("<III", out, proto_ids_off,
                     proto[0], proto[1], proto[2])
    for i, (owner, ftype, name) in enumerate(field_list):
        struct.pack_into("<HHI", out, field_ids_off + 8 * i,
                         tidx[owner], tidx[ftype], sidx[name])
    for i, (owner, name) in enumerate(method_list):
        struct.pack_into("<HHI", out, method_ids_off + 8 * i,
                         tidx[owner], 0, sidx[name])
    for i, (cls, cdo, ao) in enumerate(class_records):
        sup = cls.get("super")
        struct.pack_into(
            "<IIIIIIII", out, class_defs_off + 32 * i,
            tidx[cls["desc"]], 0x1,
            tidx[sup] if sup else 0xFFFFFFFF, 0, 0xFFFFFFFF,
            ao, cdo, 0)
    out[data_start:data_start + len(data_sec)] = data_sec
    return bytes(out)


def synthetic_dex():
    classes = [
        {"desc": "Lcom/example/MainActivity;",
         "super": "Landroidx/appcompat/app/AppCompatActivity;",
         "methods": [
             {"name": "onCreate", "code": [
                 ("cs", "settings"),
                 ("invoke", "Landroid/content/Context;",
                  "getSharedPreferences"),
                 ("invoke", "Landroid/webkit/WebView;",
                  "addJavascriptInterface"),
                 ("ret",)]},
             {"name": "saveToken", "code": [
                 ("cs", "user_token"),
                 ("invoke",
                  "Landroid/content/SharedPreferences$Editor;",
                  "putString"),
                 ("ret",)]},
         ]},
        {"desc": "Lcom/example/ui/HomeScreenKt;",
         "super": "Ljava/lang/Object;",
         "methods": [
             {"name": "HomeScreen", "annotations": [COMPOSABLE]},
             {"name": "DetailRow", "annotations": [COMPOSABLE]},
         ]},
        {"desc": "Lcom/example/ui/Widgets;",
         "super": "Ljava/lang/Object;",
         "class_annotations": [COMPOSABLE],
         "methods": []},
        {"desc": "Lcom/example/bridge/Bridge;",
         "super": "Ljava/lang/Object;",
         "methods": [
             {"name": "getData", "annotations": [JSIFACE]},
         ]},
        {"desc": "Lcom/example/data/AppDb;",
         "super": "Landroidx/room/RoomDatabase;", "methods": []},
        {"desc": "Lcom/example/data/DbHelper;",
         "super": "Landroid/database/sqlite/SQLiteOpenHelper;",
         "methods": []},
        {"desc": "Lcom/example/ui/ListFragment;",
         "super": "Landroidx/fragment/app/Fragment;",
         "methods": []},
        {"desc": "Lcom/example/work/SyncWorker;",
         "super": "Landroidx/work/Worker;", "methods": []},
        {"desc": "Lcom/example/work/SyncJob;",
         "super": "Landroid/app/job/JobService;", "methods": []},
        {"desc": "Lokhttp3/OkHttpClient;",
         "super": "Ljava/lang/Object;", "methods": []},
        {"desc": "Lokhttp3/Request;",
         "super": "Ljava/lang/Object;", "methods": []},
        {"desc": "Lnet/sqlcipher/database/SQLiteDatabase;",
         "super": "Ljava/lang/Object;", "methods": []},
    ]
    extra_refs = [
        ("Landroidx/security/crypto/EncryptedSharedPreferences;",
         "create"),
        ("Landroid/app/AlarmManager;", "set"),
        ("Lcom/google/android/gms/ads/identifier/"
         "AdvertisingIdClient;", "getAdvertisingIdInfo"),
        ("Lcom/google/android/ump/ConsentInformation;",
         "requestConsentInfoUpdate"),
        ("Landroidx/browser/customtabs/CustomTabsIntent;",
         "launchUrl"),
        ("Landroidx/datastore/core/DataStore;", "updateData"),
        ("Landroidx/work/WorkManager;", "getInstance"),
    ]
    extra_fields = [
        ("Landroid/Manifest$permission;", "Ljava/lang/String;",
         "CAMERA"),
    ]
    extra_strings = [
        "android.permission.INTERNET",
        JWT_TOKEN,
        "https://www.google-analytics.com/collect",
        "https://auth.example.com/oauth2/authorize"
        "?client_id=abc&response_type=code",
        "AndroidKeyStore",
    ]
    return build_dex(classes, extra_strings=extra_strings,
                     extra_method_refs=extra_refs,
                     extra_field_refs=extra_fields)


# ------------------------------------------------------------------
# SQLite fixture (built with sqlite3 at fixture time only)
# ------------------------------------------------------------------

def synthetic_db_bytes(tmp_path):
    path = tmp_path / "fixture.db"
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, "
                "name TEXT NOT NULL, score REAL)")
    con.execute("CREATE TABLE notes (note_id INTEGER PRIMARY "
                "KEY, user_id INTEGER, body TEXT, "
                "FOREIGN KEY(user_id) REFERENCES users(id))")
    con.execute("CREATE UNIQUE INDEX idx_users_name "
                "ON users(name)")
    con.execute("CREATE VIEW user_names AS SELECT name "
                "FROM users")
    con.execute("INSERT INTO users VALUES (1, 'ada', 9.5)")
    con.commit()
    con.close()
    return path.read_bytes()


def synthetic_apk(tmp_path):
    apk = tmp_path / "synthetic.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_axml())
        zf.writestr("classes.dex", synthetic_dex())
        zf.writestr("res/layout/activity_main.xml",
                    layout_axml("LinearLayout"))
        zf.writestr("res/layout/item_row.xml",
                    layout_axml("TextView"))
        zf.writestr("assets/data/app.db",
                    synthetic_db_bytes(tmp_path))
        zf.writestr("assets/config/settings.json",
                    b'{"theme": "dark"}')
        zf.writestr("META-INF/okhttp_okhttp.version", b"4.12.0\n")
    return str(apk)


@pytest.fixture(scope="module")
def report(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("app")
    return nar_app.scan_target(synthetic_apk(tmp))


# ------------------------------------------------------------------
# narlib.sqlite
# ------------------------------------------------------------------

def test_sqlite_schema_from_real_db(tmp_path):
    parsed = sqlite_mod.parse_sqlite_schema(
        synthetic_db_bytes(tmp_path))
    assert parsed["status"] == "supported"
    facts = parsed["facts"]
    tables = {t["name"]: t for t in facts["tables"]}
    assert set(tables) == {"users", "notes"}
    assert [c["name"] for c in tables["users"]["columns"]] == \
        ["id", "name", "score"]
    assert tables["users"]["columns"][1]["declared_type"] == "TEXT"
    assert facts["indexes"][0]["name"] == "idx_users_name"
    assert facts["indexes"][0]["unique"] is True
    assert facts["views"] == ["user_names"]
    assert facts["header"]["page_size"] in (512, 1024, 2048,
                                             4096, 8192, 16384,
                                             32768, 65536)


def test_sqlite_rejects_non_sqlite():
    parsed = sqlite_mod.parse_sqlite_schema(b"not a database")
    assert parsed["status"] == "identified_only"
    parsed = sqlite_mod.parse_sqlite_schema(
        b"SQLite format 3\x00" + b"\x00" * 200)
    assert parsed["status"] == "identified_only"


def test_sqlite_parser_never_imports_sqlite3():
    src = (ROOT / "scripts" / "narlib" / "sqlite.py").read_text()
    assert "import sqlite3" not in src
    assert ".execute(" not in src


# ------------------------------------------------------------------
# nar-app sections
# ------------------------------------------------------------------

def test_verdict_and_schema(report):
    assert report["verdict"] == "present"
    assert report["package"] == "com.example.synthetic"
    errors = evidence.validate(report, _schema("app.schema.json"))
    assert errors == [], errors


def test_compose_census(report):
    compose = report["ui_frameworks"]["jetpack_compose"]
    assert compose["present"] is True
    assert compose["composable_method_count"] == 2
    assert compose["composable_class_count"] == 1


def test_layout_census(report):
    view = report["ui_frameworks"]["view_xml"]
    assert view["layout_count"] == 2
    roots = {l["name"]: l["root_element"] for l in view["layouts"]}
    assert roots["res/layout/activity_main.xml"] == "LinearLayout"
    assert roots["res/layout/item_row.xml"] == "TextView"


def test_webview_bridge_surface(report):
    wv = report["ui_frameworks"]["webview_hybrid"]
    assert wv["add_javascript_interface_call_sites"] == 1
    assert wv["javascript_interface_method_count"] == 1
    assert "com.example.bridge.Bridge->getData" in \
        wv["javascript_interface_methods"]


def test_navigation_and_routes(report):
    nav = report["navigation"]
    assert nav["launcher_activity"] == \
        "com.example.synthetic.MainActivity"
    assert nav["activity_count"] == 2
    assert nav["fragment_class_count"] == 1
    assert nav["deep_link_count"] == 1
    dl = nav["deep_links"][0]
    assert dl["scheme"] == "exampleapp"
    assert dl["host"] == "detail"
    assert dl["component"] == "com.example.synthetic.DetailActivity"


def test_storage_sections(report):
    storage = report["storage"]
    prefs = storage["shared_preferences"]
    assert prefs["referenced"] is True
    assert "settings" in prefs["candidate_file_names"]
    assert "user_token" in prefs["candidate_keys"]
    room = storage["room_sqlite"]
    assert room["room_database_classes"] == ["com.example.data.AppDb"]
    assert room["sqlite_open_helper_classes"] == \
        ["com.example.data.DbHelper"]
    assert storage["datastore"]["present"] is True
    dbs = room["shipped_databases"]
    assert len(dbs) == 1
    assert dbs[0]["status"] == "supported"
    tables = {t["name"] for t in dbs[0]["facts"]["tables"]}
    assert tables == {"users", "notes"}
    assert storage["files_cache_assets"]["asset_file_count"] == 2


def test_encrypted_storage_detection(report):
    enc = report["encrypted_storage"]
    assert enc["sqlcipher"]["present"] is True
    assert enc["encrypted_shared_preferences"]["present"] is True
    assert enc["android_keystore"]["present"] is True
    assert enc["sqlcipher"]["detection_only"] is True


def test_background_work(report):
    bg = report["background_work"]
    assert bg["workmanager"]["worker_classes"] == \
        ["com.example.work.SyncWorker"]
    assert bg["jobscheduler"]["job_service_classes"] == \
        ["com.example.work.SyncJob"]
    assert bg["alarmmanager"]["present"] is True
    fg = bg["foreground_services"]
    assert fg and fg[0]["foreground_service_type"] == "dataSync"


def test_permissions_over_request(report):
    perm = report["permissions_in_use"]
    assert perm["declared_count"] == 3
    assert set(perm["code_referenced"]) == {
        "android.permission.INTERNET",
        "android.permission.CAMERA"}
    assert perm["declared_but_unreferenced"] == [
        "android.permission.RECORD_AUDIO"]
    assert "Manifest$permission" in perm["scan_method"]
    assert "not provably unused" in perm["scan_limits"]


def test_sdks_with_version_evidence(report):
    sdks = {s["id"]: s for s in report["sdks"]}
    assert sdks["okhttp"]["defined_class_count"] == 2
    assert sdks["okhttp"]["version"] == "4.12.0"
    assert sdks["okhttp"]["version_evidence"] == \
        "META-INF/okhttp_okhttp.version"
    assert report["library_versions"]["okhttp_okhttp"] == "4.12.0"
    # No .version evidence -> no version claimed.
    assert sdks["androidx-core"]["version"] is None


def test_compliance_surface(report):
    comp = report["compliance"]
    hosts = [t["host"] for t in comp["tracking_endpoints"]]
    assert "www.google-analytics.com" in hosts
    assert comp["advertising_id"]["present"] is True
    assert comp["consent_sdk"]["present"] is True


def test_auth_oauth_and_token_locations(report):
    auth = report["auth"]
    assert "auth.example.com" in auth["oauth"]["endpoint_hosts"]
    assert auth["oauth"]["custom_tab_refs"] >= 1
    assert auth["oauth"]["redirect_schemes"] == ["exampleapp"]
    assert "EncryptedSharedPreferences" in \
        auth["token_storage_locations"]
    assert "AndroidKeyStore-backed keys" in \
        auth["token_storage_locations"]


def test_screen_and_data_flow_maps(report):
    kinds = {}
    for e in report["screen_map"]:
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
        assert e["evidence"]
    assert kinds.get("activity") == 2
    assert kinds.get("composable") == 2
    assert kinds.get("layout") == 2
    assert kinds.get("fragment") == 1
    flow = report["data_flow"]
    assert flow and all(e["evidence"] for e in flow)
    assert any(e["via"] == "deep link intent filter" for e in flow)
    assert any(e["to"] == "www.google-analytics.com" for e in flow)


# ------------------------------------------------------------------
# JWT redaction: structure only, values nowhere
# ------------------------------------------------------------------

def test_jwt_structure_only(report):
    jwt = report["auth"]["jwt"]
    assert jwt["present"] is True
    assert jwt["structures"] == [{
        "alg": "HS256",
        "claim_names": ["exp", "iss", "scope", "sub"],
        "count": 1,
        "evidence": "DEX string pool: JWT-shaped string; "
                    "structure decoded, value redacted"}]


def test_jwt_leak_scan_all_outputs(tmp_path):
    apk = synthetic_apk(tmp_path)
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "nar-app.py"),
         apk, "--json"], capture_output=True, text=True,
        timeout=300)
    assert proc.returncode == 0
    assert JWT_TOKEN not in proc.stdout
    assert JWT_TOKEN not in proc.stderr
    proc_h = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "nar-app.py"),
         apk], capture_output=True, text=True, timeout=300)
    assert proc_h.returncode == 0
    assert JWT_TOKEN not in proc_h.stdout
    assert "alg=HS256" in proc_h.stdout
    # nar-ask answers over a case carrying this app.json.
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    target = tmp_path / "target.apk"
    make_mini_case(str(case_dir), str(target))
    with open(case_dir / "app.json", "w", encoding="utf-8") as fh:
        fh.write(proc.stdout)
    for question in ("What screens does it have?",
                     "How is the token stored?",
                     "How does the bridge work?"):
        doc = ask.answer_question(question, str(target),
                                  str(case_dir))
        blob = json.dumps(doc)
        assert JWT_TOKEN not in blob, question
    # nar-blueprint documents over the same case.
    spec_case = blueprint.Case(str(case_dir))
    spec = blueprint.Spec(spec_case, ask.sha256_of(str(target)))
    flows = blueprint.build_flows(spec)
    model = blueprint.build_data_model(spec)
    assert JWT_TOKEN not in flows
    assert JWT_TOKEN not in model
    assert "exampleapp" in flows


def test_scrub_pass_catches_planted_shapes():
    dirty = {"a": ["token is " + JWT_TOKEN + " ok"],
             "b": "api_key=supersecretvalue"}
    clean = nar_app.scrub(dirty)
    blob = json.dumps(clean)
    assert JWT_TOKEN not in blob
    assert "supersecretvalue" not in blob


# ------------------------------------------------------------------
# Absent / missing targets + ask & blueprint deepenings
# ------------------------------------------------------------------

def test_absent_target_verdict(tmp_path):
    loose = tmp_path / "notes.txt"
    loose.write_text("just text")
    rep = nar_app.scan_target(str(loose))
    assert rep["verdict"] == "absent"
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "nar-app.py"),
         str(loose), "--json"], capture_output=True, text=True,
        timeout=120)
    assert proc.returncode == 0
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "nar-app.py"),
         str(tmp_path / "missing.apk"), "--json"],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 2


def test_ask_screens_and_storage_deepen_from_app_json(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    target = tmp_path / "target.apk"
    make_mini_case(str(case_dir), str(target))
    rep = nar_app.scan_target(synthetic_apk(tmp_path))
    with open(case_dir / "app.json", "w", encoding="utf-8") as fh:
        json.dump(rep, fh)
    doc = ask.answer_question("What screens does it have?",
                              str(target), str(case_dir))
    assert doc["intent"] == "screens"
    assert "app.json" in json.dumps(doc["evidence"])
    assert "@Composable" in doc["answer"]
    doc = ask.answer_question("How is data stored?",
                              str(target), str(case_dir))
    assert doc["intent"] == "storage"
    blob = json.dumps(doc)
    assert "app.db" in blob
    assert "users" in blob
