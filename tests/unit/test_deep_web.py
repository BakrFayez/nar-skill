"""Unit tests: Part 3.2 web/text deep dives (nar-cordova,
nar-capacitor, nar-air, nar-love, nar-rpgmaker,
nar-webassets).

Synthetic APKs only (zips built in tmp with invented
content); golden assertions on parsed values — plugin merge
sources, descriptor fields, a hand-built CWS SWF's tag
census / exported symbol / frame count, conf.lua textual
facts, the RPG Maker database census, and bundle marker
counts. Each tool also gets an absent control (empty APK ->
verdict absent, exit 0) and the shared --json verdict shape
is asserted. The nar-engines --deep integration is NOT
exercised here: nar-engines resolves deep tools from
formats.json, which names these scripts only after the
coordinator merge.
"""
import io
import json
import struct
import subprocess
import sys
import zipfile
import zlib
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"

TOOLS = ("nar-cordova", "nar-capacitor", "nar-air", "nar-love",
         "nar-rpgmaker", "nar-webassets")


def _apk(tmp_path, name, members):
    path = tmp_path / name
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for member, data in members:
            if isinstance(data, str):
                data = data.encode()
            zf.writestr(member, data)
    path.write_bytes(buf.getvalue())
    return path


def _run(tool, target, *extra):
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / f"{tool}.py"),
         str(target), "--json", *extra],
        capture_output=True, text=True, timeout=120)
    return proc


def _report(tool, target):
    proc = _run(tool, target)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def _empty_apk(tmp_path):
    return _apk(tmp_path, "empty.apk",
                [("classes.dex", b"dex\n035\x00")])


# ---------------------------------------------------------------
# Cordova

CORDOVA_CONFIG = """<?xml version="1.0" encoding="utf-8"?>
<widget id="com.example.hello" version="1.2.3"
    xmlns="http://www.w3.org/ns/widgets"
    xmlns:cdv="http://cordova.apache.org/ns/1.0">
    <name>HelloApp</name>
    <description>A synthetic hello app.</description>
    <preference name="Fullscreen" value="true" />
    <preference name="Orientation" value="portrait" />
    <access origin="*" />
    <access origin="https://example.com" />
    <feature name="cordova-plugin-device">
        <param name="android-package"
               value="org.apache.cordova.device.Device" />
    </feature>
    <feature name="cordova-plugin-camera">
        <param name="android-package"
               value="org.apache.cordova.camera.CameraLauncher" />
    </feature>
</widget>
"""

CORDOVA_PLUGINS_JS = """cordova.define('cordova/plugin_list', function(require, exports, module) {
module.exports = [];
module.exports.metadata =
// TOP OF METADATA
{
    "cordova-plugin-device": "2.0.0",
    "cordova-plugin-network": "1.0.0"
}
// BOTTOM OF METADATA
});
"""


def _cordova_apk(tmp_path):
    return _apk(tmp_path, "cordova.apk", [
        ("assets/www/config.xml", CORDOVA_CONFIG),
        ("assets/www/index.html",
         "<html><head><title>Hello Title</title></head></html>"),
        ("assets/www/cordova.js", "// cordova runtime"),
        ("assets/www/cordova_plugins.js", CORDOVA_PLUGINS_JS),
        ("assets/www/js/app.js", "console.log(1)"),
        ("assets/www/css/style.css", "body{}"),
    ])


def test_cordova_descriptor_and_census(tmp_path):
    report = _report("nar-cordova", _cordova_apk(tmp_path))
    assert report["verdict"] == "present"
    d = report["descriptor"]
    assert d["id"] == "com.example.hello"
    assert d["version"] == "1.2.3"
    assert d["name"] == "HelloApp"
    assert d["description_present"] is True
    assert d["preference_count"] == 2
    assert d["preference_names"] == ["Fullscreen", "Orientation"]
    assert d["access_origins"] == ["*", "https://example.com"]
    web = report["web_root"]
    assert web["root"] == "assets/www/"
    assert web["file_count"] == 6
    assert web["by_extension"]["js"] == 3
    assert web["index_html_present"] is True
    assert web["index_title"] == "Hello Title"


def test_cordova_merged_plugins(tmp_path):
    report = _report("nar-cordova", _cordova_apk(tmp_path))
    plugins = {p["id"]: p for p in report["plugins"]}
    assert set(plugins) == {"cordova-plugin-device",
                            "cordova-plugin-camera",
                            "cordova-plugin-network"}
    device = plugins["cordova-plugin-device"]
    assert device["source"] == "both"
    assert device["version"] == "2.0.0"
    assert device["android_package"] == \
        "org.apache.cordova.device.Device"
    camera = plugins["cordova-plugin-camera"]
    assert camera["source"] == "config"
    assert camera["version"] is None
    assert camera["android_package"] == \
        "org.apache.cordova.camera.CameraLauncher"
    network = plugins["cordova-plugin-network"]
    assert network["source"] == "plugins_js"
    assert network["version"] == "1.0.0"


def test_cordova_nonexistent_target_exit_2(tmp_path):
    proc = _run("nar-cordova", tmp_path / "nope.apk")
    assert proc.returncode == 2


# ---------------------------------------------------------------
# Capacitor

CAPACITOR_CONFIG = json.dumps({
    "appId": "com.example.cap",
    "appName": "CapApp",
    "webDir": "public",
    "bundledWebRuntime": False,
    "server": {
        "androidScheme": "https",
        "hostname": "localhost",
        "url": "https://user:secret@example.com/app",
    },
})


def _capacitor_apk(tmp_path):
    return _apk(tmp_path, "capacitor.apk", [
        ("assets/capacitor.config.json", CAPACITOR_CONFIG),
        ("assets/capacitor.plugins.json", json.dumps([
            {"id": "com.example.plugin-a", "name": "PluginA",
             "version": "1.0.0"},
        ])),
        ("assets/native-bridge.js", "// bridge"),
        ("assets/public/index.html",
         "<html><head><title>Cap Title</title></head></html>"),
        ("assets/public/main.js", "console.log(2)"),
        ("assets/public/styles.css", "body{}"),
        ("assets/public/capacitor.js", "// capacitor web runtime"),
    ])


def test_capacitor_descriptor_plugins_markers(tmp_path):
    proc = _run("nar-capacitor", _capacitor_apk(tmp_path))
    assert proc.returncode == 0, proc.stderr
    # The full server URL (with its credentials) never prints.
    assert "secret" not in proc.stdout
    assert "user:secret@example.com" not in proc.stdout
    report = json.loads(proc.stdout)
    assert report["verdict"] == "present"
    d = report["descriptor"]
    assert d["appId"] == "com.example.cap"
    assert d["appName"] == "CapApp"
    assert d["webDir"] == "public"
    assert d["bundledWebRuntime"] is False
    assert d["server"]["androidScheme"] == "https"
    assert d["server"]["hostname"] == "localhost"
    assert d["server"]["url_present"] is True
    assert d["server"]["url_host"] == "example.com"
    web = report["web_root"]
    assert web["root"] == "assets/public/"
    assert web["file_count"] == 4
    assert web["index_title"] == "Cap Title"
    assert report["plugins"] == [
        {"id": "com.example.plugin-a", "name": "PluginA",
         "version": "1.0.0"}]
    markers = report["native_markers"]
    assert markers["native_bridge_js_present"] is True
    assert markers["capacitor_js_present"] is True


def test_capacitor_no_plugins_json_note(tmp_path):
    apk = _apk(tmp_path, "cap-noplugins.apk", [
        ("assets/capacitor.config.json", CAPACITOR_CONFIG),
        ("assets/public/index.html", "<html></html>"),
    ])
    report = _report("nar-capacitor", apk)
    assert report["verdict"] == "present"
    assert report["plugins"] == []
    assert any("native-side" in n for n in report["notes"])


# ---------------------------------------------------------------
# Adobe AIR

AIR_DESCRIPTOR = """<?xml version="1.0" encoding="utf-8"?>
<application xmlns="http://ns.adobe.com/air/application/33.1">
    <id>com.example.air</id>
    <versionNumber>1.0.0</versionNumber>
    <filename>AirApp</filename>
    <name>AirApp</name>
    <initialWindow>
        <content>AirApp.swf</content>
        <title>Air Title</title>
        <systemChrome>standard</systemChrome>
        <transparent>false</transparent>
    </initialWindow>
    <supportedProfiles>desktop extendedDesktop</supportedProfiles>
    <extensions>
        <extensionID>com.example.ext-one</extensionID>
        <extensionID>com.example.ext-two</extensionID>
    </extensions>
</application>
"""


def _tag(code, payload):
    # Real SWF RECORDHEADER: high 10 bits code, low 6 bits
    # short length (0x3F -> long u32 length follows).
    if len(payload) < 0x3F:
        return struct.pack("<H", (code << 6) | len(payload)) \
            + payload
    return struct.pack("<H", (code << 6) | 0x3F) \
        + struct.pack("<I", len(payload)) + payload


def _cws_swf():
    body = bytearray()
    body += bytes([0x08, 0x00])            # RECT, nbits=1
    body += struct.pack("<H", 24 << 8)     # frame rate 24.0
    body += struct.pack("<H", 3)           # frame count 3
    body += _tag(9, b"\xff\xff\xff")       # SetBackgroundColor
    body += _tag(82, b"\x00\x01\x02\x03")  # DoABC placeholder
    symbol = struct.pack("<HH", 1, 0) + b"com.example.Hero\x00"
    body += _tag(76, symbol)               # SymbolClass
    body += _tag(0, b"")                   # End
    header = b"CWS" + bytes([15]) \
        + struct.pack("<I", 8 + len(body))
    return header + zlib.compress(bytes(body))


def test_air_descriptor_and_swf(tmp_path):
    apk = _apk(tmp_path, "air.apk", [
        ("META-INF/AIR/application.xml", AIR_DESCRIPTOR),
        ("AirApp.swf", _cws_swf()),
    ])
    report = _report("nar-air", apk)
    assert report["verdict"] == "present"
    d = report["descriptor"]
    assert d["id"] == "com.example.air"
    assert d["version"] == "1.0.0"
    assert d["filename"] == "AirApp"
    assert d["name"] == "AirApp"
    win = d["initialWindow"]
    assert win["content"] == "AirApp.swf"
    assert win["title"] == "Air Title"
    assert win["systemChrome"] == "standard"
    assert win["transparent"] == "false"
    assert d["supportedProfiles"] == ["desktop", "extendedDesktop"]
    assert d["extension_count"] == 2
    assert len(report["swf"]) == 1
    swf = report["swf"][0]
    assert swf["signature"] == "CWS"
    assert swf["version"] == 15
    assert swf["frame_count"] == 3
    assert swf["frame_rate"] == 24.0
    assert swf["tag_census"]["SetBackgroundColor"] == 1
    assert swf["tag_census"]["DoABC"] == 1
    assert swf["tag_census"]["SymbolClass"] == 1
    assert swf["tag_census"]["End"] == 1
    assert swf["exported_symbols"] == ["com.example.Hero"]
    assert swf["doabc_count"] == 1
    assert swf["doabc_bytes"] == 4


def test_air_bare_swf_target(tmp_path):
    swf_path = tmp_path / "movie.swf"
    swf_path.write_bytes(_cws_swf())
    report = _report("nar-air", swf_path)
    assert report["swf"][0]["frame_count"] == 3
    assert report["swf"][0]["exported_symbols"] == \
        ["com.example.Hero"]


# ---------------------------------------------------------------
# LÖVE

CONF_LUA = """function love.conf(t)
    t.identity = "mygame"
    t.title = "My Game"
    t.version = "11.4"
    t.window.width = 800
    t.window.height = 600
    t.modules.physics = false
    t.modules.video = false
    t.modules.audio = true
end
"""


def _love_bytes(extra=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("conf.lua", CONF_LUA)
        zf.writestr("main.lua", "function love.draw() end")
        zf.writestr("lib/util.lua", "return {}")
        for name, data in (extra or []):
            zf.writestr(name, data)
    return buf.getvalue()


def test_love_member_in_apk(tmp_path):
    apk = _apk(tmp_path, "love.apk",
               [("assets/game.love", _love_bytes())])
    report = _report("nar-love", apk)
    assert report["verdict"] == "present"
    arch = report["love_archives"][0]
    assert arch["valid_zip"] is True
    assert arch["file_count"] == 3
    assert arch["main_lua_present"] is True
    conf = arch["conf"]
    assert conf["identity"] == "mygame"
    assert conf["title"] == "My Game"
    assert conf["version"] == "11.4"
    assert conf["window_width"] == 800
    assert conf["window_height"] == 600
    assert conf["modules_disabled"] == ["physics", "video"]
    assert arch["love_version_hint"] == "11.4"
    assert arch["lua_census"]["count"] == 3
    assert arch["lua_census"]["largest"]["name"] == "conf.lua"


def test_love_bare_file_target(tmp_path):
    love_path = tmp_path / "game.love"
    love_path.write_bytes(_love_bytes())
    report = _report("nar-love", love_path)
    assert report["verdict"] == "present"
    assert report["love_archives"][0]["conf"]["title"] == "My Game"


def test_love_invalid_member_identified(tmp_path):
    apk = _apk(tmp_path, "badlove.apk",
               [("assets/bad.love", b"this is not a zip")])
    report = _report("nar-love", apk)
    assert report["verdict"] == "present"
    arch = report["love_archives"][0]
    assert arch["valid_zip"] is False
    assert "error" in arch


# ---------------------------------------------------------------
# RPG Maker

PLUGINS_JS = """// Generated by RPG Maker.
var $plugins =
[
{"name":"PluginA","status":true,"description":"Does A","parameters":{}},
{"name":"PluginB","status":false,"description":"","parameters":{}}
];
"""


def _rpgmaker_apk(tmp_path):
    return _apk(tmp_path, "rpg.apk", [
        ("assets/www/Game.rpgproject", "RPGMV 1.6.2"),
        ("assets/www/package.json",
         json.dumps({"name": "RPG Game", "main": "index.html"})),
        ("assets/www/data/Actors.json",
         json.dumps([None, {"name": "Eric"}, {"name": "Nia"}])),
        ("assets/www/data/MapInfos.json",
         json.dumps([None, {"name": "Town"}])),
        ("assets/www/data/Map001.json", json.dumps({
            "width": 17, "height": 13,
            "events": [None, {"id": 1}, {"id": 2}]})),
        ("assets/www/js/plugins.js", PLUGINS_JS),
        ("assets/www/js/rpg_core.js", "// MV core"),
        ("assets/www/img/pictures/pic.png", b"\x89PNG"),
        ("assets/www/audio/bgm/theme.ogg", b"OggS"),
    ])


def test_rpgmaker_mv_census(tmp_path):
    report = _report("nar-rpgmaker", _rpgmaker_apk(tmp_path))
    assert report["verdict"] == "present"
    assert report["root"] == "assets/www/"
    assert report["data_census"]["Actors"] == 3
    assert report["data_census"]["MapInfos"] == 2
    assert report["data_census"]["Skills"] is None
    assert report["map_count"] == 1
    sample = report["map_sample"]
    assert sample["width"] == 17
    assert sample["height"] == 13
    assert sample["events_count"] == 2
    plugins = report["plugins"]
    assert [p["name"] for p in plugins] == ["PluginA", "PluginB"]
    assert plugins[0]["status"] is True
    assert plugins[0]["description_present"] is True
    assert plugins[1]["status"] is False
    assert plugins[1]["description_present"] is False
    assert report["package"] == {"name": "RPG Game",
                                 "main": "index.html"}
    assert report["asset_census"]["img/pictures"] == 1
    assert report["asset_census"]["audio/bgm"] == 1
    assert report["asset_census"]["movies"] == 0
    gen = report["engine_generation"]
    assert gen["guess"] == "MV"
    assert any("rpg_" in e for e in gen["evidence"])


def test_rpgmaker_mz_markers(tmp_path):
    apk = _apk(tmp_path, "rpgmz.apk", [
        ("assets/www/data/Actors.json", json.dumps([None])),
        ("assets/www/data/Effects.json", json.dumps([None])),
        ("assets/www/js/rmmz_core.js", "// MZ core"),
    ])
    report = _report("nar-rpgmaker", apk)
    assert report["verdict"] == "present"
    assert report["engine_generation"]["guess"] == "MZ"


# ---------------------------------------------------------------
# Web assets

WEB_INDEX = """<html ng-version="15.0.0">
<head><title>Web Title</title><base href="/">
<link rel="stylesheet" href="styles.css"></head>
<body><script src="main.js"></script></body></html>
"""

WEB_BUNDLE = ("var x = __webpack_require__(1); "
              "__webpack_require__(2); webpackJsonp([0]);")


def test_webassets_census_and_markers(tmp_path):
    apk = _apk(tmp_path, "web.apk", [
        ("assets/www/index.html", WEB_INDEX),
        ("assets/www/main.js", WEB_BUNDLE),
        ("assets/www/styles.css", "body{}"),
    ])
    report = _report("nar-webassets", apk)
    assert report["verdict"] == "present"
    root = report["roots"][0]
    assert root["root"] == "assets/www/"
    assert root["file_count"] == 3
    assert root["by_extension"] == {"css": 1, "html": 1, "js": 1}
    idx = root["index"]
    assert idx["title"] == "Web Title"
    assert idx["script_srcs"] == ["main.js"]
    assert idx["link_hrefs"] == ["styles.css"]
    assert idx["base_href"] == "/"
    assert idx["ng_version_present"] is True
    evidence = report["framework_evidence"]
    assert evidence["by_framework"]["webpack"] == 3
    assert evidence["by_framework"]["angular"] >= 1
    assert evidence["by_marker"]["__webpack_require__"] == 2
    assert evidence["bundles_scanned"] == 1


def test_webassets_root_without_index_is_absent(tmp_path):
    apk = _apk(tmp_path, "web-noindex.apk", [
        ("assets/www/main.js", "console.log(3)"),
    ])
    report = _report("nar-webassets", apk)
    assert report["verdict"] == "absent"


# ---------------------------------------------------------------
# Absent controls + shared verdict shape for every tool

def test_absent_controls_and_verdict_shape(tmp_path):
    empty = _empty_apk(tmp_path)
    for tool in TOOLS:
        report = _report(tool, empty)
        assert report["tool"] == tool, tool
        assert report["version"] == "3.0.3", tool
        assert report["target"].endswith("empty.apk"), tool
        assert "container" in report, tool
        assert report["verdict"] == "absent", tool


def test_human_output_runs(tmp_path):
    apk = _cordova_apk(tmp_path)
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / "nar-cordova.py"),
         str(apk)], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0
    assert "PRESENT" in proc.stdout
    assert "com.example.hello" in proc.stdout
