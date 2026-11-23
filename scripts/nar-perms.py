#!/usr/bin/env python3
"""nar-perms.py: permission, component, and intent-filter audit from an APK manifest.

Stdlib-only, no pip dependencies. Parses the binary AndroidManifest.xml with
a small built-in AXML reader (string pool + start-element chunks); if that
fails, falls back to `aapt2 dump xmltree` when aapt2 is available. The output
says plainly which path was used.

Usage:
    python3 nar-perms.py app.apk [--json] [--parser {auto,axml,aapt2}]

Output: package identity and SDK levels, permissions grouped by protection
level (normal / dangerous / signature / unknown, from a small built-in list
of well-known AOSP permissions plus any <permission> declarations in the
manifest itself), components by type with exported status and intent filters,
and flags worth attention (exported components, debuggable, allowBackup,
networkSecurityConfig presence, cleartext traffic).

Permission grouping notes: the built-in lists cover well-known AOSP
permissions only. Anything else (vendor, third-party, or custom permissions)
is reported as "unknown" and should be checked against the declaring app or
the AOSP source. Signature|appop special-access permissions
(SYSTEM_ALERT_WINDOW, WRITE_SETTINGS, MANAGE_EXTERNAL_STORAGE) are grouped
under "signature".

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import zipfile

ANDROID_NS = "http://schemas.android.com/apk/res/android"
ANDROID_PERM_PREFIX = "android.permission."
MANIFEST_ENTRIES = ("AndroidManifest.xml", "base/manifest/AndroidManifest.xml")
COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")
PERMISSION_TAGS = ("uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m")

# Well-known AOSP dangerous permissions (protectionLevel="dangerous").
DANGEROUS_PERMISSIONS = {
    "READ_CALENDAR", "WRITE_CALENDAR",
    "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS",
    "CAMERA",
    "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "ACCESS_MEDIA_LOCATION",
    "RECORD_AUDIO",
    "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE", "USE_SIP",
    "ADD_VOICEMAIL", "ANSWER_PHONE_CALLS", "ACCEPT_HANDOVER",
    "BODY_SENSORS", "BODY_SENSORS_BACKGROUND",
    "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "RECEIVE_WAP_PUSH", "RECEIVE_MMS",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO",
    "READ_MEDIA_VISUAL_USER_SELECTED",
    "ACTIVITY_RECOGNITION",
    "BLUETOOTH_ADVERTISE", "BLUETOOTH_CONNECT", "BLUETOOTH_SCAN",
    "NEARBY_WIFI_DEVICES", "POST_NOTIFICATIONS", "UWB_RANGING",
}

# Well-known AOSP signature permissions (protectionLevel="signature").
# Any android.permission.BIND_* permission is also signature by rule (see
# classify_permission); only non-BIND entries need listing here.
SIGNATURE_PERMISSIONS = {
    "CLEAR_APP_CACHE", "DELETE_CACHE_FILES", "DELETE_PACKAGES",
    "INSTALL_PACKAGES", "READ_LOGS",
    # signature|appop special-access permissions (grouped under signature).
    "SYSTEM_ALERT_WINDOW", "WRITE_SETTINGS", "MANAGE_EXTERNAL_STORAGE",
    "REQUEST_COMPANION_PROFILE_WATCH",
}

# Common AOSP normal permissions (protectionLevel="normal").
NORMAL_PERMISSIONS = {
    "ACCESS_LOCATION_EXTRA_COMMANDS", "ACCESS_NETWORK_STATE",
    "ACCESS_NOTIFICATION_POLICY", "ACCESS_WIFI_STATE",
    "ACCESS_ADSERVICES_AD_ID", "ACCESS_ADSERVICES_ATTRIBUTION",
    "ACCESS_ADSERVICES_CUSTOM_AUDIENCE", "ACCESS_ADSERVICES_TOPICS",
    "BLUETOOTH", "BLUETOOTH_ADMIN", "BROADCAST_STICKY",
    "CHANGE_NETWORK_STATE", "CHANGE_WIFI_MULTICAST_STATE", "CHANGE_WIFI_STATE",
    "DETECT_SCREEN_CAPTURE", "DETECT_SCREEN_RECORDING",
    "DISABLE_KEYGUARD", "EXPAND_STATUS_BAR", "FLASHLIGHT",
    "FOREGROUND_SERVICE", "FOREGROUND_SERVICE_CAMERA",
    "FOREGROUND_SERVICE_CONNECTED_DEVICE", "FOREGROUND_SERVICE_DATA_SYNC",
    "FOREGROUND_SERVICE_FILE_MANAGEMENT", "FOREGROUND_SERVICE_HEALTH",
    "FOREGROUND_SERVICE_LOCATION", "FOREGROUND_SERVICE_MEDIA_PLAYBACK",
    "FOREGROUND_SERVICE_MEDIA_PROJECTION", "FOREGROUND_SERVICE_MICROPHONE",
    "FOREGROUND_SERVICE_PHONE_CALL",
    "FOREGROUND_SERVICE_REMOTE_MESSAGING", "FOREGROUND_SERVICE_SPECIAL_USE",
    "FOREGROUND_SERVICE_SYSTEM_EXEMPTED",
    "HIDE_NON_SYSTEM_OVERLAY_WINDOWS", "HIGH_SAMPLING_RATE_SENSORS",
    "INSTANT_APP_FOREGROUND_SERVICE", "INTERNET", "KILL_BACKGROUND_PROCESSES",
    "MODIFY_AUDIO_SETTINGS", "NFC", "NFC_PREFERRED_PAYMENT_INFO",
    "PERSISTENT_ACTIVITY", "READ_SYNC_SETTINGS", "READ_SYNC_STATS",
    "RECEIVE_BOOT_COMPLETED", "REORDER_TASKS", "REQUEST_DELETE_PACKAGES",
    "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS", "REQUEST_INSTALL_PACKAGES",
    "SCHEDULE_EXACT_ALARM", "SET_ALARM", "SET_TIME_ZONE", "SET_WALLPAPER",
    "SUBSCRIBED_FEEDS_READ", "SUBSCRIBED_FEEDS_WRITE", "TRANSMIT_IR",
    "USE_BIOMETRIC", "USE_EXACT_ALARM", "USE_FINGERPRINT", "VIBRATE",
    "WAKE_LOCK", "WRITE_SYNC_SETTINGS",
}

# Well-known full permission names that do not use the
# android.permission.* prefix (Play billing, ads ID, push).
FULL_NAME_LEVELS = {
    "com.android.vending.BILLING": "normal",
    "com.android.vending.CHECK_LICENSE": "normal",
    "com.google.android.gms.permission.AD_ID": "normal",
    "com.google.android.c2dm.permission.RECEIVE": "normal",
}

# protectionLevel base values (low nibble) as compiled into binary XML.
PROTECTION_LEVELS = {0: "normal", 1: "dangerous", 2: "signature",
                     3: "signatureOrSystem"}
PROTECTION_FLAGS = {
    0x10: "privileged", 0x20: "development", 0x40: "appop", 0x80: "pre23",
    0x100: "installer", 0x200: "verifier", 0x400: "preinstalled",
    0x800: "setup", 0x1000: "instant", 0x2000: "runtimeOnly",
    0x4000: "oem", 0x8000: "vendorPrivileged",
    0x10000: "systemTextClassifier", 0x20000: "companion",
    0x40000: "knownSigner",
}


class ManifestError(Exception):
    """Raised when the manifest cannot be read or parsed at all."""


class Element:
    """Minimal XML element: tag, attributes, children."""

    __slots__ = ("tag", "attrs", "children")

    def __init__(self, tag):
        self.tag = tag
        self.attrs = {}
        self.children = []

    def find_all(self, tag):
        out = []
        for child in self.children:
            if child.tag == tag:
                out.append(child)
            out.extend(child.find_all(tag))
        return out

    def find_child(self, tag):
        for child in self.children:
            if child.tag == tag:
                return child
        return None


# ---------------------------------------------------------------------------
# Binary AXML reader (primary path)
# ---------------------------------------------------------------------------

def _read_utf8_length(data, pos):
    b0 = data[pos]
    if b0 & 0x80:
        return ((b0 & 0x7F) << 8) | data[pos + 1], pos + 2
    return b0, pos + 1


def _read_utf16_length(data, pos):
    v = struct.unpack_from("<H", data, pos)[0]
    if v & 0x8000:
        v2 = struct.unpack_from("<H", data, pos + 2)[0]
        return ((v & 0x7FFF) << 16) | v2, pos + 4
    return v, pos + 2


def _parse_string_pool(data, chunk_off):
    header_size = struct.unpack_from("<H", data, chunk_off + 2)[0]
    string_count, _style_count, flags, strings_start, _styles_start = \
        struct.unpack_from("<IIIII", data, chunk_off + 8)
    utf8 = bool(flags & 0x100)
    offsets_base = chunk_off + header_size
    strings_base = chunk_off + strings_start
    strings = []
    for i in range(string_count):
        off = struct.unpack_from("<I", data, offsets_base + i * 4)[0]
        pos = strings_base + off
        if utf8:
            _char_len, pos = _read_utf8_length(data, pos)  # UTF-16 char length
            byte_len, pos = _read_utf8_length(data, pos)
            strings.append(data[pos:pos + byte_len].decode("utf-8", "replace"))
        else:
            char_len, pos = _read_utf16_length(data, pos)
            strings.append(data[pos:pos + char_len * 2].decode("utf-16-le", "replace"))
    return strings


def _attr_value(strings, raw_value, data_type, data):
    """Resolve one attribute to a Python value.

    raw_value (a string-pool index) wins when present; otherwise the typed
    value is decoded. Resource references stay as "@0x........" strings.
    """
    if raw_value != 0xFFFFFFFF:
        return strings[raw_value] if raw_value < len(strings) else f"@str#{raw_value}"
    if data_type == 0x03:  # TYPE_STRING
        return strings[data] if data < len(strings) else f"@str#{data}"
    if data_type == 0x12:  # TYPE_INT_BOOLEAN
        return bool(data)
    if data_type == 0x10:  # TYPE_INT_DEC
        return data if data < 0x80000000 else data - 0x100000000
    if data_type == 0x11:  # TYPE_INT_HEX
        return data
    if data_type == 0x01:  # TYPE_REFERENCE
        return f"@0x{data:08x}"
    if data_type == 0x02:  # TYPE_ATTRIBUTE
        return f"?0x{data:08x}"
    if data_type == 0x04:  # TYPE_FLOAT
        return struct.unpack("<f", struct.pack("<I", data))[0]
    if data_type == 0x05:  # TYPE_DIMENSION
        return f"dim:0x{data:08x}"
    if data_type == 0x06:  # TYPE_FRACTION
        return f"frac:0x{data:08x}"
    if data_type == 0x00:  # TYPE_NULL
        return None
    return f"0x{data:08x}"


def parse_axml(data):
    """Parse binary AndroidManifest.xml bytes into an Element tree."""
    if len(data) < 8:
        raise ManifestError("manifest too short to be binary XML")
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != 0x00080003:
        raise ManifestError("not a binary AndroidManifest.xml (bad magic)")
    strings = []
    root = None
    stack = []
    off = 8
    try:
        while off + 8 <= len(data):
            chunk_type, _header_size, chunk_size = struct.unpack_from("<HHI", data, off)
            if chunk_size < 8 or off + chunk_size > len(data):
                raise ManifestError(
                    f"malformed chunk at offset {off} (type 0x{chunk_type:04x})")
            if chunk_type == 0x0001:  # string pool
                strings = _parse_string_pool(data, off)
            elif chunk_type == 0x0102:  # start element
                ns_idx, name_idx = struct.unpack_from("<II", data, off + 16)
                attr_start, attr_size, attr_count = struct.unpack_from(
                    "<HHH", data, off + 24)
                name = strings[name_idx] if name_idx < len(strings) else f"?{name_idx}"
                el = Element(name)
                for i in range(attr_count):
                    # attributeStart is relative to the attrExt struct, which
                    # starts 16 bytes into the chunk (after the node header).
                    a_off = off + 16 + attr_start + i * attr_size
                    a_ns, a_name, a_raw, _sz, _zero, a_type, a_data = \
                        struct.unpack_from("<IIIHBBI", data, a_off)
                    a_name_str = (strings[a_name] if a_name < len(strings)
                                  else f"?{a_name}")
                    if (a_ns != 0xFFFFFFFF and a_ns < len(strings)
                            and strings[a_ns] == ANDROID_NS):
                        key = "android:" + a_name_str
                    else:
                        key = a_name_str
                    el.attrs[key] = _attr_value(strings, a_raw, a_type, a_data)
                if stack:
                    stack[-1].children.append(el)
                elif root is None:
                    root = el
                stack.append(el)
            elif chunk_type == 0x0103:  # end element
                if stack:
                    stack.pop()
            # 0x0100/0x0101 namespaces, 0x0180 resource map, 0x0104 CDATA: skip.
            off += chunk_size
    except (struct.error, IndexError) as e:
        raise ManifestError(f"malformed binary XML: {e}") from e
    if root is None:
        raise ManifestError("no root element found in manifest")
    return root


# ---------------------------------------------------------------------------
# aapt2 dump xmltree fallback
# ---------------------------------------------------------------------------

def find_aapt2():
    aapt2 = shutil.which("aapt2")
    if aapt2:
        return aapt2
    for root in filter(None, [
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        os.path.expanduser("~/workspace/android-sdk"),
        os.path.expanduser("~/Android/Sdk"),
    ]):
        bt = os.path.join(root, "build-tools")
        if os.path.isdir(bt):
            def _ver_key(v):
                try:
                    return tuple(int(x) for x in v.split("."))
                except ValueError:
                    return (0,)
            for ver in sorted(os.listdir(bt), key=_ver_key, reverse=True):
                cand = os.path.join(bt, ver, "aapt2")
                if os.path.isfile(cand) and os.access(cand, os.X_OK):
                    return cand
    return None


ELEMENT_RE = re.compile(r"^(\s*)E: (\S+) \(line=\d+\)")
ATTR_RE = re.compile(r"^(\s*)A: ([^=]+)=(.*)$")
ATTR_NAME_RE = re.compile(r"^(.*?)(?:\(0x[0-9a-fA-F]+\))?$")
QUOTED_RE = re.compile(r'^"(.*)"(?: \(Raw: .*\))?$')
TYPED_RE = re.compile(r"^\(type 0x([0-9a-fA-F]+)\)(-?0x[0-9a-fA-F]+|-?\d+)$")


def _xmltree_value(raw):
    raw = raw.strip()
    m = QUOTED_RE.match(raw)
    if m:
        return m.group(1)
    m = TYPED_RE.match(raw)
    if m:
        dtype = int(m.group(1), 16)
        num = int(m.group(2), 0)
        if dtype == 0x12:
            return bool(num)
        if dtype == 0x10:
            return num
        if dtype == 0x01:
            return f"@0x{num & 0xFFFFFFFF:08x}"
        if dtype == 0x02:
            return f"?0x{num & 0xFFFFFFFF:08x}"
        return f"0x{num & 0xFFFFFFFF:08x}"
    if raw in ("true", "false"):
        return raw == "true"
    if re.fullmatch(r"-?\d+", raw):
        return int(raw)
    if raw.startswith("0x"):
        try:
            return int(raw, 16)
        except ValueError:
            return raw
    return raw


def parse_xmltree(apk_path, manifest_entry):
    """Parse the manifest via `aapt2 dump xmltree` into an Element tree."""
    aapt2 = find_aapt2()
    if not aapt2:
        raise ManifestError("aapt2 not found (fallback unavailable)")
    try:
        out = subprocess.run(
            [aapt2, "dump", "xmltree", apk_path, "--file", manifest_entry],
            capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
        raise ManifestError(f"aapt2 xmltree failed: {e}") from e
    if out.returncode != 0:
        first_err = (out.stderr.strip().splitlines() or ["unknown error"])[0][:200]
        raise ManifestError(f"aapt2 xmltree failed: {first_err}")
    root = None
    stack = []  # (indent, element)
    for line in out.stdout.splitlines():
        m = ELEMENT_RE.match(line)
        if m:
            indent = len(m.group(1))
            el = Element(m.group(2))
            while stack and stack[-1][0] >= indent:
                stack.pop()
            if stack:
                stack[-1][1].children.append(el)
            elif root is None:
                root = el
            stack.append((indent, el))
            continue
        m = ATTR_RE.match(line)
        if m and stack:
            indent = len(m.group(1))
            while stack and stack[-1][0] >= indent:
                stack.pop()
            if not stack:
                continue
            name = ATTR_NAME_RE.match(m.group(2).strip()).group(1)
            # aapt2 prints the full namespace URI; normalize to android:*
            # so the analysis code sees the same keys as the AXML path.
            if name.startswith(ANDROID_NS + ":"):
                name = "android:" + name[len(ANDROID_NS) + 1:]
            stack[-1][1].attrs[name] = _xmltree_value(m.group(3))
    if root is None:
        raise ManifestError("aapt2 xmltree produced no elements")
    return root


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def _as_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.lower() == "true":
            return True
        if value.lower() == "false":
            return False
    return None


def _as_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def resolve_name(name, package):
    if not name or not package:
        return name
    if name.startswith("."):
        return package + name
    if "." not in name:
        return package + "." + name
    return name


def decode_protection_level(value):
    """Return (base_name, [flag_names]) for a <permission> protectionLevel.

    Handles both the compiled integer form and the plain string form.
    """
    if isinstance(value, str):
        parts = [p.strip() for p in value.split("|")]
        base = parts[0] if parts else "?"
        return base, parts[1:]
    num = _as_int(value)
    if num is None:
        return "?", []
    base = PROTECTION_LEVELS.get(num & 0x0F, f"level{num & 0x0F}")
    flags = [name for bit, name in sorted(PROTECTION_FLAGS.items()) if num & bit]
    return base, flags


def classify_permission(name, declared):
    """Group a permission name: dangerous / signature / normal / unknown."""
    if name in declared:
        base = declared[name]["protection_level"]
        if base in ("dangerous", "signature", "signatureOrSystem"):
            return "signature" if base != "dangerous" else "dangerous"
        if base == "normal":
            return "normal"
    if name in FULL_NAME_LEVELS:
        return FULL_NAME_LEVELS[name]
    if name.startswith(ANDROID_PERM_PREFIX):
        short = name[len(ANDROID_PERM_PREFIX):]
        if short in DANGEROUS_PERMISSIONS or short.startswith("health."):
            # android.permission.health.* (Health Connect) permissions
            # are all runtime/dangerous.
            return "dangerous"
        if short in SIGNATURE_PERMISSIONS or short.startswith("BIND_"):
            return "signature"
        if short in NORMAL_PERMISSIONS:
            return "normal"
    return "unknown"


def parse_intent_filter(el):
    f = {"actions": [], "categories": [], "data": []}
    for child in el.children:
        if child.tag == "action":
            f["actions"].append(child.attrs.get("android:name", "?"))
        elif child.tag == "category":
            f["categories"].append(child.attrs.get("android:name", "?"))
        elif child.tag == "data":
            f["data"].append({k.replace("android:", ""): v
                              for k, v in child.attrs.items()})
    return f


def analyze(root):
    """Turn a parsed manifest tree into the audit report dict."""
    package = root.attrs.get("package")
    version_code = root.attrs.get("android:versionCode")
    version_name = root.attrs.get("android:versionName")
    shared_user_id = root.attrs.get("android:sharedUserId")

    # <uses-sdk> can appear more than once in old manifests (sometimes
    # nested inside a component, where the platform ignores it). Count
    # every occurrence in document order; the FIRST one wins, in
    # agreement with nar-perms.
    uses_sdk_els = root.find_all("uses-sdk")
    uses_sdk = uses_sdk_els[0] if uses_sdk_els else None
    min_sdk = _as_int(uses_sdk.attrs.get("android:minSdkVersion")) if uses_sdk else None
    target_sdk = _as_int(uses_sdk.attrs.get("android:targetSdkVersion")) if uses_sdk else None
    uses_sdk_all = [{
        "min_sdk": _as_int(el.attrs.get("android:minSdkVersion")),
        "target_sdk": _as_int(el.attrs.get("android:targetSdkVersion")),
    } for el in uses_sdk_els]
    # Split APKs carry a split="..." attribute on <manifest>; their
    # <application> element is a stub, so app-level flags do not apply.
    split_name = root.attrs.get("split") or root.attrs.get("android:split")

    # Declared <permission> elements (custom permissions this app defines).
    declared = {}
    custom_permissions = []
    for el in root.find_all("permission"):
        name = el.attrs.get("android:name")
        if not name:
            continue
        base, flags = decode_protection_level(el.attrs.get("android:protectionLevel"))
        declared[name] = {"protection_level": base, "protection_flags": flags}
        custom_permissions.append({
            "name": name, "protection_level": base, "protection_flags": flags,
        })

    # Requested permissions (uses-permission*), de-duplicated by name.
    permissions = []
    seen = set()
    for tag in PERMISSION_TAGS:
        for el in root.find_all(tag):
            name = el.attrs.get("android:name")
            if not name or name in seen:
                continue
            seen.add(name)
            permissions.append({
                "name": name,
                "group": classify_permission(name, declared),
                "declared_in_manifest": name in declared,
                "source": tag,
            })
    permissions.sort(key=lambda p: (p["group"] != "dangerous",
                                    p["group"] != "signature",
                                    p["group"] != "normal", p["name"]))
    by_group = {g: sum(1 for p in permissions if p["group"] == g)
                for g in ("normal", "dangerous", "signature", "unknown")}

    # <application> attributes.
    app_el = root.find_child("application")
    app = {"name": None, "label": None, "debuggable": None, "allow_backup": None,
           "network_security_config": None, "uses_cleartext_traffic": None}
    if app_el is not None:
        app["name"] = resolve_name(app_el.attrs.get("android:name"), package)
        app["label"] = app_el.attrs.get("android:label")
        app["debuggable"] = _as_bool(app_el.attrs.get("android:debuggable"))
        app["allow_backup"] = _as_bool(app_el.attrs.get("android:allowBackup"))
        app["network_security_config"] = app_el.attrs.get(
            "android:networkSecurityConfig")
        app["uses_cleartext_traffic"] = _as_bool(
            app_el.attrs.get("android:usesCleartextTraffic"))

    # Components, with exported status and intent filters.
    components = {t: [] for t in COMPONENT_TAGS}
    launcher_activity = None
    intent_filter_count = 0
    exported_count = 0
    app_children = app_el.children if app_el is not None else []
    for el in app_children:
        if el.tag not in COMPONENT_TAGS:
            continue
        raw_name = el.attrs.get("android:name")
        name = resolve_name(raw_name, package)
        filters = [parse_intent_filter(f) for f in el.children
                   if f.tag == "intent-filter"]
        intent_filter_count += len(filters)
        explicit = _as_bool(el.attrs.get("android:exported"))
        if explicit is not None:
            exported, exported_explicit = explicit, True
        elif el.tag == "provider":
            # Providers default to exported only on API <= 16.
            sdk = min_sdk if min_sdk is not None else target_sdk
            exported, exported_explicit = (sdk is not None and sdk <= 16), False
        else:
            # Activities, services, receivers: exported by default when they
            # carry at least one intent filter.
            exported, exported_explicit = bool(filters), False
        if exported:
            exported_count += 1
        comp = {
            "name": name,
            "exported": exported,
            "exported_explicit": exported_explicit,
            "permission": el.attrs.get("android:permission"),
            "intent_filters": filters,
            "intent_filter_count": len(filters),
        }
        components[el.tag].append(comp)
        if (el.tag in ("activity", "activity-alias") and launcher_activity is None
                and any("android.intent.action.MAIN" in f["actions"]
                        and "android.intent.category.LAUNCHER" in f["categories"]
                        for f in filters)):
            launcher_activity = name
    for tag in COMPONENT_TAGS:
        components[tag].sort(key=lambda c: c["name"] or "")

    counts = {t: len(components[t]) for t in COMPONENT_TAGS}
    counts["total"] = sum(counts.values())

    # Flags worth attention.
    flags = []

    def flag(severity, title, detail):
        flags.append({"severity": severity, "flag": title, "detail": detail})

    if app["debuggable"] is True:
        flag("high", "debuggable=true",
             "Release builds must not be debuggable; it allows adb debugging and"
             " run-as access to the app's private data.")
    if shared_user_id:
        flag("medium", f"sharedUserId: {shared_user_id}",
             "This app shares a Linux UID and data directory with every other"
             " app that declares the same sharedUserId and is signed by the"
             " same key. Common in system apps (android.uid.system,"
             " android.uid.shared); the shared apps must be analyzed together.")
    if split_name:
        flag("info", f"split APK manifest (split: {split_name})",
             "This file is one split of a bundle. Its <application>"
             " element is a stub: app-level flags (allowBackup,"
             " networkSecurityConfig) belong to the base APK, so they"
             " are not reported here.")
    elif app["allow_backup"] is None or app["allow_backup"]:
        allow_backup = app["allow_backup"] if app["allow_backup"] is not None else True
        if allow_backup:
            flag("info", "allowBackup enabled"
                 + (" (default; attribute absent)" if app["allow_backup"] is None
                    else " (explicit)"),
                 "App data can be backed up with adb backup unless backup rules"
                 " exclude it.")
    if split_name is None and app["network_security_config"] is None:
        flag("info", "no networkSecurityConfig",
             "Cleartext policy falls back to the platform default for the"
             " target SDK; there is no explicit pinning or cleartext policy.")
    if len(uses_sdk_els) > 1:
        pairs = "; ".join(
            f"min {p['min_sdk']} / target {p['target_sdk']}" for p in uses_sdk_all)
        flag("info", f"duplicate <uses-sdk> ({len(uses_sdk_els)} elements)",
             f"The manifest declares <uses-sdk> {len(uses_sdk_els)} times"
             f" ({pairs}). The FIRST occurrence is used, in agreement"
             " with nar-triage (aapt2 badging).")
    if app["uses_cleartext_traffic"] is True:
        flag("medium", "usesCleartextTraffic=true",
             "The app explicitly allows cleartext (non-TLS) network traffic.")
    if min_sdk is not None and min_sdk < 23:
        flag("info", f"minSdk {min_sdk} < 23",
             "On devices below API 23 the install-time permission model applies;"
             " dangerous permissions are granted at install, not at runtime.")
    dangerous = [p["name"] for p in permissions if p["group"] == "dangerous"]
    if dangerous:
        flag("medium", f"{len(dangerous)} dangerous permission(s)",
             ", ".join(dangerous))
    for tag in COMPONENT_TAGS:
        for comp in components[tag]:
            if not comp["exported"]:
                continue
            kind = tag.replace("-", " ")
            if not comp["exported_explicit"] and target_sdk is not None \
                    and target_sdk >= 31:
                flag("high", f"missing android:exported on {kind}: {comp['name']}",
                     "Target SDK 31+ requires an explicit android:exported on"
                     " every component with an intent filter; this app would"
                     " fail to install.")
                continue
            how = "explicit" if comp["exported_explicit"] else \
                "implicit (intent filter, no android:exported)"
            severity = "high" if tag == "provider" else "medium"
            detail = ("Content providers expose data to other apps; check the"
                      " read/write permissions on it."
                      if tag == "provider" else
                      f"Reachable by other apps ({how}).")
            if comp["permission"]:
                detail += f" Guarded by permission: {comp['permission']}."
            flag(severity, f"exported {kind}: {comp['name']}", detail)
    severity_order = {"high": 0, "medium": 1, "info": 2}
    flags.sort(key=lambda f: severity_order[f["severity"]])

    return {
        "package": package,
        "version_code": version_code,
        "version_name": version_name,
        "shared_user_id": shared_user_id,
        "split_name": split_name,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "uses_sdk_count": len(uses_sdk_els),
        "uses_sdk_all": uses_sdk_all,
        "application": app,
        "launcher_activity": launcher_activity,
        "permissions": permissions,
        "permission_count": len(permissions),
        "permissions_by_group": by_group,
        "custom_permissions": custom_permissions,
        "components": components,
        "component_counts": counts,
        "intent_filter_count": intent_filter_count,
        "exported_count": exported_count,
        "flags": flags,
    }


def audit(apk_path, parser="auto"):
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"not a file: {apk_path}")
    report = {
        "file": os.path.basename(apk_path),
        "path": os.path.abspath(apk_path),
        "parser_requested": parser,
    }
    try:
        zf = zipfile.ZipFile(apk_path)
    except zipfile.BadZipFile:
        report["error"] = "not a valid ZIP/APK container"
        return report
    with zf:
        names = set(zf.namelist())
        manifest_entry = next((e for e in MANIFEST_ENTRIES if e in names), None)
        if manifest_entry is None:
            report["error"] = ("no AndroidManifest.xml in this archive"
                               " (not an APK, or a split without a manifest)")
            return report
        manifest_bytes = zf.read(manifest_entry)
    report["manifest_entry"] = manifest_entry

    root = None
    axml_error = None
    if parser in ("auto", "axml"):
        try:
            root = parse_axml(manifest_bytes)
            report["parse_path"] = "axml"
            report["parse_note"] = ("binary AndroidManifest.xml parsed with the"
                                    " built-in stdlib AXML reader")
        except ManifestError as e:
            axml_error = str(e)
    if root is None and parser in ("auto", "aapt2"):
        try:
            root = parse_xmltree(apk_path, manifest_entry)
            report["parse_path"] = "aapt2-xmltree"
            if axml_error:
                report["parse_note"] = ("binary AXML parse failed"
                                        f" ({axml_error}); fell back to"
                                        " `aapt2 dump xmltree`")
            else:
                report["parse_note"] = "parsed with `aapt2 dump xmltree`"
        except ManifestError as e:
            report["error"] = f"could not parse the manifest: {e}"
            if axml_error:
                report["error"] += f" (AXML reader also failed: {axml_error})"
            return report
    if root is None:
        report["error"] = (f"binary AXML parse failed: {axml_error}"
                           " (fallback not attempted: --parser axml)")
        return report
    if root.tag != "manifest":
        report["error"] = f"unexpected manifest root element: {root.tag!r}"
        return report
    report.update(analyze(root))
    return report


# ---------------------------------------------------------------------------
# Human-readable output
# ---------------------------------------------------------------------------

def _filter_summary(f):
    parts = []
    if f["actions"]:
        parts.append("action=" + ", ".join(f["actions"]))
    if f["categories"]:
        parts.append("category=" + ", ".join(f["categories"]))
    for d in f["data"]:
        parts.append("data=" + " ".join(f"{k}={v}" for k, v in d.items()))
    return "; ".join(parts) if parts else "(empty filter)"


def human(report):
    title = f"NAR permission audit: {report['file']}"
    lines = [title, "=" * len(title)]
    if report.get("error"):
        lines.append(f"ERROR: {report['error']}")
        return "\n".join(lines)
    path_label = {"axml": "binary AXML (built-in stdlib reader)",
                  "aapt2-xmltree": "aapt2 dump xmltree (fallback)"}.get(
                      report.get("parse_path"), report.get("parse_path", "?"))
    lines.append(f"Parser: {path_label}")
    if report.get("parse_path") == "aapt2-xmltree":
        lines.append(f"  ({report.get('parse_note', '')})")
    ver_parts = []
    if report.get("version_name") is not None:
        ver_parts.append(f"v{report['version_name']}")
    if report.get("version_code") is not None:
        ver_parts.append(f"(code {report['version_code']})")
    lines.append(f"Package: {report.get('package') or '?'}"
                 + (("  " + " ".join(ver_parts)) if ver_parts else ""))
    lines.append(f"SDK: min {report.get('min_sdk') if report.get('min_sdk') is not None else '?'} / "
                 f"target {report.get('target_sdk') if report.get('target_sdk') is not None else '?'}")
    if report.get("uses_sdk_count", 1) > 1:
        pairs = "; ".join(f"min {p['min_sdk']} / target {p['target_sdk']}"
                          for p in report["uses_sdk_all"])
        lines.append(f"WARNING: <uses-sdk> appears {report['uses_sdk_count']} times"
                     f" ({pairs}); the FIRST is used, in agreement with nar-triage.")
    if report.get("split_name"):
        lines.append(f"NOTE: split APK manifest (split: {report['split_name']})."
                     " App-level flags below describe the stub, not the base app.")
    if report.get("shared_user_id"):
        lines.append(f"sharedUserId: {report['shared_user_id']}")
    app = report["application"]
    lines.append("")
    lines.append("Application:")
    if app.get("name"):
        lines.append(f"  class: {app['name']}")
    if app.get("label"):
        lines.append(f"  label: {app['label']}")
    lines.append(f"  debuggable: {app['debuggable'] if app['debuggable'] is not None else '?'}")
    ab = app["allow_backup"]
    lines.append("  allowBackup: " + ("true (default; attribute absent)" if ab is None
                                      else str(ab).lower()))
    nsc = app["network_security_config"]
    lines.append(f"  networkSecurityConfig: {nsc if nsc is not None else '(none)'}")
    lines.append(f"  usesCleartextTraffic: {app['uses_cleartext_traffic'] if app['uses_cleartext_traffic'] is not None else '?'}")
    if report.get("launcher_activity"):
        lines.append(f"  launcher activity: {report['launcher_activity']}")

    by_group = report["permissions_by_group"]
    lines.append("")
    lines.append(f"Permissions ({report['permission_count']}): "
                 f"{by_group['dangerous']} dangerous, {by_group['signature']} signature,"
                 f" {by_group['normal']} normal, {by_group['unknown']} unknown")
    for group in ("dangerous", "signature", "normal", "unknown"):
        names = [p["name"] for p in report["permissions"] if p["group"] == group]
        if names:
            lines.append(f"  {group.upper()} ({len(names)}):")
            for n in names:
                lines.append(f"    - {n}")
    if report["custom_permissions"]:
        lines.append(f"Custom permissions declared ({len(report['custom_permissions'])}):")
        for cp in report["custom_permissions"]:
            extra = (" | " + "|".join(cp["protection_flags"])
                     if cp["protection_flags"] else "")
            lines.append(f"  - {cp['name']}  ({cp['protection_level']}{extra})")

    counts = report["component_counts"]
    lines.append("")
    lines.append(f"Components ({counts['total']} total, "
                 f"{report['exported_count']} exported): "
                 f"{counts['activity']} activities, "
                 f"{counts['activity-alias']} activity-aliases, "
                 f"{counts['service']} services, {counts['receiver']} receivers, "
                 f"{counts['provider']} providers")
    lines.append(f"Intent filters: {report['intent_filter_count']}")
    plural = {"activity": "Activities", "activity-alias": "Activity-aliases",
              "service": "Services", "receiver": "Receivers",
              "provider": "Providers"}
    for tag in COMPONENT_TAGS:
        comps = report["components"][tag]
        if not comps:
            continue
        lines.append(f"  {plural[tag]} ({len(comps)}):")
        for c in comps:
            exp = "exported" if c["exported"] else "not exported"
            how = "explicit" if c["exported_explicit"] else "inferred"
            lines.append(f"    - {c['name']}  [{exp}, {how}]"
                         + (f"  {c['intent_filter_count']} intent filter(s)"
                            if c["intent_filter_count"] else ""))
            if c["permission"]:
                lines.append(f"        requires permission: {c['permission']}")
            for i, f in enumerate(c["intent_filters"], 1):
                lines.append(f"        filter {i}: {_filter_summary(f)}")

    lines.append("")
    lines.append(f"Flags worth attention ({len(report['flags'])}):")
    if not report["flags"]:
        lines.append("  (none)")
    for f in report["flags"]:
        lines.append(f"  [{f['severity'].upper()}] {f['flag']}")
        lines.append(f"        {f['detail']}")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="NAR permission audit: permissions, components, and "
                    "intent filters from an APK manifest.")
    p.add_argument("apk", help="path to the .apk file")
    p.add_argument("--json", action="store_true", help="machine-readable JSON output")
    p.add_argument("--parser", choices=("auto", "axml", "aapt2"), default="auto",
                   help="manifest parser: auto (AXML reader, aapt2 fallback), "
                        "axml (built-in reader only), aapt2 (xmltree only)")
    args = p.parse_args(argv)
    try:
        report = audit(args.apk, args.parser)
    except FileNotFoundError as e:
        print(f"nar-perms: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"nar-perms: cannot read file: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(human(report))
    return 0 if "error" not in report else 1


if __name__ == "__main__":
    sys.exit(main())
