#!/usr/bin/env python3
"""nar-app.py: the non-game app universe (Part 6).

    python3 nar-app.py <target> [--json]

Deep app-intelligence scan of one target (resolved through
narlib.container, splits merged like nar-assets), emitting
the `app.json` companion document (schemas/app.schema.json)
that nar-analyze writes into a case and that nar-ask /
nar-blueprint deepen from. Sections, each evidence-cited:

- Identity: package, app label (manifest literal or
  resources.arsc string-table resolution of the label
  reference), versionName/versionCode, compileSdk,
  min/target SDK, native ABIs and the signer certificate
  subject (stdlib DER parse of the shipped v1 PKCS#7 and
  APK Signing Block certificates; conflicting sources are
  surfaced, never silently resolved).
- Components: the full manifest component census (all four
  component types + aliases: counts, explicit
  android:exported=true counts, effective exported counts
  under the manifest defaulting rules, and inventories),
  plus a DEX *Activity class census reported alongside the
  manifest activity inventory with its basis named.
- Behaviour: the manifest <application> element's declared
  attributes (debuggable, allowBackup, fullBackupContent,
  usesCleartextTraffic, networkSecurityConfig,
  extractNativeLibs, ...), each asserted as declared with
  its value or explicitly not declared, plus the bundled
  network-security-config resource census.
- UI frameworks: Jetpack Compose (@Composable-annotated
  class/method census from DEX annotation directories —
  annotation TYPES only are decoded), View/XML layouts
  (res/layout census; each layout parsed with the AXML
  machinery from nar-perms for its root element), Flutter /
  React Native presence (widget/component counts are not
  derivable from the shipped artifacts with the stdlib and
  are reported null with the reason), WebView hybrid
  surface (addJavascriptInterface call sites counted in DEX
  code + @JavascriptInterface-annotated methods).
- Navigation: manifest Activity graph + DEX Fragment
  census + deep links / intent filters as a route map.
- Storage: SharedPreferences candidate file names and keys
  (string constants co-occurring in methods that call the
  SharedPreferences accessors — a labelled co-occurrence
  heuristic), Room/SQLite (RoomDatabase subclasses, shipped
  database assets parsed read-only by narlib.sqlite —
  sqlite_master only, bytes parsed, never the sqlite3
  module), DataStore markers, asset file/cache inventory.
- Encrypted storage: SQLCipher, EncryptedSharedPreferences
  / Jetpack Security, AndroidKeyStore — detection only,
  named, never decrypted.
- Auth: OAuth markers, token storage LOCATIONS (mechanism
  names only), JWT presence — STRUCTURE ONLY (header alg +
  claim NAMES). Secret VALUES are never emitted: a final
  scrub pass over the whole report replaces any JWT-shaped
  or credential-shaped string that slipped into a curated
  field, and the unit suite leak-scans every output.
- Background work: WorkManager / JobScheduler /
  AlarmManager / foreground-service inventory.
- Permissions in use: declared (manifest) vs
  code-referenced (DEX string constants + Manifest$permission
  field references) -> over-request report, with the scan
  method and its limits stated in the output itself.
- SDKs: named third-party SDK inventory — versions only
  where a META-INF/*.version file (or equivalent shipped
  evidence) states one; class-count census per SDK package
  family otherwise.
- Compliance surface: tracking/analytics endpoint hosts
  (from DEX URL strings, redacted via nar-network),
  advertising-ID usage markers, consent SDK markers.

Output: a screen/module map and a data-flow map, both
evidence-cited. Bounded reads throughout; exit 0 whenever
the scan completes, including when the target carries no
app evidence (verdict "absent"); exit 2 for a missing
target.

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import struct
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import container as container_mod  # noqa: E402
from narlib import sqlite as sqlite_mod  # noqa: E402
from narlib.dex import Dex, DexError, _uleb128  # noqa: E402

VERSION = "3.0.1"
TOOL = "nar-app"

DEX_CAP = 200 * 1024 * 1024        # per-DEX read cap
DB_CAP = 64 * 1024 * 1024          # shipped-database read cap
TEXT_CAP = 4 * 1024 * 1024         # small text asset scan cap
MAX_CODE_METHODS = 300000          # code-item scan bound
MAX_LAYOUTS = 2000
SAMPLE = 25                        # per-list sample cap

BASE_LIMITATIONS = [
    "Static evidence only: screens, routes and storage "
    "mechanisms are what the artifact declares and references; "
    "runtime navigation order, stored values and server "
    "behaviour are not in the artifact.",
    "SharedPreferences keys are string constants that "
    "co-occur in methods calling SharedPreferences accessors "
    "(labelled heuristic): a constant can be a key, a file "
    "name or an unrelated literal in the same method.",
    "The permissions over-request scan sees only literal "
    "android.permission.* string constants and "
    "Manifest$permission field references in DEX; permissions "
    "requested through reflection, native code, dynamically "
    "built strings or SDK manifests merged at build time are "
    "invisible to it, so 'declared but unreferenced' means "
    "unreferenced BY THIS SCAN, not provably unused.",
    "Flutter widget and React Native component counts are "
    "not derivable from the shipped artifacts with the "
    "stdlib (AOT snapshot / Hermes bundle) and are reported "
    "null; nar flutter / nar rn carry the engine-level "
    "evidence for those targets.",
    "JWT and credential VALUES are never reported: JWT "
    "presence is structure only (header alg + claim names), "
    "token storage is reported as mechanism locations only, "
    "and every emitted URL passes nar-network's redactor.",
    "Encrypted storage is detected and named only; nothing "
    "is decrypted, and no key material exists in the output.",
]


def _load_sibling(name):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        name)
    spec = importlib.util.spec_from_file_location(
        name.replace("-", "_").replace(".py", ""), path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_PERMS = None
_NETWORK = None


def _perms():
    global _PERMS
    if _PERMS is None:
        _PERMS = _load_sibling("nar-perms.py")
    return _PERMS


def _network():
    global _NETWORK
    if _NETWORK is None:
        _NETWORK = _load_sibling("nar-network.py")
    return _NETWORK


def _redact_url(url):
    try:
        return _network().redact_url(url)[0]
    except Exception:
        return url


class Scan:
    """Bounded member access across a resolved target's
    roots (same shape as nar-script's Scan)."""

    def __init__(self, resolved):
        self.members = []
        self._zfs = {}
        seen = set()
        for root in list(resolved.assets_roots) + \
                list(resolved.native_roots):
            if root in seen or not os.path.isfile(root):
                continue
            seen.add(root)
            try:
                zf = zipfile.ZipFile(root)
            except (zipfile.BadZipFile, OSError):
                continue
            self._zfs[root] = zf
            for info in zf.infolist():
                if info.filename.endswith("/"):
                    continue
                self.members.append({
                    "root": root,
                    "archive": os.path.basename(root),
                    "name": info.filename,
                    "size": info.file_size})

    def read(self, member, cap):
        if member["size"] > cap:
            return None
        try:
            return self._zfs[member["root"]].read(member["name"])
        except (KeyError, OSError, RuntimeError,
                zipfile.BadZipFile):
            return None

    def read_head(self, member, n):
        try:
            with self._zfs[member["root"]].open(member["name"]) as fh:
                return fh.read(n)
        except (KeyError, OSError, RuntimeError,
                zipfile.BadZipFile):
            return b""

    def names(self):
        return [m["name"] for m in self.members]

    def close(self):
        for zf in self._zfs.values():
            try:
                zf.close()
            except Exception:
                pass


# ------------------------------------------------------------------
# Redaction scrub (defence in depth: curated fields only are
# built, and this pass guarantees no JWT-shaped or
# credential-shaped value survives into any output string)
# ------------------------------------------------------------------

_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
_CRED_RE = re.compile(
    r"(?i)\b(api[_-]?key|client[_-]?secret|access[_-]?token|"
    r"refresh[_-]?token|password|passwd|secret)\b\s*[:=]\s*\S+")


def scrub(obj):
    if isinstance(obj, str):
        out = _JWT_RE.sub("REDACTED-JWT", obj)
        out = _CRED_RE.sub(lambda m: m.group(0).split("=")[0]
                           .split(":")[0] + "=REDACTED"
                           if "=" in m.group(0) or ":" in m.group(0)
                           else "REDACTED", out)
        return out
    if isinstance(obj, list):
        return [scrub(v) for v in obj]
    if isinstance(obj, dict):
        return {k: scrub(v) for k, v in obj.items()}
    return obj


def _jwt_structure(token):
    """(header dict, claim-name list) for one JWT-shaped
    string, or None. Values are decoded only far enough to
    read the header alg and the payload KEY NAMES; no value
    is returned or stored anywhere."""
    parts = token.split(".")
    if len(parts) != 3:
        return None

    def _dec(seg):
        pad = "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg + pad))

    try:
        header = _dec(parts[0])
        payload = _dec(parts[1])
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return {"alg": header.get("alg"), "typ": header.get("typ"),
            "claim_names": sorted(payload.keys())}


# ------------------------------------------------------------------
# DEX annotation-directory walk (annotation TYPES only)
# ------------------------------------------------------------------

def _annotation_set_types(dex, set_off):
    """Annotation type descriptors in one annotation_set_item:
    reads each item's visibility byte + type index only; the
    encoded elements are never decoded."""
    data = dex.data
    if not set_off or set_off + 4 > len(data):
        return []
    size = struct.unpack_from("<I", data, set_off)[0]
    available = (len(data) - set_off - 4) // 4
    types = dex.types()
    out = []
    for i in range(min(size, available, 4096)):
        item_off = struct.unpack_from(
            "<I", data, set_off + 4 + i * 4)[0]
        if not item_off or item_off + 1 >= len(data):
            continue
        try:
            type_idx, _ = _uleb128(data, item_off + 1)
        except Exception:
            continue
        if type_idx < len(types):
            out.append(types[type_idx])
    return out


def _class_annotation_types(dex, class_def):
    ann_off = class_def.get("annotations_off") or 0
    data = dex.data
    if not ann_off or ann_off + 4 > len(data):
        return []
    class_set_off = struct.unpack_from("<I", data, ann_off)[0]
    return _annotation_set_types(dex, class_set_off)


def _method_annotation_types(dex, class_def):
    """{method_idx: [annotation type descriptors]} from the
    annotations directory's method_annotations table."""
    ann_off = class_def.get("annotations_off") or 0
    data = dex.data
    if not ann_off or ann_off + 16 > len(data):
        return {}
    try:
        _cls, fields_size, methods_size, params_size = \
            struct.unpack_from("<IIII", data, ann_off)
    except struct.error:
        return {}
    pos = ann_off + 16 + fields_size * 8
    out = {}
    for i in range(min(methods_size, 100000)):
        if pos + 8 > len(data):
            break
        method_idx, set_off = struct.unpack_from("<II", data, pos)
        pos += 8
        tys = _annotation_set_types(dex, set_off)
        if tys:
            out[method_idx] = tys
    return out


# ------------------------------------------------------------------
# SDK families (package-prefix census; versions only from
# shipped .version evidence, matched by artifact substring)
# ------------------------------------------------------------------

SDK_FAMILIES = [
    ("firebase", "Firebase",
     ("Lcom/google/firebase/",), ("firebase",)),
    ("google-play-services", "Google Play services / GMS",
     ("Lcom/google/android/gms/",), ("play-services", "gms")),
    ("google-ads", "Google Ads (AdMob)",
     ("Lcom/google/android/ads/", "Lcom/google/ads/"),
     ("ads", "admob")),
    ("facebook-sdk", "Facebook SDK",
     ("Lcom/facebook/",), ("facebook",)),
    ("adjust", "Adjust", ("Lcom/adjust/",), ("adjust",)),
    ("appsflyer", "AppsFlyer", ("Lcom/appsflyer/",),
     ("appsflyer",)),
    ("amplitude", "Amplitude", ("Lcom/amplitude/",),
     ("amplitude",)),
    ("mixpanel", "Mixpanel", ("Lcom/mixpanel/",), ("mixpanel",)),
    ("segment", "Segment", ("Lcom/segment/",), ("segment",)),
    ("braze", "Braze", ("Lcom/braze/", "Lcom/appboy/"),
     ("braze", "appboy")),
    ("onesignal", "OneSignal", ("Lcom/onesignal/",),
     ("onesignal",)),
    ("sentry", "Sentry", ("Lio/sentry/",), ("sentry",)),
    ("crashlytics", "Crashlytics",
     ("Lcom/google/firebase/crashlytics/",
      "Lcom/crashlytics/"), ("crashlytics",)),
    ("stripe", "Stripe", ("Lcom/stripe/",), ("stripe",)),
    ("okhttp", "OkHttp", ("Lokhttp3/",), ("okhttp",)),
    ("retrofit", "Retrofit", ("Lretrofit2/",), ("retrofit",)),
    ("glide", "Glide", ("Lcom/bumptech/glide/",), ("glide",)),
    ("coil", "Coil", ("Lcoil/",), ("coil",)),
    ("picasso", "Picasso", ("Lcom/squareup/picasso/",),
     ("picasso",)),
    ("applovin", "AppLovin", ("Lcom/applovin/",), ("applovin",)),
    ("unity-ads", "Unity Ads", ("Lcom/unity3d/ads/",),
     ("unity-ads", "unityads")),
    ("ironsource", "ironSource", ("Lcom/ironsource/",),
     ("ironsource",)),
    ("vungle", "Vungle / Liftoff", ("Lcom/vungle/",),
     ("vungle",)),
    ("chartboost", "Chartboost", ("Lcom/chartboost/",),
     ("chartboost",)),
    ("pangle", "Pangle (ByteDance)",
     ("Lcom/bytedance/sdk/openadsdk/", "Lcom/bytedance/pangle/"),
     ("pangle",)),
    ("adcolony", "AdColony", ("Lcom/adcolony/",), ("adcolony",)),
    ("inmobi", "InMobi", ("Lcom/inmobi/",), ("inmobi",)),
    ("mintegral", "Mintegral (MBridge)",
     ("Lcom/mbridge/", "Lcom/mintegral/"),
     ("mintegral", "mbridge")),
    ("fyber", "Fyber", ("Lcom/fyber/", "Lcom/inneractive/"),
     ("fyber", "inneractive")),
    ("moloco", "Moloco", ("Lcom/moloco/",), ("moloco",)),
    ("deltadna", "DeltaDNA", ("Lcom/deltadna/",), ("deltadna",)),
    ("tapjoy", "Tapjoy", ("Lcom/tapjoy/",), ("tapjoy",)),
    ("bidstack", "BidStack", ("Lcom/bidstack/",), ("bidstack",)),
    ("revenuecat", "RevenueCat", ("Lcom/revenuecat/",),
     ("revenuecat",)),
    ("garena", "Garena platform (Beetalk / GGPay)",
     ("Lcom/beetalk/", "Lcom/garena/"), ("garena", "beetalk")),
    ("branch", "Branch", ("Lio/branch/",), ("branch",)),
    ("intercom", "Intercom", ("Lio/intercom/",), ("intercom",)),
    ("mapbox", "Mapbox", ("Lcom/mapbox/",), ("mapbox",)),
    ("huawei-hms", "Huawei HMS", ("Lcom/huawei/hms/",),
     ("hms", "huawei")),
    ("kotlin-stdlib", "Kotlin stdlib", ("Lkotlin/",),
     ("kotlin-stdlib",)),
    ("androidx-core", "AndroidX core libraries",
     ("Landroidx/",), ("androidx",)),
]

# Native-carried SDK evidence: some SDKs ship (also) as a
# named native library; the census consults the native
# inventory for these families, not only the DEX. Member
# markers are shipped-asset evidence for a plugin-carried
# SDK. Both channels are deterministic name matches, stated
# in the entry's evidence when they fire.
SDK_NATIVE_LIBS = {
    "tapjoy": ("tapjoy",),
    "bidstack": ("bidstack",),
    "garena": ("libggp",),
}

SDK_MEMBER_MARKERS = {
    "revenuecat": ("purchases_flutter",),
}

TRACKER_HOST_MARKERS = (
    "google-analytics.com", "googletagmanager.com",
    "doubleclick.net", "app-measurement.com",
    "graph.facebook.com", "connect.facebook.net",
    "api.amplitude.com", "api.mixpanel.com",
    "api.segment.io", "app.adjust.com",
    "t.appsflyer.com", "api.appsflyer.com",
    "analytics.twitter.com", "ads-api.twitter.com",
    "log.byteoversea.com", "analytics.tiktok.com",
    "crashlytics.com", "api.statsig.com",
    "api.honeybadger.io", "o.ingest.sentry.io",
    "ingest.sentry.io",
)

_PERM_STRING_RE = re.compile(r"^android\.permission\.[A-Z0-9_]+$")
_URL_RE = re.compile(r"https?://[^\s\"'<>\\]{4,300}")


# ------------------------------------------------------------------
# Manifest pass (nar-perms machinery: the navigation source
# of truth)
# ------------------------------------------------------------------

def _manifest_pass(scan, resolved):
    """(perms_report, raw_root, member) for the base APK's
    AndroidManifest.xml, or (None, None, None)."""
    base_root = resolved.base
    member = None
    for m in scan.members:
        if m["root"] == base_root and \
                m["name"] == "AndroidManifest.xml":
            member = m
            break
    if member is None:
        return None, None, None
    data = scan.read(member, 16 * 1024 * 1024)
    if not data:
        return None, None, member
    perms = _perms()
    try:
        root = perms.parse_axml(data)
    except Exception:
        return None, None, member
    try:
        report = perms.analyze(root)
    except Exception:
        report = None
    return report, root, member


# ------------------------------------------------------------------
# Signer certificates (stdlib DER parse: v1 PKCS#7 files and
# the APK Signing Block) + resources.arsc string resolution
# ------------------------------------------------------------------

def _der_tlv(data, off):
    """(tag, content_offset, content_length) for the DER TLV
    at off. Raises ValueError on truncation."""
    if off + 2 > len(data):
        raise ValueError("der: truncated")
    tag = data[off]
    off += 1
    if tag & 0x1F == 0x1F:
        while off < len(data) and data[off] & 0x80:
            off += 1
        off += 1
    if off >= len(data):
        raise ValueError("der: truncated length")
    first = data[off]
    off += 1
    if first & 0x80:
        nbytes = first & 0x7F
        if nbytes == 0 or nbytes > 4 or off + nbytes > len(data):
            raise ValueError("der: bad long-form length")
        length = int.from_bytes(data[off:off + nbytes], "big")
        off += nbytes
    else:
        length = first
    if off + length > len(data):
        raise ValueError("der: content overruns buffer")
    return tag, off, length


def _der_children(data, start, end):
    """[(tag, content_off, content_len, raw_off, raw_end)] for
    the consecutive TLVs inside data[start:end]."""
    out = []
    off = start
    while off < end:
        tag, coff, clen = _der_tlv(data, off)
        out.append((tag, coff, clen, off, coff + clen))
        off = coff + clen
    return out


_OID_NAMES = {
    (2, 5, 4, 3): "CN", (2, 5, 4, 6): "C", (2, 5, 4, 7): "L",
    (2, 5, 4, 8): "ST", (2, 5, 4, 9): "STREET",
    (2, 5, 4, 10): "O", (2, 5, 4, 11): "OU",
    (2, 5, 4, 17): "postalCode", (2, 5, 4, 5): "serialNumber",
    (1, 2, 840, 113549, 1, 9, 1): "emailAddress",
}


def _oid_arcs(content):
    if not content:
        return ()
    arcs = [content[0] // 40, content[0] % 40]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    return tuple(arcs)


def _directory_string(tag, raw):
    try:
        if tag == 0x1E:  # BMPString
            return raw.decode("utf-16-be", "replace")
        if tag == 0x14:  # TeletexString
            return raw.decode("utf-8", "replace")
        return raw.decode("utf-8" if tag == 0x0C else "ascii",
                          "replace")
    except Exception:
        return ""


def _name_string(data, content_off, content_len):
    """RFC 4519-style DN for one X.501 Name content span:
    RDNs print most-specific first, the reverse of the DER
    sequence order — the order keytool/apksigner print."""
    rdns = []
    try:
        for _t, set_off, set_len, _r, _e in _der_children(
                data, content_off, content_off + content_len):
            parts = []
            for _t2, av_off, av_len, _r2, _e2 in _der_children(
                    data, set_off, set_off + set_len):
                pair = _der_children(data, av_off, av_off + av_len)
                if len(pair) != 2:
                    continue
                _ot, oid_off, oid_len, _or, _oe = pair[0]
                vtag, val_off, val_len, _vr, _ve = pair[1]
                arcs = _oid_arcs(data[oid_off:oid_off + oid_len])
                key = _OID_NAMES.get(
                    arcs, ".".join(str(a) for a in arcs))
                value = _directory_string(
                    vtag, data[val_off:val_off + val_len])
                value = value.replace("\\", "\\\\") \
                    .replace(",", "\\,")
                parts.append(f"{key}={value}")
            if parts:
                rdns.append("+".join(parts))
    except ValueError:
        return None
    return ", ".join(reversed(rdns)) if rdns else None


def _cert_info(cert_der, source):
    """{subject, issuer, sha256, source} for one X.509 cert,
    or None when the structure does not parse. The subject
    is the 4th SEQUENCE child of the TBSCertificate (after
    signature algorithm, issuer and validity)."""
    try:
        tag, coff, clen = _der_tlv(cert_der, 0)
        if tag != 0x30:
            return None
        top = _der_children(cert_der, coff, coff + clen)
        if not top or top[0][0] != 0x30:
            return None
        _t, tbs_off, tbs_len, _r, _e = top[0]
        seqs = [c for c in _der_children(
            cert_der, tbs_off, tbs_off + tbs_len) if c[0] == 0x30]
        if len(seqs) < 4:
            return None
        issuer = _name_string(cert_der, seqs[1][1], seqs[1][2])
        subject = _name_string(cert_der, seqs[3][1], seqs[3][2])
    except ValueError:
        return None
    if subject is None:
        return None
    return {"subject": subject, "issuer": issuer,
            "sha256": hashlib.sha256(cert_der).hexdigest(),
            "source": source}


def _certs_from_pkcs7(data):
    """Certificate DER blobs inside a PKCS#7 SignedData blob
    (the META-INF/*.RSA v1 signature file shape)."""
    certs = []
    try:
        tag, coff, clen = _der_tlv(data, 0)
        if tag != 0x30:
            return certs
        outer = _der_children(data, coff, coff + clen)
        holder = next((c for c in outer if c[0] == 0xA0), None)
        if holder is None:
            return certs
        signed = _der_children(data, holder[1],
                               holder[1] + holder[2])
        if not signed or signed[0][0] != 0x30:
            return certs
        _t, sd_off, sd_len, _r, _e = signed[0]
        for child in _der_children(data, sd_off, sd_off + sd_len):
            if child[0] != 0xA0:
                continue
            for cert in _der_children(data, child[1],
                                      child[1] + child[2]):
                if cert[0] == 0x30:
                    certs.append(data[cert[3]:cert[4]])
    except ValueError:
        return certs
    return certs


def _lp_read(data, off):
    """One uint32-LE length-prefixed blob from an APK Signing
    Block structure: (blob, next_offset)."""
    if off + 4 > len(data):
        raise ValueError("lp: truncated")
    size = struct.unpack_from("<I", data, off)[0]
    if off + 4 + size > len(data):
        raise ValueError("lp: overruns buffer")
    return data[off + 4:off + 4 + size], off + 4 + size


def _signing_block_certs(value):
    """Certificates inside one v2/v3 signer block value."""
    certs = []
    try:
        signers, _ = _lp_read(value, 0)
        off = 0
        while off < len(signers):
            signer, off = _lp_read(signers, off)
            signed_data, _ = _lp_read(signer, 0)
            _digests, pos = _lp_read(signed_data, 0)
            cert_blob, _ = _lp_read(signed_data, pos)
            coff = 0
            while coff < len(cert_blob):
                cert, coff = _lp_read(cert_blob, coff)
                certs.append(cert)
    except ValueError:
        return certs
    return certs


_SIGNING_BLOCK_IDS = {0x7109871A: "v2", 0xF05368C0: "v3",
                      0x1B93AD61: "v3.1"}


def _certs_from_signing_block(path):
    """[(cert_der, scheme)] from the APK Signing Block of the
    file at path, located via its End Of Central Directory."""
    out = []
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            tail_len = min(size, 65536 + 22)
            fh.seek(size - tail_len)
            tail = fh.read()
            eocd = tail.rfind(b"PK\x05\x06")
            if eocd < 0:
                return out
            cd_off = struct.unpack_from("<I", tail, eocd + 16)[0]
            if cd_off < 24 or cd_off > size:
                return out
            fh.seek(cd_off - 24)
            foot = fh.read(24)
            if foot[8:24] != b"APK Sig Block 42":
                return out
            block_size = struct.unpack_from("<Q", foot, 0)[0]
            start = cd_off - (block_size + 8)
            if start < 0 or block_size + 8 > size:
                return out
            fh.seek(start)
            block = fh.read(block_size + 8)
        pos = 8
        end = len(block) - 24
        while pos + 8 <= end:
            plen = struct.unpack_from("<Q", block, pos)[0]
            pos += 8
            if plen < 4 or pos + plen > len(block) - 24 + 8:
                break
            pair_id = struct.unpack_from("<I", block, pos)[0]
            if pair_id in _SIGNING_BLOCK_IDS:
                value = block[pos + 4:pos + plen]
                for cert in _signing_block_certs(value):
                    out.append((cert, _SIGNING_BLOCK_IDS[pair_id]))
            pos += plen
    except (OSError, struct.error, ValueError):
        return out
    return out


def _signer_section(scan, resolved):
    """Signer identity from the certificates the base APK
    itself ships: v1 PKCS#7 signature files and the APK
    Signing Block, both parsed with the stdlib. Sources that
    disagree are surfaced as a conflict, never resolved
    silently."""
    by_hash = {}
    base = resolved.base
    if base:
        for m in scan.members:
            if m["root"] != base:
                continue
            upper = m["name"].upper()
            if upper.startswith("META-INF/") and upper.endswith(
                    (".RSA", ".DSA", ".EC")):
                data = scan.read(m, 16 * 1024 * 1024)
                if not data:
                    continue
                for cert in _certs_from_pkcs7(data):
                    info = _cert_info(
                        cert, f"v1 signature file {m['name']}")
                    if info:
                        slot = by_hash.setdefault(
                            info["sha256"],
                            dict(info, sources=[]))
                        slot["sources"].append(info["source"])
        if os.path.isfile(base):
            for cert, scheme in _certs_from_signing_block(base):
                info = _cert_info(
                    cert, f"APK Signing Block ({scheme})")
                if info:
                    slot = by_hash.setdefault(
                        info["sha256"], dict(info, sources=[]))
                    slot["sources"].append(info["source"])
    certs = sorted(by_hash.values(), key=lambda c: c["sha256"])
    for cert in certs:
        cert["source"] = "; ".join(sorted(set(cert.pop(
            "sources"))))
    subjects = sorted({c["subject"] for c in certs})
    out = {
        "found": bool(certs),
        "certificates": certs,
        "subject": subjects[0] if len(subjects) == 1 else None,
        "evidence": "signing certificate(s) shipped in the "
                    "base APK: META-INF PKCS#7 (v1) and/or APK "
                    "Signing Block (v2/v3), X.509 subject parsed "
                    "with a stdlib DER reader; certificate "
                    "SHA-256 over the exact DER bytes",
    }
    if len(subjects) > 1:
        out["conflicting_subjects"] = subjects
        out["conflict_note"] = (
            "the shipped signing sources disagree on the "
            "signer subject; every certificate is listed "
            "above and no single signer is asserted")
    if not certs:
        out["reason"] = (
            "no v1 signature file and no parseable APK "
            "Signing Block certificate in the base APK")
    return out


def _arsc_lookup(data, res_id):
    """Resolve one string resource id against a resources.arsc
    blob: global string pool + package type chunks, default
    configuration preferred. Returns the string or None."""
    perms = _perms()
    if len(data) < 12 or \
            struct.unpack_from("<H", data, 0)[0] != 0x0002:
        return None
    header_size = struct.unpack_from("<H", data, 2)[0]
    total = struct.unpack_from("<I", data, 4)[0]
    pkg_id = (res_id >> 24) & 0xFF
    type_idx = (res_id >> 16) & 0xFF
    entry_idx = res_id & 0xFFFF
    global_strings = None
    packages = []
    off = header_size
    end = min(total, len(data))
    while off + 8 <= end:
        ctype, _chdr, csize = struct.unpack_from("<HHI", data, off)
        if csize < 8:
            break
        if ctype == 0x0001 and global_strings is None:
            try:
                global_strings = perms._parse_string_pool(data, off)
            except Exception:
                global_strings = None
        elif ctype == 0x0200:
            packages.append(off)
        off += csize
    if global_strings is None:
        return None
    for poff in packages:
        try:
            if struct.unpack_from("<I", data, poff + 8)[0] != pkg_id \
                    and len(packages) > 1:
                continue
            phdr = struct.unpack_from("<H", data, poff + 2)[0]
            psize = struct.unpack_from("<I", data, poff + 4)[0]
            type_off = struct.unpack_from("<I", data, poff + 268)[0]
            type_id_offset = struct.unpack_from(
                "<I", data, poff + 284)[0] if phdr >= 288 else 0
            try:
                type_names = perms._parse_string_pool(
                    data, poff + type_off)
            except Exception:
                continue
            candidates = []
            sub = poff + phdr
            pend = min(poff + psize, len(data))
            while sub + 8 <= pend:
                ctype, chdr, csize = struct.unpack_from(
                    "<HHI", data, sub)
                if csize < 8:
                    break
                if ctype == 0x0201 and sub + 20 <= pend:
                    type_id = data[sub + 8] + type_id_offset
                    entry_count = struct.unpack_from(
                        "<I", data, sub + 12)[0]
                    entries_start = struct.unpack_from(
                        "<I", data, sub + 16)[0]
                    name_idx = data[sub + 8] - 1
                    if type_id == type_idx and entry_idx < entry_count \
                            and 0 <= name_idx < len(type_names) \
                            and type_names[name_idx] == "string":
                        eoff = struct.unpack_from(
                            "<I", data, sub + chdr + entry_idx * 4)[0]
                        if eoff != 0xFFFFFFFF:
                            epos = sub + entries_start + eoff
                            esize, eflags = struct.unpack_from(
                                "<HH", data, epos)
                            if not eflags & 0x0001 and \
                                    epos + esize + 8 <= len(data):
                                _vs, _r0, dtype, value = \
                                    struct.unpack_from(
                                        "<HBBI", data, epos + esize)
                                if dtype == 0x03 and \
                                        value < len(global_strings):
                                    cfg_size = struct.unpack_from(
                                        "<I", data, sub + 20)[0]
                                    cfg = data[sub + 20:
                                               sub + 20 + cfg_size]
                                    is_default = all(
                                        b == 0 for b in cfg[4:])
                                    candidates.append(
                                        (is_default,
                                         global_strings[value]))
                sub += csize
            if candidates:
                candidates.sort(key=lambda c: not c[0])
                return candidates[0][1]
        except (struct.error, IndexError):
            # A package chunk whose fixed fields or
            # entry table run past the end of the blob is
            # malformed input, not a parser failure: the
            # lookup's contract is string-or-None (the
            # Phase 3 ARSC fuzz sweep caught bare
            # struct.error escapes here on truncated and
            # offset-blasted packages). Skip the package.
            continue
    return None


def _arsc_string(scan, resolved, res_id):
    member = None
    for m in scan.members:
        if m["root"] == resolved.base and \
                m["name"] == "resources.arsc":
            member = m
            break
    if member is None:
        return None
    data = scan.read(member, 64 * 1024 * 1024)
    if not data:
        return None
    try:
        return _arsc_lookup(data, res_id)
    except Exception:
        return None


def _as_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _identity_section(scan, resolved, perms_report, raw_root,
                      names):
    rep = perms_report or {}
    app = rep.get("application") or {}
    raw_attrs = raw_root.attrs if raw_root is not None else {}
    label_raw = app.get("label")
    label = None
    label_source = None
    if isinstance(label_raw, str) and label_raw:
        if label_raw.startswith("@0x"):
            try:
                res_id = int(label_raw[1:], 16)
            except ValueError:
                res_id = None
            resolved_label = _arsc_string(
                scan, resolved, res_id) if res_id else None
            if resolved_label is not None:
                label = resolved_label
                label_source = "resources.arsc string-table " \
                    "resolution of the manifest label reference"
            else:
                label_source = "unresolved resource reference: " \
                    "resources.arsc yielded no string for it"
        else:
            label = label_raw
            label_source = "manifest android:label literal"
    abis = sorted({
        n.split("/")[1] for n in names
        if n.startswith("lib/") and n.count("/") >= 2
        and n.endswith(".so")})
    return {
        "package": rep.get("package"),
        "app_label": label,
        "app_label_raw": label_raw,
        "app_label_source": label_source,
        "version_name": rep.get("version_name"),
        "version_code": _as_int(rep.get("version_code")),
        "compile_sdk_version": _as_int(
            raw_attrs.get("android:compileSdkVersion")),
        "compile_sdk_codename": raw_attrs.get(
            "android:compileSdkVersionCodename"),
        "min_sdk": rep.get("min_sdk"),
        "target_sdk": rep.get("target_sdk"),
        "native_abis": abis,
        "signer": _signer_section(scan, resolved),
        "evidence": "manifest root + <application> attributes "
                    "and <uses-sdk> via the nar-perms AXML parse "
                    "of the base APK; native ABIs from the "
                    "lib/<abi>/ member layout across the "
                    "resolved roots; app label resolved from "
                    "resources.arsc when the manifest carries "
                    "a reference; signer from the shipped "
                    "signing certificates",
    }


_BEHAVIOUR_KEYS = (
    "debuggable", "allowBackup", "fullBackupContent",
    "usesCleartextTraffic", "networkSecurityConfig",
    "extractNativeLibs", "largeHeap", "hardwareAccelerated",
    "requestLegacyExternalStorage", "isGame", "hasCode",
    "supportsRtl", "dataExtractionRules", "backupAgent",
    "appComponentFactory", "allowNativeHeapPointerTagging",
)

_INSTALL_LOCATIONS = {0: "internalOnly", 1: "preferExternal",
                      2: "auto"}


def _behaviour_section(raw_root, perms_report, names):
    """Declared <application>-element behaviour, asserted
    from the manifest parse itself: every tracked attribute
    is reported declared-with-value or explicitly not
    declared (a parse result, never a platform default)."""
    app_el = raw_root.find_child("application") \
        if raw_root is not None else None
    raw = {}
    if app_el is not None:
        for key, value in app_el.attrs.items():
            raw[key[len("android:"):]
                if key.startswith("android:") else key] = value
    tracked = {key: {"declared": key in raw,
                     "value": raw.get(key)}
               for key in _BEHAVIOUR_KEYS}
    nsc_members = sorted(
        n for n in names
        if n.startswith("res/xml/")
        and "network_security_config" in os.path.basename(n))
    root_attrs = raw_root.attrs if raw_root is not None else {}
    install_location = _as_int(
        root_attrs.get("android:installLocation"))
    gl_es = []
    if raw_root is not None:
        for el in raw_root.find_all("uses-feature"):
            version = _as_int(el.attrs.get("android:glEsVersion"))
            if version is not None:
                gl_es.append(f"0x{version:x}")
    return {
        "application_class": (perms_report or {}).get(
            "application", {}).get("name"),
        "attributes": tracked,
        "all_declared_attributes": raw,
        "network_security_config_resource": {
            "present": bool(nsc_members),
            "members": nsc_members,
            "evidence": "res/xml member census (bundled "
                        "resource, independent of whether the "
                        "application element references it)",
        },
        "install_location": install_location,
        "install_location_name": _INSTALL_LOCATIONS.get(
            install_location),
        "gl_es_versions": gl_es,
        "evidence": "AndroidManifest.xml <application> "
                    "element attributes via the nar-perms AXML "
                    "parse; 'declared: false' is the parse "
                    "result (attribute absent from the "
                    "element), not a platform default",
    }


_COMPONENT_KINDS = ("activity", "activity-alias", "service",
                    "receiver", "provider")


def _components_section(perms_report):
    """Full manifest component census for app.json: every
    component type with its count, its explicit
    android:exported=true count, its effective exported
    count (nar-perms defaulting rules) and its inventory —
    the facts the sibling manifest companions already carry,
    asserted on the app.json surface itself."""
    rep = perms_report or {}
    components = rep.get("components") or {}
    per_type = {}
    inventories = {}
    totals = {"exported_explicit_true": 0,
              "exported_effective": 0,
              "exported_attribute_declared": 0}
    truncated = False
    for kind in _COMPONENT_KINDS:
        comps = components.get(kind) or []
        explicit_true = sum(
            1 for c in comps
            if c.get("exported_explicit") and c.get("exported"))
        effective = sum(1 for c in comps if c.get("exported"))
        explicit_attr = sum(
            1 for c in comps if c.get("exported_explicit"))
        per_type[kind] = {
            "count": len(comps),
            "exported_explicit_true": explicit_true,
            "exported_effective": effective,
            "exported_attribute_declared": explicit_attr,
        }
        totals["exported_explicit_true"] += explicit_true
        totals["exported_effective"] += effective
        totals["exported_attribute_declared"] += explicit_attr
        if len(comps) > 1000:
            truncated = True
        inventories[kind] = [
            {"name": c.get("name"),
             "exported": c.get("exported"),
             "exported_explicit": c.get("exported_explicit")}
            for c in comps[:1000]]
    counts = {kind: per_type[kind]["count"]
              for kind in _COMPONENT_KINDS}
    counts["total"] = sum(counts.values())
    return {
        "counts": counts,
        "per_type": per_type,
        "exported_explicit_true_total":
            totals["exported_explicit_true"],
        "exported_effective_total": totals["exported_effective"],
        "exported_attribute_declared_total":
            totals["exported_attribute_declared"],
        "application_class": (rep.get("application") or {}).get(
            "name"),
        "launcher_activity": rep.get("launcher_activity"),
        "inventories": inventories,
        "inventories_truncated": truncated,
        "evidence": "AndroidManifest.xml component census via "
                    "the nar-perms AXML parse of the base "
                    "manifest: counts are element counts; "
                    "exported_explicit_true counts components "
                    "whose android:exported attribute is "
                    "present and true; exported_effective "
                    "applies the manifest defaulting rules "
                    "(intent-filter presence, provider SDK "
                    "rule) exactly as nar-perms computes them",
    }


def _dex_activity_census(facts, package, launcher=None):
    """DEX type-descriptor census of *Activity classes, the
    second screen-census basis: reported alongside the
    manifest activity inventory, never substituted for it.
    The census counts type descriptors (defined and
    referenced types alike — the classes.txt-style census),
    and the app-package subset is taken under the manifest
    package and under the launcher activity's package,
    which differ when the applicationId carries a suffix
    the code root does not."""
    named = set()
    for desc in facts.type_refs:
        if not desc:
            continue
        simple = _simple(desc)
        leaf = simple.rsplit(".", 1)[-1]
        if leaf.endswith("Activity"):
            named.add(simple)
    distinct = sorted(named)
    roots = set()
    if package:
        roots.add(package)
    if launcher and "." in launcher:
        roots.add(launcher.rsplit(".", 1)[0])
    app_named = [n for n in distinct
                 if any(n.startswith(root + ".")
                        for root in roots)]
    app_top = [n for n in app_named if "$" not in n]
    return {
        "basis": "DEX type-descriptor census",
        "activity_named_class_count": len(distinct),
        "app_package_activity_named_class_count": len(app_named),
        "app_package_top_level_activity_count": len(app_top),
        "app_package_top_level_activities": app_top[:200],
        "app_package_roots": sorted(roots),
        "activity_named_class_sample": distinct[:SAMPLE],
        "evidence": "DEX type-descriptor census (narlib.dex "
                    "type lists, defined and referenced types "
                    "unioned): types whose simple class name "
                    "ends with 'Activity', counted distinctly; "
                    "the app-package subset is those under "
                    "the manifest package or the launcher "
                    "activity's package, and top-level "
                    "excludes inner classes (names containing "
                    "'$'). This census complements the "
                    "manifest activity inventory in the "
                    "navigation section; the two bases count "
                    "different things and are both reported",
    }


def _foreground_service_types(root):
    out = []
    if root is None:
        return out
    app_el = root.find_child("application")
    if app_el is None:
        return out
    for el in app_el.children:
        if el.tag != "service":
            continue
        fst = el.attrs.get("android:foregroundServiceType")
        out.append({"name": el.attrs.get("android:name"),
                    "foreground_service_type": fst,
                    "exported": el.attrs.get("android:exported")})
    return out


# ------------------------------------------------------------------
# DEX pass
# ------------------------------------------------------------------

_INTERESTING_METHODS = {
    "addJavascriptInterface", "getSharedPreferences",
    "putString", "putInt", "putLong", "putBoolean",
    "putFloat", "putStringSet",
    "getString", "getInt", "getLong", "getBoolean",
    "loadUrl", "evaluateJavascript",
}
_PREFS_ACCESSORS = {
    "getSharedPreferences", "putString", "putInt", "putLong",
    "putBoolean", "putFloat", "putStringSet", "getString",
    "getInt", "getLong", "getBoolean",
}


class DexFacts:
    def __init__(self):
        self.dex_files = []
        self.class_count = 0
        self.classes = []            # (descriptor, superclass)
        self.sqlcipher_string_marker = False
        self.composable_methods = []  # "Class->name"
        self.composable_class_count = 0
        self.jsinterface_methods = []
        self.room_databases = []
        self.sqlite_helpers = []
        self.fragment_classes = []
        self.activity_classes = []
        self.worker_classes = []
        self.jobservice_classes = []
        self.method_ref_names = {}    # name -> count
        self.api_refs = {}            # label -> count
        self.field_perm_refs = set()
        self.string_perm_refs = set()
        self.add_js_interface_calls = 0
        self.prefs_file_names = set()
        self.prefs_key_candidates = set()
        self.code_methods_scanned = 0
        self.code_scan_truncated = False
        self.jwt_structures = {}      # (alg, claims tuple) -> count
        self.urls = {}                # host -> count
        self.url_samples = {}         # host -> redacted sample
        self.oauth_markers = set()
        self.type_refs = set()        # all type descriptors seen
        self.errors = []


_API_OWNERS = [
    ("workmanager", ("Landroidx/work/",)),
    ("jobscheduler", ("Landroid/app/job/",)),
    ("alarmmanager", ("Landroid/app/AlarmManager;",)),
    ("keystore", ("Ljava/security/KeyStore;",
                  "Landroid/security/keystore/")),
    ("encrypted-prefs",
     ("Landroidx/security/crypto/EncryptedSharedPreferences;",
      "Landroidx/security/crypto/MasterKey;")),
    ("datastore", ("Landroidx/datastore/",)),
    ("sqlcipher", ("Lnet/sqlcipher/",)),
    ("advertising-id",
     ("Lcom/google/android/gms/ads/identifier/",
      "Landroidx/ads/identifier/")),
    ("consent-ump", ("Lcom/google/android/ump/",)),
    ("webview", ("Landroid/webkit/WebView;",)),
    ("custom-tabs", ("Landroidx/browser/customtabs/",)),
    ("appauth", ("Lnet/openid/appauth/",)),
]


def _dex_pass(scan):
    facts = DexFacts()
    dex_members = [m for m in scan.members
                   if re.fullmatch(r"classes\d*\.dex",
                                   os.path.basename(m["name"]))]
    interesting_idx = {}  # (dex id, method idx) -> name
    for m in dex_members:
        data = scan.read(m, DEX_CAP)
        if data is None:
            facts.errors.append(
                f"{m['name']}: exceeds the {DEX_CAP}-byte read "
                "cap; skipped")
            continue
        try:
            dex = Dex(data, name=m["name"])
        except DexError as exc:
            facts.errors.append(f"{m['name']}: {exc}")
            continue
        facts.dex_files.append(m["name"])
        try:
            _dex_one(dex, m["name"], facts, interesting_idx)
        except Exception as exc:  # one bad DEX never sinks the run
            facts.errors.append(f"{m['name']}: pass failed: {exc}")
    return facts


def _dex_one(dex, name, facts, interesting_idx):
    strings = dex.strings()
    types = dex.types()
    facts.type_refs.update(types)
    defs = dex.class_defs_tolerant()[0] \
        if hasattr(dex, "class_defs_tolerant") else dex.class_defs()
    facts.class_count += len(defs)
    type_set = set(types)

    # Method-reference table: name census + API owner census.
    # narlib.dex returns None past the end of the table.
    method_refs = []
    idx = 0
    while True:
        try:
            ref = dex.method_ref(idx)
        except Exception:
            break
        if ref is None:
            break
        method_refs.append(ref)
        idx += 1
        if idx > 2000000:
            break
    for ref in method_refs:
        owner, mname = ref[0], ref[1]
        facts.method_ref_names[mname] = \
            facts.method_ref_names.get(mname, 0) + 1
        for label, owners in _API_OWNERS:
            if any(owner.startswith(o) or owner == o
                   for o in owners):
                facts.api_refs[label] = \
                    facts.api_refs.get(label, 0) + 1
    # Map method idx -> name for the code scan: the interesting
    # index->name table for interesting methods of THIS dex.
    interesting_here = {}
    for i, ref in enumerate(method_refs):
        if ref[1] in _INTERESTING_METHODS:
            interesting_here[i] = ref[1]
    # Field references: Manifest$permission constants.
    fidx = 0
    while True:
        try:
            fref = dex.field_ref(fidx)
        except Exception:
            break
        if fref is None:
            break
        owner, _ftype, fname = fref
        if owner == "Landroid/Manifest$permission;" and fname:
            facts.field_perm_refs.add("android.permission." + fname)
        fidx += 1
        if fidx > 2000000:
            break
    # String-pool derived facts.
    for s in strings:
        if _PERM_STRING_RE.match(s):
            facts.string_perm_refs.add(s)
        for match in _JWT_RE.finditer(s):
            struct_info = _jwt_structure(match.group(0))
            if struct_info:
                key = (struct_info["alg"],
                       tuple(struct_info["claim_names"]))
                facts.jwt_structures[key] = \
                    facts.jwt_structures.get(key, 0) + 1
        for match in _URL_RE.finditer(s):
            url = match.group(0).rstrip(".,);]")
            host = re.sub(r"^https?://", "", url).split("/")[0] \
                .split("?")[0].lower()
            if not re.fullmatch(r"[a-z0-9.-]+", host or "") \
                    or "." not in host:
                continue  # concatenated/garbled string, not a host
            if host:
                facts.urls[host] = facts.urls.get(host, 0) + 1
                facts.url_samples.setdefault(host, _redact_url(url))
            low = url.lower()
            if "/oauth" in low or "/authorize" in low or \
                    "oauth2" in low:
                facts.oauth_markers.add(host)
        low_s = s.lower()
        if low_s == "androidkeystore":
            facts.api_refs["keystore-string"] = \
                facts.api_refs.get("keystore-string", 0) + 1
        if "sqlcipher" in low_s:
            facts.sqlcipher_string_marker = True

    # Class census + annotations.
    for cdef in defs:
        desc = cdef.get("class")
        sup = cdef.get("superclass")
        facts.classes.append((desc, sup))
        if not desc:
            continue
        if sup in ("Landroidx/fragment/app/Fragment;",
                   "Landroid/app/Fragment;",
                   "Landroidx/fragment/app/DialogFragment;",
                   "Landroidx/fragment/app/ListFragment;"):
            facts.fragment_classes.append(desc)
        if sup and ("Activity;" in sup and sup.startswith("L")
                    and ("appcompat" in sup or "component" in sup
                         or sup.startswith("Landroid/app/")
                         or sup.startswith("Landroidx/activity/"))):
            facts.activity_classes.append(desc)
        if sup in ("Landroidx/room/RoomDatabase;",):
            facts.room_databases.append(desc)
        if sup in ("Landroid/database/sqlite/SQLiteOpenHelper;",):
            facts.sqlite_helpers.append(desc)
        if sup in ("Landroidx/work/Worker;",
                   "Landroidx/work/ListenableWorker;",
                   "Landroidx/work/CoroutineWorker;"):
            facts.worker_classes.append(desc)
        if sup in ("Landroid/app/job/JobService;",):
            facts.jobservice_classes.append(desc)
        ann_types = _class_annotation_types(dex, cdef)
        if "Landroidx/compose/runtime/Composable;" in ann_types:
            facts.composable_class_count += 1
        if "Landroidx/room/Database;" in ann_types and \
                desc not in facts.room_databases:
            facts.room_databases.append(desc)
        method_anns = _method_annotation_types(dex, cdef)
        for midx, tys in method_anns.items():
            try:
                ref = dex.method_ref(midx)
            except Exception:
                continue
            label = f"{desc}->{ref[1]}"
            if "Landroidx/compose/runtime/Composable;" in tys:
                facts.composable_methods.append(label)
            if "Landroid/webkit/JavascriptInterface;" in tys:
                facts.jsinterface_methods.append(label)

    # Code scan: call sites for the interesting methods +
    # SharedPreferences co-occurrence strings.
    if not interesting_here:
        return
    for cdef in defs:
        if facts.code_methods_scanned >= MAX_CODE_METHODS:
            facts.code_scan_truncated = True
            return
        try:
            indexed = dex.class_methods_indexed(
                cdef.get("class_data_off") or 0)
        except Exception:
            continue
        for _midx, _mname, _flags, code_off, _kind in indexed:
            if not code_off:
                continue
            if facts.code_methods_scanned >= MAX_CODE_METHODS:
                facts.code_scan_truncated = True
                return
            facts.code_methods_scanned += 1
            try:
                scanres = dex.scan_code(code_off)
            except Exception:
                continue
            invoked = {interesting_here[i]
                       for i, _kind in scanres["invokes"]
                       if i in interesting_here}
            if "addJavascriptInterface" in invoked:
                facts.add_js_interface_calls += 1
            if invoked & _PREFS_ACCESSORS:
                strpool = strings
                cand = [strpool[i] for i in scanres["string_refs"]
                        if i < len(strpool)]
                if "getSharedPreferences" in invoked:
                    for c in cand:
                        if c and len(c) <= 64 and \
                                not _JWT_RE.search(c):
                            facts.prefs_file_names.add(c)
                else:
                    for c in cand:
                        if c and len(c) <= 64 and " " not in c \
                                and not _JWT_RE.search(c) \
                                and not c.startswith(("L", "http")):
                            facts.prefs_key_candidates.add(c)


# ------------------------------------------------------------------
# Section builders
# ------------------------------------------------------------------

def _simple(descriptor):
    if not descriptor:
        return descriptor
    name = descriptor.rstrip(";").lstrip("L")
    return name.replace("/", ".")


def _library_versions(scan):
    """META-INF/<group>_<artifact>.version parse — the same
    evidence nar-triage reads (bounded 256-byte reads)."""
    versions = {}
    for m in scan.members:
        n = m["name"]
        if n.startswith("META-INF/") and n.endswith(".version"):
            raw = scan.read_head(m, 256)
            try:
                text = raw.decode("utf-8", "replace").strip()
            except Exception:
                continue
            ver = text.splitlines()[0].strip() if text else ""
            if ver and len(ver) <= 64:
                versions[n[len("META-INF/"):-len(".version")]] = ver
    return dict(sorted(versions.items()))


def _sdk_inventory(facts, library_versions, native_libs=(),
                   member_names=()):
    out = []
    class_descs = [d for d, _s in facts.classes if d]
    for fid, label, prefixes, version_keys in SDK_FAMILIES:
        count = sum(1 for d in class_descs
                    if any(d.startswith(p) for p in prefixes))
        type_count = sum(1 for t in facts.type_refs
                         if any(t.startswith(p) for p in prefixes))
        native_hits = sorted({
            lib for lib in native_libs
            if any(p in lib.lower()
                   for p in SDK_NATIVE_LIBS.get(fid, ()))})
        member_hits = sorted({
            n for n in member_names
            if any(p in n
                   for p in SDK_MEMBER_MARKERS.get(fid, ()))})
        if not count and not type_count and not native_hits \
                and not member_hits:
            continue
        version = None
        version_evidence = None
        for key, ver in library_versions.items():
            if any(vk in key for vk in version_keys):
                version = ver
                version_evidence = f"META-INF/{key}.version"
                break
        evidence = f"DEX class census: {count} defined " \
                   f"class(es) under {prefixes[0]}"
        if not count and type_count:
            evidence += f"; {type_count} referenced type(s) " \
                        "and no defined classes (referenced-" \
                        "only census hit: the SDK's API types " \
                        "are referenced by bundled code)"
        if native_hits:
            evidence += "; native library evidence: " + \
                ", ".join(native_hits)
        if member_hits:
            evidence += "; shipped member evidence: " + \
                member_hits[0]
        evidence += (f"; version from {version_evidence}"
                     if version_evidence else
                     "; no shipped .version evidence — "
                     "version not claimed")
        out.append({
            "id": fid, "name": label,
            "defined_class_count": count,
            "referenced_type_count": type_count,
            "native_libraries": native_hits,
            "member_evidence": member_hits[:SAMPLE],
            "version": version,
            "version_evidence": version_evidence,
            "evidence": evidence,
        })
    out.sort(key=lambda s: -s["defined_class_count"])
    return out


def _layouts(scan):
    layouts = []
    truncated = False
    members = [m for m in scan.members
               if re.match(r"res/layout[^/]*/", m["name"])
               and m["name"].endswith(".xml")]
    for m in members[:MAX_LAYOUTS]:
        root_tag = None
        data = scan.read(m, 2 * 1024 * 1024)
        if data:
            try:
                root = _perms().parse_axml(data)
                root_tag = root.tag
            except Exception:
                root_tag = None
        layouts.append({"name": m["name"], "root_element": root_tag,
                        "size_bytes": m["size"],
                        "evidence": "res layout member; root "
                                    "element via nar-perms AXML "
                                    "parse" if root_tag else
                                    "res layout member (AXML parse "
                                    "did not yield a root element)"})
    if len(members) > MAX_LAYOUTS:
        truncated = True
    return layouts, truncated


def _databases(scan):
    records = []
    for m in scan.members:
        low = m["name"].lower()
        if not (low.endswith((".db", ".sqlite", ".sqlite3"))
                or "/databases/" in low):
            continue
        data = scan.read(m, DB_CAP)
        if data is None:
            records.append({
                "file": m["name"], "source_archive": m["archive"],
                "status": "identified_only",
                "reason": f"member exceeds the {DB_CAP}-byte "
                          "read cap; identified by name, not "
                          "parsed",
                "facts": {}})
            continue
        parsed = sqlite_mod.parse_sqlite_schema(data)
        records.append({
            "file": m["name"], "source_archive": m["archive"],
            "status": parsed["status"], "facts": parsed["facts"],
            "reason": parsed["reason"], "error": parsed["error"],
            "evidence": "narlib.sqlite sqlite_master page walk "
                        "(read-only byte parse)"})
    return records


def scan_target(target):
    resolved = container_mod.resolve_target(target)
    try:
        return _scan_resolved(target, resolved)
    finally:
        resolved.cleanup()


def _scan_resolved(target, resolved):
    limitations = list(BASE_LIMITATIONS)
    roots = list(resolved.assets_roots) + list(resolved.native_roots)
    if not roots and os.path.isfile(target) \
            and not zipfile.is_zipfile(target):
        return _report(target, None, None, limitations)
    scan = Scan(resolved)
    try:
        perms_report, raw_root, _member = _manifest_pass(scan, resolved)
        facts = _dex_pass(scan)
        library_versions = _library_versions(scan)
        layouts, layouts_truncated = _layouts(scan)
        databases = _databases(scan)
        names = scan.names()
        doc = _build_doc(target, resolved, scan, perms_report,
                         raw_root, facts, library_versions,
                         layouts, layouts_truncated, databases,
                         names, limitations)
    finally:
        scan.close()
    return scrub(doc)


def _report(target, container_block, _unused, limitations):
    return {
        "tool": TOOL, "version": VERSION,
        "target": os.path.abspath(target),
        "verdict": "absent",
        "container": container_block,
        "package": None,
        "identity": {}, "behaviour": {}, "components": {},
        "ui_frameworks": {}, "navigation": {},
        "storage": {}, "encrypted_storage": {}, "auth": {},
        "background_work": {}, "permissions_in_use": {},
        "sdks": [], "library_versions": {},
        "compliance": {}, "screen_map": [], "data_flow": [],
        "totals": {}, "limitations": limitations,
    }


def _build_doc(target, resolved, scan, perms_report, raw_root,
               facts, library_versions, layouts,
               layouts_truncated, databases, names, limitations):
    if facts.code_scan_truncated:
        limitations.append(
            f"DEX code scan stopped at the {MAX_CODE_METHODS}-"
            "method bound; call-site counts are lower bounds.")
    if layouts_truncated:
        limitations.append(
            f"Layout census truncated at {MAX_LAYOUTS} layouts.")
    if not layouts and any(n.startswith("res/")
                           and n.endswith(".xml") for n in names):
        limitations.append(
            "No res/layout members were found although res/*.xml "
            "members exist: resource paths in this target appear "
            "renamed/obfuscated, so the layout census cannot "
            "classify them by path.")
    for err in facts.errors[:10]:
        limitations.append("DEX pass: " + err)

    package = (perms_report or {}).get("package")
    identity = _identity_section(scan, resolved, perms_report,
                                 raw_root, names)
    behaviour = _behaviour_section(raw_root, perms_report,
                                   names)
    components_section = _components_section(perms_report)
    components = (perms_report or {}).get("components") or {}
    activities = components.get("activity") or []
    launcher = (perms_report or {}).get("launcher_activity")

    # ---- UI frameworks -------------------------------------
    flutter_present = any(
        os.path.basename(n) == "libflutter.so" or
        n.startswith("flutter_assets/") for n in names)
    rn_present = any(
        os.path.basename(n) in ("index.android.bundle",
                                "main.jsbundle")
        or os.path.basename(n) == "libhermes.so" for n in names)
    compose_count = len(facts.composable_methods)
    ui = {
        "jetpack_compose": {
            "present": compose_count > 0
                       or facts.composable_class_count > 0,
            "composable_method_count": compose_count,
            "composable_class_count": facts.composable_class_count,
            "screen_sample": [_simple(x.split("->")[0]) + "->"
                              + x.split("->")[1]
                              for x in
                              facts.composable_methods[:SAMPLE]],
            "evidence": "DEX annotation directories: "
                        "@Composable annotation type census "
                        "(types only decoded)",
        },
        "view_xml": {
            "present": bool(layouts),
            "layout_count": len(layouts),
            "layouts": layouts[:100],
            "evidence": "res/layout member census + AXML root "
                        "elements via nar-perms",
        },
        "flutter": {
            "present": flutter_present,
            "widget_count": None,
            "reason": "widget census is not derivable from "
                      "the AOT snapshot with the stdlib; nar "
                      "flutter carries the engine evidence"
                      if flutter_present else None,
            "evidence": "libflutter.so / flutter_assets member "
                        "presence" if flutter_present else None,
        },
        "react_native": {
            "present": rn_present,
            "component_count": None,
            "reason": "component census is not derivable from "
                      "the Hermes/JS bundle with the stdlib; "
                      "nar rn carries the bundle evidence"
                      if rn_present else None,
            "evidence": "JS bundle / libhermes.so member "
                        "presence" if rn_present else None,
        },
        "webview_hybrid": {
            "present": facts.add_js_interface_calls > 0
                       or bool(facts.jsinterface_methods)
                       or facts.api_refs.get("webview", 0) > 0,
            "add_javascript_interface_call_sites":
                facts.add_js_interface_calls,
            "javascript_interface_method_count":
                len(facts.jsinterface_methods),
            "javascript_interface_methods":
                [_simple(x.split("->")[0]) + "->" + x.split("->")[1]
                 for x in facts.jsinterface_methods[:SAMPLE]],
            "webview_type_refs": facts.api_refs.get("webview", 0),
            "evidence": "DEX code scan for "
                        "addJavascriptInterface invokes + "
                        "@JavascriptInterface annotation census",
        },
    }

    # ---- Navigation ----------------------------------------
    routes = []
    deep_links = []
    for kind in ("activity", "activity-alias"):
        for comp in components.get(kind) or []:
            for f in comp.get("intent_filters") or []:
                data_entries = f.get("data") or []
                if data_entries:
                    route = {
                        "component": comp.get("name"),
                        "kind": kind,
                        "actions": f.get("actions") or [],
                        "categories": f.get("categories") or [],
                        "data": data_entries,
                        "evidence": "AndroidManifest.xml intent "
                                    "filter (nar-perms parse)",
                    }
                    routes.append(route)
                    for d in data_entries:
                        scheme = d.get("scheme")
                        if scheme:
                            deep_links.append({
                                "component": comp.get("name"),
                                "scheme": scheme,
                                "host": d.get("host"),
                                "path": d.get("path") or
                                        d.get("pathPrefix"),
                                "evidence": "manifest intent "
                                            "filter data element"})
    navigation = {
        "launcher_activity": launcher,
        "activity_count": len(activities),
        "activities": [
            {"name": a.get("name"), "exported": a.get("exported"),
             "intent_filter_count": a.get("intent_filter_count")}
            for a in activities[:200]],
        "dex_activity_class_count": len(facts.activity_classes),
        "dex_activity_census": _dex_activity_census(
            facts, package, launcher),
        "fragment_class_count": len(facts.fragment_classes),
        "fragment_sample": [_simple(x) for x in
                            facts.fragment_classes[:SAMPLE]],
        "route_count": len(routes),
        "routes": routes[:100],
        "deep_link_count": len(deep_links),
        "deep_links": deep_links[:100],
        "evidence": "manifest components (nar-perms) + DEX "
                    "Fragment/Activity superclass census",
    }

    # ---- Storage -------------------------------------------
    native_libs = sorted({os.path.basename(n) for n in names
                          if n.endswith(".so")})
    # Library-level Room signal: defined classes under
    # androidx/room. The lone MultiInstanceInvalidationService
    # class is a manifest-service artifact that also appears
    # in targets with no Room library, so presence requires
    # at least one further Room class.
    room_classes = sorted({
        d for d, _s in facts.classes
        if d and d.startswith("Landroidx/room/")})
    room_beyond_service = [
        d for d in room_classes
        if "MultiInstanceInvalidationService" not in d]
    # MMKV signal: defined classes in any */mmkv/ package
    # (the canonical package and vendor forks alike) and/or
    # an mmkv-named native library.
    mmkv_classes = sorted({
        d for d, _s in facts.classes
        if d and "/mmkv/" in d.lower()})
    mmkv_libs = [lib for lib in native_libs
                 if "mmkv" in lib.lower()]
    datastore_libs = [lib for lib in native_libs
                      if "datastore" in lib.lower()]
    asset_members = [m for m in scan.members
                     if m["name"].startswith("assets/")]
    asset_dirs = {}
    for m in asset_members:
        top = m["name"].split("/")[1] if "/" in m["name"] else ""
        asset_dirs[top] = asset_dirs.get(top, 0) + 1
    storage = {
        "shared_preferences": {
            "referenced": facts.method_ref_names.get(
                "getSharedPreferences", 0) > 0,
            "get_shared_preferences_refs":
                facts.method_ref_names.get("getSharedPreferences", 0),
            "candidate_file_names":
                sorted(facts.prefs_file_names)[:SAMPLE],
            "candidate_keys":
                sorted(facts.prefs_key_candidates)[:100],
            "method": "string constants in the same DEX "
                      "methods that invoke getSharedPreferences "
                      "(file-name candidates) or "
                      "SharedPreferences accessor/editor calls "
                      "(key candidates) — co-occurrence "
                      "heuristic, labelled",
            "evidence": "DEX code scan (scan_code string refs "
                        "+ invoke targets)",
        },
        "room_sqlite": {
            "room_database_classes":
                [_simple(x) for x in facts.room_databases[:SAMPLE]],
            "sqlite_open_helper_classes":
                [_simple(x) for x in facts.sqlite_helpers[:SAMPLE]],
            "shipped_databases": databases,
            "room_library": {
                "present": bool(room_beyond_service),
                "defined_class_count": len(room_classes),
                "defined_class_count_excluding_service":
                    len(room_beyond_service),
                "sample": [_simple(x) for x in
                           room_classes[:SAMPLE]],
                "evidence": "DEX defined-class census under "
                            "androidx/room (library-level "
                            "presence, independent of any "
                            "RoomDatabase subclass): presence "
                            "requires a class beyond "
                            "MultiInstanceInvalidationService, "
                            "which is a manifest-service "
                            "artifact that also ships in "
                            "targets with no Room library",
            },
            "evidence": "DEX superclass census + narlib.sqlite "
                        "sqlite_master walk of shipped .db/"
                        ".sqlite members",
        },
        "datastore": {
            "present": facts.api_refs.get("datastore", 0) > 0,
            "type_refs": facts.api_refs.get("datastore", 0),
            "native_libraries": datastore_libs,
            "evidence": "DEX type references under "
                        "androidx/datastore/",
        },
        "mmkv": {
            "present": bool(mmkv_classes or mmkv_libs),
            "dex_class_count": len(mmkv_classes),
            "dex_class_sample": [_simple(x) for x in
                                 mmkv_classes[:SAMPLE]],
            "native_libraries": mmkv_libs,
            "evidence": "DEX defined classes in a */mmkv/ "
                        "package (canonical or vendor-fork "
                        "package) and/or an mmkv-named native "
                        "library in the native inventory",
        },
        "files_cache_assets": {
            "asset_file_count": len(asset_members),
            "asset_bytes": sum(m["size"] for m in asset_members),
            "asset_top_dirs": dict(sorted(asset_dirs.items())),
            "evidence": "member census of assets/ across the "
                        "resolved roots (base + merged splits)",
        },
    }

    # ---- Encrypted storage ---------------------------------
    sqlcipher_lib = any("sqlcipher" in lib.lower()
                        for lib in native_libs)
    sqlcipher_dex = facts.api_refs.get("sqlcipher", 0) > 0 or \
        facts.sqlcipher_string_marker
    encrypted = {
        "sqlcipher": {
            "present": sqlcipher_lib or sqlcipher_dex,
            "native_lib": next((lib for lib in native_libs
                                if "sqlcipher" in lib.lower()), None),
            "dex_type_refs": facts.api_refs.get("sqlcipher", 0),
            "detection_only": True,
            "evidence": "native library name / DEX type refs "
                        "under net/sqlcipher — detection only, "
                        "never decrypted",
        },
        "encrypted_shared_preferences": {
            "present": facts.api_refs.get("encrypted-prefs", 0) > 0,
            "type_refs": facts.api_refs.get("encrypted-prefs", 0),
            "evidence": "DEX type refs to androidx/security/"
                        "crypto EncryptedSharedPreferences / "
                        "MasterKey",
        },
        "android_keystore": {
            "present": facts.api_refs.get("keystore", 0) > 0
                       or facts.api_refs.get("keystore-string", 0) > 0,
            "type_refs": facts.api_refs.get("keystore", 0),
            "evidence": "DEX type refs to java/security/"
                        "KeyStore / android/security/keystore, "
                        "or the AndroidKeyStore provider string",
        },
    }

    # ---- Auth ----------------------------------------------
    token_locations = []
    if storage["shared_preferences"]["referenced"]:
        token_locations.append("SharedPreferences (plain)")
    if encrypted["encrypted_shared_preferences"]["present"]:
        token_locations.append("EncryptedSharedPreferences")
    if storage["datastore"]["present"]:
        token_locations.append("DataStore")
    if storage["mmkv"]["present"]:
        token_locations.append("MMKV")
    if facts.room_databases or facts.sqlite_helpers or databases:
        token_locations.append("SQLite / Room database")
    if encrypted["android_keystore"]["present"]:
        token_locations.append("AndroidKeyStore-backed keys")
    redirect_schemes = sorted({
        d["scheme"] for d in deep_links
        if d.get("scheme") and d["scheme"] not in ("http", "https")})
    jwt_list = [
        {"alg": alg, "claim_names": list(claims), "count": count,
         "evidence": "DEX string pool: JWT-shaped string; "
                     "structure decoded, value redacted"}
        for (alg, claims), count in sorted(facts.jwt_structures.items())]
    auth = {
        "oauth": {
            "endpoint_hosts": sorted(facts.oauth_markers)[:SAMPLE],
            "custom_tab_refs": facts.api_refs.get("custom-tabs", 0),
            "appauth_refs": facts.api_refs.get("appauth", 0),
            "redirect_schemes": redirect_schemes,
            "evidence": "DEX URL strings with oauth/authorize "
                        "paths (hosts only), manifest redirect "
                        "schemes, Custom Tabs / AppAuth type refs",
        },
        "token_storage_locations": token_locations,
        "token_storage_note": "locations are mechanism names "
                              "only; no token value is read or "
                              "reported",
        "jwt": {
            "present": bool(jwt_list),
            "structure_count": sum(j["count"] for j in jwt_list),
            "structures": jwt_list,
            "evidence": "DEX string pool scan for JWT shape; "
                        "header alg + claim NAMES only — "
                        "values redacted everywhere",
        },
    }

    # ---- Background work ------------------------------------
    fg_services = _foreground_service_types(raw_root)
    background = {
        "workmanager": {
            "present": facts.api_refs.get("workmanager", 0) > 0
                       or bool(facts.worker_classes),
            "worker_classes": [_simple(x) for x in
                               facts.worker_classes[:SAMPLE]],
            "type_refs": facts.api_refs.get("workmanager", 0),
            "evidence": "DEX Worker/ListenableWorker superclass "
                        "census + androidx/work type refs",
        },
        "jobscheduler": {
            "present": bool(facts.jobservice_classes)
                       or facts.api_refs.get("jobscheduler", 0) > 0,
            "job_service_classes": [_simple(x) for x in
                                    facts.jobservice_classes[:SAMPLE]],
            "type_refs": facts.api_refs.get("jobscheduler", 0),
            "evidence": "DEX JobService superclass census + "
                        "android/app/job type refs",
        },
        "alarmmanager": {
            "present": facts.api_refs.get("alarmmanager", 0) > 0,
            "type_refs": facts.api_refs.get("alarmmanager", 0),
            "evidence": "DEX method/type refs to "
                        "android/app/AlarmManager",
        },
        "foreground_services": fg_services,
        "evidence": "manifest service elements "
                    "(foregroundServiceType attribute, nar-perms "
                    "AXML parse)",
    }

    # ---- Permissions in use ---------------------------------
    declared = sorted({p.get("name") for p in
                       (perms_report or {}).get("permissions") or []
                       if p.get("name")})
    referenced = sorted(facts.string_perm_refs |
                        facts.field_perm_refs)
    over = sorted(set(declared) - set(referenced))
    permissions_in_use = {
        "declared": declared,
        "declared_count": len(declared),
        "code_referenced": referenced,
        "code_referenced_count": len(referenced),
        "declared_but_unreferenced": over,
        "over_request_count": len(over),
        "scan_method": "DEX string-pool constants matching "
                       "android.permission.* plus "
                       "Landroid/Manifest$permission; field "
                       "references, unioned, compared with the "
                       "manifest uses-permission list",
        "scan_limits": "reflection, native code, dynamically "
                       "built strings and SDK-merged manifest "
                       "entries are invisible to this scan; "
                       "unreferenced means unreferenced by "
                       "this scan, not provably unused",
        "evidence": "AndroidManifest.xml uses-permission "
                    "(nar-perms) vs classes.dex string pool + "
                    "field references (narlib.dex)",
    }

    # ---- SDKs + compliance ----------------------------------
    sdks = _sdk_inventory(facts, library_versions, native_libs,
                          names)
    tracker_hosts = []
    for host, count in sorted(facts.urls.items(),
                              key=lambda kv: -kv[1]):
        if any(t in host for t in TRACKER_HOST_MARKERS):
            tracker_hosts.append({
                "host": host, "url_refs": count,
                "sample_redacted": facts.url_samples.get(host),
                "evidence": "DEX URL string host matched the "
                            "known tracker/analytics host list"})
    compliance = {
        "tracking_endpoints": tracker_hosts[:SAMPLE],
        "advertising_id": {
            "present": facts.api_refs.get("advertising-id", 0) > 0,
            "type_refs": facts.api_refs.get("advertising-id", 0),
            "evidence": "DEX type refs to AdvertisingIdClient "
                        "/ androidx ads identifier",
        },
        "consent_sdk": {
            "present": facts.api_refs.get("consent-ump", 0) > 0,
            "type_refs": facts.api_refs.get("consent-ump", 0),
            "evidence": "DEX type refs to com/google/android/"
                        "ump (User Messaging Platform)",
        },
    }

    # ---- Screen / module map --------------------------------
    screen_map = []
    for a in activities[:200]:
        screen_map.append({
            "name": a.get("name"), "kind": "activity",
            "exported": a.get("exported"),
            "evidence": "AndroidManifest.xml components."
                        "activity (nar-perms)"})
    for label in facts.composable_methods[:100]:
        screen_map.append({
            "name": _simple(label.split("->")[0]) + "->"
                    + label.split("->")[1],
            "kind": "composable",
            "evidence": "DEX @Composable annotation census"})
    for lay in layouts[:100]:
        screen_map.append({
            "name": lay["name"], "kind": "layout",
            "root_element": lay["root_element"],
            "evidence": lay["evidence"]})
    for frag in facts.fragment_classes[:100]:
        screen_map.append({
            "name": _simple(frag), "kind": "fragment",
            "evidence": "DEX Fragment superclass census"})

    # ---- Data-flow map ---------------------------------------
    flow = []
    for d in deep_links[:SAMPLE]:
        flow.append({
            "from": f"external app / browser ({d.get('scheme')}://"
                    f"{d.get('host') or ''})",
            "to": d.get("component"), "via": "deep link intent "
            "filter", "evidence": d["evidence"]})
    if launcher:
        flow.append({
            "from": "launcher", "to": launcher,
            "via": "MAIN/LAUNCHER intent filter",
            "evidence": "permissions launcher_activity "
                        "(nar-perms)"})
        for a in activities[:SAMPLE]:
            if a.get("name") != launcher:
                flow.append({
                    "from": launcher, "to": a.get("name"),
                    "via": "in-app navigation (manifest-declared "
                           "destination; tap order is runtime)",
                    "evidence": "AndroidManifest.xml components."
                                "activity (nar-perms)"})
    for mech in token_locations:
        flow.append({
            "from": "app code", "to": mech,
            "via": "storage API references",
            "evidence": "DEX storage census (this report, "
                        "storage section)"})
    for t in tracker_hosts[:10]:
        flow.append({
            "from": "app code", "to": t["host"],
            "via": "tracking/analytics endpoint",
            "evidence": t["evidence"]})
    for host, count in sorted(facts.urls.items(),
                              key=lambda kv: -kv[1])[:10]:
        if any(t["host"] == host for t in tracker_hosts):
            continue
        flow.append({
            "from": "app code", "to": host,
            "via": "endpoint URL string in DEX",
            "evidence": f"DEX string pool URL host census "
                        f"({count} ref(s)); sample redacted: "
                        f"{facts.url_samples.get(host)}"})
    for sdk in sdks[:10]:
        if sdk["defined_class_count"]:
            flow.append({
                "from": "app code", "to": sdk["name"],
                "via": "bundled SDK classes",
                "evidence": sdk["evidence"]})

    verdict = "present" if (perms_report or facts.dex_files
                            or layouts) else "absent"
    return {
        "tool": TOOL, "version": VERSION,
        "target": os.path.abspath(target),
        "verdict": verdict,
        "container": resolved.container_block(),
        "package": package,
        "identity": identity,
        "behaviour": behaviour,
        "components": components_section,
        "ui_frameworks": ui,
        "navigation": navigation,
        "storage": storage,
        "encrypted_storage": encrypted,
        "auth": auth,
        "background_work": background,
        "permissions_in_use": permissions_in_use,
        "sdks": sdks,
        "library_versions": library_versions,
        "compliance": compliance,
        "screen_map": screen_map,
        "data_flow": flow,
        "totals": {
            "dex_files": len(facts.dex_files),
            "dex_classes": facts.class_count,
            "activities": len(activities),
            "services": components_section["counts"]["service"],
            "receivers":
                components_section["counts"]["receiver"],
            "providers":
                components_section["counts"]["provider"],
            "exported_components_explicit":
                components_section[
                    "exported_explicit_true_total"],
            "fragments": len(facts.fragment_classes),
            "composable_methods": compose_count,
            "layouts": len(layouts),
            "routes": len(routes),
            "deep_links": len(deep_links),
            "shipped_databases": len(databases),
            "sdks": len(sdks),
            "declared_permissions": len(declared),
            "over_requested_permissions": len(over),
            "jwt_structures": len(jwt_list),
            "screen_map_entries": len(screen_map),
            "data_flow_edges": len(flow),
            "code_methods_scanned": facts.code_methods_scanned,
        },
        "limitations": limitations,
    }


def human(report):
    lines = [f"NAR app intelligence: "
             f"{os.path.basename(report['target'])}"]
    lines.append("=" * 60)
    totals = report.get("totals") or {}
    lines.append(f"Verdict: {report['verdict']} — "
                 f"{totals.get('dex_classes', 0)} DEX classes, "
                 f"{totals.get('activities', 0)} activities, "
                 f"{totals.get('layouts', 0)} layouts, "
                 f"{totals.get('composable_methods', 0)} "
                 "@Composable methods")
    identity = report.get("identity") or {}
    if identity:
        signer = (identity.get("signer") or {}).get("subject")
        lines.append(
            f"Identity: {identity.get('package')} "
            f"{identity.get('version_name')} "
            f"(code {identity.get('version_code')}), label "
            f"{identity.get('app_label')!r}, SDK min "
            f"{identity.get('min_sdk')} / target "
            f"{identity.get('target_sdk')} / compile "
            f"{identity.get('compile_sdk_version')}, ABIs "
            f"{', '.join(identity.get('native_abis') or [])}, "
            f"signer {signer}")
    behaviour = report.get("behaviour") or {}
    if behaviour:
        attrs = behaviour.get("attributes") or {}
        shown = []
        for key in ("debuggable", "allowBackup",
                    "usesCleartextTraffic",
                    "networkSecurityConfig"):
            entry = attrs.get(key) or {}
            shown.append(
                f"{key}={entry.get('value')}"
                if entry.get("declared")
                else f"{key}=not declared")
        lines.append("Behaviour: " + ", ".join(shown))
    comp_section = report.get("components") or {}
    if comp_section:
        counts = comp_section.get("counts") or {}
        lines.append(
            f"Components: {counts.get('activity', 0)} "
            f"activities, {counts.get('service', 0)} services, "
            f"{counts.get('receiver', 0)} receivers, "
            f"{counts.get('provider', 0)} providers; "
            f"{comp_section.get('exported_explicit_true_total', 0)} "
            f"exported (explicit)")
    nav = report.get("navigation") or {}
    lines.append(f"Navigation: launcher "
                 f"{nav.get('launcher_activity')}; "
                 f"{nav.get('route_count', 0)} routes, "
                 f"{nav.get('deep_link_count', 0)} deep links, "
                 f"{nav.get('fragment_class_count', 0)} fragments")
    perm = report.get("permissions_in_use") or {}
    lines.append(f"Permissions: {perm.get('declared_count', 0)} "
                 f"declared, {perm.get('code_referenced_count', 0)} "
                 f"code-referenced, "
                 f"{perm.get('over_request_count', 0)} declared "
                 f"but unreferenced by the DEX scan")
    for p in (perm.get("declared_but_unreferenced") or [])[:15]:
        lines.append(f"  over-request candidate: {p}")
    storage = (report.get("storage") or {}).get("room_sqlite") or {}
    for db in storage.get("shipped_databases") or []:
        f = db.get("facts") or {}
        lines.append(f"  database {db.get('file')}: "
                     f"{db.get('status')} — "
                     f"{f.get('table_count', 0)} tables, "
                     f"{f.get('column_count', 0)} columns")
    auth = report.get("auth") or {}
    jwt = auth.get("jwt") or {}
    if jwt.get("present"):
        for s in jwt.get("structures") or []:
            lines.append(f"  JWT structure: alg={s.get('alg')} "
                         f"claims={s.get('claim_names')} "
                         f"x{s.get('count')} (values redacted)")
    lines.append(f"SDKs: {', '.join(s['name'] for s in report.get('sdks', [])[:10])}")
    lines.append(f"Screen map: {totals.get('screen_map_entries', 0)} "
                 f"entries; data flow: "
                 f"{totals.get('data_flow_edges', 0)} edges")
    lines.append("Limitations:")
    for line in report["limitations"]:
        lines.append(f"  - {line}")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Non-game app universe: UI frameworks, "
                    "navigation, storage, encrypted storage, "
                    "auth (structure only), background work, "
                    "permissions in use, SDKs and compliance "
                    "surface, as a screen map + data-flow map.")
    parser.add_argument("target",
                        help="path to an APK/AAB/container target")
    parser.add_argument("--json", action="store_true",
                        help="emit the report as JSON "
                             "(schemas/app.schema.json)")
    args = parser.parse_args(argv)
    if not os.path.isfile(args.target):
        print(f"nar-app: target not found: {args.target}",
              file=sys.stderr)
        return 2
    try:
        report = scan_target(args.target)
    except (FileNotFoundError, IsADirectoryError,
            zipfile.BadZipFile) as exc:
        print(f"nar-app: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=1, sort_keys=True))
    else:
        print(human(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
