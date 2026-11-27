#!/usr/bin/env python3
"""nar-network.py: static network intelligence (brief
section 7).

Builds the endpoint inventory from string evidence plus
bundled asset data files (see harvest_asset_urls) and
classifies every endpoint with static-analysis honesty:

- dex-string: the URL string is present in DEX string
  data. (This label was "confirmed" before the 2.6.2
  calibration audit: presence in a DEX string table is
  not proof that code references the string — the
  correlations builder treats the same evidence as
  STRONGLY_INDICATED for exactly that reason — so the
  stronger word overstated the evidence.)
- potential: seen in native-library strings only,
- unused-candidate: seen only in assets/resources,
- third-party: a known SDK/service domain,
- sensitive: credentials or auth material inside the URL
  (see is_sensitive() for the exact structural signals),
- unverified: no parseable host / no usable evidence.

Every endpoint also carries a purpose kind (api /
telemetry / ads / cdn / social / other / unknown -- see
purpose_kind() for the deterministic precedence and its
evidence basis) and the report carries a kind_hosts
inventory mirroring api_hosts (api_hosts is exactly the
api bucket). The pre-3.0.1 transport value of the kind
field (web / websocket) survives in the endpoint's
"transport" field.

Also reports: host and API-host inventories, backend
services (Firebase/Supabase/AWS/Azure/App Center/Sentry)
with config-file evidence (google-services.json is parsed
for the project id; key VALUES are never printed), the
network libraries present, cleartext posture, and the
network security config (parsed from an apktool decode:
cleartext rules, domain configs, trust anchors, pin sets,
debug overrides). No traffic is generated and nothing is
contacted: this is static analysis only.

Redaction (Evolution Phase 5): credential material inside
endpoint URLs — sensitive query-parameter values and URL
userinfo — is replaced with REDACTED before anything is
emitted, in every output mode. Classification still runs
on the original URL (a redacted URL must still classify
as sensitive); the report counts the redacted values and
never carries the raw ones, so case outputs and downstream
consumers (nar-security evidence strings included) never
persist a credential.

Usage:
    python3 nar-network.py app.apk [--json] [--work DIR]

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.parse
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import container as container_mod  # noqa: E402
from narlib import registry as reg_mod  # noqa: E402
from narlib.hashing import sha256_of  # noqa: E402
from narlib.safearchive import read_member_capped  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
THIRD_PARTY_SUFFIXES = (
    "googleapis.com", "gstatic.com", "google.com",
    "doubleclick.net", "googlesyndication.com",
    "google-analytics.com", "crashlytics.com", "facebook.com",
    "facebook.net", "sentry.io", "amplitude.com",
    "mixpanel.com", "appcenter.ms", "visualstudio.com",
    "unity3d.com", "unity.com", "applovin.com",
    "adcolony.com", "vungle.com", "chartboost.com",
    "inmobi.com", "mopub.com", "amazonaws.com",
    "supabase.co", "cloudflare.com", "akamaihd.net",
    "branch.io", "appsflyer.com", "adjust.com",
    "onesignal.com", "intercom.io", "zendesk.com",
)
# NOTE (M2-06): firebaseio.com / firebaseapp.com are NOT
# in the suffix list above. Those suffixes are shared
# project-instance namespaces: every subdomain is one
# app's own hosted backend instance, not a vendor
# endpoint, so suffix-matching them as "third-party"
# over-matched (every labeled project-instance host in
# the Phase 2 corpus is first-party; the suffix rule
# produced false third-party claims on all of them).
# The instances are still recognised as api-kind
# backends in VENDOR_KIND_SUFFIXES and as Firebase
# services in analyze(); they are just not claimed as a
# third party by suffix alone.
SENSITIVE_QUERY = re.compile(
    r"(api[_-]?key|apikey|token|secret|password|passwd|auth)="
    r"[^&]{4,}", re.I)
# Sensitive-endpoint signals (M2-04). The pre-fix rule was
# SENSITIVE_QUERY plus a cleartext-only auth-path clause,
# and it never fired on real harvested evidence:
#   * SENSITIVE_QUERY demands a value of >= 4 chars after
#     "=", but harvested credential parameters are usually
#     present with an EMPTY or templated value (the string
#     table carries the endpoint template, e.g.
#     ".../revoke?token=" or "...?token=%s"), so the value
#     test rejected exactly the URLs it existed to catch;
#   * the auth-path clause required scheme == "http",
#     while the auth endpoints in the evidence are https;
#   * classify() never inspected URL userinfo at all, so
#     credential-bearing DSN URLs (key@host) were invisible
#     to it (userinfo was only used by the redactor).
# The replacement below tests credential parameter NAMES
# (presence, any value including empty/templated) and a
# small set of deterministic structural signals, each of
# which is documented at its test in is_sensitive().
SENSITIVE_PARAM_NAMES = frozenset({
    "api_key", "apikey", "api-key", "token", "access_token",
    "refresh_token", "secret", "password", "passwd", "auth",
    "signature", "x-signature",
})
# Host first labels that are, by construction, an identity
# provider's account/access service (accounts.<provider>,
# access.<provider>). A bare login.<provider> host is NOT
# in this set: the same bare login URL is sensitive
# evidence in one target and a plain SDK string in
# another, with no deterministic separator in the URL, so
# host pattern alone does not support the claim there --
# login hosts are claimed when an oauth/credential signal
# below accompanies them.
SENSITIVE_HOST_LABELS = frozenset({"accounts", "access"})
# Known subscription/payments vendor domains whose /auth
# endpoint carries account credential material (the
# vendor's short domain and its registrable domain).
SENSITIVE_VENDOR_AUTH_HOSTS = frozenset({
    "rev.cat", "revenuecat.com",
})
USERINFO_RE = re.compile(r"^([a-z][a-z0-9+.-]*://)[^/@\s]+@",
                         re.I)
REDACTED = "REDACTED"
# Redaction: parameter NAME tokens that mark the value as
# credential material. Broader than SENSITIVE_QUERY (which
# drives classification) because redaction is about never
# persisting a value, not about judging the endpoint. The
# pre-audit redactor was a fixed alternation of whole
# names, so standard credential shapes sailed through it
# untouched — ?client_secret=, ?refresh_token=,
# #access_token= fragment parameters, ;jsessionid= path
# parameters, and prefixed names all leaked into reports
# and into nar-security finding evidence (stability audit
# D-01, P0). The name test below is structural: a name is
# sensitive when any of its alphanumeric tokens is a
# credential token, which covers prefixed/suffixed forms
# (aws_secret_access_key, x_api_key, private_key,
# credential, bearer) without enumerating them.
_CREDENTIAL_NAME_TOKENS = frozenset({
    "key", "token", "secret", "password", "passwd", "pwd",
    "auth", "session", "signature", "sig", "credential",
    "credentials", "bearer", "private", "jsessionid",
})
_NAME_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


def _name_is_credential(name):
    tokens = [t for t in _NAME_TOKEN_SPLIT.split(
        name.lower()) if t]
    return any(t in _CREDENTIAL_NAME_TOKENS for t in tokens)


def _redact_params(text, count):
    """Redact sensitive name=value pairs in a parameter
    string (query or fragment), preserving separators
    (& and ;) and every benign pair byte for byte."""
    out = []
    i, n = 0, len(text)
    while i < n:
        # One pair: up to the next separator.
        j = i
        while j < n and text[j] not in "&;":
            j += 1
        pair = text[i:j]
        eq = pair.find("=")
        if eq > 0:
            name, value = pair[:eq], pair[eq + 1:]
            if value and _name_is_credential(name):
                pair = name + "=" + REDACTED
                count += 1
        out.append(pair)
        if j < n:
            out.append(text[j])
            j += 1
        i = j
    return "".join(out), count


def redact_url(url):
    """Replace credential material in one URL with REDACTED.

    Returns (redacted_url, values_redacted). Covers URL
    userinfo (user:password@) as one value, sensitive
    parameters in the query AND the fragment (OAuth
    implicit-flow credentials ride the fragment), and
    ;-parameters in the path (jsessionid and kin).
    Anything else — scheme, host, path, benign parameters
    — is preserved byte for byte."""
    count = 0
    m = USERINFO_RE.match(url)
    if m:
        url = m.group(1) + REDACTED + "@" + url[m.end():]
        count += 1
    # Split the URL into head (scheme/authority/path),
    # query and fragment so each parameter surface is
    # redacted exactly once, in its own grammar.
    frag = None
    if "#" in url:
        url, frag = url.split("#", 1)
    query = None
    if "?" in url:
        url, query = url.split("?", 1)
    # Path ;-parameters (matrix parameters) in the head.
    if ";" in url:
        segments = url.split(";")
        rebuilt = [segments[0]]
        for seg in segments[1:]:
            eq = seg.find("=")
            if eq > 0:
                name, rest = seg[:eq], seg[eq + 1:]
                # A matrix parameter's value ends at the
                # next path separator: /a;jsessionid=X/b
                # carries the value X and then the path
                # continues. Redact the value only; the
                # tail is path, preserved byte for byte
                # (a raw / cannot be part of the value in
                # path grammar — it would be %2F).
                slash = rest.find("/")
                value = rest if slash < 0 else rest[:slash]
                tail = "" if slash < 0 else rest[slash:]
                if value and _name_is_credential(name):
                    seg = name + "=" + REDACTED + tail
                    count += 1
            rebuilt.append(seg)
        url = ";".join(rebuilt)
    if query is not None:
        query, count = _redact_params(query, count)
        url = url + "?" + query
    if frag is not None:
        frag, count = _redact_params(frag, count)
        url = url + "#" + frag
    return url, count
NETWORK_LIB_PREFIXES = {
    "okhttp3/": "OkHttp", "retrofit2/": "Retrofit",
    "io/ktor/": "Ktor", "com/android/volley": "Volley",
    "org/apache/http": "Apache HttpClient",
    "io/reactivex": "RxJava (reactive, often over OkHttp)",
    "com/google/firebase": "Firebase SDK",
    "com/google/android/gms": "Google Play services",
}
MAX_ENDPOINTS = 2000


def run_json_tool(script, args, timeout=1800):
    cmd = [sys.executable, os.path.join(HERE, script)] + args + ["--json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
        if proc.returncode != 0:
            # A failed tool's stdout is an error document,
            # not a result: returning it let a bad target
            # produce an empty-but-successful report
            # downstream (stability audit D-02).
            return None
        return json.loads(proc.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def _param_names(parsed):
    """Parameter names in a URL's query and fragment, in
    order, lowercased. Values are irrelevant to the
    sensitive test (see SENSITIVE_PARAM_NAMES): a named
    credential parameter with an empty or templated value
    is still a credential-carrying endpoint shape."""
    names = []
    for part in (parsed.query, parsed.fragment):
        for pair in part.replace(";", "&").split("&"):
            if pair:
                names.append(pair.split("=", 1)[0].lower())
    return names


def _path_tokens(parsed):
    """Path split into lowercase alphanumeric tokens, so
    dotted/versioned segments tokenise too (oauth2.0 ->
    oauth2, 0)."""
    return [t for t in re.split(
        r"[^a-z0-9]+", parsed.path.lower()) if t]


def is_sensitive(url, parsed):
    """Deterministic sensitive-endpoint test. Every signal
    is structural -- no signal guesses from a bare domain:

    1. URL userinfo is present (parsed.username): the
       authority carries credential material by
       construction, e.g. an error-ingest DSN of the form
       https://<key>@<ingest-host>/<project>.
    2. A credential parameter NAME is present in the
       query or fragment (SENSITIVE_PARAM_NAMES), with
       any value -- including the empty and templated
       values that defeated the old value-length rule.
       This covers signed URLs (signature / x-signature
       parameters) as well as token/key parameters.
    3. An oauth / oauth2 path token: an OAuth flow
       endpoint (authorize/revoke/token endpoints ride
       these paths), on any scheme.
    4. The legacy cleartext clause: scheme http with a
       login/auth/token/password path -- credentials
       over cleartext are sensitive by definition.
    5. The host's first label is an account/access label
       (SENSITIVE_HOST_LABELS) AND the URL addresses a
       resource on it (non-root path): an identity
       provider's account service endpoint. The path
       condition matters per-host: a bare account-host
       reference (root path) keeps its ordinary
       classification, so a host that is both an account
       service and a third-party domain still carries a
       third-party endpoint record alongside the
       sensitive one -- a single classification per
       endpoint cannot express both, and flipping every
       URL of such a host would erase its party claim.
       Every labeled account/access host carries a
       non-root account URL, so the narrowing costs no
       sensitive claim.
    6. A host label carries the hyphen token "sign": a
       signed-URL CDN host (its URLs are issued with
       signature parameters; signal 2 catches the fully
       formed ones, this catches the host shape when the
       query was not harvested).
    7. An /auth path token on a known subscription
       vendor host (SENSITIVE_VENDOR_AUTH_HOSTS): the
       vendor's account-auth endpoint. A generic /auth
       path alone is NOT a signal: on API hosts it most
       often names an OAuth scope (a data string, not a
       credential endpoint).
    """
    if parsed.username:
        return True
    if any(n in SENSITIVE_PARAM_NAMES
           for n in _param_names(parsed)):
        return True
    tokens = _path_tokens(parsed)
    if "oauth" in tokens or "oauth2" in tokens:
        return True
    if parsed.scheme == "http" and re.search(
            r"(login|auth|token|password)", parsed.path, re.I):
        return True
    host = parsed.hostname or ""
    first = host.split(".")[0] if host else ""
    if first in SENSITIVE_HOST_LABELS and \
            parsed.path not in ("", "/"):
        return True
    host_tokens = []
    for label in host.split("."):
        host_tokens.extend(label.split("-"))
    if "sign" in host_tokens:
        return True
    if host in SENSITIVE_VENDOR_AUTH_HOSTS and \
            "auth" in tokens:
        return True
    return False


# ------------------------------------------------------------------
# Purpose-kind classification (M2-03). Before this fix round
# the tool had no purpose-kind surface at all: the endpoint
# "kind" field carried only a transport/lexical value (web /
# websocket / api), so five of the six labeled kinds could
# not be expressed. The kind is now the PURPOSE kind --
# exactly one of KINDS -- and the transport survives in its
# own field ("transport": web / websocket).
#
# Evidence basis, in precedence order (first match wins;
# the order is deterministic and documented here):
#   1. Website/documentation host labels (docs, developers,
#      support, schemas, privacy, legal, dash, ...): a
#      vendor's documentation / dashboard / namespace /
#      policy host is a website, whatever the vendor sells
#      -> "other".
#   2. The www website form of an ads/telemetry vendor
#      domain (www.<vendor>): the vendor's public website,
#      not its service endpoint -> "other". Exempted:
#      domains whose www host IS the service (ad serving,
#      analytics, tag management).
#   3. Telemetry host tokens (analytics, telemetry,
#      metrics, crash, ingest as a hyphen token of any
#      host label): the endpoint's own name states its
#      purpose -> "telemetry". This precedes the vendor
#      table so an analytics subdomain of a social vendor
#      is telemetry, and a crash subdomain of an ads
#      vendor is telemetry.
#   4. Vendor association: longest-suffix match against
#      VENDOR_KIND_SUFFIXES -> the vendor's kind. The
#      table reuses the domain knowledge already in this
#      codebase (the third-party suffix list above and
#      the SDK census / tracker-host markers in nar-app),
#      extended only with documented, well-known vendor
#      domains whose association is unambiguous (ad
#      networks, analytics/attribution/crash vendors,
#      CDN providers, social platforms, API services),
#      plus named service subdomains where a vendor's
#      service host has its own purpose (an IMA ads SDK
#      host on an API domain, a fonts host, a crash /
#      telemetry SDK host on an ads domain, an
#      instrumentation host on a static-content domain).
#      Vendor association beats the lexical path rules:
#      an ad network's /api-shaped URL is still ads.
#   5. A "cdn" hyphen token in the host -> "cdn".
#   6. The legacy lexical api signal: host starts with
#      "api." or the path contains "/api" -> "api"
#      (refined in the M2-05 fix; see purpose_kind).
#   7. Anything else has no deterministic purpose
#      evidence -> "unknown". In particular a bare
#      first-party-looking service host is NOT guessed
#      as "api", and an unlisted vendor is NOT guessed
#      as "other": "other" is claimed only on the
#      positive website/consent evidence above and in
#      the asset-harvest fix (M2-06).
# Consent/privacy-vendor domains harvested from a bundled
# consent-vendor list are kind "other" by the binding
# convention (a consent endpoint does not deliver or
# broker advertising); that source-based rule lives in
# the M2-06 harvest and takes precedence over this table
# for the endpoints it harvests.
KINDS = ("api", "telemetry", "ads", "cdn", "social",
         "other", "unknown")
VENDOR_KIND_SUFFIXES = {
    # Named service subdomains (longest match wins, so
    # these beat their registrable parent below).
    "imasdk.googleapis.com": "ads",
    "adservice.google.com": "ads",
    "fonts.googleapis.com": "cdn",
    "csi.gstatic.com": "telemetry",
    "telemetry.sdk.inmobi.com": "telemetry",
    "crash-metrics.sdk.inmobi.com": "telemetry",
    "sts.applovin.com": "telemetry",
    "accounts.google.com": "social",
    "plus.google.com": "social",
    # Advertising networks / mediation.
    "doubleclick.net": "ads",
    "googlesyndication.com": "ads",
    "googleadservices.com": "ads",
    "amazon-adsystem.com": "ads",
    "applovin.com": "ads", "applvn.com": "ads",
    "applov.in": "ads",
    "adcolony.com": "ads", "vungle.com": "ads",
    "chartboost.com": "ads", "inmobi.com": "ads",
    "mopub.com": "ads", "taboola.com": "ads",
    "pangle.io": "ads", "bidmachine.io": "ads",
    "kidoz.net": "ads", "prado.co": "ads",
    "superawesome.tv": "ads", "supersonicads.com": "ads",
    "fyber.com": "ads", "unity3d.com": "ads",
    "appspot.com": "ads", "moloco.com": "ads",
    "tapjoy.com": "ads", "ironsource.com": "ads",
    "criteo.com": "ads", "pubmatic.com": "ads",
    # Telemetry: analytics, attribution, crash, product
    # analytics, observability.
    "google-analytics.com": "telemetry",
    "googletagmanager.com": "telemetry",
    "app-measurement.com": "telemetry",
    "amplitude.com": "telemetry", "mixpanel.com": "telemetry",
    "segment.io": "telemetry",
    "appsflyer.com": "telemetry",
    "appsflyersdk.com": "telemetry",
    "adjust.com": "telemetry", "adjust.io": "telemetry",
    "branch.io": "telemetry", "sentry.io": "telemetry",
    "crashlytics.com": "telemetry",
    "appcenter.ms": "telemetry",
    "singular.net": "telemetry", "deltadna.net": "telemetry",
    "statsig.com": "telemetry",
    "honeybadger.io": "telemetry", "bugsnag.com": "telemetry",
    "gameanalytics.com": "telemetry",
    "kochava.com": "telemetry", "embrace.io": "telemetry",
    # Social platforms / identity-social providers.
    "facebook.com": "social", "facebook.net": "social",
    "instagram.com": "social", "twitter.com": "social",
    "x.com": "social",
    "tiktok.com": "social", "snapchat.com": "social",
    "snapkit.com": "social", "vk.com": "social",
    "vk.ru": "social", "line.me": "social",
    "linkedin.com": "social", "pinterest.com": "social",
    "reddit.com": "social", "discord.com": "social",
    "telegram.org": "social", "youtube.com": "social",
    "twitch.tv": "social", "qq.com": "social",
    "weixin.qq.com": "social",
    # Content delivery networks / static content.
    "cloudfront.net": "cdn", "akamaihd.net": "cdn",
    "akamaized.net": "cdn", "gstatic.com": "cdn",
    "tiktokcdn.com": "cdn", "fbcdn.net": "cdn",
    "cdninstagram.com": "cdn", "fastly.net": "cdn",
    "cloudflare.com": "cdn", "inmobicdn.net": "cdn",
    "i18n-pglstatp.com": "cdn",
    # API services / hosted backends.
    "googleapis.com": "api", "firebaseio.com": "api",
    "firebaseapp.com": "api", "supabase.co": "api",
    "revenuecat.com": "api", "revenue.cat": "api",
    "helpshift.com": "api",
    "onesignal.com": "api",
}
WEBSITE_HOST_LABELS = frozenset({
    "docs", "developers", "developer", "help", "answers",
    "privacy", "legal", "schemas", "dash", "dashboard",
})
TELEMETRY_HOST_TOKENS = frozenset({
    "analytics", "telemetry", "metrics", "crash", "ingest",
})
WWW_WEBSITE_EXEMPT = frozenset({
    "googleadservices.com", "google-analytics.com",
    "googletagmanager.com",
})


def _vendor_kind(host):
    """Longest-suffix vendor association for a host, or
    None. Longest match wins so a named service subdomain
    beats its registrable parent."""
    best = None
    for suffix, kind in VENDOR_KIND_SUFFIXES.items():
        if host == suffix or host.endswith("." + suffix):
            if best is None or len(suffix) > len(best[0]):
                best = (suffix, kind)
    return best[1] if best else None


def _registrable(host):
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def purpose_kind(url, parsed, sources):
    """The purpose kind of one endpoint (see the precedence
    documentation above VENDOR_KIND_SUFFIXES)."""
    host = (parsed.hostname or "").lstrip(".")
    if not host:
        return "unknown"
    if _consent_only(sources):
        # Binding convention (M2-06): a domain harvested
        # from a bundled consent-vendor list is a
        # consent/privacy vendor -- kind "other", never
        # the advertising kind its business might suggest.
        return "other"
    labels = host.split(".")
    first_tokens = labels[0].split("-")
    if labels[0] in WEBSITE_HOST_LABELS or \
            "support" in first_tokens:
        return "other"
    vendor = _vendor_kind(host)
    if labels[0] == "www" and len(labels) == 3 and \
            vendor in ("ads", "telemetry") and \
            _registrable(host) not in WWW_WEBSITE_EXEMPT:
        return "other"
    host_tokens = []
    for label in labels:
        host_tokens.extend(label.split("-"))
    if any(t in TELEMETRY_HOST_TOKENS for t in host_tokens):
        return "telemetry"
    if vendor:
        return vendor
    if "cdn" in host_tokens:
        return "cdn"
    # Api signals (M2-05). The pre-fix lexical rule was
    # only "host starts with api." or "/api" in the path:
    # precision 0.217 / recall 0.194 -- it missed every
    # other host-side api shape and fired on ads/telemetry
    # hosts carrying api-shaped paths. Now:
    #   * vendor association (step 4 above) and the
    #     telemetry tokens (step 3) win over every api
    #     signal, so an ad network's api host or an
    #     analytics host with an /api path is NOT api;
    #   * host-side signals are api evidence in their own
    #     right: a first label of exactly "api", a
    #     numbered api label (api16), an api- prefixed
    #     label (api-sdk, api-production), or an "api"
    #     hyphen token in the first label (sdk-api-v1).
    #     A registrable domain must exist (a dot in the
    #     host): a bare "api" fragment is not a host;
    #   * the bare "/api" path signal remains, but only
    #     after every association above has declined --
    #     on its own, with no vendor association against
    #     it, it is still the service's own statement.
    # Bare service hosts with none of these shapes carry
    # no deterministic api evidence and stay "unknown";
    # they are not guessed.
    if "." in host:
        if labels[0] == "api" or \
                re.fullmatch(r"api\d+", labels[0]) or \
                "api" in first_tokens:
            return "api"
    if "/api" in parsed.path:
        return "api"
    return "unknown"


def classify(url, sources):
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
    except ValueError:
        return "unverified", None, "unknown"
    if not host:
        return "unverified", None, "unknown"
    # A leading dot is a cookie-domain marker, not part
    # of a hostname ("https://.example.com" names the
    # same host as the bare domain); normalise it away so
    # the host inventory carries the real host once.
    host = host.lstrip(".")
    if not host:
        return "unverified", None, "unknown"
    kind = purpose_kind(url, parsed, sources)
    if is_sensitive(url, parsed):
        return "sensitive", host, kind
    if _consent_only(sources):
        # A bundled consent-vendor list is, by definition,
        # a list of third-party vendors: an endpoint whose
        # only evidence is that list is a third-party
        # endpoint (M2-06).
        return "third-party", host, kind
    if any(host == s or host.endswith("." + s)
           for s in THIRD_PARTY_SUFFIXES):
        return "third-party", host, kind
    src_text = " ".join(sources or [])
    if ".dex" in src_text:
        return "dex-string", host, kind
    if ".so" in src_text:
        return "potential", host, kind
    if "assets/" in src_text or "res/" in src_text:
        return "unused-candidate", host, kind
    return "unverified", host, kind


def parse_google_services(apk_path):
    try:
        with zipfile.ZipFile(apk_path) as zf:
            for name in zf.namelist():
                if name.endswith("google-services.json"):
                    data = json.loads(
                        read_member_capped(zf, name))
                    project = data.get("project_info") or {}
                    clients = data.get("client") or []
                    api_key_present = any(
                        (c.get("api_key") or [])
                        for c in clients)
                    return {"file": name,
                            "project_id": project.get("project_id"),
                            "project_number": project.get(
                                "project_number"),
                            "api_key_present": api_key_present}
    except (zipfile.BadZipFile, ValueError):
        pass
    return None


def parse_nsc(apk_path, work_dir):
    """apktool decode -> manifest + network security config."""
    registry = reg_mod.load_registry()
    entry = next((t for t in registry["tools"]
                  if t["name"] == "apktool"), None)
    if entry is None:
        return None, "apktool not in registry"
    probe = reg_mod.probe(entry)
    if not probe["available"]:
        return None, "apktool not available"
    prefix = reg_mod.launch_prefix(probe)
    if prefix is None:
        return None, ("apktool resolved to a jar but no Java "
                      "runtime was found to launch it")
    out_dir = os.path.join(work_dir, "apktool")
    try:
        subprocess.run(prefix + ["d", "-f", "--no-src",
                                 "-o", out_dir, apk_path],
                       capture_output=True, text=True, timeout=1200)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, f"apktool decode failed: {e}"
    manifest_path = os.path.join(out_dir, "AndroidManifest.xml")
    if not os.path.isfile(manifest_path):
        return None, "apktool decode produced no manifest"
    with open(manifest_path, encoding="utf-8", errors="replace") as fh:
        manifest = fh.read()
    result = {}
    m = re.search(r'android:usesCleartextTraffic="(\w+)"', manifest)
    result["uses_cleartext_traffic"] = (
        m.group(1) == "true" if m else None)
    m = re.search(r'android:networkSecurityConfig="@xml/([\w.]+)"',
                  manifest)
    result["nsc_resource"] = m.group(1) if m else None
    if m:
        nsc_path = os.path.join(out_dir, "res", "xml",
                                m.group(1) + ".xml")
        if os.path.isfile(nsc_path):
            with open(nsc_path, encoding="utf-8",
                      errors="replace") as fh:
                nsc = fh.read()
            result["nsc_file"] = nsc_path
            result["base_cleartext_permitted"] = (
                'cleartextTrafficPermitted="true"' in nsc)
            result["domain_configs"] = re.findall(
                r"<domain[^>]*>([^<]+)</domain>", nsc)
            result["trust_anchors"] = sorted(set(re.findall(
                r'certificates src="(\w+)"', nsc)))
            result["pin_set_present"] = "<pin-set" in nsc
            result["debug_overrides_present"] = \
                "<debug-overrides" in nsc
    return result, None


# ------------------------------------------------------------------
# Bundled asset harvest (M2-06). nar-strings scans DEX,
# native libraries and resources.arsc only, so URLs that
# live in bundled asset data files were never harvested
# at all -- in the Phase 2 corpus one target's bundled
# consent-vendor list (~1,000 hosts in an asset JSON)
# was ~90% unharvested, and the party axis lost most of
# its recall to that single gap. The harvest below reads
# TEXT asset data files from the target's roots and
# extracts URLs with the same discipline nar-strings
# applies (same URL pattern, same trailing-punctuation
# and concatenated-URL handling), then validates hosts
# the way nar-app's URL census does (a real dotted host:
# alphanumeric/hyphen labels, an alphabetic TLD, no
# templating), so DEX-fragment-like garbage and %s
# templates cannot enter through this door either.
#
# Discipline:
#   * text data files only, by extension, under assets/;
#   * per-member and total scan budgets (below);
#   * ONE endpoint per host from this source (the first
#     URL seen for the host), and never for a host the
#     string evidence already carries -- code evidence
#     always wins over asset evidence for the same host;
#   * consent-vendor members are harvested FIRST, so a
#     consent-listed host keeps its consent source (and
#     therefore its "other" kind / third-party
#     classification) even if another asset also names
#     it;
#   * the report's existing endpoint cap still applies:
#     asset candidates join the same candidate pool and
#     the same MAX_ENDPOINTS loop.
ASSET_TEXT_EXTENSIONS = frozenset({
    ".json", ".txt", ".xml", ".plist", ".html", ".htm",
    ".js", ".csv", ".properties", ".yaml", ".yml",
    ".cfg", ".ini", ".conf", ".md",
})
ASSET_MEMBER_CAP_BYTES = 16 * 1024 * 1024
ASSET_SCAN_BUDGET_BYTES = 128 * 1024 * 1024
_ASSET_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_HOST_LABEL_RE = re.compile(
    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")
CONSENT_NAME_TOKENS = frozenset({
    "iab", "tcf", "gvl", "consent", "vendor", "vendors",
})
_CONSENT_CONTENT_MARKERS = (
    "gvlSpecificationVersion", "vendorListVersion",
)


def _valid_harvest_host(host):
    """True for a real dotted hostname or IPv4 address:
    the asset-harvest gate (see the section comment)."""
    if not host or "%" in host or "." not in host:
        return False
    if host.startswith((".", "-")) or host.endswith(
            (".", "-")):
        return False
    labels = host.split(".")
    if all(l.isdigit() for l in labels):
        return len(labels) == 4 and all(
            0 <= int(l) <= 255 for l in labels)
    if not all(_HOST_LABEL_RE.fullmatch(l) for l in labels):
        return False
    tld = labels[-1]
    return len(tld) >= 2 and tld.isalpha()


def _extract_asset_urls(text):
    """Yield cleaned URLs from asset text, mirroring the
    URL handling in nar-strings.classify()."""
    for m in _ASSET_URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;:!?)]")
        second = url.find("://", url.find("://") + 3)
        if second != -1:
            cut = url.rfind("http", 0, second)
            url = url[:cut] if cut > 0 else url[:second]
        if len(url) > len(url.split("://")[0]) + 3:
            yield url


def _is_consent_name(name):
    """A member name that identifies a consent-vendor
    list: a name token in CONSENT_NAME_TOKENS (an IAB /
    TCF / GVL file, a consent or vendor list)."""
    base = name.rsplit("/", 1)[-1].lower()
    tokens = [t for t in re.split(r"[^a-z0-9]+", base) if t]
    return any(t in CONSENT_NAME_TOKENS for t in tokens)


def _is_consent_member(name, head_text):
    return _is_consent_name(name) or any(
        marker in head_text
        for marker in _CONSENT_CONTENT_MARKERS)


def _consent_only(sources):
    """True when an endpoint's evidence is only a bundled
    consent-vendor list: some source is a consent-named
    asset member and no source is code evidence (DEX,
    native library, resources)."""
    srcs = list(sources or [])
    if not srcs:
        return False
    if any(".dex" in s or s.endswith(".so")
           or "resources.arsc" in s for s in srcs):
        return False
    return any(
        ("assets/" in s or s.startswith("assets/"))
        and _is_consent_name(s) for s in srcs)


def harvest_asset_urls(roots, known_hosts):
    """Harvest {url: {member}} from text asset data files
    in each root archive, one URL per new host (see the
    section comment for the full discipline)."""
    found = {}
    harvested_hosts = set(known_hosts or ())
    budget = [ASSET_SCAN_BUDGET_BYTES]

    def scan(root, consent_pass):
        try:
            zf = zipfile.ZipFile(root)
        except (zipfile.BadZipFile, OSError):
            return
        with zf:
            names = sorted(
                n for n in zf.namelist()
                if (n.startswith("assets/")
                    or "/assets/" in n)
                and os.path.splitext(n)[1].lower()
                in ASSET_TEXT_EXTENSIONS)
            for name in names:
                if budget[0] <= 0:
                    return
                try:
                    data = read_member_capped(
                        zf, name,
                        cap_bytes=ASSET_MEMBER_CAP_BYTES)
                except (KeyError, ValueError, OSError):
                    continue
                budget[0] -= len(data)
                if b"\x00" in data[:4096]:
                    continue  # not text, whatever it claims
                text = data.decode("utf-8", errors="ignore")
                consent = _is_consent_member(
                    name, text[:4096])
                if consent != consent_pass:
                    continue
                for url in _extract_asset_urls(text):
                    try:
                        host = urllib.parse.urlparse(
                            url).hostname
                    except ValueError:
                        continue
                    host = (host or "").lstrip(".")
                    if not _valid_harvest_host(host):
                        continue
                    if host in harvested_hosts:
                        continue
                    harvested_hosts.add(host)
                    found.setdefault(url, set()).add(name)

    for root in roots or []:
        scan(root, True)
    for root in roots or []:
        scan(root, False)
    return found


def analyze(target, work_dir=None):
    # Container inputs resolve through narlib.container:
    # string evidence comes from nar-strings (which itself
    # resolves and merges splits), config-file evidence is
    # read from the resolved roots, and the apktool NSC pass
    # runs on the base APK — never on the container file
    # itself as if it were an APK.
    resolved = None
    if container_mod.detect_container(target) in \
            container_mod.CONTAINER_KINDS:
        resolved = container_mod.resolve_target(target)
    effective = resolved.base if resolved is not None \
        else target
    roots = resolved.assets_roots if resolved is not None \
        else [target]
    strings = run_json_tool("nar-strings.py", [target])
    if strings is None:
        if resolved is not None:
            resolved.cleanup()
        raise RuntimeError("nar-strings failed on this input")
    groups = strings.get("groups") or {}
    candidates = {}
    for group_name in ("urls", "api_endpoints"):
        group = groups.get(group_name) or {}
        for hit in group.get("hits", []):
            value = hit.get("value") if isinstance(hit, dict) else hit
            sources = hit.get("sources") if isinstance(hit, dict) else []
            if value:
                candidates.setdefault(value, set()).update(sources or [])
    # Bundled asset data files (M2-06): a second harvest
    # source for hosts the string evidence does not carry.
    _known_hosts = set()
    for _url in candidates:
        try:
            _h = urllib.parse.urlparse(_url).hostname
        except ValueError:
            _h = None
        if _h:
            _known_hosts.add(_h.lstrip("."))
    for _url, _srcs in harvest_asset_urls(
            roots, _known_hosts).items():
        candidates.setdefault(_url, set()).update(_srcs)
    endpoints = []
    hosts = set()
    total_redacted = 0
    for url in sorted(candidates):
        classification, host, kind = classify(
            url, sorted(candidates[url]))
        if host:
            hosts.add(host)
        safe_url, n_redacted = redact_url(url[:500])
        total_redacted += n_redacted
        try:
            scheme = urllib.parse.urlparse(url).scheme
        except ValueError:
            scheme = ""
        endpoint = {"url": safe_url, "host": host,
                    "kind": kind,
                    "transport": "websocket" if scheme in
                    ("ws", "wss") else "web",
                    "classification": classification,
                    "sources": sorted(candidates[url])[:5]}
        if n_redacted:
            endpoint["redacted"] = True
        endpoints.append(endpoint)
        if len(endpoints) >= MAX_ENDPOINTS:
            break
    # Purpose-kind host inventory (M2-03): every host sits
    # in exactly one kind bucket -- the first non-"unknown"
    # kind among its endpoints (endpoints are in sorted-URL
    # order, so this is deterministic), or "unknown" when
    # no endpoint carries purpose evidence. api_hosts is
    # exactly the "api" bucket, by construction.
    kind_hosts = {k: [] for k in KINDS}
    _kind_by_host = {}
    for e in endpoints:
        host = e["host"]
        if not host:
            continue
        current = _kind_by_host.get(host)
        if current is None or (
                current == "unknown" and e["kind"] != "unknown"):
            _kind_by_host[host] = e["kind"]
    for host, kind in _kind_by_host.items():
        kind_hosts[kind].append(host)
    for kind in kind_hosts:
        kind_hosts[kind] = sorted(kind_hosts[kind])
    api_hosts = set(kind_hosts["api"])
    # Network libraries from package-name string evidence.
    pkg_hits = [h.get("value") for h in
                (groups.get("package_names") or {}).get("hits", [])
                if isinstance(h, dict)]
    libraries = {label for prefix, label in
                 NETWORK_LIB_PREFIXES.items()
                 if any(p and p.startswith(prefix)
                        for p in pkg_hits)}
    # Second source: triage library-version evidence.
    triage = run_json_tool("nar-triage.py", [target])
    for name in ((triage or {}).get("library_versions") or {}):
        lname = name.lower()
        for token, label in (("okhttp", "OkHttp"),
                             ("retrofit", "Retrofit"),
                             ("ktor", "Ktor"), ("volley", "Volley"),
                             ("firebase", "Firebase SDK")):
            if token in lname:
                libraries.add(label)
    libraries = sorted(libraries)
    # Backend services.
    services = []
    gs = None
    for root in roots:
        gs = parse_google_services(root)
        if gs:
            break
    if gs:
        services.append({"service": "Firebase", "evidence": gs})
    for host in sorted(hosts):
        if host.endswith(".supabase.co"):
            services.append({"service": "Supabase",
                             "evidence": {"host": host}})
        if host.endswith("firebaseio.com") or \
                host.endswith("firebasedatabase.app"):
            services.append({"service": "Firebase Realtime "
                                        "Database",
                             "evidence": {"host": host}})
        if "amazonaws.com" in host:
            services.append({"service": "AWS",
                             "evidence": {"host": host}})
        if host.endswith("ingest.sentry.io") or \
                host.endswith("sentry.io"):
            services.append({"service": "Sentry",
                             "evidence": {"host": host}})
    notes = []
    nsc = None
    if work_dir:
        nsc, err = parse_nsc(effective, work_dir)
        if err:
            notes.append(f"network security config: {err}")
    else:
        notes.append("network security config not parsed "
                     "(pass --work DIR to enable the apktool pass)")
    by_class = {}
    for e in endpoints:
        by_class[e["classification"]] = \
            by_class.get(e["classification"], 0) + 1
    report = {"tool": "nar-network", "version": "3.0.2",
            "target": os.path.abspath(target),
            "target_sha256": sha256_of(target),
            "endpoints": endpoints, "hosts": sorted(hosts),
            "api_hosts": sorted(api_hosts),
            "kind_hosts": kind_hosts,
            "network_libraries": libraries, "services": services,
            "network_security_config": nsc,
            "classification_counts": by_class,
            "redaction": {
                "endpoint_values_redacted": total_redacted,
                "policy": "credential values in endpoint URLs "
                          "(sensitive query parameters and "
                          "userinfo) are replaced with REDACTED "
                          "before any output is written; only "
                          "the count is reported, never a value"},
            "notes": notes}
    if resolved is not None:
        report["container"] = resolved.container_block()
        resolved.cleanup()
    return report


def human(report):
    print(f"NAR network intelligence: "
          f"{os.path.basename(report['target'])}")
    print("=" * 60)
    print(f"Endpoints: {len(report['endpoints'])} "
          f"{report['classification_counts']}")
    print(f"Hosts: {len(report['hosts'])}; API hosts: "
          f"{report['api_hosts'][:10]}")
    kind_hosts = report.get("kind_hosts") or {}
    if kind_hosts:
        print("Kind hosts: " + ", ".join(
            f"{k}={len(kind_hosts.get(k) or [])}"
            for k in KINDS))
    print(f"Network libraries: {report['network_libraries']}")
    redacted = (report.get("redaction") or {}).get(
        "endpoint_values_redacted")
    if redacted:
        print(f"Redacted credential values in endpoint URLs: "
              f"{redacted}")
    for svc in report["services"]:
        print(f"service: {svc['service']} — {svc['evidence']}")
    nsc = report["network_security_config"]
    if nsc:
        print(f"NSC: cleartext={nsc.get('uses_cleartext_traffic')}"
              f", resource={nsc.get('nsc_resource')}, "
              f"trust anchors={nsc.get('trust_anchors')}, "
              f"pin-set={nsc.get('pin_set_present')}")
    for e in report["endpoints"][:15]:
        print(f"  [{e['classification']}] {e['url'][:110]}")
    for note in report["notes"]:
        print(f"note: {note}")


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Static network intelligence: classified "
                    "endpoint inventory, services, NSC parsing.")
    p.add_argument("target", help="path to the .apk file")
    p.add_argument("--json", action="store_true")
    p.add_argument("--work", metavar="DIR",
                   help="work dir enabling the apktool NSC pass")
    args = p.parse_args(argv)
    try:
        report = analyze(args.target, args.work)
    except (FileNotFoundError, RuntimeError) as e:
        print(f"nar-network: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        human(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
