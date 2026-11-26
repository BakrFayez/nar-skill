"""Phase 2 fix-round regression tests: nar-network.

M2-04 (sensitive rule), M2-03 (purpose-kind surface),
M2-05 (api kind precision/recall), M2-06 (asset harvest
+ party suffix). All fixtures are synthetic: vendor
domains appear only as the well-known service domains
the rules are documented to key on, never as a target
identity.
"""
import importlib.util
import json
import os
import sys
import zipfile

ROOT = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))


def _load_network():
    spec = importlib.util.spec_from_file_location(
        "nar_network_phase2", os.path.join(
            ROOT, "scripts", "nar-network.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


net = _load_network()


def _classify(url, sources=("classes.dex",)):
    return net.classify(url, list(sources))


# ------------------------------------------------------
# M2-04: the sensitive rule must fire on the harvested
# shapes that defeated the old value-length rule, and
# must not fire on the documented non-signals.
# ------------------------------------------------------

def test_sensitive_empty_credential_value_fires():
    # Root cause: the old rule demanded >= 4 chars after
    # "=", so a credential parameter present with an
    # empty value never fired.
    cls, host, _ = _classify(
        "https://accounts.example-idp.com/o/oauth2/revoke"
        "?token=")
    assert cls == "sensitive"
    assert host == "accounts.example-idp.com"


def test_sensitive_templated_credential_value_fires():
    cls, _, _ = _classify(
        "https://service.example.com/cb?token=%s")
    assert cls == "sensitive"


def test_sensitive_named_credential_params_fire():
    for url in (
            "https://service.example.com/x?api_key=",
            "https://service.example.com/x#access_token=",
            "https://service.example.com/x?refresh_token=a",
            "https://service.example.com/x?client=1&secret="):
        cls, _, _ = _classify(url)
        assert cls == "sensitive", url


def test_sensitive_signature_param_fires():
    # Signed URLs carry signature / x-signature parameter
    # names; the old name list did not include them.
    for url in (
            "https://cdn.example.com/a?x-expires=1"
            "&x-signature=abc",
            "https://open.example-social.com/connect"
            "?appid=%s&signature=%s"):
        cls, _, _ = _classify(url)
        assert cls == "sensitive", url


def test_sensitive_userinfo_credentials_fire():
    # Error-ingest DSN shape: key@host. classify() never
    # inspected userinfo before the fix.
    cls, host, _ = _classify(
        "https://0123456789abcdef0123456789abcdef"
        "@o123.ingest.example-telemetry.com/456")
    assert cls == "sensitive"
    assert host == "o123.ingest.example-telemetry.com"


def test_sensitive_account_and_access_hosts_fire():
    for url in ("https://accounts.example-idp.com"
                "/o/oauth2/revoke?token=",
                "https://accounts.example-social.com/a",
                "https://access.example-messenger.com"
                "/.well-known/openid-configuration"):
        cls, _, _ = _classify(url)
        assert cls == "sensitive", url


def test_sensitive_bare_account_host_reference_alone():
    # A bare account-host reference (root path) is a
    # domain mention, not an account-service endpoint:
    # it keeps its ordinary classification so the host
    # retains a third-party record next to the sensitive
    # account URLs (per-host party preservation).
    cls, _, _ = _classify("https://accounts.google.com/")
    assert cls == "third-party"


def test_sensitive_oauth_paths_fire_on_https():
    # The old auth-path clause required http, so https
    # OAuth endpoints never fired.
    for url in ("https://api.example-social.com/oauth"
                "/authorize",
                "https://service.example.com/oauth2/token",
                "https://openmobile.example.com/oauth2.0"
                "/m_authorize"):
        cls, _, _ = _classify(url)
        assert cls == "sensitive", url


def test_sensitive_signed_host_token_fires():
    cls, _, _ = _classify(
        "https://p16-sign-sg.example-cdn.com/v0201/abc"
        "~tplv-noop.image")
    assert cls == "sensitive"


def test_sensitive_subscription_vendor_auth_fires():
    cls, _, _ = _classify("https://rev.cat/auth")
    assert cls == "sensitive"


def test_sensitive_cleartext_auth_path_still_fires():
    # The legacy synthetic-corpus clause is preserved.
    cls, _, _ = _classify("http://example.com/login")
    assert cls == "sensitive"


def test_sensitive_non_signals_do_not_fire():
    for url, sources in (
            # An /auth/<scope> path on an API host names
            # an OAuth scope (a data string); generic
            # /auth is not a signal on https.
            ("https://www.example-apis.com/auth/appstate",
             ("classes.dex",)),
            # A bare login host alone carries no
            # deterministic separator (see rule comment).
            ("https://login.example-idp.com/",
             ("classes.dex",)),
            # Compound credential-ish names outside the
            # documented name list are not signals.
            ("https://example-ads.com/c?client_token=abc",
             ("classes.dex",)),
            ("https://example.com/collect?session_id=abc",
             ("classes.dex",)),
            # Plain endpoints stay plain.
            ("https://example.com/about",
             ("classes.dex",))):
        cls, _, _ = _classify(url, sources)
        assert cls != "sensitive", url


# ------------------------------------------------------
# M2-03: purpose-kind surface. classify() returns the
# purpose kind; analyze() emits kind_hosts mirroring
# api_hosts, with every host in exactly one bucket.
# ------------------------------------------------------

def _kind(url, sources=("classes.dex",)):
    return _classify(url, sources)[2]


def test_kind_vendor_associations():
    cases = {
        "https://a.applovin.com/": "ads",
        "https://doubleclick.net/": "ads",
        "https://www.google-analytics.com/collect":
            "telemetry",
        "https://o123.ingest.sentry.io/456": "telemetry",
        "https://graph.facebook.com/me": "social",
        "https://d123.cloudfront.net/x.png": "cdn",
        "https://firebaseremoteconfig.googleapis.com"
        "/v1/projects/x/remoteConfig": "api",
        "https://project-x.firebaseio.com/data": "api",
        "https://webchat.helpshift.com/a": "api",
    }
    for url, want in cases.items():
        assert _kind(url) == want, url


def test_kind_named_service_subdomain_beats_parent():
    # An ads SDK host on an API domain is ads; a fonts
    # host on an API domain is cdn; a crash host on an
    # ads domain is telemetry.
    assert _kind("https://imasdk.googleapis.com/ads") \
        == "ads"
    assert _kind("https://fonts.googleapis.com/css") \
        == "cdn"
    assert _kind("https://crash-metrics.sdk.inmobi.com"
                 "/") == "telemetry"


def test_kind_telemetry_token_beats_social_vendor():
    assert _kind("https://analytics.us.tiktok.com"
                 "/monitor") == "telemetry"


def test_kind_cdn_host_token():
    assert _kind("https://cdn.example-game.com/a.png") \
        == "cdn"
    assert _kind("https://media-cdn.example.com/a") \
        == "cdn"


def test_kind_website_hosts_are_other():
    for url in ("https://docs.example-vendor.com/guide",
                "https://developers.example.com/",
                "https://support.example.com/hc",
                "https://schemas.example.com/android/1.0",
                "https://privacy.example.com/policy",
                "https://www.applovin.com/"):
        assert _kind(url) == "other", url


def test_kind_unknown_without_deterministic_evidence():
    # Bare service hosts are not guessed as api, and
    # unlisted domains are not guessed as other.
    for url in ("https://validate.example-game.com/x",
                "https://example.com/about",
                "https://unlisted-vendor.example.net/"):
        assert _kind(url) == "unknown", url


def test_kind_legacy_api_signal_still_fires():
    assert _kind("https://api.example.com/v1/items") \
        == "api"
    assert _kind("https://service.example.com/api/v2") \
        == "api"


def _analyze_with_urls(urls):
    import tempfile
    strings_doc = {"groups": {
        "urls": {"hits": [
            {"value": u, "sources": ["classes.dex"]}
            for u in urls]},
        "api_endpoints": {"hits": []},
        "package_names": {"hits": []}}}
    triage_doc = {"library_versions": {}}
    real = net.run_json_tool
    net.run_json_tool = lambda script, args, timeout=1800: \
        strings_doc if "strings" in script else triage_doc
    try:
        with tempfile.NamedTemporaryFile(
                suffix=".apk", delete=False) as fh:
            fh.write(b"PK\x03\x04 planted")
            target = fh.name
        try:
            return net.analyze(target)
        finally:
            os.unlink(target)
    finally:
        net.run_json_tool = real


def test_analyze_kind_hosts_surface():
    report = _analyze_with_urls([
        "https://a.applovin.com/",
        "https://api.example.com/v1/items",
        "https://www.google-analytics.com/collect",
        "https://graph.facebook.com/me",
        "https://cdn.example-game.com/a.png",
        "https://docs.example-vendor.com/guide",
        "https://validate.example-game.com/x",
        "wss://stream.example.com/socket",
    ])
    kind_hosts = report["kind_hosts"]
    assert set(kind_hosts) == set(net.KINDS)
    assert kind_hosts["ads"] == ["a.applovin.com"]
    assert kind_hosts["api"] == ["api.example.com"]
    assert kind_hosts["telemetry"] == [
        "www.google-analytics.com"]
    assert kind_hosts["social"] == ["graph.facebook.com"]
    assert kind_hosts["cdn"] == ["cdn.example-game.com"]
    assert kind_hosts["other"] == [
        "docs.example-vendor.com"]
    assert set(kind_hosts["unknown"]) == {
        "validate.example-game.com", "stream.example.com"}
    # api_hosts is exactly the api bucket.
    assert report["api_hosts"] == kind_hosts["api"]
    # Every host in exactly one bucket.
    all_bucketed = [h for hosts in kind_hosts.values()
                    for h in hosts]
    assert sorted(all_bucketed) == report["hosts"]
    # Transport survives in its own field.
    by_host = {e["host"]: e for e in report["endpoints"]}
    assert by_host["stream.example.com"]["transport"] \
        == "websocket"
    assert by_host["api.example.com"]["transport"] \
        == "web"
    # The report still validates against the schema.
    from narlib import evidence
    with open(os.path.join(
            ROOT, "schemas", "endpoints.schema.json"),
            encoding="utf-8") as fh:
        schema = json.load(fh)
    assert evidence.validate(report, schema) == []


# ------------------------------------------------------
# M2-05: api kind -- host-side signals are api evidence;
# vendor association wins over every lexical api signal.
# ------------------------------------------------------

def test_api_host_side_signals():
    for url in ("https://api-sdk.example.net/",
                "https://api-production.example.io/",
                "https://api16.example.net/data",
                "https://sdk-api-v1.example.net/",
                "https://api.example.com/v1"):
        assert _kind(url) == "api", url


def test_api_vendor_association_wins_over_host_signal():
    cases = {
        "https://api.vungle.com/": "ads",
        "https://api16-access-sg.pangle.io/": "ads",
        "https://api.twitter.com/1.1/": "social",
        "https://api.line.me/v2/": "social",
        "https://sdk-api-v1.singular.net/": "telemetry",
    }
    for url, want in cases.items():
        assert _kind(url) == want, url


def test_api_vendor_association_wins_over_api_path():
    cases = {
        "https://a.applovin.com/api/v1": "ads",
        "https://t.appsflyer.com/api/v1": "telemetry",
        "https://privacy-sandbox.appsflyersdk.com"
        "/api/privacy": "telemetry",
        "https://a.revenue.cat/v1/subscribers": "api",
    }
    for url, want in cases.items():
        assert _kind(url) == want, url


def test_api_bare_fragment_host_is_not_api():
    # A bare "api" string is not a host (no registrable
    # domain); the host-side signals must not fire on it.
    assert _kind("https://api/v1/items") == "unknown"


def test_api_bare_service_host_stays_unknown():
    # No lexical signal, no vendor association: not
    # guessed, however api-shaped the service may be.
    assert _kind("https://validate.example.net/") \
        == "unknown"
    assert _kind("https://connect.example.net/") \
        == "unknown"


# ------------------------------------------------------
# M2-06: bundled asset data files are a harvest source;
# consent-vendor list endpoints are kind "other" and
# third-party; project-instance suffixes are not claimed
# third-party by suffix alone.
# ------------------------------------------------------

def test_party_project_instance_suffix_not_third_party():
    # A hosted-backend project instance is the app's own
    # backend: kind api, but not a third-party claim.
    cls, host, kind = _classify(
        "https://my-project-123.firebaseio.com/data")
    assert cls != "third-party"
    assert kind == "api"
    cls, _, _ = _classify(
        "https://myapp.firebaseapp.com/")
    assert cls != "third-party"


def test_leading_dot_host_normalised():
    # A leading dot is a cookie-domain marker, not part
    # of the hostname.
    cls, host, kind = _classify("https://.facebook.com/")
    assert host == "facebook.com"
    assert cls == "third-party"
    assert kind == "social"


def _analyze_apk(members, string_urls):
    import tempfile
    strings_doc = {"groups": {
        "urls": {"hits": [
            {"value": u, "sources": ["classes.dex"]}
            for u in string_urls]},
        "api_endpoints": {"hits": []},
        "package_names": {"hits": []}}}
    triage_doc = {"library_versions": {}}
    real = net.run_json_tool
    net.run_json_tool = lambda script, args, timeout=1800: \
        strings_doc if "strings" in script else triage_doc
    try:
        with tempfile.NamedTemporaryFile(
                suffix=".apk", delete=False) as fh:
            target = fh.name
        with zipfile.ZipFile(target, "w") as zf:
            for name, data in members.items():
                zf.writestr(name, data)
        try:
            return net.analyze(target)
        finally:
            os.unlink(target)
    finally:
        net.run_json_tool = real


_CONSENT_JSON = json.dumps({
    "gvlSpecificationVersion": 3,
    "vendors": {
        "1": {"urls": [{"privacy":
                "https://vendor-one.example/privacy"}]},
        "2": {"urls": [{"privacy":
                "https://www.vendor-two.example/policy",
                "legIntClaim":
                "https://vendor-one.example/claims"}]},
        "3": {"urls": [{"privacy": "https://%s"}]},
        "4": {"urls": [{"privacy": "https://a-"}]},
        "5": {"urls": [{"privacy": "https://nodot"}]},
        "6": {"urls": [{"privacy":
                "https://known.example.com/privacy"}]},
    }})


def test_asset_harvest_consent_list():
    report = _analyze_apk(
        {"assets/test_iab_config.json": _CONSENT_JSON,
         "assets/config.json":
             "https://backend.example.net/api/v1",
         "assets/binary.json":
             b"\x00\x01https://binary.example.com/"},
        ["https://known.example.com/from-dex"])
    by_host = {}
    for e in report["endpoints"]:
        by_host.setdefault(e["host"], []).append(e)
    # Consent-listed hosts are harvested, one endpoint
    # per host, kind "other", classification third-party.
    assert len(by_host["vendor-one.example"]) == 1
    e = by_host["vendor-one.example"][0]
    assert e["kind"] == "other"
    assert e["classification"] == "third-party"
    assert e["sources"] == ["assets/test_iab_config.json"]
    assert by_host["www.vendor-two.example"][0][
        "classification"] == "third-party"
    assert report["kind_hosts"]["other"] == sorted(
        report["kind_hosts"]["other"])
    assert "vendor-one.example" in \
        report["kind_hosts"]["other"]
    # A plain asset data file is harvested too, with the
    # asset-source classification and its own kind.
    e = by_host["backend.example.net"][0]
    assert e["classification"] == "unused-candidate"
    assert e["kind"] == "api"
    # Garbage and binary members do not enter; a host the
    # string evidence already carries is not duplicated
    # from the asset.
    assert "binary.example.com" not in by_host
    assert "%s" not in report["hosts"]
    assert "a-" not in report["hosts"]
    assert "nodot" not in report["hosts"]
    assert len(by_host["known.example.com"]) == 1
    assert by_host["known.example.com"][0]["url"] == \
        "https://known.example.com/from-dex"
    assert set(report["hosts"]) == set(by_host)


def test_consent_source_does_not_relabel_code_endpoints():
    # The same URL in code evidence AND a consent file:
    # code evidence wins, no consent relabelling.
    cls, _, kind = net.classify(
        "https://vendor-one.example/privacy",
        ["classes.dex", "assets/test_iab_config.json"])
    assert cls == "dex-string"
    assert kind == "unknown"
