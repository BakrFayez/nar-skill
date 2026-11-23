#!/usr/bin/env python3
"""nar-network.py: static network intelligence (brief
section 7).

Builds the endpoint inventory from string evidence and
classifies every endpoint with static-analysis honesty:

- confirmed: referenced from DEX code,
- potential: seen in native-library strings only,
- unused-candidate: seen only in assets/resources,
- third-party: a known SDK/service domain,
- sensitive: credentials or auth material inside the URL,
- unverified: no parseable host / no usable evidence.

Also reports: host and API-host inventories, backend
services (Firebase/Supabase/AWS/Azure/App Center/Sentry)
with config-file evidence (google-services.json is parsed
for the project id; key VALUES are never printed), the
network libraries present, cleartext posture, and the
network security config (parsed from an apktool decode:
cleartext rules, domain configs, trust anchors, pin sets,
debug overrides). No traffic is generated and nothing is
contacted: this is static analysis only.

Usage:
    python3 nar-network.py app.apk [--json] [--work DIR]

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
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
from narlib import registry as reg_mod  # noqa: E402
from narlib.hashing import sha256_of  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
THIRD_PARTY_SUFFIXES = (
    "googleapis.com", "gstatic.com", "google.com",
    "doubleclick.net", "googlesyndication.com",
    "google-analytics.com", "firebaseio.com",
    "firebaseapp.com", "crashlytics.com", "facebook.com",
    "facebook.net", "sentry.io", "amplitude.com",
    "mixpanel.com", "appcenter.ms", "visualstudio.com",
    "unity3d.com", "unity.com", "applovin.com",
    "adcolony.com", "vungle.com", "chartboost.com",
    "inmobi.com", "mopub.com", "amazonaws.com",
    "supabase.co", "cloudflare.com", "akamaihd.net",
    "branch.io", "appsflyer.com", "adjust.com",
    "onesignal.com", "intercom.io", "zendesk.com",
)
SENSITIVE_QUERY = re.compile(
    r"(api[_-]?key|apikey|token|secret|password|passwd|auth)="
    r"[^&]{4,}", re.I)
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
        return json.loads(proc.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def classify(url, sources):
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
    except ValueError:
        return "unverified", None, "web"
    if not host:
        return "unverified", None, "web"
    kind = "web"
    if parsed.scheme in ("ws", "wss"):
        kind = "websocket"
    elif "/api" in parsed.path or host.startswith("api."):
        kind = "api"
    if SENSITIVE_QUERY.search(url) or (
            parsed.scheme == "http"
            and re.search(r"(login|auth|token|password)",
                          parsed.path, re.I)):
        return "sensitive", host, kind
    if any(host == s or host.endswith("." + s)
           for s in THIRD_PARTY_SUFFIXES):
        return "third-party", host, kind
    src_text = " ".join(sources or [])
    if ".dex" in src_text:
        return "confirmed", host, kind
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
                    data = json.loads(zf.read(name))
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
    out_dir = os.path.join(work_dir, "apktool")
    try:
        subprocess.run([probe["path"], "d", "-f", "--no-src",
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


def analyze(target, work_dir=None):
    strings = run_json_tool("nar-strings.py", [target])
    if strings is None:
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
    endpoints = []
    hosts, api_hosts = set(), set()
    for url in sorted(candidates):
        classification, host, kind = classify(
            url, sorted(candidates[url]))
        if host:
            hosts.add(host)
            if kind == "api":
                api_hosts.add(host)
        endpoints.append({"url": url[:500], "host": host,
                          "kind": kind,
                          "classification": classification,
                          "sources": sorted(candidates[url])[:5]})
        if len(endpoints) >= MAX_ENDPOINTS:
            break
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
    gs = parse_google_services(target)
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
        nsc, err = parse_nsc(target, work_dir)
        if err:
            notes.append(f"network security config: {err}")
    else:
        notes.append("network security config not parsed "
                     "(pass --work DIR to enable the apktool pass)")
    by_class = {}
    for e in endpoints:
        by_class[e["classification"]] = \
            by_class.get(e["classification"], 0) + 1
    return {"tool": "nar-network", "version": "2.0.0",
            "target": os.path.abspath(target),
            "target_sha256": sha256_of(target),
            "endpoints": endpoints, "hosts": sorted(hosts),
            "api_hosts": sorted(api_hosts),
            "network_libraries": libraries, "services": services,
            "network_security_config": nsc,
            "classification_counts": by_class, "notes": notes}


def human(report):
    print(f"NAR network intelligence: "
          f"{os.path.basename(report['target'])}")
    print("=" * 60)
    print(f"Endpoints: {len(report['endpoints'])} "
          f"{report['classification_counts']}")
    print(f"Hosts: {len(report['hosts'])}; API hosts: "
          f"{report['api_hosts'][:10]}")
    print(f"Network libraries: {report['network_libraries']}")
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
