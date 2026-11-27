#!/usr/bin/env python3
"""nar-security.py: structured security findings (brief
section 9).

Reviews the static evidence from nar-perms, nar-triage,
nar-network (and nar-dex with --deep) and emits findings in
the section 9.5 schema: id (NAR-SEC-NNN), title, severity,
confidence, affected component, file path, evidence,
explanation, potential impact, reproduction, remediation,
and false-positive considerations. Each finding also
carries a verification_status (CONFIRMED for facts read
directly off the target, STRONGLY_INDICATED for conclusions
from classified patterns, POTENTIAL for review prompts) —
kept separate from confidence, and never upgraded beyond
what the static evidence supports. Severity is assigned
conservatively and every finding names the evidence it
rests on; absences that are commonly benign are reported
as informational with their false-positive notes, and
protective controls that ARE present are listed as
positive observations, not findings.

Checks: debuggable builds, backup posture, cleartext
traffic (manifest + NSC + DEX-string http endpoints),
credentials embedded in endpoint URLs, exported components
without permission guards, dangerous-permission surface,
v1-only signing, outdated target/min SDK, dynamic code
loading and WebView JavaScript bridges (with --deep).

Usage:
    python3 nar-security.py app.apk [--json] [--deep]
                            [--work DIR]

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import container as container_mod  # noqa: E402
from narlib import dex as dexlib  # noqa: E402
from narlib import evidence as ev  # noqa: E402
from narlib.hashing import sha256_of  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


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


class Findings:
    def __init__(self):
        self.items = []

    def add(self, title, severity, confidence, component, path,
            evidence_text, explanation, impact, remediation,
            false_positives="",
            verification_status="UNVERIFIED"):
        # verification_status (Phase 6): CONFIRMED only for
        # facts read directly off the target (manifest
        # attributes, signer verdicts, permission sets);
        # STRONGLY_INDICATED for conclusions drawn from
        # classified patterns; POTENTIAL for review prompts.
        self.items.append(ev.make_finding(
            f"NAR-SEC-{len(self.items) + 1:03d}", title, severity,
            confidence, component, path, evidence_text,
            explanation, impact, remediation,
            reproduction="static analysis (see evidence)",
            false_positives=false_positives,
            verification_status=verification_status))


def review(target, deep=False, work_dir=None):
    # Container inputs resolve through narlib.container:
    # the manifest audit (nar-perms) runs on the base APK —
    # never on the container file itself as if it were an
    # APK — while triage / network / dex consume the
    # container through their own resolution. The resolution
    # is recorded under the report's `container` block.
    resolved = None
    if container_mod.detect_container(target) in \
            container_mod.CONTAINER_KINDS + ("apk",):
        # A plain APK resolves too, but the resolution is
        # adopted only when it actually assembled a set (a
        # container, or a loose split set merged by sibling
        # discovery — field round F-01); an ordinary lone
        # APK keeps the single-archive path unchanged.
        _candidate = container_mod.resolve_target(target)
        if _candidate.is_container or _candidate.splits:
            resolved = _candidate
        else:
            _candidate.cleanup()
    perms_target = resolved.base if resolved is not None \
        else target
    perms = run_json_tool("nar-perms.py", [perms_target])
    triage = run_json_tool("nar-triage.py", [target])
    if perms is None or triage is None:
        if resolved is not None:
            resolved.cleanup()
        raise RuntimeError("nar-perms/nar-triage failed")
    network_args = [target]
    network = run_json_tool("nar-network.py", network_args)
    findings = Findings()
    positives = []
    skipped = []
    if network is None:
        # A missing sub-result must never read as "no
        # network findings" (stability audit D-13).
        skipped.append(
            "network checks (sensitive endpoints, "
            "cleartext, network security config) skipped: "
            "nar-network.py did not return a result")
    app = perms.get("application") or {}
    manifest = "AndroidManifest.xml"

    if app.get("debuggable") is True:
        findings.add(
            "Application is debuggable", "high", "high",
            "application", manifest,
            "android:debuggable=\"true\" in the manifest "
            "(nar-perms application block)",
            "A debuggable build lets anyone with device access "
            "attach a debugger and read app-private data.",
            "Data exposure and full runtime inspection of the "
            "shipped build.",
            "Set android:debuggable=\"false\" for release "
            "builds; keep debug flags in debug variants only.",
            "A debug/test build distributed intentionally "
            "would explain this; it is critical only for "
            "production distribution.",
            verification_status="CONFIRMED")
    if app.get("allow_backup") is True:
        findings.add(
            "Full backup allowed", "medium", "high",
            "application", manifest,
            "android:allowBackup=\"true\" (nar-perms)",
            "App data can be extracted through the platform "
            "backup transport by anyone with device access.",
            "Private app data (tokens, files) can leave the "
            "device via backup.",
            "Set allowBackup=\"false\" or define backup rules "
            "excluding sensitive files.",
            "Apps that intentionally support user backup "
            "migration may accept this risk.",
            verification_status="CONFIRMED")
    # Exported components without permission guards.
    # "activity-alias" is a real component kind (nar-perms
    # COMPONENT_TAGS includes it): an exported alias
    # exposes its target activity, and omitting it here
    # was a silent false negative (stability audit D-07).
    components = perms.get("components") or {}
    for kind in ("activity", "activity-alias", "service",
                 "receiver", "provider"):
        exposed = [c for c in components.get(kind, [])
                   if c.get("exported") and not c.get("permission")]
        if not exposed:
            continue
        names = [c["name"] for c in exposed][:10]
        severity = "high" if kind == "provider" else "medium"
        findings.add(
            f"Exported {kind}(s) without a permission guard",
            severity, "high", kind, manifest,
            f"{len(exposed)} exported {kind}(s) with no "
            f"android:permission: {', '.join(names)}",
            "Any app on the device can invoke these components "
            "directly, bypassing the app's own UI flow.",
            "Unauthorized feature invocation; for providers, "
            "possible read/write access to app data.",
            "Set exported=\"false\" where external access is "
            "not required, or protect with a signature-level "
            "permission.",
            "Launcher activities and share/deep-link targets "
            "are exported by design; verify each listed "
            "component's intent before treating as a defect.",
            verification_status="CONFIRMED")
    dangerous = [p["name"] for p in perms.get("permissions", [])
                 if p.get("group") == "dangerous"]
    if dangerous:
        findings.add(
            "Dangerous-permission surface", "low", "high",
            "permissions", manifest,
            f"{len(dangerous)} dangerous permission(s): "
            f"{', '.join(dangerous[:12])}",
            "Dangerous permissions expand the data the app can "
            "reach if compromised or misused.",
            "Wider blast radius for any other defect.",
            "Remove permissions the features do not strictly "
            "need; request at runtime only.",
            "Most such permissions are legitimate for the "
            "app's stated features; this is a review prompt, "
            "not a defect by itself.",
            verification_status="POTENTIAL")
    target_sdk = perms.get("target_sdk")
    if isinstance(target_sdk, int) and target_sdk < 31:
        findings.add(
            "Outdated target SDK", "low", "high",
            "application", manifest,
            f"targetSdkVersion {target_sdk} (nar-perms)",
            "Older target levels keep legacy platform "
            "behaviors (storage, permissions, component "
            "export defaults) in force.",
            "Weaker platform security defaults apply.",
            "Raise targetSdkVersion and adopt the current "
            "behavior changes.",
            "", verification_status="CONFIRMED")
    min_sdk = perms.get("min_sdk")
    if isinstance(min_sdk, int) and min_sdk < 23:
        findings.add(
            "Very low minimum SDK", "informational", "high",
            "application", manifest,
            f"minSdkVersion {min_sdk} (nar-perms)",
            "Devices below API 23 lack runtime permissions "
            "and several platform protections.",
            "Install-time permission grants on old devices.",
            "Raise minSdkVersion if the user base allows.",
            "", verification_status="CONFIRMED")
    schemes = triage.get("signature_schemes") or {}
    if schemes.get("v1") and not (schemes.get("v2")
                                  or schemes.get("v3")):
        findings.add(
            "v1-only APK signature", "medium", "high",
            "signing", "META-INF/",
            "apksigner: v1 verified, v2/v3 absent "
            "(nar-triage signature_schemes)",
            "JAR-only (v1) signing is exposed to the Janus "
            "class of issues on Android 5.0-8.0 devices.",
            "Modified DEX could be accepted on old devices.",
            "Sign with v2 (and v3 where supported) in "
            "addition to v1.",
            "", verification_status="CONFIRMED")
    if network:
        sensitive = [e for e in network.get("endpoints", [])
                     if e["classification"] == "sensitive"]
        for e in sensitive[:5]:
            findings.add(
                "Sensitive material in endpoint URL", "high",
                "medium", "network", ", ".join(
                    e.get("sources") or ["strings"]),
                f"endpoint classified sensitive: {e['url'][:160]}",
                "Credentials or tokens embedded in URLs leak "
                "through logs, proxies, and analytics.",
                "Credential disclosure.",
                "Move secrets to headers over HTTPS; rotate "
                "any exposed credential.",
                "Some flagged URLs are format templates, not "
                "live credentials; verify before rotating.",
                verification_status="STRONGLY_INDICATED")
        cleartext = [e for e in network.get("endpoints", [])
                     if e["classification"] == "dex-string"
                     and e["url"].startswith("http://")]
        if cleartext:
            findings.add(
                "Cleartext HTTP endpoints in code", "medium",
                "high", "network", "DEX string tables",
                f"{len(cleartext)} DEX-string http:// endpoint"
                f"(s), e.g. {cleartext[0]['url'][:120]}",
                "Cleartext traffic can be read and modified "
                "on the network path.",
                "Data interception and tampering.",
                "Use HTTPS everywhere; set "
                "cleartextTrafficPermitted=\"false\".",
                "Endpoints may be dead code or redirected to "
                "HTTPS by the server; runtime confirmation "
                "needs a device.",
                verification_status="STRONGLY_INDICATED")
        nsc = network.get("network_security_config") or {}
        if nsc.get("uses_cleartext_traffic") is True or \
                nsc.get("base_cleartext_permitted") is True:
            findings.add(
                "Cleartext traffic permitted by configuration",
                "medium", "high", "network",
                nsc.get("nsc_file", manifest),
                "network security config / manifest permits "
                "cleartext traffic",
                "The app opts out of the platform cleartext "
                "ban.",
                "Interception exposure for any http traffic.",
                "Permit cleartext only for named legacy "
                "domains that require it.", "",
                verification_status="CONFIRMED")
    protections = triage.get("protections") or {}
    prot_text = json.dumps(protections).lower()
    if "pinning" in prot_text or "certificate pinning" in prot_text:
        positives.append("certificate pinning evidence present "
                         "(triage protections)")
    if "root" in prot_text:
        positives.append("root-detection client code present "
                         "(triage protections; client-side only)")
    if schemes.get("v2") or schemes.get("v3"):
        positives.append("modern APK signature scheme (v2/v3) "
                         "verified")
    if app.get("debuggable") is False:
        positives.append("debuggable explicitly disabled")
    if deep:
        dex = run_json_tool("nar-dex.py", [target])
        if dex is None:
            skipped.append(
                "deep DEX checks (dynamic code loading, "
                "WebView bridges) skipped: nar-dex.py did "
                "not return a result")
        if dex:
            loaders = set()
            js_bridge = False
            for d in dex.get("dex_files", []):
                loaders.update(
                    d.get("reflection", {}).get(
                        "loader_types_present", []))
                # nar-dex emits compact call edges by
                # default since 3.0; expand_call_edges
                # reads both shapes identically.
                for edge in dexlib.expand_call_edges(d):
                    if edge.get("to_method") == \
                            "addJavascriptInterface":
                        js_bridge = True
            dynamic = [t for t in loaders
                       if "DexClassLoader" in t
                       or "InMemoryDexClassLoader" in t
                       or "PathClassLoader" in t]
            if dynamic:
                findings.add(
                    "Dynamic code loading present", "medium",
                    "high", "dex", "classes.dex",
                    f"class-loader types referenced: "
                    f"{', '.join(dynamic)}",
                    "Code loaded at runtime escapes static "
                    "review and store scanning.",
                    "Downloaded code execution if the source "
                    "is not authenticated.",
                    "Avoid dynamic loading; if required, load "
                    "only signature-verified code over HTTPS.",
                    "Many frameworks (plugins, hotfix, game "
                    "engines) load code legitimately.",
                    verification_status="STRONGLY_INDICATED")
            if js_bridge:
                findings.add(
                    "WebView JavaScript bridge exposed", "medium",
                    "medium", "dex", "classes.dex",
                    "addJavascriptInterface invoked from app "
                    "code (nar-dex call edges)",
                    "A JavaScript bridge exposes Java objects "
                    "to web content; hostile pages in the "
                    "WebView can call it.",
                    "Bridge method abuse from loaded web "
                    "content.",
                    "Expose the minimum bridge surface, gate "
                    "by origin, and never load untrusted "
                    "content in a bridged WebView.",
                    "The bridge may only serve first-party "
                    "bundled pages.",
                    verification_status="STRONGLY_INDICATED")
    report = {"tool": "nar-security", "version": "3.0.3",
              "target": os.path.abspath(target),
              "target_sha256": sha256_of(target),
              "findings": findings.items,
              "checks_skipped": skipped,
              "positive_observations": positives,
              "severity_counts": {
                  s: sum(1 for f in findings.items
                         if f["severity"] == s)
                  for s in ("critical", "high", "medium", "low",
                            "informational")}}
    if resolved is not None:
        report["container"] = resolved.container_block()
        resolved.cleanup()
    return report


def human(report):
    print(f"NAR security review: "
          f"{os.path.basename(report['target'])}")
    print("=" * 60)
    print(f"Severity counts: {report['severity_counts']}")
    for f in report["findings"]:
        print(f"- [{f['severity'].upper()}] {f['id']} "
              f"{f['title']} (confidence {f['confidence']}, "
              f"verification "
              f"{f.get('verification_status', 'UNVERIFIED')})")
        print(f"    evidence: {f['evidence'][:180]}")
        print(f"    remediation: {f['remediation'][:150]}")
    for pos in report["positive_observations"]:
        print(f"positive: {pos}")
    for skipped_check in report.get("checks_skipped", []):
        print(f"skipped: {skipped_check}")
    if not report["findings"]:
        print("No findings from the static rule set.")


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Structured security findings in the "
                    "section 9.5 schema from static evidence.")
    p.add_argument("target", help="path to the .apk file")
    p.add_argument("--json", action="store_true")
    p.add_argument("--deep", action="store_true",
                   help="add DEX-level checks (dynamic loading, "
                        "WebView bridges) via nar-dex")
    p.add_argument("--work", metavar="DIR",
                   help="work dir for the network NSC pass")
    args = p.parse_args(argv)
    try:
        report = review(args.target, args.deep, args.work)
    except (FileNotFoundError, RuntimeError) as e:
        print(f"nar-security: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        human(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
