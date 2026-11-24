"""narlib.investigation: deterministic investigation layer
(2.6.0 Phase 8, R-009 + R-020 investigation half).

Builds investigation.json, a case companion, from the
case's real stage data ONLY. It is rule-based and offline:
no external calls, no LLM, no invented entities. Every
class / endpoint / component / library named in the output
is copied from a stage document or the correlations
document, and every item carries an evidence reference
{stage, document, field_path}.

Sections:
- verified_facts: items lifted directly from findings /
  correlations / stage inventories, with evidence.
- unverified_findings: security findings whose own
  verification_status is UNVERIFIED (2.6.1 deep-audit
  remediation: they were previously reported inside
  verified_facts with the status merely preserved on the
  item — a finding that has not been verified does not
  belong under a "verified" heading).
- paths: prioritized next-step recommendations generated
  by explicit rules (each carries its rule id, triggering
  evidence and a confidence). A path is advice, not a fact.
- hypotheses: clearly separated, each labeled hypothesis
  with its basis and what would confirm / refute it.
- unknowns: material questions static data cannot answer.

The layer is optional: nar-analyze skips it when disabled
(--no-investigation or NAR_NO_INVESTIGATION /
NAR_DISABLE_INVESTIGATION) and works identically without
it. A builder failure is recorded by the caller as a stage
error and never fails the whole analysis.

Part of NAR (Nirous Android Reversing). Research by Bakr
Fayez. MIT License. See LICENSE in the repo root.
"""
import os


def investigation_disabled(environ=None):
    env = os.environ if environ is None else environ
    for key in ("NAR_NO_INVESTIGATION",
                "NAR_DISABLE_INVESTIGATION"):
        if str(env.get(key, "")).lower() in ("1", "true", "yes"):
            return True
    return False


def graph_disabled(environ=None):
    env = os.environ if environ is None else environ
    for key in ("NAR_NO_GRAPH", "NAR_DISABLE_GRAPH"):
        if str(env.get(key, "")).lower() in ("1", "true", "yes"):
            return True
    return False


def _ev(stage, document, field_path):
    return {"stage": stage, "document": document,
            "field_path": field_path}


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2,
              "low": 3, "informational": 4}


def build_investigation(dex_data=None, native_data=None,
                        perms_data=None, network_data=None,
                        security_data=None,
                        correlations_data=None,
                        engines_data=None, version="2.6.1"):
    facts, paths, hypotheses, unknowns = [], [], [], []
    unverified = []
    notes = []
    for label, data in (
            ("dex", dex_data), ("native", native_data),
            ("permissions", perms_data),
            ("network", network_data),
            ("security", security_data),
            ("correlations", correlations_data)):
        if data is None:
            notes.append(
                f"{label} stage data unavailable; rules "
                "depending on it did not run")

    # ---- facts: security findings, split by status -------
    # A finding whose verification_status is UNVERIFIED
    # (or absent, which defaults to UNVERIFIED) is
    # reported under unverified_findings, never as a
    # verified fact (2.6.1 deep-audit remediation).
    findings = (security_data or {}).get("findings") or []
    for i, f in enumerate(findings):
        item = {
            "fact": f.get("title"),
            "kind": "security_finding",
            "subject": f.get("affected_component"),
            "detail": f.get("evidence"),
            "verification_status": f.get(
                "verification_status", "UNVERIFIED"),
            "evidence": _ev(
                "security", "security-findings.json",
                f"findings[{i}]"),
        }
        if item["verification_status"] == "UNVERIFIED":
            unverified.append(item)
        else:
            facts.append(item)

    # ---- verified facts + paths from correlations --------
    corr = correlations_data or {}
    for i, e in enumerate(corr.get("jni_bindings") or []):
        status = e.get("status")
        if status == "matched":
            facts.append({
                "fact": "JNI binding matched between DEX "
                        "declaration and native export",
                "kind": "jni_binding", "subject": e.get("symbol"),
                "detail": f"{e.get('class')}.{e.get('method')}",
                "verification_status": e.get(
                    "verification_status"),
                "evidence": _ev("correlations",
                                "correlations.json",
                                f"jni_bindings[{i}]"),
            })
        elif status == "declaration-only":
            paths.append({
                "rule_id": "INV-JNI-DECL-ONLY",
                "priority": 3,
                "recommendation": (
                    "Check for dynamic JNI registration "
                    "(RegisterNatives) or a split/native "
                    "library not in this file for the "
                    "declared native method; static export "
                    "matching found no export."),
                "subject": e.get("symbol"),
                "confidence": "medium",
                "triggering_evidence": _ev(
                    "correlations", "correlations.json",
                    f"jni_bindings[{i}]"),
            })
            hypotheses.append({
                "label": "hypothesis",
                "statement": (
                    "The declared native method may be bound "
                    "dynamically at runtime rather than by a "
                    "static export."),
                "subject": e.get("symbol"),
                "basis": _ev("correlations",
                             "correlations.json",
                             f"jni_bindings[{i}]"),
                "confirm": "Runtime JNI observation showing "
                           "a RegisterNatives call for this "
                           "method, or the export appearing in "
                           "another split's native library.",
                "refute": "Exhaustive search of all splits' "
                          "native libraries and a runtime "
                          "trace with no registration for "
                          "this method.",
            })
        elif status == "export-only":
            paths.append({
                "rule_id": "INV-JNI-EXPORT-ONLY",
                "priority": 4,
                "recommendation": (
                    "Look for the declaring class in another "
                    "DEX file / split, or treat the export as "
                    "dead or library-internal surface."),
                "subject": e.get("symbol"),
                "confidence": "low",
                "triggering_evidence": _ev(
                    "correlations", "correlations.json",
                    f"jni_bindings[{i}]"),
            })

    for i, e in enumerate(corr.get("components") or []):
        status = e.get("status")
        if status == "matched":
            facts.append({
                "fact": "Component declared in the manifest "
                        "and implemented in DEX",
                "kind": "component", "subject": e.get("component"),
                "detail": e.get("kind"),
                "verification_status": e.get(
                    "verification_status"),
                "evidence": _ev("correlations",
                                "correlations.json",
                                f"components[{i}]"),
            })
        elif status in ("declaration-only",
                        "implementation-only"):
            paths.append({
                "rule_id": "INV-COMPONENT-ONE-SIDED",
                "priority": 3,
                "recommendation": (
                    "Reconcile the one-sided component: "
                    "check other DEX files / splits for the "
                    "missing side before treating it as "
                    "absent."),
                "subject": e.get("component"),
                "confidence": "medium",
                "triggering_evidence": _ev(
                    "correlations", "correlations.json",
                    f"components[{i}]"),
            })

    for i, e in enumerate(corr.get("endpoints") or []):
        if e.get("status") == "code-referenced":
            facts.append({
                "fact": "Endpoint is referenced from code",
                "kind": "endpoint", "subject": e.get("url"),
                "detail": ", ".join(
                    e.get("referencing_classes") or []),
                "verification_status": e.get(
                    "verification_status"),
                "evidence": _ev("correlations",
                                "correlations.json",
                                f"endpoints[{i}]"),
            })
        elif e.get("status") == "no-code-reference":
            paths.append({
                "rule_id": "INV-ENDPOINT-NO-CODE-REF",
                "priority": 3,
                "recommendation": (
                    "Follow up the endpoint in bundles, "
                    "assets and string pools: it was found "
                    "by the network stage but no DEX string "
                    "reference joins it to code."),
                "subject": e.get("url"),
                "confidence": "medium",
                "triggering_evidence": _ev(
                    "correlations", "correlations.json",
                    f"endpoints[{i}]"),
            })

    for i, e in enumerate(
            corr.get("network_libraries") or []):
        if e.get("status") == "library-only":
            paths.append({
                "rule_id": "INV-NETLIB-LIBRARY-ONLY",
                "priority": 4,
                "recommendation": (
                    "Confirm whether the network library is "
                    "actually used: it was detected by the "
                    "network stage but no matching classes "
                    "were found in DEX."),
                "subject": e.get("library"),
                "confidence": "low",
                "triggering_evidence": _ev(
                    "correlations", "correlations.json",
                    f"network_libraries[{i}]"),
            })

    # ---- rule: exported component without permission -----
    # Source of truth is the permissions stage document
    # itself (exported + permission fields), not a summary.
    if perms_data:
        for kind, items in (
                (perms_data.get("components") or {}).items()):
            for i, item in enumerate(items or []):
                if item.get("exported") and not item.get(
                        "permission"):
                    paths.append({
                        "rule_id": "INV-EXPORTED-NO-PERMISSION",
                        "priority": 1,
                        "recommendation": (
                            "Confirm at runtime whether the "
                            "exported component can be invoked "
                            "by another app without a "
                            "permission check, and review its "
                            "intent handling."),
                        "subject": item.get("name"),
                        "confidence": "high",
                        "triggering_evidence": _ev(
                            "permissions", "permissions.json",
                            f"components.{kind}[{i}]"),
                    })
                elif item.get("exported") and item.get(
                        "permission"):
                    facts.append({
                        "fact": "Exported component is guarded "
                                "by a declared permission",
                        "kind": "component",
                        "subject": item.get("name"),
                        "detail": item.get("permission"),
                        "verification_status": "CONFIRMED",
                        "evidence": _ev(
                            "permissions", "permissions.json",
                            f"components.{kind}[{i}]"),
                    })

    # ---- rule: findings drive priority paths -------------
    for i, f in enumerate(findings):
        sev = f.get("severity")
        if sev in ("critical", "high", "medium"):
            paths.append({
                "rule_id": "INV-FINDING-FOLLOWUP",
                "priority": 1 if sev == "critical" else
                2 if sev == "high" else 3,
                "recommendation": (
                    "Follow up this security finding: "
                    "verify it against the cited evidence "
                    "and apply or rebut its remediation."),
                "subject": f.get("affected_component"),
                "confidence": f.get("confidence") or "low",
                "triggering_evidence": _ev(
                    "security", "security-findings.json",
                    f"findings[{i}]"),
            })

    # ---- rule: cleartext / network posture ---------------
    if network_data:
        nsc = network_data.get("network_security_config") or {}
        if nsc.get("uses_cleartext_traffic") or nsc.get(
                "base_cleartext_permitted"):
            paths.append({
                "rule_id": "INV-CLEARTEXT",
                "priority": 2,
                "recommendation": (
                    "Review cleartext traffic posture at "
                    "runtime: static config permits "
                    "cleartext; confirm which endpoints "
                    "actually use it."),
                "subject": "network_security_config",
                "confidence": "medium",
                "triggering_evidence": _ev(
                    "network", "endpoints.json",
                    "network_security_config"),
            })

    # ---- unknowns: always-honest static limits -----------
    unknowns.append({
        "question": "What does the application do at "
                    "runtime (actual network calls, dynamic "
                    "code loading, runtime JNI registration)?",
        "reason": "Static stage data cannot observe "
                  "execution; this requires an authorized "
                  "runtime session.",
        "evidence": _ev("investigation",
                        "investigation.json", "unknowns"),
    })
    if corr.get("jni_bindings") and any(
            e.get("status") == "declaration-only"
            for e in corr["jni_bindings"]):
        unknowns.append({
            "question": "Are the declaration-only native "
                        "methods bound dynamically?",
            "reason": "RegisterNatives binding is a runtime "
                      "event; static exports cannot settle "
                      "it.",
            "evidence": _ev("correlations",
                            "correlations.json", "jni_bindings"),
        })
    if network_data and (network_data.get("endpoints")):
        unknowns.append({
            "question": "Which statically found endpoints "
                        "are contacted in real use, with what "
                        "payloads?",
            "reason": "Endpoint presence in static data is "
                      "not evidence of a runtime call.",
            "evidence": _ev("network", "endpoints.json",
                            "endpoints"),
        })

    paths.sort(key=lambda p: (p["priority"], p["rule_id"],
                              str(p.get("subject"))))
    for idx, p in enumerate(paths):
        p["rank"] = idx + 1

    return {
        "tool": "nar-analyze", "version": version,
        "kind": "investigation",
        "method": "deterministic-offline-rules",
        "verified_facts": facts,
        "unverified_findings": unverified,
        "paths": paths,
        "hypotheses": hypotheses,
        "unknowns": unknowns,
        "counts": {
            "verified_facts": len(facts),
            "unverified_findings": len(unverified),
            "paths": len(paths),
            "hypotheses": len(hypotheses),
            "unknowns": len(unknowns),
        },
        "notes": notes + [
            "Paths are rule-generated recommendations, not "
            "facts. Hypotheses are labeled as such and are "
            "never merged into verified_facts. Security "
            "findings whose verification status is "
            "UNVERIFIED are reported under "
            "unverified_findings, not as verified facts."],
    }


def summarize_investigation(doc):
    """Small CLI summary view of an investigation doc."""
    doc = doc or {}
    return {
        "tool": doc.get("tool", "nar-analyze"),
        "version": doc.get("version"),
        "kind": "investigation",
        "counts": doc.get("counts") or {},
        "top_paths": (doc.get("paths") or [])[:10],
        "verified_facts": doc.get("verified_facts") or [],
        "unverified_findings":
            doc.get("unverified_findings") or [],
        "hypotheses": doc.get("hypotheses") or [],
        "unknowns": doc.get("unknowns") or [],
    }
