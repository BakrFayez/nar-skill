"""Common evidence/result schema and a stdlib structural
validator for the schemas in schemas/.

Every 2.0 module result is an envelope:

    {module, tool, tool_version, source, timestamp, status,
     confidence, fact_class, evidence[], data{}}

- status: one of narlib.RESULT_STATUSES
- fact_class: observed | derived | inferred | hypothesis |
  unknown (brief section 13: an inference is never presented
  as an observed fact)
- evidence: [{kind, location, detail}] — file paths, entry
  names, offsets, class:method names.

Security findings follow the brief section 9.5 field list and
are built with make_finding(). Findings also carry a
verification_status from narlib.VERIFICATION_STATUSES
(Evolution Phase 6/8): how the finding was verified, kept
separate from the analyst confidence in the underlying
observation.
"""
import datetime
import re

from . import (CONFIDENCE_LEVELS, FACT_CLASSES, RESULT_STATUSES,
               VERIFICATION_STATUSES)

SEVERITIES = ("critical", "high", "medium", "low",
              "informational")


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec="seconds")


def verification_for_fact_class(fact_class):
    """Map a fact class to the verification status it can
    honestly carry (Evolution Phase 8): a directly observed
    fact is CONFIRMED; a derived one is STRONGLY_INDICATED
    (computed from observations, not itself observed); an
    inference or hypothesis is POTENTIAL at best; an
    unknown is UNVERIFIED. CONTRADICTED is never assigned
    by mapping — it is set explicitly where two checks
    disagree."""
    return {"observed": "CONFIRMED",
            "derived": "STRONGLY_INDICATED",
            "inferred": "POTENTIAL",
            "hypothesis": "POTENTIAL",
            "unknown": "UNVERIFIED"}.get(fact_class, "UNVERIFIED")


def make_result(module, tool, tool_version, source, data,
                status="ok", confidence="high",
                fact_class="observed", evidence=None):
    if status not in RESULT_STATUSES:
        raise ValueError(f"bad status: {status}")
    if confidence not in CONFIDENCE_LEVELS:
        raise ValueError(f"bad confidence: {confidence}")
    if fact_class not in FACT_CLASSES:
        raise ValueError(f"bad fact_class: {fact_class}")
    return {
        "module": module,
        "tool": tool,
        "tool_version": tool_version,
        "source": source,
        "timestamp": now_iso(),
        "status": status,
        "confidence": confidence,
        "fact_class": fact_class,
        "evidence": evidence or [],
        "data": data,
    }


def make_finding(finding_id, title, severity, confidence,
                 component, file_path, evidence, explanation,
                 impact, remediation, reproduction="static",
                 false_positives="",
                 verification_status="UNVERIFIED"):
    """One security finding in the brief section 9.5 schema.

    verification_status (narlib.VERIFICATION_STATUSES) states
    how the finding was verified: a fact read directly from
    the target is CONFIRMED; a conclusion drawn from
    classified patterns is STRONGLY_INDICATED at best; a
    review prompt is POTENTIAL. The default is UNVERIFIED —
    a finding never claims verification its producer did
    not perform."""
    if severity not in SEVERITIES:
        raise ValueError(f"bad severity: {severity}")
    if confidence not in CONFIDENCE_LEVELS:
        raise ValueError(f"bad confidence: {confidence}")
    if verification_status not in VERIFICATION_STATUSES:
        raise ValueError(
            f"bad verification_status: {verification_status}")
    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "verification_status": verification_status,
        "affected_component": component,
        "file_path": file_path,
        "evidence": evidence,
        "explanation": explanation,
        "potential_impact": impact,
        "reproduction": reproduction,
        "remediation": remediation,
        "false_positive_considerations": false_positives,
    }


# ----------------------------------------------------------------
# Minimal structural JSON-Schema validator (stdlib only).
# Supports the subset the schemas in schemas/ use: type,
# required, properties, items, enum, pattern, minimum, maximum,
# additionalProperties=false, and local $ref (#/definitions/...).
# It is a structural checker, not a full JSON-Schema engine.
# ----------------------------------------------------------------

def _type_ok(value, type_name):
    return {
        "object": lambda v: isinstance(v, dict),
        "array": lambda v: isinstance(v, list),
        "string": lambda v: isinstance(v, str),
        "integer": lambda v: isinstance(v, int)
        and not isinstance(v, bool),
        "number": lambda v: isinstance(v, (int, float))
        and not isinstance(v, bool),
        "boolean": lambda v: isinstance(v, bool),
        "null": lambda v: v is None,
    }[type_name](value)


def validate(instance, schema, root_schema=None, path="$"):
    """Return a list of violation strings ([] means valid)."""
    root_schema = root_schema if root_schema is not None else schema
    errors = []
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/definitions/"):
            return [f"{path}: unsupported $ref {ref}"]
        name = ref.split("/")[-1]
        target = (root_schema.get("definitions") or {}).get(name)
        if target is None:
            return [f"{path}: unresolved $ref {ref}"]
        return validate(instance, target, root_schema, path)
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} not in enum")
    type_name = schema.get("type")
    if type_name:
        types = type_name if isinstance(type_name, list) else [type_name]
        if not any(_type_ok(instance, t) for t in types):
            errors.append(f"{path}: expected type {type_name}")
            return errors
    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{path}: missing required {key}")
        props = schema.get("properties", {})
        for key, subschema in props.items():
            if key in instance:
                errors += validate(instance[key], subschema,
                                   root_schema, f"{path}.{key}")
        if schema.get("additionalProperties") is False:
            for key in instance:
                if key not in props:
                    errors.append(f"{path}: unexpected key {key}")
    if isinstance(instance, list) and "items" in schema:
        for i, item in enumerate(instance):
            errors += validate(item, schema["items"], root_schema,
                               f"{path}[{i}]")
    if isinstance(instance, str) and "pattern" in schema:
        if not re.search(schema["pattern"], instance):
            errors.append(f"{path}: does not match pattern")
    if isinstance(instance, (int, float)) \
            and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path}: below minimum")
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"{path}: above maximum")
    return errors
