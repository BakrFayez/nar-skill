# Output schema

NAR evidence outputs are standardized JSON documents.
Their schemas live in `schemas/` (draft-07, written to the
subset the built-in validator in `narlib.evidence` checks).

## The case directory (nar-analyze output)

| File | Schema | Content |
|---|---|---|
| `report.json` | report | identity, 1.x sections, 2.0 stage summaries, limitations |
| `report.md` | — | the human report (1.x format, preserved) |
| `report.html` | — | offline dashboard (nar-report.py); when native.json carries a dependency graph, the dashboard renders it as an inline SVG section (deterministic layered layout, escaped labels, zero external references; graphs over 120 libraries are truncated with a note pointing at native.json) |
| `fingerprint.json` | fingerprint | every property with provenance + confidence + fact class |
| `engines.json` | engine | verdicts with indicators and scores |
| `endpoints.json` | endpoints | classified endpoint inventory, hosts, services |
| `security-findings.json` | security-findings | findings in the §9.5 shape (below) |
| `assets.json` | assets | full asset inventory with hashes and duplicates |
| `dex.json`, `dex/classes.json`, `dex/methods.json` | dex, dex-classes, dex-methods | DEX intelligence + enumeration companions (schemas added in 2.5.1) |
| `native.json` | native | ELF facts, JNI map, dependency graph (schema added in 2.5.1) |
| `case.json` | case | case id, input hash, stage states, tool versions |
| `execution-log.json` | execution-log | one entry per tool run: stage, status, duration |
| `cache/` | — | per-stage cached documents + keys (resume) |
| `application.json` | application | brief-named projection of the fingerprint's identity properties (provenance envelopes preserved) |
| `manifest.json` | manifest | brief-named projection of the permission audit: counts, groups, dangerous set, component counts, flags |
| `native-inventory.json` | native-inventory | brief-named projection of `native.json`: per-library identity/dependency facts, JNI library list, dependency graph |
| `frameworks.json` | frameworks | brief-named projection of the engine verdicts + fingerprint marker evidence |
| `network-analysis.json` | network-analysis | brief-named projection of `endpoints.json`: counts, hosts, libraries, services, cleartext posture, redaction counts |
| `api-architecture.json` | api-architecture | brief-named projection of `endpoints.json`: per-host API shape (kinds, classifications, sample paths — query strings dropped), endpoint-kind totals, services |

The brief-named companions are projections
(`"projected": true`), built by `narlib.companions` from
stage data the same run already computed — no stage re-runs
and nothing is re-derived. Each is validated against its
schema before it is written; when a source stage degraded,
the projection carries an explicit `unavailable` field
instead of an empty success document, and a projection that
fails validation is not written at all (the report records
a limitation instead).

Endpoint URLs are redacted at the source (nar-network):
credential values in sensitive query parameters and URL
userinfo are replaced with `REDACTED` before any document
is written, and `endpoints.json` reports the redaction
count under `redaction.endpoint_values_redacted`. Raw
credential values never appear in any case output.

## Security finding shape (§9.5)

`{id: "NAR-SEC-NNN", title, severity (critical|high|medium|
low|informational), confidence, affected_component,
file_path, evidence, explanation, potential_impact,
reproduction, remediation, false_positive_considerations}` —
built by `narlib.evidence.make_finding`, which rejects
severities/confidences outside the vocabularies. Findings
also carry `verification_status` (CONFIRMED |
STRONGLY_INDICATED | POTENTIAL | UNVERIFIED |
CONTRADICTED): how the finding was verified, kept separate
from confidence. The field is in the schema's properties
but deliberately not in its `required` list, so findings
written before it existed still validate; nar-security
always emits it (CONFIRMED only for facts read directly
off the target).

## Correlations

Case runs also emit `correlations.json` (schema:
schemas/correlations.schema.json): explicit cross-module
join records — DEX native declarations ↔ ELF JNI exports
(matched / declaration-only / export-only; the JNI
entries are also embedded in `native.json` and counted
in the report), manifest components ↔ DEX entry points,
endpoints ↔ the DEX classes that reference them, and
detected network libraries ↔ DEX class presence. A
declaration or endpoint seen in several places is one
entry (the document states the deduplication rule), and
every entry carries a `verification_status`.

## Orchestration budgets and case bundles

`nar-analyze --stage-timeout S --total-budget S` caps
stage runtimes; a stage stopped by a budget is recorded
in `execution-log.json` (and `case.json` stage states)
with status `budget-exceeded` — a recorded stop, never a
hang. The budgets used are recorded in the case config.
`nar-analyze --export CASE --bundle FILE`,
`--import FILE --out DIR`, and `--verify CASE` move a
case as a single archive with a per-file SHA-256
manifest; verify re-checks the recorded input hash, the
manifest, and the stage-cache integrity keys — a
tampered bundle fails verify.

## Runtime session records

`nar-runtime plan|status --session-out DIR` persists
`runtime-session.json` (schema:
schemas/runtime-session.schema.json) into a case
workspace: session id, flow kind, device identity and its
verification label carried unchanged, adb/frida probes,
start/stop times, the events the flow produced, evidence
paths, and errors. A record documents the flow — it never
upgrades the label: a session recorded with no device
attached still says IMPLEMENTED_BUT_UNVERIFIED.

## Endpoint classification

`confirmed` (referenced from DEX code), `potential` (native
strings only), `unused-candidate` (assets/resources only),
`third-party` (known SDK/service domain), `sensitive`
(credentials/auth material in the URL), `unverified` (no
parseable host). Static evidence only — a classification is
never a claim that traffic occurred.

## Validation

`narlib.evidence.validate(instance, schema)` performs the
structural check (type/required/properties/items/enum/
pattern/min-max/additionalProperties/local $ref). It is a
structural checker, not a full JSON-Schema engine, and says
so in its docstring.
