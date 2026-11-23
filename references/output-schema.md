# Output schema

NAR 2.0 evidence outputs are standardized JSON documents.
Their schemas live in `schemas/` (draft-07, written to the
subset the built-in validator in `narlib.evidence` checks).

## The case directory (nar-analyze output)

| File | Schema | Content |
|---|---|---|
| `report.json` | report | identity, 1.x sections, 2.0 stage summaries, limitations |
| `report.md` | — | the human report (1.x format, preserved) |
| `report.html` | — | offline dashboard (nar-report.py) |
| `fingerprint.json` | fingerprint | every property with provenance + confidence + fact class |
| `engines.json` | engine | verdicts with indicators and scores |
| `endpoints.json` | endpoints | classified endpoint inventory, hosts, services |
| `security-findings.json` | security-findings | findings in the §9.5 shape (below) |
| `assets.json` | assets | full asset inventory with hashes and duplicates |
| `dex.json`, `dex/classes.json`, `dex/methods.json` | — | DEX intelligence + enumeration companions |
| `native.json` | — | ELF facts, JNI map, dependency graph |
| `case.json` | case | case id, input hash, stage states, tool versions |
| `execution-log.json` | execution-log | one entry per tool run: stage, status, duration |
| `cache/` | — | per-stage cached documents + keys (resume) |

## Security finding shape (§9.5)

`{id: "NAR-SEC-NNN", title, severity (critical|high|medium|
low|informational), confidence, affected_component,
file_path, evidence, explanation, potential_impact,
reproduction, remediation, false_positive_considerations}` —
built by `narlib.evidence.make_finding`, which rejects
severities/confidences outside the vocabularies.

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
