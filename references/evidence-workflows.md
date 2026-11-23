# Evidence workflows

NAR findings are only as good as their evidence. This guide defines
the ledger format, the report template, and the confidence levels used
across all NAR reports.

## Observations, inferences, unknowns

Every statement in a report is one of three kinds. Label them:

- Observation: something directly seen in the artifact. "The manifest
  declares `android.permission.INTERNET`." "Method `login()` calls
  `HttpURLConnection.connect()`." Observations cite a file and a
  location.
- Inference: a conclusion drawn from observations. "The app contacts
  `api.example.com` at login." Inferences cite the observations they
  rest on, and stay open to revision.
- Unknown: something the evidence does not settle. "Whether the token
  is refreshed in the background is unknown: no scheduler or worker
  was found in the searched DEX files." Unknowns name the search
  boundary so they can be re-checked.

Never present an inference as an observation, and never let an unknown
vanish from the report. A report that hides its unknowns overclaims.

## Confidence levels

| Level | Meaning |
|---|---|
| High | Code read end to end, or behavior observed at runtime and anchored to code. |
| Medium | Entry points and key paths seen; internals partial or one link inferred. |
| Low | Inferred from strings, layout, or filenames only; code not traced. |

Confidence applies per finding, not per report. One report routinely
mixes High, Medium, and Low findings.

## Evidence ledger

Keep a running ledger during the investigation, one row per conclusion:

| # | Finding | Evidence | Confidence | Boundary / unknowns |
|---|---|---|---|---|
| 1 | Login uses email + password | `LoginActivity.java:42`, `POST /v1/login` in `strings.xml` | High | Token storage not traced |
| 2 | No analytics SDK | No analytics package in DEX class list; no analytics host in strings | Medium | Searched DEX + strings only; native libs not searched |

Update the ledger as you go. It is the source the final report is
written from, and the artifact a later pass reuses.

## Report template

```markdown
# NAR report: <App name> <version>

## Identity
- File: <name> (SHA-256: <hash>)
- Package: <package> v<versionName> (code <versionCode>)
- SDK: min <x> / target <y>
- Size: <bytes> | DEX: <n> file(s) | Native: <n> lib(s) (<ABIs>)
- Engine: <Unity IL2CPP / Unreal / Godot / none detected>
- Signature: <schemes present, signer fingerprint>

## Findings
### 1. <Finding title> (Confidence: High/Medium/Low)
- Observation: ...
- Evidence: <file:line / class:method / offset>
- Inference: ...

## Limitations and unknowns
- <What was not checked, and why>
- <What static analysis cannot prove here>

## Next steps
- <Concrete follow-up, with the guide that covers it>
```

A filled example is in [examples/sample-report.md](../examples/sample-report.md).

## Handling partial coverage

- Multi-DEX: state which DEX files were searched. "Searched
  `classes.dex` only" is a partial result when `classes2.dex` exists.
- Obfuscation: state that names are obfuscated and that findings rest
  on strings and structure.
- Native code: state which `.so` files were and were not analyzed.
  "Native libs inventoried, not decompiled" is a legitimate scope
  line.
- Split sets: state which splits were included. A report on the base
  APK alone must say so.
- Time-boxed searches: state the boundary ("first 200 grep hits",
  "searched `com.example.*` only") so a later pass knows where to
  continue.

## Digests and reproducibility

Record the SHA-256 of every APK, AAB, split, and OBB analyzed, and the
tool versions used (`apktool --version`, `jadx --version`, `aapt2
version`). A finding without a digest cannot be reproduced after the
app updates. Keep triage JSON output beside the report as the
machine-readable identity record.
