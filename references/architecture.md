# NAR 2.0 architecture

How the 2.0 system is put together, and where the full design
record lives (`docs/NAR_ARCHITECTURE.md`, with the
Phase Zero audit in `docs/NAR_AUDIT.md`).

## Layers

1. **Input layer** — `nar-input.py` + `narlib.formats` /
   `narlib.safearchive`: magic-and-structure identification
   for APK/APKS/XAPK/AAB/AAR/JAR/DEX/ODEX/VDEX/OBB/ELF and the
   engine containers; guarded extraction (traversal, absolute
   paths, symlinks, ratio/size/count bombs rejected per entry
   and reported, never silently skipped).
2. **Module layer** — one script per question (triage,
   fingerprint, engines, dex, native, perms, strings,
   network, security, assets, the engine deep dives). Every
   module runs standalone and emits JSON with `--json`.
   Shared parsing lives in `scripts/narlib/` (DEX parser, ELF
   parser, evidence envelope + finding builder, capability
   registry client).
3. **Orchestrator** — `nar-analyze.py` runs the 1.x workup
   plus the 2.0 stages into a **case workspace**: report.md /
   report.json / report.html, the companion documents,
   case.json, execution-log.json, and a stage cache keyed by
   input SHA-256 + stage + NAR version (re-runs resume;
   `--no-cache` forces fresh stages).
4. **Presentation** — `nar-report.py` renders the case as one
   offline HTML file (embedded data, dark/light, filterable
   tables; zero external references).

## Compatibility rule

1.x script CLIs and output fields are a compatibility
surface: 2.0 extends them in place (nar-compare gained an
`extended` section; nar-analyze gained stages and files) and
never removes or renames what 1.x produced.

## Fact discipline

Every emitted fact is one of: **observed** (read directly),
**derived** (computed from observed facts), or **inferred**
(reconstruction, labeled as such) — with provenance and a
confidence in the fingerprint and engine outputs. Statuses:
IMPLEMENTED_AND_TESTED, IMPLEMENTED_BUT_UNVERIFIED (device
work — no device in the build environment), PARTIALLY_
IMPLEMENTED, MISSING, BROKEN, NOT_APPLICABLE. The audit
documents at the repo root carry the per-feature status.
