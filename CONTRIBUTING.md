# Contributing to NAR

NAR is a small skill. Keep contributions small and tested.

## What fits here

- A new reference guide for an Android reversing topic the skill does not cover yet.
- A fix to a guide: a wrong flag, an outdated version, a missing step.
- A script improvement, with a test run against a real APK in the PR description.

## Rules

- Test every script change against a real APK before opening a PR. Paste the command and its output in the PR.
- Test every command you add to a guide. Run it. Do not write flags from memory.
- Keep the writing plain and direct. Short sentences. Concrete steps. No filler.
- No cracking content. Nothing that bypasses signature checks, unlocks paid features, grants paid currency, bypasses DRM, or repackages someone else's app. PRs that add any of that will be closed.
- No binaries in the repo. No APKs, AABs, OBBs, keystores, or signing keys. The `.gitignore` blocks most of these. Check `git status` before you commit.

## How to propose a change

1. Fork the repo and create a branch.
2. Make the change. Update the README or SKILL.md routing table if you add a guide.
3. Run the checks: `bash scripts/nar-doctor.sh` and `python3 scripts/nar-triage.py <your-test-apk>` (plain and `--json`). If you touched a script, run that script too (`nar-strings.py`, `nar-compare.py`, `nar-perms.py`) with `--help` and on a real APK.
4. Open a PR with a short description of what changed and what you tested it against.

Questions: open an issue, or reach Bakr at https://t.me/BakrFayez.
