# Release guide

How a NAR version ships, distilled from the 2.x release
practice. Publication is always the owner's explicit
decision — preparation ends at a clean, verified,
release-ready tree.

## 1. Freeze and verify

- Working tree clean; every change committed on the
  release branch.
- Full battery, all green, counts recorded:
  - `~/workspace/nar2-venv/bin/python -m pytest tests/ -q`
  - `bash tests/run_e2e.sh` (with `NAR_FIXTURES`,
    `JAVA_HOME`, `TMPDIR` set as in the harness header)
  - `python3 scripts/nar.py doctor` → Core toolchain:
    READY
  - CLI smoke: every `nar <verb> --help` exits 0.
- The capability baseline (NAR_GAP_ANALYSIS.md) and the
  test matrix (NAR_TEST_MATRIX.md) carry the release's
  evidence addenda; the implementation plan carries the
  phase records.

## 2. Version bump

The version lives in **18 locations**, all guarded by
`tests/unit/test_docs_consistency.py` (it fails the
build if any two disagree):

- skill.yaml, SKILL.md frontmatter, pyproject.toml,
  README.md's Version line, .claude-plugin/plugin.json
- scripts/nar.py (fallback VERSION),
  scripts/narlib/__init__.py (__version__),
  scripts/nar-analyze.py (NAR_VERSION),
  scripts/registry.json (registry_version)
- the `"version"` field of nar-assets, nar-dex,
  nar-engines, nar-native, nar-network, nar-runtime,
  nar-security, nar-unity, nar-unreal

Bump only those fields. Historical mentions of older
versions in CHANGELOG.md, the plan, the gap analysis
and the test matrix are history — never rewrite them.
Test fixtures that carry a version string as *data*
(a synthetic case's recorded version, a fixture
argument) are not version-bearing locations either.
Re-run the docs-consistency tests after the bump.

## 3. Changelog discipline

- Move `## Unreleased`'s bullets under a new
  `## X.Y.Z (YYYY-MM-DD)` heading; leave a fresh empty
  `## Unreleased` above it.
- Bullets describe capabilities and fixes generically.
  Never name a tested app, package, file, or hash —
  findings are described by class, not by target.
- The only credit line anywhere in the project is
  "Research by Bakr Fayez".

## 4. Pre-push greps (zero hits required)

Over the full release diff:

- banned identifiers: any tested-app name, package,
  file name, or identifying hash;
- forbidden credits: any credit line other than the
  single allowed one.

## 5. Push

- Push with the GitHub tooling's push-files call:
  manifest = `git ls-files -z` **excluding
  `.github/workflows/*`** (the GitHub App has no
  workflows permission; the CI workflow file is
  maintained through the web UI).
- Verify the remote tree afterwards (read back
  skill.yaml and confirm the new version).
- Append the push to the local snapshot-sync record
  (file name, remote HEAD, version, date).

## 6. Package and release

- ZIP: `git archive HEAD --format=zip` from the
  release commit; record its size.
- GitHub Release is created through the web UI (the
  API toolset used for pushes has no release tool):
  tag `vX.Y.Z`, title `NAR vX.Y.Z`, notes from the
  CHANGELOG section, mark as Latest.
- Sync the installed skill copy
  (`~/workspace/custom-skills/nar/`) from the release
  tree and verify its skill.yaml matches.

## 7. After publication

- Confirm the release page shows the new version as
  Latest and the ZIP downloads.
- The next cycle's work starts under a fresh
  `## Unreleased`.
