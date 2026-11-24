# Tool registry

`scripts/registry.json` is the machine-readable capability
registry: every tool NAR can orchestrate, declared once with
its kind (cli / jar / dotnet / python-module / unavailable),
whether it is required, the platforms it serves, the input
formats and engines it applies to, how to find it, and its
known limitations.

## How discovery works

`narlib.registry.probe()` resolves a tool in this order:

1. `NAR_<NAME>_PATH` environment override,
2. the tool's declared environment variable (e.g. `JAVA_HOME`
   style entries where applicable),
3. PATH lookup,
4. Android SDK candidates (build-tools / platform-tools),
   for entries marked as SDK tools,
5. the entry's declared `workspace_subdirs` under
   `~/workspace/` (for example `tools/jadx-cli/bin`).

The registry currently declares 35 tools; 9 of them carry
kind `unavailable` (see the rules below). The same 35 names,
kinds, and required levels are what
`python3 scripts/nar.py tools --json` reports (it probes
this registry through `narlib.registry`).

A probe returns `{available, path, version, note}` — the
version is read from the tool itself (`--version`-style
output) wherever the tool supports it.

To see the whole registry with live probe results on the
current machine, run `nar tools` (or
`python3 scripts/nar-tools.py`; `--json` for the
machine-readable view, `--available` to list only what
probed present). It is a view, not a gate: readiness
verdicts live in the doctor.

## Rules

- A module that needs a tool probes the registry first and
  degrades to an explicit note when the tool is absent. It
  never fabricates the missing tool's output.
- Tools that are not installed in the build environment
  (Il2CppInspector, AssetRipper, UABEA, FModel, UAssetAPI,
  UnrealPak, CFR, Procyon, dex2jar) are registered
  with kind `unavailable` and an honest limitation line.
  Registering a tool is not claiming it ran.
- Unreal package inspection does not depend on the
  unavailable tools above: `narlib/uasset.py` implements
  the documented package layout directly (summary, name /
  import / export / depends tables, best-effort property
  tags). FModel/UAssetAPI stay registered `unavailable`;
  class-specific export data decoding remains out of
  scope for the built-in parser.
- Optional Python modules (UnityPy, androguard) are probed
  by import; absence is a documented degradation, not an
  error. UnityPy powers the optional bundle census in
  `nar-unity.py` when the running interpreter provides it.
- `nar-doctor.sh` remains the human-facing environment
  check; the registry is its machine-readable counterpart
  for the 2.0 modules.
