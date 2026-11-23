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
5. the workspace tools tree (`~/workspace/tools/<name>`).

A probe returns `{available, path, version, note}` — the
version is read from the tool itself (`--version`-style
output) wherever the tool supports it.

## Rules

- A module that needs a tool probes the registry first and
  degrades to an explicit note when the tool is absent. It
  never fabricates the missing tool's output.
- Tools that are not installed in the build environment
  (Il2CppInspector, AssetRipper, UABEA, FModel, UAssetAPI,
  UnrealPak, CFR, Procyon, dex2jar) are registered
  with kind `unavailable` and an honest limitation line.
  Registering a tool is not claiming it ran.
- Optional Python modules (UnityPy, androguard) are probed
  by import; absence is a documented degradation, not an
  error. UnityPy powers the optional bundle census in
  `nar-unity.py` when the running interpreter provides it.
- `nar-doctor.sh` remains the human-facing environment
  check; the registry is its machine-readable counterpart
  for the 2.0 modules.
