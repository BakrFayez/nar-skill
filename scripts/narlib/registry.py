"""Reader + prober for scripts/registry.json.

Discovery mirrors the project's established rules (the same
ones nar-doctor.sh uses): explicit environment override
NAR_<NAME>_PATH / the tool's own env_var, then PATH, then SDK
locations for SDK tools, then the conventional
$HOME/workspace/tools layout. Nothing machine-specific is
hardcoded: every location is derived from $HOME, $PATH,
$ANDROID_HOME, or an explicit override.
"""
import glob
import importlib.util
import json
import os
import re
import shutil
import subprocess

REGISTRY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "..", "registry.json")


def load_registry(path=None):
    with open(path or REGISTRY_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _sdk_candidates():
    roots = [os.environ.get("ANDROID_HOME"),
             os.environ.get("ANDROID_SDK_ROOT"),
             os.path.expanduser("~/Android/Sdk"),
             os.path.expanduser("~/workspace/android-sdk"),
             os.path.expanduser("~/android-sdk"),
             "/opt/android-sdk", "/usr/lib/android-sdk"]
    return [r for r in roots if r]


def _find_sdk_tool(name):
    for root in _sdk_candidates():
        bt = os.path.join(root, "build-tools")
        if os.path.isdir(bt):
            for ver in sorted(os.listdir(bt), reverse=True):
                cand = os.path.join(bt, ver, name)
                if os.path.isfile(cand) and os.access(cand, os.X_OK):
                    return cand
        cand = os.path.join(root, "platform-tools", name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def _run_version(argv, timeout=20):
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout)
        out = (proc.stdout or "") + (proc.stderr or "")
        lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
        return lines[0] if lines else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def probe(entry):
    """Probe one registry entry.

    Returns {name, available, path, version, kind, required,
    note}. available=False is a normal result, never an error.
    """
    result = {"name": entry["name"], "kind": entry["kind"],
              "required": entry.get("required", "optional"),
              "available": False, "path": None, "version": None,
              "note": ""}
    kind = entry["kind"]
    if kind == "unavailable":
        result["note"] = "not integrated in this release (see registry)"
        return result
    if kind == "python-module":
        spec = importlib.util.find_spec(entry["module"])
        if spec is None:
            result["note"] = "python module not importable"
            return result
        result["available"] = True
        result["path"] = spec.origin
        try:
            mod = __import__(entry["module"])
            result["version"] = getattr(mod, "__version__", None)
        except Exception:  # import side effects are the module's
            result["version"] = None
        return result

    path = None
    env_override = os.environ.get(
        "NAR_" + entry["name"].upper().replace("-", "_") + "_PATH")
    if env_override and os.path.exists(env_override):
        path = env_override
    elif entry.get("env_var") and os.environ.get(entry["env_var"]):
        base = os.environ[entry["env_var"]]
        for cand_name in entry.get("candidates", []):
            cand = os.path.join(base, "support", cand_name)
            if os.path.isfile(cand):
                path = cand
                break
        if not path and os.path.isfile(base):
            path = base
    if not path:
        for cand_name in entry.get("candidates", []):
            found = shutil.which(cand_name)
            if found:
                path = found
                break
    if not path and entry.get("sdk_tool"):
        for cand_name in entry.get("candidates", []):
            path = _find_sdk_tool(cand_name)
            if path:
                break
    if not path and entry.get("workspace_subdirs"):
        home = os.path.expanduser("~")
        for sub in entry["workspace_subdirs"]:
            base = os.path.join(home, "workspace", sub)
            for cand_name in entry.get("candidates", []):
                cand = os.path.join(base, cand_name)
                if os.path.isfile(cand):
                    path = cand
                    break
            if path:
                break
    if not path and kind == "jar":
        home = os.path.expanduser("~")
        for sub in entry.get("workspace_subdirs", []):
            hits = glob.glob(os.path.join(home, "workspace", sub,
                                          entry.get("jar_glob", "")))
            if hits:
                path = "jar:" + sorted(hits)[-1]
                break
    if not path and kind == "dotnet":
        home = os.path.expanduser("~")
        for sub in entry.get("workspace_subdirs", []):
            cand = os.path.join(home, "workspace", sub,
                                entry.get("dll", ""))
            if os.path.isfile(cand):
                path = cand
                break
    if not path:
        result["note"] = "not found"
        return result
    result["available"] = True
    result["path"] = path
    argv = entry.get("version_argv")
    if argv:
        if kind == "jar" and path.startswith("jar:"):
            java = shutil.which("java")
            if java:
                result["version"] = _run_version(
                    [java, "-jar", path[4:]] + argv)
        elif kind == "dotnet":
            result["version"] = None  # probed by execution instead
        else:
            result["version"] = _run_version([path] + argv)
    return result


def probe_all(registry=None):
    registry = registry or load_registry()
    return [probe(e) for e in registry["tools"]]


def version_of(probe_result):
    """Best-effort short version token from a probe result."""
    raw = probe_result.get("version") or ""
    m = re.search(r"\d+\.\d+(?:\.\d+)?", raw)
    return m.group(0) if m else (raw[:40] or None)
