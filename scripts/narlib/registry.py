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
import sys

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
                resolved = _resolve_executable(cand)
                if resolved:
                    return resolved
        cand = os.path.join(root, "platform-tools", name)
        resolved = _resolve_executable(cand)
        if resolved:
            return resolved
    return None


_JAVA_HOME_GLOBS = ("workspace/jdk-*/bin/java",
                    "workspace/tools/rea-engines/jdk*/bin/java",
                    "/usr/lib/jvm/*/bin/java")


def _child_env():
    """Environment for version probes: when JAVA_HOME is
    unset, point it at the first JDK the doctor's own
    discovery would find, so Java-launched tools (jadx,
    apktool jars) can start during their probe exactly as
    they do under the doctor (which puts the found JDK on
    PATH for its later checks)."""
    env = dict(os.environ)
    if not env.get("JAVA_HOME"):
        home = os.path.expanduser("~")
        for pattern in _JAVA_HOME_GLOBS:
            full = pattern if os.path.isabs(pattern) \
                else os.path.join(home, pattern)
            for cand in sorted(glob.glob(full)):
                if _executable_file(cand):
                    env["JAVA_HOME"] = os.path.dirname(
                        os.path.dirname(cand))
                    return env
    return env


def _find_java():
    """java for launching jar tools: PATH, then JAVA_HOME,
    then the doctor's JDK globs (D-04)."""
    found = shutil.which("java")
    if found:
        return found
    home_var = os.environ.get("JAVA_HOME")
    if home_var:
        cand = os.path.join(home_var, "bin", "java")
        resolved = _resolve_executable(cand)
        if resolved:
            return resolved
    home = os.path.expanduser("~")
    for pattern in _JAVA_HOME_GLOBS:
        full = pattern if os.path.isabs(pattern) \
            else os.path.join(home, pattern)
        for cand in sorted(glob.glob(full)):
            resolved = _resolve_executable(cand)
            if resolved:
                return resolved
    return None


def _is_win32():
    # Read sys.platform at call time (not a cached constant)
    # so the platform branch is the one actually taken on
    # the running host — and so tests can simulate it.
    return sys.platform == "win32"


def _resolve_executable(path):
    """Resolve *path* to the file the platform would really
    execute, or None when the platform cannot execute it.

    POSIX: unchanged semantics — the path itself, iff it is
    a regular file with the execute bit (os.access X_OK).

    Windows: os.access(X_OK) is meaningless there (it only
    reflects the read-only flag, never executability), so
    resolution goes through shutil.which, which implements
    the platform's real rule: a path (or bare name) is
    executable only when it resolves — as given, or with a
    PATHEXT extension appended — to a real file. An
    extensionless shell script, a .txt file, or any other
    non-PATHEXT file therefore resolves to None, exactly as
    Windows itself would refuse to start it, while tool.exe
    / tool.bat / tool.cmd resolve to their real path (the
    .exe-suffixed path when the probe named it bare)."""
    if not path:
        return None
    if _is_win32():
        return shutil.which(path)
    return path if _executable_file(path) else None


def _executable_file(path):
    if _is_win32():
        return _resolve_executable(path) is not None
    return os.path.isfile(path) and os.access(path, os.X_OK)


def _found_file(path):
    """Existence test for env_var tool locations (a tool
    file under a pointed-at tree, e.g. support/<tool>).

    POSIX: unchanged — a plain regular file counts.
    Windows: the candidate names a tool, so it must be a
    genuinely executable file under PATHEXT resolution,
    not merely a file that exists."""
    if _is_win32():
        return _resolve_executable(path)
    return path if os.path.isfile(path) else None


def _invocation_argv(argv):
    """The argv a version probe must actually spawn.

    POSIX: argv unchanged. Windows: .bat/.cmd shims cannot
    be started by CreateProcess directly — Windows runs
    them through the command interpreter — so they are
    invoked as [COMSPEC, /c, <shim>, <args...>], which is
    also how the real .bat tool launchers this registry
    probes (e.g. jadx/apktool launchers) are started.
    Native executables (.exe/.com, the resolved form of
    every other candidate) run directly, unchanged."""
    argv = list(argv)
    if _is_win32() and argv:
        ext = os.path.splitext(str(argv[0]))[1].lower()
        if ext in (".bat", ".cmd"):
            comspec = os.environ.get("COMSPEC") or "cmd.exe"
            return [comspec, "/c"] + argv
    return argv


def _run_version(argv, timeout=20):
    """First output line of a version command — ONLY when
    the command exits 0. The pre-audit form returned the
    first line regardless of exit code, so a launcher's
    error banner ("ERROR: JAVA_HOME is not set…") was
    recorded as the tool's version and the tool probed
    available (stability audit D-03)."""
    try:
        proc = subprocess.run(_invocation_argv(argv),
                              capture_output=True, text=True,
                              timeout=timeout, env=_child_env())
        if proc.returncode != 0:
            return None
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
    if env_override:
        # On Windows this stores the PATHEXT-resolved path
        # (e.g. ...\tool.exe for a bare ...\tool override),
        # which is the path the version run below spawns.
        resolved = _resolve_executable(env_override)
        if resolved:
            path = resolved
    if not path and entry.get("env_var") \
            and os.environ.get(entry["env_var"]):
        base = os.environ[entry["env_var"]]
        for cand_name in entry.get("candidates", []):
            cand = os.path.join(base, "support", cand_name)
            found = _found_file(cand)
            if found:
                path = found
                break
        if not path:
            path = _found_file(base)
    if not path:
        for cand_name in entry.get("candidates", []):
            found = shutil.which(cand_name)
            if found:
                path = found
                break
    if not path and entry.get("env_home"):
        # Home-variable discovery (e.g. JAVA_HOME/bin/java),
        # mirroring nar-doctor.sh (stability audit D-04).
        home_var = os.environ.get(entry["env_home"])
        if home_var:
            for rel in entry.get("env_home_candidates", []):
                cand = os.path.join(home_var, rel)
                resolved = _resolve_executable(cand)
                if resolved:
                    path = resolved
                    break
    if not path and entry.get("home_globs"):
        home = os.path.expanduser("~")
        for pattern in entry["home_globs"]:
            full = pattern if os.path.isabs(pattern) \
                else os.path.join(home, pattern)
            for cand in sorted(glob.glob(full)):
                resolved = _resolve_executable(cand)
                if resolved:
                    path = resolved
                    break
            if path:
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
                resolved = _resolve_executable(cand)
                if resolved:
                    path = resolved
                    break
            if path:
                break
    if not path and entry.get("jar_env_var"):
        jar = os.environ.get(entry["jar_env_var"])
        if jar and os.path.isfile(jar):
            path = "jar:" + jar
    if not path and entry.get("jar_globs"):
        home = os.path.expanduser("~")
        for pattern in entry["jar_globs"]:
            full = pattern if os.path.isabs(pattern) \
                else os.path.join(home, pattern)
            hits = sorted(glob.glob(full))
            if hits:
                path = "jar:" + hits[-1]
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
    result["path"] = path
    argv = entry.get("version_argv")
    if argv:
        if path.startswith("jar:"):
            java = _find_java()
            if java:
                result["version"] = _run_version(
                    [java, "-jar", path[4:]] + argv)
        elif kind == "dotnet":
            result["version"] = None  # probed by execution instead
        else:
            result["version"] = _run_version([path] + argv)
    # Availability is a real-start claim, not a path
    # sighting (D-03): an entry with a version command is
    # available only when that command actually ran and
    # exited 0. Entries without one (e.g. adb, whose
    # validation is a devices probe) are available on an
    # executable path.
    if argv and kind != "dotnet" and result["version"] is None:
        result["note"] = (
            "found but its version command did not run "
            "successfully; not counted as available")
        return result
    min_major = entry.get("min_version_major")
    if min_major and result["version"]:
        m = re.search(r"(\d+)\.", result["version"])
        if m and int(m.group(1)) < min_major:
            result["note"] = (
                f"version {result['version']} is below "
                f"the required major {min_major}")
            result["version"] = None
            return result
    result["available"] = True
    return result


def launch_prefix(probe_result):
    """Command prefix that actually runs a probed tool.

    A probe path is a launch spec, not always an executable:
    a tool resolved through a jar route (jar_env_var /
    jar_globs / kind "jar") carries a "jar:"-prefixed path
    and must be launched as [java, -jar, <jar>]; every other
    path is an executable and runs directly. Returns the
    prefix list, or None when there is no path or a jar tool
    has no Java runtime to launch it. Consumers must build
    their argv from this prefix, never from the raw probe
    path (a "jar:..." string is not a file and spawning it
    fails with Errno 2)."""
    path = (probe_result or {}).get("path")
    if not path:
        return None
    if path.startswith("jar:"):
        java = _find_java()
        if not java:
            return None
        return [java, "-jar", path[4:]]
    return [path]


def probe_all(registry=None):
    registry = registry or load_registry()
    return [probe(e) for e in registry["tools"]]


def version_of(probe_result):
    """Best-effort short version token from a probe result."""
    raw = probe_result.get("version") or ""
    m = re.search(r"\d+\.\d+(?:\.\d+)?", raw)
    return m.group(0) if m else (raw[:40] or None)
