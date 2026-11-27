#!/usr/bin/env python3
"""nar: the unified NAR command line (brief section 15).

One entry point over every NAR module. Each subcommand is a
thin pass-through to the module's own script (which keeps
working standalone, exactly as in 1.x):

    nar doctor                 environment check
    nar tools [--json]         tool registry view (live probes)
    nar input SUBCMD ...       input identification / safe
                               extraction / duplicates
    nar identify FILE          format identification
                               (= nar input identify)
    nar validate FILE          structural validation
                               (= nar input validate)
    nar triage APP             first-look static triage
    nar fingerprint APP        provenance-tagged fingerprint
    nar engines APP [--deep]   engine verdicts with confidence
    nar unity APP              Unity deep dive
    nar unreal APP             Unreal deep dive
    nar il2cpp APP             IL2CPP metadata analysis
    nar flutter APP            Flutter fingerprint
    nar godot APP              Godot pack analysis
    nar rn APP                 React Native bundle analysis
    nar pak FILE               Unreal pak listing/extraction
    nar dex APP                DEX intelligence
    nar native APP             native/ELF intelligence
    nar perms APP              permission + component audit
    nar strings APP            categorized string scan
    nar network APP            static network intelligence
    nar security APP           structured security findings
    nar assets APP             asset inventory
    nar compare OLD NEW        version comparison
    nar analyze APP [--out D]  full orchestrated workup (case
                               workspace, companions, dashboard)
    nar report CASE_DIR        offline HTML dashboard
    nar case SUBCMD ...        case bundles: export / import /
                               verify (see nar case --help)
    nar benchmark [--out F]    measured module timings +
                               accuracy metrics on the local
                               fixture corpus
    nar runtime SUBCMD         runtime subsystem (status /
                               plan / timeline-template)
    nar coverage [--gap]       coverage matrix from
                               formats.json (Part 1/16)
    nar ask "Q" APP [--json]   question answering over a
                               case (Part 7 Answer Contract)
    nar blueprint APP          rebuild specification from
           [--out DIR]         verified evidence (Part 8:
                               9 files, cited claims)
    nar version                product identity + version

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import os
import posixpath
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
try:
    from narlib import __version__ as VERSION
except Exception:
    VERSION = "3.0.3"

# verb -> (kind, script, fixed prefix args). The prefix is how
# the alias verbs (identify / validate) reach the nar-input
# subcommands without a wrapper script.
COMMANDS = {
    "doctor": ("bash", "nar-doctor.sh", []),
    "tools": ("py", "nar-tools.py", []),
    "input": ("py", "nar-input.py", []),
    "identify": ("py", "nar-input.py", ["identify"]),
    "validate": ("py", "nar-input.py", ["validate"]),
    "triage": ("py", "nar-triage.py", []),
    "fingerprint": ("py", "nar-fingerprint.py", []),
    "engines": ("py", "nar-engines.py", []),
    "unity": ("py", "nar-unity.py", []),
    "unreal": ("py", "nar-unreal.py", []),
    "il2cpp": ("py", "nar-il2cpp.py", []),
    "flutter": ("py", "nar-flutter.py", []),
    "godot": ("py", "nar-godot.py", []),
    "rn": ("py", "nar-rn.py", []),
    "pak": ("py", "nar-pak.py", []),
    "dex": ("py", "nar-dex.py", []),
    "native": ("py", "nar-native.py", []),
    "perms": ("py", "nar-perms.py", []),
    "strings": ("py", "nar-strings.py", []),
    "network": ("py", "nar-network.py", []),
    "security": ("py", "nar-security.py", []),
    "assets": ("py", "nar-assets.py", []),
    "compare": ("py", "nar-compare.py", []),
    "analyze": ("py", "nar-analyze.py", []),
    "report": ("py", "nar-report.py", []),
    "benchmark": ("py", os.path.join(
        "..", "tests", "benchmarks", "run_benchmarks.py"), []),
    "runtime": ("py", "nar-runtime.py", []),
    "coverage": ("py", "nar-coverage.py", []),
    "ask": ("py", "nar-ask.py", []),
    "blueprint": ("py", "nar-blueprint.py", []),
    "atlas": ("py", "nar-atlas.py", []),
    "anim": ("py", "nar-anim.py", []),
    "script": ("py", "nar-script.py", []),
    "app": ("py", "nar-app.py", []),
}

CASE_USAGE = """usage: nar case <export|import|verify|graph|investigation> ...

  nar case export CASE_DIR --bundle FILE [--json]
  nar case import FILE [--out DIR] [--json]
  nar case verify CASE_DIR [--json]
  nar case graph CASE_DIR [--kind KIND] [--edge-kind KIND]
                          [--min-confidence LEVEL] [--text TEXT]
  nar case investigation CASE_DIR

Case bundles are the portable form of a nar-analyze case
directory (per-file hash manifest inside). These verbs route
to nar-analyze's case operations; the standalone flags
--export / --import / --verify keep working unchanged. The
graph verb queries a case's graph.json (JSON output, filtered
by node kind, edge kind, minimum confidence and free text);
the investigation verb prints a case's investigation.json
summary as JSON."""

IDENTITY = f"""NAR {VERSION} — NIROUS ANDROID INTELLIGENCE
Understand Every Layer. Follow Every Evidence.
MIT License."""


def _is_wsl_stub(path):
    """True when *path* points at the WSL launcher stub.

    The stub is the bash.exe that ships inside the Windows
    System32 directory (C:\\Windows\\System32\\bash.exe):
    invoking it prints "Windows Subsystem for Linux has no
    installed distributions" instead of running a shell.
    Git Bash never installs under System32, so any bash
    whose path carries a System32 component is the stub,
    never a real bash. The check is pure string work on
    both separator spellings (case-insensitive), so it
    behaves identically on every host.
    """
    if not path:
        return False
    parts = [p for p in
             path.replace("/", "\\").lower().split("\\") if p]
    return "system32" in parts


def _win_bash_candidates():
    """Ordered Git Bash candidates on Windows.

    Git-relative layouts come first (derived from the git
    executable's own location), then the standard Git for
    Windows install locations, then bash on PATH — the
    last only when it is not the System32 WSL stub. The
    stub is filtered out of every source, so a real Git
    Bash always wins over it. Candidate strings are built
    with forward slashes (accepted by every Windows API
    and by Git Bash itself) via posixpath, so the result
    does not depend on the host's path flavour.
    """
    candidates = []

    def _add(candidate):
        if candidate and candidate not in candidates \
                and not _is_wsl_stub(candidate):
            candidates.append(candidate)

    git = shutil.which("git")
    if git:
        git_dir = git.replace("\\", "/").rstrip("/")
        git_dir = git_dir.rsplit("/", 1)[0] \
            if "/" in git_dir else ""
        if git_dir:
            # git in cmd/ or bin/: ../bin is Git's bin;
            # git in mingw64/bin/: ../../bin is Git's bin;
            # ../usr/bin is Git's usr/bin (also ships bash).
            for rel in ("../bin/bash.exe",
                        "../../bin/bash.exe",
                        "../usr/bin/bash.exe"):
                _add(posixpath.normpath(git_dir + "/" + rel))
    for env_name, suffix in (
            ("ProgramFiles", "Git/bin/bash.exe"),
            ("ProgramFiles(x86)", "Git/bin/bash.exe"),
            ("LOCALAPPDATA", "Programs/Git/bin/bash.exe")):
        base = os.environ.get(env_name)
        if base:
            _add(posixpath.normpath(
                base.replace("\\", "/").rstrip("/")
                + "/" + suffix))
    for name in ("bash", "bash.exe"):
        _add(shutil.which(name))
    return candidates


def resolve_bash():
    """The bash executable for the doctor dispatch.

    Non-Windows: plain "bash" from PATH, exactly as the
    dispatch has always done. Windows: the first Git Bash
    candidate that exists as a file, or None when no
    usable bash exists (the caller then fails honestly
    instead of invoking the WSL stub).
    """
    if sys.platform != "win32":
        return "bash"
    for candidate in _win_bash_candidates():
        if os.path.isfile(candidate):
            return candidate
    return None


def run_entry(entry, rest):
    kind, script, prefix = entry
    path = os.path.join(HERE, script)
    if not os.path.isfile(path):
        print(f"nar: {script} is missing from this install",
              file=sys.stderr)
        return 2
    if kind == "bash":
        bash = resolve_bash()
        if bash is None:
            print(
                "nar: the doctor requires Git Bash on Windows, "
                "but no usable bash was found (the bash.exe in "
                "the Windows System32 directory is the Windows "
                "Subsystem for Linux launcher stub, not a real "
                "bash, and is never used). Install Git for "
                "Windows, which provides Git Bash: "
                "https://git-scm.com/download/win",
                file=sys.stderr)
            return 2
        # Git Bash accepts forward-slash Windows paths
        # unconditionally; the native path uses backslashes.
        script_arg = path.replace("\\", "/") \
            if sys.platform == "win32" else path
        argv_full = [bash, script_arg]
    else:
        argv_full = [sys.executable, path]
    argv_full += list(prefix) + list(rest)
    try:
        proc = subprocess.run(argv_full)
    except OSError as e:
        print(f"nar: could not start {script}: {e}",
              file=sys.stderr)
        return 2
    return proc.returncode


def cmd_case(rest):
    """nar case: route to nar-analyze's case-bundle flags."""
    if not rest or rest[0] in ("-h", "--help", "help"):
        print(CASE_USAGE)
        return 0 if rest else 2
    sub, args = rest[0], rest[1:]
    flag = {"export": "--export", "import": "--import",
            "verify": "--verify", "graph": "--graph",
            "investigation": "--investigation"}.get(sub)
    if flag is None or not args:
        print(f"nar case: expected export|import|verify|"
              f"graph|investigation with "
              f"arguments\n{CASE_USAGE}", file=sys.stderr)
        return 2
    return run_entry(("py", "nar-analyze.py", [flag]), args)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    if argv[0] in ("version", "--version", "-V"):
        print(IDENTITY)
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd == "case":
        return cmd_case(rest)
    entry = COMMANDS.get(cmd)
    if entry is None:
        names = sorted(COMMANDS) + ["case", "version"]
        print(f"nar: unknown command {cmd!r}\n"
              f"commands: {', '.join(names)}",
              file=sys.stderr)
        return 2
    return run_entry(entry, rest)


if __name__ == "__main__":
    sys.exit(main())
