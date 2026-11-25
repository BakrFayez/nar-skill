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
    nar version                product identity + version

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
try:
    from narlib import __version__ as VERSION
except Exception:
    VERSION = "2.6.2"

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
Research by Bakr Fayez. MIT License."""


def run_entry(entry, rest):
    kind, script, prefix = entry
    path = os.path.join(HERE, script)
    if not os.path.isfile(path):
        print(f"nar: {script} is missing from this install",
              file=sys.stderr)
        return 2
    argv_full = (["bash", path] if kind == "bash"
                 else [sys.executable, path]) \
        + list(prefix) + list(rest)
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
