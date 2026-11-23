#!/usr/bin/env python3
"""nar: the unified NAR command line (brief section 15).

One entry point over every NAR module. Each subcommand is a
thin pass-through to the module's own script (which keeps
working standalone, exactly as in 1.x):

    nar doctor                 environment check
    nar input SUBCMD ...       input identification / safe
                               extraction / duplicates
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
    VERSION = "2.0.0"

COMMANDS = {
    "doctor": ("bash", "nar-doctor.sh"),
    "input": ("py", "nar-input.py"),
    "triage": ("py", "nar-triage.py"),
    "fingerprint": ("py", "nar-fingerprint.py"),
    "engines": ("py", "nar-engines.py"),
    "unity": ("py", "nar-unity.py"),
    "unreal": ("py", "nar-unreal.py"),
    "il2cpp": ("py", "nar-il2cpp.py"),
    "flutter": ("py", "nar-flutter.py"),
    "godot": ("py", "nar-godot.py"),
    "rn": ("py", "nar-rn.py"),
    "pak": ("py", "nar-pak.py"),
    "dex": ("py", "nar-dex.py"),
    "native": ("py", "nar-native.py"),
    "perms": ("py", "nar-perms.py"),
    "strings": ("py", "nar-strings.py"),
    "network": ("py", "nar-network.py"),
    "security": ("py", "nar-security.py"),
    "assets": ("py", "nar-assets.py"),
    "compare": ("py", "nar-compare.py"),
    "analyze": ("py", "nar-analyze.py"),
    "report": ("py", "nar-report.py"),
    "runtime": ("py", "nar-runtime.py"),
}

IDENTITY = f"""NAR {VERSION} — NIROUS ANDROID INTELLIGENCE
Understand Every Layer. Follow Every Evidence.
Research by Bakr Fayez. MIT License."""


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    if argv[0] in ("version", "--version", "-V"):
        print(IDENTITY)
        return 0
    cmd, rest = argv[0], argv[1:]
    entry = COMMANDS.get(cmd)
    if entry is None:
        print(f"nar: unknown command {cmd!r}\n"
              f"commands: {', '.join(sorted(COMMANDS))}, version",
              file=sys.stderr)
        return 2
    kind, script = entry
    path = os.path.join(HERE, script)
    if not os.path.isfile(path):
        print(f"nar: {script} is missing from this install",
              file=sys.stderr)
        return 2
    argv_full = (["bash", path] if kind == "bash"
                 else [sys.executable, path]) + rest
    try:
        proc = subprocess.run(argv_full)
    except OSError as e:
        print(f"nar: could not start {script}: {e}",
              file=sys.stderr)
        return 2
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
