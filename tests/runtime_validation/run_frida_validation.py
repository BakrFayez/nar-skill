#!/usr/bin/env python3
"""Frida validation suite: live driver (2.6.2 WS-B, B3).

Runs the checks defined in frida_validation.py against a
real target and writes the machine-readable report:

    python3 run_frida_validation.py \
        --package <test-package> [--apk test.apk] \
        [--serial S] [--frida-server-bin PATH] \
        --report validation-report.json

Honesty rules, enforced by construction:

- No device attached: every device-dependent check is
  NOT RUN with that reason; only the host-side syntax checks
  run. Nothing is ever PASS without being exercised.
- The device section records the classification exactly as
  nar-runtime computes it; an emulator is reported as an
  emulator. This suite's PASS on an emulator is not
  physical-device proof, and the report never claims it is.
- The test target is a controlled app the operator names
  with --package (installed from --apk when given). The
  suite only observes it with the bundled scripts.

Exit code: 0 when no check FAILed, 1 otherwise. A report is
written in both cases (and also when no device is present).

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import importlib.util
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import frida_validation as fv  # noqa: E402


def _load_runtime():
    path = os.path.join(HERE, "..", "..", "scripts",
                        "nar-runtime.py")
    spec = importlib.util.spec_from_file_location(
        "nar_runtime_for_validation", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rt = _load_runtime()


def _frida_ps(frida_path, runner):
    ps_path = os.path.join(os.path.dirname(frida_path),
                           "frida-ps")
    if not os.path.isfile(ps_path):
        ps_path = "frida-ps"
    res = runner([ps_path, "-U"], timeout=60)
    out = (res["stdout"] or "") + (res["stderr"] or "")
    return rt.parse_frida_ps(out), out, res


def _ensure_server(adb_path, serial, frida_path, server_bin,
                   runner):
    """Return (procs, error). When frida-ps cannot enumerate
    and a server binary was supplied, push it, start it as
    root, and poll enumeration for up to ~90 s."""
    # Bounded retries: a single enumeration can be cancelled
    # by a slow transport while the server is in fact up
    # (observed live on a software-emulated target).
    procs, out = [], ""
    for _attempt in range(3):
        procs, out, _res = _frida_ps(frida_path, runner)
        if procs:
            return procs, None
        time.sleep(5)
    if not server_bin:
        return [], out.strip()[:200] or "frida-ps listed no " \
                                        "processes"
    name = os.path.basename(server_bin)
    runner([adb_path, "-s", serial, "root"], timeout=60)
    time.sleep(3)
    runner([adb_path, "-s", serial, "push", server_bin,
            f"/data/local/tmp/{name}"], timeout=300)
    rt.adb_shell(adb_path, serial,
                 ["chmod", "755", f"/data/local/tmp/{name}"])
    rt.adb_shell(
        adb_path, serial,
        [f"nohup /data/local/tmp/{name} "
         ">/data/local/tmp/frida-server.log 2>&1 &"],
        timeout=20)
    deadline = time.time() + 90
    while time.time() < deadline:
        time.sleep(5)
        procs, out, _res = _frida_ps(frida_path, runner)
        if procs:
            return procs, None
    return [], "frida-server was pushed and started but " \
               "frida-ps still cannot enumerate processes"


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Run the Frida validation suite against "
                    "a device and write the JSON report.")
    p.add_argument("--serial", metavar="S")
    p.add_argument("--package", metavar="PKG",
                   help="controlled test package to attach to")
    p.add_argument("--apk", metavar="APK",
                   help="install this APK first when the "
                        "package is not installed")
    p.add_argument("--frida-server-bin", metavar="PATH",
                   help="frida-server binary to push and "
                        "start when the server is not "
                        "responding")
    p.add_argument("--scripts-dir", metavar="DIR",
                   default=os.path.join(HERE, "..", "..",
                                        "scripts", "frida"))
    p.add_argument("--session-secs", type=int, default=15,
                   help="seconds each script session runs")
    p.add_argument("--node", metavar="PATH")
    p.add_argument("--report", metavar="PATH", required=True)
    args = p.parse_args(argv)
    runner = fv.default_runner
    syntax = {}
    for spec in fv.SCRIPT_SPECS:
        syntax[spec["name"]] = fv.js_syntax_check(
            os.path.join(args.scripts_dir, spec["name"]),
            node_path=args.node, runner=runner)
    adb = rt.probe_tool("adb")
    frida = rt.probe_tool("frida")
    frida_section = {
        "host": frida.get("version") if frida.get("available")
                else None,
        "server": None, "abi": None, "compatibility": None}
    device_section = {
        "attached": False, "serial": args.serial,
        "classification": {"kind": "unknown", "evidence": [],
                           "basis": "no device attached"},
        "statuses": rt.capability_statuses(None),
        "note": "no device attached; device-dependent checks "
                "are NOT RUN"}
    results = []
    states = {}
    target = None
    caps = None
    if adb.get("available"):
        states, _err = rt.adb_device_states(adb["path"])
        if args.serial is not None:
            target = args.serial \
                if states.get(args.serial) == "device" else None
        else:
            target = next((s for s, st in states.items()
                           if st == "device"), None)
    if target is None:
        connectivity = {
            "state": "no_device",
            "detail": "no device attached (adb states: "
                      + (", ".join(f"{s}={st}" for s, st
                                    in states.items())
                         or "none enumerated")
                      + "); device-dependent checks are "
                        "NOT RUN, never PASS"}
        for spec in fv.SCRIPT_SPECS:
            results.append(fv.evaluate_script(
                spec, syntax[spec["name"]], connectivity))
    else:
        caps = rt.device_capabilities(
            adb["path"], target,
            frida_host_version=frida_section["host"])
        caps["statuses"] = rt.capability_statuses(
            caps, adb_state="device")
        device_section = {
            "attached": True, "serial": target,
            "model": caps.get("model"),
            "android": caps.get("android"),
            "api_level": caps.get("api_level"),
            "abi": caps.get("abi"),
            "classification": caps.get("classification"),
            "statuses": caps.get("statuses"),
            "note": "classification is reported exactly as "
                    "computed; an emulator result is not "
                    "physical-device proof"}
        server = caps.get("frida_server") or {}
        frida_section["server"] = server.get("version")
        frida_section["abi"] = rt.frida_arch_for_abi(
            caps.get("abi"))
        frida_section["compatibility"] = server.get(
            "compatibility")
        procs, serr = ([], "host frida CLI not available")
        if frida.get("available"):
            procs, serr = _ensure_server(
                adb["path"], target, frida["path"],
                args.frida_server_bin, runner)
        if not procs:
            connectivity = {
                "state": "server_down",
                "detail": "frida-server is not reachable on "
                          f"the device: {serr}"}
            for spec in fv.SCRIPT_SPECS:
                results.append(fv.evaluate_script(
                    spec, syntax[spec["name"]], connectivity))
        else:
            pid = None
            if args.package:
                installed = rt.app_installed(
                    adb["path"], target, args.package)
                # installed=None means pm did not answer (seen
                # live under emulation); it is not evidence of
                # absence, so an install is attempted whenever
                # installation is unproven and an APK was
                # supplied (install -r is idempotent), and the
                # pid evidence below decides the rest.
                if installed is not True and args.apk:
                    runner([adb["path"], "-s", target,
                            "install", "-r", args.apk],
                           timeout=300)
                    installed = rt.app_installed(
                        adb["path"], target, args.package)
                if installed is not False:
                    pid = rt._package_pid(adb["path"], target,
                                          args.package)
                    if pid is None:
                        rt.adb_shell(
                            adb["path"], target,
                            ["monkey", "-p", args.package,
                             "-c",
                             "android.intent.category."
                             "LAUNCHER", "1"], timeout=60)
                        deadline = time.time() + 90
                        while pid is None \
                                and time.time() < deadline:
                            time.sleep(5)
                            pid = rt._package_pid(
                                adb["path"], target,
                                args.package)
            if pid is None:
                connectivity = {
                    "state": "no_target",
                    "detail": "device and frida-server are "
                              "reachable, but no controlled "
                              "test process is running "
                              "(--package missing, not "
                              "installed, or not launchable); "
                              "attach-dependent checks are "
                              "NOT RUN"}
                for spec in fv.SCRIPT_SPECS:
                    results.append(fv.evaluate_script(
                        spec, syntax[spec["name"]],
                        connectivity))
            else:
                connectivity = {
                    "state": "ok",
                    "detail": f"frida-ps enumerated "
                              f"{len(procs)} processes; test "
                              f"process pid {pid}"}
                frida_cli = frida["path"]
                for spec in fv.SCRIPT_SPECS:
                    session = runner(
                        [frida_cli, "-U", "-p", str(pid), "-q",
                         "-t", str(args.session_secs), "-l",
                         os.path.join(args.scripts_dir,
                                      spec["name"])],
                        timeout=args.session_secs + 120)
                    # One bounded retry on a timeout-shaped
                    # attach failure (slow agent sync-up
                    # under emulation; see nar-runtime's
                    # validate probe for the live record).
                    ok, why = fv.attach_verdict(session)
                    if not ok and "timeout" in why:
                        time.sleep(3)
                        session = runner(
                            [frida_cli, "-U", "-p", str(pid),
                             "-q", "-t",
                             str(args.session_secs), "-l",
                             os.path.join(args.scripts_dir,
                                          spec["name"])],
                            timeout=args.session_secs + 120)
                    alive = rt._package_pid(
                        adb["path"], target,
                        args.package) == pid
                    recovery_session = runner(
                        [frida_cli, "-U", "-p",
                         str(fv.bogus_pid()), "-q", "-t", "5",
                         "-l", os.path.join(args.scripts_dir,
                                            spec["name"])],
                        timeout=45)
                    results.append(fv.evaluate_script(
                        spec, syntax[spec["name"]],
                        connectivity, session=session,
                        target_alive_after=alive,
                        recovery=fv.recovery_verdict(
                            recovery_session)))
    report = fv.build_report(device_section, frida_section,
                             results)
    parent = os.path.dirname(os.path.abspath(args.report))
    os.makedirs(parent, exist_ok=True)
    with open(args.report, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    s = report["summary"]
    print(f"report: {args.report}")
    print(f"checks: {s['checks_total']} total, "
          f"{s['pass']} PASS, {s['fail']} FAIL, "
          f"{s['not_run']} NOT RUN")
    for name, sub in s["scripts"].items():
        print(f"- {name}: {sub['pass']} PASS, "
              f"{sub['fail']} FAIL, {sub['not_run']} NOT RUN")
    return 1 if s["fail"] else 0


if __name__ == "__main__":
    sys.exit(main())
