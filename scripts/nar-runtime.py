#!/usr/bin/env python3
"""nar-runtime.py: runtime observation subsystem (brief
section 8).

What is real here:

- adb adapter: discovery through the capability registry,
  live `adb devices` enumeration, and (when a device is
  attached) model/Android-version reads.
- frida adapter: host CLI discovery through the registry and
  the bundled observation-script catalog.
- session plans: a complete, ordered runtime plan (install,
  launch, observe, collect) emitted as data — commands are
  generated, never silently executed.
- timeline: an empty timeline document conforming to
  schemas/timeline.schema.json, ready to be filled by a
  session on a real device.
- session records (Evolution Phase 6): the plan and status
  flows can persist a structured session record
  (schemas/runtime-session.schema.json) into a case
  workspace with --session-out DIR: session id, device
  identity, tool probes/versions, start/stop times, the
  events the flow produced, evidence paths, and errors.
  A record describes what the flow observed and planned;
  it never upgrades the verification label — a session
  recorded with no device attached still says
  IMPLEMENTED_BUT_UNVERIFIED.

Verification status: the device paths were verified live on
2026-11-23 against an Android emulator (API 26 / Android
8.0.0, google_apis x86_64 image, QEMU TCG software emulation
on a KVM-less host): adb enumeration and property reads,
package install and launch of the demo fixture, this
module's status/plan output against the attached device
(status reports verified-live), frida-server 17.27.4 running
as root, and the bundled network-observe and file-io-observe
scripts attached to the live demo process with all hooks
installed. A same-day follow-up verified Frida spawn mode
on the same target with a resume-first recipe (spawn via
the Frida API, resume immediately, settle, then load via
the CLI against the spawned pid): the one-command -f form
loses ActivityManager's ~10 s process-start-timeout race
under TCG — logcat records the gated child killed with
reason "start timeout" — while the recipe ran both
observation scripts live in Frida-spawned processes. One
limit stands, stated plainly: a physical device remains
IMPLEMENTED_BUT_UNVERIFIED — emulator success does not
transfer to real hardware. Where no device is attached,
status keeps reporting IMPLEMENTED_BUT_UNVERIFIED,
exactly as the brief's honesty rules require.

Usage:
    python3 nar-runtime.py [--json] status [--session-out DIR]
    python3 nar-runtime.py [--json] plan app.apk
                            [--session-out DIR]
    python3 nar-runtime.py [--json] timeline-template

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import subprocess
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import evidence as ev_mod  # noqa: E402
from narlib import registry as reg_mod  # noqa: E402
from narlib.hashing import sha256_of  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FRIDA_CATALOG = [
    {"script": "frida/network-observe.js",
     "purpose": "observe outbound connection attempts "
                "(HttpURLConnection, OkHttp, sockets)"},
    {"script": "frida/file-io-observe.js",
     "purpose": "observe file open/read/write/delete "
                "activity"},
    {"script": "frida/jni-trace.js",
     "purpose": "trace JNI native-method registration and "
                "native call entry"},
    {"script": "frida/java-api-trace.js",
     "purpose": "trace calls of named Java methods"},
]


def probe_tool(name):
    registry = reg_mod.load_registry()
    entry = next((t for t in registry["tools"]
                  if t["name"] == name), None)
    if entry is None:
        return {"available": False, "note": "not in registry"}
    return reg_mod.probe(entry)


def adb_devices(adb_path):
    try:
        proc = subprocess.run([adb_path, "devices"],
                              capture_output=True, text=True,
                              timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        return [], f"adb devices failed: {e}"
    devices = []
    for line in proc.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    return devices, None


def adb_prop(adb_path, serial, prop):
    try:
        proc = subprocess.run(
            [adb_path, "-s", serial, "shell", "getprop", prop],
            capture_output=True, text=True, timeout=30)
        return proc.stdout.strip() or None
    except (OSError, subprocess.TimeoutExpired):
        return None


def status():
    adb = probe_tool("adb")
    frida = probe_tool("frida")
    devices, err = ([], None)
    if adb["available"]:
        devices, err = adb_devices(adb["path"])
    device_info = []
    for serial in devices:
        device_info.append({
            "serial": serial,
            "model": adb_prop(adb["path"], serial,
                              "ro.product.model"),
            "android": adb_prop(adb["path"], serial,
                                "ro.build.version.release")})
    verified = bool(devices)
    return {
        "tool": "nar-runtime", "version": "2.5.1",
        "adb": adb, "frida": frida,
        "devices": device_info,
        "device_error": err,
        "frida_scripts": FRIDA_CATALOG,
        "verification_status": (
            "verified-live" if verified else
            "IMPLEMENTED_BUT_UNVERIFIED"),
        "note": ("a device is attached; runtime commands can "
                 "run" if verified else
                 "no Android device or emulator is attached in "
                 "this environment; adapters and plans are "
                 "complete, device execution is unverified"),
    }


def plan(apk_path):
    st = status()
    package_hint = None
    steps = [
        {"step": "install",
         "command": f"adb install -r {apk_path}",
         "evidence": "install result + package listing"},
        {"step": "baseline-logcat",
         "command": "adb logcat -c && adb logcat -v time",
         "evidence": "startup log window before launch"},
        {"step": "launch",
         "command": "adb shell monkey -p <package> "
                    "-c android.intent.category.LAUNCHER 1",
         "evidence": "process start in timeline "
                     "(kind=process-start)"},
        {"step": "frida-observe",
         "command": "frida -U -p <pid> -l "
                    "scripts/frida/network-observe.js",
         "evidence": "runtime endpoints -> timeline "
                     "(kind=network-request); compare against "
                     "nar-network static inventory"},
        {"step": "frida-fileio",
         "command": "frida -U -p <pid> -l "
                    "scripts/frida/file-io-observe.js",
         "evidence": "file operations -> timeline "
                     "(kind=file-access)"},
        {"step": "collect",
         "command": "adb shell run-as <package> ls files/ "
                    "(debuggable builds only)",
         "evidence": "app-private file inventory for the "
                     "case workspace"},
    ]
    return {"tool": "nar-runtime", "version": "2.5.1",
            "target": os.path.abspath(apk_path),
            "package_hint": package_hint,
            "verification_status": st["verification_status"],
            "devices_seen": st["devices"],
            "steps": steps,
            "safety": [
                "run only on a device and build you are "
                "authorized to test",
                "observation scripts record metadata and "
                "lengths, never credential values",
                "no step modifies the target app or its data"]}


def timeline_template():
    return {"case_id": None, "device": None, "events": []}


def new_session(kind, st, target=None):
    """Open a structured session record from a status()
    snapshot. The record is data about the flow that
    created it (plan/status), not a claim that device
    work happened: the device's verification label is
    carried through unchanged."""
    started = ev_mod.now_iso()
    record = {
        "tool": "nar-runtime", "version": "2.5.1",
        "session_id": "nar-rt-" + uuid.uuid4().hex[:12],
        "kind": kind,
        "started_at": started, "stopped_at": None,
        "target": None,
        "device": {
            "attached": bool(st.get("devices")),
            "devices": st.get("devices") or [],
            "verification_status": st.get(
                "verification_status")},
        "tools": {"adb": st.get("adb"), "frida": st.get("frida")},
        "events": [{"ts": started, "kind": "session-started",
                    "detail": f"{kind} session created"}],
        "evidence_paths": [],
        "errors": ([st["device_error"]]
                   if st.get("device_error") else []),
    }
    if target:
        entry = {"path": os.path.abspath(target), "sha256": None}
        if os.path.isfile(target):
            entry["sha256"] = sha256_of(target)
        record["target"] = entry
    return record


def close_session(record, events=()):
    """Append (kind, detail) events and stamp the stop
    time. Returns the record."""
    for kind, detail in events:
        record["events"].append(
            {"ts": ev_mod.now_iso(), "kind": kind,
             "detail": detail})
    record["stopped_at"] = ev_mod.now_iso()
    return record


def write_session(record, out_dir):
    """Persist the record as runtime-session.json inside
    out_dir (typically a case workspace). Returns the path."""
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "runtime-session.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=1)
    return path


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Runtime subsystem: adapter status, "
                    "session plans, timeline template. Device "
                    "execution is labeled honestly.")
    sub = p.add_subparsers(dest="cmd", required=True)
    status_p = sub.add_parser("status")
    status_p.add_argument("--session-out", metavar="DIR",
                          help="also persist a structured "
                               "session record into DIR")
    plan_p = sub.add_parser("plan")
    plan_p.add_argument("apk")
    plan_p.add_argument("--session-out", metavar="DIR",
                        help="also persist a structured "
                             "session record into DIR")
    sub.add_parser("timeline-template")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    session_path = None
    if args.cmd == "status":
        out = status()
        if getattr(args, "session_out", None):
            record = new_session("status", out)
            close_session(record, [(
                "status-probe",
                f"devices attached: {len(out['devices'])}; "
                f"verification: "
                f"{out['verification_status']}")])
            session_path = write_session(record,
                                         args.session_out)
    elif args.cmd == "plan":
        out = plan(args.apk)
        if getattr(args, "session_out", None):
            record = new_session("plan", status(), args.apk)
            close_session(record, [
                ("step-planned",
                 f"{step['step']}: {step['evidence']}")
                for step in out["steps"]])
            session_path = write_session(record,
                                         args.session_out)
    else:
        out = timeline_template()
    if session_path:
        out["session_record"] = session_path
    if args.json:
        print(json.dumps(out, indent=2))
    elif args.cmd == "status":
        print(f"adb: {out['adb']}")
        print(f"frida: {out['frida']}")
        print(f"devices: {out['devices']}")
        print(f"verification: {out['verification_status']} — "
              f"{out['note']}")
    elif args.cmd == "plan":
        print(f"Runtime plan for {out['target']} "
              f"({out['verification_status']})")
        for s in out["steps"]:
            print(f"- {s['step']}: {s['command']}")
            print(f"    evidence: {s['evidence']}")
    else:
        print(json.dumps(out, indent=2))
    if session_path and not args.json:
        print(f"session record: {session_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
