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

What is NOT claimed: no Android device or emulator exists in
this environment, so every device-dependent capability is
labeled IMPLEMENTED_BUT_UNVERIFIED, exactly as the brief's
honesty rules require. The moment a device is attached, the
same commands run unchanged.

Usage:
    python3 nar-runtime.py status [--json]
    python3 nar-runtime.py plan app.apk [--json]
    python3 nar-runtime.py timeline-template [--json]

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from narlib import registry as reg_mod  # noqa: E402

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
        "tool": "nar-runtime", "version": "2.1.0",
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
    return {"tool": "nar-runtime", "version": "2.1.0",
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


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Runtime subsystem: adapter status, "
                    "session plans, timeline template. Device "
                    "execution is labeled honestly.")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    plan_p = sub.add_parser("plan")
    plan_p.add_argument("apk")
    sub.add_parser("timeline-template")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    if args.cmd == "status":
        out = status()
    elif args.cmd == "plan":
        out = plan(args.apk)
    else:
        out = timeline_template()
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
