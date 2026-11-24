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
    python3 nar-runtime.py [--json] diagnose [--serial S]
                            [--package PKG] [--recover]
    python3 nar-runtime.py [--json] timeline-template

Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
MIT License. See LICENSE in the repo root.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
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


def _run(argv, timeout=30):
    """The one subprocess entry point for this module:
    list-form arguments, no shell, always a timeout."""
    return subprocess.run(argv, capture_output=True, text=True,
                          timeout=timeout)


def adb_device_states(adb_path, runner=None):
    """Enumerate devices with their adb state.

    Returns ({serial: state}, error-or-None). States are
    adb's own words: device / offline / unauthorized / ...
    Only state == "device" is usable."""
    runner = runner or _run
    try:
        proc = runner([adb_path, "devices"], timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {}, f"adb devices failed: {e}"
    states = {}
    for line in (proc.stdout or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            states[parts[0]] = parts[1]
    return states, None


def adb_devices(adb_path, runner=None):
    states, err = adb_device_states(adb_path, runner=runner)
    return [s for s, st in states.items() if st == "device"], err


def adb_prop(adb_path, serial, prop, runner=None):
    runner = runner or _run
    try:
        proc = runner(
            [adb_path, "-s", serial, "shell", "getprop", prop],
            timeout=30)
        return proc.stdout.strip() or None
    except (OSError, subprocess.TimeoutExpired):
        return None


def adb_shell(adb_path, serial, args, timeout=30, runner=None):
    """Run one adb shell command (list-form). Returns the
    stdout text, or None on transport failure."""
    runner = runner or _run
    try:
        proc = runner([adb_path, "-s", serial, "shell"] + list(args),
                      timeout=timeout)
        return proc.stdout or ""
    except (OSError, subprocess.TimeoutExpired):
        return None


# ------------------------------------------------------------------
# Phase 9 (R-007): device capabilities, emulator-vs-physical
# identification, environment validation, Frida compatibility
# diagnostics, and bounded connection recovery.
#
# The live paths go through adb_shell / adb_device_states with
# an injectable runner, so every behaviour is unit-testable
# against recorded adb/frida outputs; the pure classifiers
# (classify_device, frida_compatibility, diagnostics_from)
# take plain data and never touch a device.
# ------------------------------------------------------------------

# Properties read in ONE `getprop` dump per device.
CAPABILITY_PROPS = (
    "ro.product.model", "ro.product.brand", "ro.product.manufacturer",
    "ro.product.device", "ro.hardware", "ro.kernel.qemu",
    "ro.build.fingerprint", "ro.build.version.release",
    "ro.build.version.sdk", "ro.product.cpu.abi",
    "ro.product.cpu.abilist", "ro.serialno", "ro.boot.serialno",
    "ro.debuggable", "sys.boot_completed",
)

_EMULATOR_HARDWARE = ("ranchu", "goldfish", "vbox86", "emulator",
                      "ttvm", "nox", "intel")
_FRIDA_SERVER_DIR = "/data/local/tmp"


def parse_getprop_dump(text):
    """Parse a full `getprop` dump ('[key]: [value]' lines)
    into a dict. Malformed lines are ignored."""
    props = {}
    for line in (text or "").splitlines():
        m = re.match(r"\[([^\]]+)\]: \[(.*)\]\s*$", line.strip())
        if m:
            props[m.group(1)] = m.group(2)
    return props


def parse_version(text):
    """'17.27.4' -> (17, 27, 4); None when no leading
    dotted-numeric version is present."""
    if not text:
        return None
    m = re.search(r"(\d+(?:\.\d+){0,3})", str(text))
    if not m:
        return None
    return tuple(int(p) for p in m.group(1).split("."))


def frida_compatibility(host_version, server_version):
    """Compare host frida and on-device frida-server versions.

    Frida requires host and server to agree on major.minor;
    a patch-level difference is tolerated by the protocol
    but reported. The mismatch message names the exact fix
    (install the matching frida-server build, or align the
    host frida-tools) instead of a bare 'failed'."""
    host = parse_version(host_version)
    server = parse_version(server_version)
    out = {"host_version": host_version,
           "server_version": server_version,
           "status": "unknown", "message": ""}
    if host is None or server is None:
        missing = ("host frida" if host is None
                   else "frida-server")
        out["message"] = (f"{missing} version could not be "
                          "determined; compatibility is unknown")
        return out
    if host[:2] == server[:2]:
        out["status"] = "match"
        out["message"] = (f"host frida {host_version} and "
                          f"frida-server {server_version} agree "
                          "on major.minor")
        if host != server:
            out["message"] += (" (patch-level difference, "
                               "tolerated by the Frida protocol)")
        return out
    out["status"] = "mismatch"
    out["message"] = (
        f"frida version mismatch: host is {host_version}, "
        f"device frida-server is {server_version}; Frida "
        "requires matching major.minor. Fix: push a "
        f"frida-server {'.'.join(str(p) for p in host[:2])}.x "
        "build for the device ABI, or install frida-tools "
        f"{'.'.join(str(p) for p in server[:2])}.x on the host.")
    return out


def classify_device(props, serial=None):
    """Emulator-vs-physical identification from device
    properties. Every verdict carries the evidence that
    produced it: a list of {property, value, indicates}
    records. Strong emulator markers decide alone; weak
    markers need two; no markers on a populated property
    set means physical; an empty property set is unknown
    (never guessed)."""
    props = props or {}
    evidence = []

    def add(prop, value, indicates, strength):
        evidence.append({"property": prop, "value": value,
                         "indicates": indicates,
                         "strength": strength})

    qemu = props.get("ro.kernel.qemu")
    if qemu == "1":
        add("ro.kernel.qemu", qemu, "emulator", "strong")
    hw = (props.get("ro.hardware") or "").lower()
    if hw and any(h in hw for h in _EMULATOR_HARDWARE):
        add("ro.hardware", props.get("ro.hardware"),
            "emulator", "strong")
    model = (props.get("ro.product.model") or "")
    if re.search(r"(?i)sdk|emulator|android sdk built for",
                 model):
        add("ro.product.model", model, "emulator", "strong")
    if serial and serial.startswith("emulator-"):
        add("serial", serial, "emulator", "strong")
    fp = (props.get("ro.build.fingerprint") or "").lower()
    if "generic" in fp or "/sdk" in fp or "sdk_gphone" in fp:
        add("ro.build.fingerprint",
            props.get("ro.build.fingerprint"), "emulator", "weak")
    brand = (props.get("ro.product.brand") or "").lower()
    if brand in ("generic", "android", "google sdk"):
        add("ro.product.brand", props.get("ro.product.brand"),
            "emulator", "weak")
    strong = [e for e in evidence if e["strength"] == "strong"]
    weak = [e for e in evidence if e["strength"] == "weak"]
    if strong or len(weak) >= 2:
        kind = "emulator"
    elif not props:
        kind = "unknown"
    elif evidence:
        kind = "unknown"
    else:
        kind = "physical"
    return {"kind": kind, "evidence": evidence,
            "basis": ("strong emulator marker(s): "
                      + ", ".join(e["property"] for e in strong)
                      if strong else
                      "two or more weak emulator markers"
                      if kind == "emulator" else
                      "no property data was readable"
                      if kind == "unknown" and not props else
                      "weak emulator evidence only; not decisive"
                      if kind == "unknown" else
                      "property set populated, no emulator "
                      "markers present")}


def device_capabilities(adb_path, serial, runner=None,
                        frida_host_version=None):
    """Full capability record for one attached device:
    identity/ABI/API level, emulator-vs-physical
    classification with evidence, root state, and
    frida-server presence + version + host compatibility."""
    dump = adb_shell(adb_path, serial, ["getprop"], runner=runner)
    props = parse_getprop_dump(dump)
    caps = {
        "serial": serial,
        "model": props.get("ro.product.model"),
        "android": props.get("ro.build.version.release"),
        "api_level": None,
        "abi": props.get("ro.product.cpu.abi"),
        "abilist": [a for a in (props.get(
            "ro.product.cpu.abilist") or "").split(",") if a],
        "boot_completed": props.get("sys.boot_completed") == "1",
        "properties": {k: props.get(k) for k in CAPABILITY_PROPS
                       if props.get(k) is not None},
    }
    sdk = props.get("ro.build.version.sdk")
    if sdk and sdk.isdigit():
        caps["api_level"] = int(sdk)
    caps["classification"] = classify_device(props, serial)
    # Root state: adbd's own uid is the ground truth on
    # emulator/userdebug images; ro.debuggable is supporting
    # evidence only.
    id_out = adb_shell(adb_path, serial, ["id"], runner=runner)
    caps["root"] = {
        "adbd_uid0": bool(id_out and "uid=0" in id_out),
        "debuggable": props.get("ro.debuggable") == "1",
        "evidence": (id_out or "").strip()[:120] or None}
    # frida-server: presence by directory listing (parsed
    # here, no on-device shell pipelines), version by
    # executing the binary's --version when exactly one
    # candidate file is present.
    listing = adb_shell(adb_path, serial,
                        ["ls", _FRIDA_SERVER_DIR], runner=runner)
    names = [n.strip() for n in (listing or "").splitlines()
             if n.strip().startswith("frida-server")]
    # Version probing needs exactly one BINARY candidate:
    # sidecar files (frida-server.log, .xz archives, helper
    # dexes) share the prefix but are not the server — the
    # live emulator carries a frida-server.log beside the
    # binary, which previously suppressed the probe.
    candidates = [n for n in names
                  if n == "frida-server"
                  or re.fullmatch(
                      r"frida-server-[\d.]+(-android-.+)?", n)]
    server_version = None
    if len(candidates) == 1:
        ver_out = adb_shell(
            adb_path, serial,
            [f"{_FRIDA_SERVER_DIR}/{candidates[0]}", "--version"],
            timeout=20, runner=runner)
        if ver_out:
            m = parse_version(ver_out.strip().splitlines()[0]
                              if ver_out.strip() else "")
            if m:
                server_version = ".".join(str(p) for p in m)
    caps["frida_server"] = {
        "present": bool(names), "files": names,
        "version": server_version,
        "compatibility": frida_compatibility(
            frida_host_version, server_version)}
    return caps


def app_installed(adb_path, serial, package, runner=None):
    """True/False via `pm path`, None when pm did not answer
    (device not ready) — never a guessed False."""
    out = adb_shell(adb_path, serial, ["pm", "path", package],
                    runner=runner)
    if out is None:
        return None
    if out.strip().startswith("package:"):
        return True
    if "error" in out.lower() and "unknown" not in out.lower():
        return None
    return False


# Named failure reasons for environment validation.
FAIL_ADB_MISSING = "ADB_NOT_FOUND"
FAIL_NO_DEVICE = "NO_DEVICE_ATTACHED"
FAIL_DEVICE_NOT_READY = "DEVICE_NOT_READY"
FAIL_BOOT_INCOMPLETE = "BOOT_NOT_COMPLETED"
FAIL_APP_MISSING = "APP_NOT_INSTALLED"
FAIL_APP_UNKNOWN = "APP_INSTALL_STATE_UNKNOWN"
FAIL_FRIDA_HOST_MISSING = "FRIDA_HOST_NOT_FOUND"
FAIL_FRIDA_SERVER_MISSING = "FRIDA_SERVER_NOT_ON_DEVICE"
FAIL_FRIDA_MISMATCH = "FRIDA_VERSION_MISMATCH"
FAIL_FRIDA_UNKNOWN = "FRIDA_VERSION_UNKNOWN"


def diagnostics_from(adb, frida, caps_list, states=None,
                     package=None, installed=None):
    """Structured environment validation from already-gathered
    facts (pure). Each check is {check, status, reason,
    detail, action}: status pass/fail/warn/skip, reason a
    named failure code or None. `ok` is True only when no
    check failed."""
    checks = []

    def add(check, status, reason, detail, action=""):
        checks.append({"check": check, "status": status,
                       "reason": reason, "detail": detail,
                       "action": action})

    if adb and adb.get("available"):
        add("adb_present", "pass", None,
            f"adb at {adb.get('path')} ({adb.get('version')})")
    else:
        add("adb_present", "fail", FAIL_ADB_MISSING,
            "adb was not found by the capability registry",
            "install Android SDK platform-tools or set "
            "ANDROID_HOME")
    caps = caps_list[0] if caps_list else None
    if states is not None:
        not_ready = {s: st for s, st in states.items()
                     if st != "device"}
        if caps is not None:
            add("device_reachable", "pass", None,
                f"device {caps['serial']} answers adb")
        elif not_ready:
            add("device_reachable", "fail", FAIL_DEVICE_NOT_READY,
                "device(s) present but not ready: "
                + ", ".join(f"{s}={st}" for s, st
                            in not_ready.items()),
                "authorize the device (unauthorized) or wait "
                "for it to come back (offline); bounded "
                "recovery is available via diagnose --recover")
        else:
            add("device_reachable", "fail", FAIL_NO_DEVICE,
                "adb enumerates no device",
                "attach a device or start an emulator")
    elif caps is not None:
        add("device_reachable", "pass", None,
            f"device {caps['serial']} answers adb")
    else:
        add("device_reachable", "fail", FAIL_NO_DEVICE,
            "no device capabilities could be read",
            "attach a device or start an emulator")
    if caps is not None:
        if caps.get("boot_completed"):
            add("boot_completed", "pass", None,
                "sys.boot_completed=1")
        else:
            add("boot_completed", "fail", FAIL_BOOT_INCOMPLETE,
                "sys.boot_completed is not 1; the device is "
                "still booting",
                "wait for boot to finish before installing "
                "or observing")
    else:
        add("boot_completed", "skip", None,
            "no device to read boot state from")
    if package is None:
        add("app_installed", "skip", None,
            "no package was asked about")
    elif installed is True:
        add("app_installed", "pass", None,
            f"{package} is installed")
    elif installed is False:
        add("app_installed", "fail", FAIL_APP_MISSING,
            f"{package} is not installed on the device",
            "install it first (see the runtime plan's "
            "install step)")
    else:
        add("app_installed", "warn", FAIL_APP_UNKNOWN,
            f"pm did not answer for {package}; install state "
            "is unknown")
    if frida and frida.get("available"):
        add("frida_host", "pass", None,
            f"host frida {frida.get('version')} at "
            f"{frida.get('path')}")
    else:
        add("frida_host", "fail", FAIL_FRIDA_HOST_MISSING,
            "host frida CLI was not found by the registry",
            "pip install frida-tools into a venv (see the "
            "registry install hint)")
    if caps is None:
        add("frida_server", "skip", None, "no device")
        add("frida_version_match", "skip", None, "no device")
    else:
        server = caps.get("frida_server") or {}
        if server.get("present"):
            add("frida_server", "pass", None,
                "frida-server present in /data/local/tmp: "
                + ", ".join(server.get("files") or []))
        else:
            add("frida_server", "fail",
                FAIL_FRIDA_SERVER_MISSING,
                "no frida-server binary in /data/local/tmp",
                "push the frida-server build matching the "
                "host frida version and the device ABI to "
                "/data/local/tmp and start it as root")
        compat = server.get("compatibility") or {}
        if compat.get("status") == "match":
            add("frida_version_match", "pass", None,
                compat.get("message", ""))
        elif compat.get("status") == "mismatch":
            add("frida_version_match", "fail",
                FAIL_FRIDA_MISMATCH, compat.get("message", ""))
        else:
            add("frida_version_match", "warn",
                FAIL_FRIDA_UNKNOWN, compat.get("message", ""))
    failures = [c["reason"] for c in checks
                if c["status"] == "fail"]
    return {"ok": not failures, "checks": checks,
            "failure_reasons": failures}


def recover_connection(adb_path, serial=None, max_attempts=3,
                       delay_s=2.0, runner=None, sleep=None):
    """Bounded adb connection recovery: poll device state,
    issue `adb reconnect` between attempts, give up after
    max_attempts (clamped to 1..5 — never an infinite loop).
    Returns {recovered, attempts, history}."""
    sleep = sleep or time.sleep
    attempts_cap = max(1, min(int(max_attempts), 5))
    history = []
    for attempt in range(1, attempts_cap + 1):
        states, err = adb_device_states(adb_path, runner=runner)
        ready = [s for s, st in states.items() if st == "device"
                 and (serial is None or s == serial)]
        history.append({"attempt": attempt, "states": states,
                        "error": err})
        if ready:
            return {"recovered": True, "attempts": attempt,
                    "serial": ready[0], "history": history}
        if attempt < attempts_cap:
            runner = runner or _run
            try:
                if serial:
                    runner([adb_path, "-s", serial, "reconnect"],
                           timeout=30)
                else:
                    runner([adb_path, "reconnect"], timeout=30)
            except (OSError, subprocess.TimeoutExpired):
                pass
            sleep(min(delay_s * attempt, 30.0))
    return {"recovered": False, "attempts": attempts_cap,
            "serial": serial, "history": history,
            "note": "bounded recovery exhausted; the device "
                    "did not return to state 'device'"}


def status():
    adb = probe_tool("adb")
    frida = probe_tool("frida")
    devices, err = ([], None)
    states = {}
    if adb["available"]:
        states, err = adb_device_states(adb["path"])
        devices = [s for s, st in states.items()
                   if st == "device"]
    device_info = []
    caps_list = []
    for serial in devices:
        caps = device_capabilities(
            adb["path"], serial,
            frida_host_version=(frida.get("version")
                                if frida.get("available")
                                else None))
        caps_list.append(caps)
        device_info.append({
            "serial": serial,
            "model": caps["model"],
            "android": caps["android"],
            "capabilities": caps})
    verified = bool(devices)
    return {
        "tool": "nar-runtime", "version": "2.6.0",
        "adb": adb, "frida": frida,
        "devices": device_info,
        "device_error": err,
        "device_states": states,
        "diagnostics": diagnostics_from(adb, frida, caps_list,
                                         states=states),
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


def diagnose(serial=None, package=None, recover=False):
    """Live environment validation (Phase 9): structured
    diagnostics with named failure reasons, optionally after
    one bounded connection-recovery pass."""
    adb = probe_tool("adb")
    frida = probe_tool("frida")
    recovery = None
    if not adb["available"]:
        diag = diagnostics_from(adb, frida, [], states={})
        return {"tool": "nar-runtime", "version": "2.6.0",
                "diagnostics": diag, "recovery": None,
                "capabilities": []}
    states, _err = adb_device_states(adb["path"])
    ready = [s for s, st in states.items() if st == "device"
             and (serial is None or s == serial)]
    if recover and not ready:
        recovery = recover_connection(adb["path"], serial=serial)
        states, _err = adb_device_states(adb["path"])
        ready = [s for s, st in states.items() if st == "device"
                 and (serial is None or s == serial)]
    caps_list = []
    installed = None
    for s in ready[:1]:
        caps = device_capabilities(
            adb["path"], s,
            frida_host_version=(frida.get("version")
                                if frida.get("available")
                                else None))
        caps_list.append(caps)
        if package:
            installed = app_installed(adb["path"], s, package)
    diag = diagnostics_from(adb, frida, caps_list, states=states,
                            package=package, installed=installed)
    return {"tool": "nar-runtime", "version": "2.6.0",
            "diagnostics": diag, "recovery": recovery,
            "capabilities": caps_list}


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
    return {"tool": "nar-runtime", "version": "2.6.0",
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
        "tool": "nar-runtime", "version": "2.6.0",
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
    diag_p = sub.add_parser(
        "diagnose",
        help="validate the runtime environment (device "
             "capabilities, emulator/physical, Frida "
             "compatibility) with named failure reasons")
    diag_p.add_argument("--serial", metavar="S",
                        help="limit checks to this device serial")
    diag_p.add_argument("--package", metavar="PKG",
                        help="also check this package is "
                             "installed on the device")
    diag_p.add_argument("--recover", action="store_true",
                        help="first run one bounded adb "
                             "reconnect pass if no device is "
                             "ready")
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
    elif args.cmd == "diagnose":
        out = diagnose(serial=args.serial, package=args.package,
                       recover=args.recover)
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
    elif args.cmd == "diagnose":
        diag = out["diagnostics"]
        print("runtime environment: "
              + ("OK" if diag["ok"] else "NOT READY"))
        for c in diag["checks"]:
            line = f"- {c['check']}: {c['status']}"
            if c["reason"]:
                line += f" [{c['reason']}]"
            print(line + f" — {c['detail']}")
            if c["action"]:
                print(f"    action: {c['action']}")
        for caps in out["capabilities"]:
            cls = caps["classification"]
            print(f"device {caps['serial']}: {cls['kind']} "
                  f"({cls['basis']}); abi={caps['abi']} "
                  f"api={caps['api_level']} "
                  f"root_adbd={caps['root']['adbd_uid0']}")
        if out.get("recovery"):
            print(f"recovery: {out['recovery']}")
    else:
        print(json.dumps(out, indent=2))
    if session_path and not args.json:
        print(f"session record: {session_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
