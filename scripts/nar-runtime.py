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
    python3 nar-runtime.py validate [--serial S]
                            [--package PKG] [--json PATH]
    python3 nar-runtime.py [--json] timeline-template

Part of NAR (Nirous Android Reversing).
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
                      "ttvm", "nox")
# "intel" used to sit in the strong list: Intel is a
# legitimate physical hardware vendor (x86 phones and
# tablets shipped), so an Intel hardware string is at
# most a WEAK emulator hint (stability audit D-11).
_EMULATOR_HARDWARE_WEAK = ("intel",)
# Identity properties whose presence makes a property
# set rich enough for a "physical" verdict by absence
# of markers; a sparser set is "unknown", never
# physical-by-default (D-11).
_IDENTITY_PROPS = ("ro.product.model", "ro.product.brand",
                   "ro.product.manufacturer",
                   "ro.product.device",
                   "ro.build.fingerprint", "ro.hardware")
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
    elif hw and any(h in hw for h in _EMULATOR_HARDWARE_WEAK):
        add("ro.hardware", props.get("ro.hardware"),
            "emulator", "weak")
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
    identity_present = sum(1 for p in _IDENTITY_PROPS
                           if props.get(p))
    if strong or len(weak) >= 2:
        kind = "emulator"
    elif not props:
        kind = "unknown"
    elif evidence:
        kind = "unknown"
    elif identity_present >= 3:
        kind = "physical"
    else:
        # A near-empty property set (one or two unrelated
        # values) used to earn "physical" by absence of
        # markers — absence of evidence on a sparse set
        # is not evidence of a physical device (D-11).
        kind = "unknown"
    return {"kind": kind, "evidence": evidence,
            "basis": ("strong emulator marker(s): "
                      + ", ".join(e["property"] for e in strong)
                      if strong else
                      "two or more weak emulator markers"
                      if kind == "emulator" else
                      "no property data was readable"
                      if kind == "unknown" and not props else
                      "weak emulator evidence only; not decisive"
                      if kind == "unknown" and evidence else
                      "property set too sparse to classify "
                      "(fewer than 3 identity properties)"
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
        "fingerprint": props.get("ro.build.fingerprint"),
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
        # Presence means a BINARY candidate exists: the
        # unfiltered prefix list also matches sidecar
        # files (frida-server.log), which previously made
        # a lone log file report the server "present"
        # (stability audit D-06).
        "present": bool(candidates), "files": names,
        "version": server_version,
        "compatibility": frida_compatibility(
            frida_host_version, server_version)}
    caps["statuses"] = capability_statuses(caps)
    return caps


# ------------------------------------------------------------------
# 2.6.2 (WS-B): explicit capability status vocabulary.
#
# Every capability/property a capability record reports carries
# exactly one status from CAPABILITY_STATUSES:
#
#   detected     the value was read from the device (a property
#                or a directory listing answered) but no active
#                probe confirmed it end to end.
#   verified     an active probe confirmed the value: adb
#                answered for this serial, the `id` probe read
#                the adbd uid, or the frida-server binary itself
#                executed and reported a version that matches
#                the host.
#   unsupported  the value was read, but the toolchain cannot
#                serve it: a Frida version mismatch, or a device
#                ABI with no frida-server build.
#   unavailable  a device answered, but this value could not
#                be read (missing property, unprobeable server
#                version, no frida-server present).
#   not_tested   nothing was attempted: no capability record
#                exists (no device), so no claim is made.
#
# The mapping is a pure function of an already-gathered
# capability record (plus the adb device state when the caller
# knows it), so it is unit-testable against recorded outputs.
# Emulator-vs-physical classification is NOT re-derived here:
# it stays with classify_device() and its multi-marker
# discipline (one strong marker, or two weak ones); the status
# vocabulary only describes how well each value is established.
# ------------------------------------------------------------------

CAPABILITY_STATUSES = ("detected", "verified", "unsupported",
                       "unavailable", "not_tested")

# Device ABI -> the frida-server build architecture that serves
# it. An ABI absent from this map has no frida-server build and
# is reported unsupported for Frida work (the ABI itself is
# still detected on the device).
_FRIDA_ARCH_FOR_ABI = {"arm64-v8a": "arm64",
                       "armeabi-v7a": "arm", "armeabi": "arm",
                       "x86": "x86", "x86_64": "x86_64"}


def frida_arch_for_abi(abi):
    """frida-server build arch for a device ABI, or None when
    no frida-server build exists for that ABI."""
    return _FRIDA_ARCH_FOR_ABI.get(abi or "")


def frida_server_arch(filename):
    """Build arch named by a frida-server file name
    ('frida-server-17.27.4-android-x86_64' -> 'x86_64'); None
    for the bare 'frida-server' name, which carries no arch."""
    m = re.search(r"-android-([A-Za-z0-9_]+)$", filename or "")
    return m.group(1) if m else None


def capability_statuses(caps, adb_state=None):
    """Map one device_capabilities() record (or None) onto the
    status vocabulary. Returns {field: {status, value, detail}}
    for: adb_connectivity, api_level, android_version,
    build_fingerprint, device_model, abi_primary, abi_list
    (with a per-ABI 'entries' list), root_status and
    frida_compatibility. With caps=None every field is
    not_tested: no device means no claim."""
    out = {}

    def add(field, status, value, detail, **extra):
        entry = {"status": status, "value": value,
                 "detail": detail}
        entry.update(extra)
        out[field] = entry

    if caps is None:
        for field in ("adb_connectivity", "api_level",
                      "android_version", "build_fingerprint",
                      "device_model", "abi_primary", "abi_list",
                      "root_status", "frida_compatibility"):
            add(field, "not_tested", None,
                "no device capability record was gathered")
        return out
    props = caps.get("properties") or {}
    populated = bool(props)
    if adb_state == "device" or (adb_state is None and populated):
        add("adb_connectivity",
            "verified" if adb_state == "device" else "detected",
            caps.get("serial"),
            "adb answered for this serial and properties were "
            "read" if adb_state == "device" else
            "properties were read over adb; the adb device "
            "state was not recorded by the caller")
    elif adb_state:
        add("adb_connectivity", "unavailable", caps.get("serial"),
            f"adb reports this device as '{adb_state}', which "
            "is not usable; authorize it or wait for it to "
            "return to state 'device'")
    else:
        add("adb_connectivity", "unavailable", caps.get("serial"),
            "no properties could be read over adb")

    def prop_status(field, value, label):
        if value is not None:
            add(field, "detected", value,
                f"{label} read from the device properties")
        elif populated:
            add(field, "unavailable", None,
                f"{label} was not present in the device "
                "property dump")
        else:
            add(field, "not_tested", None,
                "no device properties could be read")

    prop_status("api_level", caps.get("api_level"), "API level")
    prop_status("android_version", caps.get("android"),
                "Android version")
    prop_status("build_fingerprint", caps.get("fingerprint"),
                "build fingerprint")
    prop_status("device_model", caps.get("model"), "device model")
    prop_status("abi_primary", caps.get("abi"), "primary ABI")
    entries = []
    for abi in caps.get("abilist") or []:
        arch = frida_arch_for_abi(abi)
        if arch:
            entries.append({
                "abi": abi, "status": "detected",
                "frida_arch": arch,
                "detail": f"device lists {abi}; a frida-server "
                          f"{arch} build serves this ABI"})
        else:
            entries.append({
                "abi": abi, "status": "unsupported",
                "frida_arch": None,
                "detail": f"device lists {abi}; no frida-server "
                          "build exists for this ABI"})
    if entries:
        add("abi_list",
            "unsupported" if all(e["status"] == "unsupported"
                                 for e in entries) else "detected",
            caps.get("abilist"),
            "per-ABI support in 'entries': an ABI is "
            "unsupported only for Frida work when no "
            "frida-server build exists for it",
            entries=entries)
    elif populated:
        add("abi_list", "unavailable", [],
            "the device reported no ABI list", entries=[])
    else:
        add("abi_list", "not_tested", None,
            "no device properties could be read", entries=[])
    root = caps.get("root") or {}
    if root.get("evidence"):
        add("root_status", "verified", root.get("adbd_uid0"),
            "the `id` probe answered: adbd runs as uid=0 "
            "(root)" if root.get("adbd_uid0") else
            "the `id` probe answered: adbd does not run as "
            "uid=0 (not root)")
    elif populated:
        add("root_status", "unavailable", None,
            "the `id` probe did not answer; root state is "
            "unknown, not guessed")
    else:
        add("root_status", "not_tested", None,
            "no device properties could be read")
    server = caps.get("frida_server") or {}
    compat = server.get("compatibility") or {}
    if compat.get("status") == "match":
        add("frida_compatibility", "verified",
            server.get("version"),
            "the frida-server binary executed on the device "
            "and its version agrees with the host on "
            "major.minor")
    elif compat.get("status") == "mismatch":
        add("frida_compatibility", "unsupported",
            server.get("version"), compat.get("message", ""))
    elif server.get("present"):
        add("frida_compatibility", "detected",
            server.get("version"),
            "a frida-server binary is present on the device "
            "but its version could not be probed (zero or "
            "several binary candidates, or the probe did not "
            "answer)")
    elif populated:
        add("frida_compatibility", "unavailable", None,
            "no frida-server binary is present in "
            "/data/local/tmp")
    else:
        add("frida_compatibility", "not_tested", None,
            "no device properties could be read")
    return out


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
FAIL_DEVICE_UNAUTHORIZED = "DEVICE_UNAUTHORIZED"
FAIL_DEVICE_OFFLINE = "DEVICE_OFFLINE"
FAIL_FRIDA_ABI_MISMATCH = "FRIDA_SERVER_ABI_MISMATCH"
FAIL_FRIDA_ABI_UNKNOWN = "FRIDA_SERVER_ABI_UNKNOWN"
FAIL_ABI_UNSUPPORTED = "DEVICE_ABI_UNSUPPORTED"
FAIL_ENUMERATION = "FRIDA_ENUMERATION_FAILED"
FAIL_ATTACH = "FRIDA_ATTACH_FAILED"
FAIL_DETACH = "FRIDA_DETACH_FAILED"


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


# ------------------------------------------------------------------
# 2.6.2 (WS-B): runtime compatibility validation.
#
# `validate` goes one step past `diagnose`: diagnose validates
# the environment from properties; validate also exercises the
# live Frida path — process enumeration, a real attach of a
# marker script to a running test process, and a clean detach
# (the target must still be alive afterwards). Every check
# keeps diagnose's shape {check, status, reason, detail,
# action} with a named failure reason and a concrete remedy.
# The assessment (validation_from) is pure; the live gathering
# (validate) is the only part that touches a device, and every
# probe it runs is read-only observation of a test process the
# caller named with --package.
# ------------------------------------------------------------------

ATTACH_MARKER = "[nar-validate] attach-ok"


def parse_frida_ps(text):
    """Parse `frida-ps -U` output into [{pid, name}]. The
    header row ('PID  Name') and separator are skipped; rows
    that do not start with a numeric pid are ignored."""
    procs = []
    for line in (text or "").splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            procs.append({"pid": int(parts[0]),
                          "name": parts[1]})
    return procs


def validation_from(adb, frida, caps_list, states=None,
                    serial=None, package=None, installed=None,
                    enumeration=None, attach=None, detach=None):
    """Structured runtime validation from already-gathered
    facts (pure). Checks: adb_available, device_authorized,
    frida_host_version, frida_server_presence,
    frida_server_version, frida_version_match,
    frida_abi_match, process_enumeration, attach_capability,
    clean_detach. A probe the caller did not run is reported
    skip with the reason in the detail — never pass."""
    checks = []

    def add(check, status, reason, detail, action=""):
        checks.append({"check": check, "status": status,
                       "reason": reason, "detail": detail,
                       "action": action})

    if adb and adb.get("available"):
        add("adb_available", "pass", None,
            f"adb at {adb.get('path')} ({adb.get('version')})")
    else:
        add("adb_available", "fail", FAIL_ADB_MISSING,
            "adb was not found by the capability registry",
            "install Android SDK platform-tools or set "
            "ANDROID_HOME")
    states = states or {}
    caps = caps_list[0] if caps_list else None
    if serial is not None:
        state = states.get(serial)
        if state == "device":
            add("device_authorized", "pass", None,
                f"device {serial} is in state 'device' "
                "(authorized and reachable)")
        elif state == "unauthorized":
            add("device_authorized", "fail",
                FAIL_DEVICE_UNAUTHORIZED,
                f"device {serial} is 'unauthorized': adb "
                "cannot run commands on it",
                "unlock the device and accept the USB "
                "debugging authorization prompt for this host, "
                "then re-run validate")
        elif state == "offline":
            add("device_authorized", "fail", FAIL_DEVICE_OFFLINE,
                f"device {serial} is 'offline': it was seen "
                "but is not answering",
                "run diagnose --recover for one bounded "
                "reconnect pass, or restart the emulator / "
                "replug the device")
        elif state is None:
            add("device_authorized", "fail", FAIL_NO_DEVICE,
                f"adb does not enumerate a device with serial "
                f"{serial}",
                "attach the device or start the emulator, "
                "then re-run validate")
        else:
            add("device_authorized", "fail",
                FAIL_DEVICE_NOT_READY,
                f"device {serial} is in state '{state}'",
                "wait for the device to reach state 'device'")
    elif caps is not None:
        add("device_authorized", "pass", None,
            f"device {caps['serial']} is in state 'device' "
            "(authorized and reachable)")
    elif states:
        add("device_authorized", "fail", FAIL_DEVICE_NOT_READY,
            "device(s) present but none is ready: "
            + ", ".join(f"{s}={st}" for s, st in states.items()),
            "authorize the device (unauthorized) or run "
            "diagnose --recover (offline)")
    else:
        add("device_authorized", "fail", FAIL_NO_DEVICE,
            "adb enumerates no device",
            "attach a device or start an emulator")
    if frida and frida.get("available") \
            and parse_version(frida.get("version")):
        add("frida_host_version", "pass", None,
            f"host frida {frida.get('version')} at "
            f"{frida.get('path')}")
    elif frida and frida.get("available"):
        add("frida_host_version", "warn", FAIL_FRIDA_UNKNOWN,
            "host frida CLI was found but its version could "
            "not be parsed, so no version comparison is "
            "possible")
    else:
        add("frida_host_version", "fail",
            FAIL_FRIDA_HOST_MISSING,
            "host frida CLI was not found by the registry",
            "pip install frida-tools into a venv (see the "
            "registry install hint)")
    if caps is None:
        for check in ("frida_server_presence",
                      "frida_server_version",
                      "frida_version_match", "frida_abi_match"):
            add(check, "skip", None, "no device to check")
    else:
        server = caps.get("frida_server") or {}
        if server.get("present"):
            add("frida_server_presence", "pass", None,
                "frida-server present in /data/local/tmp: "
                + ", ".join(server.get("files") or []))
        else:
            add("frida_server_presence", "fail",
                FAIL_FRIDA_SERVER_MISSING,
                "no frida-server binary in /data/local/tmp",
                "push the frida-server build matching the "
                "host frida version and the device ABI to "
                "/data/local/tmp and start it as root")
        if not server.get("present"):
            add("frida_server_version", "skip", None,
                "no frida-server to read a version from")
            add("frida_version_match", "skip", None,
                "no frida-server to compare versions with")
            add("frida_abi_match", "skip", None,
                "no frida-server to compare ABIs with")
        else:
            if server.get("version"):
                add("frida_server_version", "pass", None,
                    f"frida-server reports version "
                    f"{server.get('version')}")
            else:
                add("frida_server_version", "warn",
                    FAIL_FRIDA_UNKNOWN,
                    "frida-server is present but its version "
                    "could not be probed (zero or several "
                    "binary candidates, or --version did not "
                    "answer)",
                    "keep exactly one frida-server binary in "
                    "/data/local/tmp so its version can be "
                    "probed")
            compat = server.get("compatibility") or {}
            if compat.get("status") == "match":
                add("frida_version_match", "pass", None,
                    compat.get("message", ""))
            elif compat.get("status") == "mismatch":
                add("frida_version_match", "fail",
                    FAIL_FRIDA_MISMATCH,
                    compat.get("message", ""))
            else:
                add("frida_version_match", "warn",
                    FAIL_FRIDA_UNKNOWN,
                    compat.get("message", ""))
            want = frida_arch_for_abi(caps.get("abi"))
            archs = {a for a in (frida_server_arch(f)
                                 for f in server.get("files")
                                 or []) if a}
            if want is None:
                add("frida_abi_match", "fail",
                    FAIL_ABI_UNSUPPORTED,
                    f"device primary ABI {caps.get('abi')} "
                    "has no frida-server build",
                    "use a device or emulator whose ABI has a "
                    "frida-server build (arm64, arm, x86, "
                    "x86_64)")
            elif not archs:
                add("frida_abi_match", "warn",
                    FAIL_FRIDA_ABI_UNKNOWN,
                    "the frida-server file name carries no "
                    "build arch, so its ABI cannot be "
                    "confirmed from the listing",
                    "push the arch-named build "
                    f"(frida-server-<version>-android-{want}) "
                    "so the ABI match is verifiable")
            elif want in archs:
                add("frida_abi_match", "pass", None,
                    f"frida-server build arch {want} matches "
                    f"the device primary ABI {caps.get('abi')}")
            else:
                add("frida_abi_match", "fail",
                    FAIL_FRIDA_ABI_MISMATCH,
                    f"frida-server build arch "
                    f"{', '.join(sorted(archs))} does not "
                    f"serve the device primary ABI "
                    f"{caps.get('abi')} (needs {want})",
                    f"push frida-server-<version>-android-"
                    f"{want} to /data/local/tmp")
    if enumeration is None:
        add("process_enumeration", "skip", None,
            "process enumeration was not attempted (no ready "
            "device or no host frida)")
    elif enumeration.get("ok"):
        add("process_enumeration", "pass", None,
            f"frida-ps enumerated "
            f"{len(enumeration.get('processes') or [])} "
            "processes on the device")
    else:
        add("process_enumeration", "fail", FAIL_ENUMERATION,
            "frida-ps could not enumerate device processes: "
            + str(enumeration.get("error") or "no output"),
            "confirm frida-server is running on the device "
            "(start it as root) and that host and server "
            "versions match, then re-run validate")
    if attach is None:
        add("attach_capability", "skip", None,
            "no attach probe was run"
            + ("" if package else
               " (no --package test target was named)"))
    elif attach.get("ok"):
        add("attach_capability", "pass", None,
            attach.get("detail")
            or "marker script attached and reported back")
    else:
        add("attach_capability", "fail", FAIL_ATTACH,
            attach.get("detail")
            or "the marker script did not attach",
            "confirm the test app is running, frida-server "
            "is up, and the process is debuggable or the "
            "server runs as root; then re-run validate")
    if detach is None:
        add("clean_detach", "skip", None,
            "no attach session was opened, so there is "
            "nothing to detach")
    elif detach.get("ok"):
        add("clean_detach", "pass", None,
            detach.get("detail")
            or "session ended and the target stayed alive")
    else:
        add("clean_detach", "fail", FAIL_DETACH,
            detach.get("detail")
            or "the session did not end cleanly",
            "check whether the target process survived; a "
            "killed target means the detach (or the server) "
            "is at fault, not the app")
    failures = [c["reason"] for c in checks
                if c["status"] == "fail"]
    return {"ok": not failures, "checks": checks,
            "failure_reasons": failures}


def validate(serial=None, package=None, json_path=None,
             runner=None):
    """Live runtime compatibility validation: environment
    checks plus Frida process enumeration, a marker-script
    attach to the --package test process (launched via monkey
    when installed but not running), and a clean-detach check.
    With json_path, the full report is also written there."""
    runner = runner or _run
    adb = probe_tool("adb")
    frida = probe_tool("frida")
    report = {"tool": "nar-runtime", "version": "3.0.0",
              "serial": serial, "package": package,
              "capabilities": [], "checks": [],
              "validation": None}
    if not adb.get("available"):
        report["validation"] = validation_from(
            adb, frida, [], states={})
        report["checks"] = report["validation"]["checks"]
        report["ok"] = False
        if json_path:
            _write_json(report, json_path)
        return report
    states, _err = adb_device_states(adb["path"], runner=runner)
    if serial is not None:
        target = serial if states.get(serial) == "device" \
            else None
    else:
        target = next((s for s, st in states.items()
                       if st == "device"), None)
    caps_list = []
    installed = None
    enumeration = None
    attach = None
    detach = None
    if target is not None:
        caps = device_capabilities(
            adb["path"], target, runner=runner,
            frida_host_version=(frida.get("version")
                                if frida.get("available")
                                else None))
        caps["statuses"] = capability_statuses(
            caps, adb_state="device")
        caps_list.append(caps)
        report["serial"] = target
        if package:
            installed = app_installed(adb["path"], target,
                                      package, runner=runner)
    frida_path = frida.get("path") if frida.get("available") \
        else None
    if target is not None and frida_path:
        ps_path = os.path.join(os.path.dirname(frida_path),
                               "frida-ps")
        if not os.path.isfile(ps_path):
            ps_path = "frida-ps"
        # One bounded retry: a single enumeration attempt can
        # be cancelled by a slow transport (observed live on
        # a software-emulated target) while the server is in
        # fact up; the retry distinguishes that from a server
        # that is really down.
        for _attempt in range(2):
            try:
                proc = runner([ps_path, "-U"], timeout=60)
                out = (proc.stdout or "") + (proc.stderr or "")
                procs = parse_frida_ps(out)
                enumeration = {
                    "ok": proc.returncode == 0 and bool(procs),
                    "processes": procs,
                    "error": None if procs else
                             out.strip()[:200] or "no processes "
                             "were listed"}
            except (OSError, subprocess.TimeoutExpired) as e:
                enumeration = {"ok": False, "processes": [],
                               "error": str(e)}
            if enumeration.get("ok"):
                break
            time.sleep(2)
    if target is not None and frida_path and package \
            and installed is False and enumeration \
            and enumeration.get("ok"):
        attach = {"ok": False,
                  "detail": f"{package} is not installed on "
                            "the device, so there is no test "
                            "process to attach to"}
    if target is not None and frida_path and package \
            and installed is not False and enumeration \
            and enumeration.get("ok") and attach is None:
        # A `pm` answer of None means pm did not answer (seen
        # live when the package service is slow under
        # emulation); it is not evidence about installation.
        # A running or launchable process is stronger proof,
        # so the attach probe proceeds on pid evidence alone.
        pid = _package_pid(adb["path"], target, package,
                           runner=runner)
        if pid is None:
            adb_shell(adb["path"], target,
                      ["monkey", "-p", package, "-c",
                       "android.intent.category.LAUNCHER", "1"],
                      timeout=60, runner=runner)
            for _ in range(10):
                pid = _package_pid(adb["path"], target, package,
                                   runner=runner)
                if pid is not None:
                    break
                time.sleep(3)
        if pid is None:
            attach = {"ok": False,
                      "detail": f"no running process for "
                                f"{package} could be found or "
                                "launched"
                                + (" (pm also did not answer; "
                                   "install state is unknown)"
                                   if installed is None else "")}
        else:
            # One bounded retry on a timeout-shaped failure:
            # under software emulation the agent sync-up can
            # exceed Frida's internal attach timeout while
            # the target is healthy (observed live: a first
            # attempt failed with 'Failed to attach: timeout
            # was reached' and an identical manual attach
            # immediately after succeeded). A non-timeout
            # failure is never retried.
            for _attempt in range(2):
                out = ""
                try:
                    proc = runner(
                        [frida_path, "-U", "-p", str(pid), "-q",
                         "-t", "10", "-e",
                         f"console.log('{ATTACH_MARKER}')"],
                        timeout=150)
                    out = (proc.stdout or "") \
                        + (proc.stderr or "")
                    if ATTACH_MARKER in out:
                        attach = {"ok": True,
                                  "detail": f"marker script "
                                            f"attached to pid "
                                            f"{pid} and "
                                            "reported back"}
                        alive = _package_pid(
                            adb["path"], target, package,
                            runner=runner)
                        detach = {
                            "ok": alive == pid
                                  and proc.returncode == 0,
                            "detail": f"frida session ended "
                                      f"(exit "
                                      f"{proc.returncode}); "
                                      f"target pid {pid} "
                                      + ("is still running"
                                         if alive == pid else
                                         "did not survive")}
                    else:
                        attach = {"ok": False,
                                  "detail": "marker script "
                                            "did not report "
                                            "back: "
                                            + (out.strip()[:200]
                                               or "no output")}
                except subprocess.TimeoutExpired:
                    attach = {"ok": False,
                              "detail": "the frida attach "
                                        "probe did not finish "
                                        "within its timeout"}
                    out = "timeout"
                except OSError as e:
                    attach = {"ok": False, "detail": str(e)}
                if attach.get("ok") \
                        or "timeout" not in out.lower():
                    break
                time.sleep(3)
    report["validation"] = validation_from(
        adb, frida, caps_list, states=states, serial=serial,
        package=package, installed=installed,
        enumeration=enumeration, attach=attach, detach=detach)
    report["capabilities"] = caps_list
    report["checks"] = report["validation"]["checks"]
    report["ok"] = report["validation"]["ok"]
    if json_path:
        _write_json(report, json_path)
        report["report_path"] = json_path
    return report


def _package_pid(adb_path, serial, package, runner=None):
    out = adb_shell(adb_path, serial, ["pidof", package],
                    runner=runner)
    for tok in (out or "").split():
        if tok.isdigit():
            return int(tok)
    # Fallback for images without pidof: parse the `ps`
    # listing (USER PID ... NAME columns).
    out = adb_shell(adb_path, serial, ["ps"], runner=runner)
    for line in (out or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1] == package \
                and parts[1].isdigit():
            return int(parts[1])
    return None


def _write_json(doc, path):
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)
    return path


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
        caps["statuses"] = capability_statuses(
            caps, adb_state="device")
        caps_list.append(caps)
        device_info.append({
            "serial": serial,
            "model": caps["model"],
            "android": caps["android"],
            "capabilities": caps})
    verified = bool(devices)
    return {
        "tool": "nar-runtime", "version": "3.0.0",
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
        return {"tool": "nar-runtime", "version": "3.0.0",
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
        caps["statuses"] = capability_statuses(
            caps, adb_state="device")
        caps_list.append(caps)
        if package:
            installed = app_installed(adb["path"], s, package)
    diag = diagnostics_from(adb, frida, caps_list, states=states,
                            package=package, installed=installed)
    return {"tool": "nar-runtime", "version": "3.0.0",
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
    return {"tool": "nar-runtime", "version": "3.0.0",
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
        "tool": "nar-runtime", "version": "3.0.0",
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
    val_p = sub.add_parser(
        "validate",
        help="validate runtime compatibility end to end: "
             "environment checks plus Frida process "
             "enumeration, a marker-script attach to the "
             "--package test process, and a clean-detach "
             "check; every failure names its reason and "
             "remedy")
    val_p.add_argument("--serial", metavar="S",
                       help="limit checks to this device serial")
    val_p.add_argument("--package", metavar="PKG",
                       help="test package to attach the "
                            "marker script to (launched when "
                            "installed but not running)")
    val_p.add_argument("--json", metavar="PATH",
                       help="also write the full validation "
                            "report as JSON to PATH")
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
    elif args.cmd == "validate":
        out = validate(serial=args.serial, package=args.package,
                       json_path=args.json)
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
    elif args.cmd == "validate":
        val = out["validation"]
        print("runtime compatibility: "
              + ("OK" if val["ok"] else "NOT READY"))
        for c in val["checks"]:
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
                  f"api={caps['api_level']}")
        if out.get("report_path"):
            print(f"report: {out['report_path']}")
    else:
        print(json.dumps(out, indent=2))
    if session_path and not args.json:
        print(f"session record: {session_path}")
    # Exit-code discipline (stability audit D-15): a
    # diagnose/validate run whose verdict is NOT READY
    # exits 1, so scripts can gate on it; the
    # informational subcommands (status/plan/timeline)
    # keep exit 0.
    if args.cmd == "diagnose" and not out["diagnostics"]["ok"]:
        return 1
    if args.cmd == "validate" and not out["validation"]["ok"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
