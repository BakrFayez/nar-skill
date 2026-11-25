"""Frida validation suite: core logic (2.6.2 WS-B, B3).

Validates each bundled Frida observation script end to end:

  1. syntax          the script parses (node --check when node
                     exists, else a documented structural
                     fallback scan — never presented as a
                     full parse)
  2. connectivity    the host Frida CLI can reach a device
                     through frida-server
  3. attach          the script attaches to a controlled test
                     process
  4. banner          the script's expected initialization /
                     banner events appear in its output
  5. serialization   the captured event stream serializes to
                     JSON and parses back losslessly (the
                     bundled scripts emit text log lines via
                     console.log; the suite captures them as
                     the event stream and proves the stream
                     round-trips through JSON unchanged)
  6. detach          the session ends on its own and the test
                     process is still alive afterwards
  7. error_recovery  attaching the script to a nonexistent pid
                     produces a structured failure (named
                     error output, non-zero exit) and the
                     suite continues

Every check ends as exactly one of PASS / FAIL / NOT RUN, with
a detail string; a check that could not be exercised is
NOT RUN with the reason, never PASS. In particular, with no
device attached every device-dependent check is NOT RUN, and
an emulator result is recorded as an emulator result — it is
never physical-device proof.

This module is test tooling, not a shipped surface: the
shipped runtime-validation surface is `nar-runtime.py
validate`. The suite lives under tests/ because it needs a
live device and a host Frida install, and it produces a
report about the bundled scripts rather than analyzing a
target. All device interaction goes through injectable
runners so the logic is unit-testable with recorded outputs.

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import json
import os
import shutil
import subprocess

PASS = "PASS"
FAIL = "FAIL"
NOT_RUN = "NOT RUN"
CHECK_STATUSES = (PASS, FAIL, NOT_RUN)

CHECK_IDS = ("syntax", "connectivity", "attach", "banner",
             "serialization", "detach", "error_recovery")

# Expected initialization output per bundled script. `init` is
# the banner line printed when the script's main body runs;
# `hooked` (when not None) must also appear, proving at least
# one hook installed. For the JNI trace the init line IS the
# hook installation line.
SCRIPT_SPECS = [
    {"name": "network-observe.js",
     "init": "[net] observing network connections.",
     "hooked": "[net] hooked:"},
    {"name": "file-io-observe.js",
     "init": "[file-io] observing file operations.",
     "hooked": "[file-io] hooked:"},
    {"name": "jni-trace.js",
     "init": "[jni-trace] hooked RegisterNatives at",
     "hooked": None},
    {"name": "java-api-trace.js",
     "init": "[java-api-trace] tracing",
     "hooked": "[java-api-trace] hooked:"},
]

# Line prefixes the bundled scripts use for observable events.
EVENT_TAGS = ("[net] ", "[file-io] ", "[jni-trace] ",
              "[jni-register] ", "[jni-entry] ",
              "[java-api-trace] ", "[call] ", "[return] ")

ATTACH_ERROR_MARKERS = ("Failed to attach",
                        "unable to find process",
                        "ProcessNotFoundError",
                        "Failed to load script",
                        "the connection is closed")
CONNECT_ERROR_MARKERS = ("unable to connect",
                         "no device", "No device",
                         "unable to find device",
                         "Failed to enumerate processes")
JAVA_MISSING_MARKER = "Java runtime is not available"


def _check(check_id, status, detail):
    return {"id": check_id, "status": status, "detail": detail}


def default_runner(argv, timeout=60):
    """Run one command (list-form, no shell) and return
    {stdout, stderr, returncode, timed_out}."""
    try:
        proc = subprocess.run(argv, capture_output=True,
                              text=True, timeout=timeout)
        return {"stdout": proc.stdout or "",
                "stderr": proc.stderr or "",
                "returncode": proc.returncode,
                "timed_out": False}
    except subprocess.TimeoutExpired as e:
        def _text(v):
            if v is None:
                return ""
            return v.decode("utf-8", "replace") \
                if isinstance(v, bytes) else v
        return {"stdout": _text(e.stdout),
                "stderr": _text(e.stderr),
                "returncode": None, "timed_out": True}
    except OSError as e:
        return {"stdout": "", "stderr": str(e),
                "returncode": None, "timed_out": False}


# ------------------------------------------------------------------
# Check 1: syntax
# ------------------------------------------------------------------

def fallback_js_scan(text):
    """Structural fallback used only when node is absent:
    strip // and /* */ comments and string/template literals
    with a small state machine, then require balanced
    (), {} and [] and no unterminated literal or comment.
    This is NOT a JavaScript parse; it catches truncation and
    gross structural damage only, and the check detail says
    so wherever the fallback was used."""
    out = []
    i, n = 0, len(text or "")
    state = None  # None | "'" | '"' | '`' | 'line' | 'block'
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state is None:
            if ch == "/" and nxt == "/":
                state = "line"
                i += 2
                continue
            if ch == "/" and nxt == "*":
                state = "block"
                i += 2
                continue
            if ch in ("'", '"', "`"):
                state = ch
                i += 1
                continue
            out.append(ch)
            i += 1
            continue
        if state == "line":
            if ch == "\n":
                state = None
                out.append(ch)
            i += 1
            continue
        if state == "block":
            if ch == "*" and nxt == "/":
                state = None
                i += 2
                continue
            i += 1
            continue
        # Inside a string/template literal.
        if ch == "\\":
            i += 2
            continue
        if ch == state:
            state = None
        i += 1
    if state in ("'", '"', "`"):
        return False, "unterminated string literal"
    if state == "block":
        return False, "unterminated block comment"
    pairs = {")": "(", "]": "[", "}": "{"}
    stack = []
    for ch in out:
        if ch in "([{":
            stack.append(ch)
        elif ch in pairs:
            if not stack or stack[-1] != pairs[ch]:
                return False, f"unbalanced delimiter at {ch!r}"
            stack.pop()
    if stack:
        return False, f"unclosed delimiter(s): {''.join(stack)}"
    return True, "balanced delimiters, no unterminated literal"


def js_syntax_check(path, node_path=None, runner=None):
    """Syntax-check one script. Returns {status, method,
    detail} where status is PASS or FAIL (a missing file is a
    FAIL: the suite was pointed at a tree that lacks a
    bundled script)."""
    runner = runner or default_runner
    if not os.path.isfile(path):
        return {"status": FAIL, "method": "none",
                "detail": f"script file not found: {path}"}
    node = node_path or shutil.which("node")
    if node:
        res = runner([node, "--check", path], timeout=30)
        if res["returncode"] == 0:
            return {"status": PASS, "method": "node --check",
                    "detail": "node --check accepted the script"}
        detail = ((res["stderr"] or res["stdout"] or "")
                  .strip().splitlines() or ["parse error"])[0]
        return {"status": FAIL, "method": "node --check",
                "detail": f"node --check rejected the script: "
                          f"{detail[:200]}"}
    with open(path, encoding="utf-8") as fh:
        ok, why = fallback_js_scan(fh.read())
    return {"status": PASS if ok else FAIL,
            "method": "fallback-delimiter-scan",
            "detail": ("node is not available on this host, "
                       "so a structural fallback scan was used "
                       "(balanced-delimiter scan; not a full "
                       "JavaScript parse): " + why)}


# ------------------------------------------------------------------
# Session output analysis (checks 3-5 inputs)
# ------------------------------------------------------------------

def event_lines(text):
    """The event stream of one session: output lines carrying
    one of the bundled scripts' event tags, in order."""
    events = []
    for line in (text or "").splitlines():
        stripped = line.strip()
        if any(tag in stripped for tag in EVENT_TAGS):
            events.append(stripped)
    return events


def check_serialization(events):
    """Prove the captured event stream round-trips through
    JSON losslessly. Returns a check dict (id filled in by
    the caller via _check shape: {status, detail})."""
    records = [{"seq": i, "event": line}
               for i, line in enumerate(events)]
    try:
        blob = json.dumps(records)
        back = json.loads(blob)
    except (TypeError, ValueError) as e:
        return {"status": FAIL,
                "detail": f"event stream is not JSON-"
                          f"serializable: {e}"}
    if back != records:
        return {"status": FAIL,
                "detail": "event stream changed across a JSON "
                          "round-trip"}
    return {"status": PASS,
            "detail": f"{len(records)} event line(s) "
                      "serialized to JSON and parsed back "
                      "losslessly"}


def banner_verdict(spec, text):
    """(ok, detail): the script's init banner (and hook line,
    when the spec has one) must appear, and the Java-missing
    guard line must not."""
    if JAVA_MISSING_MARKER in (text or ""):
        return False, ("script loaded but reported the Java "
                       "runtime as unavailable in the test "
                       "process; its hooks never installed")
    missing = []
    if spec["init"] not in (text or ""):
        missing.append(f"init banner {spec['init']!r}")
    if spec.get("hooked") and spec["hooked"] not in (text or ""):
        missing.append(f"hook line {spec['hooked']!r}")
    if missing:
        return False, "missing " + " and ".join(missing)
    return True, "init banner and hook installation lines " \
                 "observed"


def attach_verdict(session):
    """(ok, detail) from one session result dict."""
    if session is None:
        return False, "no session was run"
    out = (session.get("stdout") or "") + \
        (session.get("stderr") or "")
    for marker in ATTACH_ERROR_MARKERS:
        if marker in out:
            return False, f"attach failed: {marker}"
    if session.get("timed_out"):
        return False, "the frida session did not end within " \
                      "its timeout"
    if session.get("returncode") not in (0, None):
        return False, f"frida exited with code " \
                      f"{session.get('returncode')}"
    return True, "frida attached and the session ran to its " \
                 "planned end"


# ------------------------------------------------------------------
# Per-script evaluation (pure assembly over gathered facts)
# ------------------------------------------------------------------

def evaluate_script(spec, syntax, connectivity, session=None,
                    target_alive_after=None, recovery=None):
    """Assemble the 7 checks for one script.

    connectivity: {"state": "ok"|"no_device"|"server_down"|
    "no_target", "detail": str} — no_target means a device and
    server were reachable but no test process was running, so
    attach-dependent checks cannot be exercised.
    session: one run result (default_runner shape) or None.
    recovery: {"ok": bool, "detail": str} or None."""
    checks = []
    checks.append(_check("syntax", syntax["status"],
                         f"[{syntax['method']}] "
                         f"{syntax['detail']}"))
    state = (connectivity or {}).get("state", "no_device")
    cdetail = (connectivity or {}).get(
        "detail", "connectivity was not probed")
    # Connectivity verdicts: 'ok' and 'no_target' both prove
    # the host reached the device through frida-server (the
    # latter only lacks a test process); 'server_down' was
    # exercised and failed; 'no_device' was never exercised.
    if state in ("ok", "no_target"):
        checks.append(_check("connectivity", PASS, cdetail))
    elif state == "server_down":
        checks.append(_check("connectivity", FAIL, cdetail))
    else:
        checks.append(_check("connectivity", NOT_RUN,
                             cdetail))
    if state != "ok":
        reason = cdetail
        for cid, what in (
                ("attach", "process attachment"),
                ("banner", "banner events"),
                ("serialization", "event serialization"),
                ("detach", "clean detachment"),
                ("error_recovery", "error recovery")):
            checks.append(_check(
                cid, NOT_RUN,
                f"{what} not exercised: {reason}"))
        return {"name": spec["name"], "checks": checks}
    ok, adetail = attach_verdict(session)
    if session is None:
        checks.append(_check("attach", NOT_RUN,
                             "no session was run"))
        for cid in ("banner", "serialization", "detach"):
            checks.append(_check(cid, NOT_RUN,
                                 "no session was run"))
    elif not ok:
        checks.append(_check("attach", FAIL, adetail))
        for cid, what in (("banner", "banner events"),
                          ("serialization", "event "
                           "serialization"),
                          ("detach", "clean detachment")):
            checks.append(_check(
                cid, NOT_RUN,
                f"{what} not exercised: the attach failed "
                f"({adetail})"))
    else:
        checks.append(_check("attach", PASS, adetail))
        text = (session.get("stdout") or "") + \
            (session.get("stderr") or "")
        bok, bdetail = banner_verdict(spec, text)
        checks.append(_check("banner",
                             PASS if bok else FAIL, bdetail))
        events = event_lines(text)
        if events:
            ser = check_serialization(events)
            checks.append(_check("serialization", ser["status"],
                                 ser["detail"]))
        else:
            checks.append(_check(
                "serialization", FAIL,
                "the session produced no event lines to "
                "serialize"))
        if target_alive_after is None:
            checks.append(_check(
                "detach", NOT_RUN,
                "target liveness after the session was not "
                "checked"))
        elif target_alive_after:
            checks.append(_check(
                "detach", PASS,
                "session ended on its own and the test "
                "process is still alive"))
        else:
            checks.append(_check(
                "detach", FAIL,
                "the test process did not survive the "
                "session; the detach (or the server) killed "
                "it, which is a suite failure, not an app "
                "result"))
    if recovery is None:
        checks.append(_check(
            "error_recovery", NOT_RUN,
            "the nonexistent-pid attach was not attempted"))
    elif recovery.get("ok"):
        checks.append(_check("error_recovery", PASS,
                             recovery.get("detail", "")))
    else:
        checks.append(_check("error_recovery", FAIL,
                             recovery.get("detail", "")))
    return {"name": spec["name"], "checks": checks}


def recovery_verdict(session):
    """Judge one attach attempt to a nonexistent pid: PASS
    when frida reported a structured failure (error marker or
    non-zero exit) and returned control to the suite."""
    if session is None:
        return {"ok": False, "detail": "not attempted"}
    out = (session.get("stdout") or "") + \
        (session.get("stderr") or "")
    markers = [m for m in ATTACH_ERROR_MARKERS if m in out]
    if markers:
        return {"ok": True,
                "detail": "attaching to a nonexistent pid "
                          f"failed as expected ({markers[0]}) "
                          "and the suite continued"}
    if session.get("returncode") not in (0, None):
        return {"ok": True,
                "detail": "attaching to a nonexistent pid "
                          f"exited with code "
                          f"{session.get('returncode')} and "
                          "the suite continued"}
    return {"ok": False,
            "detail": "attaching to a nonexistent pid "
                      "unexpectedly reported success or "
                      "produced no error output"}


# ------------------------------------------------------------------
# Report assembly
# ------------------------------------------------------------------

def summarize(script_results):
    counts = {PASS: 0, FAIL: 0, NOT_RUN: 0}
    per_script = {}
    for result in script_results:
        sub = {PASS: 0, FAIL: 0, NOT_RUN: 0}
        for check in result["checks"]:
            counts[check["status"]] += 1
            sub[check["status"]] += 1
        per_script[result["name"]] = {
            "pass": sub[PASS], "fail": sub[FAIL],
            "not_run": sub[NOT_RUN],
            "total": len(result["checks"])}
    return {"checks_total": sum(counts.values()),
            "pass": counts[PASS], "fail": counts[FAIL],
            "not_run": counts[NOT_RUN],
            "scripts": per_script}


def build_report(device, frida, script_results):
    """The machine-readable runtime-validation report:
    {device, frida, scripts, summary}. `device` carries the
    classification and the B1 status vocabulary; every check
    status is PASS / FAIL / NOT RUN."""
    return {"device": device, "frida": frida,
            "scripts": script_results,
            "summary": summarize(script_results)}


_BOGUS_PID = 999999


def bogus_pid():
    """A pid that cannot exist on the target (above the
    kernel's pid_max on Android), used for error recovery."""
    return _BOGUS_PID
