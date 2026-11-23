# Frida scripts

The `scripts/frida/` directory holds four ready observation scripts.
They watch a running app and log what it does. They never modify
arguments, return values, or app behavior, and they never print
credentials, tokens, or file contents.

Runtime execution status (2026-11-23): network-observe.js and
file-io-observe.js have been executed live on an Android
emulator (API 26, QEMU TCG), with frida-server 17.27.4 as
root — both attached to a running demo app and, in a later
session, loaded into Frida-spawned demo processes with the
resume-first recipe under "Running a script" below; every
hook installed and the scripts' own output was captured
(see "Verification" below). jni-trace.js and java-api-trace.js
have not yet run live in either mode. Nothing here has run
on a physical device yet. Run the scripts first on a test
app you own before trusting them on a real target.

## Running a script

```bash
frida -U -f <package> -l scripts/frida/java-api-trace.js
```

`-U` selects the USB device, `-f` spawns the app by package name,
`-l` loads the script. The app resumes once the script loads. Run
one script at a time; loading several at once mixes their output
and multiplies the slowdown.

On very slow emulation (QEMU TCG without KVM), the one-command
spawn above cannot work: Android's ActivityManager kills a
started process that does not attach within its ~10 s
process-start timeout, and a Frida-gated child cannot attach
while gated, so the child is killed during script load
("the connection is closed"). The verified recipe on such
hosts is resume-first: spawn the app with the Frida API
(`device.spawn`), resume it in the very next call, let the
process settle for ~40-50 s, then load the script against
the spawned pid with the command form
`frida -U -p <spawned pid> -l <script>`. Hooks then install
seconds after the app starts instead of before its first
instruction. Both observation scripts below were verified
live this way (and by plain attach) on an API 26 emulator.

Before running anything, check that a device is actually visible:

```bash
frida-ls-devices
```

On this machine that listed only `local`, `barebone`, and `socket`,
no USB device. `frida-ps -U` with no device attached waits instead
of failing fast, so check `frida-ls-devices` first rather than
wondering why a command hangs.

## Version matching

The desktop tools and the on-device server must match exactly, or
the connection fails with a protocol error. This skill was verified
with frida-tools 17.27.4:

```bash
frida --version
frida-compile --version
```

Both printed `17.27.4`. The device needs frida-server 17.27.4 for
its CPU architecture (usually `android-arm64`). Downloading the
server, pushing it to the device, and starting it were exercised
on 2026-11-23 against an x86_64 emulator (server build
`android-x86_64`, started as root after `adb root`); the same
steps on a physical arm64 device remain untested.

## Rooted device vs emulator

- Rooted test device: the normal case. frida-server runs as root,
  injects into any app, and sees the app as it behaves on real
  hardware. Use a device you own, with a test account, never a daily
  driver with real data.
- Emulator: works when the app runs on the emulator at all. Match
  the emulator image to the app's ABIs: an ARM-only `.so` will not
  load on an x86_64 image without translation, and the failure looks
  like an app bug. Some apps and games detect emulators and refuse
  to run; that is a finding about their environment checks, not a
  reason to spoof the environment.
- Non-rooted device: frida-server cannot run, so these scripts do
  not apply. `frida-gadget` (embedding the agent in a repackaged
  app) is a different workflow and is not covered here.

## The four scripts

### java-api-trace.js

Traces calls of named Java methods: every overload, every call, with
argument types and return types. Edit the `TARGETS` list at the top
of the file to name the class and method your analysis needs:

```javascript
var TARGETS = [
    { className: "com.example.ApiClient", methodName: "login" },
];
```

String arguments are logged by length only, never by value. A class
or method that does not exist is logged and skipped, so a wrong
guess costs one log line, not a crash. `MAX_CALLS_PER_METHOD`
(default 200) caps logging per method so a hot method cannot flood
the log.

Example output (format only, not captured from a device):

```text
[java-api-trace] hooked: com.example.ApiClient.login(java.lang.String, java.lang.String)
[call] com.example.ApiClient.login(java.lang.String, java.lang.String) args=[<string len=12>, <string len=9>]
[return] com.example.ApiClient.login(java.lang.String, java.lang.String) -> <boolean>
```

### jni-trace.js

Traces JNI native-method registration and native call entry. It
hooks `RegisterNatives` by reading its address from the JNI
function table (entry 215, 0-based), with a libart.so export lookup
as fallback. For each registration it logs the class, the method
name, its signature, and the native function address, then watches
the native function for entry calls.

```text
[jni-register] class=com.example.NativeLib methods=3 via JNIEnv table
[jni-register]   process (Ljava/lang/String;)I -> libnative.so!process +0x1234 (0x...)
[jni-entry] com.example.NativeLib.process thread=1234 at libnative.so!process +0x1234 (0x...)
```

Set `TRACE_NATIVE_ENTRY` to false to log registrations only, and
`MAX_ENTRY_CALLS` (default 500) to cap entry logging. Register the
script with `-f` so it loads before the app: natives registered
before the script loads are invisible to it.

### file-io-observe.js

Observes file open, read, write, and delete activity. It hooks the
`java.io.FileInputStream`, `FileOutputStream`, and `RandomAccessFile`
constructors, `File.delete`/`mkdir`/`renameTo`, and the low-level
`libcore.io.IoBridge.open` that sits behind most Java file APIs.
Only paths, operation names, and byte counts are logged; file
contents are never read or printed.

```text
[file-io] open FileInputStream /data/data/com.example/files/config.json read
[file-io] open (IoBridge) /data/data/com.example/databases/app.db read/write
[file-io] delete /data/data/com.example/cache/tmp-1.bin
```

`PATH_FILTER` limits logging to paths containing a listed substring;
leave it empty to log everything (noisy). `LOG_READ_WRITE` is false
by default; turn it on only when you need byte counts for reads and
writes, and expect far more output.

### network-observe.js

Observes network connections: `java.net.URL.openConnection`,
`HttpURLConnection.connect` and `getResponseCode`, `OkHttpClient`
requests, and `Socket.connect`. URLs are logged without query
values, header names without header values, and bodies are never
read, so tokens and session data cannot leak into the log.

```text
[net] openConnection https://api.example.com/v1/status?<query len=18>
[net] connect POST https://api.example.com/v1/login
[net] response 200 https://api.example.com/v1/login
[net] okhttp GET https://cdn.example.com/a/b.png headers=[User-Agent, Accept]
[net] socket connect 93.184.216.34:443
```

`WATCH_HOSTS` marks connections to listed hosts with `[watch]` so
they stand out. If the app uses OkHttp under a shaded package name,
the `okhttp3.OkHttpClient` lookup fails, the script logs that and
moves on, and you adapt the class name in the file. The script
performs no TLS interception and no bypass of any kind.

## Reading the output

- Every line starts with a tag (`[call]`, `[jni-register]`,
  `[file-io]`, `[net]`) so you can filter with `grep` while the
  app runs.
- A hooked method that is never called is itself a finding: the
  code path is dead, or reached by another route. Record the
  negative.
- Pair each finding with its static anchor: the class and method
  from the decompiled code, and the input that triggered the call.
  A log line without a static anchor is hard to reproduce.
- Frida changes timing. A race or timeout that appears only under
  Frida is a measurement artifact until reproduced without it.

## Verification

Each script passed three checks on this machine (Node v24.22.1,
frida-tools 17.27.4):

```bash
node --check scripts/frida/java-api-trace.js
node --check scripts/frida/jni-trace.js
node --check scripts/frida/file-io-observe.js
node --check scripts/frida/network-observe.js
frida-compile scripts/frida/java-api-trace.js -o java-api-trace.compiled.js
```

`node --check` passed on all four. `frida-compile` also built all
four without a device (output written to the verification work
directory), producing bundles of 4,340 bytes
(java-api-trace), 7,381 bytes (jni-trace), 8,622 bytes
(file-io-observe), and 10,009 bytes (network-observe). A stub
harness then ran each script in plain Node with fake Frida globals
(`Java.use` throwing for every class) and confirmed the error paths
behave: missing classes are logged and skipped, and no script throws
uncaught at load time.

Device-run addendum (2026-11-23): two of the four scripts have
since run against a real app process — network-observe.js and
file-io-observe.js, on the bundled demo app on an API 26
emulator (frida-server 17.27.4 as root, QEMU TCG host), first
attached to the running app and later loaded into
Frida-spawned processes using the resume-first recipe under
"Running a script" (the one-command gated spawn loses
ActivityManager's ~10 s process-start-timeout race under
TCG; logcat records the kill as "start timeout"). Every hook
they install took effect in the live processes
(URL/HttpURLConnection/Socket for network-observe; the stream
constructors, File operations, and libcore.io.IoBridge.open for
file-io-observe; OkHttp was absent in the demo and skipped
gracefully, as written). The demo app opens no connections and
does no Java-layer file I/O by design, so the sessions captured
hook installation rather than connection/file events; event
capture against an app that performs such operations is still
outstanding. jni-trace.js and java-api-trace.js remain unrun
live in either mode, and no script has run on a physical
device.
