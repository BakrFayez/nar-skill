# Dynamic analysis

Static analysis reads the APK. Dynamic analysis watches the app run.
Use it only when static evidence cannot answer the question, and only
on a device or emulator you own or are authorized to test.

## Prerequisites

- A device or emulator with USB debugging enabled, visible to adb:

```bash
adb devices
```

- The app installed on it (`adb install app.apk`), or pulled from it
  (`adb shell pm path <package>`, then `adb pull <remote-path>`).
- For Frida: a matching `frida-server` on the device and matching
  `frida-tools` on the desktop. Versions must match exactly or the
  connection fails with a protocol error.

Never run dynamic analysis against someone else's device, account, or
production service. Never intercept traffic you are not authorized to
inspect.

## adb and logcat basics

```bash
adb logcat -c                                  # clear the log
adb logcat -v time *:I                         # info and above, with timestamps
adb logcat -v time --pid=$(adb shell pidof -s <package>)
adb shell dumpsys package <package>            # installed-package facts
adb shell run-as <package> ls files/           # app-private files (debuggable builds only)
```

Logcat is noisy: filter by PID or tag, and reproduce one action at a
time. A log line is runtime evidence only when you can tie it to the
action you performed; background logs from other apps are not
evidence about your target.

`run-as` works only for debuggable builds. For release builds, use a
rooted test device or an emulator image you control. Never attempt
to bypass the platform's app-isolation on a device you do not own.

## Reading app data

An app's private data lives under `/data/data/<package>/` on the
device:

- `files/`, `cache/`: app files and cache.
- `databases/`: SQLite databases.
- `shared_prefs/`: XML preference files.
- `app_webview/`: WebView cache, cookies, local storage.
- `no_backup/`: files excluded from backup.

How to reach it depends on the build and the device:

- Debuggable build: `adb shell run-as <package>` gives a shell as
  the app's UID. List and pull from there.
- Rooted test device or emulator image you control: `adb shell su`
  or a direct `adb pull /data/data/<package>/`.
- `adb backup` exists on older Android but is deprecated, requires
  the user to approve on the device, and many apps opt out. Do not
  rely on it.

Pull the data to your machine and read it there. Do not edit the
live database on the device; copy first.

```bash
adb shell run-as <package> ls databases/
adb shell run-as <package> cat databases/app.db > work/app.db
adb shell run-as <package> cat shared_prefs/<package>_preferences.xml
```

Inspect a SQLite database read-only so opening it does not change
the file:

```bash
sqlite3 "file:work/app.db?mode=ro" ".tables"
sqlite3 "file:work/app.db?mode=ro" ".schema <table>"
sqlite3 "file:work/app.db?mode=ro" "SELECT * FROM <table> LIMIT 20;"
```

`shared_prefs` files are plain XML: read them directly. Look for
stored endpoints, feature flags, cached tokens, and timestamps, and
tie each value back to the code that wrote it (search jadx output
for the preference key).

Limits: app data is runtime state, not code. A value in a database
proves what the app stored at that moment, not what the code always
does. Data from a device you do not own is off limits: only read
app data on your own test device or emulator.

Verification note: the sqlite3 commands above were verified locally
on a test database (`.tables`, `.schema`, `SELECT`, read-only
open). The `run-as` and pull commands are standard adb and were not
run against a device here.

## Frida hooks

Frida injects JavaScript into a running process to trace calls and
inspect arguments. A minimal trace script:

```javascript
// trace-login.js: trace one method's calls (example, adapt names)
Java.perform(function () {
  var ApiClient = Java.use("com.example.ApiClient");
  ApiClient.login.implementation = function (user, pass) {
    console.log("[login] user=" + user);
    return this.login(user, pass);
  };
});
```

```bash
frida -U -f <package> -l trace-login.js
```

`-U` selects the USB device, `-f` spawns the app by package name,
`-l` loads the script. The app resumes once the script loads. Add
`--pause` only when you want the main thread left paused after
spawning. Older tutorials use `--no-pause`; current frida-tools
(17.x) has no such flag, so do not copy it.

Rules:

- Hook the smallest surface that answers the question. Broad hooks
  (every method of every class) flood the log and slow the app until
  behavior changes.
- Log arguments and return values, not credentials. Never print
  passwords, tokens, or session cookies into a log you will keep.
- A hooked method that is never called is itself a finding: the code
  path is dead, or reached by another route. Record the negative.
- Frida changes timing. A race or timeout that appears only under
  Frida is a measurement artifact until reproduced without it.

## What dynamic analysis can and cannot prove

Can prove:

- Which code paths actually execute for a given input.
- What network endpoints are contacted, with what payloads (on a
  device where you can observe your own traffic).
- What files, databases, and preferences the app reads and writes.
- Runtime-resolved targets of reflection and dynamic loading.

Cannot prove:

- That a code path never executes (you only observed the inputs you
  tried).
- That a behavior is absent in other builds, devices, or locales.
- Intent: a network call proves contact, not purpose.

Always pair a dynamic finding with its static anchor: the class and
method the hook targeted, and the input that triggered it. A log line
without a static anchor is hard to reproduce and harder to trust.

## Emulator notes

- Use an x86_64 emulator image matching the app's ABIs, or an ARM
  image for ARM-only apps. An ARM-only `.so` will not load on an
  x86_64 emulator without translation, and the failure looks like an
  app bug.
- Emulator detection exists in some apps and games. If the app
  refuses to run on an emulator, that is a finding about its
  environment checks, not a reason to spoof the environment.
- Snapshots make reproduction cheap: snapshot before the action,
  restore, repeat.
