# App patterns — non-game Android apps

What `nar app` (`scripts/nar-app.py`) actually measures, aligned with the
registry's `app_frameworks` entries. No app framework in the registry is
`supported`: the highest status is `partial`. This guide does not upgrade
any of them.

## How nar-app measures

- Manifest pass (wired from nar-perms): components, declared permissions,
  launcher activity, foregroundServiceType, deep-link intent filters.
- DEX pass (narlib.dex): annotation-directory walk decoding annotation
  TYPES only for `@Composable` / `@JavascriptInterface`; superclass census
  (Activity, Fragment, RoomDatabase, SQLiteOpenHelper, Worker, JobService);
  method/field-reference census; a bounded code scan for
  `addJavascriptInterface` call sites and SharedPreferences co-occurrence
  strings; string-pool census for permissions, URLs, OAuth markers and
  JWT shapes.
- JWTs are reported as structure only (header alg + payload claim NAMES);
  the raw token is never stored, and a scrub pass removes credential-shaped
  strings from the whole report.
- Shipped databases are parsed read-only by narlib.sqlite (sqlite_master
  page walk only; the parser never opens a target DB with sqlite3).

## Real run (demo fixture)

```bash
python3 scripts/nar-app.py <fixture:demo/NarDemo.apk>
```

```text
NAR app intelligence: NarDemo.apk
============================================================
Verdict: present — 7 DEX classes, 2 activities, 2 layouts, 0 @Composable methods
Navigation: launcher com.example.nardemo.MainActivity; 0 routes, 0 deep links, 0 fragments
Permissions: 2 declared, 0 code-referenced, 2 declared but unreferenced by the DEX scan
Screen map: 4 entries; data flow: 3 edges
```

## Jetpack Compose — `jetpack-compose` (partial)

Detection: `@Composable`-annotated classes/methods from DEX annotation
directories (types only), listed as screens. Not decoded: recomposition,
state flow, navigation-compose route semantics. Composables in libraries
the app merely references (no defined class in the app's DEX) are invisible.

## Views / AndroidX — `androidx` (partial)

Detection: defined AndroidX class census, res/layout census with AXML root
elements, versions ONLY from shipped `META-INF/*.version` files — a family
without `.version` evidence reports version null, never an invented one.

## React Native / Flutter (presence only)

`nar app` reports libflutter.so / flutter_assets and bundle / libhermes.so
presence; widget and component counts are null by design (not derivable
from an AOT snapshot / Hermes bundle with the stdlib). Engine-level
evidence lives in `nar flutter` / `nar rn` and `references/engines/`.

## WebView hybrid — `android-webview-hybrid` (partial)

Detection: `addJavascriptInterface` call sites in DEX code plus the
`@JavascriptInterface` method census — that pair is the JS bridge surface.
The JavaScript side inside web assets is inventoried by nar-webassets,
not traced call-by-call.

## Storage

- SharedPreferences: file/key candidates from string constants co-occurring
  in methods that call SharedPreferences accessors — labelled heuristic in
  the output (a constant can be a key, a file name, or an unrelated literal).
- Room — `jetpack-room` (partial): RoomDatabase subclass census plus
  shipped `.db`/`.sqlite` schemas via narlib.sqlite (tables, columns,
  indexes). Room entity/DAO semantics and runtime-created databases are
  not in the artifact.
- Encrypted storage (detection only, never decrypted): SQLCipher (native
  lib name / net.sqlcipher refs / string marker), EncryptedSharedPreferences
  + MasterKey refs, AndroidKeyStore refs/strings.
- DataStore: preference/proto DataStore class references in the SDK census.

## Auth (structure only)

OAuth endpoint hosts from DEX URL strings, manifest redirect schemes,
Custom Tabs / AppAuth references. Token storage is reported as mechanism
LOCATIONS only (for example SharedPreferences / DataStore / SQLite), never
values. JWT presence is structure only (see above).

## Background work — `jetpack-workmanager` (partial)

Worker / ListenableWorker and JobService superclass census, AlarmManager
references, manifest foreground services with foregroundServiceType. Work
chains, constraints and schedules are runtime configuration, not decoded.

## Permissions in use

Declared (manifest) versus code-referenced (DEX `android.permission.*`
string constants + `Manifest$permission` field refs). "Declared but
unreferenced" means unreferenced BY THIS SCAN — reflection, native code,
dynamically built strings and SDK-merged manifests are invisible to it.
Candidates are leads, not proof of non-use.

## Identified-only frameworks

`kotlin`, `compose-multiplatform`, `android-support-legacy` and
`apache-httpclient-legacy` are DEX-marker detection in nar-triage only.
`play-integrity` is `server_side`: client presence is detectable, the
verdict is made on the developer's server and cannot be obtained from the
shipped app. `easyrpg` is a triage DEX marker with no engine family entry.
