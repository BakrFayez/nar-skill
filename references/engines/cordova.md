# Cordova (hybrid) — engine guide

Registry id: `cordova` · Status: **supported** · Fidelity: structural-summary · Deep module: `scripts/nar-cordova.py`
Test reference: `tests/unit/test_deep_web.py::test_cordova_merged_plugins`

## Packaging

assets/www/ web root + cordova.js / versioned cordova-*.js / phonegap.js, config.xml with a <widget> root.

Registry path markers: assets/www/cordova.js, assets/www/cordova-1., assets/www/cordova-2., assets/www/phonegap.js.

## Serialisation

Plugin list merges config.xml <feature> entries with cordova_plugins.js module metadata.

## Common protections

Web payload is plain JS/HTML; obfuscation is bundle-level only.

## Rebuild pitfalls

A www root alone is web-assets, not Cordova; the runtime script or widget config decides.

## Real run

```bash
python3 scripts/nar-cordova.py <fixture:frameworks/cordova.apk>
```

```text
NAR Cordova deep dive: /home/hatch/workspace/nar-e2e-fixtures/frameworks/cordova.apk
ABSENT: no Cordova <widget> config.xml found
  note: no config.xml with a <widget> root found in the resolved roots
```
