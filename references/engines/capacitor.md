# Capacitor (hybrid) — engine guide

Registry id: `capacitor` · Status: **supported** · Fidelity: structural-summary · Deep module: `scripts/nar-capacitor.py`
Test reference: `tests/unit/test_deep_web.py::test_capacitor_descriptor_plugins_markers`

## Packaging

capacitor.config.json, optional capacitor.plugins.json, web root at assets/public/ or the configured webDir.

Registry path markers: capacitor.config.json, capacitor.plugins.json, assets/public/.

## Serialisation

Config is JSON (appId/appName/webDir/server); plugins are native-side, so plugin evidence lives in DEX.

## Common protections

Web payload is plain; native bridge markers are capacitor.js / native-bridge.js.

## Rebuild pitfalls

No plugins.json shipped does not mean no plugins; check the DEX layer.

## Real run

```bash
python3 scripts/nar-capacitor.py <fixture:frameworks/capacitor.apk>
```

```text
NAR Capacitor deep dive: /home/hatch/workspace/nar-e2e-fixtures/frameworks/capacitor.apk
PRESENT: None (None) webDir=None via assets/capacitor.config.json
Server: scheme=None hostname=None url=absent
Web root assets/public/: 1 files, 6 bytes; index.html: yes, title None
Plugins (0):
Native markers: native-bridge.js=False, capacitor.js=False
  note: no capacitor.plugins.json shipped: Capacitor plugins are native-side code, so plugin evidence lives in the DEX layer (nar-engines / nar-dex), not in web assets
```
