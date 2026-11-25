# Web assets (assets/www) — engine guide

Registry id: `web-assets` · Status: **supported** · Fidelity: structural-summary · Deep module: `scripts/nar-webassets.py`
Test reference: `tests/unit/test_deep_web.py::test_webassets_census_and_markers`

## Packaging

Any www-like root: assets/www, assets/web, assets/public, assets/html with an index.html.

Registry path markers: assets/www/.

## Serialisation

Plain HTML/JS/CSS census by extension; index.html parsed for title, script and link lists.

## Common protections

Framework string markers in bundles are heuristic evidence, labelled as such.

## Rebuild pitfalls

Overlap is normal: a root can be claimed by Cordova/Capacitor/RPG Maker too; nar-webassets states the overlap.

## Real run

```bash
python3 scripts/nar-webassets.py <fixture:frameworks/cordova.apk>
```

```text
NAR web-assets deep dive: /home/hatch/workspace/nar-e2e-fixtures/frameworks/cordova.apk
PRESENT: www-like web root(s) with index.html
Root assets/www/: 2 files, 16 bytes, by extension {'html': 1, 'js': 1}
  index.html: title=None, scripts=[], links=[], base=None
Framework string evidence (heuristic): {'webpack': 0, 'angular': 0, 'react': 0, 'vue': 0, 'svelte': 0, 'ionic': 0} over 1 bundles
Overlap: Cordova evidence present (config.xml / cordova*.js): the web root is also claimed by Cordova (nar-cordova)
```
