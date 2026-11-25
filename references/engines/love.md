# LÖVE — engine guide

Registry id: `love` · Status: **supported** · Fidelity: structural-summary · Deep module: `scripts/nar-love.py`
Test reference: `tests/unit/test_deep_web.py::test_love_member_in_apk`

## Packaging

A .love archive (ZIP) inside the APK or as the target; luaopen_love native marker.

Registry path markers: JNI/symbol markers (see registry).

## Serialisation

conf.lua facts (identity, title, version, window size, disabled modules) read textually with bounded regex.

## Common protections

None standard; the archive is a plain ZIP in the common case.

## Rebuild pitfalls

A .love member proves the payload; the APK wrapper still needs its own triage.

## Real run

```bash
python3 scripts/nar-love.py <fixture:demo/NarDemo.apk>
```

```text
NAR LÖVE deep dive: /home/hatch/workspace/nar-e2e-fixtures/demo/NarDemo.apk
ABSENT: no .love archive found
  note: no .love archive found in the resolved roots
```
