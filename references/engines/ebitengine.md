# Ebitengine — engine guide

Registry id: `ebitengine` · Status: **supported** · Fidelity: structural-summary · Deep module: `scripts/nar-ebiten.py`
Test reference: `tests/unit/test_deep_runtime.py::test_ebiten_buildinf_string_form`

## Packaging

Go binaries: the `Go buildinf:` block in lib/*.so, ebiten string marker, embedded assets census.

Registry path markers: JNI/symbol markers (see registry).

## Serialisation

Build-info block yields Go version and module/build settings as string evidence.

## Common protections

Go binaries are often stripped; build info survives stripping, symbols may not.

## Rebuild pitfalls

Keep runs bounded: native members over the 64 MiB scan cap are skipped and reported.

## Real run

```bash
python3 scripts/nar-ebiten.py <fixture:demo/NarDemo.apk>
```

```text
NAR Ebitengine deep dive: /home/hatch/workspace/nar-e2e-fixtures/demo/NarDemo.apk
Verdict: absent
Embedded assets: 0 (by extension: {})
```
