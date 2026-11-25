# React Native — engine guide

Registry id: `react-native` · Status: **partial** · Fidelity: structural-summary · Deep module: `scripts/nar-rn.py`
Test reference: `tests/unit/test_synthetic_fixtures.py`

## Packaging

assets/index.android.bundle (Hermes .hbc or plain JS), libhermes.so / libreactnative.so; new arch adds Fabric/TurboModule libs.

Registry path markers: libreactnativejni.so, libhermes.so, libfabricjni.so, libturbomodulejsijni.so.

## Serialisation

Hermes bytecode has an 8-byte magic + header with function/string/identifier counts.

## Common protections

Bundles may be minified/obfuscated; module attribution is not recovered.

## Rebuild pitfalls

The new-arch deciding check is the IS_NEW_ARCHITECTURE_ENABLED flag, not library presence alone.

## Honest boundary (registry reason)

Hermes header parse and bundle inventory exist; Hermes module-name attribution and bytecode decompilation are not built in (capability matrix).

## Detection run

```bash
python3 scripts/nar-engines.py <target> --json
```

The engines verdict for this family is produced by `nar engines <target> --deep`, which dispatches to its deep module.
