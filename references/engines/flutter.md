# Flutter — engine guide

Registry id: `flutter` · Status: **partial** · Fidelity: structural-summary · Deep module: `scripts/nar-flutter.py`
Test reference: `tests/unit/test_synthetic_fixtures.py`

## Packaging

libflutter.so (engine) + libapp.so (AOT Dart) per ABI, assets/flutter_assets/.

Registry path markers: libflutter.so, libapp.so.

## Serialisation

Dart code is an AOT snapshot object graph inside libapp.so, not source or bytecode files.

## Common protections

Snapshot obfuscation splits/strips symbol names.

## Rebuild pitfalls

Widget counts are not derivable from the snapshot with the stdlib; report presence, not counts.

## Honest boundary (registry reason)

Fingerprint + flutter_assets inventory only; Dart snapshot/VM structure parsing and symbol recovery are not implemented (capability matrix).

## Detection run

```bash
python3 scripts/nar-engines.py <target> --json
```

The engines verdict for this family is produced by `nar engines <target> --deep`, which dispatches to its deep module.
