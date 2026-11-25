# Qt for Android — engine guide

Registry id: `qt` · Status: **partial** · Fidelity: structural-summary · Deep module: `scripts/nar-qt.py`
Test reference: `tests/unit/test_deep_archives.py::TestQt`

## Packaging

libQt5Core/libQt6Core + libqtforandroid.so, .rcc resource archives, .qmlc/.jsc compiled QML.

Registry path markers: libqt5core.so, libqt6core.so, libqtforandroid.so.

## Serialisation

RCC v1/v2: 20-byte big-endian header + 22-byte tree nodes; zlib-compressed payloads flagged per node.

## Common protections

Resources may be compressed; payloads are listed with flags, not silently inflated.

## Rebuild pitfalls

No real Qt corpus locally: the tree walk is synthetic-fixture verified only.

## Honest boundary (registry reason)

Deep dive parses Qt RCC v1/v2 headers and walks the 22-byte tree-node records recursively (bounded nodes/depth, every offset validated) reconstructing resource paths with sizes and compression flags (zlib payloads), plus .qmlc/.jsc identification. No real Qt corpus locally; layout from public format documentation, synthetic-fixture verified.

## Detection

```bash
python3 scripts/nar-engines.py <target> --json
```

No local fixture run is claimed in this guide for this family; the registry reason above states the verified boundary.
