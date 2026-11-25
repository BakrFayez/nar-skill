# Adobe AIR — engine guide

Registry id: `adobe-air` · Status: **partial** · Fidelity: structural-summary · Deep module: `scripts/nar-air.py`
Test reference: `tests/unit/test_deep_web.py::test_air_descriptor_and_swf`

## Packaging

META-INF/AIR/application.xml descriptor is the only reliable entry marker, plus the launched SWF.

Registry path markers: META-INF/AIR/application.xml.

## Serialisation

SWF: FWS/CWS (zlib) / ZWS (LZMA) header + tag stream; DoABC tags carry ActionScript bytecode.

## Common protections

DoABC is counted and sized only; ABC bytecode is not decoded.

## Rebuild pitfalls

A bare .swf is not an AIR app (web fallbacks bundle Flash); require the descriptor.

## Honest boundary (registry reason)

Descriptor and SWF structure are parsed (header, tag census, ExportAssets/SymbolClass symbol names), but DoABC tags are counted and sized only: ABC bytecode is not decoded, so ActionScript semantics are not reconstructed.

## Detection

```bash
python3 scripts/nar-engines.py <target> --json
```

No local fixture run is claimed in this guide for this family; the registry reason above states the verified boundary.
