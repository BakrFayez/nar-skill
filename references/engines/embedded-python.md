# Embedded Python — engine guide

Registry id: `embedded-python` · Status: **supported** · Fidelity: structural-summary · Deep module: `scripts/nar-python.py`
Test reference: `tests/unit/test_deep_runtime.py::test_python_pyc_census_and_kivy`

## Packaging

libpython3.x.so / libpython2.7.so, .pyc/.pyo members, Kivy markers (org/kivy/android, .kv layouts, main.py).

Registry path markers: libpython3, libpython2.7.so.

## Serialisation

.pyc headers carry the interpreter magic; nar-python maps it to a Python version and censuses code objects.

## Common protections

Compiled files may be encrypted by packers; headers then fail validation per file.

## Rebuild pitfalls

Ren'Py also embeds Python: the DEX markers say whose runtime it is when knowable.

## Real run

```bash
python3 scripts/nar-python.py <fixture:frameworks/kivy.apk>
```

```text
NAR embedded Python deep dive: /home/hatch/workspace/nar-e2e-fixtures/frameworks/kivy.apk
Verdict: present
Compiled Python files: 0 (0 code-parsed)
libpython: lib/arm64-v8a/libpython3.11.so (Python 3.11)
Kivy: 0 .kv files, main.py=False, main.pyc=False
```
