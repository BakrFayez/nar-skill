# Frida validation suite (test tooling)

Validates the four bundled Frida observation scripts
(`scripts/frida/`) end to end against a controlled test app:
syntax, device connectivity, process attachment, banner
events, event serialization, clean detachment, and error
recovery. Every check ends as `PASS`, `FAIL`, or `NOT RUN`
(with a reason) in a machine-readable JSON report.

This is test tooling, not a shipped surface — the shipped
runtime-validation surface is `nar-runtime.py validate`. The
suite lives under `tests/` because it needs a live device
and a host Frida install and produces a report *about* the
bundled scripts rather than analyzing a target.

## Run

```sh
python3 run_frida_validation.py \
    --package <controlled-test-package> \
    --apk <test.apk> \
    --frida-server-bin <frida-server build for the device ABI> \
    --report /path/to/validation-report.json
```

`--serial` selects a device; `--session-secs` sets how long
each script session runs (default 15).

## Honesty rules

- No device attached: every device-dependent check is
  `NOT RUN` with that reason — never `PASS`. Only the
  host-side syntax checks run.
- The report's device section carries nar-runtime's own
  classification and capability statuses. An emulator result
  is labeled an emulator result; it is never
  physical-device proof.
- Reports from local validation runs are working evidence,
  not release documentation; keep them with the run's local
  evidence, not in this repository's docs.

Research by Bakr Fayez.
