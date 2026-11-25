# NAR Runtime Validation Report — 2.6.2 Stability & Certification Campaign

Scope: re-validation of the runtime subsystem on the
final stabilized tree, after the campaign's nar-runtime
changes (D-06 frida-server presence, D-11 device
classification, D-15 exit codes, D-12 Frida script
userinfo redaction). Emulator-provable subset only.

PHYSICAL_DEVICE_VALIDATION: NOT RUN

No physical device is attached to this machine
(`adb devices` empty before the emulator was started and
after it was shut down). Nothing in this report is
physical-device evidence; the owner's device run remains
the outstanding item, as it has been since 2.6.0.

## Environment

- AVD `nar_lean`, API 26, google_apis x86_64, QEMU TCG
  software emulation (no /dev/kvm on this VM;
  `ANDROID_I_WANT_MY_TCG=yes`, `-accel off`), cold boot.
- frida-server 17.27.4 (android-x86_64), host Frida
  17.27.4 — major.minor agreement confirmed by validate.
- Test target: the controlled demo application used by
  the 2.6.x runtime work (x86_64 build), installed from
  its APK by the suite.

## Results on the final tree

| Check | Result |
|---|---|
| `nar-runtime validate` (device attached) | PASS — every check pass except one warning: the on-device server binary carries the un-suffixed name, so its ABI cannot be confirmed from the listing (action printed: push the arch-named build). Exit 0. |
| Device classification | `emulator`, evidence: strong markers ro.kernel.qemu, ro.hardware, ro.product.model, serial — reported as an emulator, never laundered. |
| Frida validation suite (`tests/runtime_validation/run_frida_validation.py`) | **28 PASS / 0 FAIL / 0 NOT RUN** — network-observe.js, file-io-observe.js, jni-trace.js, java-api-trace.js: 7/7 each (syntax, attach, banner events, event serialization, clean detach, spawn where applicable). |
| `nar-runtime validate` (no device) | NOT READY, **exit 1** (D-15 behavior verified live). |
| Unit-level runtime suites | In the full battery: test_phase262_runtime_validation, test_phase262_frida_suite, test_runtime_sessions all pass. |

## Campaign notes on the runtime path

- First suite run in this campaign failed all four
  attach checks. Diagnosis (recorded, not hidden): the
  on-device frida-server had been started under the
  shell user (jailed — Frida demands Gadget to attach on
  jailed Android), and adbd was not root. After
  `adb root` and a server restart, a manual attach
  round-trip succeeded in 0.4 s and the suite passed
  28/28 unchanged. The failure was environmental, not a
  code defect; no code was changed to make the suite
  pass.
- D-06 verified live in the validate output: the
  directory listing contains both the server binary and
  a `frida-server.log` sidecar; presence is reported
  from the binary candidate (the log alone no longer
  counts — unit-tested in test_stability_campaign.py).
- D-11 unit-verified: sparse property sets classify as
  `unknown`, never `physical`; an Intel hardware string
  is a weak marker only.
- D-12: network-observe.js strips URL userinfo before
  logging (node --check passes; the e2e harness's Frida
  syntax case passes).

## Standing limitations

- Emulator evidence is emulator evidence. Timing under
  TCG is not representative of hardware.
- Spawn-mode and attach-mode were both exercised by the
  suite on the emulator; neither is claimed for any
  physical device.

MIT License.
