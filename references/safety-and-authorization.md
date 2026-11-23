# Safety and authorization

NAR is an analysis system. This page states the boundary
every module is built to, so there is no ambiguity when a
request approaches it.

## Authorized uses

- Analyzing apps and games you own or are authorized to
  test: your own builds, authorized security research,
  compatibility and interoperability work, education.
- Runtime observation on your own device, of apps you are
  authorized to instrument.
- Signing and verifying **your own** builds (the signing
  workflow in signatures-and-integrity.md exists for that).

## Never

- Killing or bypassing signature verification, license
  checks, DRM, or Play Integrity verdicts.
- Unlocking VIP/paid features, granting unlimited paid
  currency or items, or otherwise defeating a payment
  boundary — in any app, including games.
- Extracting another party's credentials, keys, or session
  material, or decrypting protected payloads whose keys are
  not yours.
- Repackaging someone else's app as your own.

Detection and reporting of protection systems (packers,
pinning, RASP, DRM presence) is analysis; defeating them is
out of scope. Where a protection is present, NAR reports its
presence and class — and stops there.

## Data handling

- Reports name evidence, not people. Tested applications
  are never named in this repository's code, docs, tests, or
  changelog; findings are described generically.
- Endpoint inventories are built from static strings; NAR
  never contacts the endpoints it lists.
- API-key *presence* in bundled config files is reported;
  key values are not printed.
- Runtime scripts observe and log; they do not modify
  requests, responses, TLS behavior, arguments, or return
  values.

## When a request crosses the line

Decline that part, state the boundary plainly, and offer
the legitimate alternative (analyze your own build, or
build the feature in your own original app).
