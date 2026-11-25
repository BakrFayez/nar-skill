# Example prompts

Ready-to-use prompts for asking an AI agent to work with
NAR. Copy one, replace the file name with your own APK,
and send it. Each prompt is written to produce evidence
with verification labels — verified facts, indicators,
and UNVERIFIED items kept separate — which is how NAR
reports everything.

## Full analysis

> Use the NAR skill to run a full analysis on this APK: app.apk — build the complete case with report, graph, and investigation, and summarize the verified facts only.

## Engine identification

> Use NAR to identify how this game was built: engine, engine version evidence, native libraries, and content packaging (pak / IoStore / asset bundles). Separate confirmed detections from indicators.

## Security & permissions audit

> Use NAR to audit this APK: permissions, exported components, network endpoints and their classification, protection systems, and security findings — every finding with its evidence and verification status.

## Version comparison

> Use NAR to compare app-v1.apk and app-v2.apk: what changed in permissions, components, endpoints, native libraries, and engine version?

## Deep game analysis

> Use NAR to analyze this game's containers end to end: extract the package inventory, parse the packages, map class and dependency relationships into the graph, and tell me which content is encrypted or compressed with unsupported codecs — named and counted, never guessed.

## Pre-install triage

> Use NAR to triage this APK before I install it: signing, permissions risk, trackers/endpoints, and anything suspicious — with confidence labels, no speculation.

## Case verification

> Use NAR to verify this case directory: check evidence integrity, graph consistency, and export/import round-trip, and report every failure with its reason.

## Rebuild blueprint

> Use the NAR skill to fully reverse-engineer app.apk, then turn the analysis into a rebuild blueprint I can implement from: (1) Run the complete NAR case analysis (triage, fingerprint, engines, DEX, native, network, assets, graph, investigation). (2) From the verified evidence only, produce a feature map: every feature the app has, what it does, and which components, permissions, endpoints, and native libraries implement it. (3) Reconstruct the architecture: tech stack and engine, data model, storage, networking layer, and how the main flows connect — screen by screen / module by module, based on the graph and investigation documents. (4) Write it up as a rebuild specification: features list, architecture, data flows, and an implementation order — detailed enough that I can build my own original app with the same features and structure. (5) Mark anything you could not verify as UNVERIFIED instead of guessing, and list what is server-side and therefore not recoverable from the APK.

## Ask anything (nar ask)

> Use the NAR skill to answer this question about app.apk: "How is the player's progress saved, and where exactly?" Give me the full Answer Contract — the answer, the evidence it rests on, the confidence, and, if any part is unknown, the named reason and the cheapest probe that would resolve it. Never a bare "I don't know".

> Use NAR to ask app.apk: "What can you NOT tell me about this app, and why?" List every gap with its named reason (encrypted, server-side, stripped, unsupported format) and what it would take to close each one.

## Rebuild specification (nar blueprint)

> Use the NAR skill to produce a rebuild specification for app.apk with `nar blueprint`: all nine files (features, architecture, data model, flows, assets, network, build order, unrecoverable, unknowns), every claim cited to case evidence or marked inferred, and the unrecoverable list explicit — server-side logic, encrypted payloads, and stripped native code named with their reasons.

## Coverage gaps (nar coverage)

> Use NAR to show me the coverage matrix and the gap report: which engines, formats, script types, and animation systems are supported, which are partial or identified-only, and for each gap the reason and the cheapest probe.

## Atlases and animation (nar atlas / nar anim)

> Use the NAR skill to analyze how game.apk's characters and vehicles are animated: parse its sprite atlases, group the parts, classify each composition (vehicle / character / UI / environment), and name the animation driver for each group — skeletal, physics, sprite-swap, or shader — with evidence and confidence for every claim.

## Script and bytecode census (nar script)

> Use NAR to census every script and bytecode format inside app.apk — Lua, GDScript, Dart, Hermes, JavaScript bundles, WebAssembly, .NET CIL, Python bytecode — with structural counts per format, and anything encrypted or custom-VM named and counted, never presented as decoded source.

## App intelligence (nar app)

> Use the NAR skill to map this app: every screen and how navigation flows between them, where it stores data (SharedPreferences keys, SQLite schemas, DataStore), which third-party SDKs it ships with versions, which declared permissions its code never references, and its tracking and consent surface — every item with evidence.
