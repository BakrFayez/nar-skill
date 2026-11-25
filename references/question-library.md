# Question library (`nar ask`)

Canonical source: `question-library.json` in this directory (schema: `schemas/question.schema.json`). This file is its human rendering; a unit test asserts both carry the same questions in the same order.

Each entry gives the canonical question, the intent the deterministic classifier returns for it, the shape of the worked answer, and the modules (case companions or tools) that serve it. Every answer is assembled in the Part 0.1 Answer Contract shape (QUESTION / ANSWER / EVIDENCE / CONFIDENCE / WHY / CHAIN / BOUNDARY, plus REASON / PROBE / COST when the confidence is unknown).

Total questions: 289

## Intent: identity

- Q: What is this app?
  - Intent: identity
  - Answer shape: identity summary: label, package, version, SDK levels, size and target hash, each cited to its companion property
  - Modules: case, manifest, application, fingerprint

- Q: What is this?
  - Intent: identity
  - Answer shape: identity summary: label, package, version, SDK levels, size and target hash, each cited to its companion property
  - Modules: case, manifest, application, fingerprint

- Q: What is this game?
  - Intent: identity
  - Answer shape: identity summary: label, package, version, SDK levels, size and target hash, each cited to its companion property
  - Modules: case, manifest, application, fingerprint

- Q: What package is this?
  - Intent: identity
  - Answer shape: identity summary: label, package, version, SDK levels, size and target hash, each cited to its companion property
  - Modules: case, manifest, application, fingerprint

- Q: What is the package name?
  - Intent: identity
  - Answer shape: identity summary: label, package, version, SDK levels, size and target hash, each cited to its companion property
  - Modules: case, manifest, application, fingerprint

- Q: What version is this app?
  - Intent: identity
  - Answer shape: identity summary: label, package, version, SDK levels, size and target hash, each cited to its companion property
  - Modules: case, manifest, application, fingerprint

- Q: What version is it?
  - Intent: identity
  - Answer shape: identity summary: label, package, version, SDK levels, size and target hash, each cited to its companion property
  - Modules: case, manifest, application, fingerprint

- Q: What is the app name?
  - Intent: identity
  - Answer shape: identity summary: label, package, version, SDK levels, size and target hash, each cited to its companion property
  - Modules: case, manifest, application, fingerprint

- Q: What is the name of this app?
  - Intent: identity
  - Answer shape: identity summary: label, package, version, SDK levels, size and target hash, each cited to its companion property
  - Modules: case, manifest, application, fingerprint

- Q: Who made this app?
  - Intent: identity
  - Answer shape: identity summary: label, package, version, SDK levels, size and target hash, each cited to its companion property
  - Modules: case, manifest, application, fingerprint

- Q: Who developed this game?
  - Intent: identity
  - Answer shape: identity summary: label, package, version, SDK levels, size and target hash, each cited to its companion property
  - Modules: case, manifest, application, fingerprint

- Q: How big is it in size?
  - Intent: identity
  - Answer shape: identity summary: label, package, version, SDK levels, size and target hash, each cited to its companion property
  - Modules: case, manifest, application, fingerprint

- Q: What size is the file?
  - Intent: identity
  - Answer shape: identity summary: label, package, version, SDK levels, size and target hash, each cited to its companion property
  - Modules: case, manifest, application, fingerprint

- Q: What is its identity?
  - Intent: identity
  - Answer shape: identity summary: label, package, version, SDK levels, size and target hash, each cited to its companion property
  - Modules: case, manifest, application, fingerprint

- Q: Which app is this?
  - Intent: identity
  - Answer shape: identity summary: label, package, version, SDK levels, size and target hash, each cited to its companion property
  - Modules: case, manifest, application, fingerprint

- Q: Which game is this?
  - Intent: identity
  - Answer shape: identity summary: label, package, version, SDK levels, size and target hash, each cited to its companion property
  - Modules: case, manifest, application, fingerprint

- Q: What label does it carry?
  - Intent: identity
  - Answer shape: identity summary: label, package, version, SDK levels, size and target hash, each cited to its companion property
  - Modules: case, manifest, application, fingerprint

- Q: What version name and version code does it declare?
  - Intent: identity
  - Answer shape: identity summary: label, package, version, SDK levels, size and target hash, each cited to its companion property
  - Modules: case, manifest, application, fingerprint

- Q: What package and version does it declare?
  - Intent: identity
  - Answer shape: identity summary: label, package, version, SDK levels, size and target hash, each cited to its companion property
  - Modules: case, manifest, application, fingerprint

- Q: Tell me the identity of this target.
  - Intent: identity
  - Answer shape: identity summary: label, package, version, SDK levels, size and target hash, each cited to its companion property
  - Modules: case, manifest, application, fingerprint

- Q: What is the package, label and version?
  - Intent: identity
  - Answer shape: identity summary: label, package, version, SDK levels, size and target hash, each cited to its companion property
  - Modules: case, manifest, application, fingerprint

- Q: What version of the app is this?
  - Intent: identity
  - Answer shape: identity summary: label, package, version, SDK levels, size and target hash, each cited to its companion property
  - Modules: case, manifest, application, fingerprint

- Q: What is this application?
  - Intent: identity
  - Answer shape: identity summary: label, package, version, SDK levels, size and target hash, each cited to its companion property
  - Modules: case, manifest, application, fingerprint

- Q: Identify this target: package, version, size.
  - Intent: identity
  - Answer shape: identity summary: label, package, version, SDK levels, size and target hash, each cited to its companion property
  - Modules: case, manifest, application, fingerprint

## Intent: build

- Q: What engine?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: What language?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: What toolchain?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: What engine does it use?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: What engine is it built on?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: What language is it written in?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: What languages does it use?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: What toolchain was used to build it?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: What framework does it use?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: What frameworks are present?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: Is it built with Kotlin?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: Was it built with Kotlin?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: What compiler produced the DEX?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: What technology stack does it use?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: What is it made with?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: What was it made in?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: Is it IL2CPP or Mono?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: What engine version is it?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: Which engine family does it belong to?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: What framework markers are present?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: What is the build stack?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: How was it built?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: What engine, language and toolchain does it use?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: Does it use a game engine?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: What engine is this game?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: What language is the main code in?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

- Q: What toolchain produced this build?
  - Intent: build
  - Answer shape: build summary: detected engine/framework verdicts with confidence, language markers, toolchain versions and DEX totals
  - Modules: engines, frameworks, fingerprint, dex

## Intent: screens

- Q: What screens does it have?
  - Intent: screens
  - Answer shape: screen inventory: launcher activity, component counts, activity list and deep-link intent filters; for a named screen, its component record and the launcher entry point
  - Modules: permissions, manifest

- Q: What screens are there?
  - Intent: screens
  - Answer shape: screen inventory: launcher activity, component counts, activity list and deep-link intent filters; for a named screen, its component record and the launcher entry point
  - Modules: permissions, manifest

- Q: List the screens.
  - Intent: screens
  - Answer shape: screen inventory: launcher activity, component counts, activity list and deep-link intent filters; for a named screen, its component record and the launcher entry point
  - Modules: permissions, manifest

- Q: What activities does it declare?
  - Intent: screens
  - Answer shape: screen inventory: launcher activity, component counts, activity list and deep-link intent filters; for a named screen, its component record and the launcher entry point
  - Modules: permissions, manifest

- Q: How do I get to the settings screen?
  - Intent: screens
  - Answer shape: screen inventory: launcher activity, component counts, activity list and deep-link intent filters; for a named screen, its component record and the launcher entry point
  - Modules: permissions, manifest

- Q: What is the main screen?
  - Intent: screens
  - Answer shape: screen inventory: launcher activity, component counts, activity list and deep-link intent filters; for a named screen, its component record and the launcher entry point
  - Modules: permissions, manifest

- Q: What menus does it have?
  - Intent: screens
  - Answer shape: screen inventory: launcher activity, component counts, activity list and deep-link intent filters; for a named screen, its component record and the launcher entry point
  - Modules: permissions, manifest

- Q: Show me the screen inventory.
  - Intent: screens
  - Answer shape: screen inventory: launcher activity, component counts, activity list and deep-link intent filters; for a named screen, its component record and the launcher entry point
  - Modules: permissions, manifest

- Q: What deep links does it register?
  - Intent: screens
  - Answer shape: screen inventory: launcher activity, component counts, activity list and deep-link intent filters; for a named screen, its component record and the launcher entry point
  - Modules: permissions, manifest

- Q: Which screens are exported?
  - Intent: screens
  - Answer shape: screen inventory: launcher activity, component counts, activity list and deep-link intent filters; for a named screen, its component record and the launcher entry point
  - Modules: permissions, manifest

- Q: How do I get to the settings screen?
  - Intent: screens
  - Answer shape: screen inventory: launcher activity, component counts, activity list and deep-link intent filters; for a named screen, its component record and the launcher entry point
  - Modules: permissions, manifest

- Q: How do I get to the profile screen?
  - Intent: screens
  - Answer shape: screen inventory: launcher activity, component counts, activity list and deep-link intent filters; for a named screen, its component record and the launcher entry point
  - Modules: permissions, manifest

- Q: How do I get to the search screen?
  - Intent: screens
  - Answer shape: screen inventory: launcher activity, component counts, activity list and deep-link intent filters; for a named screen, its component record and the launcher entry point
  - Modules: permissions, manifest

- Q: How do I get to the home screen?
  - Intent: screens
  - Answer shape: screen inventory: launcher activity, component counts, activity list and deep-link intent filters; for a named screen, its component record and the launcher entry point
  - Modules: permissions, manifest

- Q: How do I get to the library screen?
  - Intent: screens
  - Answer shape: screen inventory: launcher activity, component counts, activity list and deep-link intent filters; for a named screen, its component record and the launcher entry point
  - Modules: permissions, manifest

- Q: How do I get to the player screen?
  - Intent: screens
  - Answer shape: screen inventory: launcher activity, component counts, activity list and deep-link intent filters; for a named screen, its component record and the launcher entry point
  - Modules: permissions, manifest

- Q: How do I get to the map screen?
  - Intent: screens
  - Answer shape: screen inventory: launcher activity, component counts, activity list and deep-link intent filters; for a named screen, its component record and the launcher entry point
  - Modules: permissions, manifest

- Q: How do I get to the chat screen?
  - Intent: screens
  - Answer shape: screen inventory: launcher activity, component counts, activity list and deep-link intent filters; for a named screen, its component record and the launcher entry point
  - Modules: permissions, manifest

- Q: How do I get to the store screen?
  - Intent: screens
  - Answer shape: screen inventory: launcher activity, component counts, activity list and deep-link intent filters; for a named screen, its component record and the launcher entry point
  - Modules: permissions, manifest

- Q: How do I get to the inbox screen?
  - Intent: screens
  - Answer shape: screen inventory: launcher activity, component counts, activity list and deep-link intent filters; for a named screen, its component record and the launcher entry point
  - Modules: permissions, manifest

- Q: How do I get to the gallery screen?
  - Intent: screens
  - Answer shape: screen inventory: launcher activity, component counts, activity list and deep-link intent filters; for a named screen, its component record and the launcher entry point
  - Modules: permissions, manifest

- Q: How do I get to the editor screen?
  - Intent: screens
  - Answer shape: screen inventory: launcher activity, component counts, activity list and deep-link intent filters; for a named screen, its component record and the launcher entry point
  - Modules: permissions, manifest

- Q: How do I get to the dashboard screen?
  - Intent: screens
  - Answer shape: screen inventory: launcher activity, component counts, activity list and deep-link intent filters; for a named screen, its component record and the launcher entry point
  - Modules: permissions, manifest

- Q: How do I get to the calendar screen?
  - Intent: screens
  - Answer shape: screen inventory: launcher activity, component counts, activity list and deep-link intent filters; for a named screen, its component record and the launcher entry point
  - Modules: permissions, manifest

## Intent: behaviour

- Q: How does login work?
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

- Q: How does search work?
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

- Q: How does checkout work?
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

- Q: How does sync work?
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

- Q: How do notifications work?
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

- Q: How do downloads work?
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

- Q: How does matchmaking work?
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

- Q: How does the shop work?
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

- Q: How does the leaderboard work?
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

- Q: How does offline mode work?
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

- Q: How does sharing work?
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

- Q: How does the player work?
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

- Q: How does chat work?
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

- Q: How does backup work?
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

- Q: How does restore work?
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

- Q: How does the tutorial work?
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

- Q: How does scoring work?
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

- Q: How does the inventory work?
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

- Q: How does crafting work?
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

- Q: What happens when the user logs in?
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

- Q: What happens when a level is completed?
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

- Q: Trace the login flow.
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

- Q: Trace the checkout flow.
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

- Q: How is the main feature implemented?
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

- Q: How does the settings feature work?
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

- Q: Explain the behaviour of the download feature.
  - Intent: behaviour
  - Answer shape: static trace: component -> matching DEX classes/methods -> investigation verified facts, with the static boundary named
  - Modules: dex, permissions, investigation, decompile

## Intent: storage

- Q: How is progress saved?
  - Intent: storage
  - Answer shape: storage summary: storage-API classes found in DEX (prefs/SQLite/Room/DataStore/…), subject-linked classes and save-like assets; values are runtime state
  - Modules: dex, assets

- Q: Where are my coins?
  - Intent: storage
  - Answer shape: storage summary: storage-API classes found in DEX (prefs/SQLite/Room/DataStore/…), subject-linked classes and save-like assets; values are runtime state
  - Modules: dex, assets

- Q: How are coins stored?
  - Intent: storage
  - Answer shape: storage summary: storage-API classes found in DEX (prefs/SQLite/Room/DataStore/…), subject-linked classes and save-like assets; values are runtime state
  - Modules: dex, assets

- Q: How is user data stored?
  - Intent: storage
  - Answer shape: storage summary: storage-API classes found in DEX (prefs/SQLite/Room/DataStore/…), subject-linked classes and save-like assets; values are runtime state
  - Modules: dex, assets

- Q: How are settings stored?
  - Intent: storage
  - Answer shape: storage summary: storage-API classes found in DEX (prefs/SQLite/Room/DataStore/…), subject-linked classes and save-like assets; values are runtime state
  - Modules: dex, assets

- Q: How is the inventory stored?
  - Intent: storage
  - Answer shape: storage summary: storage-API classes found in DEX (prefs/SQLite/Room/DataStore/…), subject-linked classes and save-like assets; values are runtime state
  - Modules: dex, assets

- Q: Where is progress kept?
  - Intent: storage
  - Answer shape: storage summary: storage-API classes found in DEX (prefs/SQLite/Room/DataStore/…), subject-linked classes and save-like assets; values are runtime state
  - Modules: dex, assets

- Q: How is progress stored?
  - Intent: storage
  - Answer shape: storage summary: storage-API classes found in DEX (prefs/SQLite/Room/DataStore/…), subject-linked classes and save-like assets; values are runtime state
  - Modules: dex, assets

- Q: What database does it use?
  - Intent: storage
  - Answer shape: storage summary: storage-API classes found in DEX (prefs/SQLite/Room/DataStore/…), subject-linked classes and save-like assets; values are runtime state
  - Modules: dex, assets

- Q: Does it use SQLite?
  - Intent: storage
  - Answer shape: storage summary: storage-API classes found in DEX (prefs/SQLite/Room/DataStore/…), subject-linked classes and save-like assets; values are runtime state
  - Modules: dex, assets

- Q: Does it use SharedPreferences?
  - Intent: storage
  - Answer shape: storage summary: storage-API classes found in DEX (prefs/SQLite/Room/DataStore/…), subject-linked classes and save-like assets; values are runtime state
  - Modules: dex, assets

- Q: How are high scores stored?
  - Intent: storage
  - Answer shape: storage summary: storage-API classes found in DEX (prefs/SQLite/Room/DataStore/…), subject-linked classes and save-like assets; values are runtime state
  - Modules: dex, assets

- Q: How is the save game stored?
  - Intent: storage
  - Answer shape: storage summary: storage-API classes found in DEX (prefs/SQLite/Room/DataStore/…), subject-linked classes and save-like assets; values are runtime state
  - Modules: dex, assets

- Q: Where are saves kept?
  - Intent: storage
  - Answer shape: storage summary: storage-API classes found in DEX (prefs/SQLite/Room/DataStore/…), subject-linked classes and save-like assets; values are runtime state
  - Modules: dex, assets

- Q: How is account data stored?
  - Intent: storage
  - Answer shape: storage summary: storage-API classes found in DEX (prefs/SQLite/Room/DataStore/…), subject-linked classes and save-like assets; values are runtime state
  - Modules: dex, assets

- Q: How are downloaded levels stored?
  - Intent: storage
  - Answer shape: storage summary: storage-API classes found in DEX (prefs/SQLite/Room/DataStore/…), subject-linked classes and save-like assets; values are runtime state
  - Modules: dex, assets

- Q: What storage does it use?
  - Intent: storage
  - Answer shape: storage summary: storage-API classes found in DEX (prefs/SQLite/Room/DataStore/…), subject-linked classes and save-like assets; values are runtime state
  - Modules: dex, assets

- Q: Describe its storage.
  - Intent: storage
  - Answer shape: storage summary: storage-API classes found in DEX (prefs/SQLite/Room/DataStore/…), subject-linked classes and save-like assets; values are runtime state
  - Modules: dex, assets

- Q: How is local data persisted?
  - Intent: storage
  - Answer shape: storage summary: storage-API classes found in DEX (prefs/SQLite/Room/DataStore/…), subject-linked classes and save-like assets; values are runtime state
  - Modules: dex, assets

- Q: Where is the wallet stored?
  - Intent: storage
  - Answer shape: storage summary: storage-API classes found in DEX (prefs/SQLite/Room/DataStore/…), subject-linked classes and save-like assets; values are runtime state
  - Modules: dex, assets

- Q: How are preferences stored?
  - Intent: storage
  - Answer shape: storage summary: storage-API classes found in DEX (prefs/SQLite/Room/DataStore/…), subject-linked classes and save-like assets; values are runtime state
  - Modules: dex, assets

- Q: How is game state saved?
  - Intent: storage
  - Answer shape: storage summary: storage-API classes found in DEX (prefs/SQLite/Room/DataStore/…), subject-linked classes and save-like assets; values are runtime state
  - Modules: dex, assets

- Q: How does storage work for progress?
  - Intent: storage
  - Answer shape: storage summary: storage-API classes found in DEX (prefs/SQLite/Room/DataStore/…), subject-linked classes and save-like assets; values are runtime state
  - Modules: dex, assets

- Q: Is progress saved locally or remotely?
  - Intent: storage
  - Answer shape: storage summary: storage-API classes found in DEX (prefs/SQLite/Room/DataStore/…), subject-linked classes and save-like assets; values are runtime state
  - Modules: dex, assets

## Intent: network

- Q: What does it talk to?
  - Intent: network
  - Answer shape: network surface: endpoint inventory with classification counts, hosts, network libraries and cleartext/pinning posture; purposes labelled inferred
  - Modules: endpoints, network-analysis

- Q: What endpoints does it use?
  - Intent: network
  - Answer shape: network surface: endpoint inventory with classification counts, hosts, network libraries and cleartext/pinning posture; purposes labelled inferred
  - Modules: endpoints, network-analysis

- Q: Which servers does it contact?
  - Intent: network
  - Answer shape: network surface: endpoint inventory with classification counts, hosts, network libraries and cleartext/pinning posture; purposes labelled inferred
  - Modules: endpoints, network-analysis

- Q: What API does it call?
  - Intent: network
  - Answer shape: network surface: endpoint inventory with classification counts, hosts, network libraries and cleartext/pinning posture; purposes labelled inferred
  - Modules: endpoints, network-analysis

- Q: What URLs are in the code?
  - Intent: network
  - Answer shape: network surface: endpoint inventory with classification counts, hosts, network libraries and cleartext/pinning posture; purposes labelled inferred
  - Modules: endpoints, network-analysis

- Q: What domains does it reference?
  - Intent: network
  - Answer shape: network surface: endpoint inventory with classification counts, hosts, network libraries and cleartext/pinning posture; purposes labelled inferred
  - Modules: endpoints, network-analysis

- Q: What hosts are used?
  - Intent: network
  - Answer shape: network surface: endpoint inventory with classification counts, hosts, network libraries and cleartext/pinning posture; purposes labelled inferred
  - Modules: endpoints, network-analysis

- Q: Describe its network surface.
  - Intent: network
  - Answer shape: network surface: endpoint inventory with classification counts, hosts, network libraries and cleartext/pinning posture; purposes labelled inferred
  - Modules: endpoints, network-analysis

- Q: What does it connect to?
  - Intent: network
  - Answer shape: network surface: endpoint inventory with classification counts, hosts, network libraries and cleartext/pinning posture; purposes labelled inferred
  - Modules: endpoints, network-analysis

- Q: What is this endpoint for?
  - Intent: network
  - Answer shape: network surface: endpoint inventory with classification counts, hosts, network libraries and cleartext/pinning posture; purposes labelled inferred
  - Modules: endpoints, network-analysis

- Q: Which backend does it use?
  - Intent: network
  - Answer shape: network surface: endpoint inventory with classification counts, hosts, network libraries and cleartext/pinning posture; purposes labelled inferred
  - Modules: endpoints, network-analysis

- Q: What network libraries does it use?
  - Intent: network
  - Answer shape: network surface: endpoint inventory with classification counts, hosts, network libraries and cleartext/pinning posture; purposes labelled inferred
  - Modules: endpoints, network-analysis

- Q: What requests does it make?
  - Intent: network
  - Answer shape: network surface: endpoint inventory with classification counts, hosts, network libraries and cleartext/pinning posture; purposes labelled inferred
  - Modules: endpoints, network-analysis

- Q: How does it communicate with the server?
  - Intent: network
  - Answer shape: network surface: endpoint inventory with classification counts, hosts, network libraries and cleartext/pinning posture; purposes labelled inferred
  - Modules: endpoints, network-analysis

- Q: What API hosts appear?
  - Intent: network
  - Answer shape: network surface: endpoint inventory with classification counts, hosts, network libraries and cleartext/pinning posture; purposes labelled inferred
  - Modules: endpoints, network-analysis

- Q: List the endpoints.
  - Intent: network
  - Answer shape: network surface: endpoint inventory with classification counts, hosts, network libraries and cleartext/pinning posture; purposes labelled inferred
  - Modules: endpoints, network-analysis

- Q: What is the main API endpoint for?
  - Intent: network
  - Answer shape: network surface: endpoint inventory with classification counts, hosts, network libraries and cleartext/pinning posture; purposes labelled inferred
  - Modules: endpoints, network-analysis

- Q: Does it use HTTPS everywhere?
  - Intent: network
  - Answer shape: network surface: endpoint inventory with classification counts, hosts, network libraries and cleartext/pinning posture; purposes labelled inferred
  - Modules: endpoints, network-analysis

- Q: What network calls are implied by the code?
  - Intent: network
  - Answer shape: network surface: endpoint inventory with classification counts, hosts, network libraries and cleartext/pinning posture; purposes labelled inferred
  - Modules: endpoints, network-analysis

- Q: Which hosts does the app talk to?
  - Intent: network
  - Answer shape: network surface: endpoint inventory with classification counts, hosts, network libraries and cleartext/pinning posture; purposes labelled inferred
  - Modules: endpoints, network-analysis

- Q: What endpoints are classified as third-party?
  - Intent: network
  - Answer shape: network surface: endpoint inventory with classification counts, hosts, network libraries and cleartext/pinning posture; purposes labelled inferred
  - Modules: endpoints, network-analysis

- Q: What is the analytics endpoint for?
  - Intent: network
  - Answer shape: network surface: endpoint inventory with classification counts, hosts, network libraries and cleartext/pinning posture; purposes labelled inferred
  - Modules: endpoints, network-analysis

- Q: What does the update endpoint do on the network?
  - Intent: network
  - Answer shape: network surface: endpoint inventory with classification counts, hosts, network libraries and cleartext/pinning posture; purposes labelled inferred
  - Modules: endpoints, network-analysis

- Q: Where does it send network requests?
  - Intent: network
  - Answer shape: network surface: endpoint inventory with classification counts, hosts, network libraries and cleartext/pinning posture; purposes labelled inferred
  - Modules: endpoints, network-analysis

## Intent: security

- Q: Is it protected?
  - Intent: security
  - Answer shape: security posture: findings with severity and verification status, protection records and coverage protection kinds; for visibility questions, the decompile served rung and fidelity
  - Modules: security-findings, report, decompile, coverage

- Q: Which packer?
  - Intent: security
  - Answer shape: security posture: findings with severity and verification status, protection records and coverage protection kinds; for visibility questions, the decompile served rung and fidelity
  - Modules: security-findings, report, decompile, coverage

- Q: Which packer is used?
  - Intent: security
  - Answer shape: security posture: findings with severity and verification status, protection records and coverage protection kinds; for visibility questions, the decompile served rung and fidelity
  - Modules: security-findings, report, decompile, coverage

- Q: Can static analysis see the logic?
  - Intent: security
  - Answer shape: security posture: findings with severity and verification status, protection records and coverage protection kinds; for visibility questions, the decompile served rung and fidelity
  - Modules: security-findings, report, decompile, coverage

- Q: Can static analysis see the code?
  - Intent: security
  - Answer shape: security posture: findings with severity and verification status, protection records and coverage protection kinds; for visibility questions, the decompile served rung and fidelity
  - Modules: security-findings, report, decompile, coverage

- Q: Is the code obfuscated?
  - Intent: security
  - Answer shape: security posture: findings with severity and verification status, protection records and coverage protection kinds; for visibility questions, the decompile served rung and fidelity
  - Modules: security-findings, report, decompile, coverage

- Q: What obfuscation is present?
  - Intent: security
  - Answer shape: security posture: findings with severity and verification status, protection records and coverage protection kinds; for visibility questions, the decompile served rung and fidelity
  - Modules: security-findings, report, decompile, coverage

- Q: Does it use certificate pinning?
  - Intent: security
  - Answer shape: security posture: findings with severity and verification status, protection records and coverage protection kinds; for visibility questions, the decompile served rung and fidelity
  - Modules: security-findings, report, decompile, coverage

- Q: What pinning is configured?
  - Intent: security
  - Answer shape: security posture: findings with severity and verification status, protection records and coverage protection kinds; for visibility questions, the decompile served rung and fidelity
  - Modules: security-findings, report, decompile, coverage

- Q: What security findings are there?
  - Intent: security
  - Answer shape: security posture: findings with severity and verification status, protection records and coverage protection kinds; for visibility questions, the decompile served rung and fidelity
  - Modules: security-findings, report, decompile, coverage

- Q: How secure is it?
  - Intent: security
  - Answer shape: security posture: findings with severity and verification status, protection records and coverage protection kinds; for visibility questions, the decompile served rung and fidelity
  - Modules: security-findings, report, decompile, coverage

- Q: What are the security issues?
  - Intent: security
  - Answer shape: security posture: findings with severity and verification status, protection records and coverage protection kinds; for visibility questions, the decompile served rung and fidelity
  - Modules: security-findings, report, decompile, coverage

- Q: Does it have DRM?
  - Intent: security
  - Answer shape: security posture: findings with severity and verification status, protection records and coverage protection kinds; for visibility questions, the decompile served rung and fidelity
  - Modules: security-findings, report, decompile, coverage

- Q: What DRM is present?
  - Intent: security
  - Answer shape: security posture: findings with severity and verification status, protection records and coverage protection kinds; for visibility questions, the decompile served rung and fidelity
  - Modules: security-findings, report, decompile, coverage

- Q: Is there tamper protection?
  - Intent: security
  - Answer shape: security posture: findings with severity and verification status, protection records and coverage protection kinds; for visibility questions, the decompile served rung and fidelity
  - Modules: security-findings, report, decompile, coverage

- Q: Does it do root detection?
  - Intent: security
  - Answer shape: security posture: findings with severity and verification status, protection records and coverage protection kinds; for visibility questions, the decompile served rung and fidelity
  - Modules: security-findings, report, decompile, coverage

- Q: What hardening is applied?
  - Intent: security
  - Answer shape: security posture: findings with severity and verification status, protection records and coverage protection kinds; for visibility questions, the decompile served rung and fidelity
  - Modules: security-findings, report, decompile, coverage

- Q: Is it vulnerable?
  - Intent: security
  - Answer shape: security posture: findings with severity and verification status, protection records and coverage protection kinds; for visibility questions, the decompile served rung and fidelity
  - Modules: security-findings, report, decompile, coverage

- Q: What protection systems are present?
  - Intent: security
  - Answer shape: security posture: findings with severity and verification status, protection records and coverage protection kinds; for visibility questions, the decompile served rung and fidelity
  - Modules: security-findings, report, decompile, coverage

- Q: Which protector was applied?
  - Intent: security
  - Answer shape: security posture: findings with severity and verification status, protection records and coverage protection kinds; for visibility questions, the decompile served rung and fidelity
  - Modules: security-findings, report, decompile, coverage

- Q: Are there signature verification checks?
  - Intent: security
  - Answer shape: security posture: findings with severity and verification status, protection records and coverage protection kinds; for visibility questions, the decompile served rung and fidelity
  - Modules: security-findings, report, decompile, coverage

- Q: What RASP is present?
  - Intent: security
  - Answer shape: security posture: findings with severity and verification status, protection records and coverage protection kinds; for visibility questions, the decompile served rung and fidelity
  - Modules: security-findings, report, decompile, coverage

- Q: How is it protected against analysis?
  - Intent: security
  - Answer shape: security posture: findings with severity and verification status, protection records and coverage protection kinds; for visibility questions, the decompile served rung and fidelity
  - Modules: security-findings, report, decompile, coverage

## Intent: monetisation

- Q: How is it monetised?
  - Intent: monetisation
  - Answer shape: monetisation surface: billing/purchase classes, advertising SDK classes, billing/ad permissions and ad/purchase endpoints; verification boundary named
  - Modules: dex, endpoints, permissions

- Q: How is it monetized?
  - Intent: monetisation
  - Answer shape: monetisation surface: billing/purchase classes, advertising SDK classes, billing/ad permissions and ad/purchase endpoints; verification boundary named
  - Modules: dex, endpoints, permissions

- Q: What does the ad flow do?
  - Intent: monetisation
  - Answer shape: monetisation surface: billing/purchase classes, advertising SDK classes, billing/ad permissions and ad/purchase endpoints; verification boundary named
  - Modules: dex, endpoints, permissions

- Q: Where is purchase verified?
  - Intent: monetisation
  - Answer shape: monetisation surface: billing/purchase classes, advertising SDK classes, billing/ad permissions and ad/purchase endpoints; verification boundary named
  - Modules: dex, endpoints, permissions

- Q: Does it have in-app purchases?
  - Intent: monetisation
  - Answer shape: monetisation surface: billing/purchase classes, advertising SDK classes, billing/ad permissions and ad/purchase endpoints; verification boundary named
  - Modules: dex, endpoints, permissions

- Q: What purchases are offered?
  - Intent: monetisation
  - Answer shape: monetisation surface: billing/purchase classes, advertising SDK classes, billing/ad permissions and ad/purchase endpoints; verification boundary named
  - Modules: dex, endpoints, permissions

- Q: Which ad SDKs does it use?
  - Intent: monetisation
  - Answer shape: monetisation surface: billing/purchase classes, advertising SDK classes, billing/ad permissions and ad/purchase endpoints; verification boundary named
  - Modules: dex, endpoints, permissions

- Q: What ads does it show?
  - Intent: monetisation
  - Answer shape: monetisation surface: billing/purchase classes, advertising SDK classes, billing/ad permissions and ad/purchase endpoints; verification boundary named
  - Modules: dex, endpoints, permissions

- Q: How does it make money?
  - Intent: monetisation
  - Answer shape: monetisation surface: billing/purchase classes, advertising SDK classes, billing/ad permissions and ad/purchase endpoints; verification boundary named
  - Modules: dex, endpoints, permissions

- Q: Is there a paywall?
  - Intent: monetisation
  - Answer shape: monetisation surface: billing/purchase classes, advertising SDK classes, billing/ad permissions and ad/purchase endpoints; verification boundary named
  - Modules: dex, endpoints, permissions

- Q: What subscription tiers exist?
  - Intent: monetisation
  - Answer shape: monetisation surface: billing/purchase classes, advertising SDK classes, billing/ad permissions and ad/purchase endpoints; verification boundary named
  - Modules: dex, endpoints, permissions

- Q: Does it use billing?
  - Intent: monetisation
  - Answer shape: monetisation surface: billing/purchase classes, advertising SDK classes, billing/ad permissions and ad/purchase endpoints; verification boundary named
  - Modules: dex, endpoints, permissions

- Q: What billing library is used?
  - Intent: monetisation
  - Answer shape: monetisation surface: billing/purchase classes, advertising SDK classes, billing/ad permissions and ad/purchase endpoints; verification boundary named
  - Modules: dex, endpoints, permissions

- Q: Where is a purchase verified?
  - Intent: monetisation
  - Answer shape: monetisation surface: billing/purchase classes, advertising SDK classes, billing/ad permissions and ad/purchase endpoints; verification boundary named
  - Modules: dex, endpoints, permissions

- Q: How are purchases handled?
  - Intent: monetisation
  - Answer shape: monetisation surface: billing/purchase classes, advertising SDK classes, billing/ad permissions and ad/purchase endpoints; verification boundary named
  - Modules: dex, endpoints, permissions

- Q: What advertising networks are integrated?
  - Intent: monetisation
  - Answer shape: monetisation surface: billing/purchase classes, advertising SDK classes, billing/ad permissions and ad/purchase endpoints; verification boundary named
  - Modules: dex, endpoints, permissions

- Q: Does it show ads?
  - Intent: monetisation
  - Answer shape: monetisation surface: billing/purchase classes, advertising SDK classes, billing/ad permissions and ad/purchase endpoints; verification boundary named
  - Modules: dex, endpoints, permissions

- Q: What is the ad flow?
  - Intent: monetisation
  - Answer shape: monetisation surface: billing/purchase classes, advertising SDK classes, billing/ad permissions and ad/purchase endpoints; verification boundary named
  - Modules: dex, endpoints, permissions

- Q: Is premium content unlocked by purchase?
  - Intent: monetisation
  - Answer shape: monetisation surface: billing/purchase classes, advertising SDK classes, billing/ad permissions and ad/purchase endpoints; verification boundary named
  - Modules: dex, endpoints, permissions

- Q: What IAP surface exists?
  - Intent: monetisation
  - Answer shape: monetisation surface: billing/purchase classes, advertising SDK classes, billing/ad permissions and ad/purchase endpoints; verification boundary named
  - Modules: dex, endpoints, permissions

- Q: Which billing classes are present?
  - Intent: monetisation
  - Answer shape: monetisation surface: billing/purchase classes, advertising SDK classes, billing/ad permissions and ad/purchase endpoints; verification boundary named
  - Modules: dex, endpoints, permissions

- Q: How is the purchase flow built?
  - Intent: monetisation
  - Answer shape: monetisation surface: billing/purchase classes, advertising SDK classes, billing/ad permissions and ad/purchase endpoints; verification boundary named
  - Modules: dex, endpoints, permissions

## Intent: assets

- Q: What assets does it contain?
  - Intent: assets
  - Answer shape: asset inventory: totals, byte size, per-type and per-category counts and the largest assets, cited to assets.json
  - Modules: assets

- Q: What assets are inside?
  - Intent: assets
  - Answer shape: asset inventory: totals, byte size, per-type and per-category counts and the largest assets, cited to assets.json
  - Modules: assets

- Q: List the assets.
  - Intent: assets
  - Answer shape: asset inventory: totals, byte size, per-type and per-category counts and the largest assets, cited to assets.json
  - Modules: assets

- Q: What textures are included?
  - Intent: assets
  - Answer shape: asset inventory: totals, byte size, per-type and per-category counts and the largest assets, cited to assets.json
  - Modules: assets

- Q: What sprites does it ship?
  - Intent: assets
  - Answer shape: asset inventory: totals, byte size, per-type and per-category counts and the largest assets, cited to assets.json
  - Modules: assets

- Q: What images are inside?
  - Intent: assets
  - Answer shape: asset inventory: totals, byte size, per-type and per-category counts and the largest assets, cited to assets.json
  - Modules: assets

- Q: What audio files does it contain?
  - Intent: assets
  - Answer shape: asset inventory: totals, byte size, per-type and per-category counts and the largest assets, cited to assets.json
  - Modules: assets

- Q: What sounds are included?
  - Intent: assets
  - Answer shape: asset inventory: totals, byte size, per-type and per-category counts and the largest assets, cited to assets.json
  - Modules: assets

- Q: What music is included?
  - Intent: assets
  - Answer shape: asset inventory: totals, byte size, per-type and per-category counts and the largest assets, cited to assets.json
  - Modules: assets

- Q: What fonts does it ship?
  - Intent: assets
  - Answer shape: asset inventory: totals, byte size, per-type and per-category counts and the largest assets, cited to assets.json
  - Modules: assets

- Q: What models are included?
  - Intent: assets
  - Answer shape: asset inventory: totals, byte size, per-type and per-category counts and the largest assets, cited to assets.json
  - Modules: assets

- Q: What resources does it carry?
  - Intent: assets
  - Answer shape: asset inventory: totals, byte size, per-type and per-category counts and the largest assets, cited to assets.json
  - Modules: assets

- Q: What's inside the APK?
  - Intent: assets
  - Answer shape: asset inventory: totals, byte size, per-type and per-category counts and the largest assets, cited to assets.json
  - Modules: assets

- Q: What is inside the asset folders?
  - Intent: assets
  - Answer shape: asset inventory: totals, byte size, per-type and per-category counts and the largest assets, cited to assets.json
  - Modules: assets

- Q: How many assets are there?
  - Intent: assets
  - Answer shape: asset inventory: totals, byte size, per-type and per-category counts and the largest assets, cited to assets.json
  - Modules: assets

- Q: What are the largest assets?
  - Intent: assets
  - Answer shape: asset inventory: totals, byte size, per-type and per-category counts and the largest assets, cited to assets.json
  - Modules: assets

- Q: What asset types are present?
  - Intent: assets
  - Answer shape: asset inventory: totals, byte size, per-type and per-category counts and the largest assets, cited to assets.json
  - Modules: assets

- Q: What files does it contain under assets?
  - Intent: assets
  - Answer shape: asset inventory: totals, byte size, per-type and per-category counts and the largest assets, cited to assets.json
  - Modules: assets

- Q: Describe the asset inventory.
  - Intent: assets
  - Answer shape: asset inventory: totals, byte size, per-type and per-category counts and the largest assets, cited to assets.json
  - Modules: assets

- Q: What media assets are bundled?
  - Intent: assets
  - Answer shape: asset inventory: totals, byte size, per-type and per-category counts and the largest assets, cited to assets.json
  - Modules: assets

- Q: Which textures take the most space?
  - Intent: assets
  - Answer shape: asset inventory: totals, byte size, per-type and per-category counts and the largest assets, cited to assets.json
  - Modules: assets

- Q: What data files are inside?
  - Intent: assets
  - Answer shape: asset inventory: totals, byte size, per-type and per-category counts and the largest assets, cited to assets.json
  - Modules: assets

## Intent: animation

- Q: How is the character animated?
  - Intent: animation
  - Answer shape: animation identification: animation-shaped assets by name/extension plus per-system coverage status; boundary names composition decoding as not built (Part 4)
  - Modules: assets, coverage

- Q: How is the car animated?
  - Intent: animation
  - Answer shape: animation identification: animation-shaped assets by name/extension plus per-system coverage status; boundary names composition decoding as not built (Part 4)
  - Modules: assets, coverage

- Q: How are enemies animated?
  - Intent: animation
  - Answer shape: animation identification: animation-shaped assets by name/extension plus per-system coverage status; boundary names composition decoding as not built (Part 4)
  - Modules: assets, coverage

- Q: What animation system does it use?
  - Intent: animation
  - Answer shape: animation identification: animation-shaped assets by name/extension plus per-system coverage status; boundary names composition decoding as not built (Part 4)
  - Modules: assets, coverage

- Q: Does it use Spine?
  - Intent: animation
  - Answer shape: animation identification: animation-shaped assets by name/extension plus per-system coverage status; boundary names composition decoding as not built (Part 4)
  - Modules: assets, coverage

- Q: Does it use Lottie?
  - Intent: animation
  - Answer shape: animation identification: animation-shaped assets by name/extension plus per-system coverage status; boundary names composition decoding as not built (Part 4)
  - Modules: assets, coverage

- Q: Does it use Rive?
  - Intent: animation
  - Answer shape: animation identification: animation-shaped assets by name/extension plus per-system coverage status; boundary names composition decoding as not built (Part 4)
  - Modules: assets, coverage

- Q: Are there skeletal animations?
  - Intent: animation
  - Answer shape: animation identification: animation-shaped assets by name/extension plus per-system coverage status; boundary names composition decoding as not built (Part 4)
  - Modules: assets, coverage

- Q: What animations are present?
  - Intent: animation
  - Answer shape: animation identification: animation-shaped assets by name/extension plus per-system coverage status; boundary names composition decoding as not built (Part 4)
  - Modules: assets, coverage

- Q: How is the main character animated?
  - Intent: animation
  - Answer shape: animation identification: animation-shaped assets by name/extension plus per-system coverage status; boundary names composition decoding as not built (Part 4)
  - Modules: assets, coverage

- Q: Which animation files exist?
  - Intent: animation
  - Answer shape: animation identification: animation-shaped assets by name/extension plus per-system coverage status; boundary names composition decoding as not built (Part 4)
  - Modules: assets, coverage

- Q: Is Spine animation used?
  - Intent: animation
  - Answer shape: animation identification: animation-shaped assets by name/extension plus per-system coverage status; boundary names composition decoding as not built (Part 4)
  - Modules: assets, coverage

- Q: Is Lottie animation used?
  - Intent: animation
  - Answer shape: animation identification: animation-shaped assets by name/extension plus per-system coverage status; boundary names composition decoding as not built (Part 4)
  - Modules: assets, coverage

- Q: What keyframe data is present?
  - Intent: animation
  - Answer shape: animation identification: animation-shaped assets by name/extension plus per-system coverage status; boundary names composition decoding as not built (Part 4)
  - Modules: assets, coverage

- Q: How are the vehicles animated?
  - Intent: animation
  - Answer shape: animation identification: animation-shaped assets by name/extension plus per-system coverage status; boundary names composition decoding as not built (Part 4)
  - Modules: assets, coverage

- Q: What animation assets can be identified?
  - Intent: animation
  - Answer shape: animation identification: animation-shaped assets by name/extension plus per-system coverage status; boundary names composition decoding as not built (Part 4)
  - Modules: assets, coverage

- Q: Does it use DragonBones?
  - Intent: animation
  - Answer shape: animation identification: animation-shaped assets by name/extension plus per-system coverage status; boundary names composition decoding as not built (Part 4)
  - Modules: assets, coverage

- Q: Are sprite sheet animations used?
  - Intent: animation
  - Answer shape: animation identification: animation-shaped assets by name/extension plus per-system coverage status; boundary names composition decoding as not built (Part 4)
  - Modules: assets, coverage

- Q: How is the player character animated?
  - Intent: animation
  - Answer shape: animation identification: animation-shaped assets by name/extension plus per-system coverage status; boundary names composition decoding as not built (Part 4)
  - Modules: assets, coverage

- Q: What skeletal systems are present?
  - Intent: animation
  - Answer shape: animation identification: animation-shaped assets by name/extension plus per-system coverage status; boundary names composition decoding as not built (Part 4)
  - Modules: assets, coverage

## Intent: rebuild

- Q: How do I rebuild this app?
  - Intent: rebuild
  - Answer shape: rebuild summary from verified evidence (stack, verified features, storage, network, build order); boundary names nar blueprint as the full-spec route
  - Modules: engines, frameworks, investigation, dex, endpoints, blueprint

- Q: How do I rebuild it?
  - Intent: rebuild
  - Answer shape: rebuild summary from verified evidence (stack, verified features, storage, network, build order); boundary names nar blueprint as the full-spec route
  - Modules: engines, frameworks, investigation, dex, endpoints, blueprint

- Q: How would I build an equivalent app?
  - Intent: rebuild
  - Answer shape: rebuild summary from verified evidence (stack, verified features, storage, network, build order); boundary names nar blueprint as the full-spec route
  - Modules: engines, frameworks, investigation, dex, endpoints, blueprint

- Q: How can I build my own version?
  - Intent: rebuild
  - Answer shape: rebuild summary from verified evidence (stack, verified features, storage, network, build order); boundary names nar blueprint as the full-spec route
  - Modules: engines, frameworks, investigation, dex, endpoints, blueprint

- Q: Give me the rebuild plan.
  - Intent: rebuild
  - Answer shape: rebuild summary from verified evidence (stack, verified features, storage, network, build order); boundary names nar blueprint as the full-spec route
  - Modules: engines, frameworks, investigation, dex, endpoints, blueprint

- Q: How do I recreate it?
  - Intent: rebuild
  - Answer shape: rebuild summary from verified evidence (stack, verified features, storage, network, build order); boundary names nar blueprint as the full-spec route
  - Modules: engines, frameworks, investigation, dex, endpoints, blueprint

- Q: How do I reimplement this?
  - Intent: rebuild
  - Answer shape: rebuild summary from verified evidence (stack, verified features, storage, network, build order); boundary names nar blueprint as the full-spec route
  - Modules: engines, frameworks, investigation, dex, endpoints, blueprint

- Q: What is the build order for a rebuild?
  - Intent: rebuild
  - Answer shape: rebuild summary from verified evidence (stack, verified features, storage, network, build order); boundary names nar blueprint as the full-spec route
  - Modules: engines, frameworks, investigation, dex, endpoints, blueprint

- Q: How do I build a clone of this behaviour?
  - Intent: rebuild
  - Answer shape: rebuild summary from verified evidence (stack, verified features, storage, network, build order); boundary names nar blueprint as the full-spec route
  - Modules: engines, frameworks, investigation, dex, endpoints, blueprint

- Q: Describe the rebuild specification.
  - Intent: rebuild
  - Answer shape: rebuild summary from verified evidence (stack, verified features, storage, network, build order); boundary names nar blueprint as the full-spec route
  - Modules: engines, frameworks, investigation, dex, endpoints, blueprint

- Q: What would rebuilding it take?
  - Intent: rebuild
  - Answer shape: rebuild summary from verified evidence (stack, verified features, storage, network, build order); boundary names nar blueprint as the full-spec route
  - Modules: engines, frameworks, investigation, dex, endpoints, blueprint

- Q: How do I recreate the game from evidence?
  - Intent: rebuild
  - Answer shape: rebuild summary from verified evidence (stack, verified features, storage, network, build order); boundary names nar blueprint as the full-spec route
  - Modules: engines, frameworks, investigation, dex, endpoints, blueprint

- Q: Plan the rebuild.
  - Intent: rebuild
  - Answer shape: rebuild summary from verified evidence (stack, verified features, storage, network, build order); boundary names nar blueprint as the full-spec route
  - Modules: engines, frameworks, investigation, dex, endpoints, blueprint

- Q: How do I re-create the app?
  - Intent: rebuild
  - Answer shape: rebuild summary from verified evidence (stack, verified features, storage, network, build order); boundary names nar blueprint as the full-spec route
  - Modules: engines, frameworks, investigation, dex, endpoints, blueprint

- Q: What is the implementation order for a rebuild?
  - Intent: rebuild
  - Answer shape: rebuild summary from verified evidence (stack, verified features, storage, network, build order); boundary names nar blueprint as the full-spec route
  - Modules: engines, frameworks, investigation, dex, endpoints, blueprint

- Q: How would I rebuild the core features?
  - Intent: rebuild
  - Answer shape: rebuild summary from verified evidence (stack, verified features, storage, network, build order); boundary names nar blueprint as the full-spec route
  - Modules: engines, frameworks, investigation, dex, endpoints, blueprint

## Intent: compare

- Q: What changed between v1 and v2?
  - Intent: compare
  - Answer shape: two-artifact diff summary from nar-compare (identity and per-dimension changes); with one artifact, an unknown contract block naming the missing second path as the probe
  - Modules: compare

- Q: Compare these two versions.
  - Intent: compare
  - Answer shape: two-artifact diff summary from nar-compare (identity and per-dimension changes); with one artifact, an unknown contract block naming the missing second path as the probe
  - Modules: compare

- Q: What is the difference between the two versions?
  - Intent: compare
  - Answer shape: two-artifact diff summary from nar-compare (identity and per-dimension changes); with one artifact, an unknown contract block naming the missing second path as the probe
  - Modules: compare

- Q: What changed in the newer version compared to the old?
  - Intent: compare
  - Answer shape: two-artifact diff summary from nar-compare (identity and per-dimension changes); with one artifact, an unknown contract block naming the missing second path as the probe
  - Modules: compare

- Q: Compare the old and new builds.
  - Intent: compare
  - Answer shape: two-artifact diff summary from nar-compare (identity and per-dimension changes); with one artifact, an unknown contract block naming the missing second path as the probe
  - Modules: compare

- Q: Give me the version diff.
  - Intent: compare
  - Answer shape: two-artifact diff summary from nar-compare (identity and per-dimension changes); with one artifact, an unknown contract block naming the missing second path as the probe
  - Modules: compare

- Q: How do the two artifacts compare?
  - Intent: compare
  - Answer shape: two-artifact diff summary from nar-compare (identity and per-dimension changes); with one artifact, an unknown contract block naming the missing second path as the probe
  - Modules: compare

- Q: What changed between the two supplied builds?
  - Intent: compare
  - Answer shape: two-artifact diff summary from nar-compare (identity and per-dimension changes); with one artifact, an unknown contract block naming the missing second path as the probe
  - Modules: compare

- Q: Compare v1 and v2.
  - Intent: compare
  - Answer shape: two-artifact diff summary from nar-compare (identity and per-dimension changes); with one artifact, an unknown contract block naming the missing second path as the probe
  - Modules: compare

- Q: What is different between them?
  - Intent: compare
  - Answer shape: two-artifact diff summary from nar-compare (identity and per-dimension changes); with one artifact, an unknown contract block naming the missing second path as the probe
  - Modules: compare

- Q: Run a comparison of the two versions.
  - Intent: compare
  - Answer shape: two-artifact diff summary from nar-compare (identity and per-dimension changes); with one artifact, an unknown contract block naming the missing second path as the probe
  - Modules: compare

- Q: What changed between the legacy and current version?
  - Intent: compare
  - Answer shape: two-artifact diff summary from nar-compare (identity and per-dimension changes); with one artifact, an unknown contract block naming the missing second path as the probe
  - Modules: compare

## Intent: gaps

- Q: What can you NOT tell me, and why?
  - Intent: gaps
  - Answer shape: gap enumeration: every non-supported coverage entry with reason and probe, plus investigation unknowns and report limitations
  - Modules: coverage, investigation, report

- Q: What can you not tell me?
  - Intent: gaps
  - Answer shape: gap enumeration: every non-supported coverage entry with reason and probe, plus investigation unknowns and report limitations
  - Modules: coverage, investigation, report

- Q: What can't you tell me?
  - Intent: gaps
  - Answer shape: gap enumeration: every non-supported coverage entry with reason and probe, plus investigation unknowns and report limitations
  - Modules: coverage, investigation, report

- Q: What do you not know about it?
  - Intent: gaps
  - Answer shape: gap enumeration: every non-supported coverage entry with reason and probe, plus investigation unknowns and report limitations
  - Modules: coverage, investigation, report

- Q: What don't you know?
  - Intent: gaps
  - Answer shape: gap enumeration: every non-supported coverage entry with reason and probe, plus investigation unknowns and report limitations
  - Modules: coverage, investigation, report

- Q: What is unknown?
  - Intent: gaps
  - Answer shape: gap enumeration: every non-supported coverage entry with reason and probe, plus investigation unknowns and report limitations
  - Modules: coverage, investigation, report

- Q: What are the unknowns?
  - Intent: gaps
  - Answer shape: gap enumeration: every non-supported coverage entry with reason and probe, plus investigation unknowns and report limitations
  - Modules: coverage, investigation, report

- Q: What are the gaps?
  - Intent: gaps
  - Answer shape: gap enumeration: every non-supported coverage entry with reason and probe, plus investigation unknowns and report limitations
  - Modules: coverage, investigation, report

- Q: What gaps remain?
  - Intent: gaps
  - Answer shape: gap enumeration: every non-supported coverage entry with reason and probe, plus investigation unknowns and report limitations
  - Modules: coverage, investigation, report

- Q: What are its limitations?
  - Intent: gaps
  - Answer shape: gap enumeration: every non-supported coverage entry with reason and probe, plus investigation unknowns and report limitations
  - Modules: coverage, investigation, report

- Q: What limitation applies here?
  - Intent: gaps
  - Answer shape: gap enumeration: every non-supported coverage entry with reason and probe, plus investigation unknowns and report limitations
  - Modules: coverage, investigation, report

- Q: What is missing from the analysis?
  - Intent: gaps
  - Answer shape: gap enumeration: every non-supported coverage entry with reason and probe, plus investigation unknowns and report limitations
  - Modules: coverage, investigation, report

## Intent: other

- Q: Tell me about the leaderboard.
  - Intent: other
  - Answer shape: fallback: keyword-matched investigation verified facts, or the case identity summary, with the fallback boundary named
  - Modules: investigation, application, fingerprint

- Q: Describe the main character.
  - Intent: other
  - Answer shape: fallback: keyword-matched investigation verified facts, or the case identity summary, with the fallback boundary named
  - Modules: investigation, application, fingerprint

- Q: What is the leaderboard?
  - Intent: other
  - Answer shape: fallback: keyword-matched investigation verified facts, or the case identity summary, with the fallback boundary named
  - Modules: investigation, application, fingerprint

- Q: Tell me about the tutorial.
  - Intent: other
  - Answer shape: fallback: keyword-matched investigation verified facts, or the case identity summary, with the fallback boundary named
  - Modules: investigation, application, fingerprint

- Q: Describe the final boss.
  - Intent: other
  - Answer shape: fallback: keyword-matched investigation verified facts, or the case identity summary, with the fallback boundary named
  - Modules: investigation, application, fingerprint

- Q: What is the tutorial?
  - Intent: other
  - Answer shape: fallback: keyword-matched investigation verified facts, or the case identity summary, with the fallback boundary named
  - Modules: investigation, application, fingerprint

- Q: Tell me about the crafting system.
  - Intent: other
  - Answer shape: fallback: keyword-matched investigation verified facts, or the case identity summary, with the fallback boundary named
  - Modules: investigation, application, fingerprint

- Q: Describe the world map.
  - Intent: other
  - Answer shape: fallback: keyword-matched investigation verified facts, or the case identity summary, with the fallback boundary named
  - Modules: investigation, application, fingerprint

- Q: What is the final boss?
  - Intent: other
  - Answer shape: fallback: keyword-matched investigation verified facts, or the case identity summary, with the fallback boundary named
  - Modules: investigation, application, fingerprint

- Q: Tell me about the daily rewards.
  - Intent: other
  - Answer shape: fallback: keyword-matched investigation verified facts, or the case identity summary, with the fallback boundary named
  - Modules: investigation, application, fingerprint

## Intent: scripts

- Q: What scripts does it ship?
  - Intent: scripts
  - Answer shape: script inventory: per-format records from nar-script (format, status, header/count facts), identified_only entries carrying their named reason; bytecode reported structurally, never as source
  - Modules: coverage

- Q: Does it use Lua or Hermes bytecode?
  - Intent: scripts
  - Answer shape: script inventory: per-format records from nar-script (format, status, header/count facts), identified_only entries carrying their named reason; bytecode reported structurally, never as source
  - Modules: coverage

- Q: Are there any WebAssembly modules or source maps?
  - Intent: scripts
  - Answer shape: script inventory: per-format records from nar-script (format, status, header/count facts), identified_only entries carrying their named reason; bytecode reported structurally, never as source
  - Modules: coverage

