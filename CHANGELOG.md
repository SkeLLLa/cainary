# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0](https://github.com/SkeLLLa/cainary/compare/v0.5.2...v1.0.0) - 2026-11-08

### Added

- *(core)* add otel export catalog
- *(core)* add payload preview model and builder
- *(core)* sharpen claude code and codex telemetry findings with payloads
- *(net)* add cainary-otel-debug loopback otlp receiver
- *(cli)* show payload preview in scan output
- *(cli)* add explain and otel-debug commands
- *(macos)* show payload preview in finding details
- *(macos)* add otel debug collector toggle
- *(core)* classify otlp json against the catalog
- *(net)* classify with the core catalog, add goldens and integration tests, update architecture 12
- *(linux)* add OTel debug collector and payload previews
- *(net)* add tls endpoint takeover mode
- *(net)* explain how to allow a privileged listen port
- *(net)* let claude code and codex trust the takeover ca
- *(macos)* add https takeover settings and claude code trust buttons
- *(linux)* add HTTPS takeover trust controls
- *(linux)* add a hand-written Secret Service client for the secret store
- *(sig)* add cainary-sig with sha-256 and hmac
- *(codex)* resolve requirements [otel] over config and mark cloud-cache telemetry best effort
- *(sig)* add canonical encoding, keys and golden vectors
- *(tray-model)* add rules-key decision logic
- *(net)* trust state v2 with modes, ownership checks and owned[] in trust-status
- *(net)* trust mode registry, multi-CA bundles from sources and journaled modes
- *(net)* apply_mode and undo_mode for both trust targets
- *(net)* new claude applies use the owned bundle; direct records migrate on a second mode
- *(net)* --delete-ca undoes takeover trust first; owned[] lists modes and CA fingerprints
- *(tray-model)* build collector feed rows, red-flag groups and sidebar collapse settings
- *(linux)* redesign Details with Scan/Live sidebar, collector tabs and in-window Settings
- *(tray-model)* specific collector settings problems, low ports, structured startup failure
- *(tray-model)* add in-memory logbook ring buffer and safe_line sanitizer
- *(tray-model)* configurable logbook line cap with scaled byte budget
- *(net)* drop capabilities in every build and give fatal startup errors stable codes
- *(bind-helper)* root helper binding privileged loopback ports for the tray
- *(packaging)* ship the bind helper and its polkit policy in every Linux package
- *(tray-model)* privileged-port helper trust walk, policy check and reply grammar
- *(tray-model)* bind_privileged via pkexec with fd handoff, spawn_stream inherit, fake pkexec and guards
- *(net)* accept validated inherited loopback listeners via --listen-fd
- *(tray-model)* port access view, reservation lifecycle, version probe and failure fixtures
- *(tray)* collector failure box, Open port N for privileged ports, and held-socket lifecycle
- *(hosts-helper)* privileged /etc/hosts block editor with polkit policy and packaging
- *(tray-model)* host-name checks, /etc/hosts analysis and edits, takeover guide and start at launch
- *(tray)* collector logs tab, takeover setup guide with per-step undo, hosts quick edit and sidebar icons
- *(net)* transcode OTLP/HTTP protobuf bodies to OTLP/JSON
- *(net)* parse /proc/net/tcp to find a loopback client's uid
- *(net)* decode gzip and protobuf request bodies
- *(net)* setup notes and takeover lines for protobuf, gzip and NO_PROXY
- *(net)* [**breaking**] refuse connections from other local users

### Fixed

- *(net)* bound name expansion, matching completeness, line cap, queue accounting, regex errors; harden N1
- *(net)* per-mode regex sets, drop aho-corasick per timing, deterministic tests, endpoint in setup, redflag tests
- *(core)* resolve codex prompt and reply flags as toml booleans
- *(macos)* set close-on-exec on collector pipes before launch
- *(macos)* validate collector red-flag patterns and skip invalid rows
- *(core)* correct otel catalog entries against vendor docs
- *(core)* borrow record names and parents in otel_classify and add the metric family
- *(core)* make payload gates per export and identity conditions explicit
- *(cli)* list only unconditional identity keys in payload previews
- *(core)* stream nested otlp values to the matcher without owned paths
- *(linux)* align collector retention and settings behavior
- *(build)* pass otel-debug task arguments without the deprecated template
- *(net)* walk the certificate directory path from the root without following symlinks
- *(net)* enforce each idle, request and write deadline on every underlying tls read and write
- *(net)* drop capabilities after bind in every mode and fail closed
- *(net)* apply the name policy to batch.host
- *(net)* keep production code before test modules and guard it
- *(net)* say https, number steps, explain handshake failures by category, and soften the CA wording
- *(net)* satisfy clippy in the guard test
- *(net)* satisfy clippy in the tls module
- *(net)* drop an unused test helper
- *(net)* refuse dot components and relative state paths, and advertise the validated path
- *(net)* show only safe arguments and shell-quote every path in the privileged-port note
- *(net)* say the restart once in the applied message
- *(net)* add a lossless json editor for one settings member
- *(net)* make the trust edit transactional, compare-then-swap, lossless and strict
- *(net)* serialize trust calls, stage before compare, keep uncertain transactions, and harden inputs
- *(macos)* check trust decoding against real helper output
- *(macos)* hide the no-write command until the collector certificate exists
- *(macos)* show the trust status note and test the fixed helper output
- *(build)* bump every cainary crate in both lockfiles
- *(build)* also bump root path crates in linux/Cargo.lock
- *(linux)* bound secret prompts and unlock only locked objects
- *(sig)* make the cainary-sig workspace dependency path-only
- *(codex)* anchor otel finding keys on evidence and hedge unknown metrics exporter
- *(sig)* preflight sizing, wipe hmac buffers, ct-only digests, rejection vectors
- *(net)* never touch unrecorded bundles, journal bundle replacements and re-check before change
- *(net)* validate journal paths and recover the claude transaction before bundle journals
- *(net)* delete an orphan claude bundle only when settings are known not to reference it
- *(net)* resolve originals and refuse any collector-directory file, reject keys in mode CAs
- *(net)* journal modes on first Codex apply, refuse relative originals, validate mode CAs as X.509
- *(net)* keep the trust anchor parse under tls/
- *(net)* journal modes on claude first apply, name relative originals, drop unused publish_bundle
- *(net)* give each rcgen_cert call its own directory so parallel tests don't race
- *(build)* fail set-version when a member has no package name
- *(net)* --delete-ca holds the trust lock to the unlink and keeps the CA while recovery is pending
- *(net)* a migration after a user edit drops the exact-bytes backup so undo restores only the key
- *(net)* every changing trust operation refuses while an earlier recovery is pending
- *(linux)* size the collector tabs so "Red flags" isn't clipped
- *(linux)* draw the Red flags tab label ourselves so Breeze sizes it and adds a --width harness flag
- *(bind-helper)* refuse --version as root and print it without panicking
- *(tray-model)* parse the real helper --version format and check the shipped polkit policies
- *(tray-model)* structural policy reader, verified-helper bind entry point, fd-safe empty messages, TCP protocol check, test-fakes ship guard
- *(tray-model)* make the policy reader a strict subset of XML 1.0 and cross-check it against expat
- *(net)* take inherited listen fds through one unsafe take_inherited and keep bind OwnedFd-only
- *(tray)* show the settings problem instead of the generic collector message and allow ports 1-65535
- *(net)* protobuf whole doubles come out as JSON integers
- *(net)* don't blame another user for a client that can't be identified
- *(net)* gzip bodies are decoded under a time budget
- *(net)* protobuf transcoding stops at 500k values
- *(net)* protobuf value cap is 600k so a full batch fits
- *(net)* pair the client's socket exactly and read the tables as a stream
- *(copilot)* COPILOT_OTEL_ENDPOINT wins over the generic OTLP endpoint
- *(net)* build cleanly on macOS
- ci and lint
- *(ci)* pass the macOS, tray and deb release checks
- *(net)* quote the CA path in the takeover commands; macOS tls tests

### Other

- add sanitized otel payload fixtures
- re-bless goldens for payload previews and sharper telemetry titles
- *(rules)* describe payload previews and sharper telemetry findings
- *(guards)* add net crate guards N1-N4 and the net-only dependency closure check
- document payload preview and otel debug collector
- *(macos)* describe payload preview and otel debug collector
- re-bless goldens for corrected otel catalog
- ship cainary-otel-debug in release artifacts
- *(linux)* add cainary-otel-debug to tray packages
- skip checks that need the other os instead of failing
- add mise tasks to build and run release binaries from the checkout
- *(net)* serve requests through one stream
- *(net)* add optional tls feature with rustls and rcgen
- *(net)* cover the tls takeover end to end
- describe the tls endpoint takeover in architecture 12 and the README
- *(macos)* describe the https takeover and trust buttons
- let linux:run:release use another collector binary
- *(net)* split trust into per-concern modules
- *(net)* document mode certificate and original rules
- *(net)* a first Claude apply always points at the bundle; only old direct records stay direct
- *(linux)* add offscreen QML preview harness as linux:ui-preview
- *(net)* drop the setcap-copy recipe for privileged ports
- *(tray)* reservation lifecycle and no prompt when starting
- opening privileged ports from the tray and the collector failure box
- linux-run builds the debug collector with the tls feature
- *(net)* OTLP protobuf and gzip fixtures
- *(net)* flate2 for gzip request bodies
- *(net)* every format and encoding gives the same batch
- formats, compression and the own-user check for the collector
- *(net)* own-user check over plain and TLS
- the two own-user refusal messages
- exact socket pairing, streamed tables and the overflow uid in the own-user check
- drop citations of agent-only design notes
- *(release)* breaking changes bump the major version
- add a roadmap
- match the platform docs and READMEs to the code
- match architecture and rules to the code
- check the root helpers' --version as nobody
- *(net)* give unoptimised builds room in the decoder deadline test
- *(net)* set socket timeouts before the peer can close
- *(net)* give the TLS retry storm a window a slow runner fits in
- *(macos)* snapshot each open "What it sends" on its own

## [0.5.2](https://github.com/SkeLLLa/cainary/compare/v0.5.1...v0.5.2) - 2026-10-30

### Other

- *(deps)* bump the all-actions group with 3 updates

## [0.5.1](https://github.com/SkeLLLa/cainary/compare/v0.5.0...v0.5.1) - 2026-10-28

### Fixed

- jamf detector alert

## [0.5.0](https://github.com/SkeLLLa/cainary/compare/v0.4.1...v0.5.0) - 2026-10-25

### Added

- *(ci)* use dedicated signing key

## [0.4.1](https://github.com/SkeLLLa/cainary/compare/v0.4.0...v0.4.1) - 2026-10-25

### Fixed

- *(ci)* pages release script

## [0.4.0](https://github.com/SkeLLLa/cainary/compare/v0.3.0...v0.4.0) - 2026-10-25

### Added

- *(ci)* linux package signing

### Fixed

- *(ci)* shellckeck issues

## [0.3.0](https://github.com/SkeLLLa/cainary/compare/v0.2.1...v0.3.0) - 2026-10-25

### Added

- ci lint & macos stable signing

### Fixed

- icons and logos
- mac build & diff
- macos bundler

## [0.2.1](https://github.com/SkeLLLa/cainary/compare/v0.2.0...v0.2.1) - 2026-10-23

### Fixed

- *(linux)* monochrome icon
- ci & tests

## [0.2.0](https://github.com/SkeLLLa/cainary/compare/v0.1.0...v0.2.0) - 2026-10-23

### Added

- human scary logo

### Fixed

- add apple icon
- ci & docs

## [0.1.0](https://github.com/SkeLLLa/cainary/releases/tag/v0.1.0) - 2026-10-23

### Added

- init
- linux app

### Fixed

- ci
- *(ci)* enable trusted publishing
- ci try 2
- ci and deps
- ci try 2
- linux repos and ci fixes
- ci try 3


