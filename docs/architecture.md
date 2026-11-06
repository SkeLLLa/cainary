# cAInary — architecture

cAInary has a Rust core and CLI (`crates/`) and a thin SwiftUI menu bar app (`macos/`). This
document describes the core, the report it prints and how the pieces fit together. The detection
rules are in [rules.md](rules.md), the macOS app in [macos.md](macos.md), and prompt and
status-bar setups in [integrations.md](integrations.md).

## 1. Goals and non-goals

cAInary shows a developer what their employer enforces on, watches and collects from the AI
coding tools on their machine. It is free (GPL-3.0-or-later), **read-only** and `cainary` itself
**makes no network requests** (the one opt-in exception is a separate program, below).

Design rules, in priority order:

1. **Safe.** It never writes outside its own preferences, never uses the network, and never
   opens credential files (§6.3).

   **One exception, in a separate program.** `cainary` itself never uses the network and never
   runs in the background. The separate `cainary-otel-debug` binary (crate `cainary-net`, §12) is
   a local OTLP/HTTP receiver for checking what an AI tool's telemetry export contains. It
   listens only on loopback (127.0.0.1 and ::1) and never opens an outbound connection. It
   refuses requests whose `Host` isn't a loopback name with its port and any request that carries
   an `Origin` or `Sec-Fetch-*` header, so a web page can't reach it. It is unauthenticated, as
   any loopback listener is: any local process can post to it. It writes only to a log file the
   user names, and runs only while the user runs it: from a terminal, or through the explicit
   "OTel debug collector" toggle in the macOS app or the Linux tray, which start it as a child
   process and stop it with the app. `cainary scan` and `status` never start or contact it.
   One opt-in mode of that program, `--tls` (the endpoint takeover, §12.10), also accepts TLS
   connections on loopback, still inbound-only, and writes the *public* certificate of a
   throwaway CA to the user's state directory (the private key never leaves memory). It forwards
   nothing and never connects out. On an explicit user action only (the `--trust claude-code`
   command or the GUI's confirm button), `cainary-otel-debug` sets one key,
   `env.NODE_EXTRA_CA_CERTS`, in the user's `~/.claude/settings.json`, after a backup, and can
   undo it. It never edits Codex configuration, shell profiles or any system trust store.
   `cainary` itself still writes nothing outside its prefs. Guards (§10) keep network code out of
   `cainary-core` and `cainary-cli`.
2. **Truthful.** Every rule cites an official vendor doc. A rule that isn't confirmed by one is
   marked best effort (`maybe`) and worded "may". A source that could not be read, was refused,
   or was cut off by a cap makes the scan *incomplete*, never *clear*. A wrong result is the
   worst bug, so detection rules follow the vendor's documented semantics even when that costs a
   few more lines.
3. **Simple.** A scanner is one file; the three tools with layered managed config (Claude Code,
   Codex, Copilot) split into a resolver file plus one file per concern. There is one value type
   for every config format. Precedence is resolved by small named functions per tool (rules.md),
   not a general merge engine.
4. **Fat core, thin UI.** Levels, entries, summaries and change detection are computed in Rust
   and shipped in the JSON. A UI only draws them, so another UI (Linux, a script) needs no
   analysis code.

Non-goals: verifying code signatures, attributing who installed a binary beyond two simple
rules, heavy redaction hardening, caching, a daemon or watch mode (the opt-in collector is not a
daemon: no autostart, pidfile or service), auto-update, and any server-side visibility.

## 2. Repository layout

```
./
  Cargo.toml  Cargo.lock     workspace (members: crates/*), [workspace.dependencies], the version
  mise.toml                  local toolchain pins and tasks (rust, swift, shellcheck, …)
  Makefile                   the only build entry point (mise tasks wrap it)
  rustfmt.toml  clippy.toml  .swift-format  cliff.toml
  docs/                      this file, rules.md, macos.md, linux.md, integrations.md,
                             distribution.md
  crates/
    cainary-core/            library: model, harness, parsers, scanners, analysis, diff
      src/lib.rs             scan(): run the scanners, sort, analyze → Report
      src/model.rs           Tool, App, Level, Signal, Origin, Finding, Entry, Change, Report (+ serde)
      src/analysis.rs        counting, finding ids and keys, levels, entries, overall status
      src/diff.rs            baseline report vs current report → changes (§4)
      src/redact.rs          mask secret-looking values; display paths
      src/value.rs           JSON / JSONC / TOML / plist → serde_json::Value
      src/harness/mod.rs     Harness (roots, os, env, tool homes, which, fixture metadata), Loc
      src/harness/ctx.rs     ScanCtx: recorded reads/lists/markers, typed outcome → SourceState
      src/harness/fs.rs      the only module that touches std::fs (guarded open, §6.3)
      src/harness/deny.rs    AccessPolicy: the credential deny-list bound to this scan's homes
      src/harness/platform.rs  Os, EnvKind, MDM plist paths, the scutil subprocess
      src/rules/otel.rs      OTEL_* / exporter classification
      src/rules/otel_catalog.rs   static, versioned tables of the records each vendor's OTel export carries
      src/rules/otel_classify.rs  OTLP/JSON → classified batch (used by cainary-net)
      src/rules/otel_preview.rs   catalog + resolved flags → `Payload` (§3.7)
      src/rules/hooks.rs     classify a hook / notify command (network, interpreter, binary)
      src/rules/mcp.rs       MCP server entry → finding
      src/rules/vendor.rs    vendor-default telemetry findings and opt-out env vars
      src/scanners/mod.rs    registry: [claude_code, claude_desktop, codex, cursor, copilot, chatgpt, device]
      src/scanners/claude_code.rs            sources, tier/control selection, merge → CcConfig
      src/scanners/claude_code_policy.rs     policy keys, gateways/proxies, vendor default
      src/scanners/claude_code_telemetry.rs  the telemetry unit and OTel findings
      src/scanners/claude_code_hooks.rs      hooks, plugins, managed MCP
      src/scanners/claude_desktop.rs
      src/scanners/codex.rs                  layers, requirements, config precedence → CxConfig
      src/scanners/codex_telemetry.rs        otel exporters, prompt logging, vendor metrics
      src/scanners/cursor.rs
      src/scanners/copilot.rs                sources, channels, managed/VS Code policy, CLI → CpConfig
      src/scanners/copilot_telemetry.rs      OTel resolution per surface
      src/scanners/chatgpt.rs
      src/scanners/device.rs                 MDM, PPPC, system extensions, web filter, proxies
      tests/fixtures/<name>/ {fixture.json, root/…, home/…}
      tests/golden/<name>.json
      tests/resolve/<name>/  resolver fixtures: same layout, no goldens; asserted by unit tests
      tests/golden.rs        fixture → Report JSON == golden
      tests/otel-payloads/<vendor>-<version>/  sanitized OTLP/JSON captures the catalog is checked against
      tests/guards.rs        source-level safety guards (§10)
      tests/canary.rs        guard 5: credentials never reach the report (§10)
    cainary-cli/             binary `cainary`
      src/main.rs  src/args.rs  src/text.rs  src/status.rs  src/explain.rs
      tests/cli.rs           runs the binary on fixtures; text/status/sources/explain goldens in tests/golden/
    cainary-net/             binary `cainary-otel-debug` (§12); `publish = false`; never linked by the core or CLI
      src/main.rs            args, `--config-stdin` / stdin lifeline thread, exit codes; the only `std::env`/`std::process`
      src/lib.rs             `pub mod args, config, http, logfile, otlp, output, queue, redflag, server, setup`
      src/args.rs            hand-written parser → `Options`; exit-2 usage errors
      src/config.rs          `--config-stdin`: the one JSON config line (≤ 1 MiB), strict
      src/server.rs          the only `std::net`: bind, accept, per-connection threads, limits, Host/Origin checks
      src/http.rs            pure HTTP/1.1 parsing and response bytes (strict framing)
      src/otlp.rs            routes, content checks, OTLP/JSON walk, naming policy, alerts → events
      src/output.rs          the output thread: JSON lines, text rendering, escaping
      src/queue.rs           the job semaphore and the output queue (bounded by items and bytes)
      src/logfile.rs         the only file writer: 0600 log, rotation, descriptor-validated open
      src/redflag/           `mod.rs` (patterns, `Matcher`), `presets.rs`, `file.rs` (the `--red-flags` TOML reader)
      src/setup.rs           the "point an agent at it" lines (text and `hello.setup`)
      tests/server.rs  tests/redflag.rs  tests/redflag_timing.rs
  macos/                     SwiftUI menu bar app (macos.md)
    Info.plist  Sources/*.swift  Tests/
  linux/                     Qt 6 tray app: its own workspace, Cargo.lock and guards (linux.md)
    crates/tray-model  crates/tray-dbus  crates/cainary-tray   data/
  packaging/bundle.sh        assemble and sign dist/cAInary.app, zip it (POSIX sh)
  packaging/linux.sh         tarball, .deb and .rpm from built binaries (distribution.md)
  packaging/aur/  packaging/ci/  packaging/dist/  packaging/packslip.toml  packaging/mise-registry/
  scripts/                   action-pin checker and its test, set-version.sh (release)
  .github/workflows/         ci.yml, release.yml: plain make with rustup and Xcode (§11)
```

Dependencies, all in `[workspace.dependencies]`:

| Crate | Why | Notes |
| --- | --- | --- |
| `serde` (derive) | the model and JSON wire format | |
| `serde_json` | JSON in and out; the universal `Value` | `preserve_order` feature, so evidence keeps the file's key order |
| `toml` | Codex config, requirements, managed_config | parse to `toml::Value` → `serde_json::Value` |
| `plist` | macOS managed preferences, PPPC, app `Info.plist` (binary and XML) | read through its event stream (§5.1) |
| `libc` | `O_NOFOLLOW`/`O_NONBLOCK`/`O_CLOEXEC` for the guarded open and `fcntl(F_GETPATH)` on macOS (§6.3) | `default-features = false`; used only in `harness/fs.rs` (and in `cainary-net/src/logfile.rs` for the same open flags and the effective uid). The flag values differ between macOS and Linux targets, so they aren't hand-written |
| `rustls` (`std`, `tls12`, `ring`; no default features) | the takeover's TLS server (§12.10) | **`cainary-net` only, and only under its non-default `tls` feature.** The `ring` provider; never `aws-lc-rs` |
| `rcgen` (`ring`, `pem`; no default features) | the takeover's ephemeral CA and leaves (§12.10) | same: `cainary-net` under `tls` only |
| `time` (`std`; no default features) | validity dates for those certificates | already in the lock through `plist`; named by `cainary-net` under `tls` only |
| `regex` | user red-flag patterns in the collector (§12.5) | **`cainary-net` only.** Linear-time matching, so a hostile pattern or input can't ReDoS, and compile-size limits (1 MiB per regex, 16 MiB in all) |

Nothing else: no `clap` (a small hand-written parser), no `chrono`, and `time` only under the collector's `tls` feature (one RFC 3339
formatter elsewhere), no `regex` in the core or CLI (substring and token checks), no `dirs`, and no async. `tests/guards.rs`
parses `Cargo.lock` and fails if a package outside an allowlist appears, so adding a crate is a
visible, reviewed change. `regex` pulls in `regex-automata`, `regex-syntax` and `aho-corasick`
(the direct `aho-corasick` use was dropped after a timing test, §12.5); with `cainary-net` itself
they are the `NET_ONLY` set. `memchr` is also a dependency of those, but it is already in the
core's closure through `serde_json`, so it is not net-only. Guard 4 requires the lock to stay
inside the allowlist **and** the dependency closure of `cainary` and `cainary-core` to miss every
`NET_ONLY` package, so the network program's dependencies can't reach the read-only product (§10).
That guard is a regression check, not a proof. What keeps the product
read-only and offline is that the only call sites that open files or start a process are
`harness/fs.rs` and the one `Command::new` in `harness/platform.rs`, and fixture-mode tests show
both are bypassed (§10).

**The Linux tray has its own policy.** `linux/` is a separate workspace (`exclude = ["linux"]` in
the root `Cargo.toml`) with its own `Cargo.lock`, so none of its crates enter the table above or
the root lockfile guard. Its guards live in `linux/crates/cainary-tray/tests/guards.rs`:

1. **L1, direct dependencies.** Every `linux/crates/*/Cargo.toml` may depend only on
   `cainary-tray-model`, `cainary-tray-dbus`, `cxx`, `cxx-qt`, `cxx-qt-lib`, `cxx-qt-build`,
   `ksni`, `zbus`, `serde`, `serde_json`, `toml`, `libc`, `async-channel` and `futures-lite`.
2. **L2, transitive denylist.** `linux/Cargo.lock` must not contain GTK, GLib or GIO crates
   (`gtk*`, `gdk*`, `glib*`, `gio*`, `gobject*`, `pango*`, `cairo*`, `atk*`), AppIndicator
   libraries, `rfd`, `tray-icon`, `muda`, `webkit*`, `wry`, `tokio*`, or HTTP, TLS and networking
   clients (`reqwest`, `hyper*`, `ureq`, `curl*`, `isahc`, `h2`, `rustls*`, `openssl`,
   `native-tls`, `tungstenite*`, `webbrowser`). `ksni`'s `gtk4` is a dev-dependency and never
   reaches the lockfile used for the build.
3. **L3, source guards.** `Command::new` only in the runner (`tray-model/src/runner.rs`), no
   `std::net`, file writes only in `settings.rs` (which the baseline store writes through) and `autostart.rs`,
   and no scanning code (no `~/.claude` or similar path literals). It also needs the
   crates' `publish = false`.
4. **L4, version sync.** `linux/Cargo.toml` has the same version as the root workspace.

Qt itself comes from the distro, outside Cargo's view (see [linux.md](linux.md) §6 for what that
does and doesn't mean for GTK).

## 3. Report model

All enums serialize as lowercase kebab-case **slugs**. Slugs are part of the wire format and
never change. `model.rs` is the source of truth; the goldens are the executable contract.

### 3.1 Enums

```rust
enum Tool { ClaudeCode, ClaudeDesktop, Codex, Cursor, Copilot, Chatgpt, Device }
// slugs: claude-code, claude-desktop, codex, cursor, copilot, chatgpt, device
// a Tool is a product surface; scanners and sources are per Tool. On the wire it is `surface`.

enum App { Claude, Openai, Cursor, Copilot, Device }
// what the user sees as one app: Tool::app() maps ClaudeCode + ClaudeDesktop → Claude,
// Codex + Chatgpt → Openai ("ChatGPT & Codex"), the rest 1:1. Device findings become
// monitor entries (§3.4), not an app row.

enum Signal {
    Prompts, Responses, Transcript,                     // → Conversation
    ToolDetails, FileContents, Traffic, DeviceAccess,   // → Work
    Usage, Identity, Vendor,                            // → Usage
    Policy,                                             // → Clear
}
// slugs: prompts, responses, transcript, tool-details, file-contents, traffic,
//        device-access, usage, identity, vendor, policy. On the wire a finding's signals are `sends`.

enum Exposure { Clear, Usage, Work, Conversation }  // internal; max over a finding's signals

enum Level { NotInstalled, Ok, OptedOut, Low, Medium, High }   // Ord, §3.2
// slugs: not-installed, ok, opted-out, low, medium, high

enum Origin { Server, Mdm, System, OrgInstalled, Unattributed, Environment, User, VendorDefault }
// slugs: server, mdm, system, org-installed, unattributed, environment, user, vendor-default
// is_org(): Server | Mdm | System | OrgInstalled. Order = "most organizational first".
// On the wire a finding's origin is `setBy`.

enum AlertMode { Org, OrgUnknown, Everything }
// slugs: org, org-unknown, everything (the CLI also accepts relaxed, balanced, paranoid)
// default OrgUnknown. Only affects `counts` (§3.5).

enum SourceState { Present, Absent, Error, Refused, Capped }
// Error   = exists but unreadable or unparsable (permission, I/O, parse, budget, command failure/timeout)
// Refused = deliberately not read or run: the access policy forbade the read (requested path or
//           where it resolves), or it is an admin helper program (`policyHelper`) that is never run
// Capped  = a listing had more entries than the cap; only the first N were scanned
// Error, Refused and Capped all make the report incomplete.

enum SourceKind { File, Dir, Env, Command, Marker }
enum EntryKind { App, Monitor }
enum ChangeScope { Entry, Finding, Source, Report }
enum ChangeKind { Added, Removed, Raised, Lowered, Changed }
```

### 3.2 Levels

`Level` is ascending, so `max()` picks the worst:

| slug | colour | label | meaning |
| --- | --- | --- | --- |
| `not-installed` | grey | `NOT INSTALLED` | the app isn't on this machine |
| `ok` | green | `OK` | nothing tracked or sent that we can see |
| `opted-out` | blue | `OPTED OUT` | the vendor's standard telemetry is turned off by a setting, and nothing else is sent |
| `low` | yellow | `LOW` | usage, metrics, identity or vendor-default telemetry |
| `medium` | orange | `MEDIUM` | activity: commands, tool details, file contents, traffic, device access |
| `high` | red | `HIGH` | conversations: prompts, responses, transcripts |

**A finding's level** (`Finding::level`):
- Not in effect: `opted-out` when its origin is `vendor-default` (an opt-out finding from
  `rules/vendor.rs`), otherwise `ok` (shown as inactive).
- In effect: from its exposure. `Conversation` → `high`, `Work` → `medium`, `Usage` → `low`,
  `Clear` (policy only, or no signals) → `ok`.

**An entry's level** is `not-installed` when the app isn't installed, otherwise the max over its
findings' levels (`ok` when it has none). So `opted-out` wins over `ok` and loses to `low`. The
report's `status` is the worst entry: apps before monitors on a tie, and a monitor with only notes
doesn't count. Levels ignore `--alert`.

Short phrases (`Level::short`), used as the summary when nothing at `low` or above is sent:
"Conversations are sent", "Activity is sent", "Usage data is sent", "Standard telemetry is off",
"Nothing sent", "Not installed".

### 3.3 Findings

```rust
struct Finding {
    id: String,             // "<app>-<n>", 1-based after sorting; stable for a given input
    key: String,            // stable identity across scans (§4.1)
    app: App,               // tool.app()
    tool: Tool,             // the surface that produced it
    agent: Option<String>,  // device findings: the monitor it belongs to (§3.4); not on the wire
    signals: Vec<Signal>,   // sorted, de-duplicated; empty when !in_effect
    exposure: Exposure,     // max over signals; Clear when none
    title: String,          // plain words, no config keys: "AcmeCollector receives your prompts"
    detail: String,         // one or two sentences; may name keys
    source: Source,         // { path (display form), origin, kind }
    evidence: Vec<String>,  // "key = value" lines, already redacted
    reference: Option<String>,  // official doc URL
    best_effort: bool,      // rule rests on an unverified item → UI says "may"
    in_effect: bool,        // false = shadowed by a higher tier, or a hook that never runs
    counts: bool,           // counts toward alerts at report.alert (§3.5)
    payload: Option<Box<Payload>>, // in-effect telemetry findings: what the export carries (§3.7)
}
```

Scanners build findings with `FindingBuilder::new(title).signals(..).detail(..).source(..)
.evidence(..).reference(url).best_effort(b).in_effect(b).agent(name).payload(p)`. `ScanCtx::emit` fills in
the tool, clears the signals when `!in_effect`, and runs the final `redact::text` pass.

`analysis::sort_and_number` sorts findings by (app, tool, exposure desc, in_effect desc, origin
order, title, source path), which is what makes ids and goldens deterministic, then assigns `id`
and `key`.

### 3.4 Entries

The report is hierarchical:

- **Level 1, entries:** the AI apps and the other monitoring found on the device, each with a
  status.
- **Level 2, findings:** what each entry tracks or sends, and where it goes.
- **Level 3, config:** the file it came from, who set it, the evidence lines and the docs link.

```rust
struct Entry {
    id: String,            // "claude", "openai", "cursor", "copilot", or a monitor slug
    name: String,          // "Claude", "CrowdStrike Falcon", "This device"
    kind: EntryKind,       // app | monitor
    installed: bool,
    status: Status,        // { level, label, summary }
    sends: Vec<Signal>,    // union of in-effect signals
    surfaces: Vec<Tool>,   // apps only: surfaces that are installed or have findings
    findings: Vec<Finding>,// level desc, then sort_and_number order
    notes: Vec<String>,    // "can't be seen locally" and similar lines
}
```

- **App entries** (`apps`): always the four AI apps in `App` order. An app is installed when a
  scanner of any of its surfaces says so, or it has an in-effect finding.
- **Monitor entries** (`others`) come from `Tool::Device` findings, grouped by `agent`.
  `device.rs` sets the agent from a small table of public vendors keyed by bundle-id prefix
  (`com.crowdstrike.` → "CrowdStrike Falcon", …), else a name derived from the bundle id or the
  containing app or Application Support directory. MDM findings use "Device management", proxy
  findings "Network proxy". Findings with no agent go into "This device" (`id` `device`). The
  entry id is the slugified name. Monitors are always installed and ordered by level desc, then
  name. "This device" exists only when it has findings, or device notes next to other monitors.
- **`summary`**: the worst finding's title plus " (+N more)" for the others at that level; the
  level's short phrase below `low`.

### 3.5 Counting and completeness

- `counts(f, mode)` = `f.in_effect && !f.signals.is_empty() &&` the origin test: `org` →
  `is_org()`; `org-unknown` → `is_org() || unattributed || environment`; `everything` → any
  origin. It is kept on each finding for consumers that want an organization-only view; levels,
  summaries and the status badge don't use it.
- `complete` = no source is `error`, `refused` or `capped`. Stat-only probes for installed
  markers are not sources and never affect it (§6.2). An incomplete scan with nothing at `low`
  or above is shown as incomplete, never as a green OK (the CLI `status` and the app both apply
  this rule).

### 3.6 JSON (schema 3)

`cainary scan --json` prints one `Report` as pretty JSON, with camelCase keys. Abridged:

```json
{
  "schema": 3, "generator": "cainary 0.1.0", "scannedAt": "2026-10-21T12:00:00Z",
  "os": "macos", "envKind": "shell", "alert": "org-unknown", "complete": true,
  "status": {"level": "high", "label": "HIGH",
             "summary": "Claude Code hook posts each event to hooks.example-corp.com (+3 more)"},
  "apps": [
    {"id": "claude", "name": "Claude", "kind": "app", "installed": true,
     "status": {"level": "high", "label": "HIGH", "summary": "…"},
     "sends": ["prompts", "responses", "transcript", "tool-details", "traffic", "usage"],
     "surfaces": ["claude-code"],
     "findings": [
       {"id": "claude-1", "key": "61844d1a58abfc42", "level": "high",
        "title": "Claude Code hook posts each event to hooks.example-corp.com", "detail": "",
        "surface": "claude-code", "sends": ["prompts", "traffic"], "setBy": "mdm",
        "inEffect": true, "maybe": false, "counts": true,
        "config": {"path": "/Library/Managed Preferences/com.anthropic.claudecode.plist",
                   "kind": "file",
                   "evidence": ["events = UserPromptSubmit", "url = https://hooks.example-corp.com/prompts"]},
        "docs": "https://code.claude.com/docs/en/hooks"},
       {"id": "claude-5", "key": "9c1e0a47b2d35f68", "level": "low",
        "title": "Claude Code sends usage data and your identity to otel.example-corp.com", "detail": "…",
        "surface": "claude-code", "sends": ["usage", "identity"], "setBy": "mdm",
        "inEffect": true, "maybe": false, "counts": false,
        "config": {"path": "/Library/Managed Preferences/com.anthropic.claudecode.plist", "kind": "file",
                   "evidence": ["OTEL_LOGS_EXPORTER = otlp"]},
        "docs": "https://code.claude.com/docs/en/monitoring-usage",
        "payload": {"export": "logs", "catalog": "claude-code 2.1.316",
                    "docs": "https://code.claude.com/docs/en/monitoring-usage#events",
                    "gates": [{"flag": "OTEL_LOG_USER_PROMPTS", "label": "Prompt text", "on": false,
                               "sent": "redacted", "value": null, "setBy": null, "path": null,
                               "text": "Prompt text: sent as <REDACTED>, because OTEL_LOG_USER_PROMPTS is unset"}],
                    "identity": [{"key": "user.email", "what": "your account email (when signed in with a Claude account)", "group": "identity"}],
                    "resource": [{"key": "service.name", "what": "\"claude-code\"", "group": "resource"}],
                    "records": [{"name": "claude_code.user_prompt", "kind": "event", "what": "You sent a prompt",
                                 "unit": null, "observed": true,
                                 "attrs": [{"key": "prompt", "what": "…", "group": "content",
                                            "flag": "OTEL_LOG_USER_PROMPTS", "sent": "redacted"}]}],
                    "sample": ["resource:", "  service.name = \"claude-code\"", "…"]}}
     ],
     "notes": []}
  ],
  "others": [],
  "sources": [
    {"tool": "claude-code", "source": {"path": "~/.claude/settings.json", "origin": "user", "kind": "file"},
     "state": "present", "note": null}
  ]
}
```

With `--since`, the report also carries `since` and `changes` (§4.3).

Versioning contract:

- `schema` is an integer **major** version, currently 3. Within a major, changes are additive
  only: new optional keys and new enum slugs. Removing or renaming a key, making an optional key
  required, or changing a slug's meaning bumps `schema`. Consumers refuse a `schema` they don't
  know.
- `payload` (schema 3, optional) is present only on in-effect telemetry findings; see §3.7. It is
  an additive optional key, so the schema stays 3: §3.6 allows new optional keys within a major,
  and every consumer already ignores unknown keys (Swift `Codable` and the tray's serde have no
  `deny_unknown_fields`). The core's own baseline reader (`FindingIn`) ignores it, so `payload`
  is `None` on the baseline side. The UIs decode it leniently (`decodeIfPresent` with a `try?`
  fallback to `nil`; a lenient serde adapter in the tray), so a malformed payload hides the
  preview and never turns into "Couldn't scan". Bumping to 4 would force both apps and every
  script to update for a purely additive field.
- Consumers ignore unknown keys. A missing required key or a wrong type fails the decode, which
  a UI shows as "Couldn't scan", never as clear.
- Every enum is open. An unknown value must never make things look safer than the core said:
  an unknown level is drawn as an incomplete grey `?`, never green; other unknown slugs are
  shown as their raw text, and a change with an unknown scope or kind never notifies.
- `cainary status --format json` is a separate one-line document:
  `{"schema":3,"level","label","badge","complete","entries":{"<id>":{"level","installed"},…}}`.
  The four app ids are always present, so pointers like `/entries/openai/level` are always valid.
- `cainary sources --json` prints `{"schema":3,"sources":[…]}` (the `sources` array has the same
  shape as in the report).

### 3.7 Payload preview

A telemetry finding in effect (rules CC.3, CX.4, CX.5) carries `payload`: what that export sends,
built statically from the catalog in `rules/otel_catalog.rs` and the resolved config
(`rules/otel_preview.rs`). Nothing is captured or read beyond the scanned config. Record
descriptions and attribute groups (identity on every record, resource, per event, content gated
by a flag) come from the vendor docs. Entries seen only on the wire are `maybe`. `catalog` names
the vendor version the fixtures were captured from. Each gate states whether its flag is on in
this scan and where that came from, as one plain line (`text`). `sample` is a minimal record
with descriptions in place of values; it never holds a real value. The UIs draw it as is.

- **Which findings carry one.** Only the in-effect finding whose contribution group holds the
  destination's base variable: `OTEL_LOGS_EXPORTER` (`logs`), `OTEL_METRICS_EXPORTER`
  (`metrics`), `OTEL_TRACES_EXPORTER` (`traces`) or `BETA_TRACING_ENDPOINT` (`beta`, `maybe`) for
  Claude Code; `otel.exporter` (`logs`), `otel.trace_exporter` (`traces`, `maybe`) and
  `otel.metrics_exporter` (`metrics`) for Codex. A content-flag finding from another source
  carries none, because the base finding's `gates` already shows the flag and its origin.
- **Shape.** `payload` is `{export, catalog, docs, maybe?, gates[], identity[], resource[],
  records[], sample[]}`. A gate is `{flag, label, on, sent, value, setBy, path, text}` with
  `sent` one of `yes`, `redacted`, `generic`, `no`, `local`, and `value` redacted like evidence.
  `identity`/`resource` entries and a record's `attrs` are `{key, what, group, maybe?, flag?,
  sent?}`; a record is `{name, kind, what, unit, maybe?, observed, flag?, sent?, attrs[]}`.
- **Gate text** is built in the core, `<label>: <state>, because <why>`, and every UI prints it
  verbatim. The state is "sent", "sent as `<REDACTED>`", `replaced by "custom"`, "not sent" or
  "kept on this machine (`<dir>`); only a pointer is sent". The reason is `<FLAG> = <value> (set
  by <origin>)`, `<FLAG> is unset` (`… (on by default)` for a default-on flag) or, for a flag that
  follows another, `<FLAG> is unset, so it follows <OTHER> = 1 (set by …)`.
- **Resolution.** Claude Code gates come from the in-effect `CcConfig.env` values only, so a
  dropped or replaced value never counts. Codex gates come from `CxConfig.cfg`: the value is the
  TOML scalar as text, and a gate is on only for a real TOML `true`. The key names of
  `OTEL_RESOURCE_ATTRIBUTES` (never the values) are listed as identity attributes.
- **Catalog rule.** An entry is documented by the vendor (cited) or observed in a fixture
  (`maybe`, worded "may"). Vendor source code alone doesn't count.

## 4. Change detection

The core diffs, the UI remembers. `cainary scan --since <baseline.json|->` compares the scan with
an earlier `scan --json` (a file, or stdin) and adds `since` and `changes` to the report. The core
stays stateless and writes nothing; a UI keeps the baseline and turns `changes` into
notifications. The feature works with no UI at all:

```sh
cainary scan --json --since last.json > now.json
jq -e '[.changes[]|select(.notify)]|length>0' now.json && notify-send cAInary "$(jq -r '.changes[0].text' now.json)"
mv now.json last.json
```

### 4.1 Finding identity: `key`

The positional `id` (`claude-3`) shifts when a finding is added above it, so each finding has a
stable `key`:

- 16 hex digits of FNV-1a-64 over `surface \0 config.path \0 anchor`.
- The anchor is the evidence key names (the text before ` = ` on each line), sorted and joined
  with `\n`; with no evidence, the title. Values are left out on purpose, so a new endpoint for
  the same key is the same finding with a `changed` change.
- Findings that share a key within one report get `-2`, `-3` suffixes in sorted order.

Matching is best effort: when a finding's key names change, it shows as `removed` plus `added`
instead of `raised`. That is still true, and the entry-level change is exact.

### 4.2 What is a change (`diff.rs`)

| scope | matched by | kinds | notify |
| --- | --- | --- | --- |
| `entry` | `id` | `raised`, `lowered`; `added`, `removed` (monitors only; app entries always exist) | `raised` to `low`+, **except** `not-installed` → `low`/`opted-out`/`ok` (a fresh install with vendor defaults); `added` monitor at `low`+ |
| `finding` | `key`, within the entry | `added`, `removed`, `raised`, `lowered`, `changed` (same level; `sends`, `setBy`, `inEffect`, `title` or `evidence` differ) | `added` or `raised` to `medium`/`high` |
| `source` | (`tool`, `path`) | `changed` (state), `added`, `removed` | never |
| `report` | — | `changed` (`complete` ↔ `incomplete`) | never |

- **No false good news.** No `removed` is emitted when the finding's `config.path` is now
  `error`, `refused` or `capped`; the `report` change already says the scan is incomplete.
- **Sources:** only those with an organizational origin, plus any source that becomes `error`,
  `refused` or `capped`. A managed plist appearing is worth a line; the user's own settings file
  appearing is noise.
- No content hashes and no mtimes. Notes and the overall `status` are not diffed.
- **`payload` is not part of the key and is not compared.** It follows the catalog, which changes
  between releases, so comparing it would mark every telemetry finding `changed` on upgrade; and
  every flag that changes what is sent already changes `sends` or `evidence` (or adds a
  contribution finding). The `OTEL_METRICS_INCLUDE_*` flags only change which identity keys are
  sent, not the signal set. A test in `diff.rs` pins that two reports differing only in `payload`
  produce no changes. Wording changes to a title do show as a `changed` finding once.
- **Order:** notifying changes first, then report entry order, then scope (entry, finding,
  source, report).

Because levels ignore `--alert`, a baseline stays valid when the alert mode changes.

### 4.3 Wire format

```json
"since": {"scannedAt": "2026-10-20T09:00:00Z", "error": null},
"changes": [
  {"id": "entry:claude:raised:high", "scope": "entry", "entry": "claude", "key": null,
   "kind": "raised", "from": "low", "to": "high", "notify": true,
   "text": "Claude is now HIGH: Claude Code hook `acme-guard` receives your prompts"},
  {"id": "finding:claude:3f9c2a17d04b8e61:added:high", "scope": "finding", "entry": "claude",
   "key": "3f9c2a17d04b8e61", "kind": "added", "from": null, "to": "high", "notify": true,
   "text": "New: Claude Code hook `acme-guard` receives your prompts"}
]
```

- `from`/`to` hold level slugs (entry, finding), state slugs (source) or `complete`/`incomplete`
  (report), and `null` where there is nothing on that side. `entry` is `null` for the report
  scope.
- `id` = `scope:entry:(key|path|-):kind:to`: opaque and deterministic; a UI uses it to remember
  what it already posted.
- `text` is one redacted plain line, built by the core.
- **Baseline errors.** A missing, unreadable, over-1 MiB, non-JSON or other-`schema` baseline
  doesn't stop the scan, and the exit code stays 0. The report gets `since.error` (a short
  redacted reason) and `changes: []`.

## 5. Parsing and redaction

### 5.1 One value type (`value.rs`)

Every format is parsed into `serde_json::Value`, so scanners have one API:

| Format | Parser | Notes |
| --- | --- | --- |
| JSON | `serde_json` | |
| JSONC (VS Code, Cursor, Copilot CLI) | a small pre-pass strips comments outside strings and trailing commas, then `serde_json` | |
| TOML | `toml::Value` → convert | datetimes → strings |
| plist (XML or binary) | `plist::stream::Reader` events → build `Value` | `Date` → RFC 3339 string; `Data` → `"<data N bytes>"`. The event stream lets the node cap stop a binary plist that points many times at one container before it expands |
| TOML in base64 | `base64_decode`, then TOML | Codex `*_toml_base64` MDM keys |

**Limits.** Each document has one `Budget { depth ≤ 128, nodes ≤ 100_000 }`, charged per value by
the conversions and by `str_or_json` (JSON-in-string, common in MDM). An exceeded budget is a
parse error, so the source becomes `error` and the scan incomplete. Files are read with a 1 MiB
cap (§6.3). Parser error messages are cut to 120 characters and redacted before they become a
source note, because TOML errors quote the offending line.

Helpers: `get(&v, "a.b.c")` (dotted path; also matches a literal dotted key, as VS Code and MDM
flatten keys), `truthy(&v)`, `str_or_json`. Scanners never call the parser directly:
`ScanCtx::read`/`read_mdm` parse, and an embedded document goes through `ScanCtx::parse_inner`,
so every failure is a recorded `error` source.

### 5.2 Redaction (`redact.rs`)

Minimal by design. It masks obvious secrets and doesn't try to be clever:

- `is_secret_key(k)`: a case-insensitive key contains `token`, `secret`, `password`, `passwd`,
  `apikey`/`api_key`/`api-key`, `authorization`, `cookie`, `credential`, `private`, or ends with
  `headers`/`_key`. The helper-command keys `apiKeyHelper` and `otelHeadersHelper` and
  `max_tokens` are exceptions. The value is shown as `<redacted>`.
- `url(s)`: keep scheme, host, port and path; drop userinfo, query and fragment. `url_host(s)`
  returns the host only.
- `command(s)`: mask the word after `Bearer`/`Basic`, the value of `--token`/`--api-key`/
  `--password`/`-H 'Authorization: …'`, `NAME=value` where NAME is a secret key, and tokens with
  well-known prefixes (`sk-`, `ghp_`, `gho_`, `ghs_`, `github_pat_`, `xox?-`, `glpat-`, `AKIA`,
  `AIza`, JWT-shaped `eyJ…`). URLs in commands go through `url()`.
- `display_path(p)`: `$HOME` → `~`, control characters → `?`.
- Header maps (`OTEL_EXPORTER_OTLP_HEADERS`, MCP `headers`, `http_headers`) show names only.

Every string that reaches a finding passes through one of these, and `FindingBuilder` applies
`redact::text()` (control characters + known prefixes) to title, detail and evidence as a final
net. There is no allowlist renderer, no entropy scoring and no hashing of values.

## 6. Harness

The harness is the only code that touches the OS. Scanners get a `&mut ScanCtx` and never import
`std::fs`, `std::process` or `std::env`; `tests/guards.rs` enforces that.

### 6.1 `Harness` (`harness/mod.rs`)

```rust
pub struct Harness {
    pub os: Os,                 // Macos | Linux: a runtime value, so every test runs on every host
    pub env_kind: EnvKind,      // Shell | Launchd (§6.5)
    root: PathBuf,              // "/" live; <fixture>/root in tests
    home: PathBuf,              // $HOME live; <fixture>/home in tests
    pub user: String,           // for MDM per-user plists; fixture default "alice"
    env: BTreeMap<String, String>,   // snapshot of the process env, or the fixture env
    now: SystemTime,            // fixture "now", else the system clock
    meta: FixtureMeta,          // rootOwned paths, scutilProxy text; empty when live
    live: bool,                 // false for fixtures and --root/--home: no subprocess, ever
    policy: AccessPolicy,       // built once in the constructor, immutable (§6.3)
}
```

Constructors: `Harness::live(env_kind)`, `Harness::from_fixture(dir)` (reads `fixture.json`) and
`Harness::with_roots(root, home, os)` (`--root`/`--home`). Accessors give scanners locations
(`sys`, `home`, `tool_home`, `xdg_config`, `app_support`, `mdm`), the environment (`env`), a
stat-only PATH lookup (`which`) and the clock. A `Loc` carries the display path that goes into
the JSON and the physical path that is read.

`tool_home` is the only place the relocation variables are interpreted: `$CLAUDE_CONFIG_DIR`
(default `~/.claude`), `$CODEX_HOME` (default `~/.codex`) and `$COPILOT_HOME` (default
`~/.copilot`). A value is used when it is absolute or starts with `~/` and has no `..`; otherwise
the default is used and the tool gets a note. The `AccessPolicy` is built from the same resolved
values, so scanners and the deny-list always agree on where a tool's home is.

`fixture.json`, all keys optional:

```json
{ "os": "macos", "user": "alice", "envKind": "shell", "now": "2026-01-01T00:00:00Z",
  "env": { "OTEL_LOG_USER_PROMPTS": "1" },
  "rootOwned": ["/Library/Application Support/AcmeCollector/acme-hook", "~/.claude/settings.json"],
  "scutilProxy": "<dictionary> {\n  HTTPSEnable : 1\n  HTTPSProxy : proxy.example-corp.com\n  HTTPSPort : 8080\n}",
  "tools": ["claude-code"] }
```

`tools` restricts which scanners run, which keeps each scanner's goldens independent. With both
a fixture `tools` and CLI `--tool` flags, the scanners that run are the **intersection** (a
filter can only narrow). The report always holds all four app entries; an app whose surfaces are
all filtered out is not installed. `--tool` takes an app slug (`claude`, `openai`, expanding to
its surfaces) or a surface slug.

### 6.2 `ScanCtx` (`harness/ctx.rs`)

One per tool per scan. It collects findings, sources, the installed flag and notes, and records
every source it reads automatically. The main calls: `read(loc, origin, format)`,
`read_mdm(domain)` (present plists, user first, JSON-in-string decoded), `parse_inner` (an
embedded document, recorded as `<at>#<key>`), `list(dir, suffix, origin)`, `probe` (stat only,
not recorded: installed markers), `marker` (stat only, recorded: markers that make findings),
`root_owned`, `system_proxy`, `not_run` (records an admin helper as refused), `installed`,
`note` and `emit`.

Every helper below `ScanCtx` returns a typed outcome (`fs::ReadError`, `fs::Listing`,
`platform::CmdError`), and `ScanCtx` is the one place that maps it to a `SourceState`. Scanners
see `Option`/`Vec` and don't handle errors; the report's `complete` flag carries them:

| Outcome | Recorded as | Incomplete? |
| --- | --- | --- |
| read: missing file | `absent` | no |
| read: parsed | `present` | no |
| read: permission, I/O, not a regular file, hard-linked, over the cap, parse or budget error | `error` + short note | yes |
| read: the access policy refused the requested or resolved path | `refused`, "not read: credential location" | **yes**: the tool may read that config even though cAInary won't |
| list: more entries than the cap (256) | `capped` | yes |
| list: permission or I/O error | `error` | yes |
| list: refused (a denied dir, or a dir with a denied direct child) | `refused` | yes |
| `not_run`: an admin helper whose output would change the config (rules CC.5) | `refused` | yes: the effective config is unknown |
| `marker`: stat failed | `error` | yes |
| `probe`: anything | not recorded | no: an installed marker is a hint, not an input |
| scutil: failure, non-zero exit, timeout, output over 64 KiB | `error` | yes |
| scutil: not macOS, or a fixture without `scutilProxy` | `absent` | no |

No scanner asks for a credential path on purpose, so a `refused` source in practice means a
config file is a symlink into a denied location. Treating it as incomplete is the honest result.

### 6.3 File access and the access policy (`harness/fs.rs`, `harness/deny.rs`)

**AccessPolicy** (`deny.rs`): one immutable value, built in the `Harness` constructor and passed
explicitly to every `fs::read` and `fs::list`.

- Each entry is expanded against every base it is relative to. `~` means both the logical home
  and its canonical form. `<cfg>`, `<codex>` and `<cp>` mean the default tool home *and* the
  relocated one, each logical and canonical. `<xdg>` means `~/.config` and `$XDG_CONFIG_HOME`.
  Absolute entries are under `root`. So a relocated home is denied exactly like the default one.
- Matching is ASCII case-insensitive on both OSes: conservative on case-sensitive Linux disks,
  right for APFS.
- `check` is pure (no I/O) and table-tested. Canonicalization happens in `fs.rs`.

| Kind | Entries |
| --- | --- |
| files | `<codex>/auth.json`, `<codex>/history.jsonl`, `<cp>/config.json`, `<cp>/apps.json`, `<xdg>/github-copilot/hosts.json`, `<xdg>/github-copilot/apps.json`, `<xdg>/gh/hosts.yml`, `<cfg>/.claude.json`, `<cfg>/history.jsonl`, `~/.claude.json`, `~/.docker/config.json`, `~/.netrc`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.vault-token`, `~/.terraform.d/credentials.tfrc.json`, `~/.gemini/oauth_creds.json`, `/Library/Preferences/com.apple.networkextension*.plist` |
| dirs (and everything below) | `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.azure`, `~/.kube`, `<xdg>/gcloud`, `~/.password-store`, `~/Library/Keychains`, `/Library/Keychains`, `<codex>/sessions`, `<codex>/memories`, `<codex>/log`, `<cfg>/projects`, `<cfg>/shell-snapshots`, `<cfg>/todos`, `<cp>/session-state`, `~/Library/Application Support/Codex`, `~/Library/HTTPStorages/com.openai.codex`, `~/Library/Application Support/com.openai.chat`, `~/Library/Application Support/Google/Chrome`, `~/Library/Application Support/Firefox`, `~/.mozilla`, `<xdg>/google-chrome`, `<xdg>/chromium`, `~/Library/Cookies` |
| any basename | `.env`, `.env.*`, `.envrc`, `.credentials*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa*`, `id_ed25519*`, `*.sqlite`, `*.vscdb`, `Cookies` |

Directories with a denied direct child (`<codex>`, `<cp>`, `<cfg>`, `~`, `<xdg>`, …) are never
listed; scanners read named files in them instead.

**Guarded read** (`fs::read(&AccessPolicy, &Path, cap)`):

1. `policy.check(requested)`.
2. `canonicalize(requested)` (not found → missing), then `policy.check(resolved)`. This refuses a
   symlink anywhere in the path that leads into a denied location.
3. Open `resolved` with `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`: fails if the last component was
   swapped for a symlink after step 2, and a swapped-in FIFO can't block the open.
4. `fstat` the descriptor: it must be a regular file with `nlink == 1` and `len ≤ cap`.
5. Ask the kernel where the open descriptor is (macOS `fcntl(F_GETPATH)`, Linux
   `/proc/self/fd/<fd>`) and check that path too. If the lookup fails, the read is refused.
6. Read at most `cap + 1` bytes; more than `cap` means the file grew after the `fstat`, and the
   read fails as too large.

**Listing** (`fs::list`): canonicalize, `policy.may_list`, `read_dir`, skip hidden entries, drop
denied entries silently, sort, keep at most 256 and flag truncation. A listing never opens an
entry. **Stat** has no policy check: it reveals only existence, type, owner and mode.

**Residual risk, accepted:** an attacker who can rename directories the user owns between two
syscalls could still race steps 2–5. Such an attacker can already read those files directly, so
a full `openat`-per-component walk was judged not worth the code. The policy exists so that a
symlinked or relocated config can't turn into reading a credential by accident.

### 6.4 Platform (`harness/platform.rs`)

- `Os::host()` uses `cfg!(target_os)`, but every path decision uses the runtime `h.os`, so a
  Linux fixture is tested on a Mac and vice versa.
- **System proxy (macOS):** `scutil_proxy()` runs `/usr/sbin/scutil --proxy` (absolute path,
  fixed arguments, empty environment, stdin and stderr to `/dev/null`) and parses its output.
  It is the only subprocess in the core. A reader thread caps stdout at 64 KiB; after a 3 s
  deadline the child is killed and always reaped. In fixture mode the text comes from
  `scutilProxy`, and `scutil` is never run (a unit test checks this).
- **Linux:** proxies come from `R/etc/environment` only (no gsettings/dconf).
- **Owner checks** use `MetadataExt::uid()`/`mode()`; fixture mode answers from `rootOwned`.

### 6.5 Environment

The core reads only its own process environment, never a login shell and never dotfiles. The CLI
run from a terminal sees the shell env (`envKind: shell`). The app passes `--env-kind launchd`:
it was started by launchd, so shell exports are invisible, and scanners add a note saying so and
mark server-tier choices as best effort (rules CC.2). Env lookups are by fixed names only; the
env is never dumped.

`which(name, path)` searches the colon-separated `path`, stat only. It answers `Unknown` when an
entry is relative or holds `$`/`~`. A hook's PATH is not necessarily the scanner's, so rules H.2
layers it: command-local `PATH=` first, then the tool's settings `env.PATH` (or the MCP server's
`env.PATH`), then the scan's PATH. Under `envKind: launchd` a bare-name lookup that falls through
to the scan's PATH is `Unknown`.

## 7. Scanners

Each scanner is `pub fn scan(ctx: &mut ScanCtx)`. The registry in `scanners/mod.rs` is a static
array of `(Tool, fn)`. `lib.rs` exposes `scan(&Harness, &ScanOptions) -> Report`, where
`ScanOptions { alert, tools }`.

For Claude Code, Codex and Copilot the resolver file reads every source, resolves precedence into
a plain struct (`CcConfig`, `CxConfig`, `CpConfig`; shapes in rules.md), and then calls the
concern files (`claude_code_policy`, `claude_code_telemetry`, `claude_code_hooks`,
`codex_telemetry`, `copilot_telemetry`). The struct is the interface between those files, and
concern tests build it by hand.

The key tables, signals and doc references are in **[rules.md](rules.md)**. Scope at a glance
(R = system root):

| Tool | macOS | Linux | Detects |
| --- | --- | --- | --- |
| Claude Code | `<cfg>`=`~/.claude` (`$CLAUDE_CONFIG_DIR`): `remote-settings.json`, `settings.json`, `policy-limits.json`; MDM `com.anthropic.claudecode`; `R/Library/Application Support/ClaudeCode/{managed-settings.json, managed-settings.d/, managed-mcp.json}`; env | same `<cfg>`; `R/etc/claude-code/…`; env | OTel export and content flags, gateways/providers/proxies, managed policy and locks, hooks, org MCP, org-enabled plugins, vendor telemetry |
| Claude Desktop | MDM `com.anthropic.claudefordesktop`; `~/Library/Application Support/Claude/claude_desktop_config.json`; `Claude.app` | — (no official Linux app) | OTLP export + content capture, inference gateway/provider, egress proxy, org MCP and instructions, feature locks, vendor telemetry |
| Codex | MDM `com.openai.codex` (`*_toml_base64`); `~/.codex` (`$CODEX_HOME`): `config.toml`, `hooks.json`, `cloud-config-bundle-cache.json`; `R/etc/codex/{requirements.toml, managed_config.toml, config.toml}` | same minus MDM | requirements (policy), provider base URLs, OTel, `notify`, hooks, org MCP, vendor telemetry |
| Cursor | `~/.cursor/{hooks.json, cli-config.json}`; `R/Library/Application Support/Cursor/hooks.json`; MDM `com.todesktop.230313mzl4w4u92`, `co.anysphere.cursor.nightly` | `~/.cursor/…`; `R/etc/cursor/hooks.json` | hooks (user and enterprise), MDM policy, CLI permissions, vendor telemetry |
| Copilot | MDM `com.github.copilot`, `com.microsoft.VSCode[Insiders]`; `R/Library/Application Support/GitHubCopilot/managed-settings.json`; `R/etc/github-copilot/policy.d/`; `~/Library/Application Support/Code/User/settings.json`; `~/.copilot/{settings.json, hooks/, providers.json}` | `R/etc/github-copilot/…`, `R/etc/vscode/policy.json`, `~/.config/Code/User/settings.json`, `~/.copilot/…` | managed settings, OTel (managed/env/VS Code), proxies, BYOK providers, hooks, VS Code telemetry level and chat policies |
| ChatGPT | `ChatGPT.app` Info.plist; MDM `com.openai.codex` (browser keys); Computer Use / Locked use / Computer History markers (stat only) | — | in-app browser proxy and policies, device unlock, Computer History |
| Device | `R/Library/Managed Preferences` listing; PPPC plist; `R/Library/SystemExtensions/db.plist`; sysext policy; web filter; `scutil --proxy` | `R/etc/environment` proxies | MDM presence, Full Disk Access/Accessibility grants, network and endpoint-security extensions, web filter, system proxy/PAC/WPAD |

Linux paths not stated in a vendor doc are marked in rules.md, and findings from them are best
effort.

Shared rule modules (`rules/`) keep the scanners short: `hooks.rs` (command target, PATH
layering, hook origin, network hint, local-notifier test, grouping), `mcp.rs` (MCP server entry
→ finding), `otel.rs` (truthy/exporter/endpoint helpers, OTLP header names) and `vendor.rs`
(vendor-default findings and their opt-out env vars).

## 8. CLI (`cainary`)

```
cainary scan    [--json | --summary] [--since <baseline.json|->] [COMMON]
cainary status  [--format emoji|text|nerd|json] [COMMON]
cainary sources [--json] [COMMON]
cainary explain <id|key> [COMMON]
cainary otel-debug
cainary --version | --help

COMMON: [--alert org|org-unknown|everything]   (aliases relaxed|balanced|paranoid; default org-unknown)
        [--tool <slug>]...                      (repeatable; default all)
        [--fixture <dir> | --root <dir> --home <dir> [--os macos|linux]]
        [--env-kind launchd|shell]              (default shell; both apps pass launchd)
        [--no-color]                            (also NO_COLOR; colour only on a tty)
```

Arguments are parsed by hand (`args.rs`). The CLI doesn't read the app's preferences.

**Exit codes:** `0` the scan ran, whatever it found. `1` setup error (missing `--fixture`/
`--root` dir, bad `fixture.json`, `--os` without roots). `2` usage error, with usage on stderr.
`3` internal error: a panic is caught in `main`, so a UI can tell it apart from a clean scan.

### 8.1 `scan` text

Hierarchical, with colour only on a TTY; the label text alone is clear without colour.

```
cAInary · macOS · 2026-10-21 16:40 UTC · complete

HIGH  Claude sends prompts to your organization (+3 more)

AI apps
  HIGH           Claude            Claude Code hook `acme-guard` receives your prompts (+2 more)
  MEDIUM         ChatGPT & Codex   Codex sends tool results to otel.example-corp.com
  OPTED OUT      Cursor            Standard telemetry is off
  NOT INSTALLED  GitHub Copilot

Other monitoring on this device
  MEDIUM         CrowdStrike Falcon  can observe app launches and file access (may)
  LOW            Device management   This Mac is managed: 42 configuration domains

────────────────────────────────────────
Claude — HIGH · Conversations are sent
  Claude Code, Claude Desktop · sends prompts, transcript, usage

  HIGH    Claude Code hook `acme-guard` receives your prompts
          sends: prompts, transcript · set by: organization (MDM profile)
          config: /Library/Managed Preferences/com.anthropic.claudecode.plist
            hooks.UserPromptSubmit = /usr/local/bin/acme-guard
          docs: https://code.claude.com/docs/en/hooks
  ...
  notes:
    • Server-managed settings are visible only through the local cache.
```

- A header line, the overall status, then the level-1 tables (apps, then other monitoring), then
  one detail block per installed entry: each finding with its level label (level 2) and the
  indented `sends`, `set by`, `config`, evidence and `docs` lines (level 3).
- An inactive finding shows `inactive` in place of its level. The surface name prefixes a
  finding only when the entry has more than one surface.
- `--summary` prints only the header, the overall status and the level-1 tables.
- With `--since`, a "Changes since …" block follows the overall status (also under `--summary`),
  with markers `+` added, `-` removed, `↑` raised, `↓` lowered and `~` changed, or
  "No changes since …".
- Colours: high red, medium orange (256-colour 208), low yellow, opted-out blue, ok green,
  not-installed dim.

A finding with a `payload` gets payload lines after its evidence and before `docs:`: a header
(`payload: 28 events · catalog claude-code 2.1.316 · more: cainary explain claude-11`, the noun
being events, metrics or spans), one line of the identity keys sent on every record, and one dim
line per gate (`gate.text` verbatim). `--summary` prints none of it.

### 8.2 `status`, `sources`, `explain` and `otel-debug`

`status` prints one line from the overall level, using the same scan as `scan` (no cache; a scan
takes tens of milliseconds, fast enough for every prompt):

| level | emoji | text |
| --- | --- | --- |
| high | `🔴 HIGH (7)` | `ai:high:7` |
| medium | `🟠 MEDIUM` | `ai:medium` |
| low | `🟡 LOW` | `ai:low` |
| opted-out | `🔵 OPTED OUT` | `ai:opted-out` |
| ok | `🟢 OK` | `ai:ok` |
| not-installed | `⚪ NO AI APPS` | `ai:not-installed` |
| below low, scan incomplete | `❔ INCOMPLETE` | `ai:incomplete` |

The count is the number of entries (apps and monitors) at `low` or above, shown when there are
two or more. An incomplete scan with alerts appends ` ⚠` (` !incomplete` in text). `nerd` uses
Nerd Font glyphs, and `json` is the document in §3.6. See [integrations.md](integrations.md).

`sources` prints a TSV of `tool  origin  state  path`, or JSON with `--json`.

`explain <id|key>` runs the same scan, finds the finding by `id` (`claude-11`) or `key`, and
prints the finding block, then "What the <export> export carries (catalog …; <docs>)", `Flags`
(the gate lines), `Identity (on every record)`, `Resource`, the records (`Events`, `Metrics` or
`Spans`, each with `*` if seen on the wire and `(may)` if not in the vendor docs, its per-event
keys, and its content attributes with their sent state) and a `Sample record`. An unknown id
exits 2 (`no finding 'x'; `cainary scan` lists the ids`); a finding without a payload prints its
block plus "This finding has no payload preview." `explain` takes the COMMON flags.

`otel-debug` prints two lines and exits 0: that the collector is a separate program
(`cainary-otel-debug`), and that `cainary` itself never listens on or connects to the network.
It never runs anything.

## 9. User interfaces

### 9.1 Core↔UI contract

A UI runs the CLI as a subprocess and decodes its JSON. There is no FFI. Compared with a C ABI or
uniffi:

- **Build:** two independent builds (`cargo`, `swiftc`); the app bundle just copies the binary.
- **UI-agnostic:** any toolkit or script can spawn a process and parse JSON.
- **One contract:** the UI shows exactly what `cainary scan --json` prints, and the goldens test
  both.
- **Isolation:** a parser panic, hang or memory spike can't take down the menu bar app.
- **Auditability:** the user can run the same binary and see the same result.
- **Cost:** a process spawn per scan, at most a few times a minute. Irrelevant.

The macOS app bundles the helper at `cAInary.app/Contents/Helpers/cainary` (not
`Contents/MacOS`, where `cAInary` and `cainary` would collide on a case-insensitive disk) and
runs `scan --json --env-kind launchd [--since -]` with the baseline on stdin. Its bounded runner,
change tracking and screens are in [macos.md](macos.md).

### 9.2 Linux UI

The Linux tray app (`cainary-tray`, Qt 6 / QML, in the separate `linux/` workspace) follows the
same contract and needs nothing from the core beyond the CLI. It runs
`cainary scan --json --env-kind launchd`, like the macOS app, refuses a schema major other than 3,
and draws `status`, `apps`, `others` and their findings. It keeps a baseline and the notified
change ids under `$XDG_STATE_HOME/cainary/` and passes it as `--since -`, like the macOS app's
change tracking. It looks for the CLI next to its own executable, then at `/usr/bin/cainary`,
never on `PATH`. `launchd` is the core's "no login shell" environment kind: a tray started at
login has no shell exports, so scanners mark environment-dependent findings best effort (§6.5)
and they can differ from a terminal scan ([linux.md](linux.md) §3). Both apps show the same text
for the same report, and the CLI's output is identical on macOS and Linux (the shared starship
config). Placement, packaging and the runner are in [linux.md](linux.md).

**Toolkit split.** The UI is QML, driven by cxx-qt `QObject`s that stay thin: `AppController`
and `SettingsController` hold a view as JSON that `tray-model` computes, so the QML never
interprets the report. About 360 lines of C++ remain, in `linux/crates/cainary-tray/cpp/`,
because Qt offers no Rust-callable API for them:

| File | Lines (approx.) | Why it is C++ |
| --- | --- | --- |
| `icons.cpp` | 110 | The QML image provider and the pixmap fallback for the tray host: SVG rendering with a recoloured palette. |
| `layershell.cpp` | 85 | LayerShellQt is a C++ API (`LayerShellQt::Window`); built only with the `layer-shell` feature. |
| `qt_shims.cpp` | 160 | Qt message capture for `--self-test`, controls-style probe, platform name, screen geometry, clipboard, activation token, window grab and the dark palette. |
| `cainary.h` | 35 | The declarations the bridge imports. |

Popup placement has three strategies (`layer-shell`, `x11`, `decorated`). There is no
compositor-specific scripting: layer-shell covers Plasma and wlroots, and GNOME gets an ordinary
window (linux.md §2).

**Threads.**

- **Qt main thread:** every `QObject`, the QML engine and the controller's slots. Nothing
  blocks it.
- **Controller thread:** one worker that serialises `AppMessage`s from the Qt thread and the
  D-Bus thread and turns store outcomes into view updates.
- **Store threads:** the runner worker that spawns `cainary` and a scheduler timer thread; both
  talk to the controller only through channels.
- **D-Bus thread:** one `async_io::block_on` thread in `tray-dbus` (ksni, notifications,
  single instance, logind, watcher). It exchanges `UiEvent` and `TrayUpdate` with the controller.

**Shutdown order.** On Quit or a signal the app stops in this order, so nothing writes to a
service that is already gone: `scheduler.stop()`, then the D-Bus `service.shutdown()`, then
`store.shutdown(3 s)`, which cancels a scan in flight and kills the child's process group, then
the controller gets `Stop` and is joined. If the scan doesn't stop within 3 s the app logs it and
exits anyway.

## 10. Testing

All Rust tests are `cargo test` on macOS and Linux. They need no network and no real machine
state.

- **Unit tests** sit next to the code: value conversion and budgets, each redaction rule (with
  synthetic tokens like `sk-test-EXAMPLE`), deny-list cases (relocations, aliases, case),
  analysis (counting per mode, levels, entries, summaries), finding keys, every diff rule, hook
  classification, and the per-tool resolvers against `tests/resolve/` fixtures.
- **Fixtures** live in `crates/cainary-core/tests/fixtures/<name>/` with `fixture.json`, `root/`
  and `home/`. They hold only synthetic data: `example-corp.com`, `AcmeCollector`, user `alice`.
  Names are prefixed by tool (`claude-code-org-macos`, `codex-bad-base64`, `device-only-proxy`,
  …), and each sets `tools` to its own scanner, so a change in one scanner never touches
  another's goldens. `empty-macos` and `empty-linux` cover a clean machine.
- **Goldens:** `tests/golden.rs` runs every fixture and compares pretty JSON with
  `tests/golden/<name>.json`. `CAINARY_BLESS=1 cargo test` rewrites them; review the diff.
- **Guarded-read tests** (`fs.rs`, temp dir): a symlink as the last component or as a parent into
  a denied dir, a FIFO at a config path, a file over the cap, a hard link, relocated tool homes,
  a home that is itself a symlink, and upper-case aliases.
- **Safety guards** (`tests/guards.rs`):
  1. No `std::fs`, `std::process`, `std::net` or `std::env` in `crates/*/src` outside
     `cainary-core/src/harness/` (the CLI `main.rs` may read args, `NO_COLOR` and stdin). Guards
     1–3 leave `cainary-net/src/` to its own rules N1–N3 below.
  2. `OpenOptions` only in `harness/fs.rs`, and no write, create, append, truncate or remove calls
     anywhere outside tests.
  3. `Command::new` exactly once, in `harness/platform.rs`, with the literal `/usr/sbin/scutil`;
     `libc::` only in `harness/fs.rs`.
  4. `Cargo.lock` packages ⊆ the allowlist, which is three sets: `CORE_ALLOWED` (the core's
     closure), `NET_ONLY` (`cainary-net`, `regex`, `regex-automata`, `regex-syntax`,
     `aho-corasick`) and `TLS_ONLY` (`rustls`, `ring`, `rcgen`, `rustls-webpki`, `rustls-pki-types`
     and the rest of their closure, including the optional `x509-parser` family the lock lists for
     rcgen; no `aws-lc-rs`). The **dependency closure** of `cainary` and `cainary-core` (walked
     through `[[package]].dependencies` in `Cargo.lock`) must not reach any `NET_ONLY` or
     `TLS_ONLY` package. A further set (goal 3's `MITM_ONLY`) is one more row in the closure
     table.

  The collector crate has its own source guards, over `crates/cainary-net/src/`:

  - **N1:** `std::net` only in `server.rs`; no outbound or resolving call anywhere in the crate
    (`TcpStream::connect`, `.connect(`, `connect_timeout`, `UdpSocket`, `ToSocketAddrs`,
    `to_socket_addrs`, `lookup_host`, Unix sockets), the identifier `connect` is banned outright,
    and renaming `std`/`core`/`alloc`/`net` in a `use` is refused so an alias can't hide a dial.
  - **N2:** `std::fs` only in `logfile.rs` (write), `redflag/file.rs` (read) and `tls/ca_file.rs`
    (the certificate directory); `OpenOptions` and write-shaped calls only in `logfile.rs` and
    `tls/ca_file.rs` (`.write(` is also allowed in `server.rs` and `tls/mod.rs`, which can't open
    a file); `std::env` and `std::process` only in `main.rs`.
  - **N3:** no `Command` anywhere in the crate; `libc::` only in `logfile.rs` (the open flags and
    the effective uid), `tls/ca_file.rs` (the same, `flock`, `openat`) and `tls/privdrop.rs`
    (`capset`, `prctl`). Guard 3's "`Command::new` exactly once" counts the whole workspace.
  - **N4 (manifests):** the `cainary-core` and `cainary-cli` manifests never mention
    `cainary-net`; the net manifest declares only `cainary-core`, `libc`, `rcgen`, `regex`,
    `rustls`, `serde`, `serde_json`, `time` and `toml` (in any dependency table) and sets
    `publish = false`.
  - **N5 (TLS crates):** `rustls`, `rcgen` and `ring` are named only under
    `cainary-net/src/tls/`, or on a line right after `#[cfg(feature = "tls")]`; `mod tls` is gated
    the same way.

  Every new guard has a `fires` test that feeds a violation in memory.

  Guard 5, the canary (`tests/canary.rs`): a temp fixture plants a marker in credential files
  from the deny-list and symlinks tool configs (`~/.claude/settings.json`, `~/.codex/config.toml`,
  …) to them. A scan of every tool must never show the marker, each symlinked config must be
  `refused`, and the report must be incomplete.

  Plus, in `harness/ctx.rs`: a fixture without `scutilProxy` gives an `absent` proxy source and
  `scutil` is never called.
- **CLI tests** (`cainary-cli/tests/cli.rs`) run the built binary against fixtures and compare
  text, `--summary`, `--since`, status (all formats) and sources output with
  `cainary-cli/tests/golden/`, and check exit codes.
- **Collector tests** (`cainary-net`): unit tests for the HTTP parser, args, red-flag presets (hits
  and near-misses), the naming policy and the escaping; `tests/server.rs` runs the library server
  on port 0 and posts to it over `std::net::TcpStream` (limits, timeouts, Host/Origin refusal,
  masking, log file, `--once`, stdin lifeline). `tests/redflag_timing.rs` is `#[ignore]`.
- **App tests:** `make ui-test` decodes every Rust golden through the Swift model, runs the app's
  unit checks against stub helpers and the real binary, and renders snapshots (macos.md §5).
- **Smoke:** `make scan` runs the real scan on the dev machine. It is not golden-checked.

## 11. Build, CI and release

- **Toolchain:** `mise.toml` pins rust (with both Apple and both Linux musl targets, rustfmt and
  clippy), swift (macOS only), shellcheck, jactionlint, mr-boxington, and on Linux `cargo-deb` and
  `cargo-generate-rpm`. Its tasks wrap the Makefile. Under mise, cargo runs through `mbx` (a shared
  build cache) and `SWIFTC` points at mise's swiftc, or plain `swiftc` where swift isn't a mise
  tool. When `CARGO_HOME` isn't writable (a sandbox), the Makefile moves it to
  `$TMPDIR/cargo-home`. The Linux tray also needs the distro's Qt 6 development packages
  ([linux.md](linux.md) §8).
- **Version:** `[workspace.package] version` in `Cargo.toml` is the single source.
  `bundle.sh` stamps it into the app's `Info.plist` and refuses a helper that reports a
  different version.
- **Makefile targets:** `build`, `test`, `fmt`, `lint` (`cargo fmt --check`, clippy
  `-D warnings`, `swift format lint --strict`, shellcheck), `lint-actions` (jactionlint, with
  shellcheck on `run:` scripts; CI's `actions-lint` job, and a dependency of `mise run check`),
  `check-rust`, `check` (lint + test + ui-test), `core-universal` (release builds for both Apple targets, `lipo` →
  `target/universal/cainary`), `app`, `bundle` (`RELEASE=1` for the universal release app),
  `ui-test`, `scan`, `release` (release `cainary` and `cainary-otel-debug` in `target/release/`), `otel-debug` (runs that collector; `OTEL_DEBUG_ARGS=` for flags), `publish-check` (`cargo publish --workspace --dry-run`), `clean` (also
  `linux/target`). The app and bundle steps are in macos.md §4. Checks for the other OS are skipped with a
  note, never failed: on Linux, `lint` skips `swift format` and `ui-test` is a no-op; on macOS, `linux-lint`,
  `linux-test`, `linux-check` and `linux-ui-test` are no-ops (`HOST_OS`, from `uname -s`). The Linux targets use the
  `linux/` workspace through `--manifest-path`: `linux-cli` (static musl `cainary`),
  `linux-build`, `linux-test` (under `dbus-run-session`, `QT_QPA_PLATFORM=offscreen`),
  `linux-fmt`, `linux-lint`, `linux-check` (lint, test, shellcheck, desktop-file and AppStream
  validation), `linux-ui-test`, `linux-run`, and `linux` (CLI plus tray release build, then
  `packaging/linux.sh` into `dist/`; `LINUX_FORMATS` defaults to `tar`). See
  [linux.md](linux.md) §8.
- **Install:** copy `cAInary.app` to `/Applications`. For the CLI, optionally
  `ln -s /Applications/cAInary.app/Contents/Helpers/cainary ~/.local/bin/cainary`, or
  `cargo install cainary --locked`. The other methods are in [distribution.md](distribution.md).
- **CI** (`.github/workflows/ci.yml`): Conventional Commit messages, action pins, `make check` on
  macOS (uploading the UI snapshots), and `make check-rust` plus `make publish-check` on Linux.
  CI doesn't use mise: it runs plain `make` with rustup's cargo (version read from `mise.toml`)
  and Xcode's swiftc. The Linux tray has its own jobs, which run `packaging/ci/linux-ci.sh` in
  distro containers (Debian trixie, Fedora, Arch; see [distribution.md](distribution.md)).
- **Release** (`.github/workflows/release.yml`): an action-pin gate, `make check` and the Linux
  tray checks (`make linux-check` on Debian trixie), then `prepare` has git-cliff
  pick the version (`scripts/set-version.sh` updates `Cargo.toml`, `Cargo.lock`,
  `linux/Cargo.toml`, `linux/Cargo.lock` and the AppStream release list) without pushing, the
  builds apply it locally to the same commit for the universal macOS bundle and the Linux
  tarballs, .deb and .rpm, and one `checksums` job hashes and attests every asset. Only then does
  `publish` commit the bump and `CHANGELOG.md`, tag, and create the release with all assets. The crates `cainary-core` and `cainary` (the CLI
  package; its directory is `crates/cainary-cli`) are then published to crates.io. The macOS
  bundle is signed there with the project's pinned self-signed certificate (no notarization);
  local bundles are signed ad hoc. The jobs
  are in [distribution.md](distribution.md).

## 12. OTel debug collector (`cainary-otel-debug`)

A separate, opt-in program (crate `cainary-net`, `publish = false`) that receives OTLP/JSON
exports on loopback and prints what they carry, so a user can see what a tool's telemetry
actually contains, as opposed to what the payload preview (§3.7) predicts from config. It is the
one place in the repository that listens on a socket (§1). It is inbound-only: it never opens an
outbound connection, never resolves a name, starts no process, and reads only the red-flags file
the user names. `cainary` never starts or contacts it. It is not a daemon: it runs while the user
runs it (a terminal, or a child of a GUI toggle), and leaves no pidfile, service or autostart.

The collector is **unauthenticated**. Any local process can post to it, so the stream shows what
was *received*, and the vendor is inferred from the payload, not proven by the sender.

### 12.1 Command line

```
cainary-otel-debug [--port <n>] [--listen <ip>]... [--json] [--show-values] [--once]
                   [--log-file <path> [--log-max-mib <n>] [--log-keep <n>]]
                   [--red-flag <name>=<text>]... [--red-flag-re <name>=<regex>]... [--match-case <name>]...
                   [--red-flags <file>] [--preset <name>]... [--no-default-red-flags] [--list-presets]
                   [--exit-on-stdin-eof] [--config-stdin]
                   [--tls --tls-host <name>... [--tls-public-port <n>]]
cainary-otel-debug --trust claude-code [--dry-run] [--undo] [--json]
cainary-otel-debug --trust codex [--undo] [--json]
cainary-otel-debug --trust-status [--json]
cainary-otel-debug --delete-ca
cainary-otel-debug --version | --help
```

| Flag | Rule |
| --- | --- |
| `--port` | 0–65535, default 4318; `0` picks a free port |
| `--listen` | repeatable IP literal; each must satisfy `IpAddr::is_loopback()` (so `::ffff:127.0.0.1` is refused); replaces the default 127.0.0.1 then ::1 |
| `--json` | JSON lines on stdout (§12.6); without it, a text rendering |
| `--show-values` | print and log values raw (§12.3) |
| `--once` | exit 0 after the first batch (and its alerts) |
| `--log-file`, `--log-max-mib` (1–1024, default 10), `--log-keep` (0–9, default 3) | §12.4 |
| `--red-flag`, `--red-flag-re` | `<name>=<pattern>` split at the first `=`; text or regex |
| `--match-case` | names a pattern; patterns are case-insensitive by default |
| `--red-flags` | a TOML file (§12.5) |
| `--preset`, `--no-default-red-flags`, `--list-presets` | enable a preset (also a default-off one), start from none, list the built-ins |
| `--exit-on-stdin-eof` | a thread reads stdin and exits 0 at EOF or a read error (§12.7) |
| `--config-stdin` | the first stdin line is a JSON config (§12.7); implies `--exit-on-stdin-eof` |
| `--trust <claude-code\|codex>`, `--dry-run`, `--undo`, `--trust-status` | let a client trust the takeover CA (§12.11); `--dry-run` is for `claude-code` only; all need the `tls` feature |
| `--tls`, `--tls-host`, `--tls-public-port`, `--delete-ca` | the endpoint takeover (§12.10); needs a build with the `tls` cargo feature, else exit 2 "this build has no TLS support (cargo feature `tls`)". `--tls` defaults `--port` to 8443 |

`--flag=value` works as in `cainary`. A pattern name matches `^[a-z0-9][a-z0-9_-]{0,63}$`. A
duplicate name, a name equal to a preset, or an unknown `--match-case` name is a usage error.
`--help` and, in text mode, startup (on stderr) print the "point an agent at it" lines (§12.8).
`--red-flag` values land in shell history; the GUIs use `--config-stdin` instead.

**Exit codes:** `0` normal, `--once`, stdin EOF, or the reader of stdout went away (a broken
pipe); `1` setup (port in use, log file or red-flags file unusable, a failed bind); `2` usage
(including an invalid or oversized pattern, a non-loopback `--listen`, a bad `--tls-host` and `--tls` in a build without the feature); `3` a panic. A second `--tls` run for the same certificate directory, and `--delete-ca` while one runs, exit `1`.

**A refused privileged port.** `--port <n>` chooses the port in every mode. When `bind` fails with
`EACCES` the program exits `1` with a short fixed error (`{"v":1,"type":"error","source":"listen","message":"can't listen on <addr>: permission denied"}` on stdout under `--json`, text on stderr otherwise) and a note on stderr (`setup::privileged_port_note`; one plain line on other systems than Linux). The note gives three options, concrete for the run and printed, never run: a `cap_net_bind_service` capability on a root-owned copy (the running executable, read in `main.rs` only, counts as that when it and its directory are root-owned and writable by nobody else; otherwise `sudo install -D -m 755 -o root -g root <exe> /usr/local/libexec/cainary/cainary-otel-debug` comes first); an unprivileged port (`n + 8000`, or 8443) with a loopback-only, both-families `nft` redirect and its removal; and the `net.ipv4.ip_unprivileged_port_start` sysctl with its revert. Commands are written for both fish and bash.

### 12.2 Server

- **Bind.** Default `127.0.0.1:<port>`, then `[::1]:<port>` on the same port (Node resolves
  `localhost` to `::1` first, and Claude Code's default endpoint is `localhost:4318`). A failed
  IPv6 bind is not fatal and is noted in `hello.listen`. Sockets are bound from `SocketAddr`
  values, never strings, so there is no DNS; after `bind`, `local_addr().ip().is_loopback()` is
  asserted again. A port in use exits 1 (`port 4318 is in use (another collector?); try --port 4319`).
- **Threads.** One acceptor per listener; at most **16** connection threads (over the limit the
  acceptor writes `503` and closes); one output thread that owns stdout and the log file; and the
  stdin thread. At most **2** requests are in their read-body/parse/classify/match stage at once
  (a semaphore taken *before* the body is allocated; others wait under the request deadline and
  get `503` if they time out).
- **Timeouts and limits.** Read and write timeout 10 s; a per-request deadline of 30 s from the
  first byte (slowloris), checked before every read; keep-alive idle 10 s. Request line ≤ 8 KiB;
  headers ≤ 16 KiB and ≤ 64 (`431`); body ≤ **16 MiB** (`413` from `Content-Length` before any
  body is read; chunked bodies are counted); chunk-size line ≤ 1 KiB; trailers ≤ 8 KiB and 32
  fields, ignored; **20 MiB** total on the wire per request. After parsing, a request with more
  than **10,000 records** or **20,000 attributes** is `413`.
- **HTTP.** HTTP/1.1 keep-alive; HTTP/1.0 closes; `Expect: 100-continue` is answered after the
  Host/Origin and content checks. Framing is strict (RFC 9112): CRLF only; obs-fold, whitespace
  before a colon, bad token characters and control characters are `400`; duplicate
  `Content-Length` (even equal), both `Content-Length` and `Transfer-Encoding`, any transfer
  coding other than exactly `chunked`, and a POST without explicit framing are `400`. Every
  non-200 sets `Connection: close`.
- **Host and Origin** are checked before any body is read: exactly one `Host` equal to
  `127.0.0.1:<port>`, `[::1]:<port>` or `localhost:<port>` (or a bound address with its port);
  another value is `421`, none or several `400`. Any `Origin` header (including `null`) or any
  `Sec-Fetch-*` header is `403`. There are no CORS headers, and `OPTIONS` is `405`. This stops a
  web page, or a DNS-rebinding name, from posting to it.

| Request | Answer |
| --- | --- |
| `POST /v1/logs`, `/v1/metrics`, `/v1/traces` | `200` `{}` (`application/json`), written **before** the batch is emitted, after room in the output queue is reserved |
| other path | `404` |
| known path, other method | `405` with `Allow: POST` |
| `Content-Type` not `application/json` (parameters ignored) | `415`, saying to set `OTEL_EXPORTER_OTLP_PROTOCOL=http/json` (or `protocol = "json"` for Codex) |
| `Content-Encoding` other than `identity` | `415`, saying to unset `OTEL_EXPORTER_OTLP_COMPRESSION` |
| body not JSON | `400` `invalid JSON (line L, column C)` |
| not an OTLP document of that signal | `400` `not an OTLP <signal> document` |
| over the record or attribute limit | `413` |
| the batch can't fit one output line or the queue | `413` / `503` |
| the 17th connection, or a stalled queue or job semaphore | `503` |

Error bodies are `{"code":3,"message":"…"}` with fixed messages. Exporters retry only 429 and
5xx, so a 4xx doesn't cause a retry storm. Each rejection also emits an `error` line, rate-limited
to **10 per second**, then one summary line with `dropped`.

Protobuf and gzip are not supported (the default OTLP protocol is protobuf; the setup lines ask
for `http/json`).

### 12.3 What is printed (one policy for every payload-derived string)

Applies to JSON lines, text, the log file, alerts and any GUI notification.

- **Values** are masked as `<string, 22 chars>`, `<int>`, `<double>`, `<bool>`, `<array, 3 items>`,
  `<kvlist, 2 keys>`, `<bytes, 12 chars>` or `<empty>`. `--show-values` prints them raw (and
  writes them to the log file): a warning is printed once on stderr naming the file if there is
  one. Size limits and terminal escaping still apply with it.
- **Names** (attribute keys, record, metric and span names, scope names and versions,
  `service.*`) are printed verbatim when they match `^[A-Za-z0-9_.:/-]{1,128}$` **and** no red
  flag matches them after a complete scan; otherwise a request-local label `<unknown-key-N>` or
  `<unknown-name-N>` stands in. A secret used as a key never prints.
- **Alert `match`** is the first 3 characters plus `…(<n> chars)` when n ≥ 8, otherwise only
  `…(<n> chars)` (`AKI…(20 chars)`).
- **Errors** are fixed categories (plus a line and column for bad JSON). Serde messages, JSON
  pointers, header values and body fragments are never echoed. Methods other than the standard
  ones print as `<other>`; paths print only when they are a known route.
- **Terminal escaping.** Every attacker-derived string is escaped before it reaches a terminal:
  C0 and C1 controls, ESC, CR, LF, DEL and bidi format controls (U+202A–U+202E, U+2066–U+2069,
  U+200E/F, U+061C) become `\u{…}`. JSON lines use serde_json. Text output per batch is capped
  (256 KiB, 512 characters per value).

### 12.4 Log file (`logfile.rs`)

`--log-file` is the only thing the collector writes. Without it the collector is stream-only.

- Missing parent directories are created `0700`; an existing parent must be owned by the user
  and not group- or other-writable, else exit 1.
- The file is opened with `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`, `create`, `append`, mode `0600`,
  then validated **on the descriptor** (`fstat`): a regular file, owned by the effective user,
  one hard link; permissions are set to `0600` through the descriptor. A symlink is refused. No
  path-based check follows the open, so there is no check-then-use window.
- It always receives the JSON lines, whatever the stdout format.
- **Rotation** before a write when `size + len > max` and `size > 0`: `path.(k-1)` → `path.k` down
  to `path` → `path.1`, then the new file is created with `create_new` and validated again (an
  unexpected entry at the path stops file logging). `--log-keep 0` truncates through the
  validated descriptor. A line larger than the maximum still goes into a fresh file.
- A write error emits one `error` line (`source: "log-file"`), stops file logging and keeps
  streaming.

### 12.5 Red flags (`redflag/`)

Patterns that raise an `alert` line when a value, key or name contains them. Matching sees the
raw text before masking: every attribute key and every string or number value (recursively,
depth ≤ 32), log bodies, resource attributes, scope names and versions, and record names.

- **Kinds.** `text` (a literal, ASCII case folding only: non-ASCII letters match exactly) and
  `regex` (the `regex` crate, linear time, no look-around or backreferences). Text patterns are
  escaped into regexes, so there is one engine.
- **Limits.** A pattern is ≤ 1024 bytes; at most **64** patterns; each regex compiles under a
  1 MiB size limit and 64 nesting levels, all of them under a 16 MiB budget. Per request at most
  **4 MiB** of text is matched and at most **256 KiB** of any single value; beyond that, or past
  1,024 alert groups, the batch is marked `"scanIncomplete": true` and an `error` line
  (`source: "red-flags"`) says so. Matching is never silently truncated. An over-large regex is
  `red flag 'x': regex is too big to compile (limit 1 MiB)`.
- **Presets** (`--list-presets`; all case-sensitive regexes, all on by default except `ipv4`):
  `email`, `private-key`, `jwt`, `aws-access-key`, `github-token`, `anthropic-key`, `openai-key`,
  `slack-token`, and `ipv4` (off). IPv6 is left out because IPv6 regexes match hex-and-colon
  strings such as timestamps; `ipv4` is opt-in because false positives can't be measured on the
  sanitized fixtures. The `email` preset also matches `git@github.com:org/repo`, by design.
- **Selection order.** Default presets (unless `--no-default-red-flags`), then each config's
  `[presets]` table (the file, then `--config-stdin`), then `--preset`; then CLI patterns, then
  the configs' patterns.
- **Alerts** are aggregated per batch by (pattern, attribute key, where) with a `count` and up to
  8 sample event names, at most 1,024 groups; identifiers are cut to 256 bytes. This is
  aggregation, not throttling: throttling belongs to the GUIs.
- **The TOML file** (`--red-flags`, ≤ 1 MiB, read once, strict; an unknown key is exit 2 naming
  the key):

```toml
[presets]                 # optional: true or false per preset name
ipv4 = true
email = false

[red_flags]
customer = "acme-internal"                                   # text, case-insensitive
prod-db  = { kind = "regex", pattern = '\bdb-[0-9]+\.prod\.example-corp\.com\b' }
api-host = { pattern = "api.example-corp.com", case_sensitive = true }
```

- **Text path decision.** The design started with Aho-Corasick for text patterns. A timing test
  (`tests/redflag_timing.rs`, `#[ignore]`; `cargo test -p cainary-net --release -- --ignored
  --nocapture`: 505,000 synthetic values, 20 literals) measured 307 ns per value for the
  Aho-Corasick `Matcher` against 268 ns for one case-insensitive `RegexSet` of the escaped
  literals, a ratio of 0.87× against a required 1.5×. The direct dependency and its path were
  dropped; text goes through `regex::escape`. Adversarial single values at the 256 KiB cap
  (repeated characters against 40 overlapping literals, presets plus literals, a mostly-matching
  set) take 1.3–2.6 ms.
- `redflag` is `pub` in the library so goal 3 (below) can reuse it.

### 12.6 JSON lines (`--json`), version 1

A public contract like `scan --json` (§3.6), for the GUIs and for scripts. One JSON object per
line on stdout (and in the log file), with keys in this order: `v` (integer major, 1), `type`,
`ts` (RFC 3339 UTC), then the type's keys. A `batch` and its `alert` lines share a `seq`.

**Versioning.** `v` is an integer major. Within a major, changes are additive only: new optional
keys, new `type`s and new values of open strings. Consumers ignore unknown `type`s and unknown
keys, and refuse a `v` they don't know (the GUIs stop with "Update cAInary"). `error.source` is
an **open string** (today `http`, `log-file`, `red-flags`); consumers tolerate others. A line is
at most **1 MiB**: when a batch would exceed it, `resources` is dropped and `resourcesOmitted:
true` is set, and the `summary` always stays.

| `type` | Keys after `v`, `type`, `ts` |
| --- | --- |
| `hello` (first line) | `generator` (`cainary-otel-debug <version>`), `mode` (`receiver`, or `tls-receiver` for the takeover), `listen` (bound addresses, plus a note for any that couldn't bind), `endpoint` (`http://127.0.0.1:4318`), `showValues`, `logFile` (path or `null`), `redFlags` (`[{name, kind, preset, caseSensitive}]`), `tls` (takeover only: `{hosts, ca: {path, sha256}}`, host names as the user configured them, not a sender identity), `setup` (`{claudeCode: [...], codex: [...], notes: [...], takeover?: [...]}`, the §12.8 lines with the real endpoint; in takeover mode `claudeCode` and `codex` hold the certificate-trust variables and `takeover` the instructions of §12.10) |
| `batch` | `seq`, `signal` (`logs`, `metrics`, `traces`), `path` (`/v1/<signal>`, or the fixed marker `<custom path>` in takeover mode: request paths are never printed), `host` (takeover only: the validated host name), `bytes`, `vendor` (`claude-code`, `codex` or `null`), `service` (`{name, version}` or `null`), `catalog` (the catalog label or `null`), `records`, `notInCatalog`, `summary`, `resources` or `resourcesOmitted`, and `scanIncomplete` when set |
| `alert` | `seq`, `pattern`, `preset`, `signal`, `event` (record name or `null`), `events` (up to 8 names), `attribute` (key label or `null`), `where` (`key`, `value`, `body`, `resource`, `scope` or `name`), `count`, `match` |
| `trust` | one per `--trust` call: `target` (`claude-code`, `codex`), `action` (`preview`, `applied`, `already`, `undone`, `nothing-to-undo`, `refused`), `message` (fixed text), `settingsPath`, `backupPath`, `key` (`NODE_EXTRA_CA_CERTS` or `null`), `from`, `to`, `bundlePath`, `command` (`null` where not applicable) |
| `trust-status` | `claudeCode` (`{state: applied\|absent\|other-value\|managed, settingsPath, value}`), `codex` (`{state: ready\|absent, bundlePath, command}`), `caPath`, `caExists` (the collector certificate file exists), `note` (a sentence when an interrupted change was just finished or cleared, else `null`) |
| `error` | `source`, then either `status`, `method`, `path`, `message` (for `http`) or `dropped`, `message`, or `message` alone |

- `summary` is `{identity: [keys], resource: [keys], records: [{name, kind, count, known, what?,
  attrs: [{key, group, flag?, known}]}]}`: what a GUI draws. `identity` and `resource` list the
  keys the catalog puts in those groups; `what` is the catalog's one-line description; `flag` names
  the setting that gates a content attribute. `resources` is the raw tree, shown only under "Raw
  records": `[{attrs: [F], scopes: [{name, version, records: [{name, kind, known, unit?,
  metricType?, span?, attrs: [F]}]}]}]`. `kind` is `event`, `metric` (one record per data point,
  with `unit` from the catalog and `metricType` `sum`, `gauge`, `histogram`,
  `exponentialHistogram` or `summary`), `span` or `span-event` (with `span`, its span's name).
- `F` is `{key, group, flag?, known, type, len?, value}`: `type` is `string`, `int`, `double`,
  `bool`, `array`, `kvlist`, `bytes` or `empty`; `len` is the character, item or key count when
  there is one; `value` is always a string, masked unless `showValues` (§12.3). `group` is
  `identity`, `resource`, `event` or `content`, and `null` when the key isn't in the catalog.
- The vendor comes from `service.name` (`claude-code`, `claude-code-desktop`, `codex*`), else from
  the scope name, else it is `null` and every record counts in `notInCatalog`. Names (record, key,
  scope, service) print verbatim only when they are exact catalog entries, or pass the name rule
  after a complete red-flag scan (§12.3); a wildcard catalog entry such as `vcs.ref.head.*` still
  classifies its keys (`known`, `group`) but they take the name rule.
- A rejected request emits no `batch`, only an `error` line.

**Text mode** (no `--json`) prints per batch a header line (`── logs · claude-code 2.1.316 · 12
records · 12:17:49Z`), a `resource` line, an `identity` line ("on every record"), then per record
name its count and the catalog's description, with `event`, `content` (each content attribute
followed by its gating flag) and `NOT IN CATALOG` lines taken from the first record of that name,
and one `⚠ red flag <name>: …` line per alert. Every payload-derived string is escaped (§12.3),
and retained text per batch is capped at 256 KiB. The setup lines go to stderr at startup.

### 12.7 Running it from the apps, and `--config-stdin`

The macOS app and the Linux tray start the collector as a child through an explicit "OTel debug
collector" toggle, with `--json --exit-on-stdin-eof --config-stdin` (and `--port`, `--log-file`
in argv).

- **Lifeline.** The child's stdin is a pipe the app holds and never writes after the config. When
  the app dies for any reason, SIGKILL included, the kernel closes the write end, the stdin thread
  sees EOF and calls `process::exit(0)` independently of stdout locks and queues. A stdout write
  by an orphan fails (`BrokenPipe`, since SIGPIPE is ignored) and also exits 0. Toggling off or
  quitting closes stdin, then SIGTERM, then SIGKILL after a grace period.
- **`--config-stdin`.** The first stdin line is one JSON object, at most 1 MiB, read within 5 s
  (else exit 2): `{"v":1,"redFlags":[{"name","kind":"text|regex","pattern","caseSensitive"}],
  "presets":{"<name>":true|false}}`. The check is strict: unknown keys, wrong types, bad names,
  unknown presets and patterns that don't compile are exit 2. Errors name the key or pattern,
  never its text. It keeps pattern text out of argv, where any process of the same user can read
  it. After the config line, stdin stays open as the lifeline.
- The apps' stream handling (line cap, retention, alerts, notifications) and their toggle UI are
  specified in `docs/design/otel-payload-preview.md` §9 and each app's own document.

### 12.8 "Point an agent at it"

`--help`, the text-mode startup note and `hello.setup` carry the same lines, with the real
endpoint:

- **Claude Code**, from the shell that starts it: `CLAUDE_CODE_ENABLE_TELEMETRY=1`,
  `OTEL_LOGS_EXPORTER=otlp`, `OTEL_METRICS_EXPORTER=otlp`,
  `OTEL_EXPORTER_OTLP_PROTOCOL=http/json`, `OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:<port>`,
  `OTEL_LOGS_EXPORT_INTERVAL=1000` and `OTEL_METRIC_EXPORT_INTERVAL=10000`.
- **Codex**, in `~/.codex/config.toml` `[otel]` or one `-c` per line: `otel.exporter`,
  `otel.metrics_exporter` and `otel.trace_exporter`, each `{otlp-http={endpoint="http://127.0.0.1:<port>/v1/<signal>",protocol="json"}}`.
- **Notes:** settings can override these. A Claude Code `env` block in `~/.claude/settings.json`
  overwrites the same shell variable, and managed settings override both; a managed
  `OTEL_EXPORTER_OTLP_ENDPOINT`, `_PROTOCOL` or `_HEADERS` also removes your local endpoints, so
  Claude Code keeps sending to your organization's collector
  (<https://code.claude.com/docs/en/monitoring-usage#how-managed-settings-lock-the-otlp-destination>).
  Codex `requirements.toml` `[otel]` overrides `config.toml`. `cainary scan` shows which of these
  your organization sets. The collector is unauthenticated.

### 12.9 Goal 3 compatibility

The collector stays inbound-only for good. The traffic watchdog (`docs/design/ai-traffic-watchdog.md`)
would be a separate `cainary-proxy` binary behind a non-default `mitm` feature, with its own
`MITM_ONLY` package set; guard 4's closure rule is a table so a third set is one more row. The
JSON-lines contract is open for a future `leak` type, and `redflag` is reusable.

### 12.10 Endpoint takeover (`--tls`)

For a telemetry host that managed settings pin to HTTPS, which no shell variable can override.
The user points that host name at loopback, and the collector serves it. It **forwards nothing**:
while the takeover runs, the organization's collector receives nothing from this machine and every
other request to that host fails. `--help`, the startup text and the README say so. The
recommended default for pinned HTTPS endpoints is the later proxy (§12.9); the takeover stays for
users who can't change how the agent is launched. It is built only with the `tls` cargo feature
(release builds enable it; a plain `cargo build` doesn't), and the code lives in
`cainary-net/src/tls/`.

- **Flags.** `--tls --tls-host <name>` (repeatable, 1–32; DNS names of at least two labels, no
  wildcard or IP, ≤ 253 bytes, lowercased and deduplicated). The default port is **8443**; binding
  is loopback only, as ever. `--tls-public-port` (default 443 when the bound port isn't 443) is the
  port an exporter's URL uses. `--delete-ca` removes the certificate file (and refuses while a run
  holds the lock).
- **Privilege.** The program prints, and never runs, a loopback-only `nft` redirect of 443 to 8443
  for locally generated traffic (both address families, exact destinations) with its removal. As
  an alternative it documents `setcap cap_net_bind_service=+ep` only for an installed binary in a
  root-owned directory (`/usr/bin/cainary-otel-debug`), never a development path. If the process
  holds `CAP_NET_BIND_SERVICE` it drops every capability right after binding and before the first
  accept (`tls/privdrop.rs`; the stdin thread, started earlier, drops its own copy). It never
  calls `sudo`, `setcap`, `nft` or edits `/etc/hosts`.
- **CA.** A new CA per start: ECDSA P-256, valid from an hour ago for 30 days, name-constrained
  (critical) to exactly the `--tls-host` names, `CA:true` with path length 0, `keyCertSign`. The
  constraints are defence in depth: DNS constraints cover subdomains and enforcement on a directly
  trusted root depends on the client (rustls/webpki enforces them; it does not enforce a trust
  anchor's path length). What restricts the names is that the leaf issuer signs only for a
  configured host, and the SNI allowlist. The private key exists only in memory: it is never
  serialized, written, printed or logged. Leaves (P-256, CA:false, `digitalSignature`, `serverAuth`,
  one DNS SAN) are built once per host at startup.
- **Certificate file.** Only the public certificate is written, to
  `$XDG_STATE_HOME/cainary/otel-debug-ca.pem` (default `~/.local/state/…`; macOS
  `~/Library/Application Support/cAInary/`), a path that stays fixed so `NODE_EXTRA_CA_CERTS` is
  stable across runs. The directory is opened through a descriptor and must be ours with no
  group/other write (a symlinked final component is refused); the temporary is made with
  `openat(create_new | O_NOFOLLOW | O_CLOEXEC)`, set to 0644 through its descriptor and renamed
  in place; an exclusive `flock` on a lock file there is held for the whole run. It is never
  installed in any trust store.
- **Server.** TLS 1.2 and 1.3 (rustls, ring), ALPN `http/1.1` only (a client offering only other
  protocols is refused; offering none is fine), no early data, bounded TLS buffers. The connection
  slot is taken before any TLS state; an over-limit connection is closed with no handshake and no
  plaintext reply. Every underlying socket read and write, including the several a TLS record can
  take, is clipped to the absolute deadline in force (accept, idle, request, write or linger), so a
  trickled record can't outlive it. An absolute 30 s deadline from accept covers the handshake and the first
  request, enforced on every TCP read and write by clipping the socket timeout (a trickled
  handshake or a stalled write can't outlive it); later requests keep the usual deadlines. A
  handshake is accepted only for a configured SNI (exact, case-insensitive); a refusal is an
  `error` line (`source: "tls"`) with a fixed message per category (no SNI, SNI not in `--tls-host`,
  no common ALPN, the client rejected the certificate and doesn't trust the CA, not TLS, protocol
  error, the client went away), at most one line per category per 10 s with a `count`.
- **Requests.** `Host` must be exactly one header whose host equals the connection's SNI, with no
  port (443) or the bound port or the public port: malformed is 400, a mismatch 421; no loopback
  aliases. `Origin` and `Sec-Fetch-*` are 403 as before. Routing accepts POST to any path (any
  other method 405; origin-form only, never `CONNECT`, forwarding, redirects or tunnelling; the
  query is ignored): the signal is the path suffix `/v1/<signal>`, else the last segment
  `logs|metrics|traces`, else the body's single OTLP root key; a path/body conflict or no signal
  is 400. Every §12.2 limit applies. Request paths, queries and headers are never printed.
- **Startup text** (also `hello.setup.takeover`): the warning, `/etc/hosts` lines for the families
  actually bound, the redirect and its removal, `env NODE_EXTRA_CA_CERTS=<path> claude`, the
  Codex variables, the certificate's SHA-256, and the lifecycle (start the exporter after the
  certificate is published and restart it after every run, since each run makes a new CA;
  deleting the file doesn't revoke trust a process already loaded).

### 12.11 Trusting the takeover CA (`--trust`, `src/trust.rs`)

The exporting process has to trust the takeover's CA, and the CA changes at every start. `--trust`
makes that a one-time step. It is the only code that edits another program's file, on an explicit
action only, and it needs the `tls` feature.

- **Claude Code** (`--trust claude-code [--dry-run] [--undo]`). Sets `env.NODE_EXTRA_CA_CERTS` in
  the user's `~/.claude/settings.json` (or `$CLAUDE_CONFIG_DIR`) to the collector CA path, and
  nothing else. If the key already holds another path, it is never overwritten with ours alone: a
  combined bundle (that file's certificates plus the collector's, last and exactly once) is written
  as `otel-debug-claude-bundle.pem` next to the CA, and the key points there. If your shell sets
  `NODE_EXTRA_CA_CERTS` the message says so (the shell value wins). If managed settings set the
  key (resolved with the core's Claude Code configuration resolution, in-process and read-only),
  it refuses: they override this.
- **File safety.** The directory is opened through a descriptor and validated with the same
  root-down walk as the CA directory; **a directory that group or others can write is refused**
  (the message gives `chmod go-w <dir>`), because an authorized writer could swap the temporary
  file between its validation and the rename. The file is refused if it is a symlink, not yours,
  not a regular one-link file, or over 1 MiB.
- **Lossless edit (`jsonedit.rs`).** The file is not round-tripped through a value tree (that
  would change integers past 64 bits, precise decimals and drop duplicate members). A strict
  scanner (RFC 8259: no comments, no trailing commas, depth ≤ 64, ≤ 1 MiB) locates the top-level
  `env` member and its `NODE_EXTRA_CA_CERTS` member and splices only that, or adds the member (or
  `env`) in the file's own indentation. A key twice in one object, at any level, is refused. Every
  other byte stays identical, and apply followed by undo restores the original bytes exactly. A
  new file is `{"env": {…}}` with a trailing newline.
- **Concurrent editing.** Claude Code may write the file too, so the edit is compare-then-swap:
  the file is read once (bytes and device, inode, size, mtime), and immediately before the rename it
  is read again; if either differs nothing is written, the stale backup is removed and the answer
  is `refused`: "Your Claude Code settings changed while editing; close Claude Code and try
  again." No POSIX call compares and renames atomically, so a window of microseconds remains; the
  preview therefore says to close Claude Code first. Neither undo nor any recovery ever overwrites
  or deletes content that differs from what cAInary last wrote.
- **Transactions.** Before the settings change, a pending record (hashes of the file before and
  after, the original value, the backup name) is written durably to `otel-debug-trust.json` (file
  and directory fsync); the backup, the swap and the record that replaces it are fsynced too. A
  crash at any point is reconciled by the next `--trust` or `--trust-status` from the file's hash:
  after the swap, the change is committed (or the undo completed); before it, the record is
  cleared; if the file has changed since, it is left alone. A failure to write the final record is
  reported (never as success) and never rolls the settings back.
- **One lock, and staging.** Every `--trust` and `--trust-status` call holds one exclusive lock
  (`otel-debug-trust.lock` in the state directory, separate from the collector's run lock so
  `--trust` works while it runs) across recovery, reads, edits and the final state write; a second
  caller is refused with a fixed message after waiting 10 s (Codex and the bundle refresh at a
  `--tls` start too). `--trust-status` waits 2 s and, if it can't get the lock, only inspects: it
  never clears a transaction another process is in the middle of. The new settings file is written
  and fsynced to a temporary first, then compared against the file, then renamed at once. A failure
  after the rename or unlink (a failed directory fsync) is reported as uncertain, keeps the
  transaction and never restores old state or claims nothing changed.
- **Input hygiene.** The settings file must be valid UTF-8 (no lossy conversion); reads are
  bounded by the 1 MiB cap itself, so a file that grows during the read is refused; the edited
  result and any bundle are checked against the same cap before anything is recorded; file names
  that come from a record are validated (`settings.json.cainary-…bak` only) and a NUL in a name is
  an error, not a panic.
- **Previews and status never write.** `--dry-run` (apply or undo) takes no lock, finishes or clears
  nothing and deletes nothing: it only mentions a pending transaction. Recovery runs only in a call
  that holds the lock.
- **State and undo.** The state file records the settings path, the original value, what was
  written, whether the file and the `env` object were created, and the hashes and backup that make
  an exact restore possible. `--undo` acts only on the **same settings location** it recorded (a
  changed `CLAUDE_CONFIG_DIR` is refused with the reason, and a record never counts for another
  location's status) and only when the current value is the one it wrote. If the file is exactly
  as cAInary left it, the original bytes come back from the verified backup; otherwise just this
  key is put back (or removed), `env` is dropped if it was created and is now empty, and a file
  it created is deleted if now `{}`. A backup of the state before the change is made first, and
  the bundle is removed. Otherwise it answers `nothing-to-undo` (no record) or `refused` (the value
  changed since). `--undo --dry-run` changes nothing, not even a stale record.
- **Codex** (`--trust codex [--undo]`). Writes `otel-debug-codex-bundle.pem` (0644): the system
  roots (first existing of `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`,
  `/etc/ssl/certs/ca-certificates.crt`, `/etc/ssl/cert.pem`) plus the collector CA, and returns
  `env CODEX_CA_CERTIFICATE=<quoted path> codex`. Codex replaces the system roots with that one
  bundle, hence the combined file. No Codex configuration or shell file is touched; `--undo`
  deletes the bundle.
- **Each `--tls` start** regenerates the recorded bundles from their originals plus the new CA,
  so the paths never change; the client still has to be restarted. Nothing is refreshed, and a
  warning is printed, if a source file has gone.
- **Reading other bundles.** The harness refuses `*.pem` by design, so a bundle the user already
  points at, and the system roots, are read by `read_certs`: a regular file of at most 2 MiB that
  others can't write, symlinks followed, certificate blocks only, and a file that contains a
  private key is refused outright.
- **Output.** One `trust` line per call (§12.6), exit 0 for everything but `refused` (1);
  `--trust-status` prints one `trust-status` line. Without `--json` both print text. `--dry-run`
  prints exactly what would change; the apps show that text in their confirmation dialog.
