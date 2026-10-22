# cAInary — architecture

cAInary has a Rust core and CLI (`crates/`) and a thin SwiftUI menu bar app (`macos/`). This
document describes the core, the report it prints and how the pieces fit together. The detection
rules are in [rules.md](rules.md), the macOS app in [macos.md](macos.md), and prompt and
status-bar setups in [integrations.md](integrations.md).

## 1. Goals and non-goals

cAInary shows a developer what their employer enforces on, watches and collects from the AI
coding tools on their machine. It is free (GPL-3.0-or-later), **read-only** and **makes no
network requests**.

Design rules, in priority order:

1. **Safe.** It never writes outside its own preferences, never uses the network, and never
   opens credential files (§6.3).
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
rules, heavy redaction hardening, caching, a daemon or watch mode, auto-update, and any
server-side visibility.

## 2. Repository layout

```
./
  Cargo.toml  Cargo.lock     workspace (members: crates/*), [workspace.dependencies], the version
  mise.toml                  local toolchain pins and tasks (rust, swift, shellcheck, …)
  Makefile                   the only build entry point (mise tasks wrap it)
  rustfmt.toml  clippy.toml  .swift-format  cliff.toml
  docs/                      this file, rules.md, macos.md, integrations.md
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
      tests/guards.rs        source-level safety guards (§10)
      tests/canary.rs        guard 5: credentials never reach the report (§10)
    cainary-cli/             binary `cainary`
      src/main.rs  src/args.rs  src/text.rs  src/status.rs
      tests/cli.rs           runs the binary on fixtures; text/status/sources goldens in tests/golden/
  macos/                     SwiftUI menu bar app (macos.md)
    Info.plist  Sources/*.swift  Tests/
  packaging/bundle.sh        assemble and sign dist/cAInary.app, zip it (POSIX sh)
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
| `libc` | `O_NOFOLLOW`/`O_NONBLOCK`/`O_CLOEXEC` for the guarded open and `fcntl(F_GETPATH)` on macOS (§6.3) | `default-features = false`; used only in `harness/fs.rs`. The flag values differ between macOS and Linux targets, so they aren't hand-written |

Nothing else: no `clap` (a small hand-written parser), no `chrono`/`time` (one RFC 3339
formatter), no `regex` (substring and token checks), no `dirs`, and no async. `tests/guards.rs`
parses `Cargo.lock` and fails if a package outside an allowlist appears, so adding a crate is a
visible, reviewed change. That guard is a regression check, not a proof. What keeps the product
read-only and offline is that the only call sites that open files or start a process are
`harness/fs.rs` and the one `Command::new` in `harness/platform.rs`, and fixture-mode tests show
both are bypassed (§10).

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
}
```

Scanners build findings with `FindingBuilder::new(title).signals(..).detail(..).source(..)
.evidence(..).reference(url).best_effort(b).in_effect(b).agent(name)`. `ScanCtx::emit` fills in
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
        "docs": "https://code.claude.com/docs/en/hooks"}
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
cainary --version | --help

COMMON: [--alert org|org-unknown|everything]   (aliases relaxed|balanced|paranoid; default org-unknown)
        [--tool <slug>]...                      (repeatable; default all)
        [--fixture <dir> | --root <dir> --home <dir> [--os macos|linux]]
        [--env-kind shell|launchd]              (default shell; the app passes launchd)
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

### 8.2 `status` and `sources`

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

### 9.2 Linux UI (planned)

It needs nothing from the core beyond the CLI: a tray app (toolkit not chosen) that runs
`cainary scan --json` and draws `status`, `apps`, `others` and their findings, and can keep a
baseline for `--since` the same way the macOS app does.

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
     `cainary-core/src/harness/` (the CLI `main.rs` may read args, `NO_COLOR` and stdin).
  2. `OpenOptions` only in `harness/fs.rs`, and no write, create, append, truncate or remove calls
     anywhere outside tests.
  3. `Command::new` exactly once, in `harness/platform.rs`, with the literal `/usr/sbin/scutil`;
     `libc::` only in `harness/fs.rs`.
  4. `Cargo.lock` packages ⊆ the allowlist.

  Guard 5, the canary (`tests/canary.rs`): a temp fixture plants a marker in credential files
  from the deny-list and symlinks tool configs (`~/.claude/settings.json`, `~/.codex/config.toml`,
  …) to them. A scan of every tool must never show the marker, each symlinked config must be
  `refused`, and the report must be incomplete.

  Plus, in `harness/ctx.rs`: a fixture without `scutilProxy` gives an `absent` proxy source and
  `scutil` is never called.
- **CLI tests** (`cainary-cli/tests/cli.rs`) run the built binary against fixtures and compare
  text, `--summary`, `--since`, status (all formats) and sources output with
  `cainary-cli/tests/golden/`, and check exit codes.
- **App tests:** `make ui-test` decodes every Rust golden through the Swift model, runs the app's
  unit checks against stub helpers and the real binary, and renders snapshots (macos.md §5).
- **Smoke:** `make scan` runs the real scan on the dev machine. It is not golden-checked.

## 11. Build, CI and release

- **Toolchain:** `mise.toml` pins rust (with both Apple targets, rustfmt and clippy), swift,
  shellcheck, jactionlint and mr-boxington for local work, and its tasks wrap the Makefile.
  Under mise, cargo runs through `mbx` (a shared build cache) and `SWIFTC` points at mise's
  swiftc. When `CARGO_HOME` isn't writable (a sandbox), the Makefile moves it to
  `$TMPDIR/cargo-home`.
- **Version:** `[workspace.package] version` in `Cargo.toml` is the single source.
  `bundle.sh` stamps it into the app's `Info.plist` and refuses a helper that reports a
  different version.
- **Makefile targets:** `build`, `test`, `fmt`, `lint` (`cargo fmt --check`, clippy
  `-D warnings`, `swift format lint --strict`, shellcheck), `check-rust`, `check` (lint + test +
  ui-test), `core-universal` (release builds for both Apple targets, `lipo` →
  `target/universal/cainary`), `app`, `bundle` (`RELEASE=1` for the universal release app),
  `ui-test`, `scan`, `publish-check` (`cargo publish --workspace --dry-run`), `clean`. The app and bundle steps are in macos.md §4. `linux` is reserved for
  a static Linux tarball and isn't implemented yet.
- **Install:** copy `cAInary.app` to `/Applications`. For the CLI, optionally
  `ln -s /Applications/cAInary.app/Contents/Helpers/cainary ~/.local/bin/cainary`, or
  `cargo install cainary --locked`. The other methods are in [distribution.md](distribution.md).
- **CI** (`.github/workflows/ci.yml`): Conventional Commit messages, action pins, `make check` on
  macOS (uploading the UI snapshots), and `make check-rust` plus `make publish-check` on Linux. CI doesn't use mise: it runs
  plain `make` with rustup's cargo (version read from `mise.toml`) and Xcode's swiftc.
- **Release** (`.github/workflows/release.yml`): an action-pin gate and `make check`, then
  git-cliff bumps the version (`scripts/set-version.sh` updates `Cargo.toml`, `Cargo.lock` and
  `CHANGELOG.md`), tags, and builds and publishes the universal macOS bundle, then publishes the crates `cainary-core`
  and `cainary` (the CLI package; its directory is `crates/cainary-cli`) to crates.io. Developer ID signing
  and notarization are optional steps there; local bundles are signed ad hoc.
