# cAInary — detection rules

What each scanner reads and what it reports, with the official doc behind each rule. The report
model the findings feed into is in architecture.md §3.

Conventions:

- **Apps vs surfaces.** A scanner and its rules are per surface (`Tool`: claude-code,
  claude-desktop, codex, chatgpt, …). The report groups surfaces into apps (`Tool::app()`): Claude
  Code + Claude Desktop → "Claude", Codex + ChatGPT → "ChatGPT & Codex". Finding ids and entry
  levels are per app; each finding keeps its `tool` (`surface` on the wire).
- **Paths.** `R/` = the system root (`/` in production, `<fixture>/root` in tests). `~/` = home.
  `MDM(domain)` = the two plists `R/Library/Managed Preferences/<user>/<domain>.plist` (read
  first, wins per key) and `R/Library/Managed Preferences/<domain>.plist`. MDM is macOS only; on
  Linux it yields nothing.
- **Linux column.** ✅ = stated in a vendor doc; 🔎 = believed correct but must be checked
  against the vendor doc (until then the scanner marks findings from that path `bestEffort`);
  — = the tool or mechanism doesn't exist on Linux.
- **Signals → exposure** as in architecture.md §3.1. "policy" = `[policy]` (level ok).
  "info" = no signals (finding shown, level ok). `BE` = `bestEffort: true`.
- **Truthy** = case-insensitive `1`, `true`, `yes`, `on`. **Set** = present and non-empty.
- **Host** = the URL host only, never path, query or userinfo (redact.rs `url_host`).
- Every finding carries `reference` = the doc URL in the rule's "Ref" cell.
- Origin of a file source comes from its row. A user-tier file in `~` owned by uid 0 is
  `org-installed`. Hook origin is per hook (H.3).

---

## H. Shared: hooks, commands, MCP (`rules/hooks.rs`, `rules/mcp.rs`)

Used by Claude Code, Codex, Cursor and Copilot. Nothing here runs a command: it is string work
plus `which`, `stat` and `canonical`.

### H.1 Command target

`hooks::target(cmd: &Cmd, path: Option<&str>, ctx) -> Target`. `Cmd::Shell(String)` is a
command string that a shell runs. `Cmd::Argv(Vec<String>)` is an argv array (Codex `notify` and
hook arrays, Copilot `exec` + `args`). Argv words are never re-joined or re-split.

```rust
pub enum Target {
    File(Loc),                       // an absolute or ~/ path, or a bare name that `which` found
    Unresolved(String),              // a relative path, or a bare name with Which::NotFound/Unknown
    Inline { interpreter: String },  // sh -c '…', node -e '…': no binary to attribute
}
```

1. `Shell`: split on whitespace honoring simple `'…'` / `"…"` quotes, and take the first `;`,
   `&&`, `||`, `|` segment. `Argv`: the words as given.
2. Drop leading `VAR=value` words (keep a `PATH=` value for H.2) and the wrappers `env` (with
   its `-x` options and its own `VAR=` words), `exec`, `nohup`, `command`.
3. If the first word is an interpreter (`sh bash zsh dash ksh fish node python python3 ruby perl
   deno bun osascript npx uvx bunx pnpm`) and the next non-option word isn't `-c`/`-e`, the
   target is that script path. An inline `-c`/`-e` payload gives `Inline`.
4. Else the first word: with a `/` it is a path (relative → `Unresolved`); a bare name goes
   through `ctx.h().which(name, layered PATH)` (H.2).

### H.2 PATH layering

A hook doesn't necessarily run with the scanner's PATH. `hooks::layered_path(cmd_path,
tool_path, h) -> Option<String>` picks the first that applies:

1. the command's own `PATH=` word (H.1 step 2);
2. the PATH the tool gives the process: Claude Code's effective `env.PATH` (`CcConfig.env`,
   CC.2), or for a local MCP server its own `env.PATH`. Codex, Cursor and Copilot hooks have no
   such layer;
3. the scan's `PATH`, except under `envKind: launchd`, where it is launchd's PATH → `None`.

`None`, or a layer holding `$`, `~` or a relative entry, makes `which` answer `Unknown`
(architecture.md §6.5). `NotFound` and `Unknown` both give `Target::Unresolved`: the evidence
says "couldn't tell which `<name>` runs", the origin stays the file's (H.3), and the signals
stay.

### H.3 Hook origin

`hooks::origin(file_origin, target, ctx)`: a hook in a user-tier file is `org-installed` when its
target is `Target::File`, the canonical path is **root-owned** (`ctx.root_owned`), and it sits
under a **vendor root**: `R/Library/Application Support/<V>/`, `R/opt/<V>/`, or
`R/usr/local/<V>/` where `<V>` isn't `bin sbin lib libexec share include etc var Cellar
Caskroom Homebrew opt`. Otherwise it keeps the file's origin. Paths in `$HOME`, `/usr/bin`,
`/bin`, `/System`, `/opt/homebrew`, `/nix` and so on are never org. `Unresolved` and `Inline`
keep the file's origin. That's the whole rule: no code signatures and no launch-job markers.

### H.4 Local notifier (narrow)

`hooks::is_local_notifier(cmd, path, ctx) -> bool` is checked **before** H.1, because
`osascript` is also an interpreter. All of these must hold:

1. **Plain.** A `Shell` command contains none of `$(`, a backtick, `;`, `&`, `|`, `<`, `>` or a
   newline, has no leading `VAR=` word, and doesn't start with `env`, `exec`, `nohup` or
   `command`. An `Argv` has no shell, but its first word still must not be one of those
   wrappers.
2. **Trusted binary.** The first word is an absolute path, or a bare name whose H.2 lookup is
   `Found`. Its `ctx.canonical` path is one of these. macOS: `R/usr/bin/{afplay,say,osascript,tput}`.
   Linux: `R/usr/bin/` or `R/bin/` plus `{notify-send,paplay,aplay,tput}`. It is also
   `ctx.root_owned`. Homebrew's `terminal-notifier` is never trusted.
3. **Recognised arguments.**

   | Binary | Allowed arguments |
   | --- | --- |
   | `afplay`, `paplay`, `aplay` | options and file paths |
   | `say` | anything except `-o`, `--output-file`, `-n`, `--network-send` (and their `=` forms) |
   | `osascript` | exactly one `-e <script>`, where the script starts with `display notification` or `beep` and contains none of `do shell script`, `run script`, `load script`, `tell` |
   | `tput` | exactly `bel` |
   | `notify-send` | anything |

If all hold, the finding has **no signals** (info): "plays a sound or shows a notification". If
any fails, the normal hook rules apply, so a look-alike `say` early on PATH, or one that a
`PATH=` prefix redirects, keeps its exposure.

### H.5 Network hint

`hooks::sends_to(cmd) -> Option<host>`: the command contains `curl`, `wget`, `nc `, `ncat`,
`http`/`https` URLs, `Invoke-WebRequest`. Then the title says "…and sends it to `<host>`" (the
host from the first URL, else "the network"). This only changes the wording. It never removes
signals.

### H.6 Grouping

One finding per (tool, source path, target, in_effect, known-local-tool classification). The
evidence lists the events and the redacted command (max 3 commands).

### H.7 MCP server entry

`mcp::server(name, value, origin, ctx) -> FindingBuilder` (the caller adds `.source(…)`):
- A `url`/`http_url`/`serverUrl` gives a remote server: `[tool-details]` "receives your tool
  requests at `<host>`". BE unless the tool documents that the org server is always used.
  Header names are evidence, values are `••••`.
- A `command` gives a local server, with its target resolved by H.1 (H.2 layer 2 = the server's
  `env.PATH`). From an org origin, `[tool-details]` BE ("runs `<basename>` with your tool
  requests"). From a user origin, info, unless H.3 makes it org-installed.
- `env` keys are evidence, values are redacted by key name.

### H.8 Known local tool

`hooks::is_known_local_tool_hook(cmd, tool_path, ctx) -> bool` recognizes only a plain `rtk hook …`
command for now; `rtk` is held in a const tool-name table for future additions. The second word
must be `hook`. An absolute path or a bare name found through H.2's layered `PATH` (the tool's
configured path when present, otherwise the scan's `PATH`) must resolve to a canonical path whose
basename is `rtk`. There is no install-directory allowlist, so an absolute path such as
`/tmp/anything/rtk` can match if it resolves to the user's file. If a bare `rtk` is unresolved, it
still matches on a best-effort (`may`) basis; this covers launchd, which has no scan `PATH`. Its
detail says cAInary couldn't tell which `rtk` runs. Absolute paths that fail to canonicalize or
whose canonical basename is not `rtk`, relative paths containing `/`, and unresolved bare names
other than `rtk` do not match.
Leading environment assignments and the `env`, `exec`, `nohup` and `command` wrappers do not
match. A shell command containing `$(`, a backtick, `;`, `&`, `|`, `<`, `>`, or a newline also
does not match. `Argv` commands are shell-free. Other rtk commands, look-alike names, and
compound commands use their normal hook exposure.

The title follows `<Tool> hook … runs on <events>`; for example, “Codex hook `rtk` runs on Stop”.
Its telemetry state controls the signals:

- **On → medium:** `~/Library/Application Support/rtk/config.toml` on macOS;
  `$XDG_CONFIG_HOME/rtk/config.toml` on Linux, falling back to `~/.config/rtk/config.toml`.
  `[telemetry].consent_given = true` opts in; `enabled = false` disables it. A missing `enabled`
  with consent counts as on, unless `RTK_TELEMETRY_DISABLED=1` is in the scan environment. The
  finding uses the existing traffic signal and cites the config path in its evidence: rtk sends
  a daily anonymous usage ping to `telemetry.rtk-ai.app`.
- **Off or unknown → low:** a missing file or telemetry table, absent consent, `enabled = false`,
  or the environment override uses the existing usage signal. Invalid or unreadable TOML is
  treated as off and the detail says the config couldn't be read.

The hook's source, origin, gates, in-effect state and provenance still come from its hook
configuration. cAInary reads only this config file for H.8; it does not read rtk history,
tracking, recall databases, or the device salt.

---

## CC. Claude Code (`claude_code.rs` → `CcConfig`; `claude_code_policy.rs`, `claude_code_telemetry.rs`, `claude_code_hooks.rs`)

Ref base: `https://code.claude.com/docs/en/` — `managed-settings`, `server-managed-settings`,
`settings-reference`, `settings`, `env-vars`, `monitoring-usage`, `hooks`, `managed-mcp`,
`data-usage`.

`<cfg>` = the `ClaudeConfig` tool home (`$CLAUDE_CONFIG_DIR` if absolute or `~/…` without
`..`, else `~/.claude`).

### CC.1 Sources (highest tier first)

| Tier | macOS | Linux | Format | Origin |
| --- | --- | --- | --- | --- |
| server | `<cfg>/remote-settings.json` (the local cache) | same ✅ | json | server |
| mdm | `MDM(com.anthropic.claudecode)` | — | plist | mdm |
| file | `R/Library/Application Support/ClaudeCode/managed-settings.json`, then `managed-settings.d/*.json` | `R/etc/claude-code/…` ✅ | json | system |
| mcp lock | `R/Library/Application Support/ClaudeCode/managed-mcp.json` | `R/etc/claude-code/managed-mcp.json` ✅ | json | system |
| user | `<cfg>/settings.json` | same ✅ | json | user |
| policy cache | `<cfg>/policy-limits.json` (internals UNVERIFIED → BE) | same | json | server |
| env | process env | same | — | environment |

The file tier is one document. `managed-settings.json` comes first, then every
`managed-settings.d/*.json` in alphabetical order (hidden files and non-`.json` names are
skipped), folded with `merge_dropin` (CC.2). The `.d` listing is recorded, so more than 256
drop-ins make the scan incomplete.

Installed marker (probe): `<cfg>` is a dir, or `which("claude")` is `Found`, or any source is
present.

Not read: project `.claude/settings*.json` and `.mcp.json` (there is no cwd scan),
`<cfg>/.claude.json`, `<cfg>/.credentials*`, `<cfg>/projects/`, plugin caches. The access policy
refuses these anyway.

### CC.2 Resolution (`claude_code.rs`)

There is no generic merge engine. Each step is a small named function with its own unit test, and
each one knows the handful of keys it handles.

1. **`merge_dropin(a, b)`**: a scalar → `b`; a list → `a` ∪ `b` (deduplicated by JSON equality,
   order kept); an object → merged key by key with the same rules. At the top level these are
   the exceptions: `fallbackModel` and `modelPicker` → `b` whole; `extraKnownMarketplaces` and
   `managedMcpServers` → merged by name, with `b`'s entry replacing the whole entry.
2. **`is_policy_doc(v)`**: holds a key other than the control keys `managedSourcesBehavior`
   and `wslInheritsWindowsSettings` (and `$schema`) with a non-null value. A control-only
   document is not a policy tier. A server cache equal to `{}` gives an info finding, "your
   organization has no server-managed settings".
3. **`policy_tier(tiers)`** = the highest of server, mdm, file with `is_policy_doc`.
4. **`behavior(tiers)`** = `managedSourcesBehavior` read from the highest admin tier that holds
   either that key or a policy key. That can be a control-only server or MDM document. `"merge"` →
   `Merge`; absent or `"first-wins"` → `FirstWins`; any other value → `FirstWins` plus an info
   finding.
5. **`in_effect(key, tier, cfg) -> bool`**, for a top-level key in an admin tier:
   - Every tier: the **cross-source keys** `env`; `sandbox.network.allowManagedDomainsOnly` and
     `sandbox.filesystem.allowManagedReadPathsOnly` (while one is on, its allowlist unions
     across tiers); `allowAllClaudeAiMcps`; `allowManagedMcpServersOnly` (while on,
     `allowedMcpServers` comes from the highest tier that sets it); `deniedMcpServers`,
     `disableClaudeAiConnectors`; `sandbox.bwrapPath`, `sandbox.socatPath`, `sandbox.ripgrep`,
     `sandbox.filesystem.disabled`, `sandbox.network.strictAllowlist`; `useAutoModeDuringPlan`,
     `syncClaudeAiSkills`, `syncClaudeAiPlugins`, `enableArtifact` (a `false` wins);
     `maxEffortLevel` (the lowest wins); an `attribution` / `includeCoAuthoredBy` opt-out;
     `forceRemoteSettingsRefresh`. `allowManagedHooksOnly` and `disableAllHooks` are **not**
     cross-source.
   - **Gateway login keys** (`forceLoginGatewayUrl`, `gatewayInternalNetworks`,
     `forceLoginMethod: "gateway"`) are never read from the server tier. They come from the
     highest non-server tier with a policy key.
   - `FirstWins`: any other key is in effect only from `policy_tier`.
   - `Merge`: the **top-only keys** (`apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`,
     `gcpAuthRefresh`, `otelHeadersHelper`, `proxyAuthHelper`, `forceLoginOrgUUID`,
     `forceLoginMethod` `claudeai`/`console`, `parentSettingsBehavior`, `modelPicker`,
     `policyHelper`, `permissions.defaultMode`) come only from `policy_tier`. Lists (`hooks`,
     `permissions.allow`, …) and `managedMcpServers` names come from every policy tier. A
     lock is on if any tier turns it on. Any other key comes from its highest setter.
   - A key that is not in effect gives one info finding per tier, "Settings in `<tier>` are
     ignored", listing those keys (max 20).
6. **`managed_env(tiers)`**: each variable comes from the highest admin tier that defines it,
   except the **telemetry unit**. The unit is `OTEL_EXPORTER_OTLP_*`, `OTEL_LOG_*`,
   `OTEL_LOGS_EXPORTER`, `ENABLE_BETA_TRACING_DETAILED` and `BETA_TRACING_ENDPOINT`. The
   *unit tier* is the highest admin tier whose `env` sets any unit member or that sets
   `otelHeadersHelper`. Every unit member comes from the unit tier alone, and members set in
   other admin tiers become info, not in effect: "replaced by `<tier>`'s telemetry settings".
   If `otelHeadersHelper` chose the unit tier and that tier isn't `policy_tier`, the tier
   supplies no members and still blocks the lower ones. `OTEL_METRICS_EXPORTER`,
   `OTEL_TRACES_EXPORTER`, `CLAUDE_CODE_ENABLE_TELEMETRY` and
   `CLAUDE_CODE_ENHANCED_TELEMETRY_BETA` are outside the unit and merge per variable.
7. **`effective_env(managed, user_env, process_env)`**: per variable, managed > user
   `settings.json` `env` > process env. A local value (user or process) of a unit member is
   then dropped as follows:
   - a managed `OTEL_EXPORTER_OTLP_ENDPOINT` drops the local per-signal `…_{LOGS,METRICS,TRACES}_ENDPOINT`;
   - a managed `OTEL_EXPORTER_OTLP_PROTOCOL` drops the local per-signal protocols;
   - a managed `OTEL_EXPORTER_OTLP_HEADERS`, `…_CLIENT_KEY` or `…_CLIENT_CERTIFICATE` drops the
     local per-signal copies of those and every local endpoint;
   - a managed logs or traces destination drops the local `BETA_TRACING_ENDPOINT`;
   - local `OTEL_LOG_*` content flags the managed unit leaves unset stay in effect, BE.

   Dropped variables become info, not in effect. The Swift version dropped all local routing
   once an admin unit existed. That was wrong, and it isn't kept.
8. **Server tier is a guess** (`server_be`): if any `CLAUDE_CODE_USE_{BEDROCK,VERTEX,FOUNDRY}` is
   truthy, or `ANTHROPIC_BASE_URL`'s host isn't `api.anthropic.com`, Claude Code doesn't fetch
   server settings, so server-tier findings get BE ("Claude Code skips server-managed settings
   with this setup"). With `envKind = launchd`, server-tier findings are always BE, and the CC.7
   note is added.
9. **`policy_helper(cfg)`** (CC.5).

```rust
// Plain data, no methods: concern tests build it by hand.
pub enum CcTierId { Server, Mdm, File }
pub enum Behavior { FirstWins, Merge }
pub struct CcTier { pub id: CcTierId, pub loc: Loc, pub origin: Origin, pub value: Map<String, Value>, pub policy: bool }
pub struct CcSetting { pub key: String, pub value: Value, pub tier: CcTierId, pub in_effect: bool } // step 5
pub enum CcFrom { Tier(CcTierId), User, Process }
pub struct CcEnvVar { pub name: String, pub value: String, pub from: CcFrom, pub in_effect: bool, pub why: Option<String> }

pub struct CcConfig {
    pub tiers: Vec<CcTier>,                 // present admin tiers, highest first (file = merged drop-ins)
    pub policy_tier: Option<CcTierId>,
    pub behavior: Behavior,
    pub helper: Option<(Loc, CcTierId)>,    // a selected policyHelper (CC.5)
    pub server_be: bool,
    pub managed: Vec<CcSetting>,            // every top-level key of every admin tier
    pub user: Option<(Loc, Map<String, Value>)>,   // <cfg>/settings.json
    pub mcp_lock: Option<(Loc, Map<String, Value>)>, // managed-mcp.json
    pub limits: Option<(Loc, Map<String, Value>)>,   // policy-limits.json
    pub env: Vec<CcEnvVar>,                 // steps 6–7: every candidate, in effect or dropped, sorted by name
}
```

### CC.3 Telemetry (`claude_code_telemetry.rs`, from `CcConfig.env`)

Exporter variables take comma lists. `none` and `console` don't count, and `prometheus` is
pull-only (info).

- `enabled` = `CLAUDE_CODE_ENABLE_TELEMETRY` truthy.
- `metrics` = enabled + a counting `OTEL_METRICS_EXPORTER`.
- `logs` = enabled + a counting `OTEL_LOGS_EXPORTER`.
- `traces` = enabled + `CLAUDE_CODE_ENHANCED_TELEMETRY_BETA` (or its alias
  `ENABLE_ENHANCED_TELEMETRY_BETA`) truthy + a counting `OTEL_TRACES_EXPORTER`. Without the beta
  switch, a traces exporter sends nothing.
- `beta` = enabled + `ENABLE_BETA_TRACING_DETAILED` truthy + `BETA_TRACING_ENDPOINT` set. It is
  allowlist-gated by Anthropic, so findings from it are BE.

The endpoint per signal is `OTEL_EXPORTER_OTLP_<SIGNAL>_ENDPOINT`, else
`OTEL_EXPORTER_OTLP_ENDPOINT`, else "a local collector". For `beta` it is `BETA_TRACING_ENDPOINT`.
The value of `OTEL_EXPORTER_OTLP_HEADERS` is never shown, only its names.

| Condition | Signals |
| --- | --- |
| `metrics`, `logs`, `traces` or `beta` | usage: "sends usage data to `<hosts>`" |
| … and (`logs`, `traces` or `beta`), or `OTEL_RESOURCE_ATTRIBUTES` set, or `metrics` with `OTEL_METRICS_INCLUDE_ACCOUNT_UUID` not `false` | + identity |

Content flags (truthy unless noted) and where each one lands:

| Flag | with `logs` | with `traces` | with `beta` |
| --- | --- | --- | --- |
| `OTEL_LOG_USER_PROMPTS` | prompts; + responses unless `OTEL_LOG_ASSISTANT_RESPONSES` is set (`1` on, `0` off) | prompts | prompts, responses, file-contents |
| `OTEL_LOG_ASSISTANT_RESPONSES` | responses | — | — |
| `OTEL_LOG_TOOL_DETAILS` | tool-details | tool-details | tool-details |
| `OTEL_LOG_TOOL_CONTENT` | — | file-contents | file-contents |
| `OTEL_LOG_RAW_API_BODIES` = `1`/`true` | prompts, responses, tool-details, file-contents | — | — |

- `OTEL_LOG_RAW_API_BODIES` = `file:<dir>` → info, BE: "writes raw API bodies to `<dir>` on this
  machine" (local disk). Any other value → info, BE: "unrecognised value".
- A content flag with none of its destinations on → info, not in effect: "would log … if
  `<logs/traces>` export were on".
- Telemetry variables present but not enabled → info.

One finding per destination (logs, traces, beta) and contributing source. The evidence lists the
contributing variables, redacted. Ref `monitoring-usage`.

### CC.4 Gateways, providers, proxies (effective env + in-effect settings)

| Condition | Signals | Notes |
| --- | --- | --- |
| `ANTHROPIC_BASE_URL` host ≠ `api.anthropic.com` | traffic | "model traffic goes through `<host>`" |
| `CLAUDE_CODE_USE_BEDROCK` / `_VERTEX` / `_FOUNDRY` truthy | traffic | "runs through `<provider>`". Provider `*_BASE_URL` vars are evidence |
| gateway login keys in effect (CC.2 step 5) | traffic, policy | |
| `apiKeyHelper` in effect | policy if admin origin, else info | the helper's H.1 target is evidence; never run |
| `HTTPS_PROXY`/`HTTP_PROXY` (either case) + `NODE_EXTRA_CA_CERTS` | traffic | "a proxy that can decrypt traffic" |
| proxy without an extra CA | info | the proxy sees hosts only |
| `NODE_EXTRA_CA_CERTS` alone | traffic, BE | path only; the file is never opened |

Ref `settings-reference`, `env-vars`, `network-config`.

### CC.5 Policy keys and `policyHelper` (`claude_code_policy.rs`)

One `[policy]` finding per tier and group, for the keys in effect from that tier. The evidence is
the keys with redacted values (max 20 lines). Lock-style keys (`allowManaged*`, `disable*`,
`strict*`, `force*`) that are `false` are skipped.

| Group | Keys |
| --- | --- |
| login | `forceLoginMethod`, `forceLoginOrgUUID`, `allowedProviders` |
| permissions | `permissions`, `allowManagedPermissionRulesOnly`, `sandbox` (except `sandbox.network.tlsTerminate`, which → traffic) |
| mcp & plugins | `allowedMcpServers`, `deniedMcpServers`, `allowManagedMcpServersOnly`, `managedMcpServers`, `enabledPlugins`, `strictKnownMarketplaces`, `blockedMarketplaces`, `extraKnownMarketplaces`, `disableClaudeAiConnectors` |
| hooks | `allowManagedHooksOnly`, `disableAllHooks`, `allowedHttpHookUrls` |
| models & updates | `availableModels`, `model`, `requiredMinimumVersion`, `autoUpdatesChannel` |
| instructions | `claudeMd`, `companyAnnouncements` (character count only) |
| other | any other key (names only) |

- `enabledPlugins` in effect from an admin tier → also `[tool-details]` BE: "plugins your
  organization enabled may run hooks or MCP servers". Plugin caches are not read.
- `managed-mcp.json` `mcpServers` → policy "your organization fixes which MCP servers Claude
  Code uses", plus one H.7 finding per remote server.
- `policy-limits.json`: `monitoring_notice` set → usage BE "your organization may monitor
  Claude Code use"; `restrictions.*.allowed == false` → policy BE.
- User `settings.json` `permissions`/`sandbox.enabled` → info "you restricted Claude Code
  yourself".

**`policyHelper`** (`policy_helper(cfg) -> Option<(Loc, CcTierId)>`): it is *selected* when
`policy_tier` is mdm or file and that tier sets `policyHelper` as an object with a string `path`
(`timeoutMs` and `refreshIntervalMs` are evidence). A server `policy_tier` suppresses a lower
helper, even under `Merge`; that case is info, not in effect. A non-object value is dropped
(info "invalid `policyHelper` ignored"). A selected helper can replace **all** managed settings,
including the cross-source keys and env. cAInary never runs it, so:

- `ctx.not_run(helper path, origin, "policyHelper output decides the managed settings")`
  records a `refused` source. The scan is incomplete, so it can't read as clear.
- One policy finding: "your organization computes Claude Code policy at runtime with
  `<basename>`; cAInary doesn't run it, so the managed settings below may not be what applies".
- Every finding that comes from an admin tier (policy, managed env telemetry, gateways, locks,
  admin hooks, hook blocking) gets BE and the evidence line "may be replaced by policyHelper".
  User and process findings keep their certainty.

### CC.6 Hooks (`claude_code_hooks.rs`)

Sources: `hooks` from each admin tier where `in_effect("hooks", tier)` holds (`FirstWins`:
`policy_tier` only; `Merge`: every policy tier), and from user `settings.json`. The shape is
`hooks.<Event>[] { matcher?, hooks[] { type = command|http|mcp_tool|prompt|agent, command?, url? } }`,
where a missing `type` means `command`. A `command` hook with an `args` array is exec form:
`command` is the executable (it may contain spaces) and the argv is `[command, ...args]`, no shell
(`Cmd::Argv`); without `args`, `command` is a shell string (`Cmd::Shell`).

| Type | Signals |
| --- | --- |
| `command` | transcript (every hook input has `transcript_path`), + prompts on `UserPromptSubmit`/`UserPromptExpansion`, + tool-details on `PreToolUse`/`PostToolUse`/`PostToolUseFailure`/`PostToolBatch`/`PermissionRequest`/`PermissionDenied`, + responses on `Stop`/`SubagentStop` |
| `http` | traffic + the event signals above: "posts each event to `<host>`" |
| `mcp_tool` | the event signals, BE |
| `prompt`, `agent` | policy if admin, else info ("evaluated by Claude, nothing leaves") |

- Blocked (info, not in effect): every hook when an in-effect admin `disableAllHooks` is native
  `true`; user hooks when an in-effect admin `allowManagedHooksOnly` is `true`/`"true"` (any
  other non-false value also means on, failing closed); user hooks when user `disableAllHooks`
  is `true`. Under `Merge` these are locks, so any policy tier can turn them on.
- H applies for the target (H.2 layer 2 = `CcConfig.env` `PATH`), origin, the local-notifier
  rule and grouping.
- H.8 recognizes a plain `rtk hook …` command and reports LOW when rtk telemetry is off or
  unknown, and MEDIUM when consent enables its daily usage ping.

### CC.7 Vendor default and notes

- Installed and none of `DISABLE_TELEMETRY` (any value), `DO_NOT_TRACK` truthy,
  `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` (any value) or a provider switch is set → `[vendor]`
  origin vendor-default: "Anthropic receives usage metrics by default". An opt-out gives info.
  Ref `data-usage#telemetry-services`.
- Notes: "Server-managed settings are visible only through the local cache." With launchd: "Your
  shell's variables aren't visible here… run `cainary scan` in a terminal."

---

## CD. Claude Desktop (`scanners/claude_desktop.rs`) — macOS only

Ref: `https://claude.com/docs/third-party/claude-desktop/configuration`, `…/mdm`, `…/telemetry`,
`https://support.claude.com/en/articles/12622667`.

| Source | Path | Origin |
| --- | --- | --- |
| MDM | `MDM(com.anthropic.claudefordesktop)` (per-user wins per key; a shadowed device key → info, not in effect). Values may be native or JSON strings: decode strings starting with `[`/`{` | mdm |
| user config | `~/Library/Application Support/Claude/claude_desktop_config.json` | user |
| marker | `R/Applications/Claude.app`, `~/Applications/Claude.app` (stat) | — |

Mode: 3P when `inferenceProvider` is set, else 1P.

| Keys (MDM) | Signals |
| --- | --- |
| `otlpEndpoint` set | usage + identity: "sends usage telemetry to `<host>`". Identity always: the exported resource carries `process.owner` (your OS login). `endUserAttribution = false` removes only `enduser.id`, and `otlpResourceAttributes` can add more, so neither clears identity |
| `otlpContentCapture` (array or JSON-array string): `userPrompts` → prompts, responses (Desktop 1.17377+ also sends replies and conversation titles); `assistantResponses` → responses; `toolDetails` → tool-details (tool input); `toolContent` → file-contents (tool output); `rawApiBodies` → prompts, responses, tool-details, file-contents | as listed when `otlpEndpoint` is set; BE on 1P without it (row below); info if the array is empty |
| 1P, OTLP keys but no `otlpEndpoint` | identity BE, "collector may be set in the admin console" |
| `otlpAuthMode = inference-credential` | + identity: "the collector receives your sign-in token" |
| `inferenceGatewayBaseUrl` | traffic: "model requests go through `<host>`" |
| else `inferenceProvider` | traffic: "model requests go to `<provider>` instead of Anthropic" |
| `egressProxyPacUrl` / `egressProxyUrl` | traffic (host; PAC query stripped) |
| `managedMcpServers` | tool-details: "your organization added N MCP servers" + §H per remote server |
| `organizationInstructions` | policy (character count only) |
| `forceLoginOrgUUID`; feature locks (`isClaudeCodeForDesktopEnabled=false`, `chatTabEnabled=false`, `disableBypassPermissionsMode=true`, `blockReadsOutsideWorkingDirectories=true`, `allowedWorkspaceFolders`, `disableAutoUpdates=true`, `isDesktopExtensionEnabled=false`, `isLocalDevMcpEnabled=false`, `disabledBuiltinTools`, `disableEssentialTelemetry`, `disableNonessentialTelemetry`) | policy, one finding per group (sign-in, features, extensions, Anthropic telemetry off) |
| any other key | info, names only |

- `claude_desktop_config.json` `mcpServers` → §H per server (a user origin, so local servers are
  info, unless the hook-origin rule makes the command org-installed).
- Vendor default (installed, and `disableEssentialTelemetry`/`disableNonessentialTelemetry`
  not both true): vendor "sends crash reports and product analytics to Anthropic", BE on 1P
  (documented only for 3P).

---

## CX. Codex (`codex.rs` → `CxConfig`; `codex_telemetry.rs`)

Ref: `https://learn.chatgpt.com/docs/` — `enterprise/managed-configuration`,
`config-file/config-reference`, `config-file/config-advanced`, `hooks`.

`<home>` = the `CodexHome` tool home (`$CODEX_HOME` if absolute or `~/…` without `..`, else
`~/.codex`).

### CX.1 Sources and layers

| Layer | macOS | Linux | Format | Origin | Kind |
| --- | --- | --- | --- | --- | --- |
| mdm req | `MDM(com.openai.codex)` key `requirements_toml_base64` | — | base64 TOML | mdm | requirements |
| mdm cfg | same, key `config_toml_base64` | — | base64 TOML | mdm | config |
| cloud | `<home>/cloud-config-bundle-cache.json` (`signed_payload.bundle.{requirements_toml,config_toml}.enterprise_managed[].contents` = TOML text, merged in order; shape from vendor source → BE) | same | json+toml | server | both |
| legacy req | `R/etc/codex/managed_config.toml` keys `approval_policy`, `approvals_reviewer`, `sandbox_mode`, read as constraints | same ✅ | toml | system | requirements |
| sys req | `R/etc/codex/requirements.toml` | same ✅ | toml | system | requirements |
| managed cfg | `R/etc/codex/managed_config.toml` | same ✅ | toml | system | config |
| user cfg | `<home>/config.toml` | same | toml | user | config |
| sys defaults | `R/etc/codex/config.toml` | same | toml | system | config (defaults only → info) |
| hooks | `<home>/hooks.json` | same | json | user | hooks |
| plugin cache | `<home>/plugins/cache/<marketplace>/<plugin>/<version>/` | same | json | user | plugin |

- The MDM `*_toml_base64` values (`Format::TomlBase64`) and the cloud cache's TOML texts are
  parsed through `ctx.parse_inner`, so an undecodable or unparsable one is an `error` source
  and the scan is incomplete.
- **Requirements**, highest first: mdm req > legacy req > cloud req > sys req.
  `compose_req(lower, higher)`: a scalar or list → the higher layer's; a table → merged by key.
  The `rules`, `hooks` and `filesystem` tables have field-specific composition in Codex; here
  their entries are unioned. Hooks findings are BE only when more than one requirements layer contributes hooks, or the layer is the cloud cache (CX.7). The legacy layer only pins the three
  keys it holds; it adds no allowlists.
- **Config**, highest first: mdm cfg > managed cfg > user cfg > cloud cfg > sys defaults. The
  highest setter of a key is in effect. Lower setters of the same key → info, not in effect.
- **Requirements vs config.** Requirements constrain and config chooses within them; there is
  no blanket "requirements override config". For the keys read here: a requirements
  `features.<f>` pins that feature; `allow_managed_hooks_only` and the MCP allowlists only
  remove things; `model_provider` in requirements pins the provider.

### CX.2 Cloud keys the client ignores

Codex ignores exactly these keys from cloud requirements: `allowed_login_methods`,
`allowed_chatgpt_workspaces`, `cli_auth_credentials_store`, `chatgpt_base_url`. They give info,
not in effect: "set in your organization's cloud policy, but Codex doesn't enforce it here".
(The Swift list also had `model_provider(s)`. The current vendor docs don't, so it is not
kept.)

### CX.3 Policy and routing

| Key (effective) | Signals |
| --- | --- |
| requirements: any key | policy, one finding per layer; evidence = keys (values redacted) grouped as approvals/sandbox, login (`allowed_login_methods`, `allowed_chatgpt_workspaces`), features, mcp, hooks (`allow_managed_hooks_only`), other |
| selected provider = requirements `model_provider`, else config `model_provider`, else `openai` | |
| `model_providers.<selected>.base_url` | traffic: "model traffic goes through `<host>`" (+ policy if from requirements). An unselected provider → info |
| `openai_base_url` (selected = openai) / config `chatgpt_base_url` | traffic |
| provider `http_headers` / `env_http_headers` | + identity (names only) |
| `notify` (effective only; a `Cmd::Argv`) | prompts, responses: "`<target>` receives your prompts and Codex's replies after every turn" (H.1 target, H.4 notifier) |
| `mcp_servers.*` merged by server name across config layers, higher layer winning on a name; enabled plugin `mcpServers` files | H.7 MCP (remote `url` → tool-details BE; local servers use H.3 target origin). Each server finding cites the layer that set that server. |
| managed layer, any other key | policy "your organization sets Codex defaults" |
| `CODEX_CA_CERTIFICATE` / `SSL_CERT_FILE` (env) | traffic BE (path only) |

Plugin servers use the manifest's `mcpServers` path or `./.mcp.json` by default. The path must
start with `./`, contain no `..`, and resolve inside the plugin root. A server disabled in that
file or by `plugins.<p>.mcp_servers.<s>.enabled = false` is skipped.

### CX.4 OTel (`codex_telemetry.rs`)

```rust
pub enum Exporter { None, Statsig, OtlpHttp { endpoint: Option<String> }, OtlpGrpc { endpoint: Option<String> }, Unknown(String) }
pub fn exporter(v: &Value) -> Exporter;
```

`exporter` accepts the string `none`, `statsig`, `otlp-http` or `otlp-grpc`, or a table with
exactly one key, `otlp-http` or `otlp-grpc`. That key's table may hold `endpoint`, `protocol`,
`headers` and `tls.*`. Anything else is `Unknown(<shape>)`. `otel.exporter` (log events) and
`otel.trace_exporter` take `none|otlp-http|otlp-grpc`. `otel.metrics_exporter` also takes
`statsig`, and defaults to `Statsig`.

| Condition | Signals |
| --- | --- |
| `otel.exporter` OTLP | tool-details, usage, identity: "sends tool results and session data to `<host>`" |
| `otel.trace_exporter` OTLP | tool-details, usage, identity: "sends traces to `<host>`" |
| … and `otel.log_user_prompt = true` with `otel.exporter` OTLP | + prompts |
| `otel.log_user_prompt = true` with only a trace exporter | info: "prompts would be logged only through `otel.exporter`, which is off" |
| OTLP `headers` / `tls` client certificate | + identity (names only) |
| an `Unknown` exporter | info BE: "unrecognised exporter setting" |

A missing endpoint reads as "a collector". Hosts only.

### CX.5 Vendor metrics

| Condition | Result |
| --- | --- |
| `analytics.enabled = false` | info "usage metrics are off" (this turns off custom metrics too) |
| `metrics_exporter` = `None` | info "usage metrics are off" |
| `Statsig` (explicit or the default) | vendor: "OpenAI receives anonymous usage metrics by default" (origin vendor-default unless set explicitly) |
| OTLP | usage: "sends usage metrics to `<host>`". No OpenAI finding |
| `Unknown` | vendor BE (unlike Swift, an unknown kind doesn't hide the default) |

The vendor row needs Codex to be installed.

### CX.6 Profiles

`codex --profile <name>` overlays `<home>/<name>.config.toml`. cAInary can't know which profile
you start Codex with, so it doesn't resolve profiles and doesn't list `<home>`. When Codex is
installed, one note is added: "Findings about telemetry, analytics, model providers, `notify`
and hooks describe your base config; a `--profile` you use can change them." Findings from
requirements and managed layers stay firm. A top-level `profile` key or `[profiles.*]` tables
(retired by Codex) → info "Codex no longer reads this". A later `--codex-profile <name>` option
could read one profile file; it is out of scope now.

### CX.7 Hooks

From `hooks.json`, from `hooks` in any in-effect config layer, and from each
requirements layer's own `hooks` table. Requirements hooks are the managed hooks: each takes the origin of the layer that set it, and is never blocked by `allow_managed_hooks_only`. They are BE only when more than one requirements layer has hook events (composition uncertain) or the layer is the cloud cache (CX.1); a single plain `requirements.toml` is not BE. Non-array
keys in the table (`managed_dir`, `windows_managed_dir`) are ignored. The shape is
`hooks.<Event>[] { hooks[] { type, command } } | { command }`, where `command` is a string
(`Cmd::Shell`) or an argv array (`Cmd::Argv`). Signals: transcript always; + prompts on
`UserPromptSubmit`; + tool-details on `PreToolUse`/`PostToolUse`/`PermissionRequest`;
+ responses on `Stop`/`SubagentStop`. Blocked (info) when requirements
`allow_managed_hooks_only = true` and the hook is from a user layer, or when the effective
`features.hooks = false` and requirements don't pin it on, or when requirements pin `features.hooks = false` (both gates apply to managed hooks too). H applies for target, origin and the
notifier rule.

**Plugin hooks.** Each `[plugins."<name>@<marketplace>"]` table with `enabled = true` (merged across config layers; missing or false is disabled) can contribute hook sources from the highest installed version (dotted-number order; hidden dirs such as `.tmp` are skipped). The chosen version directory must canonicalize inside `plugins/cache/<marketplace>/<name>/`, and the manifest must resolve inside that version directory. If the manifest has a `hooks` field, it replaces the default `<plugin-root>/hooks/hooks.json`; otherwise that default file is read. The field may be a `./` path, an array of paths and inline objects, or one inline object. Referenced paths must start with `./`, contain no `..`, and canonicalize inside the plugin root. A JSON file or inline object uses its top-level `hooks` object when present, otherwise the value itself. Findings cite the hooks file or `plugin.json` (origin user).

Plugin hooks run only after the user trusts them with `/hooks`; cAInary cannot see the trust records. Plugin findings are best-effort and include a trust detail. Plugin hooks are not managed: `allow_managed_hooks_only` blocks them like user hooks, and both `features.hooks` gates apply. Only `command` and `mcp_tool` handlers are used; `prompt` and `agent` handlers are skipped. A handler `{ type = "mcp_tool", server, tool, input }` has no `command`; it gives one finding per `<server>.<tool>`, with the same event signals (`Interrupt` is transcript only). `input` isn't shown.

When an in-effect hook from a user-origin source is present, one scan note says: "Codex runs hooks that don't come from your organization only after you trust them with /hooks; cAInary can't see which ones you trusted." Organization config layers and requirements hooks do not trigger this note. User hook findings remain firm.

H.8 also applies to plain `rtk hook …` commands from hooks files, config layers, requirements,
and plugins. The Codex hook's origin, gates, in-effect state and cited source remain unchanged;
the rtk config path is listed in evidence for its telemetry state. An unresolved bare `rtk` still
uses H.8 on a best-effort (`may`) basis, with a detail that cAInary couldn't tell which `rtk` runs.

Not read: project `<repo>/.codex/` (no cwd scan), hook trust records, plugin `skills/` and `.app.json`.

```rust
// Plain data, no methods: concern tests build it by hand.
pub enum CxLayerId { MdmReq, MdmCfg, CloudReq, CloudCfg, LegacyReq, SysReq, ManagedCfg, UserCfg, SysDefaults }
pub struct CxLayer { pub id: CxLayerId, pub loc: Loc, pub origin: Origin }
pub struct CxSetting { pub value: Value, pub layer: CxLayerId, pub shadowed: Vec<CxLayerId> }

/// The dotted keys the resolver resolves; everything else is only listed in policy evidence.
pub const CX_KEYS: &[&str] = &["model_provider", "model_providers", "openai_base_url",
    "chatgpt_base_url", "notify", "mcp_servers", "hooks", "features", "otel.exporter",
    "otel.trace_exporter", "otel.metrics_exporter", "otel.log_user_prompt", "analytics.enabled",
    "profile", "profiles"];

pub struct CxConfig {
    pub layers: Vec<CxLayer>,                   // every present layer, requirements and config
    pub req: BTreeMap<String, CxSetting>,       // composed requirements, by top-level key
    pub req_hooks: Vec<(CxLayerId, Value)>,     // each requirements layer's own hooks table
    pub cfg: BTreeMap<String, CxSetting>,       // effective config for CX_KEYS
    pub hooks_file: Option<(Loc, Value)>,       // <home>/hooks.json
    pub plugin_hooks: Vec<(Loc, Value)>,         // one file or inline hook object per source
    pub plugin_mcp_servers: Vec<(Loc, String, Value)>, // enabled entries and their source
    pub cloud_ignored: Vec<String>,             // CX.2 keys found in cloud requirements
}
```

Installed marker (probe): `<home>` is a dir or `which("codex")` is `Found`.

Never read: `<home>/auth.json`, `<home>/sessions/`, `<home>/memories/`, `<home>/history.jsonl`,
`<home>/log/`, profile files, the `<home>` listing.

---

## CU. Cursor (`scanners/cursor.rs`)

Ref: `https://cursor.com/docs/hooks`, `…/enterprise/deployment-patterns`,
`…/cli/reference/configuration`, `https://cursor.com/privacy`.

| Source | macOS | Linux | Origin |
| --- | --- | --- | --- |
| enterprise hooks | `R/Library/Application Support/Cursor/hooks.json` | `R/etc/cursor/hooks.json` ✅ https://cursor.com/docs/hooks | system |
| user hooks | `~/.cursor/hooks.json` (JSONC) | same | user (§H per hook) |
| CLI config | `~/.cursor/cli-config.json` (JSONC) | same | user |
| MDM | `MDM(com.todesktop.230313mzl4w4u92)`, `MDM(co.anysphere.cursor.nightly)` | — | mdm |
| marker | `R/Applications/Cursor.app`, `~/Applications/Cursor.app`, `~/Library/Application Support/Cursor` | `~/.config/Cursor`, `cursor` on PATH | — |

Hooks: the shape is `{version:1, hooks:{<event>:[{command, type?}]}}`, and `type:"prompt"` is
skipped. Every event → identity (`user_email`). Every event except `workspaceOpen` → transcript.
Plus `beforeSubmitPrompt` → prompts; `beforeReadFile`/`beforeTabFileRead`/`afterFileEdit`/
`afterTabFileEdit` → file-contents; shell/MCP/tool events (`before|afterShellExecution`,
`before|afterMCPExecution`, `preToolUse`, `postToolUse`, `postToolUseFailure`) → tool-details;
`afterAgentResponse`/`afterAgentThought` → responses. All hook tiers run (no blocking).

MDM: `AllowedTeamId`, `AllowedExtensions`, `ExtensionGalleryServiceUrl`, `UpdateMode`,
`WorkspaceTrustEnabled`, `NetworkDisableHttp2` → policy (one finding); other non-`Payload*` keys
→ policy BE. CLI config `permissions.allow/deny`, `approvalMode`, `sandbox`: policy when the
origin is org, else info. Vendor default when installed: vendor "Cursor collects usage and
device data; Privacy Mode can't be read locally" (BE).

Never read: `…/Cursor/User/globalStorage/state.vscdb` (auth/state DB, undocumented).

---

## CP. GitHub Copilot (`copilot.rs` → `CpConfig`; `copilot_telemetry.rs`) — VS Code + Copilot CLI

Ref: `https://docs.github.com/en/copilot/reference/enterprise-administrators/enterprise-managed-settings`,
`…/copilot-cli-reference/cli-config-dir-reference`, `…/hooks-reference`,
`https://code.visualstudio.com/docs/enterprise/policies`,
`https://code.visualstudio.com/docs/agents/guides/monitoring-agents`,
`https://code.visualstudio.com/docs/configure/telemetry`.

`<cp>` = the `CopilotHome` tool home (`$COPILOT_HOME` if absolute or `~/…` without `..`, else
`~/.copilot`). `<vsc>` = macOS `~/Library/Application Support/Code/User` (and `Code -
Insiders`), Linux `<xdg>/Code/User` ✅ (`$XDG_CONFIG_HOME`, default `~/.config`).

### CP.1 Sources

| Source | macOS | Linux | Origin |
| --- | --- | --- | --- |
| Copilot MDM | `MDM(com.github.copilot)` | — | mdm |
| Copilot managed file | `R/Library/Application Support/GitHubCopilot/managed-settings.json` | `R/etc/github-copilot/managed-settings.json` ✅ https://docs.github.com/en/copilot/how-tos/administer-copilot/manage-for-enterprise/use-managed-settings/deploy-managed-settings | system |
| Copilot policy hooks | `R/etc/github-copilot/policy.d/*.json` | — no `policy.d` in GitHub's Copilot docs (deploy-managed-settings, cli-config-dir-reference) | system |
| VS Code policy | `MDM(com.microsoft.VSCode)` (BE), `MDM(com.microsoft.VSCodeInsiders)` | `R/etc/vscode/policy.json` ✅ https://code.visualstudio.com/docs/enterprise/policies | mdm / system |
| VS Code user | `<vsc>/settings.json` (JSONC) | same | user |
| CLI settings | `<cp>/settings.json` (JSONC), `<cp>/hooks/*.json`, `<cp>/providers.json` | same | user |
| surface markers (probe) | VS Code: `~/.vscode/extensions/github.copilot*` (listing); CLI: `<cp>` dir or `which("copilot")` `Found` | same | — |

- **Managed channel:** MDM > managed file (this order is UNVERIFIED → the channel choice is BE
  when both exist). The highest present channel wins outright, and the other gets info "not in
  effect". The managed file and the policy.d files are honored only when root-owned and not
  group/world-writable; otherwise info "Copilot ignores this file".
- **Managed keys:** `telemetry` → CP.2; any other key → policy "your organization restricts
  GitHub Copilot" (leaf lines, max 16).

### CP.2 Managed telemetry (`copilot_telemetry.rs`)

The winning channel's `telemetry` object is used **whole**; a lower channel's object is info,
not in effect. Its fields: `enabled`, `endpoint`, `protocol`, `headers`, `headersProvider`
(CLI), `serviceName`, `resourceAttributes`,
`capture.{identity,prompts,responses,toolArguments,toolOutput,policyDetail}`, `captureContent`
(legacy), `lockCaptureContent`.

`capture(class)` for each content class (`prompts`, `responses`, `toolArguments`,
`toolOutput`, `policyDetail`) takes the first of:

1. managed `capture.<class>` (an explicit `false` beats `captureContent: true`);
2. managed `captureContent`;
3. `false` if managed `lockCaptureContent` is `true`;
4. the local value for that surface (CP.3);
5. `false`.

`identity` uses steps 1, 4 and 5 only: `captureContent` and the lock don't cover it.

Signals with an active export (enabled and an endpoint): usage; + identity if
`capture(identity)`, `headers`, `headersProvider` or `resourceAttributes` holds; prompts →
prompts; responses → responses; toolArguments → tool-details; toolOutput → file-contents;
policyDetail → tool-details BE. A file or console exporter → info "written locally only".

### CP.3 Surfaces

Copilot runs on several surfaces that honor different fields. cAInary can't see which one you
use, so it emits one telemetry finding per installed surface:

| Surface | Classes it honors | Local layer (CP.2 step 4), highest first |
| --- | --- | --- |
| Copilot CLI | all | `COPILOT_OTEL_*` env, then `<cp>/settings.json` telemetry |
| VS Code, local chat | identity + legacy `captureContent` (all content) only | `COPILOT_OTEL_ENDPOINT` > `OTEL_EXPORTER_OTLP_ENDPOINT` env, then `github.copilot.chat.otel.*` settings; `CopilotOtel*` VS Code policies |
| VS Code, agent sessions (Agent Host) | all except identity | as for the CLI |

- For VS Code, the local-chat classes are certain. Classes only the Agent Host honors are added
  BE: "in Copilot agent sessions inside VS Code".
- In the Copilot Chat extension, env beats managed values, except identity and
  `resourceAttributes`. A VS Code finding that relies on that is BE.
- VS Code `CopilotOtel*` policies: `Enabled`, `Endpoint`, `ExporterType`, `Protocol`,
  `Headers`, `Outfile` (→ "written locally only"), `ResourceAttributes`, `ServiceName`,
  `CaptureContent`, `CaptureIdentity`. They sit above the user settings.
- `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true` with an exporter → prompts,
  responses, tool-details (VS Code).
- If no surface marker is found but managed telemetry exists, one finding with the union of
  classes, BE.

### CP.4 VS Code policy

- `TelemetryLevel`: `off` → policy; anything else → vendor + policy.
- The chat/MCP/extension policy keys (`ChatHooks`, `ChatAllowManagedHooksOnly`, `ChatMCP`,
  `ChatAllowedMcpServers`, `AllowedExtensions`, `ChatToolsAutoApprove`, …) → policy, one
  finding, names only.
- `ChatHooks` maps to `chat.useHooks` and is **policy only**: `true` "your organization allows
  chat hooks", `false` "your organization turned chat hooks off". It carries no content
  signals. Content comes only from real hook definitions (CP.6). VS Code hook files
  (`chat.hookFilesLocations`) are not read; when hooks are allowed, a note says so.

### CP.5 VS Code user and CLI

- **VS Code user:** `http.proxy` → traffic BE (host); `telemetry.telemetryLevel` ≠ `off` →
  vendor; unset and Copilot present → vendor BE, origin vendor-default.
- **CLI:** `proxyUrl` → traffic; `providers.json` entries with a URL → traffic ("can send
  requests to your own model providers at `<hosts>`"); `disableAllHooks: true` blocks user
  hooks (policy.d still runs). Vendor default when `<cp>` exists: vendor "Copilot CLI sends usage
  telemetry to GitHub".

### CP.6 Hooks

Sources: CLI `<cp>/hooks/*.json`, inline `<cp>/settings.json` `hooks`, policy.d. The shape is
`{version:1, hooks:{<event>:[{type, bash|command|exec+args|url}]}}` (`exec` + `args` is a
`Cmd::Argv`). Events are case-insensitive, letters only. Signals:
`userPromptSubmitted`/`userPromptTransformed` → prompts; `sessionStart` → prompts BE;
`agentStop`/`subagentStart`/`subagentStop`/`preCompact` → transcript;
`preToolUse`/`postToolUse`/`postToolUseFailure`/`permissionRequest` → tool-details; anything
else → usage. `url` → + traffic. `powershell`-only → info (doesn't run here). policy.d → system
"always runs". H applies.

```rust
// Plain data, no methods: concern tests build it by hand.
pub enum Surface { Cli, VsCode }
pub struct CpManaged { pub loc: Loc, pub origin: Origin, pub value: Map<String, Value> }
pub struct CpConfig {
    pub managed: Option<CpManaged>,           // the winning channel (CP.1)
    pub ignored: Vec<(Loc, &'static str)>,    // shadowed channel, not root-owned files
    pub vscode_policy: Vec<(Loc, Map<String, Value>)>,
    pub vscode_user: Option<(Loc, Map<String, Value>)>,
    pub cli_settings: Option<(Loc, Map<String, Value>)>,
    pub providers: Option<(Loc, Value)>,
    pub surfaces: Vec<Surface>,               // installed surfaces (probes)
    pub hook_files: Vec<(Loc, Origin, Value)>,// <cp>/hooks/*.json and policy.d
}
```

Never read: `<cp>/config.json`, `<cp>/apps.json`, `<cp>/session-state/`,
`~/.config/github-copilot/{hosts,apps}.json`, `~/.config/gh/hosts.yml`, and the `<cp>` listing
(only `hooks/` is listed).

---

## CG. ChatGPT desktop (`scanners/chatgpt.rs`) — macOS only

Ref: `https://help.openai.com/en/articles/20001535`, `…/20001276`,
`https://learn.chatgpt.com/docs/computer-use`, `…/customization/computer-history`.

| Source | Path | Rule |
| --- | --- | --- |
| app | `R/Applications/ChatGPT.app/Contents/Info.plist`, `~/Applications/…` | `CFBundleIdentifier == com.openai.codex` → installed (merged app). `ChatGPT Classic.app` → installed, BE |
| MDM | `MDM(com.openai.codex)` minus `requirements_toml_base64`/`config_toml_base64` (Codex owns those) | Chromium policies of the **in-app browser**: `ProxyMode` (not direct/system), `ProxyServer`, `ProxyPacUrl` → traffic "the built-in browser goes through your organization's proxy" (hosts only); `ExtensionInstallForcelist` → traffic BE; `BrowserSignin`/`RestrictSigninToPattern` → policy; `CloudReportingEnabled`/`ReportingPolicies` → usage BE ("may be inert"); any other key → policy (count + names) |
| Computer Use | `<codex home>/computer-use/Codex Computer Use.app` (stat) | info "Computer Use is set up; its grants live in TCC.db, which cAInary can't read" |
| Locked use | `R/Library/Security/SecurityAgentPlugins/CodexComputerUseAuthorizationPlugin.bundle` (stat) | device-access "ChatGPT can unlock this Mac" |
| Computer History | `<codex home>/memories/extensions/skysight` (**stat only**, the directory is never listed or opened) | tool-details "Computer History is on" |

Notes: "Workspace restrictions, Memory and Compliance API are server-side."

---

## DV. Device (`scanners/device.rs`)

Ref: Apple's TCC payload schema
(`https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.TCC.configuration-profile-policy.yaml`),
`https://www.electronjs.org/docs/latest/api/net`,
`https://code.visualstudio.com/docs/setup/network#_proxy-server-support`. Device is always
"installed".

| Source | macOS | Linux | Origin |
| --- | --- | --- | --- |
| managed domains | listing of `R/Library/Managed Preferences/*.plist` (names only, never opened here) | — | mdm |
| PPPC | `R/Library/Managed Preferences/com.apple.TCC.configuration-profile-policy.plist` (device file) | — | mdm |
| system extensions | `R/Library/SystemExtensions/db.plist` (undocumented format → BE; a parse failure is a source error) | — | system |
| sysext policy | `R/Library/Managed Preferences/com.apple.system-extension-policy.plist` | — | mdm |
| web content filter | `R/Library/Managed Preferences/com.apple.webcontent-filter.plist` (stat only) | — | mdm |
| system proxy | `/usr/sbin/scutil --proxy` (architecture.md §6.4; fixture: `scutilProxy` text) | `R/etc/environment` `http_proxy`/`https_proxy`/`all_proxy` (either case) | unattributed (macOS), system (Linux) |
| package registries | macOS: `~/.cargo/config.toml` (`$CARGO_HOME`), `~/.config/pip/pip.conf`, `~/.pip/pip.conf`, `~/Library/Application Support/pip/pip.conf`, `~/.config/uv/uv.toml`, `~/Library/Application Support/go/env`, `~/.nuget/NuGet/NuGet.Config`, `~/.yarnrc.yml`; `R/Library/LaunchDaemons/*.plist` only to attribute a hit | same, with `$XDG_CONFIG_HOME` in place of Application Support; no launchd attribution | org-installed if the file is root-owned or has no owner write bit, else unattributed; env: environment |

| Rule | Signals |
| --- | --- |
| ≥1 managed domain | info: "This Mac is managed: N configuration domains" (domain names as evidence, max 40) |
| PPPC `Services.<Svc>[]` (also one level of `PayloadContent[].Services`), Allow (`Authorization == Allow` or `Allowed == true`) for `SystemPolicyAllFiles` or `Accessibility` | device-access: "`<grantee>` can read all your files" / "…control your Mac". Grantee = `Identifier`, team from `CodeRequirement` substring `subject.OU] = "<team>"` |
| Allow-standard-user for `ScreenCapture` or `ListenEvent` | device-access BE ("may") — a profile can't grant these outright |
| other allowed services | info |
| Deny | policy: "MDM blocks `<grantee>` from `<service>`" |
| sysext `state == activated_enabled` with a network-extension category | traffic BE: "`<id>` may inspect or redirect network traffic, including AI tools'" |
| … with the endpoint-security category | device-access BE: "`<id>` can observe app launches and file access" |
| sysext origin | mdm if its team id is in `AllowedTeamIdentifiers` or `AllowedSystemExtensions[<team>]` lists the id; else user |
| web content filter present | traffic BE, mdm: "Your organization installed a web content filter" |
| proxy: `HTTPEnable`/`HTTPSEnable`/`SOCKSEnable` = 1 (host:port), `ProxyAutoConfigEnable` = 1 (PAC URL, query stripped, never fetched), `ProxyAutoDiscoveryEnable` = 1 (WPAD) | traffic BE: "Network traffic may go through a proxy at `<host>`". The detail notes that Electron apps (Desktop, Cursor, VS Code) follow the system proxy, and that CLIs do only if they honor it. `ExceptionsList` is shown as a count |
| package manager registry points at `127.0.0.1`, `localhost` or `::1` | traffic: "`<manager>` downloads go through a local proxy at `<host:port>`", one finding per manager, in one monitor entry. The detail says the proxy sees the name and version of every package and can block them. Not best effort: the file proves the redirect. A non-local registry is never reported |
| … Cargo | `[source.crates-io] replace-with = "<n>"` and `[source.<n>] registry = "<url>"` ([source replacement](https://doc.rust-lang.org/cargo/reference/source-replacement.html)); `config.toml`, else legacy `config`, under `$CARGO_HOME` (absolute, no `..`) or `~/.cargo` |
| … pip, uv | pip `index-url` in `pip.conf` (read as `key = value` lines, any section; [pip configuration](https://pip.pypa.io/en/stable/topics/configuration/)); uv `index-url`, or the `[[index]]` entry with `default = true`, in `uv.toml` ([uv configuration files](https://docs.astral.sh/uv/concepts/configuration-files/)). Env first: `PIP_INDEX_URL`; `UV_DEFAULT_INDEX`, `UV_INDEX_URL` |
| … Go | `GOPROXY` in the `go env` file (`,` or `\|` separated list; any local entry counts; [Go modules reference](https://go.dev/ref/mod#environment-variables)). Env first: `GOPROXY` |
| … NuGet, npm, Yarn | NuGet: a `<add key= value=>` line in `NuGet.Config` ([nuget.config reference](https://learn.microsoft.com/en-us/nuget/reference/nuget-config-file); line scan, no XML parser). npm: env `npm_config_registry` / `NPM_CONFIG_REGISTRY` only ([npm config](https://docs.npmjs.com/cli/v10/using-npm/config#registry)); `~/.npmrc` holds auth tokens and is on the deny-list, so it is never read. Yarn: top-level `npmRegistryServer` in `~/.yarnrc.yml` ([yarnrc](https://yarnpkg.com/configuration/yarnrc#npmRegistryServer)) |
| … credentials | userinfo in the URL, or a NuGet `packageSourceCredentials` element for the source: the detail says they go to the proxy, evidence shows `credentials = present (not shown)`; URLs go through `redact::url` |
| … attribution | macOS: the `R/Library/LaunchDaemons/*.plist` whose `ProgramArguments` has a token ending in `:<port>` of the registry names the entry (`agent_name` of its program, e.g. `Application Support/BayCollector/…` → "BayCollector") and adds `served by = <program>`; otherwise the entry is "Package registry proxy" |

Notes: "Whether a corporate root certificate is trusted can't be seen; cAInary doesn't read the
Keychain." "Permissions you granted yourself live in TCC.db, which needs Full Disk Access." On
Linux: "Linux has no standard device-management store; only /etc/environment proxies are
checked."

Never read: `R/Library/Preferences/com.apple.networkextension*.plist` (VPN identities and
passwords inline), `SystemConfiguration/preferences.plist`, the Keychains, TCC.db.
