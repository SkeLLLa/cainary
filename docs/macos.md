# macOS app

The native macOS menu bar app for cAInary, and how it is tested without a human. It runs the
bundled `cainary` CLI and draws its JSON: the report model is in architecture.md §3, change
detection in §4, and the subprocess contract in §9.1.

**Ground rules.** The UI renders what the core says: it never computes a level, a summary or a
diff, and its only arithmetic is the badge count (the `status` rule). It writes only its prefs
domain `ua.SkeLLLa.cAInary` and the login-item registration. (The opt-in OTel debug collector's
log file, §2.8, is written by the collector child, not by the app.) No network in the app itself:
Docs and Support links open in the browser on click (`NSWorkspace.open`, http(s) only). The only
listening socket belongs to the opt-in collector child (§2.8), on loopback. No credential files: it reads its
prefs, its own bundle, and (through `NSWorkspace`, for icons) the AI apps' `Info.plist`.

## 1. Contract with the core

**Helper:** `Bundle.main.bundleURL/Contents/Helpers/cainary`, kept out of `Contents/MacOS` so
`cAInary` and `cainary` can't collide on a case-insensitive disk. DEBUG builds also honour
`CAINARY_CORE=<path>` and `CAINARY_SCAN_ARGS="<extra args>"` (split on spaces and appended), so the
app can run against `target/debug/cainary --fixture …`.

| call | args | stdin |
| --- | --- | --- |
| scan, no baseline yet | `scan --json --env-kind launchd` | `/dev/null` |
| scan with baseline | `scan --json --env-kind launchd --since -` | baseline bytes |
| Copy report | `scan --no-color --env-kind launchd [--since -]` | baseline bytes, if any |

The app never passes `--alert`, because levels ignore it (architecture.md §3.2).

**Runner:** `CoreClient.run(args, stdin: Data?, timeout) -> Result<CoreOutput, CoreError>`. When a
baseline is passed, stdin is a pipe; otherwise it is `/dev/null`.
- All three pipe ends are `DispatchIO` stream channels: no thread ever blocks in `read`/`write`.
  stdin is written, then closed; write errors are ignored (the helper may exit without reading).
  `signal(SIGPIPE, SIG_IGN)` is set at launch and in the test main, so a closed pipe gives `EPIPE`.
- **One deadline (20 s, injectable) bounds all I/O**: the stdin write, exit, and EOF on stdout
  and stderr. EOF can't be trusted to arrive: a descendant that inherited a pipe keeps it open
  after the helper dies. On the deadline or a cap (stdout 8 MiB, stderr 64 KiB): SIGTERM → 2 s →
  SIGKILL → reap the helper, then `close(flags: .stop)` every channel without waiting for EOF →
  `.timedOut` / `.outputTooLarge`. A helper that exits but whose pipes stay open past the deadline
  is also `.timedOut`.
- Decode only after exit and EOF on both pipes; scans never overlap.

**Checks, in order:** exit ≠ 0 → `.exit(code, firstStderrLine)`; decode `{"schema": Int}` alone,
and anything but `3` → `.schema(n)`; a failed full decode → `.decode(msg)`; otherwise
`Scan(report, raw: Data)`, whose raw bytes become the baseline.

**`CoreError`:** `.helperMissing`, `.launchFailed`, `.exit`, `.timedOut`, `.outputTooLarge`,
`.decode`, `.schema`. Any of these → the **"Couldn't scan"** state: a grey `?` icon (never green),
a one-line reason plus Retry in the popover, and the last good report shown dimmed under "Last
scan at 16:30".

**Model** (`Report.swift`): a Codable mirror of architecture.md §3.6 and §4.3. Types: `Report`,
`Status`, `Entry`, `Finding`, `Config`, `SourceRecord`, `Since`, `Change`.
- Every enum is open. `Level.unknown(String)` sorts below `not-installed` and renders as a grey
  `?`. `Signal`, `Origin`, `SourceState`, `EntryKind`, `ChangeScope` and `ChangeKind` show an
  unknown value as its slug, and a change with an unknown scope or kind never notifies.
- Unknown keys are ignored; a missing required key or a wrong type fails the decode. `alert` and
  `counts` are optional and unused.

## 2. Screens

### 2.1 Menu bar icon (`MenuBarIcon.swift`)

The app's robo-canary (`CanaryLogo.swift`, drawn from `resources/icons/cainary-macos.svg` and
`cainary-mono.svg`): colored once there is a level, the template silhouette before that, with a
count badge (a knock-out ring) in its empty top-left corner, plus a monochrome template variant.
`MenuState(state:)` is a pure function in `AppState.swift`:

| state | logo | badge |
| --- | --- | --- |
| first scan running | template | — |
| `.failed`, unknown level, or `!complete && level < low` (the `status` incomplete rule) | template | `?` |
| `not-installed` | template, dimmed | — |
| `ok` / `opted-out` | colored | — |
| `low` / `medium` / `high` | colored | yellow / orange / red: entries (apps + others) at `low`+, capped at 9 |

The tooltip and accessibility label read `cAInary · HIGH · <status.summary>`, or
`cAInary · Couldn't scan: <reason>`.

### 2.2 Popover (`PopoverView.swift`, 360 pt wide)

From top to bottom:
1. **Header:** the level symbol, `status.label` and `status.summary` (two lines); the caption
   "Scanned 16:40", plus "· ⚠ N locations couldn't be read" when a source is `error`, `refused` or
   `capped`, and "Change tracking unavailable" when the baseline can't be replaced (§2.7); a
   Refresh button. In the failed state it becomes the Couldn't-scan banner.
2. **Changes since `<since.scannedAt>`** (`ChangesView.swift`), only while `changes` is non-empty.
   Up to 5 rows: a marker (`+` added, `−` removed, `↑` raised, `↓` lowered, `~` changed, `•`
   unknown), the entry name (by id; "Scan" for the `report` scope) and `text`. "+N more" opens
   Details on the Changes pane. A **Mark as seen** button sits below.
3. **AI apps:** one row per installed entry, showing `EntryIcon`, the name, a `LevelChip` and a
   one-line summary. Not-installed apps fold into "N not installed" (the `notInstalledExpanded`
   pref, as in `MatrixView.swift`). Clicking a row opens Details at that entry.
4. **Other monitoring on this device:** the `others` entries in core order, using the same row. With
   none: "No other monitoring found".
5. **"What the levels mean"** (`LegendView.swift`): six rows of symbol, colour, label and the
   meaning from architecture.md §3.2.
6. **Footer:** "Open details", and a ⋯ menu with Copy report, Settings…, About cAInary, Support
   Ukraine ▸ and Quit.

`App.swift` wraps the popover in a `ScrollView` capped at 640 pt. `PopoverView` itself has no
`ScrollView`, so it can be snapshot-rendered (§5c).

**Level style** (`Style.swift`): colour is never the only cue.

| level | colour | symbol |
| --- | --- | --- |
| high | `systemRed` | `exclamationmark.octagon.fill` |
| medium | `systemOrange` | `exclamationmark.triangle.fill` |
| low | `systemYellow` | `exclamationmark.circle.fill` |
| opted-out | `systemBlue` | `hand.raised.circle.fill` |
| ok | `systemGreen` | `checkmark.circle.fill` |
| not-installed | `tertiaryLabelColor` | `circle.dashed` |
| unknown | `secondaryLabelColor` | `questionmark.circle` |

`LevelChip(level, text?)` draws a level; inactive findings show "inactive".

**Icons** (`EntryIcon.swift`, keyed by entry id):

| entry | real icon, when installed | glyph otherwise |
| --- | --- | --- |
| `claude` | Claude.app, else the claude-code URL handler | starburst |
| `openai` | ChatGPT.app, else Codex.app | rosette |
| `cursor` | Cursor | cube |
| `copilot` | VS Code | goggles |

Monitors use SF Symbols: `device` → `laptopcomputer`, `device-management` → `building.2`,
`network-proxy` → `network`, and `shield.lefthalf.filled` otherwise. Snapshots turn the real icons
off with `EntryIcon.useAppIcons = false`.

### 2.3 Details window (`DetailView.swift`, 780×560)

A `NavigationSplitView`. The sidebar has Changes (when there are any), AI apps (the four, with
not-installed ones greyed), Other monitoring, and Checked locations and OTel debug collector (§2.8).
Popover rows and notification clicks set `Navigation.selection: DetailSelection` (`.changes`,
`.entry(id)`, `.sources`, `.collector`).

`DetailView` takes the `ScanState`. `.scanning(nil)` shows "Scanning…". `.failed(_, nil)` shows a
centered "Couldn't scan", the error's reason and **Retry** (the store's refresh). `.failed(_, last)`
keeps the last report but puts a banner ("Couldn't scan — showing results from HH:MM" + Retry) over
the detail pane and dims it (opacity 0.5, no colour), so stale green never reads as current.

**Entry pane:** `EntryDetailView`. It has no `ScrollView` of its own; the split view adds one.
1. **Level 1:** the icon, name, `LevelChip` and `status.summary`; a line with the `surfaces`
   display names and "sends: prompts, transcript…".
2. **Level 2:** one `FindingRow` (`DisclosureGroup`) per in-effect finding, in core order: a
   `LevelChip`, the title, a "may" tag when `maybe`, and "set by you" when `setBy == user`. A
   surface prefix ("Claude Desktop: …") appears only when the entry has more than one surface.
   Inactive findings go under "Present but not in effect", dimmed.
3. **Level 3**, when a row is expanded:
   - `detail`, "Sends: …", and "Set by: …" (an origin phrase: mdm → "your organization (MDM)",
     user → "you", …);
   - `config.path`, then the evidence in a selectable monospaced block;
   - **What it sends** (`PayloadView.swift`), only when the finding has a `payload` (in-effect
     telemetry findings): a collapsed `DisclosureGroup` after the evidence and before Docs, drawn
     from the core's JSON as is. Inside: the export and catalog version (plus a "may" tag); one
     line per gate (a chip, "sent", "redacted", "generic", "not sent" or "local only", and the
     core's `text`); the identity attributes ("on every record"); the resource attributes; the
     records, each with a "may" tag when `maybe`, a "seen" tag when `observed`, its attributes as
     `key — what`, and a chip on content attributes; and the sample in a selectable monospaced
     block with **Copy** (`NSPasteboard`). The model decodes `payload` leniently: a missing or
     malformed one is `nil` and never fails the report, and `Sent`, `Export` and `ItemKind` are open
     string enums. It is closed by default, and its state lives in `Navigation.expanded` under
     `"<findingKey>#payload"`.
   - **Reveal in Finder**, only for `config.kind` `file`/`dir` with a path starting `/` or `~/`
     (`~` expanded) that exists;
   - **Docs**, a `Button` (not a `Link`, so it renders in snapshots) that opens the http(s) URL.

Below the findings come the entry `notes`. App entries also get one caption: "The app sees
launchd's environment, not your shell's. Run `cainary scan` in a terminal to check your shell."
Expanded rows live in `Navigation.expanded: Set<String>` (finding
`key`), since there is no `@State` (§3).

**Changes pane:** every change, plus `from → to`.

**Checked locations:** `sources` grouped by `tool`, with path and state. `error`, `refused` and
`capped` show in orange, with their `note`.

### 2.4 Notifications (`Notifier.swift`)

The app turns the core's notifying `changes` (architecture.md §4.2) into notifications. A click
opens Details at that entry, not the popover: `MenuBarExtra` has no public API to open its window.
- **One notification per entry per scan:** title `<entry name> · <status.label>`, body the first
  notifying `text` plus ` (+N more)`, identifier and `threadIdentifier` the entry id.
- **`plan(changes, report, ids) -> [Planned]`** is a pure function. `Planned` carries its change ids.
- **`NotificationPosting.post([Planned], isCurrent: () -> Bool) async -> Set<String>`** returns the
  change ids it *handled*. It requests authorization on the first post, then calls `isCurrent()`
  (after that await, and again before each `add`); false → stop, handling nothing more.
  - Handled: `add` succeeded, or the change was deliberately muted (`notifyChanges` off, or
    authorization denied). Muted changes count as handled, so turning notifications on later
    doesn't replay old changes.
  - Not handled: `add` failed. Those ids stay due and are retried on the next scan.
  - `UNNotifier` is the real one. With `Bundle.main.bundleIdentifier == nil` it treats everything
    as muted and never touches `UNUserNotificationCenter`, which crashes outside a bundle.
    `RecordingNotifier` (test) records, and can be told to fail ids.
- **The app delegate** (`@NSApplicationDelegateAdaptor`) sets the center delegate at launch:
  `willPresent` → `.banner`; `didReceive` → `Navigation.select(.entry(id))` and
  `WindowOpener.openDetails()`.

A red-flag notification from the collector (§2.8) has the identifier prefix
`otel-collector-alert:`; its click opens Details at the collector pane instead of an entry.

### 2.5 Settings (`SettingsView.swift`)

A grouped `Form`, 480 pt wide:
- **Notifications:** "Notify about changes" (`notifyChanges`, default on). When authorization is
  denied: "Notifications are off for cAInary" and an "Open System Settings" button.
- **Menu bar:** icon style, Color or Monochrome (`menuBarIconStyle`).
- **Refresh:** 5, 10 (default), 30 or 60 min, or Daily (`refreshMinutes`). A stored non-standard
  value is kept in the list.
- **Startup:** Launch at login (`LoginItem.swift`: `SMAppService.mainApp`, the approval hint, the
  error line).
- **OTel debug collector:** the opt-in toggle and its options (§2.8).
- **Support Ukraine; version, Source code, About…**

There is no `--alert` picker: levels, the icon and notifications all ignore it. The legacy
`paranoia` key is never read.

### 2.6 About (`About.swift`, `SupportLinks.swift`)

The credits sentence comes from the README; the version is `CFBundleShortVersionString` +
`CNGitCommit`; COPYING ships in `Contents/Resources`.

### 2.7 Lifecycle and `ReportStore`

`main.swift` ignores SIGPIPE, exits when another instance with the bundle id runs, then calls
`CainaryApp.main()`. `ActivationPolicy.swift` shows a Dock icon only while a titled window is
open; the details window SwiftUI opens at launch is closed again.

**`ReportStore`** (`ObservableObject`, `@MainActor`) holds `state: ScanState` (`.scanning(last:)`,
`.ready(Report, at:)`, `.failed(CoreError, last:)`) and `menuState`.
- **Coalescing:** `inFlight`, `pending` and `generation`. Requests made during a scan collapse into
  one follow-up scan. A result is dropped if `generation` changed while it ran.
- **Triggers:** the `refreshMinutes` timer (restarted when the setting changes); opening the
  popover, if the last scan finished more than 30 s ago; `NSWorkspace.didWakeNotification`;
  Refresh; the confirm scan.
- **Baseline replacement** (`BaselineStore.replace(raw) -> Bool`) is used to seed, rebaseline and
  Mark as seen. It fails when `raw` is over 1 MiB, which the core would reject as a baseline every
  time. On success, `notified` and the candidates are cleared. On failure, the old baseline and
  ids are kept, and the popover header shows one caption: "Change tracking unavailable".
- **After a successful scan.** The scan's start time is `t`, `N` is its
  notifying change ids, `notified` is the persisted `notifiedChangeIds`, `C: [id: confirmAfter]`
  holds the in-memory candidates, and `posting` holds the ids of a post still in flight.
  1. No baseline: `replace(raw)`. Done.
  2. `since.error != nil`: `replace(raw)` silently. Done.
  3. `notified ∩= N`, on every diff, so a change that went away notifies again when it returns.
  4. `fresh = N − notified − posting`. `C` keeps only `fresh` ids, and gains each new one with
     `confirmAfter = t + confirmDelay` (30 s, injectable).
  5. `due` = the ids in `C` with `confirmAfter ≤ t`: only a scan that *started* after the confirm
     time confirms, so an early Refresh or wake scan can't.
  6. If `due` isn't empty, `plan()` it, move it from `C` to `posting`, note the generation `g`, and
     `await post(planned, isCurrent: { generation == g })`. When it returns: `posting −= due`; if
     `generation == g`, `notified ∪= handled ∩ N`, and the ids not handled go back into `C` with
     their old `confirmAfter`, so the next scan retries them.
  7. Keep one confirm timer, for the earliest `confirmAfter` in `C`. Replace it whenever `C`
     changes, and cancel it when `C` is empty or the generation changes.

  Steps 3–5 and the bookkeeping in step 6 are a pure `ChangeTracker` value in
  `BaselineStore.swift`, tested without a helper (§5b).
- **Mark as seen:** `replace(raw)` with the current report, bump `generation` (which also drops a
  scan or post in flight), and rescan.

### 2.8 OTel debug collector (opt-in; `CollectorClient`, `CollectorStore`, `CollectorView`)

An off-by-default toggle in Settings that runs `cainary-otel-debug`, a separate local OTLP/HTTP
receiver, as a child of the app, so you can see what an AI tool's telemetry export contains. The
design is `docs/design/otel-payload-preview.md` §8, §9 and §14. `cainary scan` never starts it, and
the app never talks to it over the network: it reads the child's stdout.

- **Helper:** `Contents/Helpers/cainary-otel-debug`; DEBUG builds also honour
  `CAINARY_OTEL_DEBUG=<path>`. A missing helper shows "the collector is missing from the app".
- **Preferences** (`Preferences.swift`, in the app's own domain):

  | key | default |
  | --- | --- |
  | `otelCollectorEnabled` (Bool) | `false` |
  | `otelCollectorPort` (Int, 1024–65535) | `4318` |
  | `otelCollectorLogToFile` (Bool) | `false` |
  | `otelCollectorLogPath` (String) | empty: `~/Library/Logs/cAInary/otel-debug.jsonl` |
  | `otelCollectorPresets` ([String], the presets that are on) | absent: the default-on set (everything but `ipv4`) |
  | `otelCollectorPatterns` (Data, JSON `[{name, kind, pattern, caseSensitive}]`) | none |
  | `otelCollectorNotify` (Bool) | `true` |
  | `otelCollectorTls` (Bool) | `false` |
  | `otelCollectorTlsHosts` ([String]) | none |
  | `otelCollectorTlsPort` (Int, 1–65535) | `8443` |

  The toggle is intent: when it is on, the collector starts at launch. Changing any option that
  reaches the child (port, log file, presets, patterns) restarts a running one after a short pause;
  "Notify about red flags" doesn't. `--show-values` is not offered.
- **Settings section:** the toggle; the port; "Show in UI only" or "Also save to:" a path with
  **Choose…** (`NSSavePanel`); a checkbox per preset; a table of your own patterns (name, pattern,
  **Regex** and **Match case** checkboxes, add and remove); "Notify about red flags".
- **Process** (`CollectorClient.swift`): Foundation `Process` with three `Pipe`s. argv is only
  `--json --config-stdin --port <n> [--log-file <path>]`. The red-flag patterns and presets go over
  stdin as one JSON line, so the pattern text never appears in `ps`. The app then keeps the write
  end of stdin open and never closes it: that is the lifeline, the child exits on stdin EOF, so it
  can't outlive the app, `kill -9` included. The write end is close-on-exec, so the `cainary scan`
  children don't inherit it. stdout is read by a line reader with a 4 MiB line cap (a longer line
  kills the child: "Stopped: output too large."); stderr keeps the last 8 KiB.
- **Stop:** close stdin, SIGTERM, wait up to 2 s (1 s when the app quits), SIGKILL, reap. Toggling
  off does this in the background; a restart waits for it, so the port is free. On quit,
  `applicationWillTerminate` stops the child synchronously.
- **State** (`CollectorStore`, an `ObservableObject`): off, starting, listening (the `hello`), or
  failed (a reason, with **Retry**; there is no auto-restart). It keeps the last 50 `batch` lines,
  200 `alert` lines and 16 MiB of lines in memory, never on disk. It reads JSON-lines v1
  (`CollectorLines.swift`) and tolerates unknown types, keys and `error.source` values; another `v`
  stops the collector with "Update cAInary".
- **Pane** (`CollectorView.swift`): a status line ("Listening on http://127.0.0.1:4318 · 12 batches
  · 3 red flags", or Stopped or Failed); the `hello.setup` lines in two monospaced blocks with
  **Copy**; the red flags; and the batches, newest first, each a `DisclosureGroup` drawn from
  `summary` (group chips, an orange "not in catalog" tag) with a "Raw records" group for the masked
  `resources`.
- **Notifications:** a red flag posts a plain-text notification titled `Red flag: <pattern>` with
  the body `<event> · <attribute> (<match>)`, at most one per pattern per 60 s. Control and bidi
  characters are escaped first. A click opens the pane.
- **HTTPS takeover** (design §16, §17; `TakeoverSettingsSection`, `TrustStore`, `TrustClient`).
  For an agent whose managed settings pin its telemetry to an HTTPS host. The collector forwards
  nothing: while it runs, your organization's collector receives nothing for those names.
  - **Settings:** "Use HTTPS takeover" adds `--tls`, one `--tls-host <name>` per valid host
    (lowercase DNS name with at least two labels, no wildcard, no IP, at most 32; invalid rows are
    flagged and skipped) and `--port <takeover port>` (default 8443, replacing the plain port).
    Host suggestions are the `http(s)` hosts in the evidence of findings that carry a `payload`
    in the last scan. Patterns still go over `--config-stdin`. With the switch on and no valid
    host, the collector doesn't start and says why.
  - **Pane:** in takeover mode (`hello.mode == "tls-receiver"`) it lists the names, the CA path
    and SHA-256, and the `setup.takeover` steps with **Copy**. Pointing the host names at this Mac
    (for example `/etc/hosts`) stays your step; the app never does it.
  - **Listen errors:** after an `error` line with `source: "listen"` and an exit, the child's whole
    stderr (the privileged-port note) shows in a selectable box under the section. On macOS low
    ports are normally allowed, so this is rare.
  - **Trust buttons**, each a one-shot `cainary-otel-debug` call (stdin `/dev/null`, pipes
    close-on-exec, 1 MiB stdout cap, 15 s timeout then SIGKILL; `OneShot` in `TrustClient.swift`):
    - **Let Claude Code trust the collector…** runs `--trust claude-code --dry-run --json` and
      opens a sheet with the exact change (`env.NODE_EXTRA_CA_CERTS: <from> → <to>`), the settings
      path, the backup path, that Claude Code must be restarted, and "Your org's collector
      receives nothing while the takeover is active". Only **Confirm** runs
      `--trust claude-code --json`; Cancel writes nothing. A `refused` result (managed settings,
      symlink, …) shows its reason and no sheet.
    - **Undo Claude Code trust** (`--trust claude-code --undo --json`) is enabled when
      `--trust-status --json` says `applied`. The status refreshes when Settings opens and after
      every action.
    - **Prepare Codex bundle** (`--trust codex --json`) shows the helper's `command`
      (`env CODEX_CA_CERTIFICATE=… codex`) with **Copy**, and **Remove** (`--undo`).
    - The no-write alternative `env NODE_EXTRA_CA_CERTS=<ca path> claude` is shown with **Copy**
      (the path is single-quoted, since the macOS state directory has a space).
    - The only file these ever change is `env.NODE_EXTRA_CA_CERTS` in `~/.claude/settings.json`,
      by the helper, after a backup; the app writes nothing itself.
- **Sandbox and entitlements:** none. The app is not sandboxed and has no entitlements, so
  `com.apple.security.network.server` isn't needed, and the hardened runtime doesn't restrict
  listening sockets. The child binds loopback only. Whether the Application Firewall prompts for
  it is untested: check by hand once.
- **The log file** is written by the child (mode 0600, in a 0700 directory it creates), not by the
  app, so "writes only its prefs domain" still holds for the app itself.
- The collector is unauthenticated: any local process can post to it, so the pane shows what it
  *received*.

## 3. Files (`macos/`: macOS 14+, SwiftUI, Swift 6, swiftc via Makefile, no SwiftPM)

| file | role |
| --- | --- |
| `Sources/main.swift` | SIGPIPE, single instance, `CainaryApp.main()` |
| `Sources/App.swift` | `MenuBarExtra(.window)`, `Window(id: "details")`, `Settings`, app delegate, wiring |
| `Sources/Report.swift` | the schema-3 model (§1) |
| `Sources/AppState.swift` | the shared interfaces: `CoreError`, `ScanState`, `MenuState(state:)`, `IconStyle`, `DetailSelection`, `Planned`, `protocol NotificationPosting`, `protocol KeyValueStore` (UserDefaults conforms), pref keys |
| `Sources/Preferences.swift` | `Prefs.defaults`: `.standard` when the bundle id is `ua.SkeLLLa.cAInary`, else `UserDefaults(suiteName:)` |
| `Sources/CoreClient.swift` | locate, bounded `run`, `scan(baseline:)`, `copyReport(baseline:)` |
| `Sources/ReportStore.swift` | §2.7 |
| `Sources/BaselineStore.swift` | `baseline`, `notifiedChangeIds`, `replace(raw) -> Bool`; `ChangeTracker` (§2.7 steps 3–6) |
| `Sources/Notifier.swift` | `plan()`, `UNNotifier` |
| `Sources/Navigation.swift` | `ObservableObject`: `selection`, `expanded` |
| `Sources/PayloadView.swift` | "What it sends" (§2.3), `CopyBlock`, `SentChip` |
| `Sources/CollectorClient.swift`, `CollectorLines.swift`, `CollectorSettings.swift`, `CollectorStore.swift`, `CollectorView.swift` | the OTel debug collector (§2.8) |
| `Sources/TrustClient.swift`, `TrustStore.swift` | the takeover's one-shot trust calls and their state (§2.8) |
| `Sources/Style.swift` | level style, `LevelChip`, display names (signal, origin, surface), `WindowAccessor` |
| `Sources/MenuBarIcon.swift` | `image(MenuState, IconStyle) -> NSImage`, the label view |
| `Sources/EntryIcon.swift` | §2.2 icons |
| `Sources/PopoverView.swift`, `ChangesView.swift`, `LegendView.swift` | §2.2 |
| `Sources/DetailView.swift` | §2.3 |
| `Sources/SettingsView.swift`, `LoginItem.swift`, `About.swift`, `SupportLinks.swift`, `WindowOpener.swift`, `ActivationPolicy.swift` | §2.5–§2.7 |
| `Info.plist` | §4 |
| `Tests/run.sh`; `Tests/Support/` (`Check.swift`: `check()`; `Fakes.swift`: `MemoryStore`, `RecordingNotifier`); `Tests/Unit/` (`main.swift` + one file per suite); `Tests/Snapshots/`; `Tests/stubs/*.sh` | §5 |

Rules:
- **Views take values, `Binding`s and action closures** (`PopoverActions`, …), never `ReportStore`
  or `UserDefaults`. Only `App.swift` wires them together. That keeps the views independent
  and lets the views be rendered in tests.
- **No SwiftUI macros.** The CommandLineTools toolchain has no SwiftUI macro plugin: `@State`
  fails with "plugin for module 'SwiftUIMacros' not found" (checked 2026-10-21). Use
  `ObservableObject`, `@Published`, `@StateObject`, `@ObservedObject` and `@AppStorage(store:)`.
  Don't use `@State`, `@Observable`, `@Entry` or `#Preview`.

## 4. Build and packaging

**Makefile** targets `app`, `bundle` and `ui-test`:
- `SWIFTC ?= swiftc`, `SDKROOT ?= $(shell xcrun --sdk macosx --show-sdk-path)`, flags
  `-swift-version 6 -sdk $(SDKROOT) -module-cache-path $(TMPDIR)/swift-mc -target <arch>-apple-macos14`.
  mise sets `SWIFTC` to its toolchain's `usr/bin/swiftc` (through the `bin/swiftc` symlink the driver
  warns "Unable to locate libSwiftScan"). Both flags matter in a sandbox: the default module
  cache isn't writable, and mise's `swiftc` finds no SDK on its own.
- `make app` → `target/macos/cAInary`: host arch, `-Onone -g -D DEBUG`; with `RELEASE=1`, `-O`,
  arm64 + x86_64 and `lipo`.
- `make bundle` needs `app` and the helper: `build` by default, `core-universal` with
  `RELEASE=1`. `CORE ?=` `target/debug/cainary`, or `target/universal/cainary` with `RELEASE=1`;
  passing `CORE=…` changes only the path bundled. It then runs `packaging/bundle.sh`.
- `make ui-test` (needs `build`) runs `sh macos/Tests/run.sh`; `check` is `lint test ui-test`.

**`packaging/bundle.sh`** (POSIX sh, shellcheck-clean). Inputs: `APP_BIN` (default
`target/macos/cAInary`), `CORE` (default `target/debug/cainary`) and `OUT` (default `dist`).
Steps:
1. Read `VERSION` with `sed` from `[workspace.package] version` in `Cargo.toml`, the single
   version source (architecture §11). Fail unless `"$CORE" --version` prints that version, which
   catches a stale helper.
2. Lay out the bundle: `Contents/MacOS/cAInary`, `Contents/Helpers/cainary`, `Contents/Info.plist`
   and `Contents/Resources/COPYING` (from the repo root).
3. Stamp the plist: `sed` replaces `__VERSION__`, `__COMMIT__` (`git rev-parse`, or `unknown`;
   `-dirty` when there are local changes) and `__BUILD_DATE__`. Then run `plutil -lint`.
4. Sign inside out: `codesign --force --options runtime` on the helper (identifier
   `ua.SkeLLLa.cAInary.helper`), then on the app, then `codesign --verify --strict`. The signature
   plus a stable bundle id is what makes notifications and `SMAppService` work locally. Ad hoc by
   default; with `CODESIGN_IDENTITY` (a certificate SHA-1) it writes and checks the designated
   requirement `identifier … and certificate leaf = H"<sha1>"`, which releases use so grants
   survive updates ([distribution.md](distribution.md#signing)). Releases are not notarized.
5. Zip with `ditto -c -k --norsrc --noextattr --keepParent` → `dist/cAInary-<ver>-macos.zip`.

**`macos/Info.plist`**: bundle id `ua.SkeLLLa.cAInary`, executable and display name `cAInary`,
`LSUIElement`, `LSMinimumSystemVersion` 14.0, and the `__VERSION__`/`__COMMIT__`/`__BUILD_DATE__`
placeholders. There is no `CFBundleIconFile` yet (no artwork; SF Symbols only).

No entitlements (the collector child needs none either, §2.8), and no Python, Ruby or Node
anywhere. `bundle.sh` is expected to put the collector at `Contents/Helpers/cainary-otel-debug`
and sign it as `ua.SkeLLLa.cAInary.otel-debug`; that change is pending (packaging is decided
separately).

## 5. Proving it works without a human

Everything below runs without a window, so it also works in a sandbox that blocks `open`;
`ImageRenderer` from a command-line binary works there too.

`Tests/run.sh` makes two `swiftc -parse-as-library` builds into `target/macos-tests/`, each from
every `Sources/*.swift` except `main.swift`, plus `Tests/Support/*.swift`:
- **`tests`**, plus `Tests/Unit/*.swift`. `Tests/Unit/main.swift` is the one `@main`; it calls
  each suite function in turn (`decodeTests()`, `stateTests()`, …). `check("name", cond)` prints
  each failure by name, and the binary exits non-zero if any failed.
- **`snapshots`**, plus `Tests/Snapshots/*.swift`, with its own `@main` (§5c).

**(a) Decode and state** (`DecodeTests.swift`, `StateTests.swift`):
- Decodes every `crates/cainary-core/tests/golden/*.json` and `crates/cainary-cli/tests/golden/*.json`.
- Forward-compatibility cases, written to `$TMPDIR`: an unknown slug per open enum decodes; an
  extra key is ignored; a missing key and a wrong type both fail.
- **`PayloadTests.swift`**: every golden decodes, and exactly the findings with a `payload` key get
  one. A string, `null` or export-less payload is `nil` and the finding survives; an unknown `sent`,
  `export` or `kind` slug is kept; an absent `maybe` is false.
- `MenuState`: `empty-macos` is a template; `device-only-proxy` is coloured with badge 1; a
  synthetic incomplete `ok` is `?`; an unknown level is `?`, never green.

**(b) Client, tracker and store:**
- **`ClientTests.swift`**, against the stubs: a valid report; exit 1 with stderr; `schema: 4` →
  `.schema(4)`; 9 MiB of stdout → `.outputTooLarge`; 1 MiB of stderr → `.outputTooLarge`; 60 KiB of
  stderr written before, and in another stub after, 1 MiB of space-padded report → decodes (either
  sequential drain would deadlock); exiting without reading 200 KiB of stdin (no hang, no
  SIGPIPE); echoing the stdin byte count (the baseline arrives intact).
  Deadline 1 s, each asserting `.timedOut`, the helper reaped, and **elapsed < 4 s**:
  `trap '' TERM; sleep 60`; `sleep 60 & exec sleep 60` (a descendant holds the pipes); and
  `sleep 60 & exit 0` (exited, pipes still open).
- **`CollectorTests.swift`** (§2.8): the v1 lines of `Tests/Support/CollectorSamples.swift`
  (hello, batch, alert, error; unknown type, key and `error.source`; `v: 2` refused; garbage
  skipped); the settings → argv (no pattern text) and stdin config line, prefs round trip and
  clamping; `CollectorClient` against `collector-*.sh` stubs (lines in order, the config on stdin,
  stop closes stdin and reaps, a SIGTERM-ignoring child is killed after the grace, an oversize
  line kills the child, an exit carries stderr, a missing helper); `CollectorStore` retention
  (50 batches, 200 alerts, 16 MiB), the 60 s per-pattern throttle, `v: 2` → "Update cAInary",
  escaped stderr, and with a real stub child: start at launch, one restart for two edits, no
  restart for a notify change, off and quit reap it. Not covered here: the no-orphan test that
  SIGKILLs a helper process holding the lifeline, and a scan running while the collector is up.
- **`TrustTests.swift`** (§2.8, HTTPS takeover): the takeover settings and argv (patterns stay out
  of it), prefs round trip, host validation and suggestions from the org golden; the one-shot
  calls against `Tests/stubs/trust.sh` (a stateful stub of `--trust` and `--trust-status`; refusal
  exits 1 and is still a report; a timeout kills `trust-hang.sh`; `trust-big.sh` is over the cap);
  the confirm flow (preview writes nothing, Cancel applies nothing, Confirm applies and refreshes
  the status, Undo, Codex prepare and remove, refusal has no sheet); the TLS `hello`; and the
  listen-error note.
- **`TrackerTests.swift`**, `ChangeTracker` with explicit times: nothing is due before
  `confirmAfter`, even if a scan runs; due after; a flap (seen, then gone at the confirm) posts
  nothing; notify A, a scan sees only B, then A+B → A is due again after a new confirm; unhandled
  ids stay due on the next scan; a generation change during the post records nothing.
- **`NotifierTests.swift`**, for `plan()`: grouping per entry, "(+N more)", the current label in
  the title, and the `report` scope and unknown scopes or kinds skipped.
- **`StoreTests.swift`** runs `ReportStore` against the real `target/debug/cainary`, with
  `extraArgs: ["--fixture", dir]`, a `MemoryStore`, a `RecordingNotifier` and
  `confirmDelay = 0.05 s`:
  1. A missing helper → `.failed(.helperMissing, last:)`, and the menu state is `?`.
  2. Three requests during one scan → one follow-up scan (counted with a stub).
  3. `empty-macos` with empty prefs → `.ready`. The baseline is saved, no `--since` is passed, and
     nothing is posted.
  4. Switch to `claude-code-org-macos` → `changes` is non-empty, and nothing is posted until the
     confirm scan. Then exactly one notification: id `claude`, title `Claude · HIGH`.
     `notifiedChangeIds` equals the notifying ids. A rescan posts nothing.
  5. Mark as seen → the next scan has `changes == []`.
  6. A baseline of `not json` → `since.error` → a silent rebaseline. The next scan has no error.
  7. `notifyChanges = false` → nothing is posted, but the ids are recorded (muted).
  8. The notifier fails `claude` once → not recorded; the next scan posts it.
  9. A 2 MiB `raw` (stub) → `replace` fails, the old baseline and ids are kept, and
     `trackingUnavailable` is true.

**(c) Snapshots** (`Tests/Snapshots/`): runs the real helper on fixtures and writes 2× PNGs to
`target/ui-snapshots/`, with `useAppIcons = false`.
- **Popover:** `popover-<fixture>.png` for `empty-macos`, `claude-code-org-macos`,
  `device-macos-managed`, `device-only-proxy` and `cursor-macos-managed`; also `-changes`
  (org-macos against an `empty-macos` baseline), `-failed`, `-scanning`, and a dark org-macos.
- **Details:** `detail-claude.png` (org-macos, all rows and every "What it sends" expanded), `detail-monitor.png` (the first
  `others` entry of `device-macos-managed`) and `detail-not-installed.png`.
- **Collector:** `collector.png` (the pane on the sample lines) and `collector-failed.png`.
- **Menu bar:** `menubar.png`, every `MenuState` look × both icon styles, on light and dark strips.

Pass: every PNG exists, isn't empty, and has a sane height (popover 200–1400 pt). Reviewers then
look at them.

What `ImageRenderer` can't draw: `Menu`, `Toggle`, segmented `Picker`, `Link`, bordered `Button`, `ProgressView` and `ScrollView`
content come out as yellow placeholders. So the ⋯ menu is a placeholder, and Settings isn't
snapshot-tested.

**(d) Manual checklist.** Run from the repo root:

```sh
make build ui-test bundle && open dist/cAInary.app
```

1. **Icon:** there is no Dock icon, and the colour matches `./target/debug/cainary status`.
2. **Popover:** it matches `./target/debug/cainary scan --summary`.
3. **Details:** a row opens Details at that entry; an expanded finding shows sends, set by, config
   and evidence; Reveal in Finder selects the file; Docs opens the browser.
4. **Settings and lifecycle:** the icon style switches; Launch at login shows up in System
   Settings → General → Login Items; Quit removes the icon.
5. **Notifications.** This writes to the real prefs domain and resets it at the end.

   ```sh
   pkill -x cAInary; defaults delete ua.SkeLLLa.cAInary 2>/dev/null; F=$PWD/crates/cainary-core/tests/fixtures
   CAINARY_SCAN_ARGS="--fixture $F/empty-macos" dist/cAInary.app/Contents/MacOS/cAInary & sleep 5; kill $!
   CAINARY_SCAN_ARGS="--fixture $F/claude-code-org-macos" dist/cAInary.app/Contents/MacOS/cAInary &
   ```

   Allow notifications when asked. About 30 s later "Claude · HIGH" arrives, and a click opens
   Claude's details. The popover shows "Changes since …", and Mark as seen clears it. Clean up
   with `kill $!; defaults delete ua.SkeLLLa.cAInary`.
6. **OTel debug collector.** In Settings turn on "Run the collector", then in fish:

   ```fish
   env CLAUDE_CODE_ENABLE_TELEMETRY=1 OTEL_LOGS_EXPORTER=otlp OTEL_EXPORTER_OTLP_PROTOCOL=http/json OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 claude -p hi
   ```

   The pane shows a batch and, with a pattern that matches the prompt, a red flag and a
   notification whose click opens the pane. Quit the app: `pgrep cainary-otel-debug` finds nothing.
   Then `kill -9` the app while it listens: the helper is gone within a few seconds.
7. **Failure:** `CAINARY_CORE=/nonexistent dist/cAInary.app/Contents/MacOS/cAInary` shows a grey
   `?` and "Couldn't scan".

## 6. Not planned

- FSEvents, a daemon or launchd agent, and the Linux UI.
- An alert-mode picker or a separate "Can't be seen locally" tab. Entry notes cover what
  can't be seen.
- Opening the popover programmatically. Notification clicks go to Details.
- App icon artwork and auto-update. Developer ID signing and notarization are not planned (see
  [distribution.md](distribution.md#signing)).
- XCTest, Swift Testing and SwiftPM, which are unavailable or blocked in the sandbox.
- Per-finding mute, change history beyond one baseline, Markdown copy and localization.
- Recomputing levels, summaries or diffs in Swift.
