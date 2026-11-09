# Roadmap

What cAInary 1.0 contains, and the work planned after it. The order below is the intended order,
not a schedule: there are no dates, and plans can change. The design of what exists is in
[architecture.md](architecture.md).

## 1.0

- **The scan.** `cainary` reads the configuration of Claude Code, Claude Desktop, Codex, ChatGPT,
  Cursor and GitHub Copilot, plus device monitoring around them (MDM, privacy grants, system
  extensions, proxies, package-registry proxies), and reports what is tracked or sent, who set it
  up and where it goes, with a link to the vendor docs ([rules.md](rules.md)). It only reads
  files and never uses the network.
- **The CLI.** `scan` (text, `--summary`, JSON), `status` for prompts and status bars,
  `sources`, `explain`, and change alerts against a saved baseline (`--since`)
  ([integrations.md](integrations.md)).
- **OTel payload preview.** For Claude Code and Codex OpenTelemetry exports, what each export
  carries: the flags in effect, the identity on every record, and each event, metric or span.
- **The apps.** A menu-bar app on macOS ([macos.md](macos.md)) and a Qt 6 tray app on Linux
  ([linux.md](linux.md)): a status icon, a popup, a Details window and change notifications.
- **OTel debug collector.** `cainary-otel-debug`, a separate, opt-in receiver on loopback that
  shows what an AI tool's telemetry really contains (OTLP over HTTP, JSON or protobuf, gzip or
  not), with masked values and red-flag alerts. On Linux it accepts only your own user's programs.
  The HTTPS takeover catches an export your organization pins to an HTTPS host, and `--trust`
  lets Claude Code and Codex trust its certificate.
- **Linux tray extras.** A collector page (feed, red flags, setup, logs), a step-by-step takeover
  guide, and two small root helpers, run through `pkexec` on a click, to add the host names to
  `/etc/hosts` and to open a port below 1024, such as 443.
- **Packages.** A signed macOS app, Linux tarballs, .deb and .rpm, signed APT and DNF
  repositories, the CLI on crates.io and through mise or packslip
  ([distribution.md](distribution.md)).

## macOS: remaining gaps with the Linux tray

The collector window (Feed, Red flags, Rules, Logs, Setup), the sidebar Live row, the popover
collector line, the step-by-step takeover guide with its `pf` redirect and DNS flush, and one-click
`/etc/hosts` and redirect editing are done ([macos.md](macos.md) §2.8). Still open:

- **Menu bar icon.** The red-flag count on the icon, and the third icon style.
- **Own-user check** (optional). Refuse telemetry from other local users, as on Linux.
- **A redirect that survives a reboot.** Today the `pf` redirect lasts until restart.

## Findings cAInary set up itself

Some findings exist because of cAInary: "Let Claude Code trust…" adds a certificate setting that
the scan then reports. The apps will mark such a finding "Set up by cAInary" and offer **Mark as
known**, after checking that the setting still points at cAInary's own certificate. A finding
whose telemetry the collector is catching gets an "Intercepted by cAInary" badge and **Treat as
intercepted**. Both are re-checked on every scan and drop back to the real level, with a
notification, when the evidence no longer holds. The CLI report and Copy report never change.

## Red-flag alert triage

- **Alert severity.** Critical, warning or info per pattern; only warning and above notify.
- **Known alerts.** Mark an alert as known, or change how it notifies, for this value here, this
  value anywhere, this location, or the whole pattern. Rules are stored as keyed signatures, with
  the key in the system keyring, so the rules file holds no values. A "Known alerts" list shows
  them, with optional expiry.

## OTel message fingerprints

Learn what each app normally sends: after you accept a baseline, get one notification when an app
starts sending a new kind of event, span or attribute, for example after an upgrade. Fingerprints
only cover structure, never values, and never hide red flags or findings.

## Telemetry proxy, then the traffic watchdog

- **Telemetry proxy (log and forward).** An opt-in, loopback-only proxy, `cainary-proxy`, for one
  process you start with `HTTPS_PROXY`. It decrypts only the telemetry hosts, shows the export like
  the collector does, and forwards it unchanged, so your organization still receives it. Other
  traffic is tunnelled untouched. No root and no `/etc/hosts` change.
- **Traffic watchdog.** Later, the same proxy for all HTTPS of a chosen process: masked
  `flow` and `leak` events when your identity or a secret goes to a third party, and then an
  opt-in mode that blocks those requests.

## Smaller follow-ups

- **Batch details.** Show a batch's format (protobuf), compression and takeover host name in both
  apps.
- **Tray activity log.** A wider Logs view in the Linux tray with the scan, collector and helper
  activity.
- **Details window size.** Remember it in the Linux tray.
- **Real desktops.** Check the Linux popup placement on Plasma Wayland, X11 and GNOME, and whether
  the macOS firewall asks about the collector.
- **More install options.** A Homebrew cask and a mise registry entry.
