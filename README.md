# cAInary

cAInary shows what your AI tools and the device monitoring around them track and send, and where it goes. It covers Claude (Code and Desktop), ChatGPT & Codex, Cursor and GitHub Copilot. The core is written in Rust and runs on macOS and Linux. It only reads files and never uses the network.

## Install

The macOS app needs macOS 14 (Sonoma) or newer. Builds are universal, so they run on both Apple
silicon and Intel Macs. The app bundles the `cainary` CLI.

1. Download the `.zip` from the
   [latest release](https://github.com/SkeLLLa/cainary/releases/latest).
2. Unzip it and move `cAInary.app` to your Applications folder.
3. If macOS says the app can't be opened, run this once in Terminal:

   ```sh
   xattr -dr com.apple.quarantine /Applications/cAInary.app
   ```

   This is needed because releases aren't notarized by Apple yet.
4. To use the CLI from a shell, link it onto your `PATH`:

   ```sh
   ln -s /Applications/cAInary.app/Contents/Helpers/cainary ~/.local/bin/cainary
   ```

<details>
<summary>Other ways to install</summary>

These install the `cainary` CLI on your `PATH`. They don't start the menu-bar app; for that,
use the release download above.

With [mise](https://mise.jdx.dev) (2026.9.2 or newer):

```sh
mise use -g packslip:github.com/SkeLLLa/cainary
```

With [cargo](https://doc.rust-lang.org/cargo/) (Rust 1.99 or newer; builds the CLI, macOS or Linux):

```sh
cargo install cainary --locked
```

With [packslip](https://packslip.dev) (1.5.1 or newer), which checks the release signature
before installing:

```sh
packslip install github.com/SkeLLLa/cainary
```

From source, with [mise](https://mise.jdx.dev) and the Xcode Command Line Tools:

```sh
mise run bundle-universal
rm -rf /Applications/cAInary.app   # quit cAInary first when upgrading
cp -R dist/cAInary.app /Applications/
```

Homebrew isn't available yet. See [Distribution](docs/distribution.md) for the release files and
how to verify them.

</details>

## Install on Linux

The tray app (Qt 6.5 or newer) shows the same status icon, popup and Details window as the macOS
app. It runs on Debian 13+, Ubuntu 25.04+ (including 26.04 LTS), Fedora 44+, Arch and openSUSE
Tumbleweed. **Ubuntu 24.04 isn't supported** for the app, because its Qt is too old; the CLI works
there. Download the file for your distribution and architecture from the
[latest release](https://github.com/SkeLLLa/cainary/releases/latest):

```sh
sudo apt install ./cainary_<version>_amd64.deb          # Debian, Ubuntu (arm64 for ARM)
sudo dnf install ./cainary-<version>-1.x86_64.rpm       # Fedora (aarch64 for ARM)
yay -S cainary-bin                                      # Arch (AUR)
```

Or, on any distribution, unpack `cainary-<version>-linux-<x86_64|aarch64>.tar.gz` and run
`./install-user.sh`. It installs for your user only, into `~/.local`, and
`./install-user.sh --uninstall` removes it.

Start **cAInary** from the application menu, or run `cainary-tray`. GNOME needs the
AppIndicator extension (`gnome-shell-extension-appindicator`) to show
the tray icon; without it the Details window opens instead. "Launch at login" is off until you
turn it on in Settings. The `cainary` CLI is installed alongside. See [docs/linux.md](docs/linux.md)
for supported distributions, popup placement, building from source and troubleshooting.

## Build

You need Rust 1.99 or newer. `mise` installs the pinned toolchain.

```sh
mise trust && mise install   # one time
make build                   # → target/debug/cainary
```

Inside a mise environment (`mise run <task>`, or a shell with mise activated), `mise.toml` sets
`CARGO_BIN=mbx`, so cargo runs through [mr-boxington](https://github.com/jdx/mr-boxington), a
shared build cache. It also sets `SWIFTC` to mise's Swift toolchain. Plain `make` without mise
(as in CI) uses `cargo` and `swiftc` from PATH. The macOS SDK path, `codesign`, `lipo`, `plutil` and
`ditto` still come from the system, because mise has no equivalent. The Linux tasks (`mise tasks`,
`linux:*`; see [docs/linux.md](docs/linux.md) §8) build, test and package the tray, also in a
distro container.

For an optimized binary, run `cargo build --release -p cainary`. It writes `target/release/cainary`.

## Run

```sh
./target/debug/cainary scan              # full report for this machine
./target/debug/cainary scan --summary    # one line per app or monitor
./target/debug/cainary scan --json       # machine-readable report (used by the UI)
./target/debug/cainary status            # one-line status (--format text|emoji|nerd|json)
./target/debug/cainary sources           # every path read, and whether it was present
./target/debug/cainary --help
```

`make scan` builds the CLI and runs `cainary scan` in one step.

### Options

| Option | Effect |
| --- | --- |
| `--tool <slug>` | Scan only this app. Repeat it to scan several. The slugs are `claude`, `openai`, `cursor`, `copilot` and `device`, or a single surface such as `claude-code`, `claude-desktop`, `codex` or `chatgpt`. |
| `--alert org\|org-unknown\|everything` | Which findings count toward the `status` badge. |
| `--fixture <dir>` | Scan a recorded fixture instead of this machine, e.g. `crates/cainary-core/tests/fixtures/claude-code-org-macos`. |
| `--root <dir> --home <dir> [--os macos\|linux]` | Scan a copied filesystem tree. |
| `--env-kind launchd\|shell` | Treat the environment as launchd's or as a login shell's (default). Both apps pass `launchd`. |
| `--no-color` | Plain output. `NO_COLOR` also turns colour off. |

**Exit codes:**

| Code | Meaning |
| --- | --- |
| `0` | The scan ran. |
| `1` | The fixture or root wasn't found. |
| `2` | Bad usage. |
| `3` | Internal error. |

## Reading the report

Every app and every monitor gets one level:

| Level | Meaning |
| --- | --- |
| `HIGH` (red) | Conversations are sent: prompts, responses or transcripts. |
| `MEDIUM` (orange) | Activity is sent: commands, tool calls, file contents, traffic or device access. |
| `LOW` (yellow) | Usage data, metrics or the vendor's default telemetry is sent. |
| `OPTED OUT` (blue) | A setting turns off the vendor's standard telemetry, and nothing else is sent. |
| `OK` (green) | Nothing tracked or sent that cAInary can see. |
| `NOT INSTALLED` | The app isn't on this machine. |

Under each app or monitor, the report lists each thing it tracks. For each one it shows:
- what is sent;
- who set it up: your organization, you, or the vendor default;
- the config file and the exact keys;
- a link to the vendor docs.

`(may)` marks a finding that rests on vendor behaviour cAInary can't confirm locally.

## Change alerts

Save a baseline, then compare a later scan with it:

```sh
cainary scan --json > baseline.json
cainary scan --since baseline.json          # adds a "Changes since …" block
cainary scan --summary --since baseline.json
cainary scan --json | cainary scan --since -   # `-` reads the baseline from stdin
```

`--since` lists what was added, removed, raised or lowered since the baseline. A baseline that is
missing, over 1 MiB or from another schema is reported in one line and the scan still exits 0.

## Test

```sh
make check-rust                               # fmt, clippy -D warnings, all tests
CAINARY_GOLDEN=codex make test                # only the codex-* golden fixtures
CAINARY_GOLDEN=codex CAINARY_BLESS=1 make test  # re-record them after an intended change
```


## macOS app

A menu-bar app (macOS 14+, SwiftUI) that runs the bundled `cainary` helper and shows the result.

```sh
mise run app                # → dist/cAInary.app (+ a zip); debug helper (= make bundle)
mise run app:open           # build and launch it
mise run bundle-universal   # universal arm64 + x86_64 release app (= make bundle RELEASE=1)
```

The bundle is signed ad hoc. To install it, see [Install](#install).

**What it shows:** a menu-bar icon with the worst level, a popover with one row per app or monitor
and a Changes section, and a Details window with every finding, its source and its vendor docs.

**Change notifications:** the app keeps a baseline and notifies you when a later scan adds or
raises a finding. "Mark as seen" in the popover resets the baseline. A notification click opens
Details.

**Preferences** live in the `ua.SkeLLLa.cAInary` defaults domain. The app writes nothing else
except the login item.

```sh
defaults read ua.SkeLLLa.cAInary     # show them
defaults delete ua.SkeLLLa.cAInary   # reset (including the baseline)
```

**Tests:** `make ui-test` decodes the Rust goldens through the Swift model, runs the unit checks
and renders snapshots to `target/ui-snapshots/`. The manual checklist for what a test can't cover
is in [docs/macos.md](docs/macos.md) §5d. The design is in the same file; packaging is in §4.

For starship, tmux and the Claude Code statusline, see [docs/integrations.md](docs/integrations.md).

See [docs/architecture.md](docs/architecture.md) for the design, the report format and change detection, [docs/rules.md](docs/rules.md) for what each scanner detects, and [docs/distribution.md](docs/distribution.md) for release files and install methods.

## Support Ukraine

If cAInary is useful to you and you want to say thanks, please consider supporting Ukrainian
defenders instead of sending money to the author.

[![Come Back Alive](resources/badges/donate-come-back-alive.svg)](https://savelife.in.ua/en/donate-en/)
[![Sternenko Fund](resources/badges/donate-sternenko-fund.svg)](https://www.sternenkofund.org/en/donate)
[![Prytula Foundation](resources/badges/donate-prytula-foundation.svg)](https://prytulafoundation.org/en/donation)

## License

GPL-3.0-or-later. See [COPYING](COPYING).
