# cAInary

<p align="center">
  <img src="linux/data/icons/hicolor/scalable/apps/ua.SkeLLLa.cAInary.svg" alt="cAInary icon" width="128" height="128">
</p>

cAInary shows what your AI tools and the device monitoring around them track and send, and where it goes. It covers Claude (Code and Desktop), ChatGPT & Codex, Cursor and GitHub Copilot. The core is written in Rust and runs on macOS and Linux. It only reads files and never uses the network.

It comes in two parts:

- **The app:** a menu-bar app on macOS and a tray app on Linux. It shows a status icon with the
  worst level, a popup with one row per app, and a Details window with every finding.
- **The `cainary` CLI:** the same scan in a terminal, as text or JSON. Every app install includes
  it, and you can also install it on its own.

**Contents:** [Install](#install) · [Usage](#usage) · [Reading the report](#reading-the-report) ·
[The apps](#the-apps) · [Development](#development) · [Documentation](#documentation) ·
[Support Ukraine](#support-ukraine)

## Install

| You want | macOS | Linux |
| --- | --- | --- |
| The app and the CLI | [Release download](#macos-app) | [APT](#debian-and-ubuntu-apt-repository) or [DNF](#fedora-dnf-repository) repository, [package file](#a-single-deb-or-rpm-file), [tarball](#any-distribution-tarball) |
| Only the CLI | [mise, packslip or cargo](#macos-cli-only) | [mise, packslip or cargo](#linux-cli-only) |
| A build from source | [From source](#macos-from-source) | [docs/linux.md §8](docs/linux.md#8-build-run-and-test) |

All downloads are on the [latest release](https://github.com/SkeLLLa/cainary/releases/latest)
page. Homebrew isn't available yet.

### macOS

You need macOS 14 (Sonoma) or newer. Builds are universal, so they run on both Apple silicon and
Intel Macs.

#### macOS: app

The app includes the `cainary` CLI.

1. Download `cainary-<version>-macos-universal.zip` from the
   [latest release](https://github.com/SkeLLLa/cainary/releases/latest).
2. Unzip it and move `cAInary.app` to your Applications folder.
3. If macOS says the app can't be opened, run this once in Terminal:

   ```sh
   xattr -dr com.apple.quarantine /Applications/cAInary.app
   ```

   You need this because the releases aren't notarized by Apple. They are signed with
   cAInary's own certificate, so macOS keeps the app's permissions across updates
   ([details](docs/distribution.md#signing)).
4. Optional: to use the CLI from a shell, link it onto your `PATH`:

   ```sh
   mkdir -p ~/.local/bin
   ln -s /Applications/cAInary.app/Contents/Helpers/cainary ~/.local/bin/cainary
   ```

To upgrade, quit cAInary, then replace `cAInary.app` with the new download.

#### macOS: CLI only

These put `cainary` on your `PATH`. They don't install the menu-bar app. Pick one:

```sh
# mise (2026.9.2 or newer). Checks the release signature before it installs.
mise use -g packslip:github.com/SkeLLLa/cainary

# packslip (1.5.1 or newer). Checks the release signature before it installs.
packslip install github.com/SkeLLLa/cainary

# cargo (Rust 1.99 or newer). Builds the CLI from crates.io.
cargo install cainary --locked
```

#### macOS: from source

You need [mise](https://mise.jdx.dev) and the Xcode Command Line Tools:

```sh
mise trust && mise install
mise run bundle-universal
rm -rf /Applications/cAInary.app   # quit cAInary first when upgrading
cp -R dist/cAInary.app /Applications/
```

### Linux

The tray app needs Qt 6.5 or newer. Packages exist for x86_64 and ARM (aarch64).

| Distribution | How to install |
| --- | --- |
| Debian 13 (trixie) and newer | [APT repository](#debian-and-ubuntu-apt-repository), [.deb](#a-single-deb-or-rpm-file), [tarball](#any-distribution-tarball) |
| Ubuntu 25.04 and newer, including 26.04 LTS | [APT repository](#debian-and-ubuntu-apt-repository), [.deb](#a-single-deb-or-rpm-file), [tarball](#any-distribution-tarball) |
| Fedora 44 and newer | [DNF repository](#fedora-dnf-repository), [.rpm](#a-single-deb-or-rpm-file), [tarball](#any-distribution-tarball) |
| Arch Linux | [tarball](#any-distribution-tarball). The AUR package `cainary-bin` isn't published yet. |
| openSUSE Tumbleweed | [tarball](#any-distribution-tarball) |
| **Ubuntu 24.04 LTS** | **CLI only.** Its Qt is too old for the app. [Install the CLI](#linux-cli-only). |

#### Debian and Ubuntu: APT repository

This is the recommended method: `apt upgrade` then keeps cAInary up to date. APT selects amd64
or arm64 for you.

```sh
echo 'deb [trusted=yes] https://skellla.github.io/cainary/deb stable main' | sudo tee /etc/apt/sources.list.d/cainary.list
sudo apt update
sudo apt install cainary
```

#### Fedora: DNF repository

This is the recommended method: `dnf upgrade` then keeps cAInary up to date. DNF selects x86_64
or aarch64 for you.

```sh
sudo curl -fsSLo /etc/yum.repos.d/cainary.repo https://skellla.github.io/cainary/rpm/cainary.repo
sudo dnf install cainary
```

The repositories are unsigned (`trusted=yes`, `repo_gpgcheck=0`), so their integrity depends on
HTTPS to GitHub Pages. They keep the 10 most recent releases, so you can also pin or downgrade a
version. To check the files against the release checksums and attestations instead, see
[Verifying a download](docs/distribution.md#verifying-a-download).

#### A single .deb or .rpm file

You get no automatic updates with this method. Download the file for your system from the
[latest release](https://github.com/SkeLLLa/cainary/releases/latest), then run:

```sh
sudo apt install ./cainary_<version>_amd64.deb      # Debian, Ubuntu (arm64 on ARM)
sudo dnf install ./cainary-<version>-1.x86_64.rpm   # Fedora (aarch64 on ARM)
```

#### Any distribution: tarball

This method installs for your user only, into `~/.local`, and doesn't need root:

```sh
tar -xzf cainary-<version>-linux-x86_64.tar.gz      # aarch64 on ARM
cd cainary-<version>-linux-x86_64
./install-user.sh
```

Add `~/.local/bin` to your `PATH` to run the CLI from a shell. You need the distribution's Qt 6
packages installed. For the list, see [docs/linux.md §5](docs/linux.md#5-supported-distributions).

#### Linux: CLI only

These put `cainary` on your `PATH` and run on any distribution, including Ubuntu 24.04. The CLI
is a static binary. Pick one:

```sh
# mise (2026.9.2 or newer). Checks the release signature before it installs.
mise use -g packslip:github.com/SkeLLLa/cainary

# packslip (1.5.1 or newer). Checks the release signature before it installs.
packslip install github.com/SkeLLLa/cainary

# cargo (Rust 1.99 or newer). Builds the CLI from crates.io.
cargo install cainary --locked
```

#### After installing on Linux

- Start **cAInary** from the application menu, or run `cainary-tray`.
- **GNOME** needs the AppIndicator extension (`gnome-shell-extension-appindicator`) to show the
  tray icon. Without it, cAInary opens the Details window instead.
- "Launch at login" is off by default. You can turn it on in Settings.

For popup placement, building from source and troubleshooting, see [docs/linux.md](docs/linux.md).

### Uninstall

| Installed with | Remove with |
| --- | --- |
| macOS app | Quit cAInary, delete `/Applications/cAInary.app`, then optionally run `defaults delete ua.SkeLLLa.cAInary` |
| APT | `sudo apt remove cainary`, then `sudo rm /etc/apt/sources.list.d/cainary.list` |
| DNF | `sudo dnf remove cainary`, then `sudo rm /etc/yum.repos.d/cainary.repo` |
| Tarball | `./install-user.sh --uninstall` from the unpacked directory |
| mise | `mise unuse -g packslip:github.com/SkeLLLa/cainary` |
| cargo | `cargo uninstall cainary` |

## Usage

```sh
cainary scan              # full report for this machine
cainary scan --summary    # one line per app or monitor
cainary scan --json       # machine-readable report (used by the apps)
cainary status            # one-line status (--format text|emoji|nerd|json)
cainary sources           # every path read, and whether it was present
cainary --help
```

### Options

| Option | Effect |
| --- | --- |
| `--tool <slug>` | Scan only this app. Repeat it to scan several. The slugs are `claude`, `openai`, `cursor`, `copilot` and `device`, or a single surface such as `claude-code`, `claude-desktop`, `codex` or `chatgpt`. |
| `--alert org\|org-unknown\|everything` | Which findings count toward the `status` badge. |
| `--since <file>` | Compare with a saved scan. See [Change alerts](#change-alerts). |
| `--fixture <dir>` | Scan a recorded fixture instead of this machine, e.g. `crates/cainary-core/tests/fixtures/claude-code-org-macos`. |
| `--root <dir> --home <dir> [--os macos\|linux]` | Scan a copied filesystem tree. |
| `--env-kind launchd\|shell` | Treat the environment as launchd's or as a login shell's (default). Both apps pass `launchd`. |
| `--no-color` | Plain output. `NO_COLOR` also turns colour off. |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The scan ran. |
| `1` | The fixture or root wasn't found. |
| `2` | Bad usage. |
| `3` | Internal error. |

### Change alerts

Save a baseline, then compare a later scan with it:

```sh
cainary scan --json > baseline.json
cainary scan --since baseline.json          # adds a "Changes since …" block
cainary scan --summary --since baseline.json
cainary scan --json | cainary scan --since -   # `-` reads the baseline from stdin
```

`--since` lists what was added, removed, raised or lowered since the baseline. If the baseline is
missing, over 1 MiB or from another schema, the scan says so in one line and still exits 0.

### Shell and editor integrations

For starship, tmux and the Claude Code statusline, see [docs/integrations.md](docs/integrations.md).

## Reading the report

Each app and each monitor gets one level:

| Level | Meaning |
| --- | --- |
| `HIGH` (red) | Conversations are sent: prompts, responses or transcripts. |
| `MEDIUM` (orange) | Activity is sent: commands, tool calls, file contents, traffic or device access. |
| `LOW` (yellow) | Usage data, metrics or the vendor's default telemetry is sent. |
| `OPTED OUT` (blue) | A setting turns off the vendor's standard telemetry, and nothing else is sent. |
| `OK` (green) | cAInary can't see anything that is tracked or sent. |
| `NOT INSTALLED` | The app isn't on this machine. |

Under each app or monitor, the report lists everything it tracks. For each item it shows:

- what is sent;
- who set it up: your organization, you, or the vendor default;
- the config file and the exact keys;
- a link to the vendor docs.

`(may)` marks a finding that depends on vendor behaviour cAInary can't confirm locally.

For what each scanner detects, see [docs/rules.md](docs/rules.md).

## The apps

Both apps run the bundled `cainary` CLI and show its result. They don't scan anything themselves.

**What they show:** a status icon with the worst level, a popup with one row per app or monitor
and a Changes section, and a Details window with every finding, its source and its vendor docs.

**Change notifications:** the app keeps a baseline and notifies you when a later scan adds or
raises a finding. "Mark as seen" resets the baseline. It is in the popup on
macOS and in the Details window on Linux. Clicking a notification opens Details.

### macOS menu-bar app

The app stores its preferences in the `ua.SkeLLLa.cAInary` defaults domain. Apart from those and
the login item, it writes nothing.

```sh
defaults read ua.SkeLLLa.cAInary     # show them
defaults delete ua.SkeLLLa.cAInary   # reset (including the baseline)
```

For the design and the manual test checklist, see [docs/macos.md](docs/macos.md).

### Linux tray app

The tray app is a Qt 6 / QML app. It shows its icon in any StatusNotifier tray, such as KDE
Plasma's, or GNOME's with the AppIndicator extension. Its settings are in
`~/.config/cainary/tray.toml`. For details, see [docs/linux.md](docs/linux.md).

## Development

### Build

You need Rust 1.99 or newer. `mise` installs the pinned toolchain.

```sh
mise trust && mise install   # one time
make build                   # → target/debug/cainary
make scan                    # build the CLI and run `cainary scan`
```

For an optimized binary, run `cargo build --release -p cainary`. It writes `target/release/cainary`.

Inside a mise environment (`mise run <task>`, or a shell with mise activated), `mise.toml` sets
`CARGO_BIN=mbx`, so cargo runs through [mr-boxington](https://github.com/jdx/mr-boxington), a
shared build cache. It also sets `SWIFTC` to mise's Swift toolchain. Plain `make` without mise
(as in CI) uses `cargo` and `swiftc` from PATH. The macOS SDK path, `codesign`, `lipo`, `plutil` and
`ditto` still come from the system, because mise has no equivalent.

### macOS app

```sh
mise run app                # → dist/cAInary.app (+ a zip); debug helper (= make bundle)
mise run app:open           # build and launch it
mise run bundle-universal   # universal arm64 + x86_64 release app (= make bundle RELEASE=1)
```

The bundle is signed ad hoc unless `CODESIGN_IDENTITY` names a certificate
([docs/distribution.md#signing](docs/distribution.md#signing)). To install it, see
[macOS: from source](#macos-from-source).

### Linux tray app

The `linux:*` mise tasks (`mise tasks`) build, test and package the tray, also inside a distro
container. See [docs/linux.md §8](docs/linux.md#8-build-run-and-test).

### Test

```sh
make check-rust                                 # fmt, clippy -D warnings, all tests
CAINARY_GOLDEN=codex make test                  # only the codex-* golden fixtures
CAINARY_GOLDEN=codex CAINARY_BLESS=1 make test  # re-record them after an intended change
make ui-test                                    # macOS app: Swift model, unit checks, snapshots
```

`make ui-test` decodes the Rust goldens through the Swift model, runs the unit checks and renders
snapshots to `target/ui-snapshots/`. The manual checklist for what a test can't cover is in
[docs/macos.md](docs/macos.md) §5d.

## Documentation

- [Architecture](docs/architecture.md): the design, the report format and change detection
- [Rules](docs/rules.md): what each scanner detects
- [macOS app](docs/macos.md): design, packaging and manual checks
- [Linux tray app](docs/linux.md): supported distributions, placement, build and troubleshooting
- [Distribution](docs/distribution.md): release files, package repositories and how to verify them
- [Integrations](docs/integrations.md): starship, tmux and the Claude Code statusline

## Support Ukraine

If cAInary is useful to you and you want to say thanks, please consider supporting Ukrainian
defenders instead of sending money to the author.

[![Come Back Alive](resources/badges/donate-come-back-alive.svg)](https://savelife.in.ua/en/donate-en/)
[![Sternenko Fund](resources/badges/donate-sternenko-fund.svg)](https://www.sternenkofund.org/en/donate)
[![Prytula Foundation](resources/badges/donate-prytula-foundation.svg)](https://prytulafoundation.org/en/donation)

## License

GPL-3.0-or-later. See [COPYING](COPYING).
