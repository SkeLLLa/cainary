# Linux tray app

The Linux tray app for cAInary, `cainary-tray`: a Qt 6 / QML status icon, popup and Details window.
Like the macOS app it runs the `cainary` CLI and draws its JSON: the report model is in
architecture.md §3, change detection in §4, and the subprocess contract in §9.1–§9.2.

**Ground rules.** The tray holds no scanning logic. It never computes a level, a summary or a diff.
It reads no credential files and opens no sockets of its own. It writes only its settings, its
baseline and the autostart entry (§3).
`linux/crates/cainary-tray/tests/guards.rs` enforces these rules and the dependency policy
(architecture.md §2).

## 1. Architecture

The app is its own Cargo workspace, `linux/`. The root workspace lists `linux` in `exclude`, so Qt,
ksni and zbus never enter the root `Cargo.lock` or the core's dependency guard.

```
linux/
  Cargo.toml  Cargo.lock       own workspace, same version as the root (guard L4)
  data/                        desktop entry, autostart template, AppStream, icons
  crates/
    tray-model/                pure Rust, no Qt, no D-Bus: report model, bounded runner, CLI lookup,
                               store, change tracker, notification plan, settings, autostart,
                               baseline, refresh schedule
    tray-dbus/                 zbus + ksni, no Qt: tray icon, notifications, single instance,
                               logind, file manager, StatusNotifierWatcher
    cainary-tray/              binary `cainary-tray`: cxx-qt bridge, QML, placement, ~360 lines of C++
                               (cpp/: icons, layer-shell, Qt shims)
```

**Toolkit.** Qt 6 through cxx-qt 0.10, QtQuick and QtQuick.Controls only (no Kirigami, no KF6).
GTK-based tray crates (`tray-icon`, `muda`, `libappindicator`, `rfd`) are banned. Everything else
is pure Rust on zbus 5 with the `async-io` executor and no tokio.

**Data flow.**

```
refresh trigger ─► Store.request() ─► runner worker thread ─► Outcome
                                                                 │
tray-dbus thread  ◄── TrayUpdate ── controller (Qt main thread) ◄┘
 (ksni, notifications,                    │
  instance, logind,                       ├─► QML models: popup, Details, Settings
  watcher)                               └─► change tracker ─► notifications
        │
        └── UiEvent ─► controller   (popup toggle, Activate(x, y), notification click, resume, …)
```

The Qt main thread owns every `QObject`. `tray-dbus` runs one `async_io::block_on` thread and talks
to the controller only through two channels, `UiEvent` and `TrayUpdate`. The threading model and
the shutdown order are in architecture.md §9.2.

**Running the CLI.** The runner starts `cainary scan --json --env-kind launchd` and parses schema 3, as the macOS
app does. When a baseline exists it adds `--since -` and sends the baseline on stdin, so the report carries the changes since it.

- The CLI is looked up in this order, and never through `PATH`: `CAINARY_CORE` (debug builds, or a
  release build started with `--dev`), then `cainary` next to the tray executable, then
  `/usr/bin/cainary`. `CAINARY_SCAN_ARGS` is honoured in debug builds only.
- The scan has a 20 s deadline, stdout is capped at 8 MiB and stderr keeps its last 64 KiB. stdin
  is `/dev/null`. The child runs in its own process group: on the deadline it gets SIGTERM, then
  SIGKILL after 2 s. The runner does not wait for pipe EOF once the child exits, so a descendant
  that holds the pipes open can't block it.
- A schema major other than 3 is refused with "Update cAInary". Unknown enum values show as a grey
  `?`. The error states are: CLI missing, unsupported schema, timeout, failure (with the stderr
  tail) and stale data. A failed scan keeps the last good snapshot and marks it stale.

**Refresh and notifications.** A scan runs at startup, on a timer (every 5, 10 or 30 minutes,
every hour, or daily; the default is every 10 minutes), on "Refresh now", on resume from suspend (logind
`PrepareForSleep`), on a second instance's `Refresh()` call and when settings change. Requests that
arrive during a scan are coalesced into one follow-up. A change must persist for 30 s before it
counts. Each confirmed change is one `org.freedesktop.Notifications` notification (hint
`desktop-entry=ua.SkeLLLa.cAInary`); clicking it opens Details at that entry.

**Tray.** A StatusNotifierItem through ksni, id `ua.SkeLLLa.cAInary`. The status is always `Active`:
Plasma animates `NeedsAttention`, and the icon already shows the level. The icon is the macOS one, the
app's robo-canary with a badge in its top-left corner: dimmed when no tool is installed, a count of tools to review (1–9) for
low/medium/high, and `?` when the scan failed or can't be trusted. The app draws it at run time into
`$XDG_RUNTIME_DIR/cainary/icons` (the icon theme path handed to the host), one SVG per picture, with
a Qt-rendered pixmap of the same SVG as a fallback. The "Tray icon" setting picks the style:
"Monochrome, colored badge" (the default: the app icon's symbolic silhouette follows the panel's
text color, the count badge is yellow, orange or red), "Monochrome" (everything follows the panel)
or "Color" (the colored app icon once a scan has a level; before that, the silhouette). Panel-colored icons are named `…-symbolic` and use `ColorScheme-Text`, so
Plasma and GTK-based hosts recolor them. The menu lists one disabled row per tool with its level, then
Refresh now, Open details…, Settings… and Quit. Primary activation toggles the popup at the click
point; secondary activation refreshes.

**Single instance.** The app owns the session bus name `ua.SkeLLLa.cAInary` and serves
`/ua/SkeLLLa/cAInary` (interface `ua.SkeLLLa.cAInary1`: `Activate()`, `ShowDetails(s)`,
`Refresh()`, `Quit()`). A second launch calls the running instance and exits 0.

**Environment variables.** `CAINARY_CORE` and `CAINARY_SCAN_ARGS` (extra `scan` arguments,
split on spaces) apply to debug builds, or to a release build started with `--dev`.
`CAINARY_ICON_THEME_PATH` sets where the app icon is looked up first; by default it is
`../share/icons` next to the executable for a private prefix such as the tarball's, and the system
theme under `/usr`. `QT_QPA_PLATFORMTHEME` and `QT_QUICK_CONTROLS_STYLE` are set only when
unset (§6).

**Command line.**

| Flag | Effect |
| --- | --- |
| `--version` | Print `cainary-tray <version>`. |
| `--background` | Start with the tray icon only, whatever "Start minimized to the tray" says. |
| `--autostart` | What the autostart entry runs: "Start minimized to the tray" decides, and a running instance is left alone. |
| `--details [entry]` | Open Details, at an entry if given. |
| `--self-test` | Force the offscreen platform, load the QML, render the popup, Details and Settings windows to PNG files with sample data, and exit 0. Any Qt warning or error message fails it, and a 60 s deadline stops a hang. |
| `--dev` | Enable the developer overrides in a release build. |
| `--verbose` | Print the diagnostics block to stderr at startup, then one line per scan start and finish, per UI event and per placement decision. |

**UI.** The popup is 360 px wide and up to 520 px tall: a header with the overall level and last
check time, one row per tool, and Refresh, Details… and Settings. It closes on Esc or when it loses
focus. Details is a normal window (780×560, minimum 640×420) with the tools and entries on the left
and the selected entry's explanation and evidence on the right; paths can be revealed in the file
manager (`FileManager1.ShowItems`), URLs opened in the browser, and the entry's JSON copied. The
window size is remembered, the position isn't (Wayland can't set it). Settings is a page in the
same window. `QT_QUICK_CONTROLS_STYLE` is chosen only when unset: `org.kde.desktop` if importable,
else `Fusion`.

## 2. Popup placement

A tray click delivers `Activate(x, y)`. Where the popup goes depends on the session. The strategy
is decided once at startup (`--verbose` prints it; `CAINARY_PLACEMENT=layer-shell|x11|decorated`
forces one under `--dev`).

| Strategy | Chosen when | Result |
| --- | --- | --- |
| `layer-shell` | A Wayland session whose compositor offers `zwlr_layer_shell_v1` (KDE Plasma 6, sway, Hyprland, COSMIC, labwc), and the build has the `layer-shell` feature | A layer-shell surface on the screen containing (x, y), anchored to the nearest edges and centred on the icon. |
| `x11` | X11, XWayland, or any platform that is not Wayland | A frameless, always-on-top `Qt.Tool` window positioned at (x, y), clamped to the screen's available area. |
| `decorated` | A Wayland session without layer-shell (GNOME: Mutter has no layer-shell) or a build without the feature | An ordinary window titled "cAInary" that the compositor places and the user can move. |

**Layer-shell.** One Wayland registry roundtrip checks for the protocol, and LayerShellQt is
attached only when it is present. The popup uses the Top layer, on-demand keyboard focus and an
exclusive zone of 0, so panels keep their space. Margins equal the distance from the nearest
edges to the click point and keep the popup at least 8 px inside the available area. The target
screen is set on the window before LayerShellQt is attached, because LayerShellQt before 6.6 has
no `setScreen` and derives the screen from the window. If the click point is (0, 0) or missing, the
popup anchors to the top-right corner. LayerShellQt ships a CMake config and no `.pc` file, so
`build.rs` finds `LayerShellQt/window.h` itself (`LAYERSHELLQT_INCLUDE_DIR` and
`LAYERSHELLQT_LIB_DIR` override the search) and links `LayerShellQtInterface`.

**The `layer-shell` feature** of `cainary-tray` is on by default and needs LayerShellQt 6.0 or
newer and its development files. `cargo build --no-default-features` (or `--no-default-features`
on any `make linux-*` cargo line) leaves out the C++ and the link dependency; the tray then uses
`x11` or `decorated` only. The packages are built with the feature and depend on LayerShellQt, so
one build serves KDE, wlroots and GNOME.

**GNOME.** The decorated window is deliberate: with no layer-shell and no client-side
positioning on Wayland, the compositor's own placement is the only reliable one. It closes like
any window, and the tray menu still carries the summary.

**Not verified on real desktops.** The strategy selection and the geometry maths are tested, but
placement on a real Wayland compositor, X11 session and GNOME has not been tried. Treat the table as
the intended behaviour and report what you see; the output of Copy diagnostics (§9) helps.

**The Details window** is always an ordinary toplevel, so its position is the compositor's choice
everywhere on Wayland.

## 3. State and files

| Path | Content |
| --- | --- |
| `$XDG_CONFIG_HOME/cainary/tray.toml` | Settings: `refresh`, `notifications`, `launch_at_login`, `start_minimized`, `close_to_tray`, `icon_style` and the Details window size. |
| `$XDG_STATE_HOME/cainary/baseline.json`, `notified.json` | The baseline report and the change ids already notified. Private to the user, because a report lists config paths. |
| `$XDG_CONFIG_HOME/autostart/ua.SkeLLLa.cAInary.desktop` | Written when "Launch at login" is on. |

To reset the app, delete `~/.config/cainary/` and `~/.local/state/cainary/`.

**Autostart.** "Launch at login" is off by default. Turning it on writes the autostart entry above
(`Exec=cainary-tray --autostart`); turning it off removes it. The entry is the truth: at startup
"Launch at login" is read back from whether it exists.

**Startup and closing.** "Start minimized to the tray" (on by default) starts the app with only the
tray icon, at login or from the app menu; off, the Details window opens too. Launching the app
again while it runs opens Details. "Close button minimizes to the tray" (on by default) makes
closing Details hide it; off, closing Details quits. Without a tray host the Details window always
opens, and closing it quits. No package installs system-wide
autostart, and `install-user.sh --uninstall` removes the entry.

> **Caveat: the autostart environment.** The tray passes `--env-kind launchd`, the core's mode for
> an app started without a login shell, as the macOS app does. A tray started by the session at
> login has no login shell's environment either. Scanners add a note saying so and mark choices
> that depend on shell exports as best effort (architecture.md §6.5), so the report can differ
> from `cainary scan` run in a terminal. To compare, run `cainary scan --env-kind launchd`.

## 4. GNOME

Stock GNOME has no status area, so no StatusNotifierWatcher. Install the AppIndicator extension
(`gnome-shell-extension-appindicator`, or from extensions.gnome.org) and enable it. Without it,
the tray notices at startup that `org.kde.StatusNotifierWatcher` is missing and opens the Details
window, so there is still a way in. The .deb and .rpm only suggest the extension; the AUR package
lists it as an optional dependency.

With the extension, GNOME places the tray menu; the popup is an ordinary window the compositor
places (§2). Notifications work without the extension.

## 5. Supported distributions

The tray links the distro's Qt 6, so the floor is **Qt 6.5**, and LayerShellQt 6.0 or newer for
the layer-shell feature. Packages are built against Debian trixie (Qt 6.8, LayerShellQt 6.3).

| Distribution | Support |
| --- | --- |
| Debian 13 (trixie) and newer | .deb, tarball |
| Ubuntu 25.04 and newer, including 26.04 LTS | .deb, tarball |
| Fedora 44 and newer | .rpm, tarball |
| Arch Linux | AUR `cainary-bin`, tarball |
| openSUSE Tumbleweed | tarball |
| **Ubuntu 24.04 LTS** | **Not supported for the app**: Qt 6.4 and no Qt 6 LayerShellQt. |

On Ubuntu 24.04 the CLI works, because it is a static musl binary that runs on any distro. An
AppImage that bundles Qt, which would cover it, is deferred. Flatpak is deferred too and won't go
to Flathub: inside the sandbox the scanner would see the runtime's `/etc`, a sanitised environment
and a restricted home, and fixing that needs a sandbox escape.

CI installs and starts the artifacts on Debian trixie, Ubuntu 26.04, Fedora 44 and Arch
(`cainary-tray --self-test`).

**Runtime dependencies.** The QML modules aren't visible to the dependency scanners, so they are
listed by hand.

- **.deb:** `libQt6*` and `liblayershellqtinterface6` are filled in automatically. It also
  depends on the `qml6-module-*` packages (QtQuick, Controls, Layouts, Window, Templates,
  WorkerScript), `qt6-wayland` and `qt6-svg-plugins`. It recommends `qml6-module-org-kde-desktop`
  (the Plasma style) and suggests `gnome-shell-extension-appindicator`.
- **.rpm:** requires `qt6-qtbase-gui`, `qt6-qtdeclarative`, `qt6-qtsvg`, `qt6-qtwayland` and
  `layer-shell-qt`, plus automatic library requirements. It recommends `kf6-qqc2-desktop-style`
  and suggests `gnome-shell-extension-appindicator`.
- **AUR:** `glibc gcc-libs qt6-base qt6-declarative qt6-svg qt6-wayland layer-shell-qt`. Optional:
  `qqc2-desktop-style` and `gnome-shell-extension-appindicator`.
- The Plasma style (`qqc2-desktop-style`, `qml6-module-org-kde-desktop` on Debian) gives the native look and pulls in KDE Frameworks, so it is only
  recommended where the package manager supports that. Without it the app uses Fusion.

## 6. Is it GTK? (GLib and `qgtk3`)

There is no GTK or GLib crate in the Cargo tree, and the dependency guard fails if one appears.
That doesn't make the running process GTK-free:

- Distro Qt links `libglib-2.0` as its event dispatcher. This is GLib, not GTK. Setting
  `QT_NO_GLIB=1` switches Qt to its own dispatcher. We document it and don't set it.
- Distro Qt also ships a `libqgtk3.so` platform-theme plugin, which Qt may load on GNOME and which
  pulls in GTK 3. To avoid that, the tray sets `QT_QPA_PLATFORMTHEME=xdgdesktopportal` before it
  creates the `QGuiApplication`, when the variable is unset. Set the variable yourself to
  override.

## 7. Install

**Packages.** Install the .deb with `sudo apt install ./cainary_<version>_<amd64|arm64>.deb`, the
.rpm with `sudo dnf install ./cainary-<version>-1.<x86_64|aarch64>.rpm`, and the AUR package with
an AUR helper (`yay -S cainary-bin`). They put `cainary` and `cainary-tray` in `/usr/bin` and the
desktop entry, AppStream data and icons under `/usr/share`.

**Tarball.** Unpack `cainary-<version>-linux-<x86_64|aarch64>.tar.gz`, then run
`./install-user.sh` from the directory. It installs to `~/.local/bin` and `~/.local/share`, with no
root, and `./install-user.sh --uninstall` removes it. Put `~/.local/bin` on `PATH` to use the CLI
from a shell. `PREFIX` changes the prefix.

Start the tray from the application menu (cAInary) or run `cainary-tray`. Verify the download as
described in [distribution.md](distribution.md).

## 8. Build, run and test

You need Rust 1.99 or newer (`mise install`), a C++ compiler, and the Qt 6 development packages.
`QMAKE` must point to Qt 6's qmake if `qmake6` isn't found.

| Distribution | Packages |
| --- | --- |
| Debian, Ubuntu | `build-essential pkg-config musl-tools qt6-base-dev qt6-base-dev-tools qt6-declarative-dev qt6-wayland-dev qt6-svg-dev liblayershellqtinterface-dev libwayland-dev`, plus the runtime `qml6-module-*` packages, `qt6-wayland`, `qt6-svg-plugins`, `dbus-daemon`. `QMAKE=/usr/lib/qt6/bin/qmake`. |
| Fedora | `gcc-c++ make pkgconf-pkg-config qt6-qtbase-devel qt6-qtdeclarative-devel qt6-qtwayland-devel qt6-qtsvg-devel layer-shell-qt-devel wayland-devel dbus-daemon`. `QMAKE=/usr/bin/qmake6`. |
| Arch | `base-devel qt6-base qt6-declarative qt6-wayland qt6-svg layer-shell-qt wayland dbus` |

The lists live in `packaging/ci/deps-lib.sh`, shared by the CI containers
(`packaging/ci/linux-ci.sh deps build`, which installs without asking) and by
`mise run linux:deps`, which prints the install command for this machine's distribution
(apt, dnf or pacman). `mise run linux:deps -- --install` asks first, then runs it with `sudo`.
Rust, `shellcheck`, `jq`, `cargo-deb` and `cargo-generate-rpm` come from mise; the Qt and D-Bus
packages, `musl-gcc`, `dpkg-dev`, `appstreamcli` and `desktop-file-validate` can only come from
the distro, and `podman` (or `docker`) for the container tasks is a host tool.

```sh
make linux-build      # debug build of the tray → linux/target/debug/cainary-tray
make linux-run        # build the debug CLI, then run the tray against it with --dev
make linux-test       # tests under dbus-run-session with QT_QPA_PLATFORM=offscreen
make linux-ui-test    # offscreen snapshots → target/ui-snapshots/linux/
make linux-check      # fmt, clippy -D warnings, tests, shellcheck, desktop and AppStream checks
make linux            # release artifacts in dist/ (LINUX_FORMATS=tar,deb,rpm; default tar)
```

The mise tasks wrap the same targets (`mise tasks` lists them):

| Task | Does |
| --- | --- |
| `linux:build`, `linux:test`, `linux:lint`, `linux:fmt` | `make linux-build`, `-test`, `-lint`, `-fmt` |
| `linux:check`, `linux:ui-test`, `linux:run` | `make linux-check`, `-ui-test`, `-run` |
| `linux:cli` | the static musl `cainary` for `LINUX_ARCH` (default: this machine) that `make linux` ships beside the tray |
| `linux:package` | tarball, .deb and .rpm in `dist/` for this machine (needs `cargo-deb`, `cargo-generate-rpm`) |
| `linux:deps` | the distro packages above; `-- --install` to install them |
| `linux:container:deb`, `linux:container:rpm` | CI's build, package, inspect and install smoke test in `debian:trixie` or `fedora:44`; artifacts in `dist/container/<deb\|rpm>/` |
| `linux:container:arch` | dependencies and a build of the tray on Arch |

The container tasks (`packaging/ci/container.sh`) use podman, or docker without it
(`CONTAINER_ENGINE` overrides). They use the digest-pinned images in `packaging/ci/images.env`
and copy the source in without `target/`, `linux/target/`, `dist/` and `.serena/`, so the host's
build directories and the container's never mix. Each run installs the toolchain again, so
expect a few minutes. Inside mise, cargo runs through `mbx` (mr-boxington) as on macOS; its
release builds are stripped on Linux, so `linux:package` uses it. The macOS universal bundle
doesn't (see `bundle-universal`). The containers and CI use plain cargo, with the Rust toolchain
installed from a pinned `rustup-init`, not mise: mise would bootstrap rustup without that digest
check, and its `cargo:` tools are `cargo install` anyway.

The tests don't need a display or a real machine's state. `tray-model` runs the bounded runner
against the shell stubs in `macos/Tests/stubs/` and report fixtures. `tray-dbus` runs against a
private session bus with fake notification and watcher services. `cainary-tray` has the guard
tests (`tests/guards.rs`) and an offscreen test that runs `--self-test` and checks the three
snapshots.

## 9. Troubleshooting

- **No icon in the tray.** On GNOME, enable the AppIndicator extension (§4). On other desktops,
  check that a StatusNotifier host is running. Without a tray, Details opens at launch.
- **"cainary CLI not found".** `cainary` must sit next to `cainary-tray` or be at
  `/usr/bin/cainary`. A `cainary` on `PATH` is never used; the banner tells you to install
  the `cainary` package or put the CLI next to `cainary-tray`. When you build from source, use `make linux-run`, or set `CAINARY_CORE`
  and pass `--dev`.
- **The popup is in the wrong place.** On GNOME Wayland it is an ordinary window and the compositor
  decides (§2). Otherwise, run `cainary-tray --verbose` and check the `placement` line against the
  table in §2. Some tray hosts send `Activate(0, 0)`, which puts the popup at the top-right.
- **"Failed to register with host portal … App info not found".** Qt registers the app id
  `ua.SkeLLLa.cAInary` with xdg-desktop-portal, which accepts it only if a desktop entry with that id
  exists and its `Exec` program is on the portal's `PATH` or is an absolute path. The packages and
  `install-user.sh` install such an entry; a build run from source (`make linux-run`) has none.
  The warning is harmless there: the tray, notifications and window icon don't go through the portal.
- **Won't start: a Qt platform plugin or QML module is missing.** Install the runtime packages from
  §5. `cainary-tray --self-test` prints the Qt messages of the failing module. It writes its snapshots
  to `$CAINARY_UI_SNAPSHOTS`, else `$XDG_RUNTIME_DIR/cainary/ui-snapshots`, else `./cainary-ui-snapshots`.
- **Results differ from a terminal scan.** See the autostart caveat in §3.
- **Reporting a problem.** Open About and press **Copy diagnostics**, or run
  `cainary-tray --verbose`. Both give the same `key: value` block: versions, Qt platform, desktop
  and session, placement strategy, layer-shell feature and protocol, controls style, tray watcher,
  notification service, CLI path and version, settings and autostart state. It contains no scan
  results.
- **"Your settings file couldn't be read."** Settings shows this when `tray.toml` can't be read or
  parsed; defaults are in use, and changing a setting replaces the file.
- **Look and feel.** Install `qqc2-desktop-style` for the Plasma style, or set
  `QT_QUICK_CONTROLS_STYLE` yourself.
- **A second launch does nothing.** It raises the running instance and exits. `cainary-tray
  --details` opens Details in it.
