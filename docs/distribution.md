# Distribution

cAInary ships for macOS and Linux.

**macOS:** an app bundle, `cAInary.app`. The bundle holds the SwiftUI menu-bar app
(`Contents/MacOS/cAInary`) and the Rust CLI (`Contents/Helpers/cainary`). It is an agent app
(`LSUIElement`, no Dock icon) and requires macOS 14. For how the bundle is built, see
[macos.md](macos.md) §4.

**Linux:** a tarball, a .deb, an .rpm and an AUR package. Each holds the static `cainary` CLI and
the Qt 6 tray app `cainary-tray` (see [linux.md](linux.md)). The tray app needs the distro's
Qt ≥ 6.5; the CLI runs anywhere.

## Install methods

| Method                                  | Installs                 | Command                                                    |
| --------------------------------------- | ------------------------ | ---------------------------------------------------------- |
| Release download                        | the app (and its CLI)    | unzip `cainary-<version>-macos-universal.zip` into `/Applications` |
| mise (packslip backend, mise 2026.9.2+) | the `cainary` CLI        | `mise use -g packslip:github.com/SkeLLLa/cainary`          |
| packslip (1.5.1+)                       | the `cainary` CLI        | `packslip install github.com/SkeLLLa/cainary`              |
| cargo (Rust 1.99+, macOS or Linux)      | the `cainary` CLI        | `cargo install cainary --locked`                           |
| From source (macOS)                     | the app (and its CLI)    | `mise run bundle-universal`, then copy `dist/cAInary.app`  |
| .deb (Debian 13+, Ubuntu 25.04+)        | the tray app and CLI     | `sudo apt install ./cainary_<version>_<amd64\|arm64>.deb`   |
| .rpm (Fedora 44+)                       | the tray app and CLI     | `sudo dnf install ./cainary-<version>-1.<x86_64\|aarch64>.rpm` |
| AUR (Arch)                              | the tray app and CLI     | `yay -S cainary-bin`                                       |
| Linux tarball                           | the tray app and CLI     | unpack `cainary-<version>-linux-<x86_64\|aarch64>.tar.gz`, run `./install-user.sh` |
| From source (Linux)                     | the tray app and CLI     | `make linux LINUX_FORMATS=tar,deb,rpm` ([linux.md](linux.md) §8) |

`cargo install` builds the CLI from the `cainary` crate on crates.io (see [crates.io](#cratesio)).

mise and packslip both verify the signed packslip manifest of the release before they install
anything. They put `cainary` on `PATH`; they do not start the menu-bar app. On Linux the packslip
manifest also lists `cainary-tray`, which needs the host's Qt 6. Without `--pin`,
packslip trusts the repository GitHub reports for the name on first install and remembers it.
After the first release, the signer pin (`ps1_…`) is printed in the `verify-packslip` job summary.
Add it to the README install commands as `--pin <pin>`, and set it as the `PACKSLIP_PIN` repository
variable.

A release download through a browser is quarantined. Until releases are notarized, run
`xattr -dr com.apple.quarantine /Applications/cAInary.app` once.

## Release artifacts

`release.yml` runs on pushes to `master` without `[skip ci]`. When there is something to release,
the `prepare` job works out the version and the commit to build, and changes nothing. The `build`
(macOS), `build-linux-cli` and `build-linux` jobs check out that commit, apply the version bump
locally (`scripts/release-tree.sh`) and build; `verify-linux` installs the Linux packages and the
`checksums` job hashes and attests every asset. Only when all of them have passed does the
`publish` job commit the bump, tag it, and create the GitHub release with the assets. It is the
only job that changes the repository, and it pushes without force, so it fails if `master` has
moved since the built commit. `aur`, `crates` and the packslip jobs follow. If a run fails before
`publish`, nothing was released and a rerun starts clean. If `publish` fails after tagging, rerun
the workflow: `prepare` sees the tag made from the same commit, the builds run again, and `publish`
completes the release without bumping again. For version `<version>`, the release holds:

- `cainary-<version>-macos-universal.zip`
- `cainary-<version>-macos-universal.tar.gz` (contains `cAInary.app`)
- `cainary-<version>-linux-x86_64.tar.gz` and `cainary-<version>-linux-aarch64.tar.gz`
- `cainary_<version>_amd64.deb` and `cainary_<version>_arm64.deb`
- `cainary-<version>-1.x86_64.rpm` and `cainary-<version>-1.aarch64.rpm`
- a `.sha256` file for each of these
- `SHA256SUMS` covering all of them
- `packslip.sigstore.json`, a signed packslip manifest for the tar.gz archives

Every archive and package carries a GitHub build provenance attestation. The `checksums` job
(which only reads this run's artifacts; `publish` uploads its output) waits for the macOS build and for every Linux package to build and pass its install test, then
hashes and attests all of them at once, so `SHA256SUMS` has one writer.

The packslip manifest (`packaging/packslip.toml`) is signed keylessly through GitHub OIDC. It
records the macOS tar.gz as os `darwin` with no architecture (universal), the command `cainary` as
`cAInary.app/Contents/Helpers/cainary`, and a resource `app` as `cAInary.app`. The two Linux
tarballs list the commands `cainary` and `cainary-tray` under `bin/` in their top-level directory.

Developer ID signing and notarization run only when the signing secrets are configured. An
unsigned or un-notarized release emits a CI warning and adds a line to the release notes.

## Linux

**Contents.** All three formats ship the same bytes, built by `packaging/linux.sh` from one asset list,
`packaging/linux-assets.txt` (mode, staged path, install path). Staging, `install-user.sh` and the
PKGBUILD read that list; the .deb and .rpm tables in `linux/crates/cainary-tray/Cargo.toml` are
written by hand and a test checks they match it. The CLI is at `/usr/bin/cainary`, where the tray
looks for it:

| Path (under `/usr` for packages, the archive's top-level directory for the tarball) | What |
| --- | --- |
| `bin/cainary` | the static musl CLI |
| `bin/cainary-tray` | the Qt 6 tray app |
| `share/applications/ua.SkeLLLa.cAInary.desktop` | desktop entry |
| `share/metainfo/ua.SkeLLLa.cAInary.metainfo.xml` | AppStream metadata |
| `share/doc/cainary/` | `README.md` |
| `share/licenses/cainary/LICENSE` | the license (also at the tarball's top level) |
| `share/icons/hicolor/scalable/apps/`, `<size>x<size>/apps/` | app icon (16–256 px PNG and SVG); the tray draws its status icons at run time |

The tarball adds `install-user.sh`, the asset list, `README.md` and `LICENSE` and has one top-level directory,
`cainary-<version>-linux-<arch>/`. No package installs system-wide autostart; the tray writes a
per-user entry only when the user turns on "Launch at login".

**Build.** The CLI is built once per architecture as static musl from the root workspace
(`make linux-cli`, `build-linux-cli`, on native x86_64 and aarch64 runners). The tray app links the
distro's Qt, so it is built inside the distro it ships for: the tarball and .deb on
`debian:trixie`, the .rpm on `fedora:44`, for both architectures. `packaging/linux.sh` checks that
both binaries report the release version, stages the tree, and builds the formats with `cargo-deb`
(`--no-build`, version exactly `<version>`) and `cargo-generate-rpm`. Their metadata is in
`linux/crates/cainary-tray/Cargo.toml`. The tarball has a stable file order, owner and times
(`SOURCE_DATE_EPOCH`, default the HEAD commit time). Locally, `make linux LINUX_FORMATS=tar,deb,rpm`
builds artifacts for this machine's architecture into `dist/`.

**Checks.** `build-linux` runs `packaging/ci/linux-ci.sh inspect` on each artifact: the file
lists, the package name, version and architecture, the Qt and QML dependencies, no system-wide
autostart, and that the tarball's CLI is static. `verify-linux` then installs the artifacts as a
user would, with no recommended packages, on Debian trixie (x86_64 and arm64), Ubuntu 26.04,
Fedora 44 (x86_64 and aarch64) and Arch Linux (the tarball with the AUR
package's dependencies). It runs `cainary --version`, `cainary scan --json --env-kind launchd`,
`cainary-tray --version` and `QT_QPA_PLATFORM=offscreen cainary-tray --self-test`. Nothing is
published unless every one passes. `ci.yml` runs the same package and install jobs on pull
requests, plus the tray's checks (`make linux-check`) on Debian trixie and Fedora 44 and a
build-only job on Arch.

**AUR.** `packaging/aur/PKGBUILD` is `cainary-bin`, built from the release tarball. The `aur` job
renders `pkgver` and the checksums from the tarballs this run built, runs
`makepkg --printsrcinfo` and pushes to `aur.archlinux.org`. It runs only when the repository
variable `AUR_PUBLISH` is `true`, in the `aur` environment, with the `AUR_SSH_KEY` secret (an SSH
private key whose public half is on the maintainer's AUR account). The package must exist on the
AUR first.

**Not shipped.** Ubuntu 24.04 can't run the tray app (Qt 6.4, no Qt 6 LayerShellQt); its users
have the CLI. An AppImage that bundles Qt, and a Flatpak, are deferred ([linux.md](linux.md) §5).
`packaging/mise-registry/cainary.toml` is a staged registry entry; mise doesn't read it from here.

## crates.io

Two crates are published at the release version: `cainary-core` (the library) and `cainary`
(the CLI package, in `crates/cainary-cli`, binary `cainary`). The CLI requires exactly the same
`cainary-core` version (`=X.Y.Z`), and `scripts/set-version.sh` bumps both. The packages leave
out `tests/`, because the tests read fixtures across both crates. `make publish-check` (also run
in CI on Linux) runs `cargo publish --workspace --dry-run`. The release profile in the root
`Cargo.toml` (size-tuned, LTO) applies to the release archives only; `cargo install` uses
cargo's defaults.

The `crates` job in `release.yml` publishes them with crates.io Trusted Publishing: the job runs
in the `crates-io` environment, `rust-lang/crates-io-auth-action` exchanges the GitHub OIDC
token for a crates.io token that expires after 30 minutes, and no API token is stored. The job
runs after `publish`, and only when the repository variable `CRATES_IO_PUBLISH` is `true`. It
skips a crate whose version is already on crates.io, so after a partial upload, rerunning the
workflow (or **Re-run failed jobs**) publishes the rest; the tag from the first attempt is reused.

One-time setup:

1. Let the first release (`v0.1.0`) run with `CRATES_IO_PUBLISH` unset.
2. Check out the tag and publish by hand with an API token (crates.io needs a crate to exist
   before it can have a trusted publisher): `cargo login --registry crates-io`, then
   `cargo publish --workspace --locked --registry crates-io`. `--registry crates-io` is needed when
   a local cargo config replaces crates-io with a mirror.
3. Create the GitHub environment `crates-io` (Settings → Environments), limited to `master`, with
   no required reviewers.
4. On crates.io, for both `cainary-core` and `cainary`: Settings → Trusted Publishing → add a
   GitHub publisher with owner `SkeLLLa`, repository `cainary`, workflow `release.yml` and
   environment `crates-io`.
5. Set the repository variable `CRATES_IO_PUBLISH` to `true`.
6. Turn on "trusted publishing only" for both crates, and revoke the API token from step 2.

## Verifying a download

```sh
shasum -a 256 -c cainary-<version>-macos-universal.zip.sha256   # sha256sum -c on Linux
shasum -a 256 -c SHA256SUMS --ignore-missing                    # sha256sum -c on Linux
gh attestation verify cainary-<version>-macos-universal.zip --repo SkeLLLa/cainary
gh attestation verify cainary-<version>-linux-x86_64.tar.gz --repo SkeLLLa/cainary
packslip verify packslip.sigstore.json --artifact cainary-<version>-macos-universal.tar.gz \
  --identity-prefix https://github.com/SkeLLLa/cainary/ \
  --issuer https://token.actions.githubusercontent.com
```

## Not available yet

- Homebrew cask (a `SkeLLLa/homebrew-tap` tap, bumped by the release workflow).
- A Linux AppImage and a Flatpak, and a tray app for Ubuntu 24.04 ([linux.md](linux.md) §5).
- Signed APT and RPM repositories: the .deb and .rpm are downloaded and installed by hand, and
  carry no package signature. Their integrity comes from the checksums and attestation above.
- Developer ID signing and notarization: the workflow supports it once the secrets are set.
- A mise registry listing, so `mise use cainary` works without the `packslip:` prefix.
