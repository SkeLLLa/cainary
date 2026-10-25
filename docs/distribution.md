# Distribution

cAInary ships for macOS and Linux.

**macOS:** an app bundle, `cAInary.app`. The bundle holds the SwiftUI menu-bar app
(`Contents/MacOS/cAInary`) and the Rust CLI (`Contents/Helpers/cainary`). It is an agent app
(`LSUIElement`, no Dock icon) and requires macOS 14. For how the bundle is built, see
[macos.md](macos.md) §4.

**Linux:** a tarball, a .deb, an .rpm, APT and DNF repositories, and an AUR package. Each holds the static `cainary` CLI and
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
| APT repository (Debian 13+, Ubuntu 25.04+) | the tray app and CLI, with updates | see [APT and DNF repositories](#apt-and-dnf-repositories) |
| DNF repository (Fedora 44+)             | the tray app and CLI, with updates | see [APT and DNF repositories](#apt-and-dnf-repositories) |
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

A release download through a browser is quarantined, and releases are not notarized (see
[Signing](#signing)), so run `xattr -dr com.apple.quarantine /Applications/cAInary.app` once.

## Release artifacts

`release.yml` runs on pushes to `master` without `[skip ci]`. When there is something to release,
the `prepare` job works out the version and the commit to build, and changes nothing. The `build`
(macOS), `build-linux-cli` and `build-linux` jobs check out that commit, apply the version bump
locally (`scripts/release-tree.sh`) and build; `sign-linux` signs the .rpm files (see
[Linux signing](#linux-signing)), `verify-linux` installs the Linux packages and the
`checksums` job hashes and attests every asset. Only when all of them have passed does the
`publish` job commit the bump, tag it, and create the GitHub release with the assets. It is the
only job that changes the repository, and it pushes without force, so it fails if `master` has
moved since the built commit. `aur`, `repo` and `pages`, `crates` and the packslip jobs follow. If a run fails before
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

The `build` job signs with the pinned certificate (see [Signing](#signing)). Until the pin is
committed it signs ad hoc, emits a CI warning and says so in the release notes; the notes always
carry the `xattr` step.

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
| `share/icons/hicolor/scalable/apps/`, `<size>x<size>/apps/` | app icon (16–256 px PNG and SVG, plus a monochrome `ua.SkeLLLa.cAInary-symbolic.svg`); the tray draws its status icons at run time |

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

**Not shipped.** Ubuntu 24.04 can't run the tray app (Qt 6.4, no Qt 6 LayerShellQt); its users
have the CLI. An AppImage that bundles Qt, and a Flatpak, are deferred ([linux.md](linux.md) §5).
`packaging/mise-registry/cainary.toml` is a staged registry entry; mise doesn't read it from here.

## APT and DNF repositories

The `repo` and `pages` jobs in `release.yml` build package repositories and deploy them to GitHub
Pages (`https://skellla.github.io/cainary/`), in the same layout as
[plasma-drop](https://skellla.github.io/plasma-drop/)'s. `packaging/ci/pages-repo.sh` writes the
site: an APT repository under `deb/` (suite `stable`, component `main`, amd64 and arm64), a DNF
repository per architecture under `rpm/x86_64/` and `rpm/aarch64/`, and an index page with these
commands. Each deploy replaces the site, so the job rebuilds it from this release's packages,
which `verify-linux` installed, plus those of the 9 releases before it, downloaded from the
release page. Users can still pin or downgrade within those 10 versions.

```sh
# Fedora 44+
sudo curl -fsSLo /etc/yum.repos.d/cainary.repo https://skellla.github.io/cainary/rpm/cainary.repo
sudo dnf install cainary

# Debian 13+, Ubuntu 25.04+
echo 'deb [trusted=yes] https://skellla.github.io/cainary/deb stable main' | sudo tee /etc/apt/sources.list.d/cainary.list
sudo apt update
sudo apt install cainary
```

Like plasma-drop's, the repositories are unsigned until a signing key is pinned (`[trusted=yes]`,
`gpgcheck=0`, `repo_gpgcheck=0`). Their integrity then rests on HTTPS to GitHub Pages; the
checksums and attestation on the release page cover the same files. Once
`packaging/signing/repo.asc` is committed ([Linux signing](#linux-signing)), `repo` signs the APT
`InRelease`, every .rpm and each `repomd.xml`, publishes the public key as `cainary.asc`, and the
index page, `cainary.list` and `cainary.repo` switch to checking it
(`signed-by=/etc/apt/keyrings/cainary.asc`, `gpgcheck=1`, `repo_gpgcheck=1`). Adding the key
changes the setup commands, and users who added the unsigned repository have to follow them
again.

The job runs after `publish` on every release, unless the repository variable `PAGES_PUBLISH` is
`false`. `PAGES_BASE_URL` overrides the URL written into the repository files (for a custom
domain). One-time setup:

1. Settings → Pages: set the source to **GitHub Actions**. The `github-pages` environment it
   creates deploys from `master` only.
2. Optional, for signed packages and metadata: see [Linux signing](#linux-signing).

To check the site locally, run `packaging/ci/pages-repo.sh` on a directory of packages with a
`file:///` base URL (it needs `apt-ftparchive` and `createrepo_c`); a test key in `GNUPGHOME`
gives the signed variant.

## AUR

`packaging/aur/PKGBUILD` is `cainary-bin`, built from the release tarball. The `aur` job renders
`pkgver` and the checksums from the tarballs this run built, runs `makepkg --printsrcinfo` and
pushes to `aur.archlinux.org`, in the `aur` environment. It runs on every release unless the
repository variable `AUR_PUBLISH` is `false`, and skips with a warning until the `AUR_SSH_KEY`
secret is set. One-time setup:

1. Make an SSH key for the release (`ssh-keygen -t ed25519 -N '' -f aur-cainary`) and add the
   public half to the maintainer's AUR account (My Account → SSH Public Key).
2. Create the GitHub environment `aur` (Settings → Environments), limited to `master`, and add
   the private key as its secret `AUR_SSH_KEY`.

The first push creates `cainary-bin` on the AUR; later releases update it.

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
runs after `publish` on every release, unless the repository variable `CRATES_IO_PUBLISH` is
`false`. Trusted Publishing can't create a crate, so a crate that isn't on crates.io yet is skipped
with a warning in the run. It also skips a crate whose version is already on crates.io, so after
a partial upload, rerunning the workflow (or **Re-run failed jobs**) publishes the rest; the tag
from the first attempt is reused.

One-time setup:

1. Let the first release (`v0.1.0`) run; its `crates` job skips both crates with a warning.
2. Check out the tag and publish by hand with an API token (crates.io needs a crate to exist
   before it can have a trusted publisher): `cargo login --registry crates-io`, then
   `cargo publish --workspace --locked --registry crates-io`. `--registry crates-io` is needed when
   a local cargo config replaces crates-io with a mirror.
3. Create the GitHub environment `crates-io` (Settings → Environments), limited to `master`, with
   no required reviewers.
4. On crates.io, for both `cainary-core` and `cainary`: Settings → Trusted Publishing → add a
   GitHub publisher with owner `SkeLLLa`, repository `cainary`, workflow `release.yml` and
   environment `crates-io`.
5. Turn on "trusted publishing only" for both crates, and revoke the API token from step 2.

## Signing

The macOS app is signed with cAInary's own self-signed code-signing certificate. There is no
Apple Developer ID: the project is open source and non-profit, so releases are not notarized and
a browser download still needs the `xattr` step above. What the certificate buys is a stable
designated requirement:

```text
designated => identifier "ua.SkeLLLa.cAInary" and certificate leaf = H"<sha1>"
```

(the helper's is the same with `ua.SkeLLLa.cAInary.helper`). macOS keys notification
permission, the launch-at-login item and any other TCC grant to this requirement, so they survive
updates. An ad-hoc signature pins the cdhash instead, and every build looks like a new app.

The certificate is cAInary's alone. quartz-drop and local dev builds each use their own, and the
requirement pins the exact leaf, so a key leaked from one can't sign as another.

**Pin.** `packaging/signing/release.sha1` holds the certificate's SHA-1. It is the `codesign`
identity and the pin `bundle.sh` checks: with `CODESIGN_IDENTITY` set, the bundle fails unless
both the signature and the designated requirement carry that leaf. Once the pin is committed, the
release fails rather than ship ad hoc or with another key; changing the pin makes every user
grant the permissions again, so do it only when the certificate expires (it is valid for 20
years) or leaks.

**Secrets.** The key lives only in the `macos-signing` GitHub environment, used by the `build`
job of `release.yml`:

| Secret                       | Value                                         |
| ---------------------------- | --------------------------------------------- |
| `MACOS_CERTIFICATE_P12`      | the .p12 (key and certificate), base64 on one line |
| `MACOS_CERTIFICATE_PASSWORD` | its password                                  |

Set up the environment in **Settings → Environments → New environment** `macos-signing`:

- **Deployment branches and tags:** *Selected branches and tags*, with only `master`. A
  workflow on any other branch or tag that names the environment is refused before it runs.
  Repository secrets have no such rule, so don't keep these as repository secrets.
- **Required reviewers** (optional): yourself, if every release should wait for approval.
- No environment variables are needed; the identity comes from the committed pin.

`ci.yml` never names the environment, and pull requests (including from forks) build ad hoc.
The import step puts the .p12 into a temporary keychain that only `/usr/bin/codesign` may use,
checks that it holds the pinned identity, and removes it after the build.

**Making the certificate.** On the maintainer's Mac (not in CI), with the
`macos-signing-cert` script from the maintainer's dotfiles, or the same steps by hand: an RSA
3072 self-signed certificate named `ua.SkeLLLa.cAInary release`, organization
`github.com/SkeLLLa/cainary`, with critical `keyUsage = digitalSignature` and
`extendedKeyUsage = codeSigning`, exported with `/usr/bin/openssl` (LibreSSL; the PKCS#12 that
OpenSSL 3 writes by default doesn't import).

```sh
macos-signing-cert -g SkeLLLa/cainary ua.SkeLLLa.cAInary
cp ~/.local/share/macos-signing/ua.SkeLLLa.cAInary.release/ua.SkeLLLa.cAInary.release.sha1 \
  packaging/signing/release.sha1
```

`-g` sets both secrets in the `macos-signing` environment through `gh`. Then back up the .p12
and its password outside the machine and delete the directory.

**Local builds.** Make a separate dev certificate (`ua.SkeLLLa.cAInary dev`) and import it into
the login keychain, so dev builds keep their grants across rebuilds without ever matching the
release requirement:

```sh
macos-signing-cert -d -i ua.SkeLLLa.cAInary
CODESIGN_IDENTITY="$(cat ~/.local/share/macos-signing/ua.SkeLLLa.cAInary.dev/*.sha1)" make bundle
codesign -d -r- dist/cAInary.app
```

## Linux signing

The .rpm files and the APT and DNF repository metadata are signed with an OpenPGP key on the
same terms as the macOS certificate: a committed pin, a key that lives only in a `master`-only
environment, and a release that fails rather than ship unsigned or with another key once the
pin exists. The key's primary part, which users trust, stays offline with a passphrase; CI holds
only a signing subkey, without the primary's secret.

| Signed                                   | Checked by                                                  |
| ---------------------------------------- | ----------------------------------------------------------- |
| each .rpm (release page and DNF repo)    | dnf (`gpgcheck=1`), `rpm -K`                                |
| `rpm/<arch>/repodata/repomd.xml`         | dnf (`repo_gpgcheck=1`)                                     |
| APT `InRelease` and `Release.gpg`        | apt (`signed-by`); `InRelease` lists every .deb's SHA-256   |

The .deb files carry no signature of their own: APT never checks one (`dpkg-sig` and `debsigs`
are off by default), so the signed `InRelease` is what covers them. A .deb downloaded from the
release page is covered by the checksums, attestation and packslip manifest instead.

**Pin.** `packaging/signing/repo.asc` holds the public key (the primary, its subkeys and their
revocations), armored, and only it. While it is absent, `sign-linux` passes the packages through
unsigned and `repo` builds unsigned repositories, with a notice. Once it is committed,
`packaging/ci/linux-signing.sh import` fails the release when the `REPO_SIGNING_KEY` secret is
missing, belongs to another primary key, or can't sign (passphrase, expiry, or a subkey the pin
revokes); setting the secret without committing the pin fails too. `import` also merges the pin
into CI's keyring, so the published `cainary.asc` is the committed certificate. `verify-linux`
checks each .rpm against the pin before installing it, and `repo` checks every .rpm it publishes.

**Where it signs.** `sign-linux` runs after `build-linux`, in the Fedora 44 container with
`rpm-sign`, and replaces the `release-linux-rpm-*` artifacts with the signed files, so
`verify-linux`, `checksums` and the release page see only those. No build runs in a job that
holds the key. `repo` (in the Debian trixie container: the runner's rpm 4.18 can't read a pin
with a revoked subkey) signs the metadata and also signs the .rpm files of the earlier releases
it republishes. The release's own are already signed and stay byte-identical, while those from
before the key, or signed by a since-revoked subkey, differ from their release page copies (and
checksums) by the signature. `pages` only deploys the site, so the key and the Pages deploy token
never share a job.

**Secret.** The subkey lives only in the `linux-signing` GitHub environment, used by
`sign-linux` and `repo`:

| Secret             | Value                                                  |
| ------------------ | ------------------------------------------------------ |
| `REPO_SIGNING_KEY` | one signing subkey, armored, without a passphrase (`linux-signing.sh ci-key`) |

Set it up like `macos-signing` (Settings → Environments → New environment `linux-signing`,
deployment branches: only `master`, optional required reviewers). Don't keep it as a repository
secret.

**Making the key.** On the maintainer's machine, not in CI, in a keyring kept for it (`gpg`
asks for the passphrase). RSA 4096 is what every supported rpm, dnf and apt (sqv) accepts. The
primary can only certify; the subkey can only sign:

```sh
export GNUPGHOME=~/.local/share/package-signing/gnupg   # any private directory
install -d -m 700 "$GNUPGHOME"
gpg --quick-gen-key 'cAInary packages <you@example.com>' rsa4096 cert never
FPR=<the primary's fingerprint, from gpg -K>
gpg --quick-add-key "$FPR" rsa4096 sign 3y
SUB=<the new subkey's fingerprint, from gpg -K --with-subkey-fingerprints>
gpg --armor --export "$FPR" > packaging/signing/repo.asc
packaging/ci/linux-signing.sh ci-key "$SUB" | gh secret set REPO_SIGNING_KEY --env linux-signing
```

`ci-key` exports that one subkey with the primary's secret left out and the passphrase removed.
Keep offline, apart from each other: the keyring (the primary's secret is passphrase-protected;
back up the whole `GNUPGHOME`) and the revocation certificate gpg wrote to
`$GNUPGHOME/openpgp-revocs.d/<fingerprint>.rev`, which revokes the whole key even if the keyring
is lost. Commit `repo.asc` in the same change that updates the README's install commands to the
signed ones (the index page shows them); the next release is the first signed one.

**Rotating or revoking the subkey.** Users trust the primary, so a subkey change needs no action
from them beyond the `cainary.asc` they fetch. Before the subkey expires, or if the secret leaks:
with the offline keyring, revoke the old subkey if it leaked (`gpg --edit-key "$FPR"`, `key N`,
`revkey`, `save`), add a new one with `--quick-add-key`, export `repo.asc` again and set the
secret from `ci-key` for the new one. Commit `repo.asc`: until then, `import` refuses a subkey the
pin doesn't know, and once a revocation is committed it refuses the revoked one. Users then get
the revocation with the next `cainary.asc` they fetch; dnf refuses packages signed by the
revoked subkey, and `repo` re-signs the earlier releases' with the new one. If the primary itself
leaks, import the revocation certificate (remove the `:` before `-----BEGIN` first), commit the
revoked `repo.asc` (every release fails from then on), and start over with a new key; users have
to fetch it again.

**Other projects.** The key is cAInary's own and signs no other project's packages.

## Verifying a download

```sh
shasum -a 256 -c cainary-<version>-macos-universal.zip.sha256   # sha256sum -c on Linux
shasum -a 256 -c SHA256SUMS --ignore-missing                    # sha256sum -c on Linux
gh attestation verify cainary-<version>-macos-universal.zip --repo SkeLLLa/cainary
gh attestation verify cainary-<version>-linux-x86_64.tar.gz --repo SkeLLLa/cainary
packslip verify packslip.sigstore.json --artifact cainary-<version>-macos-universal.tar.gz \
  --identity-prefix https://github.com/SkeLLLa/cainary/ \
  --issuer https://token.actions.githubusercontent.com
# Once the .rpm files are signed (see Linux signing):
sudo rpm --import https://raw.githubusercontent.com/SkeLLLa/cainary/master/packaging/signing/repo.asc
rpm -K cainary-<version>-1.x86_64.rpm   # "digests signatures OK"
```

## Not available yet

- Homebrew cask (a `SkeLLLa/homebrew-tap` tap, bumped by the release workflow).
- A Linux AppImage and a Flatpak, and a tray app for Ubuntu 24.04 ([linux.md](linux.md) §5).
- Signed .deb files: APT checks the signed `InRelease` instead ([Linux signing](#linux-signing)),
  and a downloaded .deb relies on the checksums and attestation above.
- A mise registry listing, so `mise use cainary` works without the `packslip:` prefix.
