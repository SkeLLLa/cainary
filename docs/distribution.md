# Distribution

cAInary ships as a macOS app bundle, `cAInary.app`. The bundle holds the SwiftUI menu-bar app
(`Contents/MacOS/cAInary`) and the Rust CLI (`Contents/Helpers/cainary`). It is an agent app
(`LSUIElement`, no Dock icon) and requires macOS 14. For how the bundle is built, see
[macos.md](macos.md) §4.

## Install methods

| Method                                  | Installs                 | Command                                                    |
| --------------------------------------- | ------------------------ | ---------------------------------------------------------- |
| Release download                        | the app (and its CLI)    | unzip `cainary-<version>-macos-universal.zip` into `/Applications` |
| mise (packslip backend, mise 2026.9.2+) | the `cainary` CLI        | `mise use -g packslip:github.com/SkeLLLa/cainary`          |
| packslip (1.5.1+)                       | the `cainary` CLI        | `packslip install github.com/SkeLLLa/cainary`              |
| cargo (Rust 1.99+, macOS or Linux)      | the `cainary` CLI        | `cargo install cainary --locked`                           |
| From source                             | the app (and its CLI)    | `mise run bundle-universal`, then copy `dist/cAInary.app`  |

`cargo install` builds the CLI from the `cainary` crate on crates.io (see [crates.io](#cratesio)).

mise and packslip both verify the signed packslip manifest of the release before they install
anything. They put `cainary` on `PATH`; it does not start the menu-bar app. Without `--pin`,
packslip trusts the repository GitHub reports for the name on first install and remembers it.
After the first release, the signer pin (`ps1_…`) is printed in the `verify-packslip` job summary.
Add it to the README install commands as `--pin <pin>`, and set it as the `PACKSLIP_PIN` repository
variable.

A release download through a browser is quarantined. Until releases are notarized, run
`xattr -dr com.apple.quarantine /Applications/cAInary.app` once.

## Release artifacts

`release.yml` runs on pushes to `master` without `[skip ci]`. When there is something to release,
the `release` job commits the version bump, tags it, and creates the GitHub release. The `build`
job then publishes, for version `<version>`:

- `cainary-<version>-macos-universal.zip`
- `cainary-<version>-macos-universal.tar.gz` (contains `cAInary.app`)
- a `.sha256` file for each archive
- `SHA256SUMS` covering both archives
- `packslip.sigstore.json`, a signed packslip manifest for the tar.gz

Both archives carry a GitHub build provenance attestation.

The packslip manifest is signed keylessly through GitHub OIDC. It records the tar.gz as os
`darwin` with no architecture (universal), the command `cainary` as
`cAInary.app/Contents/Helpers/cainary`, and a resource `app` as `cAInary.app`.

Developer ID signing and notarization run only when the signing secrets are configured. An
unsigned or un-notarized release emits a CI warning and adds a line to the release notes.

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
runs after `build`, and only when the repository variable `CRATES_IO_PUBLISH` is `true`. It
skips a crate whose version is already on crates.io, so after a partial upload, **Re-run failed
jobs** publishes the rest. Rerunning the whole workflow repeats the version logic instead.

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
shasum -a 256 -c cainary-<version>-macos-universal.zip.sha256
shasum -a 256 -c SHA256SUMS --ignore-missing
gh attestation verify cainary-<version>-macos-universal.zip --repo SkeLLLa/cainary
packslip verify packslip.sigstore.json --artifact cainary-<version>-macos-universal.tar.gz \
  --identity-prefix https://github.com/SkeLLLa/cainary/ \
  --issuer https://token.actions.githubusercontent.com
```

## Not available yet

- Homebrew cask (a `SkeLLLa/homebrew-tap` tap, bumped by the release workflow).
- Linux release archive: the core builds on Linux, but `make linux` has no packaging script yet.
- Developer ID signing and notarization: the workflow supports it once the secrets are set.
- A mise registry listing, so `mise use cainary` works without the `packslip:` prefix.
