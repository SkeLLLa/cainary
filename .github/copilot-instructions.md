# GitHub Copilot Review Instructions

When reviewing this repository, treat it as a production macOS menu-bar app with a Rust core
whose whole value is being trustworthy. Prioritize correctness, user safety and honest wording
over style.

Project context:
- `cAInary` (`cAInary.app`, CLI `cainary`) reports what an organization enforces on, and
  collects from, AI coding assistants (Claude Code, Claude Desktop, Codex; Cursor and GitHub
  Copilot best-effort). Detection rules: `docs/rules.md`; architecture:
  `docs/architecture.md`.
- `crates/cainary-core` is the Rust core (readers, scanners, rules, report). `crates/cainary-cli`
  is the `cainary` CLI; it prints the report as text or JSON.
- `macos/` is the SwiftUI menu bar app. It runs the bundled CLI
  (`cAInary.app/Contents/Helpers/cainary`) and renders its JSON; it holds no scanning logic.
- Tests: `cargo test` with synthetic fixtures, plus `macos/Tests/run.sh` (unit and snapshot
  tests for the app).
- The version lives in `[workspace.package]` of `Cargo.toml`; the release workflow (git-cliff,
  from Conventional Commits) updates it, `Cargo.lock` and `CHANGELOG.md` via
  `scripts/set-version.sh`. Do not hand-edit them.
- Validation is `make check` (CI runs it with rustup's cargo and Xcode's swiftc). Locally, tools
  are pinned in `mise.toml` and `mise run check` wraps the same targets.

Hard rules — flag any violation as a blocking issue:
- Read-only: never write, chmod or delete outside the app's own preferences domain.
- No network: no HTTP clients in the core or CLI; no `URLSession`, `NSURLConnection`,
  `Network.framework` or update checks in the app. Opening a user-clicked link in the browser is
  the only exception.
- Never read credential files (`~/.codex/auth.json`, `~/.copilot/config.json`, Keychain,
  `~/.claude/.credentials*`, `.env*`, `*.pem`, `*.key`).
- Fixtures are synthetic (`example-corp.com`, `AcmeCollector`, `alice`). No real org data.
- User-facing strings must not overclaim: "can read your prompts" only when the mechanism
  grants it; every rule cites a doc or a public, reproducible finding.

Conventions:
- Rust 2024 edition; `cargo fmt` and `cargo clippy -D warnings` are enforced.
- Swift 6 language mode with strict concurrency. UI code on `@MainActor`.
- Formatting is enforced by `cargo fmt` and `swift format`; do not comment on style they decide.
- Commits and PR titles follow Conventional Commits.
