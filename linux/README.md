# cAInary for Linux (tray app, planned)

The Linux counterpart of `macos/`. Like the macOS app it holds no scanning logic: it runs the
`cainary` CLI (`cainary scan --json --env-kind shell`) and draws `status`, `apps`, `others` and their
`findings` from the JSON (docs/architecture.md §9.2). The toolkit is not chosen yet.

Layout:

- `src/` — the tray app.
- `tests/` — UI tests against the Rust goldens and stub CLIs (as `macos/Tests`).
- `data/` — desktop entry, autostart entry and icons.

Packaging goes in `packaging/linux.sh`.
