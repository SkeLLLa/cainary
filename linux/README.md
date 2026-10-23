# cAInary for Linux (tray app)

The Linux counterpart of `macos/`. Like the macOS app it holds no scanning logic: it runs the
`cainary` CLI (`cainary scan --json --env-kind launchd`) and draws `status`, `apps`, `others` and
their `findings` from the JSON (docs/architecture.md §9.2). The toolkit is Qt 6 / QML through
cxx-qt; docs/linux.md describes the app, its popup placement and how to build it.

Layout:

- `crates/tray-model/` — pure Rust: report model, bounded runner, store, settings, change tracking.
- `crates/tray-dbus/` — zbus and ksni: tray icon, notifications, single instance.
- `crates/cainary-tray/` — the `cainary-tray` binary: cxx-qt bridge, QML, placement, C++ shims.
- `data/` — desktop entry, autostart entry, AppStream metadata and icons.

Packaging is in `packaging/linux.sh`.
