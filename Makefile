# The only build entry point for cAInary (mise tasks wrap these targets).

.DEFAULT_GOAL := help
PHONY_RELEASE := release otel-debug linux-build-release linux-run-release
.PHONY: help build test test-tls fmt lint lint-actions check-rust check core-universal app bundle bundle-debug-helpers ui-test screenshots screenshots-linux scan publish-check clean \
	linux linux-cli linux-helper linux-build linux-test linux-fmt linux-lint linux-check linux-ui-test linux-run $(PHONY_RELEASE)

# cargo needs a writable CARGO_HOME. Normally that is the existing CARGO_HOME or ~/.cargo and
# nothing changes. When that directory cannot be written (the agent sandbox), use
# $TMPDIR/cargo-home, and run cargo from $TMPDIR with --manifest-path: cargo also reads
# .cargo/config.toml from every parent of the working directory, including a ~/.cargo/config.toml
# that may point crates.io at an unreachable mirror. CARGO_BIN is plain cargo here (CI); mise.toml
# sets it to mbx (mr-boxington), a shared build cache.
CARGO_BIN ?= cargo
CARGO_CD :=
MANIFEST :=
LINUX_MANIFEST := --manifest-path "$(CURDIR)/linux/Cargo.toml"
CARGO_HOME_DIR := $(or $(CARGO_HOME),$(HOME)/.cargo)
CARGO_HOME_WRITABLE := $(shell sh -c 'mkdir -p "$$1" && : > "$$1/.write-test" && rm -f "$$1/.write-test" && echo y' sh "$(CARGO_HOME_DIR)" 2>/dev/null)
ifeq ($(CARGO_HOME_WRITABLE),)
SANDBOX_TMP := $(patsubst %/,%,$(or $(TMPDIR),/tmp))
export CARGO_HOME := $(SANDBOX_TMP)/cargo-home
export MBX_CACHE_DIR := $(SANDBOX_TMP)/mbx-cache
CARGO_CD := cd "$(SANDBOX_TMP)" &&
MANIFEST := --manifest-path "$(CURDIR)/Cargo.toml"
endif
CARGO := $(CARGO_BIN)
CARGO_CMD := $(CARGO_CD) $(CARGO)
# make exports a command-line `CARGO=mbx` to every recipe, and mbx runs $CARGO as the real cargo:
# it then starts itself recursively until memory runs out. Cargo sets CARGO for its own children.
unexport CARGO

# Checks that need the other OS are skipped with a note instead of failing: Swift (swift format,
# ui-test) runs only on macOS, the Qt tray checks only on Linux. CI runs each on its own OS.
HOST_OS := $(shell uname -s)
skipped = @echo "make $@: skipped, needs $(1) (this is $(HOST_OS))" >&2

SWIFT_FORMAT_PATHS = macos/Sources macos/Tests
APPLE_TARGETS = aarch64-apple-darwin x86_64-apple-darwin

# Linux (docs/linux.md). The tray app is its own workspace, linux/Cargo.toml.
LINUX_ARCH ?= $(shell uname -m)
LINUX_FORMATS ?= tar
LINUX_CLI_TARGET = $(LINUX_ARCH)-unknown-linux-musl
CAINARY_VERSION = $(shell sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml)
CAINARY_GIT_SHA ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || date +%s)
CAINARY_BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)
export CAINARY_GIT_SHA CAINARY_BUILD_DATE SOURCE_DATE_EPOCH

help:
	@echo "Targets:"
	@echo "  build           debug build of the Rust workspace"
	@echo "  release         release cainary, cainary-otel-debug and cainary-hosts-helper -> target/release/"
	@echo "  otel-debug      run the release cainary-otel-debug (OTEL_DEBUG_ARGS=... for flags)"
	@echo "  test            cargo test"
	@echo "  fmt             cargo fmt (in place)"
	@echo "  lint            cargo fmt --check, clippy -D warnings, swift format, shellcheck"
	@echo "  lint-actions    jactionlint on workflows and dependabot.yml (version in mise.toml)"
	@echo "  check-rust      fmt --check, clippy -D warnings, cargo test (also with --features tls for cainary-net)"
	@echo "  test-tls        cargo test -p cainary-net --features tls"
	@echo "  check           lint + test + ui-test (CI)"
	@echo "  core-universal  release cainary, cainary-otel-debug and cainary-hosts-helper for both Apple targets, lipo -> target/universal/"
	@echo "  app             build the SwiftUI app (macos/Sources)"
	@echo "  bundle          assemble dist/cAInary.app and zip it"
	@echo "  linux           Linux release artifacts in dist/ (LINUX_FORMATS=tar,deb,rpm; default tar)"
	@echo "  linux-cli       static musl cainary, cainary-otel-debug, cainary-bind-helper and cainary-hosts-helper for LINUX_ARCH (default: this machine)"
	@echo "  linux-helper    static musl cainary-bind-helper and cainary-hosts-helper; prints the admin install and uninstall commands"
	@echo "  linux-build     debug build of the Qt tray app (linux/)"
	@echo "  linux-test      tray tests under dbus-run-session, QT_QPA_PLATFORM=offscreen"
	@echo "  linux-fmt       cargo fmt for linux/ (in place)"
	@echo "  linux-lint      fmt --check and clippy -D warnings for linux/"
	@echo "  linux-check     linux-lint + linux-test + shellcheck + desktop/AppStream validation (CI)"
	@echo "  linux-ui-test   offscreen snapshots of the tray windows -> target/ui-snapshots/linux/"
	@echo "  linux-run       run the tray app against the debug cainary and collector (--dev)"
	@echo "  linux-build-release  release build of the Qt tray app -> linux/target/release/"
	@echo "  linux-run-release    run the release tray against the release cainary and collector (--dev)"
	@echo "  ui-test         decode the Rust goldens through the Swift model"
	@echo "  screenshots     run the macOS snapshots only, copy the curated PNGs -> docs/screenshots/macos/"
	@echo "  screenshots-linux  render the Linux QML snapshots, copy the curated PNGs -> docs/screenshots/linux/"
	@echo "  scan            scan this machine (smoke test, not golden-checked)"
	@echo "  publish-check   cargo publish --dry-run for the published crates (needs crates.io)"
	@echo "  clean           remove target, linux/target and dist"
	@echo "cargo uses CARGO_HOME=$(or $(CARGO_HOME),~/.cargo)"

build:
	$(CARGO_CMD) build $(MANIFEST) --workspace

test:
	$(CARGO_CMD) test $(MANIFEST) --workspace
	$(CARGO_CMD) test $(MANIFEST) -p cainary-net --features tls

fmt:
	$(CARGO_CMD) fmt $(MANIFEST) --all

# The endpoint takeover (`--tls`) is behind a non-default feature; this covers it.
test-tls:
	$(CARGO_CMD) test $(MANIFEST) -p cainary-net --features tls

check-rust:
	$(CARGO_CMD) fmt $(MANIFEST) --all --check
	$(CARGO_CMD) clippy $(MANIFEST) --workspace --all-targets -- -D warnings
	$(CARGO_CMD) clippy $(MANIFEST) -p cainary-net --features tls --all-targets -- -D warnings
	$(CARGO_CMD) test $(MANIFEST) --workspace
	$(CARGO_CMD) test $(MANIFEST) -p cainary-net --features tls

lint:
	$(CARGO_CMD) fmt $(MANIFEST) --all --check
	$(CARGO_CMD) clippy $(MANIFEST) --workspace --all-targets -- -D warnings
	$(CARGO_CMD) clippy $(MANIFEST) -p cainary-net --features tls --all-targets -- -D warnings
ifeq ($(HOST_OS),Darwin)
	@if [ -d macos/Sources ]; then swift format lint --strict --recursive $(SWIFT_FORMAT_PATHS); fi
else
	$(call skipped,macOS for swift format)
endif
	@if ls packaging/*.sh >/dev/null 2>&1; then shellcheck packaging/*.sh packaging/dist/*.sh packaging/ci/*.sh scripts/*.sh macos/Tests/run.sh macos/Tests/stubs/*.sh; fi

check: lint test ui-test

# GitHub workflows and dependabot.yml. jactionlint also runs shellcheck on `run:` scripts when
# shellcheck is on PATH. Not part of `check`: CI runs it in its own job (ci.yml, actions-lint).
lint-actions:
	jactionlint

core-universal:
	@for t in $(APPLE_TARGETS); do $(CARGO_CMD) build $(MANIFEST) --release --target $$t -p cainary -p cainary-net -p cainary-hosts-helper --features cainary-net/tls || exit 1; done
	mkdir -p target/universal
	@for b in cainary cainary-otel-debug cainary-hosts-helper; do \
		lipo -create -output target/universal/$$b \
			$(foreach t,$(APPLE_TARGETS),target/$(t)/release/$$b) || exit 1; \
	done

# The SwiftUI app: swiftc only (no SwiftPM, no Xcode). Host arch, -Onone and DEBUG by default;
# RELEASE=1 builds -O for arm64 and x86_64 and joins them with lipo. The default module cache
# isn't writable in a sandbox, so it goes in $TMPDIR. mise sets SWIFTC (see mise.toml).
SWIFTC ?= swiftc
SDKROOT ?= $(shell xcrun --sdk macosx --show-sdk-path)
SWIFT_TMP := $(patsubst %/,%,$(or $(TMPDIR),/tmp))
SWIFT_SOURCES := $(wildcard macos/Sources/*.swift)
SWIFT_FLAGS = -swift-version 6 -sdk $(SDKROOT) -module-cache-path $(SWIFT_TMP)/swift-mc
ifdef RELEASE
SWIFT_ARCHS := arm64 x86_64
SWIFT_OPT := -O
else
SWIFT_ARCHS := $(shell uname -m)
SWIFT_OPT := -Onone -g -D DEBUG
endif

app: $(SWIFT_SOURCES)
	mkdir -p target/macos
	@for a in $(SWIFT_ARCHS); do \
		echo "swiftc $$a"; \
		$(SWIFTC) $(SWIFT_FLAGS) -target $$a-apple-macos14 $(SWIFT_OPT) \
			$(SWIFT_SOURCES) -o target/macos/cAInary-$$a || exit 1; \
	done
	@rm -rf target/macos/cAInary-*.dSYM
	@if [ $(words $(SWIFT_ARCHS)) -eq 1 ]; then mv target/macos/cAInary-$(SWIFT_ARCHS) target/macos/cAInary; \
	else lipo -create -output target/macos/cAInary $(foreach a,$(SWIFT_ARCHS),target/macos/cAInary-$(a)) \
		&& rm -f $(foreach a,$(SWIFT_ARCHS),target/macos/cAInary-$(a)); fi


# Assembles dist/cAInary.app. Debug helper by default; RELEASE=1 bundles the universal one.
# CORE=..., OTEL_DEBUG=... and HOSTS_HELPER=... change only the helper paths that are bundled.
ifdef RELEASE
CORE ?= target/universal/cainary
OTEL_DEBUG ?= target/universal/cainary-otel-debug
HOSTS_HELPER ?= target/universal/cainary-hosts-helper
BUNDLE_DEPS := app core-universal
else
CORE ?= target/debug/cainary
OTEL_DEBUG ?= target/debug/cainary-otel-debug
HOSTS_HELPER ?= target/debug/cainary-hosts-helper
BUNDLE_DEPS := app bundle-debug-helpers
endif

# The debug helpers with the collector's `tls` feature, so HTTPS takeover works in a dev bundle.
bundle-debug-helpers:
	$(CARGO_CMD) build $(MANIFEST) --workspace --features cainary-net/tls

bundle: $(BUNDLE_DEPS)
	CORE="$(CORE)" OTEL_DEBUG="$(OTEL_DEBUG)" HOSTS_HELPER="$(HOSTS_HELPER)" packaging/bundle.sh

# --- Linux -----------------------------------------------------------------------------------
# The CLI and the debug collector are static musl from the root workspace; it runs on any distro. The tray app links the
# distro's Qt 6, so it is built on (or in a container of) the distro it ships for.
linux-cli:
	$(CARGO_CMD) build $(MANIFEST) --release --locked --target $(LINUX_CLI_TARGET) -p cainary -p cainary-net -p cainary-bind-helper -p cainary-hosts-helper --features cainary-net/tls

# The root helpers (docs/linux.md): bind for low ports, hosts for the /etc/hosts block. Builds both
# and PRINTS the admin commands; nothing here installs anything or runs sudo. The commands are
# fish-compatible.
HELPER_BIN = $(CURDIR)/target/$(LINUX_CLI_TARGET)/release/cainary-bind-helper
HELPER_POLICY = $(CURDIR)/packaging/linux/polkit/ua.SkeLLLa.cAInary.local.policy
HOSTS_HELPER_BIN = $(CURDIR)/target/$(LINUX_CLI_TARGET)/release/cainary-hosts-helper
HOSTS_HELPER_POLICY = $(CURDIR)/packaging/linux/polkit/ua.SkeLLLa.cAInary.hosts.local.policy
linux-helper:
	$(CARGO_CMD) build $(MANIFEST) --release --locked --target $(LINUX_CLI_TARGET) -p cainary-bind-helper -p cainary-hosts-helper
	@echo ""
	@echo "Built $(HELPER_BIN)"
	@echo "Built $(HOSTS_HELPER_BIN)"
	@echo "Install as an administrator (not run for you):"
	@echo "  sudo install -d -m 0755 -o root -g root /usr/local/libexec/cainary"
	@echo "  sudo install -m 0755 -o root -g root $(HELPER_BIN) /usr/local/libexec/cainary/cainary-bind-helper"
	@echo "  sudo install -m 0644 -o root -g root $(HELPER_POLICY) /usr/share/polkit-1/actions/ua.SkeLLLa.cAInary.local.policy"
	@echo "  sudo install -m 0755 -o root -g root $(HOSTS_HELPER_BIN) /usr/local/libexec/cainary/cainary-hosts-helper"
	@echo "  sudo install -m 0644 -o root -g root $(HOSTS_HELPER_POLICY) /usr/share/polkit-1/actions/ua.SkeLLLa.cAInary.hosts.local.policy"
	@echo "Uninstall:"
	@echo "  sudo rm /usr/local/libexec/cainary/cainary-bind-helper /usr/share/polkit-1/actions/ua.SkeLLLa.cAInary.local.policy"
	@echo "  sudo rm /usr/local/libexec/cainary/cainary-hosts-helper /usr/share/polkit-1/actions/ua.SkeLLLa.cAInary.hosts.local.policy"
	@echo "  sudo rmdir /usr/local/libexec/cainary"

linux-build:
	$(CARGO_CMD) build $(LINUX_MANIFEST) --workspace

# A private session bus for the tray's D-Bus tests, and no display.
ifeq ($(HOST_OS),Linux)
linux-test:
	$(CARGO_CD) dbus-run-session -- env QT_QPA_PLATFORM=offscreen $(CARGO) test --manifest-path "$(CURDIR)/linux/Cargo.toml"
else
linux-test:
	$(call skipped,Linux)
endif

linux-fmt:
	$(CARGO_CMD) fmt $(LINUX_MANIFEST) --all

ifeq ($(HOST_OS),Linux)
linux-lint:
	$(CARGO_CMD) fmt $(LINUX_MANIFEST) --all --check
	$(CARGO_CMD) clippy $(LINUX_MANIFEST) --workspace --all-targets -- -D warnings
	$(CARGO_CMD) check $(LINUX_MANIFEST) -p cainary-tray --no-default-features
else
linux-lint:
	$(call skipped,Linux)
endif

# appstreamcli reports cid-domain-not-lowercase: the ID ua.SkeLLLa.cAInary is fixed (it is the
# D-Bus name and the icon and desktop file names). Every other error or warning still fails.
ifeq ($(HOST_OS),Linux)
linux-check: linux-lint linux-test
	shellcheck packaging/linux.sh packaging/dist/install-user.sh packaging/ci/*.sh
	desktop-file-validate linux/data/ua.SkeLLLa.cAInary.desktop
	@tmp="$$(mktemp -d)" && cp linux/data/autostart.desktop.in "$$tmp/autostart.desktop" && \
		desktop-file-validate "$$tmp/autostart.desktop"; rc=$$?; rm -rf "$$tmp"; exit $$rc
	@out="$$(appstreamcli validate --no-net --explain linux/data/ua.SkeLLLa.cAInary.metainfo.xml 2>&1)"; rc=$$?; \
		if echo "$$out" | grep -E '^[EW]: ' | grep -v 'cid-domain-not-lowercase' | grep -q .; then \
			echo "$$out"; echo "appstreamcli: errors or warnings above" >&2; exit 1; \
		elif [ $$rc -ne 0 ] && ! echo "$$out" | grep -q 'cid-domain-not-lowercase'; then \
			echo "$$out"; echo "appstreamcli: validation failed" >&2; exit $$rc; \
		else echo "appstreamcli: metainfo OK (expected cid-domain-not-lowercase ignored)"; fi
else
linux-check:
	$(call skipped,Linux)
endif

ifeq ($(HOST_OS),Linux)
linux-ui-test:
	mkdir -p target/ui-snapshots/linux
	$(CARGO_CD) dbus-run-session -- env QT_QPA_PLATFORM=offscreen \
		CAINARY_UI_SNAPSHOTS="$(CURDIR)/target/ui-snapshots/linux" \
		$(CARGO) test $(LINUX_MANIFEST) -p cainary-tray --test offscreen
else
linux-ui-test:
	$(call skipped,Linux)
endif

# The debug workspace plus the collector's `tls` feature, so --tls works in a dev run (release builds always have it).
linux-run:
	$(CARGO_CMD) build $(MANIFEST) --workspace --features cainary-net/tls
	$(CARGO_CD) env CAINARY_CORE="$(CURDIR)/target/debug/cainary" \
		CAINARY_OTEL_DEBUG="$(CURDIR)/target/debug/cainary-otel-debug" \
		CAINARY_ICON_THEME_PATH="$(CURDIR)/linux/data/icons" \
		$(CARGO) run $(LINUX_MANIFEST) -p cainary-tray -- --dev

linux-build-release:
	$(CARGO_CMD) build $(LINUX_MANIFEST) --release --locked -p cainary-tray

# --dev makes a release tray honour CAINARY_CORE and CAINARY_OTEL_DEBUG (tray-model/src/locate.rs).
# CAINARY_OTEL_DEBUG=<path> runs another collector, e.g. a root-owned copy allowed to bind port 443.
CAINARY_OTEL_DEBUG ?= $(CURDIR)/target/release/cainary-otel-debug
linux-run-release: release linux-build-release
	env CAINARY_CORE="$(CURDIR)/target/release/cainary" \
		CAINARY_OTEL_DEBUG="$(CAINARY_OTEL_DEBUG)" \
		CAINARY_ICON_THEME_PATH="$(CURDIR)/linux/data/icons" \
		"$(CURDIR)/linux/target/release/cainary-tray" --dev

linux: linux-cli
	$(CARGO_CMD) build $(LINUX_MANIFEST) --release --locked -p cainary-tray
	packaging/linux.sh --version "$(CAINARY_VERSION)" --arch $(LINUX_ARCH) \
		--cli target/$(LINUX_CLI_TARGET)/release/cainary \
		--otel-debug target/$(LINUX_CLI_TARGET)/release/cainary-otel-debug \
		--bind-helper target/$(LINUX_CLI_TARGET)/release/cainary-bind-helper \
		--hosts-helper target/$(LINUX_CLI_TARGET)/release/cainary-hosts-helper \
		--tray linux/target/release/cainary-tray \
		--formats $(LINUX_FORMATS) --out dist

ifeq ($(HOST_OS),Darwin)
ui-test: build
	sh macos/Tests/run.sh
else
ui-test:
	$(call skipped,macOS)
endif

# README screenshots: the snapshot step alone, then a hand-picked set (no 🚫 AppKit placeholders,
# fixture names only). Look at each PNG before adding it here.
SCREENSHOTS = collector-window-feed collector-window-flags collector-setup-takeover collector-window-failure \
	sidebar-live collector-rules collector-logs detail-monitor
ifeq ($(HOST_OS),Darwin)
screenshots: build
	CAINARY_SNAPSHOTS_ONLY=1 sh macos/Tests/run.sh
	mkdir -p docs/screenshots/macos
	for n in $(SCREENSHOTS); do cp target/ui-snapshots/$$n.png docs/screenshots/macos/ || exit 1; done
else
screenshots:
	$(call skipped,macOS)
endif

# The Linux counterparts, side by side with the macOS set in the README. QML-only harness
# (fixtures only, needs Qt 6); same rule: look at each PNG before adding it here.
SCREENSHOTS_LINUX = details popup-live details-collector-feed details-collector-flags \
	details-collector-takeover-ready details-collector-logs \
	details-collector-fail-port-in-use
ifeq ($(HOST_OS),Linux)
screenshots-linux:
	linux/crates/cainary-tray/qml/dev/harness.sh -o target/ui-preview/linux $(SCREENSHOTS_LINUX)
	mkdir -p docs/screenshots/linux
	for n in $(SCREENSHOTS_LINUX); do cp target/ui-preview/linux/$$n.png docs/screenshots/linux/ || exit 1; done
else
screenshots-linux:
	$(call skipped,Linux)
endif

# Release binaries from this checkout, for trying a build without installing it.
release:
	$(CARGO_CMD) build $(MANIFEST) --release --locked -p cainary -p cainary-net -p cainary-bind-helper -p cainary-hosts-helper --features cainary-net/tls

OTEL_DEBUG_ARGS ?=
# Only the collector writes to stdout, so `--json` output can be piped.
otel-debug:
	@$(CARGO_CMD) build $(MANIFEST) --release --locked -p cainary-net --features tls >&2
	@"$(CURDIR)/target/release/cainary-otel-debug" $(OTEL_DEBUG_ARGS)

scan:
	$(CARGO_CMD) run $(MANIFEST) --quiet -p cainary -- scan

# Packages and builds both crates as crates.io would, without uploading (cargo 1.90+ resolves the
# unpublished cainary-core from the workspace).
publish-check:
	$(CARGO_CMD) publish $(MANIFEST) --workspace --dry-run --locked --registry crates-io

clean:
	$(CARGO_CMD) clean $(MANIFEST)
	@if [ -f linux/Cargo.toml ]; then echo "cargo clean (linux)"; $(CARGO_CMD) clean $(LINUX_MANIFEST); fi
	rm -rf dist
