# The only build entry point for cAInary (mise tasks wrap these targets).

.DEFAULT_GOAL := help
.PHONY: help build test fmt lint check-rust check core-universal app bundle ui-test scan publish-check clean \
	linux linux-cli linux-build linux-test linux-fmt linux-lint linux-check linux-ui-test linux-run

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
	@echo "  test            cargo test"
	@echo "  fmt             cargo fmt (in place)"
	@echo "  lint            cargo fmt --check, clippy -D warnings, swift format, shellcheck"
	@echo "  check-rust      fmt --check, clippy -D warnings, cargo test"
	@echo "  check           lint + test + ui-test (CI)"
	@echo "  core-universal  release cainary for both Apple targets, lipo -> target/universal/cainary"
	@echo "  app             build the SwiftUI app (macos/Sources)"
	@echo "  bundle          assemble dist/cAInary.app and zip it"
	@echo "  linux           Linux release artifacts in dist/ (LINUX_FORMATS=tar,deb,rpm; default tar)"
	@echo "  linux-cli       static musl cainary for LINUX_ARCH (default: this machine)"
	@echo "  linux-build     debug build of the Qt tray app (linux/)"
	@echo "  linux-test      tray tests under dbus-run-session, QT_QPA_PLATFORM=offscreen"
	@echo "  linux-fmt       cargo fmt for linux/ (in place)"
	@echo "  linux-lint      fmt --check and clippy -D warnings for linux/"
	@echo "  linux-check     linux-lint + linux-test + shellcheck + desktop/AppStream validation (CI)"
	@echo "  linux-ui-test   offscreen snapshots of the tray windows -> target/ui-snapshots/linux/"
	@echo "  linux-run       run the tray app against the debug cainary (--dev)"
	@echo "  ui-test         decode the Rust goldens through the Swift model"
	@echo "  scan            scan this machine (smoke test, not golden-checked)"
	@echo "  publish-check   cargo publish --dry-run for both crates (needs crates.io)"
	@echo "  clean           remove target, linux/target and dist"
	@echo "cargo uses CARGO_HOME=$(or $(CARGO_HOME),~/.cargo)"

build:
	$(CARGO_CMD) build $(MANIFEST) --workspace

test:
	$(CARGO_CMD) test $(MANIFEST) --workspace

fmt:
	$(CARGO_CMD) fmt $(MANIFEST) --all

check-rust:
	$(CARGO_CMD) fmt $(MANIFEST) --all --check
	$(CARGO_CMD) clippy $(MANIFEST) --workspace --all-targets -- -D warnings
	$(CARGO_CMD) test $(MANIFEST) --workspace

lint:
	$(CARGO_CMD) fmt $(MANIFEST) --all --check
	$(CARGO_CMD) clippy $(MANIFEST) --workspace --all-targets -- -D warnings
	@if [ -d macos/Sources ]; then swift format lint --strict --recursive $(SWIFT_FORMAT_PATHS); fi
	@if ls packaging/*.sh >/dev/null 2>&1; then shellcheck packaging/*.sh packaging/dist/*.sh packaging/ci/*.sh scripts/*.sh macos/Tests/run.sh macos/Tests/stubs/*.sh; fi

check: lint test ui-test

core-universal:
	@for t in $(APPLE_TARGETS); do $(CARGO_CMD) build $(MANIFEST) --release --target $$t -p cainary || exit 1; done
	mkdir -p target/universal
	lipo -create -output target/universal/cainary \
		$(foreach t,$(APPLE_TARGETS),target/$(t)/release/cainary)

# Targets backed by scripts that later tasks add; they fail clearly until then.
# The SwiftUI app: swiftc only (no SwiftPM, no Xcode). Host arch, -Onone and DEBUG by default;
# RELEASE=1 builds -O for arm64 and x86_64 and joins them with lipo. The default module cache
# isn't writable in the agent sandbox, so it goes in $TMPDIR. mise sets SWIFTC (see mise.toml).
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
# CORE=... changes only the helper path that is bundled.
ifdef RELEASE
CORE ?= target/universal/cainary
BUNDLE_DEPS := app core-universal
else
CORE ?= target/debug/cainary
BUNDLE_DEPS := app build
endif

bundle: $(BUNDLE_DEPS)
	CORE="$(CORE)" packaging/bundle.sh

# --- Linux -----------------------------------------------------------------------------------
# The CLI is static musl from the root workspace; it runs on any distro. The tray app links the
# distro's Qt 6, so it is built on (or in a container of) the distro it ships for.
linux-cli:
	$(CARGO_CMD) build $(MANIFEST) --release --locked --target $(LINUX_CLI_TARGET) -p cainary

linux-build:
	$(CARGO_CMD) build $(LINUX_MANIFEST) --workspace

# A private session bus for the tray's D-Bus tests, and no display.
linux-test:
	$(CARGO_CD) dbus-run-session -- env QT_QPA_PLATFORM=offscreen $(CARGO) test --manifest-path "$(CURDIR)/linux/Cargo.toml"

linux-fmt:
	$(CARGO_CMD) fmt $(LINUX_MANIFEST) --all

linux-lint:
	$(CARGO_CMD) fmt $(LINUX_MANIFEST) --all --check
	$(CARGO_CMD) clippy $(LINUX_MANIFEST) --workspace --all-targets -- -D warnings
	$(CARGO_CMD) check $(LINUX_MANIFEST) -p cainary-tray --no-default-features

# appstreamcli reports cid-domain-not-lowercase: the ID ua.SkeLLLa.cAInary is fixed (it is the
# D-Bus name and the icon and desktop file names). Every other error or warning still fails.
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

linux-ui-test:
	mkdir -p target/ui-snapshots/linux
	$(CARGO_CD) dbus-run-session -- env QT_QPA_PLATFORM=offscreen \
		CAINARY_UI_SNAPSHOTS="$(CURDIR)/target/ui-snapshots/linux" \
		$(CARGO) test $(LINUX_MANIFEST) -p cainary-tray --test offscreen

linux-run: build
	$(CARGO_CD) env CAINARY_CORE="$(CURDIR)/target/debug/cainary" \
		CAINARY_ICON_THEME_PATH="$(CURDIR)/linux/data/icons" \
		$(CARGO) run $(LINUX_MANIFEST) -p cainary-tray -- --dev

linux: linux-cli
	$(CARGO_CMD) build $(LINUX_MANIFEST) --release --locked -p cainary-tray
	packaging/linux.sh --version "$(CAINARY_VERSION)" --arch $(LINUX_ARCH) \
		--cli target/$(LINUX_CLI_TARGET)/release/cainary \
		--tray linux/target/release/cainary-tray \
		--formats $(LINUX_FORMATS) --out dist

ui-test: build
	sh macos/Tests/run.sh

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
