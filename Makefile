# The only build entry point for cAInary (mise tasks wrap these targets).

.DEFAULT_GOAL := help
.PHONY: help build test fmt lint check-rust check core-universal app bundle linux ui-test scan publish-check clean

# cargo needs a writable CARGO_HOME. Normally that is the existing CARGO_HOME or ~/.cargo and
# nothing changes. When that directory cannot be written (the agent sandbox), use
# $TMPDIR/cargo-home, and run cargo from $TMPDIR with --manifest-path: cargo also reads
# .cargo/config.toml from every parent of the working directory, including a ~/.cargo/config.toml
# that may point crates.io at an unreachable mirror. CARGO_BIN is plain cargo here (CI); mise.toml
# sets it to mbx (mr-boxington), a shared build cache.
CARGO_BIN ?= cargo
CARGO := $(CARGO_BIN)
MANIFEST :=
CARGO_HOME_DIR := $(or $(CARGO_HOME),$(HOME)/.cargo)
CARGO_HOME_WRITABLE := $(shell sh -c 'mkdir -p "$$1" && : > "$$1/.write-test" && rm -f "$$1/.write-test" && echo y' sh "$(CARGO_HOME_DIR)" 2>/dev/null)
ifeq ($(CARGO_HOME_WRITABLE),)
SANDBOX_TMP := $(patsubst %/,%,$(or $(TMPDIR),/tmp))
export CARGO_HOME := $(SANDBOX_TMP)/cargo-home
export MBX_CACHE_DIR := $(SANDBOX_TMP)/mbx-cache
CARGO := cd "$(SANDBOX_TMP)" && $(CARGO_BIN)
MANIFEST := --manifest-path "$(CURDIR)/Cargo.toml"
endif

SWIFT_FORMAT_PATHS = macos/Sources macos/Tests
APPLE_TARGETS = aarch64-apple-darwin x86_64-apple-darwin

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
	@echo "  linux           static Linux tarball"
	@echo "  ui-test         decode the Rust goldens through the Swift model"
	@echo "  scan            scan this machine (smoke test, not golden-checked)"
	@echo "  publish-check   cargo publish --dry-run for both crates (needs crates.io)"
	@echo "  clean           remove target and dist"
	@echo "cargo uses CARGO_HOME=$(or $(CARGO_HOME),~/.cargo)"

build:
	$(CARGO) build $(MANIFEST) --workspace

test:
	$(CARGO) test $(MANIFEST) --workspace

fmt:
	$(CARGO) fmt $(MANIFEST) --all

check-rust:
	$(CARGO) fmt $(MANIFEST) --all --check
	$(CARGO) clippy $(MANIFEST) --workspace --all-targets -- -D warnings
	$(CARGO) test $(MANIFEST) --workspace

lint:
	$(CARGO) fmt $(MANIFEST) --all --check
	$(CARGO) clippy $(MANIFEST) --workspace --all-targets -- -D warnings
	@if [ -d macos/Sources ]; then swift format lint --strict --recursive $(SWIFT_FORMAT_PATHS); fi
	@if ls packaging/*.sh >/dev/null 2>&1; then shellcheck packaging/*.sh scripts/*.sh macos/Tests/run.sh macos/Tests/stubs/*.sh; fi

check: lint test ui-test

core-universal:
	@for t in $(APPLE_TARGETS); do $(CARGO) build $(MANIFEST) --release --target $$t -p cainary || exit 1; done
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

linux:
	@test -x packaging/linux.sh || { echo "make linux: packaging/linux.sh does not exist yet (task P2)" >&2; exit 1; }
	packaging/linux.sh

ui-test: build
	sh macos/Tests/run.sh

scan:
	$(CARGO) run $(MANIFEST) --quiet -p cainary -- scan

# Packages and builds both crates as crates.io would, without uploading (cargo 1.90+ resolves the
# unpublished cainary-core from the workspace).
publish-check:
	$(CARGO) publish $(MANIFEST) --workspace --dry-run --locked --registry crates-io

clean:
	$(CARGO) clean $(MANIFEST)
	rm -rf dist
