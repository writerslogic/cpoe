.PHONY: build test run clean release

# Debug build with ad-hoc codesign (macOS only — prevents keychain prompts)
# Use this instead of `cargo build` directly to avoid repeated keychain auth dialogs.
# The ad-hoc signature gives each binary a stable identity across rebuilds.
build:
	cargo build
	@if [ "$$(uname)" = "Darwin" ]; then \
		for bin in target/debug/cpop target/debug/writerslogic-native-messaging-host; do \
			[ -f "$$bin" ] && codesign -s - -f "$$bin" 2>/dev/null && \
			echo "Ad-hoc signed $$bin"; \
		done; \
	fi

# Run all workspace tests (mock keychain — zero keychain interaction)
test:
	CPOP_NO_KEYCHAIN=1 cargo test --workspace

# Build + codesign + run the binary directly (bypasses cargo run rebuild)
run: build
	target/debug/cpop $(ARGS)

# Release build (should be properly codesigned separately for distribution)
release:
	cargo build --release

clean:
	cargo clean
