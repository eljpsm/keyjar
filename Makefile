.PHONY: build install test test-cli coverage coverage-html lint fmt release

VERSION = $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml)

# Build the release binary.
build:
	cargo build --release

# Install keyjar onto PATH (~/.cargo/bin).
install:
	cargo install --path .

# Run all tests.
test:
	cargo test

# End-to-end binary tests (exit codes, hidden input, store handling).
test-cli:
	cargo test --test cli

# Line and region coverage across all tests, printed per file.
coverage:
	cargo llvm-cov --all-targets

# Same, rendered as an annotated HTML report.
coverage-html:
	cargo llvm-cov --all-targets --open

# Clippy across all targets; warnings fail, locally and in CI alike.
lint:
	cargo clippy --all-targets -- --deny warnings

# Format the Rust source.
fmt:
	cargo fmt

# Tag the current commit with the Cargo.toml version and push the tag.
# CI then runs goreleaser and publishes the binaries.
release:
	git tag "v$(VERSION)"
	git push origin "v$(VERSION)"
