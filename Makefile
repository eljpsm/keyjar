.PHONY: build install test coverage coverage-html lint fmt

# Build the release binary.
build:
	cargo build --release

# Install keyjar onto PATH (~/.cargo/bin).
install:
	cargo install --path .

# Run all tests.
test:
	cargo test

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
