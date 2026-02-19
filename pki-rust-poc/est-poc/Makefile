.PHONY: build release test clean run docker-build docker-run install

# Build in debug mode
build:
	cargo build

# Build in release mode
release:
	cargo build --release

# Run tests
test:
	cargo test

# Clean build artifacts
clean:
	cargo clean

# Run server with example config
run:
	cargo run -- examples/config/server.conf

# Build Docker image
docker-build:
	docker build -t pki-est:latest .

# Run Docker container
docker-run:
	docker run -p 8443:8443 pki-est:latest

# Install to /usr/local/bin (requires sudo)
install: release
	install -m 755 target/release/pki-est-server /usr/local/bin/

# Format code
fmt:
	cargo fmt

# Lint code
lint:
	cargo clippy -- -D warnings

# Check code without building
check:
	cargo check

# Run with debug logging
debug:
	RUST_LOG=debug cargo run -- examples/config/server.conf

# Generate documentation
docs:
	cargo doc --open

# Benchmark (requires criterion)
bench:
	cargo bench
