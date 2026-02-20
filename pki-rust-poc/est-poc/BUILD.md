# Build Instructions

## Prerequisites

### Install Rust

If Rust is not installed:

```bash
# Install rustup (Rust installer)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Reload shell configuration
source $HOME/.cargo/env

# Verify installation
rustc --version
cargo --version
```

You need Rust 1.70 or later.

## Building

### Debug Build (for development)

```bash
cd pki-rust-poc/est-poc
cargo build
```

Binary will be at: `target/debug/pki-est-server`

### Release Build (optimized)

```bash
cargo build --release
```

Binary will be at: `target/release/pki-est-server`

**Optimization:** Release builds are ~10x faster and much smaller.

### Check Code Without Building

```bash
cargo check
```

This is faster than a full build and useful for checking syntax/types.

## Running

### Run Directly with Cargo

```bash
cargo run -- examples/config/server.conf
```

### Run the Binary

```bash
# Debug build
./target/debug/pki-est-server examples/config/server.conf

# Release build
./target/release/pki-est-server examples/config/server.conf
```

### With Debug Logging

```bash
RUST_LOG=debug cargo run -- examples/config/server.conf
```

## Testing

### Run All Tests

```bash
cargo test
```

### Run Specific Test

```bash
cargo test test_name
```

### Run Tests with Output

```bash
cargo test -- --nocapture
```

## Common Issues

### Issue: "command not found: cargo"

**Solution:** Rust is not installed or not in PATH. Install Rust using rustup (see Prerequisites).

### Issue: Compilation errors about trait bounds

**Solution:** This was an issue with:
1. Incompatible `axum-server` version - Fixed by removing dependency
2. Async traits not being dyn-compatible - Fixed by using `#[async_trait]` macro

Both issues are resolved in the current code. See [FIXES.md](FIXES.md) for details.

If you still see issues:
```bash
# Clean and rebuild
cargo clean
cargo build
```

### Issue: Port 8443 already in use

**Solution:** Either:
1. Stop the process using port 8443
2. Change the port in `examples/config/server.conf`

```bash
# Find process using port 8443
lsof -i :8443

# Kill it
kill -9 <PID>
```

### Issue: Cannot read config files

**Solution:** Config file paths in `server.conf` are relative to current directory.

Either:
- Run from `est-poc/` directory
- Use absolute paths in config files

## Development Workflow

### Format Code

```bash
cargo fmt
```

### Lint Code

```bash
cargo clippy
```

### Check All (fast)

```bash
cargo check --all-targets
```

### Update Dependencies

```bash
cargo update
```

### Audit Dependencies for Vulnerabilities

```bash
# Install cargo-audit
cargo install cargo-audit

# Run audit
cargo audit
```

## Build Performance

### First Build
- **Time:** 2-5 minutes (downloads and compiles dependencies)
- **Disk:** ~500MB in `target/` directory

### Incremental Builds
- **Time:** 5-30 seconds (only changed files)
- **Disk:** Reuses cached artifacts

### Clean Build
```bash
cargo clean  # Removes target/ directory
cargo build  # Full rebuild
```

## Cross-Compilation

To build for different platforms:

```bash
# List available targets
rustup target list

# Install target
rustup target add x86_64-unknown-linux-musl

# Build for target
cargo build --release --target x86_64-unknown-linux-musl
```

## Container Build

```bash
# Build Docker image
docker build -t pki-est:latest .

# Run container
docker run -p 8443:8443 pki-est:latest
```

## Installing System-Wide

```bash
# Build release binary
cargo build --release

# Install to /usr/local/bin (requires sudo)
sudo install -m 755 target/release/pki-est-server /usr/local/bin/

# Now can run from anywhere
pki-est-server /etc/pki/est/server.conf
```

## Build Artifacts

After building, the `target/` directory contains:

```
target/
├── debug/               # Debug build artifacts
│   ├── pki-est-server  # Debug binary
│   └── ...
├── release/             # Release build artifacts
│   ├── pki-est-server  # Optimized binary
│   └── ...
└── ...
```

**Tip:** Add `target/` to `.gitignore` (already done).

## Troubleshooting Build Issues

### Slow builds?

```bash
# Use more CPU cores (default is # of CPUs)
cargo build -j 8
```

### Out of disk space?

```bash
# Clean old build artifacts
cargo clean

# Clean all Rust build caches (frees GB of space)
cargo cache --autoclean
```

### Dependency issues?

```bash
# Start fresh
rm -rf Cargo.lock target/
cargo build
```

## Next Steps

After successful build:
1. Read [README.md](README.md) for usage instructions
2. Check [NEXT-STEPS.md](../NEXT-STEPS.md) for production roadmap
3. Review [../COMPARISON.md](../COMPARISON.md) for Java vs Rust comparison
