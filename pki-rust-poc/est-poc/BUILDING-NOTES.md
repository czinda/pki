# Building Notes and Troubleshooting

## Build System

This project uses **Cargo**, Rust's build system and package manager. Cargo handles:
- Dependency management (downloads from crates.io)
- Compilation (calls rustc)
- Testing
- Documentation generation
- Packaging

## Dependencies

The project uses these key dependencies (see `Cargo.toml`):

### Web Framework
- **axum 0.7** - Modern async web framework
- **tower** - Service middleware
- **tower-http** - HTTP-specific middleware

### Async Runtime
- **tokio 1.x** - Async runtime for handling concurrent requests

### Cryptography
- **rustls 0.23** - Modern TLS library
- **x509-parser** - Parse X.509 certificates
- **rcgen** - Generate X.509 certificates
- **pem** - PEM encoding/decoding
- **base64** - Base64 encoding

### HTTP
- **reqwest** - HTTP client (for CA backend)
- **hyper** - Low-level HTTP primitives

### Serialization
- **serde** - Serialization framework
- **serde_json** - JSON support
- **toml** - TOML config parsing

### Logging
- **tracing** - Structured logging
- **tracing-subscriber** - Log output formatting

## Common Build Issues and Solutions

### Issue: Version Compatibility Error with axum-server

**Error:**
```
error[E0277]: the trait bound `<<A as Accept<TcpStream, ...>>::Service as SendService<...>>::BodyData: Buf` is not satisfied
```

**Cause:** Incompatibility between `axum 0.7` and `axum-server 0.6`

**Solution:** Removed `axum-server` dependency and used plain `axum::serve()` with `TcpListener`. For the PoC, TLS is deferred to production (see NEXT-STEPS.md).

**Fixed in:** Commit removing axum-server from Cargo.toml

### Issue: Missing Rust Installation

**Error:**
```
bash: cargo: command not found
```

**Solution:**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### Issue: Outdated Rust Version

**Error:**
```
error: package `axum v0.7.x` cannot be built because it requires rustc 1.70 or newer
```

**Solution:**
```bash
rustup update stable
```

## Build Process Explained

When you run `cargo build`:

1. **Dependency Resolution**
   - Reads `Cargo.toml`
   - Downloads dependencies from crates.io
   - Resolves version constraints
   - Creates `Cargo.lock` (version lockfile)

2. **Compilation**
   - Compiles dependencies (once, then cached)
   - Compiles project code
   - Links everything together
   - Produces binary in `target/`

3. **Incremental Compilation**
   - Only recompiles changed code
   - Reuses cached artifacts
   - Much faster than full rebuild

## Build Modes

### Debug Build (default)
```bash
cargo build
```
- Fast compilation
- Includes debug symbols
- No optimizations
- Larger binary (~50-100 MB)
- Slower runtime performance

### Release Build
```bash
cargo build --release
```
- Slower compilation (more optimizations)
- No debug symbols (unless specified)
- Full optimizations (O3 equivalent)
- Smaller binary (~5-10 MB)
- Maximum runtime performance

**Always use release builds for performance testing!**

## Dependency Management

### View Dependency Tree
```bash
cargo tree
```

### Update Dependencies
```bash
cargo update
```

This updates dependencies within version constraints in `Cargo.toml`.

### Audit for Security Vulnerabilities
```bash
cargo install cargo-audit
cargo audit
```

### Check for Outdated Dependencies
```bash
cargo install cargo-outdated
cargo outdated
```

## Build Optimization

### Faster Linking (macOS/Linux)
Add to `~/.cargo/config.toml`:

```toml
[target.x86_64-apple-darwin]
rustflags = ["-C", "link-arg=-fuse-ld=lld"]

[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "link-arg=-fuse-ld=lld"]
```

Requires installing `lld` linker.

### Faster Compilation
```toml
# In Cargo.toml
[profile.dev]
opt-level = 1  # Some optimization for debug builds
```

### Smaller Binaries
```toml
# In Cargo.toml
[profile.release]
strip = true        # Remove debug symbols
lto = true          # Link-time optimization
codegen-units = 1   # Better optimization (slower build)
```

## Compilation Times

On a typical development machine:

### First Build (cold cache)
- **Debug:** 2-5 minutes
- **Release:** 3-7 minutes

Downloads and compiles all dependencies.

### Incremental Build (warm cache)
- **Debug:** 5-30 seconds
- **Release:** 10-60 seconds

Only recompiles changed files.

### Check Only (no binary)
```bash
cargo check  # 3-10 seconds
```

Fastest way to verify code compiles.

## Build Artifacts

The `target/` directory structure:

```
target/
├── debug/
│   ├── pki-est-server          # Debug binary
│   ├── build/                  # Build scripts output
│   ├── deps/                   # Dependency objects
│   └── incremental/            # Incremental compilation cache
├── release/
│   ├── pki-est-server          # Release binary
│   └── ...
└── CACHEDIR.TAG
```

**Size:** Expect 500MB - 1GB for `target/` directory.

## Cleaning Build Artifacts

```bash
# Remove all build artifacts
cargo clean

# Remove specific target
cargo clean --target x86_64-unknown-linux-musl

# Remove release artifacts only
cargo clean --release
```

## Continuous Integration

For CI/CD, recommended workflow:

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

# Check formatting
cargo fmt -- --check

# Lint
cargo clippy -- -D warnings

# Build
cargo build --release

# Test
cargo test --release

# Audit
cargo audit
```

## Cross-Platform Building

### Build for Linux on macOS
```bash
# Install target
rustup target add x86_64-unknown-linux-musl

# Build
cargo build --release --target x86_64-unknown-linux-musl
```

### Build for macOS on Linux
```bash
# Install target
rustup target add x86_64-apple-darwin

# Requires macOS SDK (complex)
# Consider using cross: cargo install cross
cross build --release --target x86_64-apple-darwin
```

## Container Builds

The `Dockerfile` uses multi-stage build:

**Stage 1: Builder**
- Uses `rust:1.75` image
- Compiles application
- Caches dependencies separately

**Stage 2: Runtime**
- Uses `debian:bookworm-slim`
- Copies only binary
- Minimal attack surface
- Small image size (~30 MB)

```bash
# Build
docker build -t pki-est:latest .

# Build size
docker images pki-est
# REPOSITORY   TAG       SIZE
# pki-est     latest    ~30MB
```

## Troubleshooting Specific Errors

### Error: "linker `cc` not found"

**Solution (Debian/Ubuntu):**
```bash
sudo apt-get install build-essential
```

**Solution (RHEL/Fedora):**
```bash
sudo dnf install gcc
```

**Solution (macOS):**
```bash
xcode-select --install
```

### Error: "failed to fetch https://github.com/rust-lang/crates.io-index"

**Network/proxy issue**

**Solution:**
```bash
# Configure git to use HTTP instead of git protocol
git config --global url."https://".insteadOf git://
```

### Error: "the `cargo-build` command has failed"

**Corrupted cache**

**Solution:**
```bash
rm -rf ~/.cargo/registry ~/.cargo/git
cargo clean
cargo build
```

### Warning: "unused variable" or "unused import"

**Not an error, just a warning**

To suppress:
```rust
#![allow(unused)]  // At top of file
```

Or fix by removing unused code.

## Performance Notes

### Debug vs Release Performance

Example EST enrollment operation:

| Build Mode | Latency |
|------------|---------|
| Debug | ~20ms |
| Release | ~2-5ms |

**Always benchmark with release builds!**

### Binary Size

| Build Mode | Size |
|------------|------|
| Debug | ~50-100 MB |
| Release (default) | ~10-15 MB |
| Release (stripped) | ~5-8 MB |

Stripping debug symbols:
```bash
cargo build --release
strip target/release/pki-est-server
```

Or in `Cargo.toml`:
```toml
[profile.release]
strip = true
```

## Next Steps After Successful Build

1. **Run the server:**
   ```bash
   cargo run -- examples/config/server.conf
   ```

2. **Test basic functionality:**
   ```bash
   curl http://localhost:8443/.well-known/est/cacerts
   ```

3. **Review the code** in `src/` directory

4. **Read NEXT-STEPS.md** for production roadmap

5. **Compare with Java** in `../COMPARISON.md`

## Getting Help

- **Rust Book:** https://doc.rust-lang.org/book/
- **Cargo Book:** https://doc.rust-lang.org/cargo/
- **Rust Forum:** https://users.rust-lang.org/
- **Discord:** https://discord.gg/rust-lang

## Summary

The build system is now working correctly after removing the incompatible `axum-server` dependency. The PoC uses plain HTTP with Axum, and TLS implementation is planned for the production phase (see NEXT-STEPS.md Phase 1.1).

**Current Status:** ✅ Builds successfully with `cargo build`
