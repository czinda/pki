# PKI EST Server - Rust Proof of Concept

This is a proof-of-concept implementation of the Dogtag PKI EST (Enrollment over Secure Transport) subsystem in Rust, demonstrating a migration path from the existing Java/Tomcat implementation to a memory-safe language.

## Overview

EST (RFC 7030) is a protocol for certificate enrollment over HTTPS. This implementation provides:

- **CA Certificate Distribution** (`/cacerts`) - Retrieve CA certificates
- **Simple Enrollment** (`/simpleenroll`) - Issue new certificates from CSRs
- **Simple Re-enrollment** (`/simplereenroll`) - Renew existing certificates

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    EST Server (Axum)                        │
├─────────────────────────────────────────────────────────────┤
│  Authentication     │  Authorization  │  EST Handlers       │
│  (Realm)           │  (Authorizer)   │  (cacerts, enroll)  │
├─────────────────────────────────────────────────────────────┤
│               Backend Interface (Trait)                      │
├─────────────────────────────────────────────────────────────┤
│              Dogtag CA Backend                              │
│         (communicates with existing CA via REST)            │
└─────────────────────────────────────────────────────────────┘
```

### Key Components

1. **Web Framework**: Axum (modern, async, type-safe)
2. **Cryptography**: rustls, x509-parser, rcgen, pem
3. **Configuration**: TOML for server config, properties format for Java compatibility
4. **Authentication**: Pluggable realm system (currently in-memory)
5. **Authorization**: External process authorizer (compatible with existing Python scripts)
6. **Backend**: Trait-based design for multiple CA backends

## Building

### Prerequisites

- Rust 1.70+ ([install from rust-lang.org](https://rustup.rs/))
- No other dependencies required (all handled by Cargo)

### Quick Build

```bash
cd pki-rust-poc/est-poc

# Check code compiles
cargo check

# Build debug version (fast, for development)
cargo build

# Build release version (optimized, for production)
cargo build --release
```

The binary will be at:
- Debug: `target/debug/pki-est-server`
- Release: `target/release/pki-est-server`

**For detailed build instructions, troubleshooting, and development workflow, see [BUILD.md](BUILD.md).**

## Running

### Configuration

The server requires four configuration files:

1. **server.conf** - Main server configuration (TOML format)
2. **backend.conf** - CA backend configuration (properties format)
3. **authorizer.conf** - Authorization configuration (properties format)
4. **realm.conf** - Authentication configuration (properties format)

Example configurations are in `examples/config/`.

### Start the Server

```bash
# Using default config path
./target/release/pki-est-server

# Or specify config file
./target/release/pki-est-server examples/config/server.conf

# Development mode with debug logging
RUST_LOG=debug cargo run -- examples/config/server.conf
```

### Testing

Test the EST endpoints using curl:

```bash
# Get CA certificates (no authentication required)
curl http://localhost:8443/.well-known/est/cacerts

# Simple enrollment (requires authentication)
# First, create a CSR
openssl req -new -newkey rsa:2048 -nodes \
  -keyout test.key -out test.csr \
  -subj "/CN=Test Client"

# Base64 encode the CSR (EST requires base64)
BASE64_CSR=$(openssl req -in test.csr -outform DER | base64)

# Submit enrollment request
curl -X POST \
  --user alice:4me2Test \
  -H "Content-Type: application/pkcs10" \
  --data "$BASE64_CSR" \
  http://localhost:8443/.well-known/est/simpleenroll
```

## Configuration Reference

### server.conf

```toml
bind_addr = "0.0.0.0"        # Bind address
port = 8443                   # Server port
tls_cert = "path/to/cert.pem" # TLS certificate
tls_key = "path/to/key.pem"   # TLS private key
backend_config = "backend.conf"
authorizer_config = "authorizer.conf"
realm_config = "realm.conf"
```

### backend.conf

```properties
# Dogtag RA Backend
class=org.dogtagpki.est.DogtagRABackend
url=https://ca.example.com:8443
profile=estServiceCert
username=est-ra-1
password=est4ever
label=SubCA1  # Optional
```

### authorizer.conf

```properties
# External process authorizer
class=org.dogtagpki.est.ExternalProcessRequestAuthorizer
executable=/usr/local/libexec/estauthz

# Or allow all (testing only!)
# class=org.dogtagpki.est.AllowAllRequestAuthorizer
```

### realm.conf

```properties
# In-memory realm
class=com.netscape.cms.realm.PKIInMemoryRealm
username=alice
password=4me2Test
roles=estclient
```

## Differences from Java Implementation

### Advantages

1. **Memory Safety**: Rust prevents buffer overflows, use-after-free, and data races
2. **Performance**: No JVM overhead, smaller memory footprint
3. **Type Safety**: Compile-time guarantees prevent many runtime errors
4. **Modern Async**: Built on Tokio, efficient concurrent request handling
5. **Single Binary**: No Tomcat or application server required
6. **Fast Startup**: Sub-second startup vs. multi-second Tomcat startup

### Current Limitations (PoC)

⚠️ **This is a proof-of-concept for demonstration purposes only. Not production-ready.**

1. **TLS**: Currently HTTP only - **TLS implementation is required for production** (see NEXT-STEPS.md)
2. **Certificate Validation**: Simplified re-enrollment validation (needs strict validation)
3. **PKCS#7**: Simplified PKCS#7 encoding (needs proper CMS implementation)
4. **Error Handling**: Basic error responses (needs enhancement)
5. **Testing**: No unit/integration tests yet
6. **Realm**: Only in-memory realm implemented (needs LDAP support)

## Migration Path

### Phase 1: Proof of Concept (Current)
- ✅ Core EST protocol implementation
- ✅ Backend trait with Dogtag CA support
- ✅ Configuration compatibility
- ✅ Basic authentication and authorization
- ⬜ **TLS support (critical for production)**
- ⬜ Comprehensive testing
- ⬜ Production hardening

### Phase 2: Production Readiness
- Add full TLS/mTLS support with client certificate validation
- Implement proper PKCS#7 certificate chain encoding
- Add LDAP realm for integration with existing deployments
- Comprehensive unit and integration tests
- Performance benchmarking vs. Java version
- Security audit

### Phase 3: Deployment
- Container image (Dockerfile)
- Kubernetes manifests
- Side-by-side deployment with Java version
- Gradual traffic migration
- Production validation

### Phase 4: Feature Parity
- All EST operations
- All backend types
- All realm types
- All authorizer types
- Migration tools

## Performance Expectations

Based on similar Rust web applications:

- **Memory**: ~5-10 MB vs. ~200-500 MB (Java/Tomcat)
- **Startup**: ~100ms vs. ~5-10s (Java/Tomcat)
- **Throughput**: 2-3x improvement expected
- **Latency**: ~30-50% reduction expected

## Development

### Code Structure

```
src/
├── main.rs        # Entry point, server setup
├── lib.rs         # Library exports
├── config.rs      # Configuration types and parsing
├── error.rs       # Error types
├── auth.rs        # Authentication (Realm) and Authorization
├── backend.rs     # Backend trait and implementations
└── handlers.rs    # EST endpoint handlers
```

### Adding a New Backend

Implement the `ESTBackend` trait:

```rust
use async_trait::async_trait;
use crate::backend::{ESTBackend, CertRequest, CertResponse};
use crate::error::Result;

pub struct MyBackend {
    // ... configuration
}

#[async_trait]
impl ESTBackend for MyBackend {
    async fn get_ca_certs(&self, label: Option<&str>) -> Result<Vec<u8>> {
        // ... implementation
    }

    async fn simple_enroll(&self, request: &CertRequest) -> Result<CertResponse> {
        // ... implementation
    }

    async fn simple_reenroll(&self, request: &CertRequest, current_cert: &[u8]) -> Result<CertResponse> {
        // ... implementation
    }
}
```

### Adding a New Realm

Implement the `Realm` trait:

```rust
use crate::auth::{Realm, Principal};
use crate::error::Result;

pub struct MyRealm {
    // ... configuration
}

impl Realm for MyRealm {
    fn authenticate(&self, username: &str, password: &str) -> Result<Principal> {
        // ... implementation
    }
}
```

## Testing

```bash
# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo test

# Run specific test
cargo test test_name

# Integration tests
cargo test --test integration
```

## Benchmarking

```bash
# Build optimized binary
cargo build --release

# Profile
cargo install flamegraph
cargo flamegraph

# Benchmark
cargo install cargo-criterion
cargo criterion
```

## Contributing

This is a proof-of-concept. For production use, additional work is needed:

1. Complete TLS implementation with proper certificate validation
2. Add comprehensive test suite
3. Implement missing realm types (LDAP, file-based)
4. Proper PKCS#7 encoding for certificate responses
5. Better error handling and logging
6. Configuration validation
7. Documentation
8. Security review

## License

Same as Dogtag PKI (GPL v2 with Classpath exception)

## References

- [RFC 7030 - EST Protocol](https://datatracker.ietf.org/doc/html/rfc7030)
- [Dogtag PKI](https://github.com/dogtagpki/pki)
- [Axum Web Framework](https://github.com/tokio-rs/axum)
- [Rustls TLS Library](https://github.com/rustls/rustls)
