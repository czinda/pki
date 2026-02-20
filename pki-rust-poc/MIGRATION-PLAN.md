# Dogtag PKI Migration to Rust - Implementation Plan

## Executive Summary

This document outlines a strategic plan to migrate Dogtag PKI from Java/Tomcat to Rust, prioritizing memory safety, performance, and maintainability while minimizing risk through incremental migration.

## Rationale

### Why Migrate from Java?

1. **Memory Safety**: Rust prevents entire classes of vulnerabilities (buffer overflows, use-after-free, data races) at compile time
2. **Performance**: No GC pauses, lower memory footprint, faster startup times
3. **Modern Tooling**: Cargo provides excellent dependency management and build system
4. **Operational Efficiency**: Single binary deployment, no application server required
5. **Future-Proofing**: Growing ecosystem, NIST and security community embrace

### Why Rust Specifically?

For a security-critical PKI system, Rust offers:
- **Zero-cost abstractions** while maintaining safety
- **Excellent cryptography libraries** (rustls, ring, x509-parser)
- **Strong type system** prevents many logic errors at compile-time
- **Fearless concurrency** for handling high certificate loads
- **WebAssembly support** for potential browser-based tooling

## Migration Strategy: Incremental Approach

### Phase 1: EST Subsystem (Months 1-3)

**Why EST First?**
- Smallest subsystem (~2,000 LOC in Java)
- Newest code, fewer legacy dependencies
- Well-defined protocol (RFC 7030)
- Standalone - doesn't require other subsystems
- Can run in parallel with Java version

**Deliverables:**
1. ✅ Proof-of-concept (DONE - see `pki-rust-poc/est-poc/`)
2. Full RFC 7030 compliance
3. Production TLS/mTLS support
4. Comprehensive test suite
5. LDAP realm integration
6. Container-based deployment
7. Performance benchmarks vs. Java

**Success Metrics:**
- Feature parity with Java EST
- 50%+ reduction in memory usage
- 2x improvement in request throughput
- <100ms startup time
- All container tests passing

### Phase 2: ACME Subsystem (Months 4-6)

**Why ACME Second?**
- Small subsystem (~5,000 LOC)
- Well-defined protocol (RFC 8555)
- Growing importance (Let's Encrypt, automated cert management)
- Relatively stateless operations
- Benefits from high-performance async I/O

**Deliverables:**
1. Core ACME protocol (newAccount, newOrder, finalize, etc.)
2. ACME challenges (http-01, dns-01, tls-alpn-01)
3. NSS database integration
4. PostgreSQL backend support
5. Integration tests with certbot/acme.sh

**Shared Infrastructure:**
- Common configuration system
- Shared authentication/authorization framework
- Database abstraction layer
- Logging and monitoring

### Phase 3: OCSP Subsystem (Months 7-9)

**Why OCSP Third?**
- Performance-critical (high request volume)
- Stateless operations (good fit for Rust)
- ~3,000 LOC, relatively simple
- Significant performance gains expected

**Deliverables:**
1. OCSP responder implementation (RFC 6960)
2. LDAP directory integration
3. Response caching layer
4. Nonce handling
5. Load testing to 10,000+ req/sec

**Key Challenges:**
- High-performance LDAP client in Rust
- Efficient certificate status caching
- Response signing performance

### Phase 4: Core Libraries (Months 10-12)

**Shared Component Development:**

1. **pki-common** crate:
   - X.509 certificate handling
   - CSR processing
   - Key management
   - Crypto utilities
   - Configuration management

2. **pki-database** crate:
   - LDAP abstraction layer
   - SQL support (PostgreSQL, SQLite)
   - Migration tools
   - Connection pooling

3. **pki-server** crate:
   - HTTP server framework
   - Authentication/authorization
   - Logging and metrics
   - Configuration management
   - Plugin system

4. **pki-tools** crate:
   - CLI utilities (certificate tools)
   - Certificate verification
   - Key generation

### Phase 5: TKS Subsystem (Months 13-15)

**Token Key Service Migration:**
- HSM integration (PKCS#11)
- Key wrapping/unwrapping
- Token management
- ~4,000 LOC

**Key Challenges:**
- PKCS#11 Rust bindings
- HSM compatibility testing
- Key material security

### Phase 6: KRA Subsystem (Months 16-20)

**Key Recovery Authority Migration:**
- Key archival
- Key recovery
- Approval workflows
- ~6,000 LOC

**Key Challenges:**
- Complex approval workflows
- Secure key storage
- LDAP-based request management

### Phase 7: CA Subsystem (Months 21-30)

**Certificate Authority - The Final Boss:**

**Why CA Last?**
- Most complex subsystem (~30,000+ LOC)
- Critical to entire PKI infrastructure
- Most dependencies on other components
- Requires all shared libraries to be mature
- Highest risk

**Phased Approach:**

1. **Months 21-23: CA Core**
   - Certificate issuance engine
   - Profile processing
   - Certificate lifecycle
   - Database operations

2. **Months 24-26: CA Features**
   - Certificate revocation (CRL, CRL Distribution Points)
   - Certificate renewal
   - Serial number management
   - Certificate publishing

3. **Months 27-28: Advanced Features**
   - Sub-CA support
   - External CA integration
   - Custom extensions
   - Approval workflows

4. **Months 29-30: Hardening & Migration**
   - Security audit
   - Performance optimization
   - Migration tools
   - Rollback procedures

### Phase 8: TPS Subsystem (If Needed - Months 31-36)

**Token Processing System:**
- Smartcard enrollment
- Token lifecycle management
- Most hardware-dependent
- Evaluate if needed (declining usage)

## Technical Architecture

### Target Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Rust PKI Services                     │
├──────────────┬──────────────┬──────────────┬────────────┤
│   EST        │    ACME      │    OCSP      │     CA     │
│  (Axum)      │   (Axum)     │   (Axum)     │   (Axum)   │
├──────────────┴──────────────┴──────────────┴────────────┤
│              Shared Server Framework                     │
│  (Auth, Authorization, Logging, Config, Metrics)        │
├─────────────────────────────────────────────────────────┤
│              Common Libraries (pki-common)               │
│     (X.509, Crypto, CSR, Keys, Profiles)                │
├─────────────────────────────────────────────────────────┤
│          Database Layer (pki-database)                   │
│        (LDAP, PostgreSQL, Connection Pool)              │
├─────────────────────────────────────────────────────────┤
│              Crypto & Hardware Layer                     │
│        (rustls, ring, PKCS#11, HSM Support)             │
└─────────────────────────────────────────────────────────┘
```

### Technology Stack

| Component | Technology |
|-----------|------------|
| Web Framework | Axum 0.7+ |
| TLS | rustls 0.23+ |
| Async Runtime | Tokio 1.x |
| Serialization | serde, serde_json |
| X.509/Crypto | x509-parser, rcgen, ring, rustls |
| LDAP Client | ldap3 |
| SQL | sqlx (async) |
| HTTP Client | reqwest |
| Config | TOML, serde |
| Logging | tracing, tracing-subscriber |
| Metrics | prometheus |
| CLI | clap |

### Crate Organization

```
pki-rust/
├── crates/
│   ├── pki-common/         # Shared types, crypto, utilities
│   ├── pki-database/       # Database abstraction
│   ├── pki-server/         # Server framework
│   ├── pki-est/            # EST subsystem
│   ├── pki-acme/           # ACME subsystem
│   ├── pki-ocsp/           # OCSP subsystem
│   ├── pki-tks/            # TKS subsystem
│   ├── pki-kra/            # KRA subsystem
│   ├── pki-ca/             # CA subsystem
│   └── pki-tools/          # CLI tools
├── tests/
│   └── integration/        # Integration tests
└── docs/                   # Documentation
```

## Compatibility & Migration

### Configuration Compatibility

- Support existing configuration file formats during transition
- Provide migration tools for config conversion
- Maintain Java property file format for smoother adoption

### API Compatibility

- Maintain REST API compatibility
- Same URL paths and endpoints
- Compatible request/response formats
- OpenAPI/Swagger documentation

### Database Compatibility

- Support existing LDAP schema
- Migration tools for any schema changes
- Gradual migration support
- Rollback capabilities

### Client Compatibility

- All existing clients work unchanged
- Python `pki` CLI continues to work
- Browser enrollment unchanged

## Deployment Strategy

### Parallel Deployment (Recommended)

1. **Side-by-side**: Run Rust and Java versions simultaneously
2. **Traffic splitting**: Gradually shift traffic to Rust version
3. **Canary releases**: Deploy to small subset first
4. **A/B testing**: Compare performance and reliability
5. **Rollback ready**: Keep Java version running until proven

### Container-Based Deployment

```yaml
# Example deployment progression
Stage 1: Java-only (current)
  - pki-ca:10.x (Java)
  - pki-kra:10.x (Java)
  - pki-ocsp:10.x (Java)

Stage 2: EST migration
  - pki-ca:10.x (Java)
  - pki-kra:10.x (Java)
  - pki-ocsp:10.x (Java)
  - pki-est:rust (NEW)

Stage 3: ACME migration
  - pki-ca:10.x (Java)
  - pki-kra:10.x (Java)
  - pki-ocsp:10.x (Java)
  - pki-est:rust
  - pki-acme:rust (NEW)

Stage N: Full migration
  - pki-ca:rust
  - pki-kra:rust
  - pki-ocsp:rust
  - pki-est:rust
  - pki-acme:rust
  - pki-tks:rust
```

## Risk Mitigation

### Technical Risks

| Risk | Mitigation |
|------|------------|
| Crypto compatibility | Extensive test suite, use proven libraries (rustls, ring) |
| LDAP integration | Start with well-tested ldap3 crate, contribute improvements |
| HSM support | PKCS#11 bindings exist, validate with target HSMs early |
| Performance regression | Benchmark each subsystem, should see improvements |
| Protocol compatibility | Comprehensive integration tests, RFC compliance tests |

### Project Risks

| Risk | Mitigation |
|------|------------|
| Team Rust expertise | Training, pair programming, code reviews |
| Timeline slippage | Incremental approach allows adjustment |
| Community resistance | Maintain Java version in parallel, demonstrate benefits |
| Hidden complexity | Prototype each subsystem before full implementation |

### Operational Risks

| Risk | Mitigation |
|------|------------|
| Production issues | Phased rollout, extensive testing, rollback plan |
| Monitoring gaps | Implement comprehensive metrics from day one |
| Debug tooling | Build Rust debugging expertise, logging |

## Resource Requirements

### Team Composition

- 2-3 senior Rust developers (can train existing Java team)
- 1 DevOps engineer (container/deployment expertise)
- 1 security engineer (crypto/security review)
- Existing PKI maintainers (domain knowledge)

### Infrastructure

- CI/CD pipeline for Rust builds
- Container registry for images
- Test environment for parallel deployment
- HSM access for testing
- Performance testing infrastructure

## Success Criteria

### Technical Metrics

- [ ] All container tests passing for each subsystem
- [ ] <100ms startup time (vs. 5-10s Java)
- [ ] <50MB memory footprint per subsystem (vs. 200-500MB Java)
- [ ] 2x+ throughput improvement
- [ ] 50%+ latency reduction
- [ ] RFC compliance for all protocols

### Quality Metrics

- [ ] 80%+ code coverage
- [ ] No critical security vulnerabilities
- [ ] Zero data loss during migration
- [ ] No breaking API changes for clients
- [ ] Comprehensive documentation

### Operational Metrics

- [ ] Successful production deployment
- [ ] <1 hour to deploy new version
- [ ] <5 minute rollback time
- [ ] Monitoring and alerting in place
- [ ] Runbooks for common issues

## Decision Points

### Go/No-Go Gates

**After Phase 1 (EST):**
- Evaluate: Performance gains, code quality, team velocity
- Decision: Continue with ACME or adjust approach

**After Phase 3 (OCSP):**
- Evaluate: Architecture maturity, shared library stability
- Decision: Commit to CA migration or maintain hybrid

**After Phase 6 (Before CA):**
- Evaluate: All shared libraries mature, team experienced
- Decision: Green-light CA migration

## Alternatives Considered

### Alternative 1: Big Bang Rewrite
- **Pros**: Clean slate, no hybrid complexity
- **Cons**: High risk, long time before any value
- **Decision**: Rejected - too risky

### Alternative 2: Maintain Java
- **Pros**: No migration effort
- **Cons**: Memory safety issues remain, performance limited
- **Decision**: Rejected - doesn't solve core problems

### Alternative 3: Hybrid (Java CA + Rust subsystems)
- **Pros**: Lower risk, incremental value
- **Cons**: Maintain two codebases longer
- **Decision**: Acceptable fallback position

### Alternative 4: Go Instead of Rust
- **Pros**: Easier to learn, faster development
- **Cons**: GC pauses, less memory safety guarantees
- **Decision**: Rejected for crypto-critical code

## Timeline Summary

| Phase | Duration | Deliverable | Team Size |
|-------|----------|-------------|-----------|
| 1. EST | 3 months | Production EST in Rust | 2-3 |
| 2. ACME | 3 months | Production ACME in Rust | 2-3 |
| 3. OCSP | 3 months | Production OCSP in Rust | 3-4 |
| 4. Core Libs | 3 months | Mature shared libraries | 3-4 |
| 5. TKS | 3 months | Production TKS in Rust | 3-4 |
| 6. KRA | 4 months | Production KRA in Rust | 3-4 |
| 7. CA | 10 months | Production CA in Rust | 4-5 |
| 8. TPS (optional) | 6 months | Production TPS in Rust | 2-3 |

**Total: 2.5-3 years for complete migration**

## Conclusion

This incremental migration strategy balances risk with reward, delivering value early (EST, ACME, OCSP) while building toward the ultimate goal of a fully memory-safe PKI system. The key is starting small, proving the approach, and building team expertise before tackling the complex CA subsystem.

The EST proof-of-concept demonstrates technical feasibility. The path forward is clear, achievable, and delivers measurable improvements at each phase.
