# EST Proof of Concept → Production Roadmap

This document outlines the specific steps needed to take the EST proof-of-concept from its current state to production-ready.

## Current Status: ✅ Proof of Concept Complete

**What Works:**
- ✅ Core EST protocol endpoints (`/cacerts`, `/simpleenroll`, `/simplereenroll`)
- ✅ Axum web framework integration
- ✅ Configuration system (TOML + Java properties format)
- ✅ Backend trait with Dogtag CA implementation
- ✅ Basic authentication (in-memory realm)
- ✅ External process authorization
- ✅ Error handling
- ✅ Example configurations

**What's Missing for Production:**
- ⬜ TLS/mTLS support
- ⬜ Proper PKCS#7 encoding
- ⬜ Certificate validation in re-enrollment
- ⬜ LDAP realm implementation
- ⬜ Comprehensive test suite
- ⬜ Logging and metrics
- ⬜ Container deployment
- ⬜ Documentation

## Phase 1: Core Security (2-3 weeks)

### 1.1 Enable TLS Support

**Current State:** HTTP only (insecure)

**Required Changes:**

```rust
// In main.rs, replace plain HTTP with TLS
use axum_server::tls_rustls::RustlsConfig;

let tls_config = RustlsConfig::from_pem_file(
    &server_config.tls_cert,
    &server_config.tls_key
).await?;

let addr = SocketAddr::from_str(&bind_addr)?;
axum_server::bind_rustls(addr, tls_config)
    .serve(app.into_make_service())
    .await?;
```

**Testing:**
- Generate self-signed certificates for testing
- Verify TLS handshake with `openssl s_client`
- Test with curl using `--cacert`

**Effort:** 1-2 days

### 1.2 Client Certificate Authentication (mTLS)

**Required for:** `/simplereenroll` endpoint must validate client certificate

**Implementation:**

```rust
// Add TLS client cert extraction middleware
async fn extract_client_cert(
    mut request: Request,
    next: Next,
) -> Response {
    // Extract peer certificate from TLS connection
    // Insert into request extensions
    // Verify certificate validity
}
```

**Effort:** 2-3 days

### 1.3 Certificate Validation for Re-enrollment

**Current State:** Simplified validation

**Required:** Strict validation as in Java version:
1. Extract subject DN from current certificate
2. Extract SAN extensions from current certificate
3. Compare with CSR subject and SANs
4. Reject if they don't match

**Files to modify:**
- `src/backend.rs` - Add validation logic to `simple_reenroll`

**Effort:** 2-3 days

### 1.4 Proper PKCS#7 Encoding

**Current State:** Returns raw certificate DER

**Required:** Proper PKCS#7 (CMS) encoding for certificate chain

**Options:**
1. Use `cms` crate for full PKCS#7 support
2. Use `x509-cert` crate for certificate chain building

**Implementation:**

```rust
use cms::{signed_data::SignedDataBuilder, content_info::ContentInfo};

fn encode_pkcs7_certs(certs: Vec<Certificate>) -> Result<Vec<u8>> {
    // Build PKCS#7 SignedData structure
    // Add all certificates in chain
    // Encode to DER
}
```

**Effort:** 3-5 days

## Phase 2: Production Features (3-4 weeks)

### 2.1 LDAP Realm Implementation

**Current State:** In-memory only

**Required:** LDAP authentication for production deployments

**Implementation:**

```rust
// In src/auth.rs
use ldap3::{LdapConn, Scope, SearchEntry};

pub struct LdapRealm {
    ldap_url: String,
    base_dn: String,
    user_filter: String,
}

impl Realm for LdapRealm {
    fn authenticate(&self, username: &str, password: &str) -> Result<Principal> {
        let mut ldap = LdapConn::new(&self.ldap_url)?;

        // Search for user
        let search_filter = self.user_filter.replace("{}", username);
        let (rs, _res) = ldap.search(&self.base_dn, Scope::Subtree, &search_filter, vec!["*"])?.success()?;

        // Bind as user to verify password
        // Extract roles from LDAP groups
        // Return Principal
    }
}
```

**Configuration:**

```properties
class=com.netscape.cms.realm.PKILdapRealm
ldap.url=ldaps://ldap.example.com:636
ldap.baseDN=dc=example,dc=com
ldap.userFilter=(uid={})
ldap.roleAttribute=memberOf
```

**Effort:** 5-7 days

### 2.2 Enhanced Logging and Metrics

**Current State:** Basic tracing logs

**Required:**
1. Structured logging with request IDs
2. Prometheus metrics export
3. Performance tracing

**Implementation:**

```rust
// Add to Cargo.toml
metrics = "0.21"
metrics-exporter-prometheus = "0.13"

// In src/main.rs
use metrics_exporter_prometheus::PrometheusBuilder;

PrometheusBuilder::new()
    .with_http_listener(([0, 0, 0, 0], 9090))
    .install()
    .expect("failed to install Prometheus recorder");

// In handlers
use metrics::{counter, histogram};

counter!("est.requests.total", "operation" => operation).increment(1);
let start = Instant::now();
// ... process request ...
histogram!("est.request.duration", "operation" => operation)
    .record(start.elapsed().as_secs_f64());
```

**Metrics to track:**
- Request count by operation
- Request duration by operation
- Error rate by type
- Active connections
- Backend latency

**Effort:** 3-5 days

### 2.3 Request ID Tracking

**Required:** Correlation IDs for distributed tracing

**Implementation:**

```rust
use uuid::Uuid;

async fn request_id_middleware(
    mut request: Request,
    next: Next,
) -> Response {
    let request_id = request
        .headers()
        .get("X-Request-ID")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    request.extensions_mut().insert(RequestId(request_id.clone()));

    tracing::info!(request_id = %request_id, "processing request");

    let mut response = next.run(request).await;
    response.headers_mut().insert(
        "X-Request-ID",
        request_id.parse().unwrap()
    );
    response
}
```

**Effort:** 1-2 days

### 2.4 Health Check Endpoints

**Required:** `/health` and `/ready` endpoints for Kubernetes

**Implementation:**

```rust
// In handlers.rs
pub async fn health_check() -> impl IntoResponse {
    Json(json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

pub async fn readiness_check(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse> {
    // Check backend connectivity
    state.backend.get_ca_certs(None).await?;

    Ok(Json(json!({
        "status": "ready",
        "checks": {
            "backend": "ok"
        }
    })))
}

// In main.rs router
.route("/health", get(health_check))
.route("/ready", get(readiness_check))
```

**Effort:** 1 day

## Phase 3: Testing (3-4 weeks)

### 3.1 Unit Tests

**Coverage targets:**
- Config parsing: 100%
- Error handling: 100%
- Authentication: 90%+
- Authorization: 90%+
- Backend interface: 80%+

**Example:**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_config_parsing() {
        let config = r#"
class=org.dogtagpki.est.DogtagRABackend
url=https://ca.example.com:8443
profile=estServiceCert
username=test
password=test123
        "#;

        let result = BackendConfig::from_properties(config);
        assert!(result.is_ok());

        if let BackendConfig::DogtagRA { url, profile, .. } = result.unwrap() {
            assert_eq!(url, "https://ca.example.com:8443");
            assert_eq!(profile, "estServiceCert");
        }
    }

    #[tokio::test]
    async fn test_in_memory_realm_authentication() {
        let config = RealmConfig::InMemory {
            username: "alice".to_string(),
            password: "secret".to_string(),
            roles: vec!["estclient".to_string()],
        };

        let realm = InMemoryRealm::new(config).unwrap();

        // Valid credentials
        let result = realm.authenticate("alice", "secret");
        assert!(result.is_ok());

        // Invalid credentials
        let result = realm.authenticate("alice", "wrong");
        assert!(result.is_err());
    }
}
```

**Effort:** 1-2 weeks

### 3.2 Integration Tests

**Test scenarios:**
1. Full enrollment flow with real CA
2. Re-enrollment with certificate validation
3. Authorization rejection
4. TLS handshake
5. Client certificate validation
6. Error handling

**Example:**

```rust
// tests/integration_test.rs
use reqwest::Certificate;

#[tokio::test]
async fn test_est_enrollment_flow() {
    // Start test server
    let server = spawn_test_server().await;

    // Get CA certs
    let ca_certs = reqwest::get(format!("{}/cacerts", server.url()))
        .await.unwrap()
        .bytes().await.unwrap();

    // Generate CSR
    let csr = generate_test_csr();

    // Submit enrollment
    let client = reqwest::Client::builder()
        .add_root_certificate(Certificate::from_pem(&ca_certs).unwrap())
        .build().unwrap();

    let response = client.post(format!("{}/simpleenroll", server.url()))
        .basic_auth("alice", Some("secret"))
        .body(base64::encode(&csr))
        .send().await.unwrap();

    assert_eq!(response.status(), 200);

    // Verify certificate
    let cert = response.bytes().await.unwrap();
    verify_certificate(&cert);
}
```

**Effort:** 1-2 weeks

### 3.3 Container Tests

**Reuse existing Dogtag container tests:**

```bash
# In tests/bin/
./runner.sh est-rust

# Test should:
# 1. Build Rust EST container
# 2. Start CA container
# 3. Configure EST to use CA
# 4. Run same tests as Java version
# 5. Verify all operations work
```

**Effort:** 1 week

### 3.4 Performance Benchmarks

**Measure:**
1. Startup time
2. Memory usage (idle and loaded)
3. Request latency (p50, p95, p99)
4. Throughput (requests/second)
5. Concurrent connection handling

**Tools:**
- `criterion` for benchmarks
- `flamegraph` for profiling
- `wrk` or `hey` for load testing

```rust
// benches/enrollment_bench.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn enrollment_benchmark(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let backend = setup_test_backend();
    let csr = generate_test_csr();

    c.bench_function("simple_enroll", |b| {
        b.to_async(&runtime).iter(|| async {
            backend.simple_enroll(black_box(&csr)).await
        });
    });
}

criterion_group!(benches, enrollment_benchmark);
criterion_main!(benches);
```

**Effort:** 3-5 days

## Phase 4: Deployment (2-3 weeks)

### 4.1 Container Image

**Create production Dockerfile:**

```dockerfile
# Multi-stage build
FROM rust:1.75 as builder
WORKDIR /build
COPY . .
RUN cargo build --release

FROM gcr.io/distroless/cc-debian12
COPY --from=builder /build/target/release/pki-est-server /
USER nonroot:nonroot
EXPOSE 8443
ENTRYPOINT ["/pki-est-server"]
```

**Features:**
- Minimal base image (distroless)
- Non-root user
- Health checks
- Configurable via environment

**Effort:** 2-3 days

### 4.2 Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pki-est
spec:
  replicas: 3
  selector:
    matchLabels:
      app: pki-est
  template:
    metadata:
      labels:
        app: pki-est
    spec:
      containers:
      - name: est
        image: pki-est:latest
        ports:
        - containerPort: 8443
          name: https
        - containerPort: 9090
          name: metrics
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8443
            scheme: HTTPS
          initialDelaySeconds: 5
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8443
            scheme: HTTPS
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: config
          mountPath: /etc/pki/est
          readOnly: true
        - name: certs
          mountPath: /etc/pki/certs
          readOnly: true
      volumes:
      - name: config
        configMap:
          name: est-config
      - name: certs
        secret:
          secretName: est-tls
```

**Effort:** 2-3 days

### 4.3 Monitoring Setup

**Prometheus configuration:**

```yaml
scrape_configs:
  - job_name: 'pki-est'
    kubernetes_sd_configs:
    - role: pod
    relabel_configs:
    - source_labels: [__meta_kubernetes_pod_label_app]
      regex: pki-est
      action: keep
    - source_labels: [__meta_kubernetes_pod_container_port_name]
      regex: metrics
      action: keep
```

**Grafana dashboard:**
- Request rate by operation
- Error rate
- Latency percentiles
- Active connections
- Backend latency

**Effort:** 2-3 days

### 4.4 Documentation

**Required documentation:**
1. Installation guide
2. Configuration reference
3. Operations runbook
4. Troubleshooting guide
5. Migration guide from Java version

**Effort:** 3-5 days

## Phase 5: Production Validation (2-4 weeks)

### 5.1 Staging Deployment

1. Deploy alongside Java version
2. Configure load balancer for 10% traffic to Rust
3. Monitor for errors and performance
4. Gradually increase to 50%, 100%

### 5.2 Security Audit

**Areas to review:**
1. TLS configuration (ciphers, protocols)
2. Certificate validation logic
3. Authentication and authorization
4. Input validation
5. Error message information disclosure
6. Dependency vulnerabilities (`cargo audit`)

### 5.3 Performance Validation

**Compare against Java version:**
- Memory usage under load
- Request latency
- Throughput
- Startup time
- Resource utilization

### 5.4 Rollback Plan

**If issues found:**
1. Immediate: Shift traffic back to Java
2. Document issue
3. Fix in development
4. Re-test in staging
5. Try again

## Estimated Timeline

| Phase | Duration | Can Start After |
|-------|----------|----------------|
| 1. Core Security | 2-3 weeks | Immediately |
| 2. Production Features | 3-4 weeks | Phase 1 complete |
| 3. Testing | 3-4 weeks | Phase 2 complete |
| 4. Deployment | 2-3 weeks | Phase 3 complete |
| 5. Production Validation | 2-4 weeks | Phase 4 complete |

**Total: 12-18 weeks (3-4.5 months)**

With parallel work:
- Security + Features: Overlap 1-2 weeks
- Testing during Features: Overlap 1 week
- Deployment prep during Testing: Overlap 1 week

**Optimistic: 10-12 weeks (2.5-3 months)**

## Success Criteria

Before declaring production-ready:

- [ ] All security features implemented (TLS, mTLS, validation)
- [ ] 80%+ test coverage
- [ ] All container tests passing
- [ ] Performance meets or exceeds Java version
- [ ] Security audit complete with no critical issues
- [ ] Documentation complete
- [ ] Successful staging deployment
- [ ] Team trained on Rust debugging
- [ ] Runbooks created
- [ ] Rollback plan tested

## Resources Needed

**Team:**
- 1-2 Rust developers (full-time)
- 1 DevOps engineer (part-time)
- 1 Security engineer (review only)
- Existing PKI maintainers (guidance)

**Infrastructure:**
- Development environment
- Staging environment (mirrors production)
- Container registry
- CI/CD pipeline

**Time:**
- 3-4 months for production-ready
- Additional 1-2 months for full production validation

## Risks and Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| TLS compatibility issues | Low | High | Extensive testing with various clients |
| LDAP integration bugs | Medium | Medium | Thorough integration testing |
| Performance regression | Low | High | Continuous benchmarking |
| Production issues | Medium | High | Staged rollout, rollback plan |
| Team learning curve | Medium | Medium | Training, pair programming |

## Conclusion

The EST proof-of-concept demonstrates feasibility. With focused effort, a production-ready Rust EST implementation is achievable in **3-4 months**. The incremental approach minimizes risk while delivering value through improved performance and resource efficiency.

**Recommended next step:** Approve Phase 1 (Core Security) and assign resources to begin implementation.
