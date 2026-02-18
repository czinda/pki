# Multi-stage Dockerfile for EST server

# Build stage
FROM rust:1.75 as builder

WORKDIR /build

# Copy manifests
COPY Cargo.toml ./

# Create dummy src to cache dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy actual source
COPY src ./src

# Build release binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash est

# Copy binary from builder
COPY --from=builder /build/target/release/pki-est-server /usr/local/bin/

# Copy example configs
COPY examples /etc/pki/est/examples

# Make authorizer executable
RUN chmod +x /etc/pki/est/examples/estauthz

# Set ownership
RUN chown -R est:est /etc/pki/est

USER est
WORKDIR /home/est

EXPOSE 8443

ENTRYPOINT ["/usr/local/bin/pki-est-server"]
CMD ["/etc/pki/est/examples/config/server.conf"]
