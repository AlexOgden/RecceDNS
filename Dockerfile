FROM rust:slim-bookworm AS builder

WORKDIR /app
COPY . .

# Build the binary with optimizations and locked dependencies.
# TLS uses rustls (ring), so no OpenSSL or pkg-config is required.
RUN cargo build --release --locked


# RUNTIME STAGE
FROM debian:bookworm-slim

# Install runtime dependencies (CA certs only; rustls is statically linked)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m reccedns

# Copy only the binary
COPY --from=builder /app/target/release/reccedns /usr/local/bin/

# Switch to non-root user
USER reccedns

# Create volume mount point for wordlists and data
VOLUME ["/wordlists", "/data"]
WORKDIR /data

ENTRYPOINT ["reccedns"]