FROM rust:bullseye-slim as builder

WORKDIR /app
COPY . .

# Install build dependencies for Debian
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

RUN cargo build --release --locked


# RUNTIME STAGE
FROM debian:bullseye-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl1.1 \
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
CMD ["--help"]