FROM rust:slim-bullseye as builder

WORKDIR /app
COPY . .

# Install build dependencies for Debian
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Build the binary with optimizations and locked dependencies
RUN cargo build --release --locked


# RUNTIME STAGE
FROM debian:bullseye-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl1.1 \
    ca-certificates \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Increase system limits for file descriptors and network connections
RUN echo "* soft nofile 65536" >> /etc/security/limits.conf && \
    echo "* hard nofile 65536" >> /etc/security/limits.conf && \
    echo "net.ipv4.ip_local_port_range = 1024 65535" >> /etc/sysctl.conf && \
    echo "net.ipv4.tcp_tw_reuse = 1" >> /etc/sysctl.conf && \
    echo "net.core.somaxconn = 65535" >> /etc/sysctl.conf && \
    echo "net.ipv4.tcp_max_syn_backlog = 65535" >> /etc/sysctl.conf && \
    echo "net.core.netdev_max_backlog = 65535" >> /etc/sysctl.conf

    
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