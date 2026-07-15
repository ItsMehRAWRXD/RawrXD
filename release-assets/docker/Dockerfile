# RawrXD Sovereign v1.0.0 - Production Dockerfile
# Multi-stage build for minimal, secure runtime image

# Build stage
FROM ubuntu:24.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    wget \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy source code
COPY . /build/

# Build RawrXD
RUN mkdir -p build && cd build && \
    cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DGGML_VULKAN=ON \
    -DGGML_NATIVE=ON \
    -DCMAKE_CXX_FLAGS="-O3 -march=native" && \
    cmake --build . --config Release -j$(nproc)

# Runtime stage
FROM ubuntu:24.04 AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libvulkan1 \
    vulkan-tools \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash rawrxd

# Set working directory
WORKDIR /app

# Copy binaries from builder
COPY --from=builder /build/build/bin/RawrXD /app/
COPY --from=builder /build/build/bin/benchmark_runner /app/
COPY --from=builder /build/config/ /app/config/
COPY --from=builder /build/scripts/ /app/scripts/

# Create necessary directories
RUN mkdir -p /app/models /app/logs /app/data && \
    chown -R rawrxd:rawrxd /app

# Switch to non-root user
USER rawrxd

# Expose API port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command
ENTRYPOINT ["./RawrXD"]
CMD ["--config", "config/production.yaml"]
