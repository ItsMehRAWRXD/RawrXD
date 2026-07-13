# RawrXD Sovereign Inferencer - Production Dockerfile
# Phase S.2: Container deployment with multi-stage build

# Build stage
FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    wget \
    python3 \
    python3-pip \
    libssl-dev \
    libcurl4-openssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install Vulkan SDK
RUN wget -qO - https://packages.lunarg.com/lunarg-signing-key-pub.asc | apt-key add - && \
    wget -qO /etc/apt/sources.list.d/lunarg-vulkan-jammy.list https://packages.lunarg.com/vulkan/lunarg-vulkan-jammy.list && \
    apt-get update && \
    apt-get install -y vulkan-sdk

# Set working directory
WORKDIR /build

# Copy source code
COPY . .

# Build RawrXD
RUN mkdir -p build && cd build && \
    cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/opt/rawrxd \
    -DRAWRXD_ENABLE_VULKAN=ON \
    -DRAWRXD_ENABLE_CUDA=OFF \
    -DRAWRXD_ENABLE_TESTS=OFF && \
    make -j$(nproc) && \
    make install

# Runtime stage
FROM ubuntu:22.04 AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    libcurl4 \
    vulkan-tools \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r rawrxd && useradd -r -g rawrxd -s /bin/false rawrxd

# Copy built binaries
COPY --from=builder /opt/rawrxd /opt/rawrxd

# Copy configuration
COPY --from=builder /build/config /etc/rawrxd

# Create directories
RUN mkdir -p /var/lib/rawrxd/models \
    /var/lib/rawrxd/cache \
    /var/log/rawrxd \
    /var/run/rawrxd && \
    chown -R rawrxd:rawrxd /var/lib/rawrxd /var/log/rawrxd /var/run/rawrxd

# Set environment
ENV PATH="/opt/rawrxd/bin:${PATH}"
ENV RAWRXD_CONFIG_PATH="/etc/rawrxd"
ENV RAWRXD_MODEL_PATH="/var/lib/rawrxd/models"
ENV RAWRXD_LOG_PATH="/var/log/rawrxd"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD rawrxd-cli health || exit 1

# Expose ports
EXPOSE 8080 8443 9090

# Switch to non-root user
USER rawrxd

# Entry point
ENTRYPOINT ["rawrxd-server"]
CMD ["--config", "/etc/rawrxd/config.yaml"]
