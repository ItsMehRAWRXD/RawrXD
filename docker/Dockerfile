# RawrXD Docker Image
# Phase AJ: Deployment Automation

# Build stage
FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    git \
    python3 \
    python3-pip \
    wget \
    curl \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install CUDA (optional, for GPU support)
ARG CUDA_VERSION=12.1
RUN if [ "${CUDA_VERSION}" != "none" ]; then \
    wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-keyring_1.0-1_all.deb && \
    dpkg -i cuda-keyring_1.0-1_all.deb && \
    apt-get update && \
    apt-get install -y cuda-toolkit-${CUDA_VERSION//./-} && \
    rm -rf /var/lib/apt/lists/*; \
    fi

# Set working directory
WORKDIR /build

# Copy source code
COPY . .

# Build RawrXD
RUN mkdir -p build && cd build && \
    cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/opt/rawrxd \
    -DRAWRXD_BUILD_TESTS=OFF \
    -DRAWRXD_BUILD_EXAMPLES=OFF \
    -DRAWRXD_CUDA=${CUDA_VERSION:+ON} \
    -GNinja && \
    ninja -j$(nproc) && \
    ninja install

# Runtime stage
FROM ubuntu:22.04 AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    libgomp1 \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy CUDA libraries if needed
COPY --from=builder /usr/local/cuda/lib64 /usr/local/cuda/lib64
ENV LD_LIBRARY_PATH=/usr/local/cuda/lib64:${LD_LIBRARY_PATH}

# Create rawrxd user
RUN useradd -m -s /bin/bash rawrxd

# Copy built binaries
COPY --from=builder /opt/rawrxd /opt/rawrxd

# Set up directories
RUN mkdir -p /data/models /data/cache /logs /config && \
    chown -R rawrxd:rawrxd /data /logs /config

# Switch to rawrxd user
USER rawrxd

# Set environment variables
ENV PATH=/opt/rawrxd/bin:${PATH}
ENV RAWRXD_HOME=/data
ENV RAWRXD_CONFIG=/config
ENV RAWRXD_LOGS=/logs

# Expose ports
EXPOSE 8080
EXPOSE 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command
ENTRYPOINT ["rawrxd"]
CMD ["--config", "/config/rawrxd.json", "--serve"]
