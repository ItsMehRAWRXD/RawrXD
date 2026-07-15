# Batch 6: Docker Containerization
#
# Provides reproducible benchmark execution environment
# Supports both CPU and GPU (CUDA) execution
#
# Build:
#   docker build -t rawrxd-benchmarks .
#
# Run (CPU):
#   docker run -v $(pwd)/results:/results rawrxd-benchmarks --mode quick
#
# Run (GPU):
#   docker run --gpus all -v $(pwd)/results:/results rawrxd-benchmarks --mode standard

# ============================================================================
# Stage 1: Build Environment
# ============================================================================
FROM ubuntu:22.04 AS builder

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    curl \
    wget \
    ninja-build \
    pkg-config \
    libcurl4-openssl-dev \
    nlohmann-json3-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy source code
COPY . .

# Build benchmark suite
RUN cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_BENCHMARKS=ON \
    -DCMAKE_INSTALL_PREFIX=/opt/benchmarks \
    && cmake --build build --parallel $(nproc)

# Install
RUN cmake --install build

# ============================================================================
# Stage 2: Runtime Environment
# ============================================================================
FROM ubuntu:22.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libcurl4 \
    python3 \
    python3-pip \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies for analysis
RUN pip3 install \
    matplotlib \
    pandas \
    numpy \
    requests

# Copy built binaries
COPY --from=builder /opt/benchmarks /opt/benchmarks

# Copy scripts
COPY scripts/ /opt/benchmarks/scripts/

# Create results directory
RUN mkdir -p /results && chmod 777 /results

# Set environment
ENV PATH="/opt/benchmarks/bin:${PATH}"
ENV BENCHMARK_HOME="/opt/benchmarks"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command
ENTRYPOINT ["/opt/benchmarks/bin/benchmark_runner"]
CMD ["--help"]

# ============================================================================
# Stage 3: GPU Runtime (CUDA)
# ============================================================================
FROM nvidia/cuda:12.0-runtime-ubuntu22.04 AS gpu-runtime

ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libcurl4 \
    python3 \
    python3-pip \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip3 install \
    matplotlib \
    pandas \
    numpy \
    requests

# Copy from builder
COPY --from=builder /opt/benchmarks /opt/benchmarks
COPY scripts/ /opt/benchmarks/scripts/

# Create results directory
RUN mkdir -p /results && chmod 777 /results

ENV PATH="/opt/benchmarks/bin:${PATH}"
ENV BENCHMARK_HOME="/opt/benchmarks"
ENV NVIDIA_VISIBLE_DEVICES=all
ENV NVIDIA_DRIVER_CAPABILITIES=compute,utility

ENTRYPOINT ["/opt/benchmarks/bin/benchmark_runner"]
CMD ["--help"]
