#============================================================================
# Dockerfile for RawrXD N-EVM Validation Framework
# Multi-stage build for production use
#============================================================================

# Stage 1: Build
FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libjsoncpp-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
WORKDIR /build
COPY src/nevm /build/src/nevm

# Build the framework
RUN cd /build/src/nevm && \
    mkdir -p build && cd build && \
    cmake .. && \
    make -j$(nproc)

# Stage 2: Runtime
FROM ubuntu:22.04 AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libjsoncpp25 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash nevm

# Copy built binaries
COPY --from=builder /build/src/nevm/build/bin/nevm_validate /usr/local/bin/
COPY --from=builder /build/src/nevm/build/bin/nevm_generate_golden /usr/local/bin/

# Set permissions
RUN chmod +x /usr/local/bin/nevm_validate /usr/local/bin/nevm_generate_golden

# Switch to non-root user
USER nevm

# Set working directory
WORKDIR /workspace

# Default command
ENTRYPOINT ["nevm_validate"]
CMD ["--help"]

# Labels
LABEL maintainer="RawrXD Team"
LABEL description="RawrXD N-EVM Validation Framework"
LABEL version="1.0.0"
