# RAWRXD Compiler Driver - Docker Build
# Multi-stage build for minimal image size

# Stage 1: Build
FROM gcc:latest AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    make \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
COPY include/ ./include/
COPY src/ ./src/
COPY Makefile ./

# Build the compiler driver
RUN make clean && make

# Stage 2: Runtime
FROM debian:stable-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    nasm \
    && rm -rf /var/lib/apt/lists/*

# Copy built binary
COPY --from=builder /build/bin/rawrxd-compiler /usr/local/bin/

# Create working directory
RUN mkdir -p /workspace
WORKDIR /workspace

# Set entrypoint
ENTRYPOINT ["rawrxd-compiler"]
CMD ["--help"]

# Labels
LABEL maintainer="RAWRXD Team"
LABEL version="1.0.0"
LABEL description="RAWRXD Compiler Driver - Unified compiler for C, Assembly, and C#"
