# Multi-stage build for llama.cpp server with quantized model support
FROM ubuntu:22.04 as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Clone and build llama.cpp
WORKDIR /build
RUN git clone https://github.com/ggerganov/llama.cpp.git && \
    cd llama.cpp && \
    mkdir build && \
    cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release && \
    cmake --build . --config Release -j $(nproc)

# Runtime stage
FROM ubuntu:22.04

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    libgomp1 \
    curl \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy built llama.cpp server
COPY --from=builder /build/llama.cpp/build/bin/server /usr/local/bin/llama-server

# Create models directory
RUN mkdir -p /models

WORKDIR /app

# Expose API port
EXPOSE 8080

# Default command: run server with CPU-only mode
ENTRYPOINT ["/usr/local/bin/llama-server"]
CMD ["--host", "0.0.0.0", "--port", "8080", "--threads", "2"]
