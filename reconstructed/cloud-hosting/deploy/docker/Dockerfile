# ============================================================================
# RawrXD Cloud-Hosting: llama.cpp Inference Server
# Production-Ready Multi-Stage Build  
# ============================================================================
FROM ubuntu:22.04 AS builder

ARG LLAMA_CPP_VERSION=b5560
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN git clone --depth 1 --branch ${LLAMA_CPP_VERSION} \
    https://github.com/ggml-org/llama.cpp.git . \
    && cmake -B build -DGGML_NATIVE=OFF -DLLAMA_SERVER=ON \
    && cmake --build build --config Release -j$(nproc) --target llama-server

# --- Runtime ---
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /bin/false llama

COPY --from=builder /build/build/bin/llama-server /usr/local/bin/
RUN chmod +x /usr/local/bin/llama-server

VOLUME /models
USER llama
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["llama-server"]
CMD ["--host", "0.0.0.0", "--port", "8080", "-m", "/models/model.gguf", "-ngl", "99", "-c", "4096"]
