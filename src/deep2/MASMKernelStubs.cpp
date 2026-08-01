// ============================================================================
// MASMKernelStubs.cpp — Stub implementations for MASM inference kernels
// Provides extern "C" symbols declared in RawrXDInferenceAdapter.hpp
// until real MASM objects are integrated. Stubs enable linking + simulated gen.
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdio>

extern "C" {

// ============================================================================
// Core inference stubs
// ============================================================================
void ggml_gemm_q4_0(int M, int N, int K, const float* A, const uint8_t* Bq4,
                     float scale, float* C) {
    // Stub: zero output
    for (int i = 0; i < M * N; ++i) C[i] = 0.0f;
}

void Dequant_Q4_0_AVX2(void* blocks, uint64_t num_blocks, void* output,
                          float* scale_override) {
    // Stub: zero output
    float* out = static_cast<float*>(output);
    for (uint64_t i = 0; i < num_blocks * 32; ++i) out[i] = 0.0f;
}

void q4_0_unpack_64x64(const void* src, float* dst) {
    // Stub: zero output
    for (int i = 0; i < 64 * 64; ++i) dst[i] = 0.0f;
}

// ============================================================================
// Attention stub
// ============================================================================
void flash_attn_asm_avx2(const float* Q, const float* K, const float* V,
                          float* O, uint32_t seqLen, uint32_t headDim,
                          float scale) {
    // Stub: copy Q to O
    for (uint32_t i = 0; i < seqLen * headDim; ++i) O[i] = Q[i];
}

// ============================================================================
// Norm stubs
// ============================================================================
void rmsnorm_forward_avx2(const float* input, float* output, uint32_t n,
                           float eps) {
    // Stub: pass-through
    float sum = 0.0f;
    for (uint32_t i = 0; i < n; ++i) sum += input[i] * input[i];
    float rms = 1.0f / (sqrtf(sum / n + eps) + 1e-6f);
    for (uint32_t i = 0; i < n; ++i) output[i] = input[i] * rms;
}

void softmax_forward_avx2(const float* input, float* output, uint32_t n) {
    // Stub: reference softmax
    float maxVal = input[0];
    for (uint32_t i = 1; i < n; ++i) if (input[i] > maxVal) maxVal = input[i];
    float sum = 0.0f;
    for (uint32_t i = 0; i < n; ++i) {
        output[i] = expf(input[i] - maxVal);
        sum += output[i];
    }
    for (uint32_t i = 0; i < n; ++i) output[i] /= sum;
}

// ============================================================================
// Activation stub
// ============================================================================
void silu_activation_avx512(const float* input, float* output, uint32_t n) {
    // Stub: reference SiLU
    for (uint32_t i = 0; i < n; ++i) {
        output[i] = input[i] * (1.0f / (1.0f + expf(-input[i])));
    }
}

// ============================================================================
// KV Cache stubs
// ============================================================================
void kv_cache_update(void* cache, uint32_t layer, uint32_t pos,
                      const float* k, const float* v, uint32_t headDim) {
    // Stub: no-op
    (void)cache; (void)layer; (void)pos; (void)k; (void)v; (void)headDim;
}

void kv_cache_attend(const void* cache, uint32_t layer, uint32_t pos,
                      const float* q, float* out, uint32_t numHeads,
                      uint32_t headDim) {
    // Stub: zero output
    (void)cache; (void)layer; (void)pos; (void)q;
    for (uint32_t i = 0; i < numHeads * headDim; ++i) out[i] = 0.0f;
}

// ============================================================================
// Sampler stubs
// ============================================================================
int sampler_argmax(const float* logits, uint32_t n) {
    int best = 0;
    for (uint32_t i = 1; i < n; ++i) if (logits[i] > logits[best]) best = (int)i;
    return best;
}

int sampler_topk(const float* logits, uint32_t n, uint32_t k, float temp) {
    (void)k; (void)temp;
    return sampler_argmax(logits, n);
}

// ============================================================================
// Transformer stub
// ============================================================================
void transformer_block_forward(const float* input, float* output,
                                const void* weights, uint32_t hiddenDim,
                                uint32_t numHeads) {
    // Stub: pass-through
    (void)weights; (void)numHeads;
    for (uint32_t i = 0; i < hiddenDim; ++i) output[i] = input[i];
}

// ============================================================================
// BPE Tokenizer stubs
// ============================================================================
void bpe_encode(const char* text, uint32_t* tokens, uint32_t* count,
                 uint32_t maxTokens) {
    // Stub: simple word-split tokenization
    uint32_t n = 0;
    const char* p = text;
    while (*p && n < maxTokens) {
        while (*p == ' ') ++p;
        if (!*p) break;
        const char* start = p;
        while (*p && *p != ' ') ++p;
        tokens[n++] = (uint32_t)(start - text) + 1; // pseudo-token id
    }
    *count = n;
}

void bpe_decode(const uint32_t* tokens, uint32_t count, char* text,
                 uint32_t maxChars) {
    // Stub: emit placeholder tokens
    uint32_t pos = 0;
    for (uint32_t i = 0; i < count && pos + 8 < maxChars; ++i) {
        const char* t = "[tok] ";
        uint32_t len = (uint32_t)strlen(t);
        if (pos + len >= maxChars) break;
        memcpy(text + pos, t, len);
        pos += len;
    }
    if (pos < maxChars) text[pos] = '\0';
    else text[maxChars - 1] = '\0';
}

// ============================================================================
// GGUF Reader stubs
// ============================================================================
struct StubGGUFHandle {
    char path[256];
    uint32_t numTensors;
    bool valid;
};

static StubGGUFHandle g_stubHandle = {};

void* gguf_reader_open(const char* path) {
    g_stubHandle.valid = true;
    g_stubHandle.numTensors = 42; // simulated
    size_t len = strlen(path);
    if (len > 255) len = 255;
    memcpy(g_stubHandle.path, path, len);
    g_stubHandle.path[len] = '\0';
    return &g_stubHandle;
}

void gguf_reader_close(void* handle) {
    if (handle) {
        static_cast<StubGGUFHandle*>(handle)->valid = false;
    }
}

uint32_t gguf_reader_num_tensors(void* handle) {
    if (!handle) return 0;
    return static_cast<StubGGUFHandle*>(handle)->numTensors;
}

void gguf_reader_get_tensor(void* handle, uint32_t idx, void* info) {
    (void)handle; (void)idx; (void)info;
}

void* gguf_reader_load_tensor(void* handle, const char* name) {
    (void)handle; (void)name;
    return nullptr;
}

} // extern "C"
