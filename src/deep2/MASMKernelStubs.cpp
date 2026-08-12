// ============================================================================
// MASMKernelStubs.cpp — Stub implementations for MASM inference kernels
// Provides extern "C" symbols declared in RawrXDInferenceAdapter.hpp
// until real MASM objects are integrated. Stubs enable linking + simulated gen.
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <vector>
#include <cmath>

extern "C" {

// ============================================================================
// Core inference stubs
// ============================================================================
void ggml_gemm_q4_0(int M, int N, int K, const float* A, const uint8_t* Bq4,
                     float scale, float* C) {
    // Real Q4_0 dequantization + GEMM
    // Q4_0 block: 32 weights (4-bit) + 1 scale (float32)
    const size_t blockSize = 32;
    const size_t numBlocks = K / blockSize;
    
    // Dequantize Bq4 to float buffer
    std::vector<float> Bf(K * N);
    for (int n = 0; n < N; ++n) {
        for (size_t b = 0; b < numBlocks; ++b) {
            size_t blockOffset = n * numBlocks * (blockSize / 2 + 4) + b * (blockSize / 2 + 4);
            float blockScale = *reinterpret_cast<const float*>(Bq4 + blockOffset);
            const uint8_t* quants = Bq4 + blockOffset + 4;
            
            for (size_t i = 0; i < blockSize; ++i) {
                uint8_t q = (i % 2 == 0) ? (quants[i/2] & 0x0F) : (quants[i/2] >> 4);
                float val = (q - 8) * blockScale; // symmetric quantization around 0
                Bf[n * K + b * blockSize + i] = val;
            }
        }
    }
    
    // GEMM: C[M,N] = A[M,K] * B[K,N]
    for (int m = 0; m < M; ++m) {
        for (int n = 0; n < N; ++n) {
            float sum = 0.0f;
            for (int k = 0; k < K; ++k) {
                sum += A[m * K + k] * Bf[n * K + k];
            }
            C[m * N + n] = sum;
        }
    }
}

void Dequant_Q4_0_AVX2(void* blocks, uint64_t num_blocks, void* output,
                          float* scale_override) {
    // Real Q4_0 dequantization
    uint8_t* src = static_cast<uint8_t*>(blocks);
    float* dst = static_cast<float*>(output);
    
    for (uint64_t b = 0; b < num_blocks; ++b) {
        // Each block: 4 bytes scale + 16 bytes quants (32 x 4-bit)
        float scale = *reinterpret_cast<float*>(src + b * 20);
        if (scale_override) scale = *scale_override;
        
        uint8_t* quants = src + b * 20 + 4;
        
        for (int i = 0; i < 32; ++i) {
            uint8_t q = (i % 2 == 0) ? (quants[i/2] & 0x0F) : (quants[i/2] >> 4);
            dst[b * 32 + i] = (q - 8) * scale;
        }
    }
}

void q4_0_unpack_64x64(const void* src, float* dst) {
    // Real Q4_0 64x64 block unpack
    const uint8_t* src8 = static_cast<const uint8_t*>(src);
    size_t idx = 0;
    
    for (int row = 0; row < 64; ++row) {
        for (int colBlock = 0; colBlock < 2; ++colBlock) {
            // Each 32-element block has 4-byte scale + 16 bytes quants
            float scale = *reinterpret_cast<const float*>(src8 + idx);
            idx += 4;
            
            for (int i = 0; i < 32; ++i) {
                uint8_t q = (i % 2 == 0) ? (src8[idx + i/2] & 0x0F) : (src8[idx + i/2] >> 4);
                dst[row * 64 + colBlock * 32 + i] = (q - 8) * scale;
            }
            idx += 16;
        }
    }
}

// ============================================================================
// Attention stub
// ============================================================================
void flash_attn_asm_avx2(const float* Q, const float* K, const float* V,
                          float* O, uint32_t seqLen, uint32_t headDim,
                          float scale) {
    // Real scaled dot-product attention
    std::vector<float> scores(seqLen);
    std::vector<float> attnWeights(seqLen);
    
    for (uint32_t qPos = 0; qPos < seqLen; ++qPos) {
        // Compute attention scores: score[i] = Q[qPos] · K[i] * scale
        float maxScore = -1e30f;
        for (uint32_t kPos = 0; kPos <= qPos; ++kPos) {
            float dot = 0.0f;
            for (uint32_t d = 0; d < headDim; ++d) {
                dot += Q[qPos * headDim + d] * K[kPos * headDim + d];
            }
            scores[kPos] = dot * scale;
            if (scores[kPos] > maxScore) maxScore = scores[kPos];
        }
        
        // Softmax with causal mask
        float sumExp = 0.0f;
        for (uint32_t kPos = 0; kPos <= qPos; ++kPos) {
            attnWeights[kPos] = std::exp(scores[kPos] - maxScore);
            sumExp += attnWeights[kPos];
        }
        
        float invSum = 1.0f / (sumExp + 1e-6f);
        for (uint32_t kPos = 0; kPos <= qPos; ++kPos) {
            attnWeights[kPos] *= invSum;
        }
        
        // Compute output: O[qPos] = sum(attnWeights[kPos] * V[kPos])
        for (uint32_t d = 0; d < headDim; ++d) {
            float sum = 0.0f;
            for (uint32_t kPos = 0; kPos <= qPos; ++kPos) {
                sum += attnWeights[kPos] * V[kPos * headDim + d];
            }
            O[qPos * headDim + d] = sum;
        }
    }
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
    // Real KV cache update: append K/V at position pos
    if (!cache) return;
    
    struct KVCacheEntry {
        float* k_data;
        float* v_data;
        uint32_t capacity;
        uint32_t seq_len;
    };
    
    // cache is KVCacheEntry[layer_count]
    KVCacheEntry* entries = static_cast<KVCacheEntry*>(cache);
    KVCacheEntry& entry = entries[layer];
    
    if (pos >= entry.capacity) return; // overflow guard
    
    memcpy(entry.k_data + pos * headDim, k, headDim * sizeof(float));
    memcpy(entry.v_data + pos * headDim, v, headDim * sizeof(float));
    if (pos >= entry.seq_len) entry.seq_len = pos + 1;
}

void kv_cache_attend(const void* cache, uint32_t layer, uint32_t pos,
                      const float* q, float* out, uint32_t numHeads,
                      uint32_t headDim) {
    // Real KV cache attention: attend to all cached K/V up to pos
    if (!cache) return;
    
    struct KVCacheEntry {
        const float* k_data;
        const float* v_data;
        uint32_t capacity;
        uint32_t seq_len;
    };
    
    const KVCacheEntry* entries = static_cast<const KVCacheEntry*>(cache);
    const KVCacheEntry& entry = entries[layer];
    uint32_t seqLen = entry.seq_len;
    
    float scale = 1.0f / std::sqrt(static_cast<float>(headDim));
    
    for (uint32_t h = 0; h < numHeads; ++h) {
        const float* qHead = q + h * headDim;
        float* outHead = out + h * headDim;
        
        // Compute attention scores
        std::vector<float> scores(seqLen);
        float maxScore = -1e30f;
        for (uint32_t t = 0; t < seqLen; ++t) {
            float dot = 0.0f;
            for (uint32_t d = 0; d < headDim; ++d) {
                dot += qHead[d] * entry.k_data[t * headDim + d];
            }
            scores[t] = dot * scale;
            if (scores[t] > maxScore) maxScore = scores[t];
        }
        
        // Softmax
        float sumExp = 0.0f;
        for (uint32_t t = 0; t < seqLen; ++t) {
            scores[t] = std::exp(scores[t] - maxScore);
            sumExp += scores[t];
        }
        float invSum = 1.0f / (sumExp + 1e-6f);
        for (uint32_t t = 0; t < seqLen; ++t) {
            scores[t] *= invSum;
        }
        
        // Weighted sum of values
        for (uint32_t d = 0; d < headDim; ++d) {
            float sum = 0.0f;
            for (uint32_t t = 0; t < seqLen; ++t) {
                sum += scores[t] * entry.v_data[t * headDim + d];
            }
            outHead[d] = sum;
        }
    }
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

// ============================================================================
// Missing ASM kernel stubs (added for RawrEngine link closure)
// NOTE: Sovereign_Q4K_GEMV_AVX2 and Deep2_RMSNorm_AVX2 are provided by
//       sovereign_q4k_gemv.asm and sovereign_deep2_kernels.asm respectively.
//       Do NOT define them here to avoid LNK2005 duplicate symbol errors.
// ============================================================================

} // extern "C"
