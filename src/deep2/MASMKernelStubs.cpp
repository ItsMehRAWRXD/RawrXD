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
#include <new>
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

// Byte/UTF-8 aware decode used when no vocabulary is registered.
//
// The previous implementation emitted the literal string "[tok] " for every
// token regardless of the id, so any output routed through here rendered as
// "[tok] [tok] [tok]". Ids in the 0..255 range are emitted as their byte value;
// higher ids are rendered as hex so distinct tokens stay distinguishable.
void bpe_decode(const uint32_t* tokens, uint32_t count, char* text,
                uint32_t maxChars) {
    if (!text || maxChars == 0) return;
    uint32_t pos = 0;

    for (uint32_t i = 0; i < count; ++i) {
        const uint32_t t = tokens[i];
        char buf[16];
        uint32_t len = 0;

        if (t < 256u) {
            buf[0] = static_cast<char>(t);
            len = 1;
        } else {
            buf[0] = '<';
            len = 1;
            // Emit hex digits of the token id.
            char digits[8];
            uint32_t nd = 0;
            uint32_t v = t;
            if (v == 0) {
                digits[nd++] = '0';
            }
            while (v > 0 && nd < 8) {
                const uint32_t d = v & 0xFu;
                digits[nd++] = static_cast<char>(d < 10 ? ('0' + d) : ('a' + (d - 10)));
                v >>= 4;
            }
            while (nd > 0) buf[len++] = digits[--nd];
            buf[len++] = '>';
        }

        if (pos + len >= maxChars) break;
        memcpy(text + pos, buf, len);
        pos += len;
    }

    text[(pos < maxChars) ? pos : (maxChars - 1)] = '\0';
}

// ============================================================================
// GGUF Reader — real header parsing
// ============================================================================
// Previous behaviour: gguf_reader_open never opened the file, returned a handle
// with valid=true and numTensors=42 for ANY path (including nonexistent ones),
// gguf_reader_get_tensor had an empty body, and gguf_reader_load_tensor always
// returned nullptr. Callers therefore received a "loaded" model that contained
// no tensor data at all.
namespace {

struct GguftensorEntry {
    char name[128];
    uint64_t offset;
    uint64_t nDims;
    uint32_t ggmlType;
    uint64_t dims[4];
};

struct GgufHandleImpl {
    char path[512];
    bool valid;
    uint32_t version;
    uint64_t tensorCount;
    uint64_t metadataCount;
    uint64_t dataOffset;
    uint64_t fileSize;
    std::vector<GguftensorEntry> tensors;
    std::vector<uint8_t> blob;   // mmap/file contents
};

GgufHandleImpl* ImplOf(void* h) { return static_cast<GgufHandleImpl*>(h); }

// Read helpers are plain functions (not templates) because this translation unit
// is wrapped in extern "C", where templates are ill-formed.
bool ReadU32(const std::vector<uint8_t>& buf, uint64_t off, uint32_t* out) {
    if (off + 4 > buf.size()) return false;
    memcpy(out, buf.data() + off, 4);
    return true;
}

bool ReadU64(const std::vector<uint8_t>& buf, uint64_t off, uint64_t* out) {
    if (off + 8 > buf.size()) return false;
    memcpy(out, buf.data() + off, 8);
    return true;
}

bool ReadI64(const std::vector<uint8_t>& buf, uint64_t off, int64_t* out) {
    if (off + 8 > buf.size()) return false;
    memcpy(out, buf.data() + off, 8);
    return true;
}

bool ReadStrAt(const std::vector<uint8_t>& buf, uint64_t* pos, char* out, size_t outCap) {
    uint64_t len = 0;
    if (!ReadU64(buf, *pos, &len)) return false;
    *pos += sizeof(len);
    if (len + 1 > outCap) return false;
    if (*pos + len > buf.size()) return false;
    memcpy(out, buf.data() + *pos, static_cast<size_t>(len));
    out[len] = '\0';
    *pos += len;
    return true;
}

// Skip a GGUF metadata value of the given type without decoding it.
bool SkipValue(const std::vector<uint8_t>& buf, uint64_t* pos, uint32_t type) {
    switch (type) {
        case 0: case 1: case 7:            *pos += 1; return *pos <= buf.size();
        case 2: case 3:                    *pos += 2; return *pos <= buf.size();
        case 4: case 5: case 6:            *pos += 4; return *pos <= buf.size();
        case 10: case 11: case 12:         *pos += 8; return *pos <= buf.size();
        case 8: {
            uint64_t len = 0;
            if (!ReadU64(buf, *pos, &len)) return false;
            *pos += sizeof(len) + len;
            return *pos <= buf.size();
        }
        case 9: {
            uint32_t et = 0;
            uint64_t n = 0;
            if (!ReadU32(buf, *pos, &et)) return false;
            *pos += 4;
            if (!ReadU64(buf, *pos, &n)) return false;
            *pos += 8;
            for (uint64_t i = 0; i < n; ++i) {
                if (!SkipValue(buf, pos, et)) return false;
            }
            return true;
        }
        default:
            return false;
    }
}

}  // namespace

// Reports the byte offset where GGUF parsing failed, then releases the handle.
#define GGUF_PARSE_FAIL()                                                            \
    do {                                                                             \
        fprintf(stderr, "[gguf_reader] parse failure at offset %llu\n",              \
                (unsigned long long)pos);                                           \
        delete h;                                                                    \
        return nullptr;                                                              \
    } while (0)

void* gguf_reader_open(const char* path) {
    if (!path) return nullptr;

    auto* h = new (std::nothrow) GgufHandleImpl();
    if (!h) return nullptr;
    memset(h, 0, sizeof(*h));

    FILE* f = fopen(path, "rb");
    if (!f) {
        // Report failure. Returning a handle for a file that does not exist
        // makes every later tensor access read uninitialised memory.
        fprintf(stderr, "[gguf_reader] cannot open '%s'\n", path);
        delete h;
        return nullptr;
    }
    fseek(f, 0, SEEK_END);
    const long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize < 24) {
        fprintf(stderr, "[gguf_reader] '%s' too small to be GGUF (%ld bytes)\n", path, fsize);
        fclose(f);
        delete h;
        return nullptr;
    }

    h->blob.resize(static_cast<size_t>(fsize));
    const size_t got = fread(h->blob.data(), 1, h->blob.size(), f);
    fclose(f);
    if (got != h->blob.size()) {
        fprintf(stderr, "[gguf_reader] short read on '%s'\n", path);
        delete h;
        return nullptr;
    }
    h->fileSize = h->blob.size();

    if (memcmp(h->blob.data(), "GGUF", 4) != 0) {
        fprintf(stderr, "[gguf_reader] '%s' has bad magic (not GGUF)\n", path);
        delete h;
        return nullptr;
    }

    uint64_t pos = 4;
    if (!ReadU32(h->blob, pos, &h->version)) { GGUF_PARSE_FAIL(); }
    pos += 4;
    if (!ReadU64(h->blob, pos, &h->tensorCount)) { GGUF_PARSE_FAIL(); }
    pos += 8;
    if (!ReadU64(h->blob, pos, &h->metadataCount)) { GGUF_PARSE_FAIL(); }
    pos += 8;

    // Skip metadata key/value pairs.
    char key[128];
    for (uint64_t i = 0; i < h->metadataCount; ++i) {
        if (!ReadStrAt(h->blob, &pos, key, sizeof(key))) { GGUF_PARSE_FAIL(); }
        uint32_t type = 0;
        if (!ReadU32(h->blob, pos, &type)) { GGUF_PARSE_FAIL(); }
        pos += 4;
        if (!SkipValue(h->blob, &pos, type)) { GGUF_PARSE_FAIL(); }
    }

    // Tensor directory.
    h->tensors.reserve(static_cast<size_t>(h->tensorCount));
    for (uint64_t i = 0; i < h->tensorCount; ++i) {
        GguftensorEntry e;
        memset(&e, 0, sizeof(e));
        if (!ReadStrAt(h->blob, &pos, e.name, sizeof(e.name))) { GGUF_PARSE_FAIL(); }
        // GGUF stores n_dims as uint32, then ne[i] as uint64 per dimension.
        uint32_t nDims = 0;
        if (!ReadU32(h->blob, pos, &nDims)) { GGUF_PARSE_FAIL(); }
        pos += 4;
        e.nDims = nDims;
        if (e.nDims > 4) { GGUF_PARSE_FAIL(); }
        for (uint64_t d = 0; d < e.nDims; ++d) {
            int64_t dim = 0;
            if (!ReadI64(h->blob, pos, &dim)) { GGUF_PARSE_FAIL(); }
            e.dims[d] = static_cast<uint64_t>(dim);
            pos += 8;
        }
        if (!ReadU32(h->blob, pos, &e.ggmlType)) { GGUF_PARSE_FAIL(); }
        pos += 4;
        if (!ReadU64(h->blob, pos, &e.offset)) { GGUF_PARSE_FAIL(); }
        pos += 8;
        h->tensors.push_back(e);
    }

    // Tensor data begins at the next 32-byte aligned offset.
    h->dataOffset = (pos + 31u) & ~static_cast<uint64_t>(31u);

    snprintf(h->path, sizeof(h->path), "%s", path);
    h->valid = true;
    fprintf(stderr, "[gguf_reader] '%s' v%u tensors=%llu meta=%llu data@%llu\n",
            path, h->version, (unsigned long long)h->tensorCount,
            (unsigned long long)h->metadataCount, (unsigned long long)h->dataOffset);
    return h;
}

void gguf_reader_close(void* handle) {
    if (!handle) return;
    GgufHandleImpl* h = ImplOf(handle);
    h->valid = false;
    h->blob.clear();
    h->blob.shrink_to_fit();
    h->tensors.clear();
    delete h;
}

uint32_t gguf_reader_num_tensors(void* handle) {
    if (!handle) return 0;
    GgufHandleImpl* h = ImplOf(handle);
    if (!h->valid) return 0;
    return static_cast<uint32_t>(h->tensors.size());
}

// Populates a TensorInfo-shaped structure for `idx`.
// Layout mirrors ggml_tensor_info: {name, data ptr, n_dims, ne[], type}.
void gguf_reader_get_tensor(void* handle, uint32_t idx, void* info) {
    if (!handle || !info) return;
    GgufHandleImpl* h = ImplOf(handle);
    memset(info, 0, sizeof(uint64_t) * 16);
    if (!h->valid || idx >= h->tensors.size()) return;

    const GguftensorEntry& e = h->tensors[idx];
    // TensorInfo is { char* name; void* data; int n_dims; int64_t ne[4]; int type; }
    auto* ti = static_cast<uint8_t*>(info);
    std::memcpy(ti, e.name, sizeof(e.name));                       // offset 0
    const uint64_t dataPtr = h->dataOffset + e.offset;              // offset 128
    std::memcpy(ti + 128, &dataPtr, sizeof(dataPtr));
    const uint32_t nDims = static_cast<uint32_t>(e.nDims);           // offset 136
    std::memcpy(ti + 136, &nDims, sizeof(nDims));
    for (uint32_t d = 0; d < 4; ++d) {                              // offset 144
        const int64_t dim = static_cast<int64_t>(e.dims[d]);
        std::memcpy(ti + 144 + d * 8, &dim, sizeof(dim));
    }
    const uint32_t type = e.ggmlType;                               // offset 176
    std::memcpy(ti + 176, &type, sizeof(type));
}

// Returns a pointer into the mapped file for the named tensor, or nullptr when
// the tensor is absent or its data would fall outside the file.
void* gguf_reader_load_tensor(void* handle, const char* name) {
    if (!handle || !name) return nullptr;
    GgufHandleImpl* h = ImplOf(handle);
    if (!h->valid) return nullptr;

    for (const GguftensorEntry& e : h->tensors) {
        if (strcmp(e.name, name) != 0) continue;
        const uint64_t abs = h->dataOffset + e.offset;
        if (abs >= h->blob.size()) {
            fprintf(stderr, "[gguf_reader] tensor '%s' offset %llu outside file\n",
                    name, (unsigned long long)abs);
            return nullptr;
        }
        return const_cast<uint8_t*>(h->blob.data() + abs);
    }
    fprintf(stderr, "[gguf_reader] tensor '%s' not found\n", name);
    return nullptr;
}

// ============================================================================
// Missing ASM kernel stubs (added for RawrEngine link closure)
// NOTE: Sovereign_Q4K_GEMV_AVX2 and Deep2_RMSNorm_AVX2 are provided by
//       sovereign_q4k_gemv.asm and sovereign_deep2_kernels.asm respectively.
//       Do NOT define them here to avoid LNK2005 duplicate symbol errors.
// ============================================================================

#include <windows.h>
uint64_t AssertHardThreadAffinity(HANDLE threadHandle, uint64_t coreBitmask) {
    (void)threadHandle;
    (void)coreBitmask;
    return 0; // force Win32 SetThreadAffinityMask fallback in Deep2ThreadTuning
}
void RestrictOsBackgroundTasks(HANDLE processHandle, uint64_t backgroundMask) {
    if (!processHandle || processHandle == INVALID_HANDLE_VALUE) return;
    // Vacuum: pin process to keepMask cores + elevate priority for live generate.
    if (backgroundMask)
        SetProcessAffinityMask(processHandle, static_cast<DWORD_PTR>(backgroundMask));
    SetPriorityClass(processHandle, HIGH_PRIORITY_CLASS);
}

} // extern "C"
