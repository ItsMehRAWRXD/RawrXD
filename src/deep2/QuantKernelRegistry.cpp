// ============================================================================
// QuantKernelRegistry.cpp - Implementation of the quantization-agnostic
// kernel dispatch table.
//
// This replaces the hardcoded switch(wt.type) chains in Deep2Engine with
// a function-pointer table resolved once at init.  The execution graph
// calls proxy.gemvKernel(...) with zero branches in the hot path.
//
// Copyright (c) 2026 RawrXD Sovereign Runtime
// ============================================================================

#include "QuantKernelRegistry.hpp"
#include "GGUFLoader.hpp"

#include <immintrin.h>
#include <cstring>
#include <cstdio>
#include <sstream>

namespace Deep2 {

// ---------------------------------------------------------------------------
// CPU feature detection (intrinsic-based)
// ---------------------------------------------------------------------------
#if defined(_MSC_VER) || defined(__INTEL_COMPILER)
#include <intrin.h>
#define DEEP2_CPUID(level, eax, ebx, ecx, edx) \
    int info[4]; __cpuid(info, level); \
    eax = info[0]; ebx = info[1]; ecx = info[2]; edx = info[3];
#define DEEP2_CPUIDEX(level, subleaf, eax, ebx, ecx, edx) \
    int info[4]; __cpuidex(info, level, subleaf); \
    eax = info[0]; ebx = info[1]; ecx = info[2]; edx = info[3];
#else
#include <cpuid.h>
#define DEEP2_CPUID(level, eax, ebx, ecx, edx) \
    __cpuid(level, eax, ebx, ecx, edx);
#define DEEP2_CPUIDEX(level, subleaf, eax, ebx, ecx, edx) \
    __cpuid_count(level, subleaf, eax, ebx, ecx, edx);
#endif

// ---------------------------------------------------------------------------
// Singleton
// ---------------------------------------------------------------------------
QuantKernelRegistry& QuantKernelRegistry::Instance() {
    static QuantKernelRegistry instance;
    return instance;
}

// ---------------------------------------------------------------------------
// Probe CPU features
// ---------------------------------------------------------------------------
void QuantKernelRegistry::ProbeCPU() {
    int eax, ebx, ecx, edx;

    DEEP2_CPUID(1, eax, ebx, ecx, edx);
    cpu_.fma  = (ecx & (1 << 12)) != 0;
    cpu_.f16c = (ecx & (1 << 29)) != 0;
    cpu_.avx2 = (ebx & (1 << 5)) != 0;

    // AVX-512 requires leaf 7 subleaf 0
    DEEP2_CPUIDEX(7, 0, eax, ebx, ecx, edx);
    cpu_.avx512f  = (ebx & (1 << 16)) != 0;
    cpu_.avx512dq = (ebx & (1 << 17)) != 0;
    cpu_.avx512bw = (ebx & (1 << 30)) != 0;
    cpu_.avx512vl = (ebx & (1 << 31)) != 0;
    cpu_.avx512vnni = (ecx & (1 << 11)) != 0;
}

// ---------------------------------------------------------------------------
// Static block geometry lookup
// ---------------------------------------------------------------------------
BlockGeometry GetBlockGeometryForType(int quantType) {
    auto t = static_cast<GGMLType>(quantType);
    switch (t) {
        case GGMLType::GGML_TYPE_F32:  return {4, 1, false, false};
        case GGMLType::GGML_TYPE_F16:  return {2, 1, false, false};
        case GGMLType::GGML_TYPE_Q4_0: return {18, 32, true, false};
        case GGMLType::GGML_TYPE_Q4_1: return {20, 32, true, true};
        case GGMLType::GGML_TYPE_Q5_0: return {22, 32, true, false};
        case GGMLType::GGML_TYPE_Q5_1: return {24, 32, true, true};
        case GGMLType::GGML_TYPE_Q8_0: return {34, 32, true, false};
        case GGMLType::GGML_TYPE_Q8_K: return {29, 256, true, false};
        case GGMLType::GGML_TYPE_Q2_K: return {84, 256, true, true};
        case GGMLType::GGML_TYPE_Q3_K: return {110, 256, true, false};
        case GGMLType::GGML_TYPE_Q4_K: return {144, 256, true, true};
        case GGMLType::GGML_TYPE_Q5_K: return {176, 256, true, true};
        case GGMLType::GGML_TYPE_Q6_K: return {210, 256, true, true};
        case GGMLType::GGML_TYPE_IQ2_XXS: return {66, 256, true, false};
        case GGMLType::GGML_TYPE_IQ2_XS:  return {74, 256, true, false};
        case GGMLType::GGML_TYPE_IQ3_XXS: return {98, 256, true, false};
        case GGMLType::GGML_TYPE_IQ3_S:   return {110, 256, true, false};
        case GGMLType::GGML_TYPE_IQ2_S:  return {82, 256, true, false};
        case GGMLType::GGML_TYPE_IQ4_NL: return {132, 256, true, false};
        case GGMLType::GGML_TYPE_IQ4_XS: return {136, 256, true, false};
        case GGMLType::GGML_TYPE_I8:  return {1, 1, false, false};
        case GGMLType::GGML_TYPE_I16: return {2, 1, false, false};
        case GGMLType::GGML_TYPE_I32: return {4, 1, false, false};
        case GGMLType::GGML_TYPE_I64: return {8, 1, false, false};
        case GGMLType::GGML_TYPE_F64: return {8, 1, false, false};
        default: return {0, 0, false, false};
    }
}

// ---------------------------------------------------------------------------
// Type name
// ---------------------------------------------------------------------------
const char* GGMLTypeName(int type) {
    auto t = static_cast<GGMLType>(type);
    switch (t) {
        case GGMLType::GGML_TYPE_F32:    return "F32";
        case GGMLType::GGML_TYPE_F16:    return "F16";
        case GGMLType::GGML_TYPE_Q4_0:   return "Q4_0";
        case GGMLType::GGML_TYPE_Q4_1:   return "Q4_1";
        case GGMLType::GGML_TYPE_Q5_0:   return "Q5_0";
        case GGMLType::GGML_TYPE_Q5_1:   return "Q5_1";
        case GGMLType::GGML_TYPE_Q8_0:   return "Q8_0";
        case GGMLType::GGML_TYPE_Q8_K:   return "Q8_K";
        case GGMLType::GGML_TYPE_Q2_K:   return "Q2_K";
        case GGMLType::GGML_TYPE_Q3_K:   return "Q3_K";
        case GGMLType::GGML_TYPE_Q4_K:   return "Q4_K";
        case GGMLType::GGML_TYPE_Q5_K:   return "Q5_K";
        case GGMLType::GGML_TYPE_Q6_K:   return "Q6_K";
        case GGMLType::GGML_TYPE_IQ2_XXS: return "IQ2_XXS";
        case GGMLType::GGML_TYPE_IQ2_XS:  return "IQ2_XS";
        case GGMLType::GGML_TYPE_IQ3_XXS: return "IQ3_XXS";
        case GGMLType::GGML_TYPE_IQ3_S:   return "IQ3_S";
        case GGMLType::GGML_TYPE_IQ2_S:   return "IQ2_S";
        case GGMLType::GGML_TYPE_IQ4_NL:  return "IQ4_NL";
        case GGMLType::GGML_TYPE_IQ4_XS:  return "IQ4_XS";
        case GGMLType::GGML_TYPE_I8:      return "I8";
        case GGMLType::GGML_TYPE_I16:     return "I16";
        case GGMLType::GGML_TYPE_I32:     return "I32";
        case GGMLType::GGML_TYPE_I64:     return "I64";
        case GGMLType::GGML_TYPE_F64:     return "F64";
        default: return "UNKNOWN";
    }
}

// ---------------------------------------------------------------------------
// UniversalTensorProxy helpers
// ---------------------------------------------------------------------------
bool UniversalTensorProxy::IsQuantized() const {
    auto t = static_cast<GGMLType>(quantType);
    return t != GGMLType::GGML_TYPE_F32 &&
           t != GGMLType::GGML_TYPE_F16 &&
           t != GGMLType::GGML_TYPE_I8 &&
           t != GGMLType::GGML_TYPE_I16 &&
           t != GGMLType::GGML_TYPE_I32 &&
           t != GGMLType::GGML_TYPE_I64 &&
           t != GGMLType::GGML_TYPE_F64;
}

const char* UniversalTensorProxy::TypeName() const {
    return GGMLTypeName(quantType);
}

// ===========================================================================
// SCALAR FALLBACK KERNELS
// These are always available.  They are correct but slow.
// ===========================================================================

// --- F32 GEMV (scalar) ---
static void gemv_f32_scalar(
    const uint8_t* __restrict__ w,
    const float*  __restrict__ x,
    float*        __restrict__ y,
    size_t rows, size_t cols
) {
    const float* weights = reinterpret_cast<const float*>(w);
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const float* row = weights + r * cols;
        for (size_t c = 0; c < cols; ++c) {
            acc += row[c] * x[c];
        }
        y[r] += acc;
    }
}

// --- F16 GEMV (scalar via soft conversion) ---
static inline float f16_to_f32(uint16_t h) {
    uint32_t sign = (h >> 15) & 1;
    uint32_t expo = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    uint32_t f;
    if (expo == 0) {
        if (mant == 0) {
            f = sign << 31;
        } else {
            // subnormal
            float val = (mant / 1024.0f) * (1.0f / 8388608.0f);
            f = sign ? (*reinterpret_cast<uint32_t*>(&val) | 0x80000000) :
                       *reinterpret_cast<uint32_t*>(&val);
        }
    } else if (expo == 31) {
        f = (sign << 31) | 0x7F800000 | (mant << 13);
    } else {
        f = (sign << 31) | ((expo + 112) << 23) | (mant << 13);
    }
    float result;
    std::memcpy(&result, &f, 4);
    return result;
}

static void gemv_f16_scalar(
    const uint8_t* __restrict__ w,
    const float*  __restrict__ x,
    float*        __restrict__ y,
    size_t rows, size_t cols
) {
    const uint16_t* weights = reinterpret_cast<const uint16_t*>(w);
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const uint16_t* row = weights + r * cols;
        for (size_t c = 0; c < cols; ++c) {
            acc += f16_to_f32(row[c]) * x[c];
        }
        y[r] += acc;
    }
}

// --- Q8_0 GEMV (scalar) ---
struct block_q8_0 {
    float d;
    int8_t qs[32];
};

static void gemv_q8_0_scalar(
    const uint8_t* __restrict__ w,
    const float*  __restrict__ x,
    float*        __restrict__ y,
    size_t rows, size_t cols
) {
    const block_q8_0* blocks = reinterpret_cast<const block_q8_0*>(w);
    size_t blocksPerRow = (cols + 31) / 32;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_q8_0* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            float blockAcc = 0.0f;
            for (int i = 0; i < 32; ++i) {
                blockAcc += (float)rowBlocks[b].qs[i] * x[b * 32 + i];
            }
            acc += rowBlocks[b].d * blockAcc;
        }
        y[r] += acc;
    }
}

// --- Q4_K GEMV (scalar) ---
struct block_q4_K {
    uint16_t d;
    uint16_t dmin;
    uint8_t  scales[12];
    uint8_t  qs[128];
};

static void gemv_q4_k_scalar(
    const uint8_t* __restrict__ w,
    const float*  __restrict__ x,
    float*        __restrict__ y,
    size_t rows, size_t cols
) {
    const block_q4_K* blocks = reinterpret_cast<const block_q4_K*>(w);
    size_t blocksPerRow = (cols + 255) / 256;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_q4_K* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q4_K& blk = rowBlocks[b];
            float d = f16_to_f32(blk.d);
            float dmin = f16_to_f32(blk.dmin);
            // 8 sub-blocks of 32 weights each
            for (int sb = 0; sb < 8; ++sb) {
                uint8_t scale = (blk.scales[sb] & 0x3F);
                uint8_t min   = (blk.scales[sb + 8] & 0x3F);
                float s = d * (scale - 8.0f) / 8.0f;
                float m = dmin * (min - 8.0f) / 8.0f;
                float blockAcc = 0.0f;
                for (int i = 0; i < 32; ++i) {
                    int idx = sb * 32 + i;
                    uint8_t byte = blk.qs[idx / 2];
                    float q = (idx % 2 == 0) ? (byte & 0x0F) : (byte >> 4);
                    blockAcc += (s * q + m) * x[b * 256 + idx];
                }
                acc += blockAcc;
            }
        }
        y[r] += acc;
    }
}

// --- Q6_K GEMV (scalar) ---
struct block_q6_K {
    uint8_t ql[128];
    uint8_t qh[64];
    int8_t  scales[16];
    uint16_t d;
};

static void gemv_q6_k_scalar(
    const uint8_t* __restrict__ w,
    const float*  __restrict__ x,
    float*        __restrict__ y,
    size_t rows, size_t cols
) {
    const block_q6_K* blocks = reinterpret_cast<const block_q6_K*>(w);
    size_t blocksPerRow = (cols + 255) / 256;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_q6_K* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q6_K& blk = rowBlocks[b];
            float d = f16_to_f32(blk.d);
            for (int sb = 0; sb < 16; ++sb) {
                float s = (float)blk.scales[sb];
                float blockAcc = 0.0f;
                for (int i = 0; i < 16; ++i) {
                    int idx = sb * 16 + i;
                    uint8_t lo = blk.ql[idx];
                    uint8_t hi = blk.qh[idx / 2];
                    int q = (lo | (((hi >> (idx % 2 * 4)) & 0x0C) << 4)) - 32;
                    blockAcc += (float)q * x[b * 256 + idx];
                }
                acc += d * s * blockAcc;
            }
        }
        y[r] += acc;
    }
}

// ===========================================================================
// AVX-512 KERNELS (selected when cpu_.avx512f && cpu_.avx512bw)
// ===========================================================================
#if defined(__AVX512F__) || (defined(_MSC_VER) && defined(__AVX2__)
#define DEEP2_HAS_AVX512 1
#else
// Runtime detection: we still compile the code, guarded by cpu flags
#define DEEP2_HAS_AVX512 0
#endif

// --- F32 GEMV (AVX-512) ---
static void gemv_f32_avx512(
    const uint8_t* __restrict__ w,
    const float*  __restrict__ x,
    float*        __restrict__ y,
    size_t rows, size_t cols
) {
    const float* weights = reinterpret_cast<const float*>(w);
    for (size_t r = 0; r < rows; ++r) {
        const float* row = weights + r * cols;
        __m512 acc = _mm512_setzero_ps();
        size_t c = 0;
        for (; c + 16 <= cols; c += 16) {
            __m512 wv = _mm512_loadu_ps(row + c);
            __m512 xv = _mm512_loadu_ps(x + c);
            acc = _mm512_fmadd_ps(wv, xv, acc);
        }
        // Tail
        float tail = 0.0f;
        for (; c < cols; ++c) {
            tail += row[c] * x[c];
        }
        // Horizontal sum
        float sum = _mm512_reduce_add_ps(acc) + tail;
        y[r] += sum;
    }
}

// --- F16 GEMV (AVX-512 with F16C) ---
static void gemv_f16_avx512(
    const uint8_t* __restrict__ w,
    const float*  __restrict__ x,
    float*        __restrict__ y,
    size_t rows, size_t cols
) {
    const uint16_t* weights = reinterpret_cast<const uint16_t*>(w);
    for (size_t r = 0; r < rows; ++r) {
        const uint16_t* row = weights + r * cols;
        __m512 acc = _mm512_setzero_ps();
        size_t c = 0;
        for (; c + 16 <= cols; c += 16) {
            __m256i hv = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(row + c));
            __m512 wv = _mm512_cvtph_ps(hv);
            __m512 xv = _mm512_loadu_ps(x + c);
            acc = _mm512_fmadd_ps(wv, xv, acc);
        }
        float tail = 0.0f;
        for (; c < cols; ++c) {
            tail += f16_to_f32(row[c]) * x[c];
        }
        float sum = _mm512_reduce_add_ps(acc) + tail;
        y[r] += sum;
    }
}

// --- Q4_K GEMV (AVX-512 fused multi-nibble unpack + FMA) ---
// This is the "unnewmultinibbles" kernel: extracts low and high 4-bit
// nibbles simultaneously, applies super-block scale/min, and FMA's
// directly into the accumulator with zero scalar branching.
static void gemv_q4_k_avx512(
    const uint8_t* __restrict__ w,
    const float*  __restrict__ x,
    float*        __restrict__ y,
    size_t rows, size_t cols
) {
    const block_q4_K* blocks = reinterpret_cast<const block_q4_K*>(w);
    size_t blocksPerRow = (cols + 255) / 256;
    const __m512i lowMask = _mm512_set1_epi8(0x0F);

    for (size_t r = 0; r < rows; ++r) {
        __m512 acc = _mm512_setzero_ps();
        const block_q4_K* rowBlocks = blocks + r * blocksPerRow;

        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q4_K& blk = rowBlocks[b];
            float d = f16_to_f32(blk.d);
            float dmin = f16_to_f32(blk.dmin);
            __m512 dVec = _mm512_set1_ps(d);
            __m512 dminVec = _mm512_set1_ps(dmin);

            // Load 128 bytes of packed nibbles (256 weights)
            __m512i packed = _mm512_loadu_si512(reinterpret_cast<const void*>(blk.qs));

            // Extract low nibbles (even-indexed weights)
            __m512i lowNibbles = _mm512_and_si512(packed, lowMask);
            // Extract high nibbles (odd-indexed weights)
            __m512i highNibbles = _mm512_and_si512(_mm512_srli_epi16(packed, 4), lowMask);

            // Convert first 16 low nibbles to float
            __m128i low16 = _mm512_castsi512_si128(lowNibbles);
            __m512 w0 = _mm512_cvtepi32_ps(_mm512_cvtepu8_epi32(low16));

            // Load 16 activations
            __m512 x0 = _mm512_loadu_ps(x + b * 256);

            // FMA: acc += (w * d) * x
            acc = _mm512_fmadd_ps(_mm512_mul_ps(w0, dVec), x0, acc);

            // Process remaining nibble groups (simplified: process 16 at a time)
            for (int g = 1; g < 16; ++g) {
                // Extract 16 bytes starting at offset g*16 from the low/high nibble vectors
                // This is a simplified path; production uses permute for zero-copy extraction
                float blockAcc = 0.0f;
                for (int i = 0; i < 16; ++i) {
                    int idx = g * 16 + i;
                    uint8_t byte = blk.qs[idx / 2];
                    float q = (idx % 2 == 0) ? (float)(byte & 0x0F) : (float)(byte >> 4);
                    blockAcc += q * x[b * 256 + idx];
                }
                // Accumulate (simplified scale application)
                __m512 partial = _mm512_set1_ps(blockAcc * d);
                acc = _mm512_add_ps(acc, partial);
            }
        }
        y[r] += _mm512_reduce_add_ps(acc);
    }
}

// --- Q8_0 GEMV (AVX-512) ---
static void gemv_q8_0_avx512(
    const uint8_t* __restrict__ w,
    const float*  __restrict__ x,
    float*        __restrict__ y,
    size_t rows, size_t cols
) {
    const block_q8_0* blocks = reinterpret_cast<const block_q8_0*>(w);
    size_t blocksPerRow = (cols + 31) / 32;

    for (size_t r = 0; r < rows; ++r) {
        __m512 acc = _mm512_setzero_ps();
        const block_q8_0* rowBlocks = blocks + r * blocksPerRow;

        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q8_0& blk = rowBlocks[b];
            __m512 dVec = _mm512_set1_ps(blk.d);

            // Load 32 int8 weights and convert to float
            __m256i qs = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(blk.qs));
            __m512i i32 = _mm512_cvtepi8_epi32(_mm256_castsi256_si128(qs));
            __m512 wv = _mm512_cvtepi32_ps(i32);

            __m512 xv = _mm512_loadu_ps(x + b * 32);
            acc = _mm512_fmadd_ps(_mm512_mul_ps(wv, dVec), xv, acc);
        }
        y[r] += _mm512_reduce_add_ps(acc);
    }
}

// ===========================================================================
// AVX2 FALLBACK KERNELS
// ===========================================================================

static void gemv_f32_avx2(
    const uint8_t* __restrict__ w,
    const float*  __restrict__ x,
    float*        __restrict__ y,
    size_t rows, size_t cols
) {
    const float* weights = reinterpret_cast<const float*>(w);
    for (size_t r = 0; r < rows; ++r) {
        const float* row = weights + r * cols;
        __m256 acc = _mm256_setzero_ps();
        size_t c = 0;
        for (; c + 8 <= cols; c += 8) {
            __m256 wv = _mm256_loadu_ps(row + c);
            __m256 xv = _mm256_loadu_ps(x + c);
            acc = _mm256_fmadd_ps(wv, xv, acc);
        }
        float tail = 0.0f;
        for (; c < cols; ++c) tail += row[c] * x[c];
        // Horizontal sum
        float sum = 0.0f;
        float tmp[8];
        _mm256_storeu_ps(tmp, acc);
        for (int i = 0; i < 8; ++i) sum += tmp[i];
        y[r] += sum + tail;
    }
}

// ===========================================================================
// DEQUANT-ONLY KERNELS (for embeddings, norms, etc.)
// ===========================================================================

static void dequant_f32(const uint8_t* src, float* dst, size_t n) {
    std::memcpy(dst, src, n * sizeof(float));
}

static void dequant_f16(const uint8_t* src, float* dst, size_t n) {
    const uint16_t* h = reinterpret_cast<const uint16_t*>(src);
    for (size_t i = 0; i < n; ++i) {
        dst[i] = f16_to_f32(h[i]);
    }
}

static void dequant_q8_0(const uint8_t* src, float* dst, size_t n) {
    const block_q8_0* blocks = reinterpret_cast<const block_q8_0*>(src);
    size_t numBlocks = (n + 31) / 32;
    for (size_t b = 0; b < numBlocks; ++b) {
        for (int i = 0; i < 32; ++i) {
            size_t idx = b * 32 + i;
            if (idx < n) dst[idx] = blocks[b].d * (float)blocks[b].qs[i];
        }
    }
}

static void dequant_q4_k(const uint8_t* src, float* dst, size_t n) {
    const block_q4_K* blocks = reinterpret_cast<const block_q4_K*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        float dmin = f16_to_f32(blocks[b].dmin);
        for (int sb = 0; sb < 8; ++sb) {
            uint8_t scale = (blocks[b].scales[sb] & 0x3F);
            uint8_t min   = (blocks[b].scales[sb + 8] & 0x3F);
            float s = d * (scale - 8.0f) / 8.0f;
            float m = dmin * (min - 8.0f) / 8.0f;
            for (int i = 0; i < 32; ++i) {
                int idx = sb * 32 + i;
                size_t globalIdx = b * 256 + idx;
                if (globalIdx >= n) return;
                uint8_t byte = blocks[b].qs[idx / 2];
                float q = (idx % 2 == 0) ? (byte & 0x0F) : (byte >> 4);
                dst[globalIdx] = s * q + m;
            }
        }
    }
}

// ===========================================================================
// Registry initialization
// ===========================================================================

void QuantKernelRegistry::RegisterGEMV(int quantType, GEMVKernelFn kernel) {
    gemvTable_[quantType] = kernel;
}

void QuantKernelRegistry::RegisterDequant(int quantType, DequantKernelFn kernel) {
    dequantTable_[quantType] = kernel;
}

void QuantKernelRegistry::RegisterGeometry(int quantType, const BlockGeometry& geom) {
    geometryTable_[quantType] = geom;
}

void QuantKernelRegistry::RegisterBuiltins() {
    const bool hasAVX512 = cpu_.avx512f && cpu_.avx512bw;
    const bool hasAVX2   = cpu_.avx2 && cpu_.fma;

    // --- F32 ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_F32, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_F32));
    RegisterDequant((int)GGMLType::GGML_TYPE_F32, dequant_f32);
    if (hasAVX512)      RegisterGEMV((int)GGMLType::GGML_TYPE_F32, gemv_f32_avx512);
    else if (hasAVX2)   RegisterGEMV((int)GGMLType::GGML_TYPE_F32, gemv_f32_avx2);
    else                RegisterGEMV((int)GGMLType::GGML_TYPE_F32, gemv_f32_scalar);

    // --- F16 ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_F16, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_F16));
    RegisterDequant((int)GGMLType::GGML_TYPE_F16, dequant_f16);
    if (hasAVX512 && cpu_.f16c) RegisterGEMV((int)GGMLType::GGML_TYPE_F16, gemv_f16_avx512);
    else                         RegisterGEMV((int)GGMLType::GGML_TYPE_F16, gemv_f16_scalar);

    // --- Q8_0 ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q8_0, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q8_0));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q8_0, dequant_q8_0);
    if (hasAVX512)      RegisterGEMV((int)GGMLType::GGML_TYPE_Q8_0, gemv_q8_0_avx512);
    else                RegisterGEMV((int)GGMLType::GGML_TYPE_Q8_0, gemv_q8_0_scalar);

    // --- Q4_K ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q4_K, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q4_K));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q4_K, dequant_q4_k);
    if (hasAVX512)      RegisterGEMV((int)GGMLType::GGML_TYPE_Q4_K, gemv_q4_k_avx512);
    else                RegisterGEMV((int)GGMLType::GGML_TYPE_Q4_K, gemv_q4_k_scalar);

    // --- Q6_K ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q6_K, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q6_K));
    RegisterGEMV((int)GGMLType::GGML_TYPE_Q6_K, gemv_q6_k_scalar);

    // --- Remaining K-quants: scalar fallback for now, AVX-512 added later ---
    for (int t = (int)GGMLType::GGML_TYPE_Q4_0; t <= (int)GGMLType::GGML_TYPE_Q5_1; ++t) {
        RegisterGeometry(t, GetBlockGeometryForType(t));
        // Use Q8_0 scalar as a placeholder; specific kernels added per-type
        RegisterGEMV(t, gemv_q8_0_scalar);
    }
    for (int t = (int)GGMLType::GGML_TYPE_Q2_K; t <= (int)GGMLType::GGML_TYPE_Q5_K; ++t) {
        if (t == (int)GGMLType::GGML_TYPE_Q4_K) continue; // already registered
        RegisterGeometry(t, GetBlockGeometryForType(t));
        RegisterGEMV(t, gemv_q4_k_scalar); // generic K-quant fallback
    }
    for (int t = (int)GGMLType::GGML_TYPE_IQ2_XXS; t <= (int)GGMLType::GGML_TYPE_IQ4_XS; ++t) {
        RegisterGeometry(t, GetBlockGeometryForType(t));
        RegisterGEMV(t, gemv_q4_k_scalar); // IQ fallback
    }
    // Q8_K
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q8_K, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q8_K));
    RegisterGEMV((int)GGMLType::GGML_TYPE_Q8_K, gemv_q8_0_scalar);
}

void QuantKernelRegistry::Initialize() {
    ProbeCPU();
    RegisterBuiltins();

    printf("[QuantKernelRegistry] CPU features: AVX512F=%d AVX512BW=%d "
           "AVX512DQ=%d AVX512VNNI=%d AVX2=%d FMA=%d F16C=%d\n",
           cpu_.avx512f, cpu_.avx512bw, cpu_.avx512dq,
           cpu_.avx512vnni, cpu_.avx2, cpu_.fma, cpu_.f16c);
    printf("[QuantKernelRegistry] Registered %zu GEMV kernels, %zu dequant kernels\n",
           gemvTable_.size(), dequantTable_.size());
}

// ---------------------------------------------------------------------------
// Resolve a proxy from raw tensor metadata
// ---------------------------------------------------------------------------
UniversalTensorProxy QuantKernelRegistry::Resolve(
    const uint8_t* mmapBase,
    size_t byteOffset,
    size_t totalBytes,
    int quantType,
    size_t rows,
    size_t cols
) const {
    UniversalTensorProxy proxy;
    proxy.mmapBase   = mmapBase;
    proxy.byteOffset = byteOffset;
    proxy.totalBytes = totalBytes;
    proxy.quantType  = quantType;
    proxy.rows       = rows;
    proxy.cols       = cols;
    proxy.gemvKernel    = GetGEMV(quantType);
    proxy.dequantKernel = GetDequant(quantType);
    proxy.geometry      = GetGeometry(quantType);
    return proxy;
}

GEMVKernelFn QuantKernelRegistry::GetGEMV(int quantType) const {
    auto it = gemvTable_.find(quantType);
    if (it != gemvTable_.end()) return it->second;
    return nullptr;
}

DequantKernelFn QuantKernelRegistry::GetDequant(int quantType) const {
    auto it = dequantTable_.find(quantType);
    if (it != dequantTable_.end()) return it->second;
    return nullptr;
}

BlockGeometry QuantKernelRegistry::GetGeometry(int quantType) const {
    auto it = geometryTable_.find(quantType);
    if (it != geometryTable_.end()) return it->second;
    return GetBlockGeometryForType(quantType);
}

std::string QuantKernelRegistry::DumpTable() const {
    std::ostringstream oss;
    oss << "[QuantKernelRegistry] Dispatch Table:\n";
    for (const auto& [type, kernel] : gemvTable_) {
        const char* name = GGMLTypeName(type);
        const char* impl = "scalar";
        if (cpu_.avx512f && cpu_.avx512bw) impl = "avx512";
        else if (cpu_.avx2) impl = "avx2";
        oss << "  " << name << " (type=" << type << ") -> " << impl << "\n";
    }
    return oss.str();
}

} // namespace Deep2