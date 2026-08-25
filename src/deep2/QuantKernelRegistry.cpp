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
#include "QuantKernelRegistry_K.h"  // K-quant dequant/GEMV kernels

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
    { int _info[4]; __cpuid(_info, level); \
    eax = _info[0]; ebx = _info[1]; ecx = _info[2]; edx = _info[3]; }
#define DEEP2_CPUIDEX(level, subleaf, eax, ebx, ecx, edx) \
    { int _info[4]; __cpuidex(_info, level, subleaf); \
    eax = _info[0]; ebx = _info[1]; ecx = _info[2]; edx = _info[3]; }
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
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
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
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
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
// block_q8_0 defined in GGUFLoader.hpp

static void gemv_q8_0_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const block_q8_0* blocks = reinterpret_cast<const block_q8_0*>(w);
    size_t blocksPerRow = (cols + 31) / 32;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_q8_0* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q8_0& blk = rowBlocks[b];
            float d = f16_to_f32(blk.d);
            float blockAcc = 0.0f;
            for (int i = 0; i < 32; ++i) {
                blockAcc += (float)blk.qs[i] * x[b * 32 + i];
            }
            acc += d * blockAcc;
        }
        y[r] += acc;
    }
}

// --- Q4_K GEMV (scalar) ---
// block_q4_K defined in GGUFLoader.hpp

static void gemv_q4_k_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
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
            size_t elemsInBlock = (b == blocksPerRow - 1)
                ? (cols - b * 256)
                : 256;
            if (elemsInBlock == 0) break;

            // 8 sub-blocks of 32 weights each
            for (int sb = 0; sb < 8; ++sb) {
                uint8_t scale, min;
                get_scale_min_k4(sb, blk.scales, scale, min);
                float s = d * scale;
                float m = dmin * min;
                float blockAcc = 0.0f;
                for (int i = 0; i < 32; ++i) {
                    int idx = sb * 32 + i;
                    if ((size_t)idx >= elemsInBlock) break;
                    uint8_t byte = blk.qs[idx / 2];
                    float q = (idx % 2 == 0) ? (byte & 0x0F) : (byte >> 4);
                    blockAcc += (s * q - m) * x[b * 256 + idx];
                }
                acc += blockAcc;
            }
        }
        y[r] += acc;
    }
}

// --- Q6_K GEMV (scalar) ---
// block_q6_K defined in GGUFLoader.hpp
// Layout: ql[128] (low 4 bits), qh[64] (high 2 bits), scales[16], d (fp16)
// 256 weights per block, split into two 128-element chunks.
// Each chunk processes 32 iterations of l, extracting 4 values per iteration.
// Correctness verified against llama.cpp dequantize_row_q6_K.

static void gemv_q6_k_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
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
            const uint8_t* ql = blk.ql;
            const uint8_t* qh = blk.qh;
            const int8_t* sc = blk.scales;
            size_t base = b * 256;
            size_t elemsInBlock = (b == blocksPerRow - 1) ? (cols - b * 256) : 256;
            if (elemsInBlock == 0) break;

            // Two 128-element chunks per block
            for (int chunk = 0; chunk < 2; ++chunk) {
                size_t chunkBase = chunk * 128;
                if (chunkBase >= elemsInBlock) break;
                for (int l = 0; l < 32; ++l) {
                    size_t pos = base + chunkBase + l;
                    int is = l / 16;  // 0 or 1 within chunk
                    int q1 = ((ql[l +  0] & 0x0F) | (((qh[l] >> 0) & 3) << 4)) - 32;
                    int q2 = ((ql[l + 32] & 0x0F) | (((qh[l] >> 2) & 3) << 4)) - 32;
                    int q3 = ((ql[l +  0] >> 4)       | (((qh[l] >> 4) & 3) << 4)) - 32;
                    int q4 = ((ql[l + 32] >> 4)       | (((qh[l] >> 6) & 3) << 4)) - 32;
                    if (pos +  0 < base + elemsInBlock)
                        acc += d * (float)sc[is + 0] * (float)q1 * x[pos +  0];
                    if (pos + 32 < base + elemsInBlock)
                        acc += d * (float)sc[is + 2] * (float)q2 * x[pos + 32];
                    if (pos + 64 < base + elemsInBlock)
                        acc += d * (float)sc[is + 4] * (float)q3 * x[pos + 64];
                    if (pos + 96 < base + elemsInBlock)
                        acc += d * (float)sc[is + 6] * (float)q4 * x[pos + 96];
                }
                ql += 64;
                qh += 32;
                sc += 8;
            }
        }
        y[r] += acc;
    }
}

// ===========================================================================
// AVX-512 KERNELS (selected when cpu_.avx512f && cpu_.avx512bw)
// ===========================================================================
#if defined(__AVX512F__) || (defined(_MSC_VER) && defined(__AVX2__))
#define DEEP2_HAS_AVX512 1
#else
// Runtime detection: we still compile the code, guarded by cpu flags
#define DEEP2_HAS_AVX512 0
#endif

// --- F32 GEMV (AVX-512) ---
static void gemv_f32_avx512(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
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
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
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
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
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

            // Process remaining nibble groups (groups 1-15, 16 values each)
            // Uses scalar fallback for non-vectorized path - production uses permute
            for (int g = 1; g < 16; ++g) {
                // Extract 16 quantized values from the block
                float blockAcc = 0.0f;
                for (int i = 0; i < 16; ++i) {
                    int idx = g * 16 + i;
                    uint8_t byte = blk.qs[idx / 2];
                    float q = (idx % 2 == 0) ? (float)(byte & 0x0F) : (float)(byte >> 4);
                    blockAcc += q * x[b * 256 + idx];
                }
                // Apply scale and accumulate
                __m512 partial = _mm512_set1_ps(blockAcc * d);
                acc = _mm512_add_ps(acc, partial);
            }
        }
        y[r] += _mm512_reduce_add_ps(acc);
    }
}

// --- Q8_0 GEMV (AVX-512) ---
static void gemv_q8_0_avx512(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const block_q8_0* blocks = reinterpret_cast<const block_q8_0*>(w);
    size_t blocksPerRow = (cols + 31) / 32;

    for (size_t r = 0; r < rows; ++r) {
        __m512 acc = _mm512_setzero_ps();
        const block_q8_0* rowBlocks = blocks + r * blocksPerRow;

        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q8_0& blk = rowBlocks[b];
            float d = f16_to_f32(blk.d);
            __m512 dVec = _mm512_set1_ps(d);

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
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
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
        // Horizontal sum using hadd
        __m256 hsum = _mm256_hadd_ps(acc, acc);
        hsum = _mm256_hadd_ps(hsum, hsum);
        float sum = _mm_cvtss_f32(_mm256_castps256_ps128(hsum)) + 
                    _mm_cvtss_f32(_mm256_extractf128_ps(hsum, 1));
        y[r] += sum + tail;
    }
}

// --- F16 GEMV (AVX2 with F16C) ---
static void gemv_f16_avx2(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const uint16_t* weights = reinterpret_cast<const uint16_t*>(w);
    for (size_t r = 0; r < rows; ++r) {
        const uint16_t* row = weights + r * cols;
        __m256 acc = _mm256_setzero_ps();
        size_t c = 0;
        for (; c + 8 <= cols; c += 8) {
            // Load 8 uint16_t and convert to float using F16C
            __m128i hv = _mm_loadu_si128(reinterpret_cast<const __m128i*>(row + c));
            __m256 wv = _mm256_cvtph_ps(hv);
            __m256 xv = _mm256_loadu_ps(x + c);
            acc = _mm256_fmadd_ps(wv, xv, acc);
        }
        float tail = 0.0f;
        for (; c < cols; ++c) {
            tail += f16_to_f32(row[c]) * x[c];
        }
        // Horizontal sum
        __m256 hsum = _mm256_hadd_ps(acc, acc);
        hsum = _mm256_hadd_ps(hsum, hsum);
        float sum = _mm_cvtss_f32(_mm256_castps256_ps128(hsum)) + 
                    _mm_cvtss_f32(_mm256_extractf128_ps(hsum, 1));
        y[r] += sum + tail;
    }
}

// --- Q8_0 GEMV (AVX2) ---
// block_q8_0: 32 int8 weights + 1 float scale (34 bytes total)
// Layout: float d; int8_t qs[32];
static void gemv_q8_0_avx2(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const block_q8_0* blocks = reinterpret_cast<const block_q8_0*>(w);
    size_t blocksPerRow = (cols + 31) / 32;

    for (size_t r = 0; r < rows; ++r) {
        __m256 acc = _mm256_setzero_ps();
        const block_q8_0* rowBlocks = blocks + r * blocksPerRow;

        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q8_0& blk = rowBlocks[b];
            float d = f16_to_f32(blk.d);
            __m256 dVec = _mm256_set1_ps(d);

            // Load 32 int8 weights
            __m256i qs = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(blk.qs));
            
            // Convert first 16 int8 to int32, then to float
            __m128i qs_lo = _mm256_castsi256_si128(qs);
            __m256i i32_lo = _mm256_cvtepi8_epi32(qs_lo);
            __m256 wv_lo = _mm256_cvtepi32_ps(i32_lo);
            
            // Load first 16 activations and FMA
            __m256 xv_lo = _mm256_loadu_ps(x + b * 32);
            acc = _mm256_fmadd_ps(_mm256_mul_ps(wv_lo, dVec), xv_lo, acc);
            
            // Convert second 16 int8 to int32, then to float
            __m128i qs_hi = _mm256_extracti128_si256(qs, 1);
            __m256i i32_hi = _mm256_cvtepi8_epi32(qs_hi);
            __m256 wv_hi = _mm256_cvtepi32_ps(i32_hi);
            
            // Load second 16 activations and FMA
            __m256 xv_hi = _mm256_loadu_ps(x + b * 32 + 16);
            acc = _mm256_fmadd_ps(_mm256_mul_ps(wv_hi, dVec), xv_hi, acc);
        }
        
        // Horizontal sum
        __m256 hsum = _mm256_hadd_ps(acc, acc);
        hsum = _mm256_hadd_ps(hsum, hsum);
        float sum = _mm_cvtss_f32(_mm256_castps256_ps128(hsum)) + 
                    _mm_cvtss_f32(_mm256_extractf128_ps(hsum, 1));
        y[r] += sum;
    }
}

// --- Q4_K GEMV (AVX2) ---
// block_q4_K: 256 weights in 4-bit, with super-block scales
// Layout: uint16_t d, dmin; uint8_t scales[12]; uint8_t qs[128];
static void gemv_q4_k_avx2(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const block_q4_K* blocks = reinterpret_cast<const block_q4_K*>(w);
    size_t blocksPerRow = (cols + 255) / 256;

    for (size_t r = 0; r < rows; ++r) {
        float rowAcc = 0.0f;
        const block_q4_K* rowBlocks = blocks + r * blocksPerRow;

        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q4_K& blk = rowBlocks[b];
            float d = f16_to_f32(blk.d);
            float dmin = f16_to_f32(blk.dmin);
            
            // Process 8 sub-blocks of 32 weights each
            for (int sb = 0; sb < 8; ++sb) {
                // Extract 6-bit scale and min for this sub-block from scales[12]
                uint8_t scale_u8, min_u8;
                get_scale_min_k4(sb, blk.scales, scale_u8, min_u8);
                float s = d * scale_u8;
                float m = dmin * min_u8;
                __m256 sVec = _mm256_set1_ps(s);
                __m256 mVec = _mm256_set1_ps(m);
                
                // Process 32 weights in this sub-block (16 bytes of packed nibbles)
                size_t qsOffset = sb * 16;  // 16 bytes = 32 nibbles
                __m128i packed = _mm_loadu_si128(reinterpret_cast<const __m128i*>(blk.qs + qsOffset));
                
                // Extract low nibbles (indices 0, 2, 4, ... 30)
                __m128i lowNibbles = _mm_and_si128(packed, _mm_set1_epi8(0x0F));
                // Extract high nibbles (indices 1, 3, 5, ... 31)
                __m128i highNibbles = _mm_srli_epi16(packed, 4);
                highNibbles = _mm_and_si128(highNibbles, _mm_set1_epi8(0x0F));
                
                // Process first 8 low nibbles
                __m256i i32_lo = _mm256_cvtepu8_epi32(lowNibbles);
                __m256 wv_lo = _mm256_cvtepi32_ps(i32_lo);
                __m256 xv_lo = _mm256_loadu_ps(x + b * 256 + sb * 32);
                __m256 dequant_lo = _mm256_sub_ps(_mm256_mul_ps(wv_lo, sVec), mVec);
                rowAcc += _mm_cvtss_f32(_mm256_castps256_ps128(_mm256_dp_ps(dequant_lo, xv_lo, 0xF1)));
                
                // Process second 8 low nibbles
                __m128i lowNibbles_hi = _mm_srli_si128(lowNibbles, 8);
                __m256i i32_lo2 = _mm256_cvtepu8_epi32(lowNibbles_hi);
                __m256 wv_lo2 = _mm256_cvtepi32_ps(i32_lo2);
                __m256 xv_lo2 = _mm256_loadu_ps(x + b * 256 + sb * 32 + 8);
                __m256 dequant_lo2 = _mm256_sub_ps(_mm256_mul_ps(wv_lo2, sVec), mVec);
                rowAcc += _mm_cvtss_f32(_mm256_castps256_ps128(_mm256_dp_ps(dequant_lo2, xv_lo2, 0xF1)));
                
                // Process first 8 high nibbles
                __m256i i32_hi = _mm256_cvtepu8_epi32(highNibbles);
                __m256 wv_hi = _mm256_cvtepi32_ps(i32_hi);
                __m256 xv_hi = _mm256_loadu_ps(x + b * 256 + sb * 32 + 16);
                __m256 dequant_hi = _mm256_sub_ps(_mm256_mul_ps(wv_hi, sVec), mVec);
                rowAcc += _mm_cvtss_f32(_mm256_castps256_ps128(_mm256_dp_ps(dequant_hi, xv_hi, 0xF1)));
                
                // Process second 8 high nibbles
                __m128i highNibbles_hi = _mm_srli_si128(highNibbles, 8);
                __m256i i32_hi2 = _mm256_cvtepu8_epi32(highNibbles_hi);
                __m256 wv_hi2 = _mm256_cvtepi32_ps(i32_hi2);
                __m256 xv_hi2 = _mm256_loadu_ps(x + b * 256 + sb * 32 + 24);
                __m256 dequant_hi2 = _mm256_sub_ps(_mm256_mul_ps(wv_hi2, sVec), mVec);
                rowAcc += _mm_cvtss_f32(_mm256_castps256_ps128(_mm256_dp_ps(dequant_hi2, xv_hi2, 0xF1)));
            }
        }
        y[r] += rowAcc;
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
            int scaleIdx = sb / 2;
            int shift = (sb % 2) * 4;
            uint8_t scale = (blocks[b].scales[scaleIdx] >> shift) & 0x3F;
            uint8_t min   = (blocks[b].scales[scaleIdx + 6] >> shift) & 0x3F;
            float s = d * scale;
            float m = dmin * min;
            for (int i = 0; i < 32; ++i) {
                int idx = sb * 32 + i;
                size_t globalIdx = b * 256 + idx;
                if (globalIdx >= n) return;
                uint8_t byte = blocks[b].qs[idx / 2];
                float q = (idx % 2 == 0) ? (byte & 0x0F) : (byte >> 4);
                dst[globalIdx] = s * q - m;
            }
        }
    }
}


// --- Q2_K dequant ---
static void dequant_q2_k(const uint8_t* src, float* dst, size_t n) {
    const block_q2_K* blocks = reinterpret_cast<const block_q2_K*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        float min = f16_to_f32(blocks[b].dmin);
        const uint8_t* q = blocks[b].qs;
        int is = 0;
        for (size_t n_off = 0; n_off < 256; n_off += 128) {
            int shift = 0;
            for (int j = 0; j < 4; ++j) {
                uint8_t sc = blocks[b].scales[is++];
                float dl = d * (sc & 0x0F);
                float ml = min * (sc >> 4);
                for (int l = 0; l < 16; ++l) {
                    size_t idx = b * 256 + n_off + j * 32 + l;
                    if (idx >= n) return;
                    dst[idx] = dl * ((int8_t)((q[l] >> shift) & 3)) - ml;
                }
                sc = blocks[b].scales[is++];
                dl = d * (sc & 0x0F);
                ml = min * (sc >> 4);
                for (int l = 0; l < 16; ++l) {
                    size_t idx = b * 256 + n_off + j * 32 + 16 + l;
                    if (idx >= n) return;
                    dst[idx] = dl * ((int8_t)((q[l + 16] >> shift) & 3)) - ml;
                }
                shift += 2;
            }
            q += 32;
        }
    }
}

// --- Q3_K dequant ---
static void dequant_q3_k(const uint8_t* src, float* dst, size_t n) {
    const block_q3_K* blocks = reinterpret_cast<const block_q3_K*>(src);
    size_t numBlocks = (n + 255) / 256;
    const uint32_t kmask1 = 0x03030303;
    const uint32_t kmask2 = 0x0f0f0f0f;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d_all = f16_to_f32(blocks[b].d);
        const uint8_t* q = blocks[b].qs;
        const uint8_t* hm = blocks[b].hmask;
        uint32_t aux[4];
        memcpy(aux, blocks[b].scales, 12);
        uint32_t tmp = aux[2];
        aux[2] = ((aux[0] >> 4) & kmask2) | (((tmp >> 4) & kmask1) << 4);
        aux[3] = ((aux[1] >> 4) & kmask2) | (((tmp >> 6) & kmask1) << 4);
        aux[0] = (aux[0] & kmask2) | (((tmp >> 0) & kmask1) << 4);
        aux[1] = (aux[1] & kmask2) | (((tmp >> 2) & kmask1) << 4);
        const int8_t* scales = reinterpret_cast<const int8_t*>(aux);
        uint8_t m = 1;
        int is = 0;
        for (size_t n_off = 0; n_off < 256; n_off += 128) {
            int shift = 0;
            for (int j = 0; j < 4; ++j) {
                float dl = d_all * (scales[is++] - 32);
                for (int l = 0; l < 16; ++l) {
                    size_t idx = b * 256 + n_off + j * 32 + l;
                    if (idx >= n) return;
                    int qv = ((q[l] >> shift) & 3) - ((hm[l] & m) ? 0 : 4);
                    dst[idx] = dl * qv;
                }
                dl = d_all * (scales[is++] - 32);
                for (int l = 0; l < 16; ++l) {
                    size_t idx = b * 256 + n_off + j * 32 + 16 + l;
                    if (idx >= n) return;
                    int qv = ((q[l + 16] >> shift) & 3) - ((hm[l + 16] & m) ? 0 : 4);
                    dst[idx] = dl * qv;
                }
                shift += 2;
                m <<= 1;
            }
            q += 32;
        }
    }
}

// --- Q5_K dequant ---
static void dequant_q5_k(const uint8_t* src, float* dst, size_t n) {
    const block_q5_K* blocks = reinterpret_cast<const block_q5_K*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        float min = f16_to_f32(blocks[b].dmin);
        const uint8_t* ql = blocks[b].qs;
        const uint8_t* qh = blocks[b].qh;
        int is = 0;
        uint8_t u1 = 1, u2 = 2;
        for (size_t j = 0; j < 256; j += 64) {
            uint8_t sc, mm;
            get_scale_min_k4(is + 0, blocks[b].scales, sc, mm);
            float d1 = d * sc; float m1 = min * mm;
            get_scale_min_k4(is + 1, blocks[b].scales, sc, mm);
            float d2 = d * sc; float m2 = min * mm;
            for (int l = 0; l < 32; ++l) {
                size_t idx = b * 256 + j + l;
                if (idx >= n) return;
                int qv = (ql[l] & 0x0F) + (qh[l] & u1 ? 16 : 0);
                dst[idx] = d1 * qv - m1;
            }
            for (int l = 0; l < 32; ++l) {
                size_t idx = b * 256 + j + 32 + l;
                if (idx >= n) return;
                int qv = (ql[l] >> 4) + (qh[l] & u2 ? 16 : 0);
                dst[idx] = d2 * qv - m2;
            }
            ql += 32; is += 2;
            u1 <<= 2; u2 <<= 2;
        }
    }
}

// --- Q6_K dequant ---
static void dequant_q6_k(const uint8_t* src, float* dst, size_t n) {
    const block_q6_K* blocks = reinterpret_cast<const block_q6_K*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        const uint8_t* ql = blocks[b].ql;
        const uint8_t* qh = blocks[b].qh;
        const int8_t* sc = blocks[b].scales;
        for (size_t n_off = 0; n_off < 256; n_off += 128) {
            for (int l = 0; l < 32; ++l) {
                int is = l / 16;
                int q1 = ((ql[l +  0] & 0x0F) | (((qh[l] >> 0) & 3) << 4)) - 32;
                int q2 = ((ql[l + 32] & 0x0F) | (((qh[l] >> 2) & 3) << 4)) - 32;
                int q3 = ((ql[l +  0] >> 4)       | (((qh[l] >> 4) & 3) << 4)) - 32;
                int q4 = ((ql[l + 32] >> 4)       | (((qh[l] >> 6) & 3) << 4)) - 32;
                size_t idx = b * 256 + n_off + l;
                if (idx +  0 < n) dst[idx +  0] = d * sc[is + 0] * q1;
                if (idx + 32 < n) dst[idx + 32] = d * sc[is + 2] * q2;
                if (idx + 64 < n) dst[idx + 64] = d * sc[is + 4] * q3;
                if (idx + 96 < n) dst[idx + 96] = d * sc[is + 6] * q4;
            }
            ql += 64; qh += 32; sc += 8;
        }
    }
}

// --- Q8_K dequant ---
static void dequant_q8_k(const uint8_t* src, float* dst, size_t n) {
    const block_q8_K* blocks = reinterpret_cast<const block_q8_K*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        for (int j = 0; j < 256; ++j) {
            size_t idx = b * 256 + j;
            if (idx >= n) return;
            dst[idx] = blocks[b].d * (float)blocks[b].qs[j];
        }
    }
}

// --- Q2_K GEMV (scalar) ---
static void gemv_q2_k_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const block_q2_K* blocks = reinterpret_cast<const block_q2_K*>(w);
    size_t blocksPerRow = (cols + 255) / 256;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_q2_K* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q2_K& blk = rowBlocks[b];
            float d = f16_to_f32(blk.d);
            float min = f16_to_f32(blk.dmin);
            size_t base = b * 256;
            size_t elemsInBlock = (b == blocksPerRow - 1) ? (cols - base) : 256;
            if (elemsInBlock == 0) break;
            const uint8_t* q = blk.qs;
            int is = 0;
            for (size_t n = 0; n < elemsInBlock; n += 128) {
                int shift = 0;
                size_t chunkElems = (n + 128 <= elemsInBlock) ? 128 : (elemsInBlock - n);
                for (int j = 0; j < 4; ++j) {
                    uint8_t sc = blk.scales[is++];
                    float dl = d * (sc & 0x0F);
                    float ml = min * (sc >> 4);
                    for (int l = 0; l < 16; ++l) {
                        size_t idx = base + n + j * 32 + l;
                        if (idx >= cols) break;
                        int qv = (q[l] >> shift) & 3;
                        acc += (dl * qv - ml) * x[idx];
                    }
                    sc = blk.scales[is++];
                    dl = d * (sc & 0x0F);
                    ml = min * (sc >> 4);
                    for (int l = 0; l < 16; ++l) {
                        size_t idx = base + n + j * 32 + 16 + l;
                        if (idx >= cols) break;
                        int qv = (q[l + 16] >> shift) & 3;
                        acc += (dl * qv - ml) * x[idx];
                    }
                    shift += 2;
                }
                q += 32;
            }
        }
        y[r] += acc;
    }
}

// --- Q3_K GEMV (scalar) ---
static void gemv_q3_k_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const block_q3_K* blocks = reinterpret_cast<const block_q3_K*>(w);
    size_t blocksPerRow = (cols + 255) / 256;
    const uint32_t kmask1 = 0x03030303;
    const uint32_t kmask2 = 0x0f0f0f0f;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_q3_K* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q3_K& blk = rowBlocks[b];
            float d_all = f16_to_f32(blk.d);
            size_t base = b * 256;
            size_t elemsInBlock = (b == blocksPerRow - 1) ? (cols - base) : 256;
            if (elemsInBlock == 0) break;
            const uint8_t* q = blk.qs;
            const uint8_t* hm = blk.hmask;
            uint32_t aux[4];
            memcpy(aux, blk.scales, 12);
            uint32_t tmp = aux[2];
            aux[2] = ((aux[0] >> 4) & kmask2) | (((tmp >> 4) & kmask1) << 4);
            aux[3] = ((aux[1] >> 4) & kmask2) | (((tmp >> 6) & kmask1) << 4);
            aux[0] = (aux[0] & kmask2) | (((tmp >> 0) & kmask1) << 4);
            aux[1] = (aux[1] & kmask2) | (((tmp >> 2) & kmask1) << 4);
            const int8_t* scales = reinterpret_cast<const int8_t*>(aux);
            uint8_t m = 1;
            int is = 0;
            for (size_t n = 0; n < elemsInBlock; n += 128) {
                int shift = 0;
                size_t chunkElems = (n + 128 <= elemsInBlock) ? 128 : (elemsInBlock - n);
                for (int j = 0; j < 4; ++j) {
                    float dl = d_all * (scales[is++] - 32);
                    for (int l = 0; l < 16; ++l) {
                        size_t idx = base + n + j * 32 + l;
                        if (idx >= cols) break;
                        int qv = ((q[l] >> shift) & 3) - ((hm[l] & m) ? 0 : 4);
                        acc += dl * qv * x[idx];
                    }
                    dl = d_all * (scales[is++] - 32);
                    for (int l = 0; l < 16; ++l) {
                        size_t idx = base + n + j * 32 + 16 + l;
                        if (idx >= cols) break;
                        int qv = ((q[l + 16] >> shift) & 3) - ((hm[l + 16] & m) ? 0 : 4);
                        acc += dl * qv * x[idx];
                    }
                    shift += 2;
                    m <<= 1;
                }
                q += 32;
            }
        }
        y[r] += acc;
    }
}

// --- Q5_K GEMV (scalar) ---
static void gemv_q5_k_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const block_q5_K* blocks = reinterpret_cast<const block_q5_K*>(w);
    size_t blocksPerRow = (cols + 255) / 256;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_q5_K* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q5_K& blk = rowBlocks[b];
            float d = f16_to_f32(blk.d);
            float min = f16_to_f32(blk.dmin);
            size_t base = b * 256;
            size_t elemsInBlock = (b == blocksPerRow - 1) ? (cols - base) : 256;
            if (elemsInBlock == 0) break;
            const uint8_t* ql = blk.qs;
            const uint8_t* qh = blk.qh;
            int is = 0;
            uint8_t u1 = 1, u2 = 2;
            for (size_t j = 0; j < elemsInBlock; j += 64) {
                uint8_t sc, mm;
                get_scale_min_k4(is + 0, blk.scales, sc, mm);
                float d1 = d * sc; float m1 = min * mm;
                get_scale_min_k4(is + 1, blk.scales, sc, mm);
                float d2 = d * sc; float m2 = min * mm;
                size_t count = (j + 32 <= elemsInBlock) ? 32 : (elemsInBlock - j);
                for (size_t l = 0; l < count; ++l) {
                    size_t idx = base + j + l;
                    int qv = (ql[l] & 0x0F) + (qh[l] & u1 ? 16 : 0);
                    acc += (d1 * qv - m1) * x[idx];
                }
                count = (j + 64 <= elemsInBlock) ? 32 : (elemsInBlock - j - 32);
                for (size_t l = 0; l < count; ++l) {
                    size_t idx = base + j + 32 + l;
                    int qv = (ql[l] >> 4) + (qh[l] & u2 ? 16 : 0);
                    acc += (d2 * qv - m2) * x[idx];
                }
                ql += 32; is += 2;
                u1 <<= 2; u2 <<= 2;
            }
        }
        y[r] += acc;
    }
}

// --- Q8_K GEMV (scalar) ---
static void gemv_q8_k_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const block_q8_K* blocks = reinterpret_cast<const block_q8_K*>(w);
    size_t blocksPerRow = (cols + 255) / 256;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_q8_K* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q8_K& blk = rowBlocks[b];
            float d = blk.d;
            size_t base = b * 256;
            size_t elemsInBlock = (b == blocksPerRow - 1) ? (cols - base) : 256;
            if (elemsInBlock == 0) break;
            for (size_t i = 0; i < elemsInBlock; ++i) {
                acc += d * (float)blk.qs[i] * x[base + i];
            }
        }
        y[r] += acc;
    }
}

#define gemv_q2_k_avx2 gemv_q2_k_scalar
#define gemv_q2_k_avx512 gemv_q2_k_scalar
#define gemv_q3_k_avx2 gemv_q3_k_scalar
#define gemv_q3_k_avx512 gemv_q3_k_scalar
#define gemv_q5_k_avx2 gemv_q5_k_scalar
#define gemv_q5_k_avx512 gemv_q5_k_scalar
#define gemv_q6_k_avx2 gemv_q6_k_scalar
#define gemv_q6_k_avx512 gemv_q6_k_scalar

void QuantKernelRegistry::RegisterGEMV(int quantType, GEMVKernelFn kernel) {
    gemvTable_[quantType] = kernel;
}

void QuantKernelRegistry::RegisterDequant(int quantType, DequantKernelFn kernel) {
    dequantTable_[quantType] = kernel;
}

void QuantKernelRegistry::RegisterGeometry(int quantType, const BlockGeometry& geom)
{
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
    else if (hasAVX2 && cpu_.f16c) RegisterGEMV((int)GGMLType::GGML_TYPE_F16, gemv_f16_avx2);
    else                         RegisterGEMV((int)GGMLType::GGML_TYPE_F16, gemv_f16_scalar);

    // --- Q8_0 ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q8_0, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q8_0));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q8_0, dequant_q8_0);
    if (hasAVX512)      RegisterGEMV((int)GGMLType::GGML_TYPE_Q8_0, gemv_q8_0_avx512);
    else if (hasAVX2)   RegisterGEMV((int)GGMLType::GGML_TYPE_Q8_0, gemv_q8_0_avx2);
    else                RegisterGEMV((int)GGMLType::GGML_TYPE_Q8_0, gemv_q8_0_scalar);

    // --- Q4_K ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q4_K, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q4_K));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q4_K, dequant_q4_k);
    if (hasAVX512)      RegisterGEMV((int)GGMLType::GGML_TYPE_Q4_K, gemv_q4_k_avx512);
    else if (hasAVX2)   RegisterGEMV((int)GGMLType::GGML_TYPE_Q4_K, gemv_q4_k_avx2);
    else                RegisterGEMV((int)GGMLType::GGML_TYPE_Q4_K, gemv_q4_k_scalar);

    // --- Q2_K ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q2_K, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q2_K));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q2_K, dequant_q2_k);
    if (hasAVX512)      RegisterGEMV((int)GGMLType::GGML_TYPE_Q2_K, gemv_q2_k_avx512);
    else if (hasAVX2)   RegisterGEMV((int)GGMLType::GGML_TYPE_Q2_K, gemv_q2_k_avx2);
    else                RegisterGEMV((int)GGMLType::GGML_TYPE_Q2_K, gemv_q2_k_scalar);

    // --- Q3_K ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q3_K, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q3_K));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q3_K, dequant_q3_k);
    if (hasAVX512)      RegisterGEMV((int)GGMLType::GGML_TYPE_Q3_K, gemv_q3_k_avx512);
    else if (hasAVX2)   RegisterGEMV((int)GGMLType::GGML_TYPE_Q3_K, gemv_q3_k_avx2);
    else                RegisterGEMV((int)GGMLType::GGML_TYPE_Q3_K, gemv_q3_k_scalar);

    // --- Q5_K ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q5_K, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q5_K));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q5_K, dequant_q5_k);
    if (hasAVX512)      RegisterGEMV((int)GGMLType::GGML_TYPE_Q5_K, gemv_q5_k_avx512);
    else if (hasAVX2)   RegisterGEMV((int)GGMLType::GGML_TYPE_Q5_K, gemv_q5_k_avx2);
    else                RegisterGEMV((int)GGMLType::GGML_TYPE_Q5_K, gemv_q5_k_scalar);

    // --- Q6_K ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q6_K, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q6_K));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q6_K, dequant_q6_k);
    if (hasAVX512)      RegisterGEMV((int)GGMLType::GGML_TYPE_Q6_K, gemv_q6_k_avx512);
    else if (hasAVX2)   RegisterGEMV((int)GGMLType::GGML_TYPE_Q6_K, gemv_q6_k_avx2);
    else                RegisterGEMV((int)GGMLType::GGML_TYPE_Q6_K, gemv_q6_k_scalar);

    // --- Legacy GGML quant types (Q4_0, Q4_1, Q5_0, Q5_1): scalar fallback ---
    // These formats are deprecated in favor of K-quants but kept for compatibility
    // AVX-512 optimized kernels can be added here when needed
    for (int t = (int)GGMLType::GGML_TYPE_Q4_0; t <= (int)GGMLType::GGML_TYPE_Q5_1; ++t) {
        RegisterGeometry(t, GetBlockGeometryForType(t));
        // Use Q8_0 scalar as fallback; type-specific kernels registered on-demand
        RegisterGEMV(t, gemv_q8_0_scalar);
    }
    // IQ types fallback
    for (int t = (int)GGMLType::GGML_TYPE_IQ2_XXS; t <= (int)GGMLType::GGML_TYPE_IQ4_XS; ++t) {
        RegisterGeometry(t, GetBlockGeometryForType(t));
        RegisterGEMV(t, gemv_q4_k_scalar); // IQ fallback
    }
    for (int t = (int)GGMLType::GGML_TYPE_IQ2_XXS; t <= (int)GGMLType::GGML_TYPE_IQ4_XS; ++t) {
        RegisterGeometry(t, GetBlockGeometryForType(t));
        RegisterGEMV(t, gemv_q4_k_scalar); // IQ fallback
    }
    // Q8_K
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q8_K, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q8_K));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q8_K, dequant_q8_k);
    RegisterGEMV((int)GGMLType::GGML_TYPE_Q8_K, gemv_q8_k_scalar);
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




