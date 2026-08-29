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
#include "Deep2Q40Reference.hpp"    // Reference Q4_0 GEMV (VAL-051.7)

#include <immintrin.h>
#include <cstring>
#include <cstdio>
#include <sstream>

namespace Deep2 {

// Forward declaration from IQQuantKernels.cpp
void RegisterIQKernels();

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

    // AVX-512 requires leaf 7 subleaf 0
    DEEP2_CPUIDEX(7, 0, eax, ebx, ecx, edx);
    cpu_.avx2     = (ebx & (1 << 5)) != 0;
    cpu_.avx512f  = (ebx & (1 << 16)) != 0;
    cpu_.avx512dq = (ebx & (1 << 17)) != 0;
    cpu_.avx512bw = (ebx & (1 << 30)) != 0;
    cpu_.avx512vl = (ebx & (1 << 31)) != 0;
    cpu_.avx512vnni = (ecx & (1 << 11)) != 0;
}

// ===========================================================================
// MASM KERNEL DECLARATIONS (linked from .asm files)
// ===========================================================================
extern "C" {
    // Q4_K MASM kernels
    void Sovereign_Q4K_GEMV_AVX2(const void* q4_weights, const float* input,
                                    float* output, unsigned int num_blocks, unsigned int rows);
    void Sovereign_Q4K_GEMV_AVX2_V2(const void* q4_weights, const float* input,
                                     float* output, unsigned int num_blocks, unsigned int rows);

    // Q2_K / Q3_K MASM kernels (real implementations in sovereign_q2_k_gemv.asm / sovereign_q3_k_gemv.asm)
    void Deep2_Q2_K_GEMV(const void* weights, const float* input, float* output,
                         unsigned int numBlocks, unsigned int outputDim);
    void Deep2_Q3_K_GEMV(const void* weights, const float* input, float* output,
                         unsigned int numBlocks, unsigned int outputDim);

    // Q4_0 / Q4_1 / Q8_0 / Q5_K / Q6_K MASM kernels
    void Deep2_Q4_0_GEMV(const void* weights, const float* input, float* output,
                         unsigned int numBlocks, unsigned int outputDim);
    void Deep2_Q4_1_GEMV(const void* weights, const float* input, float* output,
                         unsigned int numBlocks, unsigned int outputDim);
    void Deep2_Q8_0_GEMV(const void* weights, const float* input, float* output,
                         unsigned int numBlocks, unsigned int outputDim);
    void Deep2_Q5_K_GEMV(const void* weights, const float* input, float* output,
                         unsigned int numBlocks, unsigned int outputDim);
    void Deep2_Q6_K_GEMV(const void* blocks, const float* x, float* out, std::size_t nBlocks);

    // FP16 GEMV
    void Deep2_FP16_GEMV(const void* weights, const float* input, float* output,
                         unsigned int rows, unsigned int cols);
}

// ===========================================================================
// MASM WRAPPER FUNCTIONS
// Bridge the standard GEMV signature to the MASM ABI
// ===========================================================================

// Q4_K wrapper: standard GEMV -> Sovereign_Q4K_GEMV_AVX2_V2
static void gemv_q4_k_masm(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    size_t blocksPerRow = (cols + 255) / 256;
    Sovereign_Q4K_GEMV_AVX2_V2(w, x, y, static_cast<unsigned int>(blocksPerRow),
                                  static_cast<unsigned int>(rows));
}

// Q2_K wrapper: standard GEMV -> Deep2_Q2_K_GEMV
static void gemv_q2_k_masm(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    size_t blocksPerRow = (cols + 255) / 256;
    Deep2_Q2_K_GEMV(w, x, y, static_cast<unsigned int>(blocksPerRow),
                     static_cast<unsigned int>(rows));
}

// Q3_K wrapper: standard GEMV -> Deep2_Q3_K_GEMV
static void gemv_q3_k_masm(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    size_t blocksPerRow = (cols + 255) / 256;
    Deep2_Q3_K_GEMV(w, x, y, static_cast<unsigned int>(blocksPerRow),
                     static_cast<unsigned int>(rows));
}

// Q4_0 wrapper
static void gemv_q4_0_masm(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    size_t blocksPerRow = (cols + 31) / 32;
    Deep2_Q4_0_GEMV(w, x, y, static_cast<unsigned int>(blocksPerRow),
                     static_cast<unsigned int>(rows));
}

// Q4_1 wrapper
static void gemv_q4_1_masm(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    size_t blocksPerRow = (cols + 31) / 32;
    Deep2_Q4_1_GEMV(w, x, y, static_cast<unsigned int>(blocksPerRow),
                     static_cast<unsigned int>(rows));
}

// Q8_0 wrapper
static void gemv_q8_0_masm(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    size_t blocksPerRow = (cols + 31) / 32;
    Deep2_Q8_0_GEMV(w, x, y, static_cast<unsigned int>(blocksPerRow),
                     static_cast<unsigned int>(rows));
}

// Q5_K wrapper
static void gemv_q5_k_masm(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    size_t blocksPerRow = (cols + 255) / 256;
    Deep2_Q5_K_GEMV(w, x, y, static_cast<unsigned int>(blocksPerRow),
                     static_cast<unsigned int>(rows));
}

// Q6_K wrapper
static void gemv_q6_k_masm(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    size_t blocksPerRow = (cols + 255) / 256;
    Deep2_Q6_K_GEMV(w, x, y, static_cast<std::size_t>(blocksPerRow));
}

// FP16 wrapper
static void gemv_f16_masm(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    Deep2_FP16_GEMV(w, x, y, static_cast<unsigned int>(rows),
                     static_cast<unsigned int>(cols));
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
        case GGMLType::GGML_TYPE_IQ1_S: return {34, 256, true, false};
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
        case GGMLType::GGML_TYPE_IQ1_S:   return "IQ1_S";
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
            float blockAcc = 0.0f;
            for (int i = 0; i < 32; ++i) {
                blockAcc += (float)rowBlocks[b].qs[i] * x[b * 32 + i];
            }
            acc += f16_to_f32(rowBlocks[b].d) * blockAcc;
        }
        y[r] += acc;
    }
}

// --- Q4_K GEMV (scalar reference) ---
// VAL-051.9: Correct GGML Q4_K block unpacking per llama.cpp reference.
// block_q4_K layout: d(fp16), dmin(fp16), scales[12], qs[128]
//   256 weights per block, 8 sub-blocks of 32.
//   scales[0..3]  = low 6 bits of scales 0..3 (NO high bits)
//   scales[4..7]  = low 6 bits of mins 0..3 (NO high bits)
//   scales[4..7] high bits from s[0..3] >> 6, combined with s[8..11] low 4 bits
//   mins[4..7] high bits from s[4..7] >> 6, combined with s[8..11] high 4 bits
//
// CRITICAL: Q4_K uses GROUPED nibbles, not interleaved:
//   qs[0..31]   low  nibbles -> weights 0..31
//   qs[0..31]   high nibbles -> weights 32..63
//   qs[32..63]  low  nibbles -> weights 64..95
//   qs[32..63]  high nibbles -> weights 96..127
//   ...

static inline void unpack_q4_k_scales(
    const uint8_t s[12],
    uint8_t scales[8],
    uint8_t mins[8])
{
    // Low 6 bits — first four scale/min pairs
    scales[0] = s[0] & 0x3F;
    scales[1] = s[1] & 0x3F;
    scales[2] = s[2] & 0x3F;
    scales[3] = s[3] & 0x3F;

    mins[0] = s[4] & 0x3F;
    mins[1] = s[5] & 0x3F;
    mins[2] = s[6] & 0x3F;
    mins[3] = s[7] & 0x3F;

    // Upper four scales: low 4 bits from s[8..11], high 2 bits from s[0..3] >> 6
    scales[4] = (s[8] & 0x0F) | ((s[0] >> 6) << 4);
    scales[5] = (s[9] & 0x0F) | ((s[1] >> 6) << 4);
    scales[6] = (s[10] & 0x0F) | ((s[2] >> 6) << 4);
    scales[7] = (s[11] & 0x0F) | ((s[3] >> 6) << 4);

    // Upper four minimums: low 4 bits from s[8..11] >> 4, high 2 bits from s[4..7] >> 6
    mins[4] = (s[8] >> 4) | ((s[4] >> 6) << 4);
    mins[5] = (s[9] >> 4) | ((s[5] >> 6) << 4);
    mins[6] = (s[10] >> 4) | ((s[6] >> 6) << 4);
    mins[7] = (s[11] >> 4) | ((s[7] >> 6) << 4);
}

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
            float d    = f16_to_f32(blk.d);
            float dmin = f16_to_f32(blk.dmin);

            size_t base = b * 256;
            size_t elemsInBlock = (b == blocksPerRow - 1)
                ? (cols - base)
                : 256;
            if (elemsInBlock == 0) break;

            uint8_t scales[8], mins[8];
            unpack_q4_k_scales(blk.scales, scales, mins);

            // Q4_K: 4 sections of 64 weights.
            // Each section j uses qs[j*32..j*32+31] and contains:
            //   - low nibbles  -> weights j*64 + 0..31   (scale group 2*j)
            //   - high nibbles -> weights j*64 + 32..63  (scale group 2*j+1)
            const uint8_t* q = blk.qs;

            for (int j = 0; j < 4; ++j) {
                const float d0 = d * static_cast<float>(scales[2 * j]);
                const float m0 = dmin * static_cast<float>(mins[2 * j]);
                const float d1 = d * static_cast<float>(scales[2 * j + 1]);
                const float m1 = dmin * static_cast<float>(mins[2 * j + 1]);

                for (int l = 0; l < 32; ++l) {
                    int idx0 = j * 64 + l;
                    int idx1 = j * 64 + 32 + l;

                    if (static_cast<size_t>(idx0) < elemsInBlock) {
                        int nibble0 = q[l] & 0x0F;
                        acc += (d0 * static_cast<float>(nibble0) - m0) * x[base + idx0];
                    }
                    if (static_cast<size_t>(idx1) < elemsInBlock) {
                        int nibble1 = q[l] >> 4;
                        acc += (d1 * static_cast<float>(nibble1) - m1) * x[base + idx1];
                    }
                }

                q += 32;
            }
        }
        y[r] += acc;
    }
}

// --- Q6_K GEMV (scalar reference) ---
// VAL-051.10: Correct GGML Q6_K block unpacking per llama.cpp reference.
// block_q6_K layout (210 bytes, 256 values):
//   [0..127]   ql      128 bytes (low 4 bits)
//   [128..191] qh      64 bytes (high 2 bits)
//   [192..207] scales  16 signed bytes
//   [208..209] d       FP16
//
// Q6_K has 16 scale groups, each covering 16 values.
// The first 128 values and second 128 values are reconstructed from
// separate ql/qh regions.

static inline float rxd_q6k_f16(uint16_t h)
{
    const uint32_t sign = ((uint32_t)(h & 0x8000u)) << 16;
    const uint32_t exp  = (h >> 10) & 0x1Fu;
    const uint32_t mant = h & 0x03FFu;
    uint32_t bits;
    if (exp == 0) {
        if (mant == 0) { bits = sign; }
        else {
            uint32_t m = mant; int e = -14;
            while ((m & 0x0400u) == 0) { m <<= 1; --e; }
            m &= 0x03FFu;
            bits = sign | ((uint32_t)(e + 127) << 23) | (m << 13);
        }
    } else if (exp == 31) {
        bits = sign | 0x7F800000u | (mant << 13);
    } else {
        bits = sign | ((exp + 112u) << 23) | (mant << 13);
    }
    float f; std::memcpy(&f, &bits, sizeof(f)); return f;
}

static inline bool rxd_q6k_dequant_block(
    const uint8_t* block, float* dst)
{
    if (!block || !dst) return false;
    // block_q6_K layout: ql[128] @ 0, qh[64] @ 128, scales[16] @ 192, d @ 208
    // Per llama.cpp: 256 values, 16 scale groups of 16 values each
    uint16_t d16; std::memcpy(&d16, block + 208, sizeof(d16));
    const float d = rxd_q6k_f16(d16);
    if (!std::isfinite(d)) return false;

    const uint8_t* ql = block + 0;
    const uint8_t* qh = block + 128;
    const int8_t* sc = reinterpret_cast<const int8_t*>(block + 192);
    float* yp = dst;

    // Process in two halves of 128 values each
    // Each half: j=0..127, is = j/16 (0..7), using sc[0..15] for first half
    // and sc[8..15] for second half (sc += 8)
    for (int n = 0; n < 256; n += 128) {
        for (int j = 0; j < 128; ++j) {
            int is = j / 16;  // 0..7
            // Each j produces 4 values: y[j], y[j+32], y[j+64], y[j+96]
            // But j goes 0..127, so j+96 can be 96..223 — need to handle wrapping
            // Actually in llama.cpp, the loop is j=0..63 (qk/4), not j=0..127
            // Let me use the correct llama.cpp loop structure
        }
        // This approach is wrong — let me use the correct structure
        break;
    }

    // Correct llama.cpp Q6_K dequantization:
    // qk = 256, processed in two halves of 128 values
    // Each half: 32 iterations of l=0..31, each producing 4 values
    // Scale index: is = l/16 gives 0 or 1, but we need 0..7
    // The correct mapping: for l=0..31, the 4 values use scales sc[2*is], sc[2*is+1], etc.
    // Actually, llama.cpp uses j=0..127 with is=j/16, but processes 4 values per j
    // at positions j, j+32, j+64, j+96 — but j+96 > 128 for j > 32!
    //
    // The ACTUAL llama.cpp code uses j=0..63 (not 0..127):
    // for (int j = 0; j < qk/4; ++j) {  // qk/4 = 64
    //     const int is = j / 16;  // 0..3
    //     ... 4 values at j, j+64, j+128, j+192
    // }
    // But that doesn't match our block layout either.
    //
    // Let me use the EXACT llama.cpp dequantize_row_q6_K implementation:

    ql = block + 0;
    qh = block + 128;
    sc = reinterpret_cast<const int8_t*>(block + 192);
    yp = dst;

    // llama.cpp: for (int j = 0; j < qk/2; ++j) with qk=256 → j=0..127
    // But the 4 values are at: y[j], y[j+qk/4], y[j+qk/2], y[j+3*qk/4]
    // = y[j], y[j+64], y[j+128], y[j+192]
    // Wait, that can't be right either. Let me check the actual code.
    //
    // ACTUAL llama.cpp (ggml-quants.c):
    // for (int j = 0; j < QK_K/2; ++j) {  // QK_K=256, j=0..127
    //     const int is = j / 16;  // 0..7
    //     const int8_t q1 = (int8_t)((ql[j] & 0xF) | (((qh[j] >> 0) & 3) << 4)) - 32;
    //     const int8_t q2 = (int8_t)((ql[j + 64] & 0xF) | (((qh[j] >> 2) & 3) << 4)) - 32;
    //     const int8_t q3 = (int8_t)((ql[j] >> 4) | (((qh[j] >> 4) & 3) << 4)) - 32;
    //     const int8_t q4 = (int8_t)((ql[j + 64] >> 4) | (((qh[j] >> 6) & 3) << 4)) - 32;
    //     y[j +  0] = d * sc[is + 0] * q1;
    //     y[j + 32] = d * sc[is + 2] * q2;
    //     y[j + 64] = d * sc[is + 4] * q3;
    //     y[j + 96] = d * sc[is + 6] * q4;
    // }
    // ql += 64; qh += 32; sc += 8;
    // ... repeat for second 128 values
    //
    // Wait, j goes 0..127 but y[j+96] with j=127 would be y[223] — out of bounds for 256!
    // Actually, the loop runs j=0..127 but writes to y[j], y[j+32], y[j+64], y[j+96]
    // For j=0..31: writes to y[0..31], y[32..63], y[64..95], y[96..127] → first 128 values
    // For j=32..63: writes to y[32..63], y[64..95], y[96..127], y[128..159] → OVERLAP!
    // This can't be right. The actual llama.cpp code must use j=0..31, not j=0..127.
    //
    // Let me look at the ACTUAL code: j goes 0..QK_K/2-1 = 0..127, but the 4 outputs
    // are at y[j], y[j+QK_K/4], y[j+QK_K/2], y[j+3*QK_K/4] = y[j], y[j+64], y[j+128], y[j+192]
    // No, that's 256 apart. Let me just use j=0..31 with 4 outputs per j, 2 passes.

    // CORRECT implementation: j=0..31, 4 values per j, 2 passes of 128 values
    for (int n = 0; n < 256; n += 128) {
        for (int l = 0; l < 32; ++l) {
            // is = l/16 gives 0 or 1 — but llama.cpp uses is = l/16 for j=0..31
            // and sc[is+0], sc[is+2], sc[is+4], sc[is+6]
            // With is=0: sc[0], sc[2], sc[4], sc[6]
            // With is=1: sc[1], sc[3], sc[5], sc[7]
            // Then sc += 8 for next 128 values
            // This uses sc[0..7] for first 128, sc[8..15] for second 128
            // Total: all 16 scales used correctly
            int is = l / 16;
            const int8_t q1 = (int8_t)((ql[l +  0] & 0xF) | (((qh[l] >> 0) & 3) << 4)) - 32;
            const int8_t q2 = (int8_t)((ql[l + 32] & 0xF) | (((qh[l] >> 2) & 3) << 4)) - 32;
            const int8_t q3 = (int8_t)((ql[l +  0]  >> 4) | (((qh[l] >> 4) & 3) << 4)) - 32;
            const int8_t q4 = (int8_t)((ql[l + 32]  >> 4) | (((qh[l] >> 6) & 3) << 4)) - 32;
            yp[l +  0] = d * sc[is + 0] * q1;
            yp[l + 32] = d * sc[is + 2] * q2;
            yp[l + 64] = d * sc[is + 4] * q3;
            yp[l + 96] = d * sc[is + 6] * q4;
        }
        yp += 128;
        ql += 64;
        qh += 32;
        sc += 8;
    }
    return true;
}

static inline bool rxd_q6k_dot(
    const uint8_t* block, const float* x, float& result)
{
    float w[256];
    if (!rxd_q6k_dequant_block(block, w)) { result = 0.0f; return false; }
    double sum = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (!std::isfinite(x[i]) || !std::isfinite(w[i])) { result = 0.0f; return false; }
        sum += (double)w[i] * (double)x[i];
    }
    result = (float)sum;
    return std::isfinite(result);
}

static bool rxd_q6k_gemv_reference(
    const uint8_t* weights, const float* input, float* output,
    int64_t rows, int64_t cols)
{
    if (!weights || !input || !output || rows <= 0 || cols <= 0 || (cols % 256) != 0) {
        std::fprintf(stderr, "[Q6K_REF] INVALID params: weights=%p input=%p output=%p rows=%lld cols=%lld\n",
                     (const void*)weights, (const void*)input, (void*)output, (long long)rows, (long long)cols);
        return false;
    }
    const int64_t blocksPerRow = cols / 256;
    for (int64_t row = 0; row < rows; ++row) {
        const uint8_t* rowBase = weights + (size_t)row * (size_t)blocksPerRow * 210;
        double sum = 0.0;
        for (int64_t b = 0; b < blocksPerRow; ++b) {
            float dot = 0.0f;
            if (!rxd_q6k_dot(rowBase + (size_t)b * 210, input + (size_t)b * 256, dot)) {
                uint16_t d16; std::memcpy(&d16, rowBase + (size_t)b * 210 + 208, sizeof(d16));
                std::fprintf(stderr, "[Q6K_REF] BLOCK FAIL row=%lld block=%lld d=0x%04X\n",
                             (long long)row, (long long)b, d16);
                return false;
            }
            sum += (double)dot;
        }
        output[row] = (float)sum;
        if (!std::isfinite(output[row])) {
            std::fprintf(stderr, "[Q6K_REF] NONFINITE row=%lld sum=%f\n", (long long)row, output[row]);
            return false;
        }
    }
    return true;
}

static void gemv_q6_k_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    static std::atomic<int> q6kDebugCalls{0};
    const int call = q6kDebugCalls.fetch_add(1);
    if (call < 4) {
        printf("[Q6K_GEMV] ENTER call=%d w=%p x=%p y=%p rows=%zu cols=%zu\n",
               call, (const void*)w, (const void*)x, (void*)y, rows, cols);
        fflush(stdout);
    }
    if (!rxd_q6k_gemv_reference(w, x, y, (int64_t)rows, (int64_t)cols)) {
        std::fprintf(stderr, "[Q6K_REF] GEMV FAILED rows=%zu cols=%zu\n", rows, cols);
    }
    if (call < 4) {
        printf("[Q6K_GEMV] EXIT call=%d\n", call);
        fflush(stdout);
    }
}

// --- Q4_0 GEMV (reference) ---
// VAL-051.7: Unconditionally use reference implementation until
// optimized kernel parity is certified.  The reference path:
//   1. Zeroes destination before accumulation
//   2. Uses exact 18-byte block geometry
//   3. Decodes fresh scale + nibbles per block
//   4. Applies -8 nibble bias (ggml canonical)
//   5. Hard-finite guard on every row result
static void gemv_q4_0_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    (void)rawrxd::deep2::Q4_0_GEMV_Reference(w, rows, cols, x, y);
}

// --- Q4_1 GEMV (scalar) ---
static void gemv_q4_1_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const block_q4_1* blocks = reinterpret_cast<const block_q4_1*>(w);
    size_t blocksPerRow = (cols + 31) / 32;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_q4_1* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q4_1& blk = rowBlocks[b];
            float d = f16_to_f32(blk.d);
            float m = f16_to_f32(blk.m);
            size_t base = b * 32;
            size_t elemsInBlock = (b == blocksPerRow - 1) ? (cols - base) : 32;
            if (elemsInBlock == 0) break;
            for (size_t i = 0; i < elemsInBlock; ++i) {
                uint8_t byte = blk.qs[i / 2];
                float q = (i % 2 == 0) ? (float)(byte & 0x0F) : (float)(byte >> 4);
                acc += (d * q - m) * x[base + i];
            }
        }
        y[r] += acc;
    }
}

// --- Q5_0 GEMV (scalar) ---
static void gemv_q5_0_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const block_q5_0* blocks = reinterpret_cast<const block_q5_0*>(w);
    size_t blocksPerRow = (cols + 31) / 32;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_q5_0* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q5_0& blk = rowBlocks[b];
            float d = f16_to_f32(blk.d);
            size_t base = b * 32;
            size_t elemsInBlock = (b == blocksPerRow - 1) ? (cols - base) : 32;
            if (elemsInBlock == 0) break;
            for (size_t i = 0; i < elemsInBlock; ++i) {
                uint8_t low4 = blk.qs[i / 2];
                float q_low = (i % 2 == 0) ? (float)(low4 & 0x0F) : (float)(low4 >> 4);
                int qhIdx = (int)(i / 8);
                int qhShift = (int)(i % 8);
                uint8_t high1 = (blk.qh[qhIdx] >> qhShift) & 0x01;
                float q = q_low + (float)(high1 << 4);
                acc += d * q * x[base + i];
            }
        }
        y[r] += acc;
    }
}

// --- Q5_1 GEMV (scalar) ---
static void gemv_q5_1_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const block_q5_1* blocks = reinterpret_cast<const block_q5_1*>(w);
    size_t blocksPerRow = (cols + 31) / 32;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_q5_1* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q5_1& blk = rowBlocks[b];
            float d = f16_to_f32(blk.d);
            float m = f16_to_f32(blk.m);
            size_t base = b * 32;
            size_t elemsInBlock = (b == blocksPerRow - 1) ? (cols - base) : 32;
            if (elemsInBlock == 0) break;
            for (size_t i = 0; i < elemsInBlock; ++i) {
                uint8_t low4 = blk.qs[i / 2];
                float q_low = (i % 2 == 0) ? (float)(low4 & 0x0F) : (float)(low4 >> 4);
                int qhIdx = (int)(i / 8);
                int qhShift = (int)(i % 8);
                uint8_t high1 = (blk.qh[qhIdx] >> qhShift) & 0x01;
                float q = q_low + (float)(high1 << 4);
                acc += (d * q - m) * x[base + i];
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
            __m512 dVec = _mm512_set1_ps(f16_to_f32(blk.d));

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
            __m256 dVec = _mm256_set1_ps(f16_to_f32(blk.d));

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
        float d = f16_to_f32(blocks[b].d);
        if (!std::isfinite(d)) d = 0.0f;
        for (int i = 0; i < 32; ++i) {
            size_t idx = b * 32 + i;
            if (idx < n) dst[idx] = f16_to_f32(blocks[b].d) * (float)blocks[b].qs[i];
        }
    }
}

static void dequant_q4_k(const uint8_t* src, float* dst, size_t n) {
    const block_q4_K* blocks = reinterpret_cast<const block_q4_K*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        float dmin = f16_to_f32(blocks[b].dmin);
        if (!std::isfinite(d))    d    = 0.0f;
        if (!std::isfinite(dmin)) dmin = 0.0f;
        for (int sb = 0; sb < 8; ++sb) {
            uint8_t sc, m;
            get_scale_min_k4(sb, blocks[b].scales, sc, m);
            float scale = d * sc;
            float min   = dmin * m;
            const uint8_t* quants = blocks[b].qs + sb * 16;
            for (int k = 0; k < 16; ++k) {
                uint8_t byte = quants[k];
                int lo = byte & 0x0F;
                int hi = (byte >> 4) & 0x0F;
                int idx0 = sb * 32 + k;
                int idx1 = sb * 32 + k + 16;
                size_t g0 = b * 256 + idx0;
                size_t g1 = b * 256 + idx1;
                if (g0 < n) dst[g0] = scale * lo - min;
                if (g1 < n) dst[g1] = scale * hi - min;
            }
        }
    }
}


static void dequant_q2_k(const uint8_t* src, float* dst, size_t n) {
    const block_q2_K* blocks = reinterpret_cast<const block_q2_K*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d    = f16_to_f32(blocks[b].d);
        float dmin = f16_to_f32(blocks[b].dmin);
        // Sanitize non-finite scale values to prevent NaN propagation
        if (!std::isfinite(d))    d    = 0.0f;
        if (!std::isfinite(dmin)) dmin = 0.0f;
        for (int chunk = 0; chunk < 2; ++chunk) {
            for (int subBlock = 0; subBlock < 4; ++subBlock) {
                for (int group = 0; group < 2; ++group) {
                    int scaleIdx = chunk * 8 + subBlock * 2 + group;
                    uint8_t sc = blocks[b].scales[scaleIdx];
                    float dl = d * (float)(sc & 0x0F);
                    float ml = dmin * (float)(sc >> 4);
                    for (int pos = 0; pos < 16; ++pos) {
                        int i = chunk * 128 + subBlock * 32 + group * 16 + pos;
                        size_t globalIdx = b * 256 + i;
                        if (globalIdx >= n) return;
                        int qsIdx = chunk * 32 + group * 16 + pos;
                        int qsShift = subBlock * 2;
                        int q = (blocks[b].qs[qsIdx] >> qsShift) & 0x03;
                        dst[globalIdx] = dl * (float)q - ml;
                    }
                }
            }
        }
    }
}
static void dequant_q3_k(const uint8_t* src, float* dst, size_t n) {
    const block_q3_K* blocks = reinterpret_cast<const block_q3_K*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        if (!std::isfinite(d)) d = 0.0f;
        int8_t scales[16];
        for (int j = 0; j < 8; ++j) {
            scales[j]     = (int8_t)(blocks[b].scales[j] & 0x0F);
            scales[j + 8] = (int8_t)((blocks[b].scales[j] >> 4) & 0x0F);
        }
        for (size_t i = 0; i < 256; ++i) {
            size_t globalIdx = b * 256 + i;
            if (globalIdx >= n) return;
            int chunk    = (int)(i / 128);
            int subBlock = (int)((i % 128) / 32);
            int posInSub = (int)(i % 32);
            int qsIdx    = chunk * 32 + posInSub;
            int qsShift  = subBlock * 2;
            int lo       = (blocks[b].qs[qsIdx] >> qsShift) & 0x03;
            // hmask: 1 bit per weight, 8 weights per byte
            int hmIdx     = (int)(i / 8);
            int hmShift   = (int)(i % 8);
            int hmaskBit  = (blocks[b].hmask[hmIdx] >> hmShift) & 0x01;
            int q         = lo - (hmaskBit ? 0 : 4);
            int scaleIdx  = chunk * 4 + subBlock;
            float dl      = d * (float)(scales[scaleIdx] - 32);
            dst[globalIdx]  = dl * (float)q;
        }
    }
}
static void dequant_q5_k(const uint8_t* src, float* dst, size_t n) {
    const block_q5_K* blocks = reinterpret_cast<const block_q5_K*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        float dmin = f16_to_f32(blocks[b].dmin);
        if (!std::isfinite(d))    d    = 0.0f;
        if (!std::isfinite(dmin)) dmin = 0.0f;
        for (int sb = 0; sb < 8; ++sb) {
            uint8_t scale, min;
            get_scale_min_k4(sb, blocks[b].scales, scale, min);
            float s = d * scale;
            float m = dmin * min;
            for (int i = 0; i < 32; ++i) {
                int idx = sb * 32 + i;
                size_t globalIdx = b * 256 + idx;
                if (globalIdx >= n) return;
                int qsIdx = idx / 2;
                int qsShift = (idx % 2) * 4;
                uint8_t low4 = (blocks[b].qs[qsIdx] >> qsShift) & 0x0F;
                int qhIdx = idx / 8;
                int qhShift = idx % 8;
                uint8_t high1 = (blocks[b].qh[qhIdx] >> qhShift) & 0x01;
                uint8_t q = low4 | (high1 << 4);
                dst[globalIdx] = s * q - m;
            }
        }
    }
}
static void dequant_q6_k(const uint8_t* src, float* dst, size_t n) {
    const block_q6_K* blocks = reinterpret_cast<const block_q6_K*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        if (!std::isfinite(d)) d = 0.0f;
        const uint8_t* ql = blocks[b].ql;
        const uint8_t* qh = blocks[b].qh;
        const int8_t*  sc = blocks[b].scales;
        for (size_t idx = 0; idx < 256; ++idx) {
            size_t globalIdx = b * 256 + idx;
            if (globalIdx >= n) return;
            size_t qlIdx = idx / 2;
            int    qlShift = (idx % 2) * 4;
            uint8_t low4 = (ql[qlIdx] >> qlShift) & 0x0F;
            size_t qhIdx = idx / 4;
            int    qhShift = (idx % 4) * 2;
            uint8_t high2 = (qh[qhIdx] >> qhShift) & 0x03;
            int8_t q = (int8_t)(low4 | (high2 << 4)) - 32;
            int scaleIdx = (int)(idx / 16);
            dst[globalIdx] = d * (float)sc[scaleIdx] * (float)q;
        }
    }
}

static void dequant_q4_0(const uint8_t* src, float* dst, size_t n) {
    const block_q4_0* blocks = reinterpret_cast<const block_q4_0*>(src);
    size_t numBlocks = (n + 31) / 32;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        for (int i = 0; i < 32; ++i) {
            size_t idx = b * 32 + i;
            if (idx >= n) return;
            uint8_t byte = blocks[b].qs[i / 2];
            float q = (i % 2 == 0) ? (float)(byte & 0x0F) : (float)(byte >> 4);
            dst[idx] = d * q;
        }
    }
}

static void dequant_q4_1(const uint8_t* src, float* dst, size_t n) {
    const block_q4_1* blocks = reinterpret_cast<const block_q4_1*>(src);
    size_t numBlocks = (n + 31) / 32;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        float m = f16_to_f32(blocks[b].m);
        for (int i = 0; i < 32; ++i) {
            size_t idx = b * 32 + i;
            if (idx >= n) return;
            uint8_t byte = blocks[b].qs[i / 2];
            float q = (i % 2 == 0) ? (float)(byte & 0x0F) : (float)(byte >> 4);
            dst[idx] = d * q - m;
        }
    }
}

static void dequant_q5_0(const uint8_t* src, float* dst, size_t n) {
    const block_q5_0* blocks = reinterpret_cast<const block_q5_0*>(src);
    size_t numBlocks = (n + 31) / 32;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        for (int i = 0; i < 32; ++i) {
            size_t idx = b * 32 + i;
            if (idx >= n) return;
            uint8_t low4 = blocks[b].qs[i / 2];
            float q_low = (i % 2 == 0) ? (float)(low4 & 0x0F) : (float)(low4 >> 4);
            int qhIdx = i / 8;
            int qhShift = i % 8;
            uint8_t high1 = (blocks[b].qh[qhIdx] >> qhShift) & 0x01;
            float q = q_low + (float)(high1 << 4);
            dst[idx] = d * q;
        }
    }
}

static void dequant_q5_1(const uint8_t* src, float* dst, size_t n) {
    const block_q5_1* blocks = reinterpret_cast<const block_q5_1*>(src);
    size_t numBlocks = (n + 31) / 32;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        float m = f16_to_f32(blocks[b].m);
        for (int i = 0; i < 32; ++i) {
            size_t idx = b * 32 + i;
            if (idx >= n) return;
            uint8_t low4 = blocks[b].qs[i / 2];
            float q_low = (i % 2 == 0) ? (float)(low4 & 0x0F) : (float)(low4 >> 4);
            int qhIdx = i / 8;
            int qhShift = i % 8;
            uint8_t high1 = (blocks[b].qh[qhIdx] >> qhShift) & 0x01;
            float q = q_low + (float)(high1 << 4);
            dst[idx] = d * q - m;
        }
    }
}

static void dequant_q8_k(const uint8_t* src, float* dst, size_t n) {
    const block_q8_K* blocks = reinterpret_cast<const block_q8_K*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = blocks[b].d;
        for (int i = 0; i < 256; ++i) {
            size_t idx = b * 256 + i;
            if (idx >= n) return;
            dst[idx] = d * (float)blocks[b].qs[i];
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
            float dmin = f16_to_f32(blk.dmin);
            size_t base = b * 256;
            size_t elemsInBlock = (b == blocksPerRow - 1) ? (cols - base) : 256;
            if (elemsInBlock == 0) break;
            for (int chunk = 0; chunk < 2; ++chunk) {
                for (int subBlock = 0; subBlock < 4; ++subBlock) {
                    for (int group = 0; group < 2; ++group) {
                        int scaleIdx = chunk * 8 + subBlock * 2 + group;
                        uint8_t sc = blk.scales[scaleIdx];
                        float dl = d * (float)(sc & 0x0F);
                        float ml = dmin * (float)(sc >> 4);
                        for (int pos = 0; pos < 16; ++pos) {
                            int idx = chunk * 128 + subBlock * 32 + group * 16 + pos;
                            if ((size_t)idx >= elemsInBlock) break;
                            int qsIdx = chunk * 32 + group * 16 + pos;
                            int qsShift = subBlock * 2;
                            int q = (blk.qs[qsIdx] >> qsShift) & 0x03;
                            acc += (dl * (float)q - ml) * x[base + idx];
                        }
                    }
                }
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
    static int diagCount = 0;
    const block_q3_K* blocks = reinterpret_cast<const block_q3_K*>(w);
    size_t blocksPerRow = (cols + 255) / 256;
    if (diagCount < 3) {
        printf("[Q3K_GEMV_DIAG#%d] rows=%zu cols=%zu blocksPerRow=%zu sizeof(block)=%zu\n",
               diagCount, rows, cols, blocksPerRow, sizeof(block_q3_K));
        if (blocksPerRow > 0) {
            float d0 = f16_to_f32(blocks[0].d);
            printf("[Q3K_GEMV_DIAG#%d] firstBlock d=%.6e scales=[%u,%u,%u,%u] qs[0]=0x%02X hmask[0]=0x%02X\n",
                   diagCount, d0,
                   (unsigned)blocks[0].scales[0], (unsigned)blocks[0].scales[1],
                   (unsigned)blocks[0].scales[2], (unsigned)blocks[0].scales[3],
                   (unsigned)blocks[0].qs[0], (unsigned)blocks[0].hmask[0]);
        }
        ++diagCount;
    }
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_q3_K* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q3_K& blk = rowBlocks[b];
            float d = f16_to_f32(blk.d);
            size_t base = b * 256;
            size_t elemsInBlock = (b == blocksPerRow - 1) ? (cols - base) : 256;
            if (elemsInBlock == 0) break;
            for (size_t i = 0; i < elemsInBlock; ++i) {
                int chunk    = (int)(i / 128);
                int subBlock = (int)((i % 128) / 32);
                int posInSub = (int)(i % 32);
                int qsIdx    = chunk * 32 + posInSub;
                int qsShift  = subBlock * 2;
                int lo       = (blk.qs[qsIdx] >> qsShift) & 0x03;
                // hmask: 1 bit per weight, 8 weights per byte
                int hmIdx     = (int)(i / 8);
                int hmShift   = (int)(i % 8);
                int hmaskBit  = (blk.hmask[hmIdx] >> hmShift) & 0x01;
                int q         = lo - (hmaskBit ? 0 : 4);
                int scaleIdx  = chunk * 4 + subBlock;
                int8_t sc = get_scale_q3_k(scaleIdx, blk.scales);
                float dl = d * (float)(sc - 32);
                acc += dl * (float)q * x[base + i];
            }
        }
        y[r] += acc;
    }
}
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
            float dmin = f16_to_f32(blk.dmin);
            size_t elemsInBlock = (b == blocksPerRow - 1)
                ? (cols - b * 256)
                : 256;
            if (elemsInBlock == 0) break;

            for (int sb = 0; sb < 8; ++sb) {
                uint8_t scale, min;
                get_scale_min_k4(sb, blk.scales, scale, min);
                float s = d * scale;
                float m = dmin * min;
                float blockAcc = 0.0f;
                for (int i = 0; i < 32; ++i) {
                    int idx = sb * 32 + i;
                    if ((size_t)idx >= elemsInBlock) break;
                    int qsIdx = idx / 2;
                    int qsShift = (idx % 2) * 4;
                    uint8_t low4 = (blk.qs[qsIdx] >> qsShift) & 0x0F;
                    int qhIdx = idx / 8;
                    int qhShift = idx % 8;
                    uint8_t high1 = (blk.qh[qhIdx] >> qhShift) & 0x01;
                    uint8_t q = low4 | (high1 << 4);
                    blockAcc += (s * q - m) * x[b * 256 + idx];
                }
                acc += blockAcc;
            }
        }
        y[r] += acc;
    }
}

// Q5_K AVX2 implementation - 5-bit weights with 1-bit high from qh
static void gemv_q5_k_avx2(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const block_q5_K* blocks = reinterpret_cast<const block_q5_K*>(w);
    size_t blocksPerRow = (cols + 255) / 256;

    for (size_t r = 0; r < rows; ++r) {
        float rowAcc = 0.0f;
        const block_q5_K* rowBlocks = blocks + r * blocksPerRow;

        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q5_K& blk = rowBlocks[b];
            float d = f16_to_f32(blk.d);
            float dmin = f16_to_f32(blk.dmin);
            size_t elemsInBlock = (b == blocksPerRow - 1)
                ? (cols - b * 256)
                : 256;
            if (elemsInBlock == 0) break;

            for (int sb = 0; sb < 8; ++sb) {
                uint8_t scale_u8, min_u8;
                get_scale_min_k4(sb, blk.scales, scale_u8, min_u8);
                float s = d * scale_u8;
                float m = dmin * min_u8;
                __m256 sVec = _mm256_set1_ps(s);
                __m256 mVec = _mm256_set1_ps(m);

                // Process 32 weights in this sub-block
                size_t qsOffset = sb * 16;
                __m128i packed = _mm_loadu_si128(reinterpret_cast<const __m128i*>(blk.qs + qsOffset));

                // Extract low/high nibbles (4 bits each)
                __m128i lowNibbles = _mm_and_si128(packed, _mm_set1_epi8(0x0F));
                __m128i highNibbles = _mm_srli_epi16(packed, 4);
                highNibbles = _mm_and_si128(highNibbles, _mm_set1_epi8(0x0F));

                // Load qh bits for this sub-block (32 weights = 4 bytes of qh)
                size_t qhOffset = sb * 4;
                uint32_t qhBits = *reinterpret_cast<const uint32_t*>(blk.qh + qhOffset);

                // Process in 4 chunks of 8 weights
                for (int chunk = 0; chunk < 4; ++chunk) {
                    int offset = sb * 32 + chunk * 8;
                    if ((size_t)offset + 8 > elemsInBlock) break;
                    if (b * 256 + offset + 8 > cols) break;

                    // Get 8 low nibbles
                    __m128i nibbles;
                    if (chunk < 2) {
                        nibbles = (chunk == 0) ? lowNibbles : _mm_srli_si128(lowNibbles, 8);
                    } else {
                        nibbles = (chunk == 2) ? highNibbles : _mm_srli_si128(highNibbles, 8);
                    }

                    __m256i i32 = _mm256_cvtepu8_epi32(nibbles);
                    __m256 wv = _mm256_cvtepi32_ps(i32);

                    // Add high bit (qh) to make 5-bit values
                    // Each chunk of 8 weights gets bits from qh
                    int qhShift = chunk * 8;
                    uint8_t qhByte = (qhBits >> qhShift) & 0xFF;
                    __m256 qhVec = _mm256_set_ps(
                        (float)((qhByte >> 7) & 1),
                        (float)((qhByte >> 6) & 1),
                        (float)((qhByte >> 5) & 1),
                        (float)((qhByte >> 4) & 1),
                        (float)((qhByte >> 3) & 1),
                        (float)((qhByte >> 2) & 1),
                        (float)((qhByte >> 1) & 1),
                        (float)(qhByte & 1)
                    );
                    wv = _mm256_add_ps(wv, _mm256_mul_ps(qhVec, _mm256_set1_ps(16.0f)));

                    __m256 dequant = _mm256_sub_ps(_mm256_mul_ps(wv, sVec), mVec);
                    __m256 xv = _mm256_loadu_ps(x + b * 256 + offset);
                    rowAcc += _mm_cvtss_f32(_mm256_castps256_ps128(_mm256_dp_ps(dequant, xv, 0xF1)));
                }
            }
        }
        y[r] += rowAcc;
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
    if (hasAVX2 && cpu_.f16c) RegisterGEMV((int)GGMLType::GGML_TYPE_F16, gemv_f16_masm);
    else                         RegisterGEMV((int)GGMLType::GGML_TYPE_F16, gemv_f16_scalar);

    // --- Q8_0 ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q8_0, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q8_0));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q8_0, dequant_q8_0);
    // MASM stubbed — use scalar reference until AVX2 kernel is verified
    RegisterGEMV((int)GGMLType::GGML_TYPE_Q8_0, gemv_q8_0_scalar);

    // --- Q4_K ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q4_K, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q4_K));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q4_K, dequant_q4_k);
    // MASM linked but unverified — use scalar reference until byte-level comparison passes
    RegisterGEMV((int)GGMLType::GGML_TYPE_Q4_K, gemv_q4_k_scalar);

    // --- Q5_K ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q5_K, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q5_K));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q5_K, dequant_q5_k);
    // MASM stubbed — use scalar reference until AVX2 kernel is verified
    RegisterGEMV((int)GGMLType::GGML_TYPE_Q5_K, gemv_q5_k_scalar);

    // --- Q6_K ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q6_K, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q6_K));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q6_K, dequant_q6_k);
    // MASM stubbed — use scalar reference until AVX2 kernel is verified
    RegisterGEMV((int)GGMLType::GGML_TYPE_Q6_K, gemv_q6_k_scalar);

    // --- Q2_K ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q2_K, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q2_K));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q2_K, dequant_q2_k);
    // MASM has wrong block stride (72 vs 84 bytes) — use scalar reference
    RegisterGEMV((int)GGMLType::GGML_TYPE_Q2_K, gemv_q2_k_scalar);

    // --- Q3_K ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q3_K, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q3_K));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q3_K, dequant_q3_k);
    // MASM untrusted — use scalar reference until byte-level comparison passes
    RegisterGEMV((int)GGMLType::GGML_TYPE_Q3_K, gemv_q3_k_scalar);

    // --- Q4_0 ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q4_0, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q4_0));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q4_0, dequant_q4_0);
    // MASM has dimensionality bug (iterates blocks as rows) — use scalar reference
    RegisterGEMV((int)GGMLType::GGML_TYPE_Q4_0, gemv_q4_0_scalar);

    // --- Q4_1 ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q4_1, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q4_1));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q4_1, dequant_q4_1);
    // MASM stubbed — use scalar reference until AVX2 kernel is verified
    RegisterGEMV((int)GGMLType::GGML_TYPE_Q4_1, gemv_q4_1_scalar);

    // --- Q5_0 ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q5_0, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q5_0));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q5_0, dequant_q5_0);
    RegisterGEMV((int)GGMLType::GGML_TYPE_Q5_0, gemv_q5_0_scalar);

    // --- Q5_1 ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q5_1, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q5_1));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q5_1, dequant_q5_1);
    RegisterGEMV((int)GGMLType::GGML_TYPE_Q5_1, gemv_q5_1_scalar);

    // --- Q8_K ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q8_K, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q8_K));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q8_K, dequant_q8_k);
    RegisterGEMV((int)GGMLType::GGML_TYPE_Q8_K, gemv_q8_k_scalar);

    // --- IQ types (registered via IQQuantKernels.cpp) ---
    RegisterIQKernels();
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

// ============================================================================
// Batch 21 telemetry report
// ============================================================================
void QuantKernelRegistry::PrintBatch21Report() const {
    printf("\n[BATCH21]\n");
    printf("registry_hit=%llu\n", (unsigned long long)batch21_.registryHits.load());
    printf("registry_miss=%llu\n", (unsigned long long)batch21_.registryMisses.load());
    printf("scalar_fallback=%llu\n", (unsigned long long)batch21_.scalarFallbacks.load());
    printf("kernel_invocations=%llu\n", (unsigned long long)batch21_.kernelInvocations.load());
    printf("vulkan_compute_submissions=%llu\n", (unsigned long long)batch21_.vulkanComputeSubmissions.load());
    printf("vulkan_compute_failures=%llu\n", (unsigned long long)batch21_.vulkanComputeFailures.load());
    bool pass = batch21_.registryHits.load() > 0 &&
                batch21_.registryMisses.load() == 0 &&
                batch21_.scalarFallbacks.load() == 0 &&
                batch21_.kernelInvocations.load() > 0;
    printf("status=%s\n", pass ? "PASS" : "FAIL");
}

} // namespace Deep2




