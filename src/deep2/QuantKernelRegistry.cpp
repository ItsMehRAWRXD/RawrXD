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
#include <cmath>
#include <sstream>
#include <vector>

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
// Static block geometry lookup — authoritative QuantTypeTable (fail-closed).
// ---------------------------------------------------------------------------
BlockGeometry GetBlockGeometryForType(int quantType) {
    const auto* d = LookupQuantType(static_cast<uint32_t>(quantType));
    if (!d) return {0, 0, false, false};
    return {d->blockBytes, d->blockElements, d->hasScales, d->hasMin};
}

// ---------------------------------------------------------------------------
// Type name
// ---------------------------------------------------------------------------
const char* GGMLTypeName(int type) {
    return QuantTypeName(static_cast<uint32_t>(type));
}

// ---------------------------------------------------------------------------
// UniversalTensorProxy helpers
// ---------------------------------------------------------------------------
bool UniversalTensorProxy::IsQuantized() const {
    return QuantTypeIsQuantized(static_cast<uint32_t>(quantType));
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
// Uses the same algorithm as QuantKernelRegistry_K.h for consistency.
static inline float f16_to_f32(uint16_t h) {
    uint32_t sign = (static_cast<uint32_t>(h & 0x8000)) << 16;
    uint32_t exp  = (h >> 10) & 0x1F;
    uint32_t frac = h & 0x03FF;

    if (exp == 0) {
        if (frac == 0) return reinterpret_cast<const float&>(sign);
        // Denormalized: value = frac * 2^(-10) * 2^(-14) = frac * 2^(-24)
        uint32_t e = 1;
        uint32_t f = frac;
        while ((f & 0x0400) == 0) { f <<= 1; e++; }
        f &= 0x03FF;
        uint32_t bits = sign | ((127 - 15 + 2 - e) << 23) | (f << 13);
        return reinterpret_cast<float&>(bits);
    }
    if (exp == 31) {
        uint32_t bits = sign | 0x7F800000 | (frac << 13);
        return reinterpret_cast<float&>(bits);
    }
    uint32_t bits = sign | ((exp + 127 - 15) << 23) | (frac << 13);
    return reinterpret_cast<float&>(bits);
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
// CRITICAL: Q4_K uses GROUPED nibbles (llama.cpp dequantize_row_q4_K):
//   For each pair of 32-weight groups (64 weights total):
//     qs[0..31] low  nibbles + scale[is+0] -> weights 0..31
//     qs[0..31] high nibbles + scale[is+1] -> weights 32..63
//     then qs += 32, is += 2
//   Do NOT treat each 16-byte chunk as lo/hi within the same scale.

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

// --- Q4_K GEMV (ggml mul_mat path: Q4_K × Q8_K) ---
// BATCH2_Q4K_GEMV_001: Deep2 FP32 dequant·x matched ggml dequantize_row_q4_K,
// but Batch-2 llama Q_0 uses quantize_row_q8_K(x) + vec_dot_q4_K_q8_K.
// Production GEMV must follow that path to close Q_0 against llama CPU authority.
//
// Decode (scales/mins/nibble grouping) remains identical to dequantize_row_q4_K;
// only the activation-side quantization + integer dot differ.
// block_q8_K is defined in GGUFLoader.hpp.
static inline int nearest_int_q8k(float fval) {
    float val = fval + 12582912.f;
    int i;
    std::memcpy(&i, &val, sizeof(int));
    return (i & 0x007fffff) - 0x00400000;
}

static void quantize_row_q8_K(const float* x, block_q8_K* y, size_t k) {
    const size_t nb = k / 256;
    for (size_t i = 0; i < nb; ++i) {
        float max = 0.f, amax = 0.f;
        for (int j = 0; j < 256; ++j) {
            float ax = std::fabs(x[j]);
            if (ax > amax) { amax = ax; max = x[j]; }
        }
        if (!amax) {
            y[i].d = 0.f;
            std::memset(y[i].qs, 0, 256);
            std::memset(y[i].bsums, 0, sizeof(y[i].bsums));
            x += 256;
            continue;
        }
        const float iscale = -127.f / max;
        for (int j = 0; j < 256; ++j) {
            int v = nearest_int_q8k(iscale * x[j]);
            y[i].qs[j] = static_cast<int8_t>(v > 127 ? 127 : v);
        }
        for (int j = 0; j < 16; ++j) {
            int sum = 0;
            for (int ii = 0; ii < 16; ++ii) sum += y[i].qs[j * 16 + ii];
            y[i].bsums[j] = static_cast<int16_t>(sum);
        }
        y[i].d = 1.f / iscale;
        x += 256;
    }
}

// Port of ggml_vec_dot_q4_K_q8_K_generic
static float vec_dot_q4_K_q8_K(const block_q4_K* x, const block_q8_K* y, size_t cols) {
    const size_t nb = cols / 256;
    static const uint32_t kmask1 = 0x3f3f3f3f;
    static const uint32_t kmask2 = 0x0f0f0f0f;
    static const uint32_t kmask3 = 0x03030303;
    uint32_t utmp[4];
    const uint8_t* scales = reinterpret_cast<const uint8_t*>(&utmp[0]);
    const uint8_t* mins   = reinterpret_cast<const uint8_t*>(&utmp[2]);
    int8_t  aux8[256];
    int16_t aux16[8];
    float   sums[8];
    int32_t aux32[8];
    std::memset(sums, 0, sizeof(sums));
    float sumf = 0.f;
    for (size_t i = 0; i < nb; ++i) {
        const uint8_t* q4 = x[i].qs;
        const int8_t*  q8 = y[i].qs;
        std::memset(aux32, 0, sizeof(aux32));
        int8_t* a = aux8;
        for (int j = 0; j < 4; ++j) {
            for (int l = 0; l < 32; ++l) a[l] = static_cast<int8_t>(q4[l] & 0xF);
            a += 32;
            for (int l = 0; l < 32; ++l) a[l] = static_cast<int8_t>(q4[l] >> 4);
            a += 32;
            q4 += 32;
        }
        std::memcpy(utmp, x[i].scales, 12);
        utmp[3] = ((utmp[2] >> 4) & kmask2) | (((utmp[1] >> 6) & kmask3) << 4);
        const uint32_t uaux = utmp[1] & kmask1;
        utmp[1] = (utmp[2] & kmask2) | (((utmp[0] >> 6) & kmask3) << 4);
        utmp[2] = uaux;
        utmp[0] &= kmask1;

        int sumi = 0;
        for (int j = 0; j < 16; ++j) sumi += y[i].bsums[j] * mins[j / 2];
        a = aux8;
        int is = 0;
        for (int j = 0; j < 8; ++j) {
            const int32_t scale = scales[is++];
            for (int r = 0; r < 4; ++r) {
                for (int l = 0; l < 8; ++l) aux16[l] = static_cast<int16_t>(q8[l] * a[l]);
                for (int l = 0; l < 8; ++l) aux32[l] += scale * aux16[l];
                q8 += 8;
                a += 8;
            }
        }
        const float d = f16_to_f32(x[i].d) * y[i].d;
        for (int l = 0; l < 8; ++l) sums[l] += d * static_cast<float>(aux32[l]);
        const float dmin = f16_to_f32(x[i].dmin) * y[i].d;
        sumf -= dmin * static_cast<float>(sumi);
    }
    for (int l = 0; l < 8; ++l) sumf += sums[l];
    return sumf;
}

static void gemv_q4_k_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    if (cols % 256 != 0) {
        // Fallback: FP32 dequant·x (non-ggml-mul_mat shapes)
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
                size_t elemsInBlock = (b == blocksPerRow - 1) ? (cols - base) : 256;
                if (elemsInBlock == 0) break;
                uint8_t scales[8], mins[8];
                unpack_q4_k_scales(blk.scales, scales, mins);
                const uint8_t* q = blk.qs;
                for (int is = 0; is < 8; is += 2) {
                    const float d1 = d * static_cast<float>(scales[is]);
                    const float m1 = dmin * static_cast<float>(mins[is]);
                    const float d2 = d * static_cast<float>(scales[is + 1]);
                    const float m2 = dmin * static_cast<float>(mins[is + 1]);
                    const size_t off0 = static_cast<size_t>(is) * 32;
                    const size_t off1 = off0 + 32;
                    for (int l = 0; l < 32; ++l) {
                        if (off0 + static_cast<size_t>(l) < elemsInBlock)
                            acc += (d1 * static_cast<float>(q[l] & 0x0F) - m1)
                                 * x[base + off0 + static_cast<size_t>(l)];
                        if (off1 + static_cast<size_t>(l) < elemsInBlock)
                            acc += (d2 * static_cast<float>(q[l] >> 4) - m2)
                                 * x[base + off1 + static_cast<size_t>(l)];
                    }
                    q += 32;
                }
            }
            y[r] += acc;
        }
        return;
    }

    // Hot path: match llama.cpp CPU mul_mat(Q4_K, Q8_K)
    const size_t blocksPerRow = cols / 256;
    std::vector<block_q8_K> xQ8(blocksPerRow);
    quantize_row_q8_K(x, xQ8.data(), cols);
    const block_q4_K* blocks = reinterpret_cast<const block_q4_K*>(w);
    for (size_t r = 0; r < rows; ++r) {
        y[r] += vec_dot_q4_K_q8_K(blocks + r * blocksPerRow, xQ8.data(), cols);
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
    // Use the same algorithm as f16_to_f32 in QuantKernelRegistry_K.h
    uint32_t sign = (static_cast<uint32_t>(h & 0x8000)) << 16;
    uint32_t exp  = (h >> 10) & 0x1F;
    uint32_t frac = h & 0x03FF;

    if (exp == 0) {
        if (frac == 0) return reinterpret_cast<const float&>(sign);
        // Denormalized
        uint32_t e = 1;
        uint32_t f = frac;
        while ((f & 0x0400) == 0) { f <<= 1; e++; }
        f &= 0x03FF;
        uint32_t bits = sign | ((127 - 15 + 2 - e) << 23) | (f << 13);
        return reinterpret_cast<float&>(bits);
    }
    if (exp == 31) {
        uint32_t bits = sign | 0x7F800000 | (frac << 13);
        return reinterpret_cast<float&>(bits);
    }
    uint32_t bits = sign | ((exp + 127 - 15) << 23) | (frac << 13);
    return reinterpret_cast<float&>(bits);
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

// Port of ggml_vec_dot_q6_K_q8_K_generic (one super-block / 256 cols).
static float vec_dot_q6_K_q8_K(const block_q6_K* x, const block_q8_K* y, size_t cols) {
    const size_t nb = cols / 256;
    int8_t  aux8[256];
    int16_t aux16[8];
    float   sums[8];
    int32_t aux32[8];
    std::memset(sums, 0, sizeof(sums));
    float sumf = 0.f;
    for (size_t i = 0; i < nb; ++i) {
        const uint8_t* q4 = x[i].ql;
        const uint8_t* qh = x[i].qh;
        const int8_t*  q8 = y[i].qs;
        std::memset(aux32, 0, sizeof(aux32));
        int8_t* a = aux8;
        for (int j = 0; j < 256; j += 128) {
            for (int l = 0; l < 32; ++l) {
                a[l +  0] = static_cast<int8_t>((q4[l +  0] & 0xF) | (((qh[l] >> 0) & 3) << 4)) - 32;
                a[l + 32] = static_cast<int8_t>((q4[l + 32] & 0xF) | (((qh[l] >> 2) & 3) << 4)) - 32;
                a[l + 64] = static_cast<int8_t>((q4[l +  0] >> 4) | (((qh[l] >> 4) & 3) << 4)) - 32;
                a[l + 96] = static_cast<int8_t>((q4[l + 32] >> 4) | (((qh[l] >> 6) & 3) << 4)) - 32;
            }
            a  += 128;
            q4 += 64;
            qh += 32;
        }
        a = aux8;
        int is = 0;
        for (int j = 0; j < 256 / 16; ++j) {
            const int scale = x[i].scales[is++];
            for (int l = 0; l < 8; ++l) aux16[l] = static_cast<int16_t>(q8[l] * a[l]);
            for (int l = 0; l < 8; ++l) aux32[l] += scale * aux16[l];
            q8 += 8; a += 8;
            for (int l = 0; l < 8; ++l) aux16[l] = static_cast<int16_t>(q8[l] * a[l]);
            for (int l = 0; l < 8; ++l) aux32[l] += scale * aux16[l];
            q8 += 8; a += 8;
        }
        const float d = f16_to_f32(x[i].d) * y[i].d;
        for (int l = 0; l < 8; ++l) sums[l] += d * static_cast<float>(aux32[l]);
    }
    for (int l = 0; l < 8; ++l) sumf += sums[l];
    return sumf;
}

// BATCH2_V_PROJ_001: TinyLlama attn_v is Q6_K (type 14), not Q4_K.
// FP32 dequant·x matched dequantize_row_q6_K but diverged from llama mul_mat
// (Q6_K×Q8_K) — same class of bug as Q4K-GEMV-001. Production must use Q8_K path.
static void gemv_q6_k_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    if (cols % 256 != 0) {
        // Fallback: FP32 dequant·x (non-ggml-mul_mat shapes)
        if (!rxd_q6k_gemv_reference(w, x, y, (int64_t)rows, (int64_t)cols)) {
            std::fprintf(stderr, "[Q6K_REF] GEMV FAILED rows=%zu cols=%zu\n", rows, cols);
        }
        return;
    }
    const size_t blocksPerRow = cols / 256;
    std::vector<block_q8_K> xQ8(blocksPerRow);
    quantize_row_q8_K(x, xQ8.data(), cols);
    const block_q6_K* blocks = reinterpret_cast<const block_q6_K*>(w);
    for (size_t r = 0; r < rows; ++r) {
        y[r] += vec_dot_q6_K_q8_K(blocks + r * blocksPerRow, xQ8.data(), cols);
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

// --- Q4_K GEMV (AVX-512) ---
// Delegate to scalar until a ggml-layout SIMD kernel is re-validated.
static void gemv_q4_k_avx512(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    gemv_q4_k_scalar(w, x, y, rows, cols);
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
// Delegate to scalar reference (ggml-compatible nibble layout). SIMD path
// previously used the wrong 16-byte/same-scale packing and is not trusted.
static void gemv_q4_k_avx2(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    gemv_q4_k_scalar(w, x, y, rows, cols);
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
    // Exact layout match for ggml dequantize_row_q4_K
    const block_q4_K* blocks = reinterpret_cast<const block_q4_K*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        float dmin = f16_to_f32(blocks[b].dmin);
        if (!std::isfinite(d))    d    = 0.0f;
        if (!std::isfinite(dmin)) dmin = 0.0f;
        uint8_t scales[8], mins[8];
        unpack_q4_k_scales(blocks[b].scales, scales, mins);
        const uint8_t* q = blocks[b].qs;
        float* y = dst + b * 256;
        for (int is = 0; is < 8; is += 2) {
            const float d1 = d * static_cast<float>(scales[is]);
            const float m1 = dmin * static_cast<float>(mins[is]);
            const float d2 = d * static_cast<float>(scales[is + 1]);
            const float m2 = dmin * static_cast<float>(mins[is + 1]);
            for (int l = 0; l < 32; ++l) {
                size_t g0 = b * 256 + static_cast<size_t>(is) * 32 + static_cast<size_t>(l);
                size_t g1 = g0 + 32;
                if (g0 < n) y[static_cast<size_t>(is) * 32 + static_cast<size_t>(l)] =
                    d1 * static_cast<float>(q[l] & 0x0F) - m1;
                if (g1 < n) y[static_cast<size_t>(is) * 32 + 32 + static_cast<size_t>(l)] =
                    d2 * static_cast<float>(q[l] >> 4) - m2;
            }
            q += 32;
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
    printf("[QuantKernelRegistry] Q4_K GEMV=%p dequant=%p GetGEMV(12)=%p match=%d\n",
           (void*)(GEMVKernelFn)gemv_q4_k_scalar,
           (void*)(DequantKernelFn)dequant_q4_k,
           (void*)GetGEMV((int)GGMLType::GGML_TYPE_Q4_K),
           (int)(GetGEMV((int)GGMLType::GGML_TYPE_Q4_K) == (GEMVKernelFn)gemv_q4_k_scalar));

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




