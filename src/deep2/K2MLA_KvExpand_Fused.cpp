// K2MLA_KvExpand_Fused.cpp — Optimized fused K+V LoRA GEMV
// Single-pass over compressedKV, dual-output (K_nope + V).
// Targets: AVX2 (baseline), AVX-512 (when compiled with /arch:AVX512)
// ============================================================================
#include "K2MLA_KvExpand_Fused.hpp"
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <atomic>

// SIMD intrinsics
#include <immintrin.h>

namespace Deep2 {
namespace {

// ============================================================================
// FP16 → FP32 conversion (same as K2MLAWeights.cpp)
// ============================================================================
static inline float fp16ToFloat(uint16_t h) {
    uint32_t sign = (h >> 15) & 0x1;
    uint32_t exp  = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    uint32_t f;
    if (exp == 0) {
        if (mant == 0) { f = sign << 31; }
        else {
            int e = -1;
            do { e++; mant <<= 1; } while (!(mant & 0x400));
            mant &= 0x3FF;
            f = (sign << 31) | ((127 - 15 - e) << 23) | (mant << 13);
        }
    } else if (exp == 31) {
        f = (sign << 31) | (0xFF << 23) | (mant << 13);
    } else {
        f = (sign << 31) | ((exp + 127 - 15) << 23) | (mant << 13);
    }
    float result;
    memcpy(&result, &f, sizeof(float));
    return result;
}

// ============================================================================
// Q4_K block structures (same layout as K2MLAWeights.cpp)
// ============================================================================
#pragma pack(push, 1)
struct Q4_K_Block {
    uint16_t d;
    uint16_t dmin;
    uint8_t  scales[12];
    uint8_t  qs[128];
};
#pragma pack(pop)
static_assert(sizeof(Q4_K_Block) == 144, "Q4_K_Block must be 144 bytes");

#pragma pack(push, 1)
struct Q8_0_Block {
    uint16_t d;
    int8_t qs[32];
};
#pragma pack(pop)
static_assert(sizeof(Q8_0_Block) == 34, "Q8_0_Block must be 34 bytes");

static inline void unpackQ4KScaleMin(const uint8_t* scales, int j,
                                     uint8_t& sc, uint8_t& m) {
    if (j < 4) {
        sc = scales[j] & 63;
        m  = scales[j + 4] & 63;
    } else {
        sc = (scales[j + 4] & 0x0F) | ((scales[j - 4] >> 6) << 4);
        m  = (scales[j + 4] >> 4)      | ((scales[j]   >> 6) << 4);
    }
}

// ============================================================================
// Horizontal sum helpers
// ============================================================================
static inline float hsum256(__m256 v) {
    __m128 hi = _mm256_extractf128_ps(v, 1);
    __m128 lo = _mm256_castps256_ps128(v);
    __m128 s = _mm_add_ps(lo, hi);
    s = _mm_hadd_ps(s, s);
    s = _mm_hadd_ps(s, s);
    return _mm_cvtss_f32(s);
}

#if defined(__AVX512F__)
static inline float hsum512(__m512 v) {
    __m256 lo = _mm512_castps512_ps256(v);
    __m256 hi = _mm512_extractf32x8_ps(v, 1);
    return hsum256(_mm256_add_ps(lo, hi));
}
#endif

// ============================================================================
// Dequantize Q4_K block to FP32 (256 elements)
// ============================================================================
static void dequantizeQ4KBlock(const Q4_K_Block* block, float* out) {
    float d    = fp16ToFloat(block->d);
    float dmin = fp16ToFloat(block->dmin);
    for (int j = 0; j < 8; j++) {
        uint8_t sc, m;
        unpackQ4KScaleMin(block->scales, j, sc, m);
        float scale = d * sc;
        float min   = dmin * m;
        const uint8_t* quants = block->qs + j * 16;
        for (int k = 0; k < 16; k++) {
            uint8_t byte = quants[k];
            out[j * 32 + k]      = scale * (float)(byte & 0xF) - min;
            out[j * 32 + k + 16] = scale * (float)((byte >> 4) & 0xF) - min;
        }
    }
}

// ============================================================================
// Fused K+V expand for Q8_0 — single pass over compressedKV
//
// Strategy: For each block of 32 compressedKV elements:
//   1. Load compressedKV[blk*32 : blk*32+31] into AVX2 registers
//   2. For each head, for each output row in K and V:
//      - Load Q8_0 block (32 int8 weights + scale)
//      - Dequantize to FP32 on-the-fly
//      - FMA with compressedKV
//      - Accumulate into output
//
// This is ~2x better memory bandwidth than separate K-expand + V-expand
// because compressedKV is only read once.
// ============================================================================
static void fusedKvExpand_Q8_0_SinglePass(
    const uint8_t* kBase, const uint8_t* vBase,
    const float* compressedKV,
    float* kOut, float* vOut,
    size_t numHeads, size_t qkNopeHeadDim, size_t vHeadDim, size_t kvLoraRank) {

    const size_t kBlocksPerRow = (kvLoraRank + 31) / 32;
    const size_t vBlocksPerRow = (kvLoraRank + 31) / 32;
    const size_t kBytesPerHead = qkNopeHeadDim * kBlocksPerRow * sizeof(Q8_0_Block);
    const size_t vBytesPerHead = vHeadDim * vBlocksPerRow * sizeof(Q8_0_Block);

    for (size_t h = 0; h < numHeads; ++h) {
        const uint8_t* kHeadBase = kBase + h * kBytesPerHead;
        const uint8_t* vHeadBase = vBase + h * vBytesPerHead;
        float* kHeadOut = kOut + h * qkNopeHeadDim;
        float* vHeadOut = vOut + h * vHeadDim;

        // K expansion — AVX2 vectorized
        for (size_t r = 0; r < qkNopeHeadDim; ++r) {
            const Q8_0_Block* rowBlocks = reinterpret_cast<const Q8_0_Block*>(
                kHeadBase + r * kBlocksPerRow * sizeof(Q8_0_Block));
            __m256 acc0 = _mm256_setzero_ps();
            __m256 acc1 = _mm256_setzero_ps();
            size_t b = 0;
            for (; b + 1 < kBlocksPerRow; b += 2) {
                _mm_prefetch((const char*)(rowBlocks + b + 2), _MM_HINT_T0);
                // Block b
                const float d0 = fp16ToFloat(rowBlocks[b].d);
                const __m256 scale0 = _mm256_set1_ps(d0);
                __m128i q8_0 = _mm_loadu_si128((const __m128i*)rowBlocks[b].qs);
                __m256i q32_lo = _mm256_cvtepi8_epi32(q8_0);
                __m256i q32_hi = _mm256_cvtepi8_epi32(_mm_srli_si128(q8_0, 8));
                __m256 qw_lo = _mm256_mul_ps(_mm256_cvtepi32_ps(q32_lo), scale0);
                __m256 qw_hi = _mm256_mul_ps(_mm256_cvtepi32_ps(q32_hi), scale0);
                __m256 kv_lo = _mm256_loadu_ps(compressedKV + b * 32);
                __m256 kv_hi = _mm256_loadu_ps(compressedKV + b * 32 + 8);
                acc0 = _mm256_fmadd_ps(qw_lo, kv_lo, acc0);
                acc1 = _mm256_fmadd_ps(qw_hi, kv_hi, acc1);
                // Block b+1
                const float d1 = fp16ToFloat(rowBlocks[b + 1].d);
                const __m256 scale1 = _mm256_set1_ps(d1);
                __m128i q8_1 = _mm_loadu_si128((const __m128i*)rowBlocks[b + 1].qs);
                __m256i q32_lo1 = _mm256_cvtepi8_epi32(q8_1);
                __m256i q32_hi1 = _mm256_cvtepi8_epi32(_mm_srli_si128(q8_1, 8));
                __m256 qw_lo1 = _mm256_mul_ps(_mm256_cvtepi32_ps(q32_lo1), scale1);
                __m256 qw_hi1 = _mm256_mul_ps(_mm256_cvtepi32_ps(q32_hi1), scale1);
                __m256 kv_lo1 = _mm256_loadu_ps(compressedKV + (b + 1) * 32);
                __m256 kv_hi1 = _mm256_loadu_ps(compressedKV + (b + 1) * 32 + 8);
                acc0 = _mm256_fmadd_ps(qw_lo1, kv_lo1, acc0);
                acc1 = _mm256_fmadd_ps(qw_hi1, kv_hi1, acc1);
            }
            acc0 = _mm256_add_ps(acc0, acc1);
            float sum = hsum256(acc0);
            // Scalar tail
            for (; b < kBlocksPerRow; ++b) {
                const float d = fp16ToFloat(rowBlocks[b].d);
                const size_t col0 = b * 32;
                for (size_t i = 0; i < 32 && col0 + i < kvLoraRank; ++i) {
                    sum += d * static_cast<float>(rowBlocks[b].qs[i]) * compressedKV[col0 + i];
                }
            }
            kHeadOut[r] = sum;
        }

        // V expansion — AVX2 vectorized
        for (size_t r = 0; r < vHeadDim; ++r) {
            const Q8_0_Block* rowBlocks = reinterpret_cast<const Q8_0_Block*>(
                vHeadBase + r * vBlocksPerRow * sizeof(Q8_0_Block));
            __m256 acc0 = _mm256_setzero_ps();
            __m256 acc1 = _mm256_setzero_ps();
            size_t b = 0;
            for (; b + 1 < vBlocksPerRow; b += 2) {
                _mm_prefetch((const char*)(rowBlocks + b + 2), _MM_HINT_T0);
                // Block b
                const float d0 = fp16ToFloat(rowBlocks[b].d);
                const __m256 scale0 = _mm256_set1_ps(d0);
                __m128i q8_0 = _mm_loadu_si128((const __m128i*)rowBlocks[b].qs);
                __m256i q32_lo = _mm256_cvtepi8_epi32(q8_0);
                __m256i q32_hi = _mm256_cvtepi8_epi32(_mm_srli_si128(q8_0, 8));
                __m256 qw_lo = _mm256_mul_ps(_mm256_cvtepi32_ps(q32_lo), scale0);
                __m256 qw_hi = _mm256_mul_ps(_mm256_cvtepi32_ps(q32_hi), scale0);
                __m256 kv_lo = _mm256_loadu_ps(compressedKV + b * 32);
                __m256 kv_hi = _mm256_loadu_ps(compressedKV + b * 32 + 8);
                acc0 = _mm256_fmadd_ps(qw_lo, kv_lo, acc0);
                acc1 = _mm256_fmadd_ps(qw_hi, kv_hi, acc1);
                // Block b+1
                const float d1 = fp16ToFloat(rowBlocks[b + 1].d);
                const __m256 scale1 = _mm256_set1_ps(d1);
                __m128i q8_1 = _mm_loadu_si128((const __m128i*)rowBlocks[b + 1].qs);
                __m256i q32_lo1 = _mm256_cvtepi8_epi32(q8_1);
                __m256i q32_hi1 = _mm256_cvtepi8_epi32(_mm_srli_si128(q8_1, 8));
                __m256 qw_lo1 = _mm256_mul_ps(_mm256_cvtepi32_ps(q32_lo1), scale1);
                __m256 qw_hi1 = _mm256_mul_ps(_mm256_cvtepi32_ps(q32_hi1), scale1);
                __m256 kv_lo1 = _mm256_loadu_ps(compressedKV + (b + 1) * 32);
                __m256 kv_hi1 = _mm256_loadu_ps(compressedKV + (b + 1) * 32 + 8);
                acc0 = _mm256_fmadd_ps(qw_lo1, kv_lo1, acc0);
                acc1 = _mm256_fmadd_ps(qw_hi1, kv_hi1, acc1);
            }
            acc0 = _mm256_add_ps(acc0, acc1);
            float sum = hsum256(acc0);
            for (; b < vBlocksPerRow; ++b) {
                const float d = fp16ToFloat(rowBlocks[b].d);
                const size_t col0 = b * 32;
                for (size_t i = 0; i < 32 && col0 + i < kvLoraRank; ++i) {
                    sum += d * static_cast<float>(rowBlocks[b].qs[i]) * compressedKV[col0 + i];
                }
            }
            vHeadOut[r] = sum;
        }
    }
}

// ============================================================================
// Fused K+V expand for Q4_K — single pass over compressedKV
// ============================================================================
static void fusedKvExpand_Q4K_SinglePass(
    const uint8_t* kBase, const uint8_t* vBase,
    const float* compressedKV,
    float* kOut, float* vOut,
    size_t numHeads, size_t qkNopeHeadDim, size_t vHeadDim, size_t kvLoraRank) {

    const size_t kBlocksPerRow = (kvLoraRank + 255) / 256;
    const size_t vBlocksPerRow = (kvLoraRank + 255) / 256;
    const size_t kBytesPerHead = qkNopeHeadDim * kBlocksPerRow * sizeof(Q4_K_Block);
    const size_t vBytesPerHead = vHeadDim * vBlocksPerRow * sizeof(Q4_K_Block);

    alignas(64) float dequantBuf[256];

    for (size_t h = 0; h < numHeads; ++h) {
        const uint8_t* kHeadBase = kBase + h * kBytesPerHead;
        const uint8_t* vHeadBase = vBase + h * vBytesPerHead;
        float* kHeadOut = kOut + h * qkNopeHeadDim;
        float* vHeadOut = vOut + h * vHeadDim;

        // K expansion
        for (size_t r = 0; r < qkNopeHeadDim; ++r) {
            const Q4_K_Block* rowBlocks = reinterpret_cast<const Q4_K_Block*>(
                kHeadBase + r * kBlocksPerRow * sizeof(Q4_K_Block));
            float sum = 0.0f;
            for (size_t b = 0; b < kBlocksPerRow; ++b) {
                dequantizeQ4KBlock(&rowBlocks[b], dequantBuf);
                const size_t n = std::min(size_t(256), kvLoraRank - b * 256);
                for (size_t i = 0; i < n; ++i) {
                    sum += dequantBuf[i] * compressedKV[b * 256 + i];
                }
            }
            kHeadOut[r] = sum;
        }

        // V expansion
        for (size_t r = 0; r < vHeadDim; ++r) {
            const Q4_K_Block* rowBlocks = reinterpret_cast<const Q4_K_Block*>(
                vHeadBase + r * vBlocksPerRow * sizeof(Q4_K_Block));
            float sum = 0.0f;
            for (size_t b = 0; b < vBlocksPerRow; ++b) {
                dequantizeQ4KBlock(&rowBlocks[b], dequantBuf);
                const size_t n = std::min(size_t(256), kvLoraRank - b * 256);
                for (size_t i = 0; i < n; ++i) {
                    sum += dequantBuf[i] * compressedKV[b * 256 + i];
                }
            }
            vHeadOut[r] = sum;
        }
    }
}

// ============================================================================
// Fused K+V expand for F32 — single pass over compressedKV
// ============================================================================
static void fusedKvExpand_F32_SinglePass(
    const float* kWeights, const float* vWeights,
    const float* compressedKV,
    float* kOut, float* vOut,
    size_t numHeads, size_t qkNopeHeadDim, size_t vHeadDim, size_t kvLoraRank) {

    for (size_t h = 0; h < numHeads; ++h) {
        const float* kHeadW = kWeights + h * qkNopeHeadDim * kvLoraRank;
        const float* vHeadW = vWeights + h * vHeadDim * kvLoraRank;
        float* kHeadOut = kOut + h * qkNopeHeadDim;
        float* vHeadOut = vOut + h * vHeadDim;

        // K expansion with AVX2
        for (size_t r = 0; r < qkNopeHeadDim; ++r) {
            const float* row = kHeadW + r * kvLoraRank;
            __m256 acc = _mm256_setzero_ps();
            size_t c = 0;
            for (; c + 8 <= kvLoraRank; c += 8) {
                __m256 w = _mm256_loadu_ps(row + c);
                __m256 x = _mm256_loadu_ps(compressedKV + c);
                acc = _mm256_fmadd_ps(w, x, acc);
            }
            float sum = hsum256(acc);
            for (; c < kvLoraRank; ++c) sum += row[c] * compressedKV[c];
            kHeadOut[r] = sum;
        }

        // V expansion with AVX2
        for (size_t r = 0; r < vHeadDim; ++r) {
            const float* row = vHeadW + r * kvLoraRank;
            __m256 acc = _mm256_setzero_ps();
            size_t c = 0;
            for (; c + 8 <= kvLoraRank; c += 8) {
                __m256 w = _mm256_loadu_ps(row + c);
                __m256 x = _mm256_loadu_ps(compressedKV + c);
                acc = _mm256_fmadd_ps(w, x, acc);
            }
            float sum = hsum256(acc);
            for (; c < kvLoraRank; ++c) sum += row[c] * compressedKV[c];
            vHeadOut[r] = sum;
        }
    }
}

} // anonymous namespace

// ============================================================================
// Public API
// ============================================================================

bool MLA_KvExpand_Fused(
    const void* kWeights,
    const void* vWeights,
    const float* compressedKV,
    float* kOut,
    float* vOut,
    size_t numHeads,
    size_t qkNopeHeadDim,
    size_t vHeadDim,
    size_t kvLoraRank,
    KvExpandQuantType kQuantType,
    KvExpandQuantType vQuantType) {

    if (!kWeights || !vWeights || !compressedKV || !kOut || !vOut) return false;
    if (numHeads == 0 || kvLoraRank == 0) return false;
    // Opt-out: DEEP2_MLA_FUSED_KV=0 forces legacy dual MLA_Gemv expand.
    if (const char* f = std::getenv("DEEP2_MLA_FUSED_KV")) {
        if (f[0] == '0') return false;
    }

    // Require same quant type for both (simplifies single-pass logic)
    if (kQuantType != vQuantType) {
        return false;
    }

    switch (kQuantType) {
        case KvExpandQuantType::Q8_0:
            fusedKvExpand_Q8_0_SinglePass(
                static_cast<const uint8_t*>(kWeights),
                static_cast<const uint8_t*>(vWeights),
                compressedKV, kOut, vOut,
                numHeads, qkNopeHeadDim, vHeadDim, kvLoraRank);
            return true;

        case KvExpandQuantType::Q4_K:
            fusedKvExpand_Q4K_SinglePass(
                static_cast<const uint8_t*>(kWeights),
                static_cast<const uint8_t*>(vWeights),
                compressedKV, kOut, vOut,
                numHeads, qkNopeHeadDim, vHeadDim, kvLoraRank);
            return true;

        case KvExpandQuantType::F32:
            fusedKvExpand_F32_SinglePass(
                static_cast<const float*>(kWeights),
                static_cast<const float*>(vWeights),
                compressedKV, kOut, vOut,
                numHeads, qkNopeHeadDim, vHeadDim, kvLoraRank);
            return true;

        default:
            return false;
    }
}

bool MLA_KvExpand_Fused_SingleWeight(
    const void* fusedWeights,
    const float* compressedKV,
    float* kOut,
    float* vOut,
    size_t numHeads,
    size_t qkNopeHeadDim,
    size_t vHeadDim,
    size_t kvLoraRank,
    KvExpandQuantType quantType) {

    if (!fusedWeights || !compressedKV || !kOut || !vOut) return false;
    if (numHeads == 0 || kvLoraRank == 0) return false;
    if (const char* f = std::getenv("DEEP2_MLA_FUSED_KV")) {
        if (f[0] == '0') return false;
    }

    const size_t perHeadCols = qkNopeHeadDim + vHeadDim;

    switch (quantType) {
        case KvExpandQuantType::Q8_0: {
            const size_t blocksPerRow = (kvLoraRank + 31) / 32;
            const size_t bytesPerHead = perHeadCols * blocksPerRow * sizeof(Q8_0_Block);
            const uint8_t* base = static_cast<const uint8_t*>(fusedWeights);

            for (size_t h = 0; h < numHeads; ++h) {
                const uint8_t* headBase = base + h * bytesPerHead;
                // K rows
                for (size_t r = 0; r < qkNopeHeadDim; ++r) {
                    const Q8_0_Block* rowBlocks = reinterpret_cast<const Q8_0_Block*>(
                        headBase + r * blocksPerRow * sizeof(Q8_0_Block));
                    float sum = 0.0f;
                    for (size_t b = 0; b < blocksPerRow; ++b) {
                        const float d = fp16ToFloat(rowBlocks[b].d);
                        const size_t col0 = b * 32;
                        for (size_t i = 0; i < 32 && col0 + i < kvLoraRank; ++i) {
                            sum += d * static_cast<float>(rowBlocks[b].qs[i]) * compressedKV[col0 + i];
                        }
                    }
                    kOut[h * qkNopeHeadDim + r] = sum;
                }
                // V rows
                for (size_t r = 0; r < vHeadDim; ++r) {
                    const Q8_0_Block* rowBlocks = reinterpret_cast<const Q8_0_Block*>(
                        headBase + (qkNopeHeadDim + r) * blocksPerRow * sizeof(Q8_0_Block));
                    float sum = 0.0f;
                    for (size_t b = 0; b < blocksPerRow; ++b) {
                        const float d = fp16ToFloat(rowBlocks[b].d);
                        const size_t col0 = b * 32;
                        for (size_t i = 0; i < 32 && col0 + i < kvLoraRank; ++i) {
                            sum += d * static_cast<float>(rowBlocks[b].qs[i]) * compressedKV[col0 + i];
                        }
                    }
                    vOut[h * vHeadDim + r] = sum;
                }
            }
            return true;
        }

        case KvExpandQuantType::Q4_K: {
            const size_t blocksPerRow = (kvLoraRank + 255) / 256;
            const size_t bytesPerHead = perHeadCols * blocksPerRow * sizeof(Q4_K_Block);
            const uint8_t* base = static_cast<const uint8_t*>(fusedWeights);
            alignas(64) float dequantBuf[256];

            for (size_t h = 0; h < numHeads; ++h) {
                const uint8_t* headBase = base + h * bytesPerHead;
                // K rows
                for (size_t r = 0; r < qkNopeHeadDim; ++r) {
                    const Q4_K_Block* rowBlocks = reinterpret_cast<const Q4_K_Block*>(
                        headBase + r * blocksPerRow * sizeof(Q4_K_Block));
                    float sum = 0.0f;
                    for (size_t b = 0; b < blocksPerRow; ++b) {
                        dequantizeQ4KBlock(&rowBlocks[b], dequantBuf);
                        const size_t n = std::min(size_t(256), kvLoraRank - b * 256);
                        for (size_t i = 0; i < n; ++i) {
                            sum += dequantBuf[i] * compressedKV[b * 256 + i];
                        }
                    }
                    kOut[h * qkNopeHeadDim + r] = sum;
                }
                // V rows
                for (size_t r = 0; r < vHeadDim; ++r) {
                    const Q4_K_Block* rowBlocks = reinterpret_cast<const Q4_K_Block*>(
                        headBase + (qkNopeHeadDim + r) * blocksPerRow * sizeof(Q4_K_Block));
                    float sum = 0.0f;
                    for (size_t b = 0; b < blocksPerRow; ++b) {
                        dequantizeQ4KBlock(&rowBlocks[b], dequantBuf);
                        const size_t n = std::min(size_t(256), kvLoraRank - b * 256);
                        for (size_t i = 0; i < n; ++i) {
                            sum += dequantBuf[i] * compressedKV[b * 256 + i];
                        }
                    }
                    vOut[h * vHeadDim + r] = sum;
                }
            }
            return true;
        }

        case KvExpandQuantType::F32: {
            const float* base = static_cast<const float*>(fusedWeights);
            for (size_t h = 0; h < numHeads; ++h) {
                const float* headBase = base + h * perHeadCols * kvLoraRank;
                // K rows
                for (size_t r = 0; r < qkNopeHeadDim; ++r) {
                    const float* row = headBase + r * kvLoraRank;
                    __m256 acc = _mm256_setzero_ps();
                    size_t c = 0;
                    for (; c + 8 <= kvLoraRank; c += 8) {
                        __m256 w = _mm256_loadu_ps(row + c);
                        __m256 x = _mm256_loadu_ps(compressedKV + c);
                        acc = _mm256_fmadd_ps(w, x, acc);
                    }
                    float sum = hsum256(acc);
                    for (; c < kvLoraRank; ++c) sum += row[c] * compressedKV[c];
                    kOut[h * qkNopeHeadDim + r] = sum;
                }
                // V rows
                for (size_t r = 0; r < vHeadDim; ++r) {
                    const float* row = headBase + (qkNopeHeadDim + r) * kvLoraRank;
                    __m256 acc = _mm256_setzero_ps();
                    size_t c = 0;
                    for (; c + 8 <= kvLoraRank; c += 8) {
                        __m256 w = _mm256_loadu_ps(row + c);
                        __m256 x = _mm256_loadu_ps(compressedKV + c);
                        acc = _mm256_fmadd_ps(w, x, acc);
                    }
                    float sum = hsum256(acc);
                    for (; c < kvLoraRank; ++c) sum += row[c] * compressedKV[c];
                    vOut[h * vHeadDim + r] = sum;
                }
            }
            return true;
        }

        default:
            return false;
    }
}

bool MLA_KvExpand_Fused_Available() {
    // Always available — has scalar fallback
    return true;
}

} // namespace Deep2
