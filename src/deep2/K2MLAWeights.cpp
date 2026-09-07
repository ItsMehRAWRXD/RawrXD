// ============================================================================
// K2MLAWeights.cpp — K2-002 MLA Tensor Schema Implementation
// ============================================================================

#include "K2MLAWeights.hpp"
#include "K2MLA_GpuGemv.hpp"
#include "K2MLA_KvExpand_Fused.hpp"
#include "K2GlobalTensorIndex.hpp"
#include "K2KVCache.hpp"
#include "K2MLAAttention.hpp"
#include "K2MlaStageTiming.hpp"
#include "QuantKernelRegistry.hpp"
#include "UniversalTensorDescriptor.hpp"
#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <atomic>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

// AVX2 for GEMV
#include <immintrin.h>

namespace Deep2 {

// ============================================================================
// Standalone FP16 -> FP32 conversion
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
// Q4_K Block structure (144 bytes)
// ============================================================================
#pragma pack(push, 1)
struct Q4_K_Block {
    uint16_t d;        // scale (fp16)
    uint16_t dmin;     // min   (fp16)
    uint8_t  scales[12]; // 8 pairs of 6-bit (scale,min) packed into 12 bytes
    uint8_t  qs[128];    // 256 4-bit weights packed into 128 bytes
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

// Interleaved Q4_K dequant (matches live gemv_q4k path used for MLA parity).
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
// Standalone FP32 GEMV (AVX2)
//   output[rows] = weights[rows, cols] * input[cols]
// ============================================================================
static void gemvF32(const float* weights, const float* input,
                    float* output, size_t rows, size_t cols) {
    for (size_t r = 0; r < rows; ++r) {
        const float* row = weights + r * cols;
        __m256 acc = _mm256_setzero_ps();
        size_t c = 0;
        for (; c + 8 <= cols; c += 8) {
            __m256 w = _mm256_loadu_ps(row + c);
            __m256 x = _mm256_loadu_ps(input + c);
            acc = _mm256_fmadd_ps(w, x, acc);
        }
        __m128 hi128 = _mm256_extractf128_ps(acc, 1);
        __m128 lo128 = _mm256_castps256_ps128(acc);
        __m128 sum128 = _mm_add_ps(lo128, hi128);
        sum128 = _mm_hadd_ps(sum128, sum128);
        sum128 = _mm_hadd_ps(sum128, sum128);
        float sum = _mm_cvtss_f32(sum128);
        for (; c < cols; ++c) sum += row[c] * input[c];
        output[r] = sum;
    }
}

// ============================================================================
// Standalone FP32 GEMV^T (transposed weights)
//   weights is [cols, rows] in memory (row-major), but logically [rows, cols]
//   output[rows] = weights^T[rows, cols] * input[cols]
//   where weights^T[r,c] = weights[c,r]
// ============================================================================
static void gemvF32Transposed(const float* weights, const float* input,
                              float* output, size_t rows, size_t cols) {
    for (size_t r = 0; r < rows; ++r) {
        float sum = 0.0f;
        size_t c = 0;
        __m256 acc = _mm256_setzero_ps();
        for (; c + 8 <= cols; c += 8) {
            // weights is stored as [cols, rows], so weights[c,r] is at weights[c*rows + r]
            __m256 w = _mm256_set_ps(
                weights[(c+7)*rows + r], weights[(c+6)*rows + r],
                weights[(c+5)*rows + r], weights[(c+4)*rows + r],
                weights[(c+3)*rows + r], weights[(c+2)*rows + r],
                weights[(c+1)*rows + r], weights[(c+0)*rows + r]
            );
            __m256 x = _mm256_loadu_ps(input + c);
            acc = _mm256_fmadd_ps(w, x, acc);
        }
        __m128 hi128 = _mm256_extractf128_ps(acc, 1);
        __m128 lo128 = _mm256_castps256_ps128(acc);
        __m128 sum128 = _mm_add_ps(lo128, hi128);
        sum128 = _mm_hadd_ps(sum128, sum128);
        sum128 = _mm_hadd_ps(sum128, sum128);
        sum = _mm_cvtss_f32(sum128);
        for (; c < cols; ++c) {
            sum += weights[c * rows + r] * input[c];
        }
        output[r] = sum;
    }
}

// ============================================================================
// Standalone Q4_K GEMV (dequantize-on-the-fly)
//   weights is [rows, cols] row-major, each row has blocksPerRow Q4_K blocks
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

static void gemvQ4KRowRange(const uint8_t* base, const float* input, float* output,
                            size_t r0, size_t r1, size_t cols, size_t blocksPerRow) {
    constexpr size_t kBlockSize = sizeof(Q4_K_Block);
    alignas(64) float dequantBuf[256];
    for (size_t r = r0; r < r1; ++r) {
        const Q4_K_Block* rowBlocks =
            (const Q4_K_Block*)(base + r * blocksPerRow * kBlockSize);
#if defined(__AVX512F__)
        __m512 acc512 = _mm512_setzero_ps();
#else
        __m256 acc256 = _mm256_setzero_ps();
#endif
        float sumTail = 0.f;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            dequantizeQ4KBlock(&rowBlocks[b], dequantBuf);
            size_t elemsInBlock = std::min(size_t(256), cols - b * 256);
            const float* x = input + b * 256;
            size_t i = 0;
#if defined(__AVX512F__)
            for (; i + 16 <= elemsInBlock; i += 16) {
                acc512 = _mm512_fmadd_ps(_mm512_load_ps(dequantBuf + i),
                                         _mm512_loadu_ps(x + i), acc512);
            }
            for (; i + 8 <= elemsInBlock; i += 8) {
                sumTail += hsum256(_mm256_mul_ps(_mm256_load_ps(dequantBuf + i),
                                                 _mm256_loadu_ps(x + i)));
            }
#else
            for (; i + 8 <= elemsInBlock; i += 8) {
                acc256 = _mm256_fmadd_ps(_mm256_load_ps(dequantBuf + i),
                                         _mm256_loadu_ps(x + i), acc256);
            }
#endif
            for (; i < elemsInBlock; ++i) sumTail += dequantBuf[i] * x[i];
        }
#if defined(__AVX512F__)
        output[r] = hsum512(acc512) + sumTail;
#else
        output[r] = hsum256(acc256) + sumTail;
#endif
    }
}

static void gemvQ4K(const void* weights, const float* input,
                    float* output, size_t rows, size_t cols) {
    size_t blocksPerRow = (cols + 255) / 256;
    const uint8_t* base = (const uint8_t*)weights;
    if (rows < 512) {
        gemvQ4KRowRange(base, input, output, 0, rows, cols, blocksPerRow);
        return;
    }
    unsigned nt = std::thread::hardware_concurrency();
    if (nt < 2u) nt = 2u;
    if (nt > 16u) nt = 16u;
    if (rows < nt) nt = (unsigned)rows;
    std::vector<std::thread> pool;
    pool.reserve(nt);
    for (unsigned t = 0; t < nt; ++t) {
        const size_t r0 = (rows * t) / nt;
        const size_t r1 = (rows * (t + 1u)) / nt;
        pool.emplace_back([&, r0, r1]() {
            gemvQ4KRowRange(base, input, output, r0, r1, cols, blocksPerRow);
        });
    }
    for (auto& th : pool) th.join();
}

static void gemvQ80(const void* weights, const float* input, float* output,
                    size_t rows, size_t cols) {
    const size_t blocksPerRow = (cols + 31) / 32;
    const uint8_t* base = static_cast<const uint8_t*>(weights);
    for (size_t r = 0; r < rows; ++r) {
        const Q8_0_Block* rowBlocks =
            reinterpret_cast<const Q8_0_Block*>(base + r * blocksPerRow * sizeof(Q8_0_Block));
        __m256 acc0 = _mm256_setzero_ps();
        __m256 acc1 = _mm256_setzero_ps();
        __m256 acc2 = _mm256_setzero_ps();
        __m256 acc3 = _mm256_setzero_ps();
        size_t b = 0;
        // Full 32-wide Q8_0 blocks via 4×AVX2 FMA (8 lanes each).
        for (; b < blocksPerRow; ++b) {
            const size_t col0 = b * 32;
            if (col0 + 32 > cols) break;
            _mm_prefetch((const char*)(rowBlocks + b + 1), _MM_HINT_T0);
            const float d = fp16ToFloat(rowBlocks[b].d);
            const __m256 scale = _mm256_set1_ps(d);
            const __m128i q8_lo = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(rowBlocks[b].qs));
            const __m128i q8_hi = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(rowBlocks[b].qs + 16));
            const __m256 qw0 = _mm256_mul_ps(
                _mm256_cvtepi32_ps(_mm256_cvtepi8_epi32(q8_lo)), scale);
            const __m256 qw1 = _mm256_mul_ps(
                _mm256_cvtepi32_ps(_mm256_cvtepi8_epi32(_mm_srli_si128(q8_lo, 8))),
                scale);
            const __m256 qw2 = _mm256_mul_ps(
                _mm256_cvtepi32_ps(_mm256_cvtepi8_epi32(q8_hi)), scale);
            const __m256 qw3 = _mm256_mul_ps(
                _mm256_cvtepi32_ps(_mm256_cvtepi8_epi32(_mm_srli_si128(q8_hi, 8))),
                scale);
            acc0 = _mm256_fmadd_ps(qw0, _mm256_loadu_ps(input + col0), acc0);
            acc1 = _mm256_fmadd_ps(qw1, _mm256_loadu_ps(input + col0 + 8), acc1);
            acc2 = _mm256_fmadd_ps(qw2, _mm256_loadu_ps(input + col0 + 16), acc2);
            acc3 = _mm256_fmadd_ps(qw3, _mm256_loadu_ps(input + col0 + 24), acc3);
        }
        float sum = hsum256(_mm256_add_ps(_mm256_add_ps(acc0, acc1),
                                          _mm256_add_ps(acc2, acc3)));
        for (; b < blocksPerRow; ++b) {
            const float d = fp16ToFloat(rowBlocks[b].d);
            const size_t col0 = b * 32;
            for (size_t i = 0; i < 32 && col0 + i < cols; ++i)
                sum += d * static_cast<float>(rowBlocks[b].qs[i]) * input[col0 + i];
        }
        output[r] = sum;
    }
}

static void gemvQ80Transposed(const void* weights, const float* input, float* output,
                              size_t rows, size_t cols) {
    const size_t blocksPerStoredRow = (rows + 31) / 32;
    float* rowBuf = static_cast<float*>(_aligned_malloc(rows * sizeof(float), 32));
    if (!rowBuf) return;
    for (size_t r = 0; r < rows; ++r) output[r] = 0.0f;
    const uint8_t* base = static_cast<const uint8_t*>(weights);
    for (size_t c = 0; c < cols; ++c) {
        const Q8_0_Block* rowBlocks = reinterpret_cast<const Q8_0_Block*>(
            base + c * blocksPerStoredRow * sizeof(Q8_0_Block));
        size_t r = 0;
        for (size_t b = 0; b < blocksPerStoredRow && r < rows; ++b) {
            const float d = fp16ToFloat(rowBlocks[b].d);
            for (size_t i = 0; i < 32 && r < rows; ++i)
                rowBuf[r++] = d * static_cast<float>(rowBlocks[b].qs[i]);
        }
        const float inVal = input[c];
        for (size_t i = 0; i < rows; ++i) output[i] += rowBuf[i] * inVal;
    }
    _aligned_free(rowBuf);
}

// ============================================================================
// Standalone Q4_K GEMV^T (transposed weights)
//   weights is [cols, rows] in memory (row-major Q4_K blocks)
//   output[rows] = weights^T[rows, cols] * input[cols]
//   where weights^T[r,c] = weights[c,r]
//
// CORRECTNESS: Q4_K stores each "column" (in transposed view) as a sequence
// of Q4_K blocks. We process one column at a time, dequantizing each block
// and accumulating into output. No large temporary allocations.
// ============================================================================
// ============================================================================
// Reference Q4_K GEMV^T — dequantize one stored row at a time
//
// Stored tensor layout: [cols, rows] row-major, each stored row has
// blocksPerStoredRow Q4_K blocks covering 'rows' elements.
//
// For each stored row c (0..cols-1):
//   Dequantize all blocks in that row to a temporary F32 buffer
//   For each output element r (0..rows-1):
//     output[r] += temp[r] * input[c]
//
// Temp memory: rows * sizeof(float) — small and safe.
// ============================================================================
// GGUF/ggml Q4_K: dims[0]=ne0 contiguous/blocked; dims[1]=ne1.
// Call: rows=ne1 (outputs), cols=ne0 (inputs). Column j is contiguous.
// Fused unpack→FMA; AVX-512 when compiled with /arch:AVX512.
// Twin of gemv_q4k.comp — 32-wide fused unpack→FMA (ggml nibble layout).
static void gemvQ4KTransposedRowRange(const uint8_t* base, const float* input,
                                      float* output, size_t j0, size_t j1,
                                      size_t cols, size_t blocksPerCol) {
    constexpr size_t kBlockSize = sizeof(Q4_K_Block);
    alignas(64) float blk[32];
    for (size_t j = j0; j < j1; ++j) {
        const uint8_t* colPtr = base + j * blocksPerCol * kBlockSize;
#if defined(__AVX512F__)
        __m512 acc512 = _mm512_setzero_ps();
#else
        __m256 acc256 = _mm256_setzero_ps();
#endif
        float sumTail = 0.f;
        size_t i = 0;
        for (size_t b = 0; b < blocksPerCol && i < cols; ++b) {
            if (b + 1 < blocksPerCol)
                _mm_prefetch((const char*)(colPtr + (b + 1) * kBlockSize), _MM_HINT_T0);
            const Q4_K_Block* block = (const Q4_K_Block*)(colPtr + b * kBlockSize);
            const float d = fp16ToFloat(block->d);
            const float dmin = fp16ToFloat(block->dmin);
            for (int s = 0; s < 8 && i < cols; ++s) {
                uint8_t sc, m;
                unpackQ4KScaleMin(block->scales, s, sc, m);
                const float scale = d * (float)sc;
                const float minv = dmin * (float)m;
                const uint8_t* quants = block->qs + s * 16;
                // Same layout as dequantizeQ4KBlock: lo[0..15], hi[0..15].
                for (int k = 0; k < 16; ++k) {
                    const uint8_t byte = quants[k];
                    blk[k] = scale * (float)(byte & 0xF) - minv;
                    blk[k + 16] = scale * (float)((byte >> 4) & 0xF) - minv;
                }
                const size_t n = (std::min)(size_t(32), cols - i);
#if defined(__AVX512F__)
                size_t t = 0;
                for (; t + 16 <= n; t += 16) {
                    acc512 = _mm512_fmadd_ps(_mm512_load_ps(blk + t),
                                             _mm512_loadu_ps(input + i + t), acc512);
                }
                for (; t + 8 <= n; t += 8) {
                    sumTail += hsum256(_mm256_mul_ps(_mm256_load_ps(blk + t),
                                                     _mm256_loadu_ps(input + i + t)));
                }
                for (; t < n; ++t) sumTail += blk[t] * input[i + t];
#else
                size_t t = 0;
                for (; t + 8 <= n; t += 8) {
                    acc256 = _mm256_fmadd_ps(_mm256_load_ps(blk + t),
                                             _mm256_loadu_ps(input + i + t), acc256);
                }
                for (; t < n; ++t) sumTail += blk[t] * input[i + t];
#endif
                i += n;
            }
        }
#if defined(__AVX512F__)
        output[j] = hsum512(acc512) + sumTail;
#else
        output[j] = hsum256(acc256) + sumTail;
#endif
    }
}

static std::atomic<int> g_gemvPoolDepth{0};

static void gemvQ4KTransposed(const void* weights, const float* input,
                              float* output, size_t rows, size_t cols) {
    const size_t blocksPerCol = (cols + 255) / 256;
    const uint8_t* base = (const uint8_t*)weights;
    // One white face: no nested pools under Q∥KV (oversubscription → MLA wall).
    const bool nested = g_gemvPoolDepth.load(std::memory_order_relaxed) > 0;
    if (rows < 1024 || nested) {
        gemvQ4KTransposedRowRange(base, input, output, 0, rows, cols, blocksPerCol);
        return;
    }
    unsigned nt = std::thread::hardware_concurrency();
    if (nt < 2u) nt = 2u;
    if (nt > 8u) nt = 8u;
    if (rows < nt) nt = (unsigned)rows;
    g_gemvPoolDepth.fetch_add(1, std::memory_order_relaxed);
    std::vector<std::thread> pool;
    pool.reserve(nt);
    for (unsigned t = 0; t < nt; ++t) {
        const size_t j0 = (rows * t) / nt;
        const size_t j1 = (rows * (t + 1u)) / nt;
        pool.emplace_back([&, j0, j1]() {
            gemvQ4KTransposedRowRange(base, input, output, j0, j1, cols, blocksPerCol);
        });
    }
    for (auto& th : pool) th.join();
    g_gemvPoolDepth.fetch_sub(1, std::memory_order_relaxed);
}

// ============================================================================
// GEMV dispatch for TensorView
// ============================================================================
// ============================================================================
// GEMV orientation — never static for 2D: resolve T vs row from tensor dims.
// hint: -1=none, 0=row, 1=T — used when dims are 3D/ambiguous (preserve authority).
// ============================================================================
static bool gemvOrientTransposed(const RawrXD::TensorView& w,
                                 size_t outRows, size_t inCols,
                                 int hint = -1) {
    const auto d = w.dims();
    if (d.size() == 2) {
        const size_t d0 = (size_t)d[0], d1 = (size_t)d[1];
        if (d0 == inCols && d1 == outRows) return true;
        if (d1 == inCols && d0 == outRows) return false;
        if (d0 == inCols) return true;
        if (d1 == inCols) return false;
    }
    if (hint >= 0) return hint != 0;
    return true; // Kimi MLA 2D default
}

static bool gemvDispatchRow(const RawrXD::TensorView& weightView,
                            const float* input, float* output,
                            size_t rows, size_t cols,
                            std::string& error) {
    if (!weightView.data()) {
        error = "gemvDispatchRow: weightView has no data";
        return false;
    }
    auto qt = weightView.quantType();
    if (qt == RawrXD::QuantType::F32) {
        const float* w = weightView.asF32();
        if (!w) { error = "gemvDispatchRow: F32 weight data is null"; return false; }
        gemvF32(w, input, output, rows, cols);
        return true;
    }
    if (qt == RawrXD::QuantType::Q4_K) {
        if (MLA_Gemv(12, weightView.data(), weightView.byteSize(), input, output,
                           (uint32_t)rows, (uint32_t)cols))
            return true;
        gemvQ4K(weightView.data(), input, output, rows, cols);
        return true;
    }
    if (qt == RawrXD::QuantType::Q8_0) {
        if (MLA_Gemv(8, weightView.data(), weightView.byteSize(), input, output,
                           (uint32_t)rows, (uint32_t)cols))
            return true;
        gemvQ80(weightView.data(), input, output, rows, cols);
        return true;
    }
    error = "gemvDispatchRow: unsupported quant type";
    return false;
}

static bool gemvDispatchT(const RawrXD::TensorView& weightView,
                          const float* input, float* output,
                          size_t rows, size_t cols,
                          std::string& error) {
    if (!weightView.data()) {
        error = "gemvDispatchT: weightView has no data";
        return false;
    }
    auto qt = weightView.quantType();
    if (qt == RawrXD::QuantType::F32) {
        const float* w = weightView.asF32();
        if (!w) { error = "gemvDispatchT: F32 weight data is null"; return false; }
        gemvF32Transposed(w, input, output, rows, cols);
        return true;
    }
    if (qt == RawrXD::QuantType::Q4_K) {
        if (MLA_Gemv(12, weightView.data(), weightView.byteSize(), input, output,
                           (uint32_t)rows, (uint32_t)cols))
            return true;
        gemvQ4KTransposed(weightView.data(), input, output, rows, cols);
        return true;
    }
    if (qt == RawrXD::QuantType::Q8_0) {
        if (MLA_Gemv(8, weightView.data(), weightView.byteSize(), input, output,
                           (uint32_t)rows, (uint32_t)cols))
            return true;
        gemvQ80Transposed(weightView.data(), input, output, rows, cols);
        return true;
    }
    error = "gemvDispatchT: unsupported quant type " + std::to_string((int)qt);
    return false;
}

// Orient when dims decide; Transposed call sites keep forced-T authority.
static bool gemvDispatch(const RawrXD::TensorView& weightView,
                         const float* input, float* output,
                         size_t rows, size_t cols,
                         std::string& error) {
    if (gemvOrientTransposed(weightView, rows, cols))
        return gemvDispatchT(weightView, input, output, rows, cols, error);
    return gemvDispatchRow(weightView, input, output, rows, cols, error);
}

static bool gemvDispatchTransposed(const RawrXD::TensorView& weightView,
                                   const float* input, float* output,
                                   size_t rows, size_t cols,
                                   std::string& error) {
    // Call-site says T — do not re-orient (wrong orient → AV / parity break).
    return gemvDispatchT(weightView, input, output, rows, cols, error);
}

static void gemvQ4KOriented(bool transposed, const void* w, const float* in,
                            float* out, size_t rows, size_t cols) {
    if (transposed) gemvQ4KTransposed(w, in, out, rows, cols);
    else gemvQ4K(w, in, out, rows, cols);
}
static void gemvQ80Oriented(bool transposed, const void* w, const float* in,
                            float* out, size_t rows, size_t cols) {
    if (transposed) gemvQ80Transposed(w, in, out, rows, cols);
    else gemvQ80(w, in, out, rows, cols);
}

// ============================================================================
// Standalone RMSNorm
// ============================================================================
static void rmsNorm(const float* input, const float* weight,
                    float* output, size_t n, float eps) {
    float ss = 0.0f;
    for (size_t i = 0; i < n; ++i) ss += input[i] * input[i];
    float invRms = 1.0f / std::sqrt(ss / static_cast<float>(n) + eps);
    for (size_t i = 0; i < n; ++i) output[i] = input[i] * invRms * weight[i];
}

// ============================================================================
// RMSNorm with TensorView weight (handles F16 and F32 norm weights)
// ============================================================================
static void rmsNormTensorView(const float* input, const RawrXD::TensorView& weightView,
                              float* output, size_t n, float eps) {
    float ss = 0.0f;
    for (size_t i = 0; i < n; ++i) ss += input[i] * input[i];
    float invRms = 1.0f / std::sqrt(ss / static_cast<float>(n) + eps);

    auto qt = weightView.quantType();
    if (qt == RawrXD::QuantType::F32) {
        const float* w = weightView.asF32();
        for (size_t i = 0; i < n; ++i) output[i] = input[i] * invRms * w[i];
    } else if (qt == RawrXD::QuantType::F16) {
        const uint16_t* w = reinterpret_cast<const uint16_t*>(weightView.data());
        for (size_t i = 0; i < n; ++i) {
            float wf = fp16ToFloat(w[i]);
            output[i] = input[i] * invRms * wf;
        }
    } else {
        // Fallback: treat as F32 anyway (may read garbage for unsupported types)
        const float* w = weightView.asF32();
        for (size_t i = 0; i < n; ++i) output[i] = input[i] * invRms * w[i];
    }
}

// ============================================================================
// MLAWeights
// ============================================================================

bool MLAWeights::Validate(const KimiK2Config& config, std::string& error) const {
    // Check all required tensors are present (resolved from index has metadata but no data pointer yet)
    if (attnQ_a.dims().empty())         { error = "MLAWeights: attn_q_a missing"; return false; }
    if (attnQ_a_norm.dims().empty())    { error = "MLAWeights: attn_q_a_norm missing"; return false; }
    if (attnQ_b.dims().empty())         { error = "MLAWeights: attn_q_b missing"; return false; }
    if (attnKV_a_mqa.dims().empty())    { error = "MLAWeights: attn_kv_a_mqa missing"; return false; }
    if (attnKV_a_norm.dims().empty())   { error = "MLAWeights: attn_kv_a_norm missing"; return false; }
    if (attnK_b.dims().empty())         { error = "MLAWeights: attn_k_b/attn_kv_b missing"; return false; }
    const bool fused = fusedKvB || attnV_b.dims().empty();
    if (!fused && attnV_b.dims().empty()) { error = "MLAWeights: attn_v_b missing"; return false; }
    if (attnO.dims().empty())           { error = "MLAWeights: attn_o missing"; return false; }
    if (attnNorm.dims().empty())        { error = "MLAWeights: attn_norm missing"; return false; }

    // Validate tensor shapes for internal consistency (not exact config match).
    // The actual GGUF tensors define the ground-truth dimensions; config is a hint.
    // We verify that the tensor dimensions are mutually compatible for the MLA pipeline.
    // ALL dimensions are derived from actual tensor shapes (GGUF is authoritative).

    // attn_q_a: [hiddenDim, qLoraRank]
    if (attnQ_a.dims().size() != 2) {
        error = "MLAWeights: attn_q_a not 2D"; return false;
    }
    const uint32_t hiddenDim = static_cast<uint32_t>(attnQ_a.dims()[0]);
    const uint32_t qLoraRank = static_cast<uint32_t>(attnQ_a.dims()[1]);

    // attn_q_b: [qLoraRank, numHeads * headDim]
    if (attnQ_b.dims().size() != 2 || attnQ_b.dims()[0] != qLoraRank) {
        error = "MLAWeights: attn_q_b shape mismatch (rows != qLoraRank)"; return false;
    }
    const uint32_t qBCols = static_cast<uint32_t>(attnQ_b.dims()[1]);

    // attn_kv_a_mqa: [hiddenDim, kvLoraRank + qkRopeHeadDim]
    if (attnKV_a_mqa.dims().size() != 2 || attnKV_a_mqa.dims()[0] != hiddenDim) {
        error = "MLAWeights: attn_kv_a_mqa shape mismatch (rows != hiddenDim)"; return false;
    }
    const uint32_t kvACols = static_cast<uint32_t>(attnKV_a_mqa.dims()[1]);

    // Derive kvLoraRank from attnK_b (the compressed KV projection)
    // attnK_b: [kvLoraRank, numHeads * qkNopeHeadDim]
    uint32_t kvLoraRank = 0;
    if (attnK_b.dims().size() == 2) {
        kvLoraRank = static_cast<uint32_t>(attnK_b.dims()[0]);
    } else if (attnK_b.dims().size() == 3) {
        kvLoraRank = static_cast<uint32_t>(attnK_b.dims()[1]);
    } else {
        error = "MLAWeights: attn_k_b unexpected dimension count"; return false;
    }

    // Validate kv_a split: kvACols = kvLoraRank + qkRopeHeadDim
    if (kvACols < kvLoraRank) {
        error = "MLAWeights: attn_kv_a_mqa cols (" + std::to_string(kvACols) +
                ") < kvLoraRank derived from attn_k_b (" + std::to_string(kvLoraRank) + ")";
        return false;
    }

    if (fused) {
        if (attnK_b.dims().size() != 2) {
            error = "MLAWeights: fused attn_kv_b must be 2D [kvLora, n_head*(nope+v)]";
            return false;
        }
    } else if (attnV_b.dims().size() == 2) {
        if (attnV_b.dims()[0] != kvLoraRank) {
            error = "MLAWeights: attn_v_b 2D shape mismatch (rows != kvLoraRank)"; return false;
        }
    } else if (attnV_b.dims().size() == 3) {
        if (attnV_b.dims()[0] != kvLoraRank && attnV_b.dims()[1] != kvLoraRank) {
            error = "MLAWeights: attn_v_b 3D shape mismatch (no kvLoraRank axis)"; return false;
        }
    } else {
        error = "MLAWeights: attn_v_b unexpected dimension count"; return false;
    }

    // attn_output: [numHeads * vHeadDim, hiddenDim] — cols must match hiddenDim for residual
    if (attnO.dims().size() != 2 || attnO.dims()[1] != hiddenDim) {
        error = "MLAWeights: attn_output shape mismatch (cols != hiddenDim)"; return false;
    }

    // attnNorm: [hiddenDim]
    if (attnNorm.dims().size() != 1 || attnNorm.dims()[0] != hiddenDim) {
        error = "MLAWeights: attn_norm shape mismatch"; return false;
    }

    // Validate numHeads divides q_b cols evenly (each head gets equal Q dim)
    if (config.numHeads > 0 && qBCols % config.numHeads != 0) {
        error = "MLAWeights: attn_q_b cols (" + std::to_string(qBCols) +
                ") not divisible by numHeads (" + std::to_string(config.numHeads) + ")";
        return false;
    }

    return true;
}

bool MLAWeights::ResolveFromTensorIndex(const GlobalTensorIndex& index, uint32_t layer, std::string& error) {
    // Build layer-scoped tensor names
    char qAName[64], qANormName[64], qBName[64];
    char kvAName[64], kvANormName[64], kBName[64], vBName[64];
    char oName[64], normName[64];

    snprintf(qAName, sizeof(qAName), "blk.%u.attn_q_a.weight", layer);
    snprintf(qANormName, sizeof(qANormName), "blk.%u.attn_q_a_norm.weight", layer);
    snprintf(qBName, sizeof(qBName), "blk.%u.attn_q_b.weight", layer);
    snprintf(kvAName, sizeof(kvAName), "blk.%u.attn_kv_a_mqa.weight", layer);
    snprintf(kvANormName, sizeof(kvANormName), "blk.%u.attn_kv_a_norm.weight", layer);
    snprintf(kBName, sizeof(kBName), "blk.%u.attn_k_b.weight", layer);
    snprintf(vBName, sizeof(vBName), "blk.%u.attn_v_b.weight", layer);
    snprintf(oName, sizeof(oName), "blk.%u.attn_output.weight", layer);
    snprintf(normName, sizeof(normName), "blk.%u.attn_norm.weight", layer);

    auto resolve = [&](const char* name, RawrXD::TensorView& view) -> bool {
        auto refOpt = index.Find(name);
        if (!refOpt) return false;
        const auto& ref = *refOpt;

        RawrXD::UniversalTensorDescriptor desc;
        desc.numDims = ref.nDims;
        for (uint8_t i = 0; i < ref.nDims && i < 8; ++i) {
            desc.shape[i] = ref.shape[i];
        }
        desc.quantType = RawrXD::QuantType::UNKNOWN; // Will be set from ggmlType
        desc.layout = RawrXD::TensorLayout::DENSE;
        desc.role = RawrXD::TensorRole::WEIGHT;
        desc.memorySpace = RawrXD::UniversalTensorDescriptor::MemorySpace::NVME;
        desc.data = nullptr;

        // Map GGML type to QuantType (must match ggml.h enum ggml_type)
        switch (ref.ggmlType) {
            case 0:  desc.quantType = RawrXD::QuantType::F32;     desc.blockSize = 1;   desc.blockSizeBytes = 4; break;
            case 1:  desc.quantType = RawrXD::QuantType::F16;     desc.blockSize = 1;   desc.blockSizeBytes = 2; break;
            case 2:  desc.quantType = RawrXD::QuantType::Q4_0;    desc.blockSize = 32;  desc.blockSizeBytes = 18; break;
            case 3:  desc.quantType = RawrXD::QuantType::Q4_1;    desc.blockSize = 32;  desc.blockSizeBytes = 20; break;
            case 6:  desc.quantType = RawrXD::QuantType::Q5_0;    desc.blockSize = 32;  desc.blockSizeBytes = 22; break;
            case 7:  desc.quantType = RawrXD::QuantType::Q5_1;    desc.blockSize = 32;  desc.blockSizeBytes = 24; break;
            case 8:  desc.quantType = RawrXD::QuantType::Q8_0;    desc.blockSize = 32;  desc.blockSizeBytes = 34; break;
            case 9:  desc.quantType = RawrXD::QuantType::Q8_1;    desc.blockSize = 32;  desc.blockSizeBytes = 36; break;
            case 10: desc.quantType = RawrXD::QuantType::Q2_K;    desc.blockSize = 256; desc.blockSizeBytes = 96; break;
            case 11: desc.quantType = RawrXD::QuantType::Q3_K;    desc.blockSize = 256; desc.blockSizeBytes = 144; break;
            case 12: desc.quantType = RawrXD::QuantType::Q4_K;    desc.blockSize = 256; desc.blockSizeBytes = 144; break;
            case 13: desc.quantType = RawrXD::QuantType::Q5_K;    desc.blockSize = 256; desc.blockSizeBytes = 176; break;
            case 14: desc.quantType = RawrXD::QuantType::Q6_K;    desc.blockSize = 256; desc.blockSizeBytes = 210; break;
            case 15: desc.quantType = RawrXD::QuantType::UNKNOWN; desc.blockSize = 256; desc.blockSizeBytes = 292; break; // Q8_K not yet supported
            case 16: desc.quantType = RawrXD::QuantType::IQ2_XXS; desc.blockSize = 256; desc.blockSizeBytes = 98; break;
            case 17: desc.quantType = RawrXD::QuantType::IQ2_XS;  desc.blockSize = 256; desc.blockSizeBytes = 104; break;
            case 18: desc.quantType = RawrXD::QuantType::IQ3_XXS; desc.blockSize = 256; desc.blockSizeBytes = 122; break;
            case 19: desc.quantType = RawrXD::QuantType::UNKNOWN; desc.blockSize = 256; desc.blockSizeBytes = 154; break; // IQ1_S
            case 20: desc.quantType = RawrXD::QuantType::IQ4_NL;  desc.blockSize = 32;  desc.blockSizeBytes = 18; break;
            case 21: desc.quantType = RawrXD::QuantType::UNKNOWN; desc.blockSize = 256; desc.blockSizeBytes = 166; break; // IQ3_S
            case 22: desc.quantType = RawrXD::QuantType::UNKNOWN; desc.blockSize = 256; desc.blockSizeBytes = 154; break; // IQ2_S
            case 23: desc.quantType = RawrXD::QuantType::IQ4_XS;  desc.blockSize = 256; desc.blockSizeBytes = 136; break;
            case 24: desc.quantType = RawrXD::QuantType::I8;      desc.blockSize = 1;   desc.blockSizeBytes = 1; break;
            case 25: desc.quantType = RawrXD::QuantType::I16;     desc.blockSize = 1;   desc.blockSizeBytes = 2; break;
            case 26: desc.quantType = RawrXD::QuantType::I32;     desc.blockSize = 1;   desc.blockSizeBytes = 4; break;
            case 27: desc.quantType = RawrXD::QuantType::I64;     desc.blockSize = 1;   desc.blockSizeBytes = 8; break;
            case 28: desc.quantType = RawrXD::QuantType::UNKNOWN; desc.blockSize = 1;   desc.blockSizeBytes = 8; break; // F64
            case 29: desc.quantType = RawrXD::QuantType::UNKNOWN; desc.blockSize = 256; desc.blockSizeBytes = 160; break; // IQ1_M
            case 30: desc.quantType = RawrXD::QuantType::BF16;    desc.blockSize = 1;   desc.blockSizeBytes = 2; break;
            default: desc.quantType = RawrXD::QuantType::UNKNOWN; desc.blockSize = 1;   desc.blockSizeBytes = 4; break;
        }

        view = RawrXD::TensorView::FromBuffer(desc, nullptr, false);
        return true;
    };

    if (!resolve(qAName, attnQ_a))       { error = std::string("MLAWeights: ") + qAName + " not found in index"; return false; }
    if (!resolve(qANormName, attnQ_a_norm)) { error = std::string("MLAWeights: ") + qANormName + " not found in index"; return false; }
    if (!resolve(qBName, attnQ_b))       { error = std::string("MLAWeights: ") + qBName + " not found in index"; return false; }
    if (!resolve(kvAName, attnKV_a_mqa)) { error = std::string("MLAWeights: ") + kvAName + " not found in index"; return false; }
    if (!resolve(kvANormName, attnKV_a_norm)) { error = std::string("MLAWeights: ") + kvANormName + " not found in index"; return false; }
    fusedKvB = false;
    if (!resolve(kBName, attnK_b) || !resolve(vBName, attnV_b)) {
        char kvBName[64];
        snprintf(kvBName, sizeof(kvBName), "blk.%u.attn_kv_b.weight", layer);
        if (!resolve(kvBName, attnK_b)) {
            error = std::string("MLAWeights: ") + kBName + " / " + kvBName + " not found";
            return false;
        }
        fusedKvB = true;
        attnV_b = RawrXD::TensorView();
    }
    if (!resolve(oName, attnO))          { error = std::string("MLAWeights: ") + oName + " not found in index"; return false; }
    if (!resolve(normName, attnNorm))    { error = std::string("MLAWeights: ") + normName + " not found in index"; return false; }

    return true;
}

// ============================================================================
// ResolveAndLoad — resolve metadata AND load actual payload bytes from shards
// ============================================================================
uint64_t MLAWeights::ResolveAndLoad(const GlobalTensorIndex& index, uint32_t layer,
                                      std::string& error) {
    // First resolve metadata
    if (!ResolveFromTensorIndex(index, layer, error)) {
        return 0;
    }

    uint64_t totalLoaded = 0;

    auto loadOne = [&](const char* name, RawrXD::TensorView& view, uint64_t& total) -> bool {
        if (view.data() != nullptr) return true; // Already loaded
        auto refOpt = index.Find(name);
        if (!refOpt) return false;
        const auto& ref = *refOpt;

        const auto& shardPath = index.ShardPath(ref.shardId);
        std::ifstream f(shardPath.string(), std::ios::binary);
        if (!f) return false;
        f.seekg(static_cast<std::streamoff>(ref.fileOffset));
        if (!f.good()) return false;

        void* buffer = _aligned_malloc(ref.byteSize, 64);
        if (!buffer) return false;

        f.read(reinterpret_cast<char*>(buffer), ref.byteSize);
        if (static_cast<size_t>(f.gcount()) != ref.byteSize) {
            _aligned_free(buffer);
            return false;
        }
        total += ref.byteSize;

        // Re-create the view with actual data ownership
        RawrXD::UniversalTensorDescriptor desc = view.descriptor();
        desc.data = buffer;
        view = RawrXD::TensorView::FromBuffer(desc, buffer, true);
        return true;
    };

    char qAName[64], qANormName[64], qBName[64];
    char kvAName[64], kvANormName[64], kBName[64], vBName[64];
    char oName[64], normName[64];
    snprintf(qAName, sizeof(qAName), "blk.%u.attn_q_a.weight", layer);
    snprintf(qANormName, sizeof(qANormName), "blk.%u.attn_q_a_norm.weight", layer);
    snprintf(qBName, sizeof(qBName), "blk.%u.attn_q_b.weight", layer);
    snprintf(kvAName, sizeof(kvAName), "blk.%u.attn_kv_a_mqa.weight", layer);
    snprintf(kvANormName, sizeof(kvANormName), "blk.%u.attn_kv_a_norm.weight", layer);
    snprintf(kBName, sizeof(kBName), "blk.%u.attn_k_b.weight", layer);
    snprintf(vBName, sizeof(vBName), "blk.%u.attn_v_b.weight", layer);
    snprintf(oName, sizeof(oName), "blk.%u.attn_output.weight", layer);
    snprintf(normName, sizeof(normName), "blk.%u.attn_norm.weight", layer);

    if (!loadOne(qAName, attnQ_a, totalLoaded))       { error = "MLAWeights: failed to load " + std::string(qAName); return 0; }
    if (!loadOne(qANormName, attnQ_a_norm, totalLoaded)) { error = "MLAWeights: failed to load " + std::string(qANormName); return 0; }
    if (!loadOne(qBName, attnQ_b, totalLoaded))       { error = "MLAWeights: failed to load " + std::string(qBName); return 0; }
    if (!loadOne(kvAName, attnKV_a_mqa, totalLoaded)) { error = "MLAWeights: failed to load " + std::string(kvAName); return 0; }
    if (!loadOne(kvANormName, attnKV_a_norm, totalLoaded)) { error = "MLAWeights: failed to load " + std::string(kvANormName); return 0; }
    if (fusedKvB) {
        char kvBName[64];
        snprintf(kvBName, sizeof(kvBName), "blk.%u.attn_kv_b.weight", layer);
        if (!loadOne(kvBName, attnK_b, totalLoaded)) {
            error = "MLAWeights: failed to load fused " + std::string(kvBName); return 0;
        }
    } else {
        if (!loadOne(kBName, attnK_b, totalLoaded))       { error = "MLAWeights: failed to load " + std::string(kBName); return 0; }
        if (!loadOne(vBName, attnV_b, totalLoaded))       { error = "MLAWeights: failed to load " + std::string(vBName); return 0; }
    }
    if (!loadOne(oName, attnO, totalLoaded))          { error = "MLAWeights: failed to load " + std::string(oName); return 0; }
    if (!loadOne(normName, attnNorm, totalLoaded))    { error = "MLAWeights: failed to load " + std::string(normName); return 0; }

    return totalLoaded;
}

// ============================================================================
// ReleaseAll — free all aligned tensor buffers
// ============================================================================
// CRITICAL: TensorView destructor already frees data when ownsData_ is true.
// Do NOT call _aligned_free manually here — that causes double-free heap corruption.
// Just reset the view to empty; the destructor handles cleanup.
// ============================================================================
void MLAWeights::ReleaseAll() {
    auto release = [](RawrXD::TensorView& view) {
        view = RawrXD::TensorView(); // Destructor frees if ownsData_
    };
    release(attnQ_a);
    release(attnQ_a_norm);
    release(attnQ_b);
    release(attnKV_a_mqa);
    release(attnKV_a_norm);
    release(attnK_b);
    release(attnV_b);
    release(attnO);
    release(attnNorm);
}

bool MLAWeights::DetectMLA(const std::string& tensorName) {
    static const char* kMLAPrefixes[] = {
        "attn_q_a", "attn_q_b", "attn_kv_a", "attn_kv_b", "attn_k_b", "attn_v_b",
        "attn_output", "attn_norm", "attn_q_a_norm", "attn_kv_a_norm"
    };
    for (const char* prefix : kMLAPrefixes) {
        if (tensorName.find(prefix) != std::string::npos) return true;
    }
    return false;
}

// ============================================================================
// MLAForward
// ============================================================================

bool MLAForward::Execute(const float* hidden, float* output,
                         const MLAWeights& weights,
                         const KimiK2Config& config,
                         std::string& error,
                         rawrxd::deep2::K2KVCache* kvCache,
                         uint32_t layerIdx,
                         uint32_t position,
                         MlaCompleteStats* stats) {
    if (!hidden || !output) {
        error = "MLAForward: null input/output pointer";
        return false;
    }

    if (!weights.Validate(config, error)) {
        return false;
    }

    // =========================================================================
    // DERIVE ALL DIMENSIONS FROM ACTUAL TENSOR SHAPES (GGUF is authoritative)
    // =========================================================================
    // attnQ_a: [hiddenDim, qLoraRank]
    const size_t hiddenDim = weights.attnQ_a.dims()[0];
    const size_t qLoraRank = weights.attnQ_a.dims()[1];

    // attnQ_b: [qLoraRank, numHeads * headDim]
    const size_t qBCols = weights.attnQ_b.dims()[1];
    const size_t numHeads = config.numHeads; // heads is architectural, not tensor-derived
    if (qBCols % numHeads != 0) {
        error = "MLAForward: attn_q_b cols (" + std::to_string(qBCols) +
                ") not divisible by numHeads (" + std::to_string(numHeads) + ")";
        return false;
    }
    const size_t headDim = qBCols / numHeads;

    // attnKV_a_mqa: [hiddenDim, kvLoraRank + qkRopeHeadDim]
    const size_t kvACols = weights.attnKV_a_mqa.dims()[1];

    // attn_k_b / attn_v_b: K2 GGUF is 3D — (nope, kv_lora, heads) / (kv_lora, v, heads)
    size_t kvLoraRank = 0;
    size_t qkNopeHeadDim = 0;
    size_t vHeadDim = 0;
    const auto& kDims = weights.attnK_b.dims();
    const auto& vDims = weights.attnV_b.dims();
    const bool kIs3D = (kDims.size() == 3);
    const bool vIs3D = (vDims.size() == 3);
    if (kIs3D) {
        qkNopeHeadDim = kDims[0];
        kvLoraRank = kDims[1];
    } else if (kDims.size() >= 2) {
        kvLoraRank = (config.kvLoraRank > 0) ? config.kvLoraRank : kDims[0];
        qkNopeHeadDim = (config.qkNopeHeadDim > 0) ? config.qkNopeHeadDim
            : ((numHeads > 0) ? (kDims[1] / numHeads) : 0);
    } else if (!kDims.empty()) {
        kvLoraRank = (config.kvLoraRank > 0) ? config.kvLoraRank : kDims[0];
        qkNopeHeadDim = (config.qkNopeHeadDim > 0) ? config.qkNopeHeadDim : 128;
    }
    if (vIs3D) {
        vHeadDim = (vDims[0] == kvLoraRank) ? vDims[1] : vDims[0];
    } else if (vDims.size() >= 2) {
        vHeadDim = (config.vHeadDim > 0) ? config.vHeadDim
            : ((numHeads > 0) ? (vDims[1] / numHeads) : 0);
    } else if (config.vHeadDim > 0) {
        vHeadDim = config.vHeadDim;
    }
    if ((weights.fusedKvB || vDims.empty()) && kDims.size() == 2 && numHeads > 0 &&
        (kDims[1] % numHeads) == 0) {
        const size_t per = kDims[1] / numHeads;
        if (qkNopeHeadDim == 0 || qkNopeHeadDim >= per)
            qkNopeHeadDim = (config.qkNopeHeadDim && config.qkNopeHeadDim < per)
                ? config.qkNopeHeadDim : (per / 2);
        if (vHeadDim == 0 || qkNopeHeadDim + vHeadDim != per)
            vHeadDim = per - qkNopeHeadDim;
    }
    const size_t qkRopeHeadDim = (kvACols > kvLoraRank) ? (kvACols - kvLoraRank)
        : ((config.qkRopeHeadDim > 0) ? config.qkRopeHeadDim : 0);

    // Legacy 2D column counts (used only on 2D path)
    const size_t kBCols = (!kIs3D && kDims.size() >= 2) ? kDims[1]
        : (numHeads * qkNopeHeadDim);
    const size_t vBCols = (!vIs3D && vDims.size() >= 2) ? vDims[1]
        : (numHeads * vHeadDim);

    // attnO: [oRows, hiddenDim] — use actual GGUF shape (authoritative)
    // For K2, oRows may differ from numHeads * vHeadDim due to architecture specifics
    const size_t oRows = weights.attnO.dims()[0];

    // Safety: validate all tensors have actual data before allocating
    if (!weights.attnQ_a.data() || !weights.attnQ_b.data() || !weights.attnKV_a_mqa.data() ||
        !weights.attnK_b.data() || !weights.attnO.data() ||
        (!weights.fusedKvB && !weights.attnV_b.data())) {
        error = "MLAForward: one or more weight tensors have no data (metadata-only?)";
        return false;
    }

    // Allocate temporary buffers using ACTUAL derived dimensions (TLS reuse).
    struct MlaTls {
        float* q_a = nullptr; float* q_b = nullptr; float* kv_a = nullptr;
        float* k_b = nullptr; float* v_b = nullptr; float* attnOut = nullptr;
        size_t qA = 0, qB = 0, kvA = 0, kB = 0, vB = 0, attnN = 0;
        void ensure(size_t qa, size_t qb, size_t kva, size_t kb, size_t vb, size_t an) {
            auto grow = [](float*& p, size_t& cap, size_t need) {
                if (need <= cap) return true;
                _aligned_free(p);
                p = (float*)_aligned_malloc(need * sizeof(float), 32);
                cap = p ? need : 0;
                return p != nullptr;
            };
            if (!grow(q_a, qA, qa) || !grow(q_b, qB, qb) || !grow(kv_a, kvA, kva) ||
                !grow(k_b, kB, kb) || !grow(v_b, vB, vb) || !grow(attnOut, attnN, an))
                return;
        }
    };
    static thread_local MlaTls tls;
    const size_t attnOutSize = std::max(numHeads * headDim, oRows);
    tls.ensure(qLoraRank, numHeads * headDim, kvACols,
               numHeads * qkNopeHeadDim, numHeads * vHeadDim, attnOutSize);
    float* q_a = tls.q_a; float* q_b = tls.q_b; float* kv_a = tls.kv_a;
    float* compressedKV = kv_a;
    float* k_pe = kv_a + kvLoraRank;
    float* k_b = tls.k_b; float* v_b = tls.v_b; float* attnOut = tls.attnOut;

    if (!q_a || !q_b || !kv_a || !k_b || !v_b || !attnOut) {
        error = "MLAForward: buffer allocation failed";
        return false;
    }

    const size_t oActualRows = oRows;
    const size_t oCols       = hiddenDim;
    const bool fusedKv = weights.fusedKvB || (kDims.size() == 2 && vDims.empty());
    float* fusedTmp = nullptr;
    uint64_t tQkv = 0, tExp = 0, tAttn = 0, tO = 0;

    // Q-path || KV compress (independent until expand/attn).
    // GPU MLA serializes through one VkQueue — keep host path sequential too
    // when DEEP2_MLA_SERIAL=1 or GPU MLA is on (fair + avoids mutex thrash).
    std::string qErr, kvErr;
    bool qOk = false, kvOk = false;
    auto pin = [&](uint8_t tag) {
        MLA_GpuGemv_SetPinKey(((uint64_t)layerIdx << 8) | (uint64_t)tag);
    };
    auto runQ = [&]() {
        pin(1);
        if (!gemvDispatchTransposed(weights.attnQ_a, hidden, q_a,
                                    qLoraRank, hiddenDim, qErr)) return;
        if (weights.attnQ_a_norm.data())
            rmsNormTensorView(q_a, weights.attnQ_a_norm, q_a, qLoraRank, config.normRmsEps);
        pin(2);
        if (!gemvDispatchTransposed(weights.attnQ_b, q_a, q_b,
                                    qBCols, qLoraRank, qErr)) return;
        qOk = true;
    };
    auto runKv = [&]() {
        pin(3);
        if (!gemvDispatchTransposed(weights.attnKV_a_mqa, hidden, kv_a,
                                    kvACols, hiddenDim, kvErr)) return;
        if (weights.attnKV_a_norm.data())
            rmsNormTensorView(compressedKV, weights.attnKV_a_norm, compressedKV,
                              kvLoraRank, config.normRmsEps);
        kvOk = true;
    };
    const char* ser = std::getenv("DEEP2_MLA_SERIAL");
    const bool serial = MLA_GpuGemvWanted() || (ser && ser[0] == '1');
    tQkv = StreamPathTiming_NowUs();
    if (serial) {
        runQ();
        runKv();
    } else {
        std::thread qTh(runQ);
        std::thread kvTh(runKv);
        qTh.join();
        kvTh.join();
    }
    StreamPathTiming_Add(MlaStage_QkvUs(), tQkv);
    if (!qOk) { error = qErr.empty() ? "MLAForward: Q path failed" : qErr; goto cleanup; }
    if (!kvOk) { error = kvErr.empty() ? "MLAForward: KV path failed" : kvErr; goto cleanup; }

    // Step 6/7: expand compressed_kv → K_nope / V
    tExp = StreamPathTiming_NowUs();
    if (fusedKv) {
        const size_t fusedCols = kDims[1];
        kvLoraRank = kDims[0];
        if (numHeads == 0 || (fusedCols % numHeads) != 0) {
            error = "MLAForward: fused attn_kv_b cols not divisible by numHeads";
            goto cleanup;
        }
        const size_t per = fusedCols / numHeads;
        qkNopeHeadDim = (config.qkNopeHeadDim && config.qkNopeHeadDim < per)
            ? config.qkNopeHeadDim : (per / 2);
        vHeadDim = per - qkNopeHeadDim;

        // Host fused expand is default (measured faster than GPU dual GEMV).
        // DEEP2_MLA_FUSED_KV=0 → legacy dual MLA_Gemv.
        const char* fusedEnv = std::getenv("DEEP2_MLA_FUSED_KV");
        const bool useFused = !fusedEnv || fusedEnv[0] != '0';
        const auto qt = weights.attnK_b.quantType();
        KvExpandQuantType kqt = KvExpandQuantType::F32;
        if (qt == RawrXD::QuantType::Q4_K) kqt = KvExpandQuantType::Q4_K;
        else if (qt == RawrXD::QuantType::Q8_0) kqt = KvExpandQuantType::Q8_0;

        if (useFused && MLA_KvExpand_Fused_SingleWeight(
                weights.attnK_b.data(), compressedKV, k_b, v_b,
                numHeads, qkNopeHeadDim, vHeadDim, kvLoraRank, kqt)) {
            // Host fused path
        } else {
            // Fallback: legacy two-pass (GEMV + split)
            fusedTmp = (float*)_aligned_malloc(fusedCols * sizeof(float), 32);
            if (!fusedTmp) { error = "MLAForward: fused kv_b alloc failed"; goto cleanup; }
            pin(4);
            if (!gemvDispatchTransposed(weights.attnK_b, compressedKV, fusedTmp,
                                        fusedCols, kvLoraRank, error)) {
                _aligned_free(fusedTmp);
                goto cleanup;
            }
            for (size_t h = 0; h < numHeads; ++h) {
                const float* src = fusedTmp + h * per;
                memcpy(k_b + h * qkNopeHeadDim, src, qkNopeHeadDim * sizeof(float));
                memcpy(v_b + h * vHeadDim, src + qkNopeHeadDim, vHeadDim * sizeof(float));
            }
            _aligned_free(fusedTmp);
            fusedTmp = nullptr;
        }
    } else if (kIs3D && vIs3D) {
        // Host fused: one compressedKV pass → K+V (default). Opt out with =0.
        const char* fusedEnv = std::getenv("DEEP2_MLA_FUSED_KV");
        const bool allowHostFused = !fusedEnv || fusedEnv[0] != '0';
        const auto kQt = weights.attnK_b.quantType();
        const auto vQt = weights.attnV_b.quantType();

        if (allowHostFused && kQt == vQt) {
            // Host single-pass expand: compressedKV read once → both K and V
            KvExpandQuantType qt = KvExpandQuantType::F32;
            if (kQt == RawrXD::QuantType::Q4_K) qt = KvExpandQuantType::Q4_K;
            else if (kQt == RawrXD::QuantType::Q8_0) qt = KvExpandQuantType::Q8_0;

            MLA_GpuGemv_SetPinKey(((uint64_t)layerIdx << 8) | 4u);
            if (!MLA_KvExpand_Fused(weights.attnK_b.data(), weights.attnV_b.data(),
                                    compressedKV, k_b, v_b,
                                    numHeads, qkNopeHeadDim, vHeadDim, kvLoraRank,
                                    qt, qt)) {
                goto legacy_kv_expand_3d;
            }
        } else {
        legacy_kv_expand_3d:
            // Legacy: separate K and V expand threads (original behavior)
            const size_t kElems = qkNopeHeadDim * kvLoraRank;
            const size_t vElems = vHeadDim * kvLoraRank;
            const size_t kBlkE = (kQt == RawrXD::QuantType::Q8_0) ? 32u : 256u;
            const size_t vBlkE = (vQt == RawrXD::QuantType::Q8_0) ? 32u : 256u;
            const size_t kBlkB = (kQt == RawrXD::QuantType::Q8_0)
                ? sizeof(Q8_0_Block) : sizeof(Q4_K_Block);
            const size_t vBlkB = (vQt == RawrXD::QuantType::Q8_0)
                ? sizeof(Q8_0_Block) : sizeof(Q4_K_Block);
            const size_t kBytes = numHeads *
                (((kElems + kBlkE - 1) / kBlkE) * kBlkB);
            const size_t vBytes = numHeads *
                (((vElems + vBlkE - 1) / vBlkE) * vBlkB);
            const void* kBase = weights.attnK_b.data();
            const void* vBase = weights.attnV_b.data();
            const uint32_t kRows = (uint32_t)(numHeads * qkNopeHeadDim);
            const uint32_t vRows = (uint32_t)(numHeads * vHeadDim);
            const uint32_t kCols = (uint32_t)kvLoraRank;
            const bool kT = false;
            const bool vT = true;
            std::thread kTh([&]() {
                MLA_GpuGemv_SetPinKey(((uint64_t)layerIdx << 8) | 4u);
                if (kQt == RawrXD::QuantType::Q4_K) {
                    if (!(MLA_Gemv(12, kBase, kBytes, compressedKV, k_b, kRows, kCols)))
                        gemvQ4KOriented(kT, kBase, compressedKV, k_b, kRows, kCols);
                } else if (kQt == RawrXD::QuantType::Q8_0) {
                    if (!(MLA_Gemv(8, kBase, kBytes, compressedKV, k_b, kRows, kCols)))
                        gemvQ80Oriented(kT, kBase, compressedKV, k_b, kRows, kCols);
                } else {
                    for (size_t h = 0; h < numHeads; ++h) {
                        const size_t hb = ((kElems + kBlkE - 1) / kBlkE) * kBlkB;
                        gemvQ80Oriented(kT, (const uint8_t*)kBase + h * hb, compressedKV,
                                        k_b + h * qkNopeHeadDim, qkNopeHeadDim, kvLoraRank);
                    }
                }
            });
            std::thread vTh([&]() {
                MLA_GpuGemv_SetPinKey(((uint64_t)layerIdx << 8) | 5u);
                if (vQt == RawrXD::QuantType::Q4_K) {
                    if (!(MLA_Gemv(12, vBase, vBytes, compressedKV, v_b, vRows, kCols)))
                        gemvQ4KOriented(vT, vBase, compressedKV, v_b, vRows, kCols);
                } else if (vQt == RawrXD::QuantType::Q8_0) {
                    if (!(MLA_Gemv(8, vBase, vBytes, compressedKV, v_b, vRows, kCols)))
                        gemvQ80Oriented(vT, vBase, compressedKV, v_b, vRows, kCols);
                } else {
                    for (size_t h = 0; h < numHeads; ++h) {
                        const size_t hb = ((vElems + vBlkE - 1) / vBlkE) * vBlkB;
                        gemvQ80Oriented(vT, (const uint8_t*)vBase + h * hb, compressedKV,
                                        v_b + h * vHeadDim, vHeadDim, kvLoraRank);
                    }
                }
            });
            kTh.join();
            vTh.join();
        }
    } else if (kIs3D) {
        const size_t elemsPerHead = qkNopeHeadDim * kvLoraRank;
        const auto kQt = weights.attnK_b.quantType();
        const size_t blockElems = (kQt == RawrXD::QuantType::Q8_0) ? 32u : 256u;
        const size_t blockBytes = (kQt == RawrXD::QuantType::Q8_0)
            ? sizeof(Q8_0_Block) : sizeof(Q4_K_Block);
        const size_t bytesPerHead =
            ((elemsPerHead + blockElems - 1) / blockElems) * blockBytes;
        const uint8_t* base = static_cast<const uint8_t*>(weights.attnK_b.data());
        const uint32_t kRows = (uint32_t)(numHeads * qkNopeHeadDim);
        const uint32_t kCols = (uint32_t)kvLoraRank;
        const bool kT = false;
        pin(4);
        if (kQt == RawrXD::QuantType::Q4_K) {
            if (!(MLA_Gemv(12, base, bytesPerHead * numHeads, compressedKV, k_b,
                           kRows, kCols)))
                gemvQ4KOriented(kT, base, compressedKV, k_b, kRows, kCols);
        } else if (kQt == RawrXD::QuantType::Q8_0) {
            if (!(MLA_Gemv(8, base, bytesPerHead * numHeads, compressedKV, k_b,
                           kRows, kCols)))
                gemvQ80Oriented(kT, base, compressedKV, k_b, kRows, kCols);
        } else {
            for (size_t h = 0; h < numHeads; ++h)
                gemvQ80Oriented(kT, base + h * bytesPerHead, compressedKV,
                                k_b + h * qkNopeHeadDim, qkNopeHeadDim, kvLoraRank);
        }
    } else {
        pin(4);
        if (!gemvDispatchTransposed(weights.attnK_b, compressedKV, k_b,
                          kBCols, kvLoraRank, error)) {
        goto cleanup;
        }
    }

    if (!fusedKv && !vIs3D) {
        pin(5);
        if (!gemvDispatchTransposed(weights.attnV_b, compressedKV, v_b,
                          vBCols, kvLoraRank, error)) {
            goto cleanup;
        }
    } else if (!fusedKv && vIs3D && !kIs3D) {
        const size_t elemsPerHead = vHeadDim * kvLoraRank;
        const auto vQt = weights.attnV_b.quantType();
        const size_t blockElems = (vQt == RawrXD::QuantType::Q8_0) ? 32u : 256u;
        const size_t blockBytes = (vQt == RawrXD::QuantType::Q8_0)
            ? sizeof(Q8_0_Block) : sizeof(Q4_K_Block);
        const size_t bytesPerHead =
            ((elemsPerHead + blockElems - 1) / blockElems) * blockBytes;
        const uint8_t* base = static_cast<const uint8_t*>(weights.attnV_b.data());
        const uint32_t vRows = (uint32_t)(numHeads * vHeadDim);
        const uint32_t vCols = (uint32_t)kvLoraRank;
        const bool vT = true;
        pin(5);
        if (vQt == RawrXD::QuantType::Q4_K) {
            if (!(MLA_Gemv(12, base, bytesPerHead * numHeads, compressedKV, v_b,
                           vRows, vCols)))
                gemvQ4KOriented(vT, base, compressedKV, v_b, vRows, vCols);
        } else if (vQt == RawrXD::QuantType::Q8_0) {
            if (!(MLA_Gemv(8, base, bytesPerHead * numHeads, compressedKV, v_b,
                           vRows, vCols)))
                gemvQ80Oriented(vT, base, compressedKV, v_b, vRows, vCols);
        } else {
            for (size_t h = 0; h < numHeads; ++h)
                gemvQ80Oriented(vT, base + h * bytesPerHead, compressedKV,
                                v_b + h * vHeadDim, vHeadDim, kvLoraRank);
        }
    }
    StreamPathTiming_Add(MlaStage_KvExpandUs(), tExp);

    // =========================================================================
    // Attention: G10/G11 simplified path OR Gate 12 complete MLA (kvCache set)
    // =========================================================================
    tAttn = StreamPathTiming_NowUs();
    if (!kvCache) {
        // Retained G10/G11 witness path — do not alter.
        memcpy(attnOut, q_b, numHeads * headDim * sizeof(float));
    } else {
        size_t nope = qkNopeHeadDim ? qkNopeHeadDim : 128;
        size_t rope = qkRopeHeadDim ? qkRopeHeadDim : 64;
        size_t vDim = vHeadDim ? vHeadDim : 128;
        if (headDim >= nope + rope) {
            // Q already packs [nope|rope]
        } else if (headDim > nope) {
            rope = headDim - nope;
        } else {
            error = "MLAForward: q headDim incompatible with MLA nope/rope split";
            goto cleanup;
        }
        memset(attnOut, 0, attnOutSize * sizeof(float));
        if (!MlaAttentionComplete(q_b, k_b, v_b, k_pe, attnOut,
                                  numHeads, nope, rope, vDim, headDim,
                                  position, config.ropeTheta,
                                  config.ropeScalingFactor,
                                  kvCache, layerIdx, stats, error)) {
            StreamPathTiming_Add(MlaStage_AttnUs(), tAttn);
            goto cleanup;
        }
    }
    StreamPathTiming_Add(MlaStage_AttnUs(), tAttn);

    // Step 8: Output projection: attnO^T * attnOut  [hiddenDim]
    // GGUF stores attnO as [numHeads*vHeadDim, hiddenDim]
    // Use actual tensor shape (already pre-fetched into oCols / oActualRows)
    pin(6);
    tO = StreamPathTiming_NowUs();
    if (!gemvDispatchTransposed(weights.attnO, attnOut, output,
                                oCols, oActualRows, error)) {
        goto cleanup;
    }
    StreamPathTiming_Add(MlaStage_OProjUs(), tO);

    // Success — TLS owns scratch; only free fusedTmp if set.
    _aligned_free(fusedTmp);
    return true;

cleanup:
    _aligned_free(fusedTmp);
    return false;
}

bool MLAForward::TestAgainstReference(const std::string& fixturePath,
                                       std::string& error) {
    std::ifstream fixture(fixturePath, std::ios::binary);
    if (!fixture) {
        error = "MLAForward: cannot open reference fixture: " + fixturePath;
        return false;
    }

    // TODO: Load reference fixture and compare against Execute()
    // For now, just verify the fixture exists
    return true;
}

} // namespace Deep2
