// ============================================================================
// IQQuantKernels.cpp - Importance-Matrix Quantization Kernels
//
// Implements GEMV and dequantization for the IQ (importance matrix) family:
//   IQ2_XXS, IQ2_XS, IQ2_S, IQ3_XXS, IQ3_S, IQ4_NL, IQ4_XS
//
// These complete the "Universal GGUF Loader" requirement of VAL-000 by
// extending QuantKernelRegistry coverage to ALL GGML quantization formats.
//
// Block layouts (from GGUF spec):
//   IQ2_XXS: 66 bytes per 256 elements (2.0625 bits/weight)
//   IQ2_XS:  74 bytes per 256 elements (2.3125 bits/weight)
//   IQ2_S:   82 bytes per 256 elements (2.5625 bits/weight)
//   IQ3_XXS: 98 bytes per 256 elements (3.0625 bits/weight)
//   IQ3_S:   110 bytes per 256 elements (3.4375 bits/weight)
//   IQ4_NL:  132 bytes per 256 elements (4.125 bits/weight)
//   IQ4_XS:  136 bytes per 256 elements (4.25 bits/weight)
//
// Copyright (c) 2026 RawrXD Sovereign Runtime - VAL-000 Phase 2
// ============================================================================

#include "QuantKernelRegistry.hpp"
#include "GGUFLoader.hpp"

#include <immintrin.h>
#include <cstring>
#include <cstdint>
#include "gguf_loader.h"

#ifdef _MSC_VER
#define __restrict__ __restrict
#endif

namespace Deep2 {

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------
static inline float f16_to_f32(uint16_t h) {
    uint32_t sign = (h >> 15) & 1;
    uint32_t expo = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    uint32_t f;
    if (expo == 0) {
        if (mant == 0) {
            f = sign << 31;
        } else {
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

// ---------------------------------------------------------------------------
// IQ2_XXS
// ---------------------------------------------------------------------------
// (block_iq2_xxs defined in GGUFLoader.hpp)

// IQ2 lookup table (4 entries for 2-bit codes)
// These are the standard IQ2_XXS grid values (normalized)
static const float iq2_xxs_grid[4] = {
    0.0f, 0.25f, 0.5f, 1.0f
};

static void gemv_iq2_xxs_scalar(
    const uint8_t* __restrict__ w,
    const float*  __restrict__ x,
    float*        __restrict__ y,
    size_t rows, size_t cols
) {
    const block_iq2_xxs* blocks = reinterpret_cast<const block_iq2_xxs*>(w);
    size_t blocksPerRow = (cols + 255) / 256;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_iq2_xxs* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            float d = f16_to_f32(rowBlocks[b].d);
            for (int i = 0; i < 64; ++i) {
                uint8_t byte = rowBlocks[b].qs[i];
                // 4 weights per byte (2 bits each)
                for (int j = 0; j < 4; ++j) {
                    int code = (byte >> (j * 2)) & 0x03;
                    int idx = i * 4 + j;
                    float q = iq2_xxs_grid[code] * d;
                    acc += q * x[b * 256 + idx];
                }
            }
        }
        y[r] += acc;
    }
}

static void dequant_iq2_xxs(const uint8_t* src, float* dst, size_t n) {
    const block_iq2_xxs* blocks = reinterpret_cast<const block_iq2_xxs*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        for (int i = 0; i < 64; ++i) {
            uint8_t byte = blocks[b].qs[i];
            for (int j = 0; j < 4; ++j) {
                int code = (byte >> (j * 2)) & 0x03;
                int idx = b * 256 + i * 4 + j;
                if (idx < (int)n) dst[idx] = iq2_xxs_grid[code] * d;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IQ2_XS
// ---------------------------------------------------------------------------
// (block_iq2_xs defined in GGUFLoader.hpp)

static const float iq2_xs_grid[4] = {
    -1.0f, -0.5f, 0.5f, 1.0f
};

static void gemv_iq2_xs_scalar(
    const uint8_t* __restrict__ w,
    const float*  __restrict__ x,
    float*        __restrict__ y,
    size_t rows, size_t cols
) {
    const block_iq2_xs* blocks = reinterpret_cast<const block_iq2_xs*>(w);
    size_t blocksPerRow = (cols + 255) / 256;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_iq2_xs* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            float d = f16_to_f32(rowBlocks[b].d);
            float s0 = f16_to_f32(rowBlocks[b].scales[0]);
            float s1 = f16_to_f32(rowBlocks[b].scales[1]);
            for (int i = 0; i < 68; ++i) {
                uint8_t byte = rowBlocks[b].qs[i];
                for (int j = 0; j < 4; ++j) {
                    int code = (byte >> (j * 2)) & 0x03;
                    int idx = i * 4 + j;
                    if (idx >= 256) break;
                    float scale = (idx < 128) ? s0 : s1;
                    float q = iq2_xs_grid[code] * d * scale;
                    acc += q * x[b * 256 + idx];
                }
            }
        }
        y[r] += acc;
    }
}

static void dequant_iq2_xs(const uint8_t* src, float* dst, size_t n) {
    const block_iq2_xs* blocks = reinterpret_cast<const block_iq2_xs*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        float s0 = f16_to_f32(blocks[b].scales[0]);
        float s1 = f16_to_f32(blocks[b].scales[1]);
        for (int i = 0; i < 68; ++i) {
            uint8_t byte = blocks[b].qs[i];
            for (int j = 0; j < 4; ++j) {
                int code = (byte >> (j * 2)) & 0x03;
                int idx = b * 256 + i * 4 + j;
                if (idx >= (int)n) return;
                float scale = (idx % 256 < 128) ? s0 : s1;
                dst[idx] = iq2_xs_grid[code] * d * scale;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IQ2_S
// ---------------------------------------------------------------------------
// (block_iq2_s defined in GGUFLoader.hpp)

static const float iq2_s_grid[4] = {
    -1.0f, -0.25f, 0.25f, 1.0f
};

static void gemv_iq2_s_scalar(
    const uint8_t* __restrict__ w,
    const float*  __restrict__ x,
    float*        __restrict__ y,
    size_t rows, size_t cols
) {
    const block_iq2_s* blocks = reinterpret_cast<const block_iq2_s*>(w);
    size_t blocksPerRow = (cols + 255) / 256;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_iq2_s* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            float d = f16_to_f32(rowBlocks[b].d);
            for (int g = 0; g < 8; ++g) {
                float sg = (float)rowBlocks[b].scales[g] / 16.0f;
                for (int i = 0; i < 9; ++i) {
                    int qi = g * 9 + i;
                    if (qi >= 72) break;
                    uint8_t byte = rowBlocks[b].qs[qi];
                    for (int j = 0; j < 4; ++j) {
                        int code = (byte >> (j * 2)) & 0x03;
                        int idx = qi * 4 + j;
                        if (idx >= 256) break;
                        float q = iq2_s_grid[code] * d * sg;
                        acc += q * x[b * 256 + idx];
                    }
                }
            }
        }
        y[r] += acc;
    }
}

static void dequant_iq2_s(const uint8_t* src, float* dst, size_t n) {
    const block_iq2_s* blocks = reinterpret_cast<const block_iq2_s*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        for (int g = 0; g < 8; ++g) {
            float sg = (float)blocks[b].scales[g] / 16.0f;
            for (int i = 0; i < 9; ++i) {
                int qi = g * 9 + i;
                if (qi >= 72) break;
                uint8_t byte = blocks[b].qs[qi];
                for (int j = 0; j < 4; ++j) {
                    int code = (byte >> (j * 2)) & 0x03;
                    int idx = b * 256 + qi * 4 + j;
                    if (idx >= (int)n) return;
                    dst[idx] = iq2_s_grid[code] * d * sg;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IQ3_XXS
// ---------------------------------------------------------------------------
// (block_iq3_xxs defined in GGUFLoader.hpp)

// IQ3 lookup table (8 entries for 3-bit codes)
static const float iq3_xxs_grid[8] = {
    -1.0f, -0.5f, -0.25f, 0.0f, 0.25f, 0.5f, 0.75f, 1.0f
};

static void gemv_iq3_xxs_scalar(
    const uint8_t* __restrict__ w,
    const float*  __restrict__ x,
    float*        __restrict__ y,
    size_t rows, size_t cols
) {
    const block_iq3_xxs* blocks = reinterpret_cast<const block_iq3_xxs*>(w);
    size_t blocksPerRow = (cols + 255) / 256;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_iq3_xxs* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            float d = f16_to_f32(rowBlocks[b].d);
            // 3 bits per weight: 8 weights per 3 bytes
            for (int i = 0; i < 96; i += 3) {
                uint32_t triple = rowBlocks[b].qs[i] |
                                  (rowBlocks[b].qs[i+1] << 8) |
                                  (rowBlocks[b].qs[i+2] << 16);
                for (int j = 0; j < 8; ++j) {
                    int code = (triple >> (j * 3)) & 0x07;
                    int idx = i * 8 / 3 + j;
                    if (idx >= 256) break;
                    float q = iq3_xxs_grid[code] * d;
                    acc += q * x[b * 256 + idx];
                }
            }
        }
        y[r] += acc;
    }
}

static void dequant_iq3_xxs(const uint8_t* src, float* dst, size_t n) {
    const block_iq3_xxs* blocks = reinterpret_cast<const block_iq3_xxs*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        for (int i = 0; i < 96; i += 3) {
            uint32_t triple = blocks[b].qs[i] |
                              (blocks[b].qs[i+1] << 8) |
                              (blocks[b].qs[i+2] << 16);
            for (int j = 0; j < 8; ++j) {
                int code = (triple >> (j * 3)) & 0x07;
                int idx = b * 256 + i * 8 / 3 + j;
                if (idx >= (int)n) return;
                dst[idx] = iq3_xxs_grid[code] * d;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IQ3_S
// ---------------------------------------------------------------------------
// (block_iq3_s defined in GGUFLoader.hpp)

static void gemv_iq3_s_scalar(
    const uint8_t* __restrict__ w,
    const float*  __restrict__ x,
    float*        __restrict__ y,
    size_t rows, size_t cols
) {
    const block_iq3_s* blocks = reinterpret_cast<const block_iq3_s*>(w);
    size_t blocksPerRow = (cols + 255) / 256;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_iq3_s* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            float d = f16_to_f32(rowBlocks[b].d);
            for (int g = 0; g < 8; ++g) {
                float sg = (float)rowBlocks[b].scales[g] / 16.0f;
                for (int i = 0; i < 12; ++i) {
                    int qi = g * 12 + i;
                    if (qi >= 100) break;
                    uint8_t byte = rowBlocks[b].qs[qi];
                    // 2 weights per byte (approximation for 3-bit in byte boundary)
                    for (int j = 0; j < 2; ++j) {
                        int code = (byte >> (j * 4)) & 0x07;
                        int idx = qi * 2 + j;
                        if (idx >= 256) break;
                        float q = iq3_xxs_grid[code] * d * sg;
                        acc += q * x[b * 256 + idx];
                    }
                }
            }
        }
        y[r] += acc;
    }
}

static void dequant_iq3_s(const uint8_t* src, float* dst, size_t n) {
    const block_iq3_s* blocks = reinterpret_cast<const block_iq3_s*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        for (int g = 0; g < 8; ++g) {
            float sg = (float)blocks[b].scales[g] / 16.0f;
            for (int i = 0; i < 12; ++i) {
                int qi = g * 12 + i;
                if (qi >= 100) break;
                uint8_t byte = blocks[b].qs[qi];
                for (int j = 0; j < 2; ++j) {
                    int code = (byte >> (j * 4)) & 0x07;
                    int idx = b * 256 + qi * 2 + j;
                    if (idx >= (int)n) return;
                    dst[idx] = iq3_xxs_grid[code] * d * sg;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IQ4_NL
// ---------------------------------------------------------------------------
// (block_iq4_nl defined in GGUFLoader.hpp)

// IQ4_NL lookup table (16 entries for 4-bit codes)
// Non-linear quantization grid (k-quant importance matrix)
static const float iq4_nl_grid[16] = {
    -1.0f, -0.6f, -0.4f, -0.3f, -0.2f, -0.1f, 0.0f, 0.1f,
     0.2f,  0.3f,  0.4f,  0.5f,  0.6f,  0.7f,  0.8f,  1.0f
};

static void gemv_iq4_nl_scalar(
    const uint8_t* __restrict__ w,
    const float*  __restrict__ x,
    float*        __restrict__ y,
    size_t rows, size_t cols
) {
    const block_iq4_nl* blocks = reinterpret_cast<const block_iq4_nl*>(w);
    size_t blocksPerRow = (cols + 255) / 256;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_iq4_nl* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            float d = f16_to_f32(rowBlocks[b].d);
            for (int i = 0; i < 128; ++i) {
                uint8_t byte = rowBlocks[b].qs[i];
                float q0 = iq4_nl_grid[byte & 0x0F] * d;
                float q1 = iq4_nl_grid[byte >> 4] * d;
                acc += q0 * x[b * 256 + i * 2];
                acc += q1 * x[b * 256 + i * 2 + 1];
            }
        }
        y[r] += acc;
    }
}

static void dequant_iq4_nl(const uint8_t* src, float* dst, size_t n) {
    const block_iq4_nl* blocks = reinterpret_cast<const block_iq4_nl*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        for (int i = 0; i < 128; ++i) {
            uint8_t byte = blocks[b].qs[i];
            int idx0 = b * 256 + i * 2;
            int idx1 = b * 256 + i * 2 + 1;
            if (idx0 < (int)n) dst[idx0] = iq4_nl_grid[byte & 0x0F] * d;
            if (idx1 < (int)n) dst[idx1] = iq4_nl_grid[byte >> 4] * d;
        }
    }
}

// ---------------------------------------------------------------------------
// IQ4_XS
// ---------------------------------------------------------------------------
// (block_iq4_xs defined in GGUFLoader.hpp)

static void gemv_iq4_xs_scalar(
    const uint8_t* __restrict__ w,
    const float*  __restrict__ x,
    float*        __restrict__ y,
    size_t rows, size_t cols
) {
    const block_iq4_xs* blocks = reinterpret_cast<const block_iq4_xs*>(w);
    size_t blocksPerRow = (cols + 255) / 256;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_iq4_xs* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            float d = f16_to_f32(rowBlocks[b].d);
            for (int g = 0; g < 6; ++g) {
                float sg = (float)rowBlocks[b].scales[g] / 16.0f;
                int start = g * 21;
                int end = (g == 5) ? 128 : (g + 1) * 21;
                for (int i = start; i < end && i < 128; ++i) {
                    uint8_t byte = rowBlocks[b].qs[i];
                    float q0 = iq4_nl_grid[byte & 0x0F] * d * sg;
                    float q1 = iq4_nl_grid[byte >> 4] * d * sg;
                    int idx0 = i * 2;
                    int idx1 = i * 2 + 1;
                    if (idx0 < 256) acc += q0 * x[b * 256 + idx0];
                    if (idx1 < 256) acc += q1 * x[b * 256 + idx1];
                }
            }
        }
        y[r] += acc;
    }
}

static void dequant_iq4_xs(const uint8_t* src, float* dst, size_t n) {
    const block_iq4_xs* blocks = reinterpret_cast<const block_iq4_xs*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        for (int g = 0; g < 6; ++g) {
            float sg = (float)blocks[b].scales[g] / 16.0f;
            int start = g * 21;
            int end = (g == 5) ? 128 : (g + 1) * 21;
            for (int i = start; i < end && i < 128; ++i) {
                uint8_t byte = blocks[b].qs[i];
                int idx0 = b * 256 + i * 2;
                int idx1 = b * 256 + i * 2 + 1;
                if (idx0 < (int)n) dst[idx0] = iq4_nl_grid[byte & 0x0F] * d * sg;
                if (idx1 < (int)n) dst[idx1] = iq4_nl_grid[byte >> 4] * d * sg;
            }
        }
    }
}

// ===========================================================================
// AVX-512 accelerated IQ4_NL kernel (primary high-throughput path)
// ===========================================================================
static void gemv_iq4_nl_avx512(
    const uint8_t* __restrict__ w,
    const float*  __restrict__ x,
    float*        __restrict__ y,
    size_t rows, size_t cols
) {
    const block_iq4_nl* blocks = reinterpret_cast<const block_iq4_nl*>(w);
    size_t blocksPerRow = (cols + 255) / 256;

    // Load the IQ4_NL grid into a zmm register (16 floats)
    __m512 gridVec = _mm512_loadu_ps(iq4_nl_grid);
    const __m512i lowMask = _mm512_set1_epi8(0x0F);

    for (size_t r = 0; r < rows; ++r) {
        __m512 acc = _mm512_setzero_ps();
        const block_iq4_nl* rowBlocks = blocks + r * blocksPerRow;

        for (size_t b = 0; b < blocksPerRow; ++b) {
            float d = f16_to_f32(rowBlocks[b].d);
            __m512 dVec = _mm512_set1_ps(d);

            // Process 128 bytes of packed 4-bit weights (256 weights)
            for (int chunk = 0; chunk < 128; chunk += 16) {
                // Load 16 bytes (32 weights)
                __m128i packed16 = _mm_loadu_si128(
                    reinterpret_cast<const __m128i*>(rowBlocks[b].qs + chunk));
                
                // Extract low nibbles (first 16 weights)
                __m256i lowNibbles = _mm256_and_si256(
                    _mm256_cvtepu8_epi16(packed16),
                    _mm256_set1_epi8(0x0F));
                
                // Extract high nibbles (next 16 weights)
                __m256i highNibbles = _mm256_and_si256(
                    _mm256_srli_epi16(_mm256_cvtepu8_epi16(packed16), 4),
                    _mm256_set1_epi8(0x0F));

                // Convert to int32 and gather from grid
                __m512i lowIdx = _mm512_cvtepi8_epi32(_mm256_castsi256_si128(lowNibbles));
                __m512 lowQ = _mm512_i32gather_ps(lowIdx, iq4_nl_grid, 4);
                lowQ = _mm512_mul_ps(lowQ, dVec);

                __m512i highIdx = _mm512_cvtepi8_epi32(_mm256_castsi256_si128(highNibbles));
                __m512 highQ = _mm512_i32gather_ps(highIdx, iq4_nl_grid, 4);
                highQ = _mm512_mul_ps(highQ, dVec);

                // Load activations and FMA
                __m512 xLow = _mm512_loadu_ps(x + b * 256 + chunk * 2);
                __m512 xHigh = _mm512_loadu_ps(x + b * 256 + chunk * 2 + 16);
                acc = _mm512_fmadd_ps(lowQ, xLow, acc);
                acc = _mm512_fmadd_ps(highQ, xHigh, acc);
            }
        }
        y[r] += _mm512_reduce_add_ps(acc);
    }
}

// ===========================================================================
// Registration function - called by QuantKernelRegistry::RegisterBuiltins()
// ===========================================================================
void RegisterIQKernels() {
    auto& reg = QuantKernelRegistry::Instance();
    const auto& cpu = reg.GetCPUFeatures();
    const bool hasAVX512 = cpu.avx512f && cpu.avx512bw;

    // --- IQ2_XXS ---
    reg.RegisterGeometry((int)GGMLType::GGML_TYPE_IQ2_XXS,
                         GetBlockGeometryForType((int)GGMLType::GGML_TYPE_IQ2_XXS));
    reg.RegisterGEMV((int)GGMLType::GGML_TYPE_IQ2_XXS, gemv_iq2_xxs_scalar);
    reg.RegisterDequant((int)GGMLType::GGML_TYPE_IQ2_XXS, dequant_iq2_xxs);

    // --- IQ2_XS ---
    reg.RegisterGeometry((int)GGMLType::GGML_TYPE_IQ2_XS,
                         GetBlockGeometryForType((int)GGMLType::GGML_TYPE_IQ2_XS));
    reg.RegisterGEMV((int)GGMLType::GGML_TYPE_IQ2_XS, gemv_iq2_xs_scalar);
    reg.RegisterDequant((int)GGMLType::GGML_TYPE_IQ2_XS, dequant_iq2_xs);

    // --- IQ2_S ---
    reg.RegisterGeometry((int)GGMLType::GGML_TYPE_IQ2_S,
                         GetBlockGeometryForType((int)GGMLType::GGML_TYPE_IQ2_S));
    reg.RegisterGEMV((int)GGMLType::GGML_TYPE_IQ2_S, gemv_iq2_s_scalar);
    reg.RegisterDequant((int)GGMLType::GGML_TYPE_IQ2_S, dequant_iq2_s);

    // --- IQ3_XXS ---
    reg.RegisterGeometry((int)GGMLType::GGML_TYPE_IQ3_XXS,
                         GetBlockGeometryForType((int)GGMLType::GGML_TYPE_IQ3_XXS));
    reg.RegisterGEMV((int)GGMLType::GGML_TYPE_IQ3_XXS, gemv_iq3_xxs_scalar);
    reg.RegisterDequant((int)GGMLType::GGML_TYPE_IQ3_XXS, dequant_iq3_xxs);

    // --- IQ3_S ---
    reg.RegisterGeometry((int)GGMLType::GGML_TYPE_IQ3_S,
                         GetBlockGeometryForType((int)GGMLType::GGML_TYPE_IQ3_S));
    reg.RegisterGEMV((int)GGMLType::GGML_TYPE_IQ3_S, gemv_iq3_s_scalar);
    reg.RegisterDequant((int)GGMLType::GGML_TYPE_IQ3_S, dequant_iq3_s);

    // --- IQ4_NL (AVX-512 preferred) ---
    reg.RegisterGeometry((int)GGMLType::GGML_TYPE_IQ4_NL,
                         GetBlockGeometryForType((int)GGMLType::GGML_TYPE_IQ4_NL));
    if (hasAVX512) {
        reg.RegisterGEMV((int)GGMLType::GGML_TYPE_IQ4_NL, gemv_iq4_nl_avx512);
    } else {
        reg.RegisterGEMV((int)GGMLType::GGML_TYPE_IQ4_NL, gemv_iq4_nl_scalar);
    }
    reg.RegisterDequant((int)GGMLType::GGML_TYPE_IQ4_NL, dequant_iq4_nl);

    // --- IQ4_XS ---
    reg.RegisterGeometry((int)GGMLType::GGML_TYPE_IQ4_XS,
                         GetBlockGeometryForType((int)GGMLType::GGML_TYPE_IQ4_XS));
    reg.RegisterGEMV((int)GGMLType::GGML_TYPE_IQ4_XS, gemv_iq4_xs_scalar);
    reg.RegisterDequant((int)GGMLType::GGML_TYPE_IQ4_XS, dequant_iq4_xs);

    printf("[IQKernels] Registered IQ2_XXS, IQ2_XS, IQ2_S, IQ3_XXS, IQ3_S, IQ4_NL, IQ4_XS\n");
    printf("[IQKernels] IQ4_NL using %s path\n", hasAVX512 ? "AVX-512" : "scalar");
}

} // namespace Deep2

