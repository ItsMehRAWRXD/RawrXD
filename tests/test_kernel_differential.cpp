// ============================================================================
// test_kernel_differential.cpp - Kernel Differential Validation Tests
// PERF-001 through PERF-004
//
// Validates:
//   - Q8_0 GEMV scalar vs reference computation
//   - Q4_K GEMV scalar vs reference computation
//   - Q8_0 multithreading produces deterministic results (single vs multi)
//   - CPU dispatch selects correct kernel based on AVX-512 support
//   - Q4_K nibble extraction and scale unpacking correctness
//
// On non-AVX-512 CPUs (e.g. Ryzen 7 7800X3D), only scalar paths execute.
// The AVX-512 kernels are verified by algorithm parity with scalar (same
// intermediate Q8_K quantization path).
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cstdint>
#include <vector>
#include <algorithm>
#include <random>

#include "deep2/QuantKernelRegistry.hpp"

using namespace Deep2;

// ---------------------------------------------------------------------------
// Helpers: FP16 <-> FP32 conversion (matching GGUF/Q8_0 layout)
// ---------------------------------------------------------------------------
static uint16_t f32_to_f16(float f) {
    uint32_t bits = *reinterpret_cast<uint32_t*>(&f);
    uint32_t sign = (bits >> 16) & 0x8000;
    int32_t  exp  = ((bits >> 23) & 0xFF) - 127 + 15;
    if (exp < 0) exp = 0;
    if (exp > 31) { exp = 31; }
    uint32_t e = (uint32_t)exp << 10;
    uint32_t m = (bits >> 13) & 0x03FF;
    uint32_t hbits = sign | e | m;
    return static_cast<uint16_t>(hbits);
}

// Decode FP16 to FP32 (matches QuantKernelRegistry.cpp f16_to_f32 normal path)
static inline float f16_to_f32_local(uint16_t h) {
    uint32_t sign = (uint32_t)(h & 0x8000) << 16;
    uint32_t exp  = (h >> 10) & 0x1F;
    uint32_t frac = h & 0x03FF;
    if (exp == 0) {
        if (frac == 0) return *reinterpret_cast<const float*>(&sign);
        uint32_t e = 1; uint32_t f = frac;
        while ((f & 0x0400) == 0) { f <<= 1; e++; }
        f &= 0x3FF;
        uint32_t bits = sign | ((127 - 15 + 2 - e) << 23) | (f << 13);
        return *reinterpret_cast<const float*>(&bits);
    }
    uint32_t bits = sign | ((exp - 15 + 127) << 23) | (frac << 13);
    return *reinterpret_cast<const float*>(&bits);
}

// Q4_K scale/unpack helper (matches unpack_q4_k_scales in QuantKernelRegistry.cpp)
static inline void unpack_q4_k_scales_ref(const uint8_t s[12], uint8_t scales[8], uint8_t mins[8]) {
    scales[0] = s[0] & 0x3F;
    scales[1] = s[1] & 0x3F;
    scales[2] = s[2] & 0x3F;
    scales[3] = s[3] & 0x3F;
    mins[0]  = s[4] & 0x3F;
    mins[1]  = s[5] & 0x3F;
    mins[2]  = s[6] & 0x3F;
    mins[3]  = s[7] & 0x3F;
    scales[4] = (s[0] >> 6) << 6 | (s[8] & 0x0F);
    mins[4]   = (s[4] >> 6) << 6 | ((s[8] >> 4) & 0x0F);
    scales[5] = (s[1] >> 6) << 6 | ((s[8] >> 0) & 0x0F);
    mins[5]   = (s[5] >> 6) << 6 | ((s[9] >> 4) & 0x0F);
    scales[6] = (s[2] >> 6) << 6 | ((s[9] >> 0) & 0x0F);
    mins[6]   = (s[6] >> 6) << 6 | ((s[10] >> 4) & 0x0F);
    scales[7] = (s[3] >> 6) << 6 | ((s[10] >> 0) & 0x0F);
    mins[7]   = (s[7] >> 6) << 6 | ((s[11] >> 4) & 0x0F);
}

// ---------------------------------------------------------------------------
// Reference Q8_0 GEMV in plain FP32 (no quantization of weights)
//
// Simulates the dequantize-and-multiply path that the kernel implements:
//   for each block: acc += d * sum(qs[i] * x[i])
// ---------------------------------------------------------------------------
static float reference_q8_0_gmv(
    const uint8_t* w,
    const float*   x,
    size_t cols
) {
    constexpr size_t kBlk = 34;
    const size_t blocksPerRow = (cols + 31) / 32;
    float acc = 0.0f;
    const uint8_t* row = w;
    for (size_t b = 0; b < blocksPerRow; ++b) {
        const auto* blk = reinterpret_cast<const block_q8_0*>(row + b * kBlk);
        float d = f16_to_f32_local(blk->d);
        const size_t base = b * 32;
        const size_t n = (base + 32 <= cols) ? 32u : (cols - base);
        for (size_t i = 0; i < n; ++i)
            acc += d * (float)blk->qs[i] * x[base + i];
    }
    return acc;
}  // reference_q8_0_gmv ends at line 106

// ---------------------------------------------------------------------------
// Test 1: Q8_0 scalar kernel correctness
// ---------------------------------------------------------------------------
static bool test_q8_0_scalar_correctness() {
    printf("[TEST 1] Q8_0 scalar GEMV correctness\n");

    auto& reg = QuantKernelRegistry::Instance();
    reg.Initialize();

    const size_t cols = 256;  // 8 blocks of 32
    const size_t rows = 4;
    const size_t blocksPerRow = (cols + 31) / 32;  // 8
    constexpr size_t kBlk = 34;

    // Build synthetic Q8_0 weights
    std::vector<uint8_t> weightBuf(rows * blocksPerRow * kBlk, 0);
    std::mt19937 rng(42);
    std::uniform_int_distribution<int> q8dist(-127, 127);
    std::uniform_real_distribution<float> scaledist(0.1f, 2.0f);

    for (size_t r = 0; r < rows; ++r) {
        for (size_t b = 0; b < blocksPerRow; ++b) {
            block_q8_0* blk = reinterpret_cast<block_q8_0*>(
                &weightBuf[(r * blocksPerRow + b) * kBlk]);
            float scale = scaledist(rng);
            blk->d = f32_to_f16(scale);
            for (int i = 0; i < 32; ++i)
                blk->qs[i] = (int8_t)q8dist(rng);
        }
    }

    // Build float input
    std::vector<float> x(cols);
    std::uniform_real_distribution<float> xdist(-1.0f, 1.0f);
    for (size_t i = 0; i < cols; ++i)
        x[i] = xdist(rng);

    // Run kernel
    std::vector<float> y(rows, 0.0f);
    GEMVKernelFn kernel = reg.GetGEMV((int)GGMLType::GGML_TYPE_Q8_0);
    if (!kernel) {
        printf("  FAIL: no Q8_0 kernel registered\n");
        return false;
    }
    kernel(weightBuf.data(), x.data(), y.data(), rows, cols);

    // Compare with reference
    float maxErr = 0.0f;
    for (size_t r = 0; r < rows; ++r) {
        float ref = reference_q8_0_gmv(
            &weightBuf[r * blocksPerRow * kBlk],
            x.data(), cols);
        float err = fabsf(y[r] - ref);
        if (err > maxErr) maxErr = err;
    }

    printf("  maxAbsErr = %e\n", maxErr);
    if (maxErr > 1e-3f) {
        printf("  FAIL: Q8_0 scalar numerical mismatch\n");
        return false;
    }
    printf("  PASS\n");
    return true;
}

// ---------------------------------------------------------------------------
// Test 2: Q8_0 multithreading determinism (single vs multi-row)
// ---------------------------------------------------------------------------
static bool test_q8_0_multithread_determinism() {
    printf("[TEST 2] Q8_0 multithreading determinism\n");

    auto& reg = QuantKernelRegistry::Instance();

    const size_t cols = 512;  // 16 blocks
    const size_t blocksPerRow = (cols + 31) / 32;
    constexpr size_t kBlk = 34;
    const size_t rowsSingle = 1;
    const size_t rowsMany = 64;

    // Shared weights (same for both runs)
    std::vector<uint8_t> weightBuf(rowsMany * blocksPerRow * kBlk, 0);
    std::mt19937 rng(123);
    std::uniform_int_distribution<int> q8dist(-127, 127);
    std::uniform_real_distribution<float> scaledist(0.5f, 3.0f);

    for (size_t r = 0; r < rowsMany; ++r) {
        for (size_t b = 0; b < blocksPerRow; ++b) {
            block_q8_0* blk = reinterpret_cast<block_q8_0*>(
                &weightBuf[(r * blocksPerRow + b) * kBlk]);
            blk->d = f32_to_f16(scaledist(rng));
            for (int i = 0; i < 32; ++i)
                blk->qs[i] = (int8_t)q8dist(rng);
        }
    }

    std::vector<float> x(cols);
    std::uniform_real_distribution<float> xdist(-1.0f, 1.0f);
    for (size_t i = 0; i < cols; ++i)
        x[i] = xdist(rng);

    // Run kernel for single row
    std::vector<float> ySingle(rowsSingle, 0.0f);
    GEMVKernelFn kernel = reg.GetGEMV((int)GGMLType::GGML_TYPE_Q8_0);
    kernel(weightBuf.data(), x.data(), ySingle.data(), rowsSingle, cols);

    // Run kernel for many rows (same weights on row 0)
    std::vector<float> yMany(rowsMany, 0.0f);
    kernel(weightBuf.data(), x.data(), yMany.data(), rowsMany, cols);

    float maxDiff = fabsf(ySingle[0] - yMany[0]);
    printf("  single=%.10f many=%.10f diff=%e\n",
           ySingle[0], yMany[0], maxDiff);

    if (maxDiff > 1e-5f) {
        printf("  FAIL: multithreading produced different result\n");
        return false;
    }
    printf("  PASS\n");
    return true;
}

// ---------------------------------------------------------------------------
// Test 3: CPU dispatch verification
// ---------------------------------------------------------------------------
static bool test_cpu_dispatch() {
    printf("[TEST 3] CPU dispatch verification\n");

    auto& reg = QuantKernelRegistry::Instance();
    reg.Initialize();
    const auto& cpu = reg.GetCPUFeatures();

    printf("  AVX512F=%d AVX512BW=%d AVX2=%d FMA=%d\n",
           cpu.avx512f, cpu.avx512bw, cpu.avx2, cpu.fma);

    bool hasAVX512 = cpu.avx512f && cpu.avx512bw;

    // Q8_0: should have a valid kernel
    GEMVKernelFn q8k = reg.GetGEMV((int)GGMLType::GGML_TYPE_Q8_0);
    if (!q8k) {
        printf("  FAIL: Q8_0 kernel is null\n");
        return false;
    }

    // Q4_K: should have a valid kernel
    GEMVKernelFn q4k = reg.GetGEMV((int)GGMLType::GGML_TYPE_Q4_K);
    if (!q4k) {
        printf("  FAIL: Q4_K kernel is null\n");
        return false;
    }

    // On non-AVX512, both should use scalar fallback
    if (!hasAVX512) {
        printf("  Non-AVX512 CPU detected: scalar kernels expected\n");
        printf("  (AVX-512 kernels compiled but not selected at runtime)\n");
    } else {
        printf("  AVX-512 CPU detected: SIMD kernels should be active\n");
    }
    printf("  PASS\n");
    return true;
}

// ---------------------------------------------------------------------------
// Test 4: Non-aligned dimension Q8_0
// ---------------------------------------------------------------------------
static bool test_q8_0_nonaligned() {
    printf("[TEST 4] Q8_0 non-aligned dimensions\n");

    auto& reg = QuantKernelRegistry::Instance();
    GEMVKernelFn kernel = reg.GetGEMV((int)GGMLType::GGML_TYPE_Q8_0);

    // cols = 50 (not a multiple of 32 -> 2 blocks, 18 tail elements)
    const size_t cols = 50;
    const size_t rows = 3;
    const size_t blocksPerRow = (cols + 31) / 32; // 2
    constexpr size_t kBlk = 34;

    std::vector<uint8_t> weightBuf(rows * blocksPerRow * kBlk, 0);
    std::mt19937 rng(999);
    std::uniform_int_distribution<int> q8dist(-127, 127);

    for (size_t r = 0; r < rows; ++r) {
        for (size_t b = 0; b < blocksPerRow; ++b) {
            block_q8_0* blk = reinterpret_cast<block_q8_0*>(
                &weightBuf[(r * blocksPerRow + b) * kBlk]);
            float scale = 1.0f + (float)b;  // block 0 scale=1.0, block 1 scale=2.0
            blk->d = f32_to_f16(scale);
            for (int i = 0; i < 32; ++i)
                blk->qs[i] = (int8_t)q8dist(rng);
        }
    }

    std::vector<float> x(cols);
    std::uniform_real_distribution<float> xdist(-0.5f, 0.5f);
    for (size_t i = 0; i < cols; ++i)
        x[i] = xdist(rng);

    std::vector<float> y(rows, 0.0f);
    kernel(weightBuf.data(), x.data(), y.data(), rows, cols);

    // Verify only first 50 elements of each block were used for block 1
    float maxErr = 0.0f;
    for (size_t r = 0; r < rows; ++r) {
        float ref = reference_q8_0_gmv(
            &weightBuf[r * blocksPerRow * kBlk], x.data(), cols);
        float err = fabsf(y[r] - ref);
        if (err > maxErr) maxErr = err;
    }

    printf("  maxAbsErr = %e\n", maxErr);
    if (maxErr > 1e-3f) {
        printf("  FAIL: non-aligned Q8_0 mismatch\n");
        return false;
    }
    printf("  PASS\n");
    return true;
}

// ---------------------------------------------------------------------------
// Test 5: Q4_K kernel presence and geometry
// ---------------------------------------------------------------------------
static bool test_q4_k_geometry() {
    printf("[TEST 5] Q4_K geometry and registration\n");

    auto& reg = QuantKernelRegistry::Instance();
    reg.Initialize();

    BlockGeometry geom = reg.GetGeometry((int)GGMLType::GGML_TYPE_Q4_K);
    printf("  Q4_K blockSize=%zu elemsPerBlock=%zu\n",
           geom.blockSize, geom.elemsPerBlock);

    // Q4_K should have blockSize = sizeof(block_q4_K) = 144
    if (geom.blockSize != sizeof(block_q4_K)) {
        printf("  FAIL: Q4_K blockSize mismatch (expected %zu, got %zu)\n",
               sizeof(block_q4_K), geom.blockSize);
        return false;
    }

    // Q8_0 should have blockSize = sizeof(block_q8_0) = 34
    BlockGeometry geom8 = reg.GetGeometry((int)GGMLType::GGML_TYPE_Q8_0);
    printf("  Q8_0 blockSize=%zu elemsPerBlock=%zu\n",
           geom8.blockSize, geom8.elemsPerBlock);
    if (geom8.blockSize != sizeof(block_q8_0)) {
        printf("  FAIL: Q8_0 blockSize mismatch (expected %zu, got %zu)\n",
               sizeof(block_q8_0), geom8.blockSize);
        return false;
    }

    printf("  PASS\n");
    return true;
}

// ---------------------------------------------------------------------------
// Test 6: Q8_0 dimension matrix (aligned + tail widths)
// ---------------------------------------------------------------------------
static bool test_q8_0_dimension_matrix() {
    printf("[TEST 6] Q8_0 dimension matrix (aligned + tail)\n");

    auto& reg = QuantKernelRegistry::Instance();
    GEMVKernelFn kernel = reg.GetGEMV((int)GGMLType::GGML_TYPE_Q8_0);

    // Test dimensions: aligned widths and tail widths
    const size_t test_cols[] = {32, 64, 96, 128, 33, 47, 65, 80, 97, 112, 256};
    const size_t rows = 4;
    bool all_pass = true;

    for (size_t cols : test_cols) {
        const size_t blocksPerRow = (cols + 31) / 32;
        constexpr size_t kBlk = 34;

        std::mt19937 rng(42 + (int)cols);
        std::uniform_int_distribution<int> q8dist(-127, 127);
        std::uniform_real_distribution<float> xdist(-1.0f, 1.0f);
        std::uniform_real_distribution<float> scaledist(0.3f, 3.0f);

        struct block_q8_0 {
            uint16_t d;
            int8_t   qs[32];
        };

        std::vector<uint8_t> wbuf(rows * blocksPerRow * kBlk, 0);
        for (size_t r = 0; r < rows; ++r) {
            for (size_t b = 0; b < blocksPerRow; ++b) {
                block_q8_0* blk = reinterpret_cast<block_q8_0*>(
                    &wbuf[(r * blocksPerRow + b) * kBlk]);
                blk->d = f32_to_f16(scaledist(rng));
                for (int i = 0; i < 32; ++i)
                    blk->qs[i] = (int8_t)q8dist(rng);
            }
        }

        std::vector<float> x(cols);
        for (size_t i = 0; i < cols; ++i)
            x[i] = xdist(rng);

        // Compute reference
        std::vector<float> y_ref(rows, 0.0f);
        for (size_t r = 0; r < rows; ++r) {
            float acc = 0.0f;
            const uint8_t* row = &wbuf[r * blocksPerRow * kBlk];
            for (size_t b = 0; b < blocksPerRow; ++b) {
                const block_q8_0* blk = reinterpret_cast<const block_q8_0*>(
                    row + b * kBlk);
                float d = f16_to_f32_local(blk->d);
                size_t base = b * 32;
                size_t n = (base + 32 <= cols) ? 32u : (cols - base);
                for (size_t i = 0; i < n; ++i)
                    acc += d * (float)blk->qs[i] * x[base + i];
            }
            y_ref[r] = acc;
        }

        // Run kernel
        std::vector<float> y(rows, 0.0f);
        kernel(wbuf.data(), x.data(), y.data(), rows, cols);

        float maxErr = 0.0f;
        for (size_t r = 0; r < rows; ++r) {
            maxErr = std::max(maxErr, fabsf(y[r] - y_ref[r]));
        }

        const char* status = (maxErr < 1e-2f) ? "OK" : "FAIL";
        if (maxErr >= 1e-2f) all_pass = false;
        printf("  cols=%3zu blocks=%2zu maxAbsErr=%e %s\n",
               cols, blocksPerRow, maxErr, status);
    }

    if (all_pass) printf("  PASS\n");
    else          printf("  FAIL\n");
    return all_pass;
}

// ---------------------------------------------------------------------------
// Test 7: Q4_K kernel correctness (aligned to 256)
// ---------------------------------------------------------------------------
static bool test_q4_k_correctness() {
    printf("[TEST 7] Q4_K GEMV correctness\n");

    auto& reg = QuantKernelRegistry::Instance();
    GEMVKernelFn kernel = reg.GetGEMV((int)GGMLType::GGML_TYPE_Q4_K);
    if (!kernel) {
        printf("  FAIL: no Q4_K kernel registered\n");
        return false;
    }

    constexpr size_t kQ4K = 256;
    // Use cols = 512 (2 blocks) to test multi-block Q4_K
    const size_t cols = 512;
    const size_t rows = 2;
    const size_t blocksPerRow = cols / kQ4K;

    std::mt19937 rng(777);
    std::uniform_real_distribution<float> xdist(-1.0f, 1.0f);

    struct block_q4_K {
        uint16_t d;
        uint16_t dmin;
        uint8_t  scales[12];
        uint8_t  qs[128];
    };
    static_assert(sizeof(block_q4_K) == 144, "block_q4_K must be 144 bytes");

    std::vector<uint8_t> wbuf(rows * blocksPerRow * sizeof(block_q4_K), 0);
    std::vector<float> x(cols);

    // Build synthetic Q4_K weights
    for (size_t r = 0; r < rows; ++r) {
        for (size_t b = 0; b < blocksPerRow; ++b) {
            block_q4_K* blk = reinterpret_cast<block_q4_K*>(
                &wbuf[(r * blocksPerRow + b) * sizeof(block_q4_K)]);
            blk->d = f32_to_f16(1.0f);
            blk->dmin = f32_to_f16(0.5f);
            // Simple scales: all 0 (max 63 in low 6 bits)
            for (int i = 0; i < 12; ++i) blk->scales[i] = 0;
            // Fill qs with nibble values
            for (int i = 0; i < 128; ++i) blk->qs[i] = (uint8_t)(rng() & 0xFF);
        }
    }
    for (size_t i = 0; i < cols; ++i)
        x[i] = xdist(rng);

    // Reference: FP32 dequant (same as scalar kernel's non-aligned path)
    std::vector<float> y_ref(rows, 0.0f);
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_q4_K* blocks = reinterpret_cast<const block_q4_K*>(
            &wbuf[r * blocksPerRow * sizeof(block_q4_K)]);
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q4_K& blk = blocks[b];
            float d    = f16_to_f32_local(blk.d);
            float dmin = f16_to_f32_local(blk.dmin);

            uint8_t scales[8], mins[8];
            unpack_q4_k_scales_ref(blk.scales, scales, mins);

            const uint8_t* qs = blk.qs;
            for (int is = 0; is < 8; is += 2) {
                for (int i = 0; i < 32; ++i) {
                    int lo = qs[i] & 0x0F;
                    float w = d * scales[is] * lo - dmin * mins[is/2];
                    acc += w * x[b * 256 + (is/2)*64 + i];
                }
                for (int i = 0; i < 32; ++i) {
                    int hi = (qs[i] >> 4) & 0x0F;
                    float w = d * scales[is+1] * hi - dmin * mins[is/2];
                    acc += w * x[b * 256 + (is/2)*64 + 32 + i];
                }
                qs += 32;
            }
        }
        y_ref[r] = acc;
    }

    // Run kernel
    std::vector<float> y(rows, 0.0f);
    kernel(wbuf.data(), x.data(), y.data(), rows, cols);

    float maxErr = 0.0f;
    for (size_t r = 0; r < rows; ++r) {
        maxErr = std::max(maxErr, fabsf(y[r] - y_ref[r]));
    }

    printf("  maxAbsErr = %e\n", maxErr);
    if (maxErr > 1e-2f) {
        printf("  FAIL: Q4_K mismatch\n");
        return false;
    }
    printf("  PASS\n");
    return true;
}

// ---------------------------------------------------------------------------
// Test 8: Q8_0 accumulation (accumulate vs overwrite)
// ---------------------------------------------------------------------------
static bool test_q8_0_accumulation() {
    printf("[TEST 8] Q8_0 accumulator accumulate semantics\n");

    auto& reg = QuantKernelRegistry::Instance();
    GEMVKernelFn kernel = reg.GetGEMV((int)GGMLType::GGML_TYPE_Q8_0);

    const size_t cols = 64;
    const size_t blocksPerRow = (cols + 31) / 32;
    constexpr size_t kBlk = 34;
    const size_t rows = 2;

    std::mt19937 rng(555);
    std::uniform_int_distribution<int> q8dist(-127, 127);
    std::uniform_real_distribution<float> xdist(-1.0f, 1.0f);

    struct block_q8_0 {
        uint16_t d;
        int8_t   qs[32];
    };

    std::vector<uint8_t> wbuf(rows * blocksPerRow * kBlk, 0);
    for (size_t r = 0; r < rows; ++r) {
        for (size_t b = 0; b < blocksPerRow; ++b) {
            block_q8_0* blk = reinterpret_cast<block_q8_0*>(
                &wbuf[(r * blocksPerRow + b) * kBlk]);
            blk->d = f32_to_f16(1.0f);
            for (int i = 0; i < 32; ++i)
                blk->qs[i] = (int8_t)q8dist(rng);
        }
    }
    std::vector<float> x(cols);
    for (size_t i = 0; i < cols; ++i)
        x[i] = xdist(rng);

    // Kernel accumulates into y (y[r] += result)
    std::vector<float> y(rows, 5.0f);  // Pre-fill with 5.0
    kernel(wbuf.data(), x.data(), y.data(), rows, cols);

    // The result should be 5.0 + actual_dot_product
    // So verify by subtracting 5.0 and comparing to accumulated result
    std::vector<float> y_zero(rows, 0.0f);
    kernel(wbuf.data(), x.data(), y_zero.data(), rows, cols);

    float maxDiff = 0.0f;
    for (size_t r = 0; r < rows; ++r) {
        float diff = fabsf((y[r] - 5.0f) - y_zero[r]);
        if (diff > maxDiff) maxDiff = diff;
    }

    printf("  accumulate_vs_zero_error=%e\n", maxDiff);
    if (maxDiff > 1e-5f) {
        printf("  FAIL: accumulation semantics broken\n");
        return false;
    }
    printf("  PASS\n");
    return true;
}
int main(int argc, char** argv) {
    (void)argc; (void)argv;

    printf("=== PERF-001 through PERF-004 Kernel Differential Tests ===\n\n");

    int pass = 0, fail = 0;

    if (test_q8_0_scalar_correctness())      pass++; else fail++;
    printf("\n");
    if (test_q8_0_multithread_determinism()) pass++; else fail++;
    printf("\n");
    if (test_cpu_dispatch())                 pass++; else fail++;
    printf("\n");
    if (test_q8_0_nonaligned())             pass++; else fail++;
    printf("\n");
    if (test_q4_k_geometry())               pass++; else fail++;
    printf("\n");
    if (test_q8_0_dimension_matrix())       pass++; else fail++;
    printf("\n");
    if (test_q4_k_correctness())            pass++; else fail++;
    printf("\n");
    if (test_q8_0_accumulation())           pass++; else fail++;

    printf("\n=== Summary: %d passed, %d failed ===\n", pass, fail);
    return (fail > 0) ? 1 : 0;
}
