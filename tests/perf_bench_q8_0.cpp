// Comparative benchmark: Q8_0 scalar vs AVX-512
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <chrono>
#include <vector>
#include <algorithm>
#include "deep2/QuantKernelRegistry.hpp"

using namespace Deep2;

static uint16_t f32_to_f16(float f) {
    uint32_t bits = *reinterpret_cast<uint32_t*>(&f);
    uint32_t sign = (bits >> 16) & 0x8000;
    int32_t exp = ((bits >> 23) & 0xFF) - 127 + 15;
    if (exp < 0) exp = 0;
    if (exp > 31) exp = 31;
    uint32_t e = (uint32_t)exp << 10;
    uint32_t m = (bits >> 13) & 0x03FF;
    return (uint16_t)(sign | e | m);
}

static inline float f16_to_f32(uint16_t h) {
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

// Standalone scalar Q8_0 GEMV (reference implementation)
static void gemv_q8_0_scalar_ref(
    const uint8_t* w, const float* x, float* y,
    size_t rows, size_t cols
) {
    constexpr size_t kBlk = 34;
    const size_t blocksPerRow = (cols + 31) / 32;
    const size_t rowBytes = blocksPerRow * kBlk;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const uint8_t* row = w + r * rowBytes;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const auto* blk = reinterpret_cast<const block_q8_0*>(row + b * kBlk);
            float d = f16_to_f32(blk->d);
            const size_t base = b * 32;
            const size_t n = (base + 32 <= cols) ? 32u : (cols - base);
            for (size_t i = 0; i < n; ++i)
                acc += d * (float)blk->qs[i] * x[base + i];
        }
        y[r] += acc;
    }
}

int main() {
    auto& reg = QuantKernelRegistry::Instance();
    reg.Initialize();

    const size_t cols = 2048;   // 64 Q8_0 blocks
    const size_t rows = 4096;
    const size_t blocksPerRow = (cols + 31) / 32;
    constexpr size_t kBlk = 34;

    struct block_q8_0 { uint16_t d; int8_t qs[32]; };

    std::vector<uint8_t> wbuf(rows * blocksPerRow * kBlk, 0);
    std::vector<float> x(cols);
    std::vector<float> y_scalar(rows, 0.0f);
    std::vector<float> y_simd(rows, 0.0f);

    // Build test data
    for (size_t r = 0; r < rows; ++r) {
        for (size_t b = 0; b < blocksPerRow; ++b) {
            block_q8_0* blk = reinterpret_cast<block_q8_0*>(
                &wbuf[(r * blocksPerRow + b) * kBlk]);
            blk->d = f32_to_f16(1.0f + (float)b * 0.1f);
            for (int i = 0; i < 32; ++i)
                blk->qs[i] = (int8_t)((r + b + i) % 256 - 128);
        }
    }
    for (size_t i = 0; i < cols; ++i) x[i] = (float)(i % 100) / 100.0f;

    GEMVKernelFn simd_kernel = reg.GetGEMV((int)GGMLType::GGML_TYPE_Q8_0);
    printf("=== Q8_0 Performance Benchmark ===\n");
    printf("rows=%zu cols=%zu blocksPerRow=%zu\n\n", rows, cols, blocksPerRow);

    // Verify correctness
    gemv_q8_0_scalar_ref(wbuf.data(), x.data(), y_scalar.data(), rows, cols);
    std::fill(y_simd.begin(), y_simd.end(), 0.0f);
    simd_kernel(wbuf.data(), x.data(), y_simd.data(), rows, cols);

    float maxDiff = 0.0f;
    for (size_t r = 0; r < rows; ++r)
        maxDiff = std::max(maxDiff, fabsf(y_scalar[r] - y_simd[r]));
    printf("Scalar vs SIMD max diff: %e\n\n", maxDiff);

    // Benchmark scalar
    const int iterations = 20;
    auto t0 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        std::fill(y_scalar.begin(), y_scalar.end(), 0.0f);
        gemv_q8_0_scalar_ref(wbuf.data(), x.data(), y_scalar.data(), rows, cols);
    }
    auto t1 = std::chrono::high_resolution_clock::now();
    auto us_scalar = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    double gops_scalar = (2.0 * cols * rows * iterations) / (1e9 * (double)us_scalar / 1e6);
    printf("Scalar:   %d us total, %.3f ms/iter, %.2f GOPS\n",
           (int)us_scalar, (double)us_scalar / (iterations * 1000.0), gops_scalar);

    // Benchmark SIMD (AVX-512)
    t0 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        std::fill(y_simd.begin(), y_simd.end(), 0.0f);
        simd_kernel(wbuf.data(), x.data(), y_simd.data(), rows, cols);
    }
    t1 = std::chrono::high_resolution_clock::now();
    auto us_simd = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    double gops_simd = (2.0 * cols * rows * iterations) / (1e9 * (double)us_simd / 1e6);
    printf("AVX-512:  %d us total, %.3f ms/iter, %.2f GOPS\n",
           (int)us_simd, (double)us_simd / (iterations * 1000.0), gops_simd);

    printf("\nSpeedup: %.2fx  (%.2f -> %.2f GOPS)\n",
           gops_simd / gops_scalar, gops_scalar, gops_simd);

    return 0;
}
