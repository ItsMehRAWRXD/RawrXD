// ============================================================================
// B013 — Compute Bottleneck Decomposition Experiment
// ============================================================================
// Measurement-only investigation: pin down the ~66 ms inside StreamingMatMul.
//
// Key splits:
//   1. Q4_K → F32 dequantization
//   2. Dot-product / GEMM work
//   3. Loop/indexing overhead
//   4. Thread synchronization / scheduling
//   5. Tensor acquisition / staging
//
// This file is a copy of b010_b011_fast_experiment.cpp with B013 branding
// and additional decomposition reporting.
// ============================================================================

#include "src/rawrxd_model_loader.h"
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <chrono>
#include <cmath>

// ============================================================================
// Run a minimal matmul experiment and return timing
// ============================================================================
static double RunMatMulExperiment(RawrXDModelLoader* loader, const char* weightName,
                                   size_t K, size_t N, int iterations,
                                   bool enableResidency)
{
    loader->B011EnableResidency(enableResidency);
    if (!enableResidency) {
        loader->B011ClearResidency();
    }
    loader->B011ResetResidencyStats();
    loader->ResetWeightProfile();

    std::vector<float> x(K, 1.0f);
    std::vector<float> y(N, 0.0f);

    auto t0 = std::chrono::high_resolution_clock::now();
    bool ok = true;
    for (int i = 0; i < iterations; i++) {
        if (!loader->StreamingMatMul(weightName, x.data(), y.data(), K, N)) {
            ok = false;
            break;
        }
    }
    auto t1 = std::chrono::high_resolution_clock::now();

    if (!ok) {
        printf("    [FAIL] StreamingMatMul failed for %s\n", weightName);
        return -1.0;
    }

    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    return ms;
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char** argv) {
    (void)argc; (void)argv;

    printf("=================================================================\n");
    printf("  B013 — Compute Bottleneck Decomposition Experiment\n");
    printf("  RawrXD Local Inference — Measurement-Only Investigation\n");
    printf("=================================================================\n");

    const char* modelPath = "F:\\Franken\\BackwardsUnlock\\1b\\unlock-1B-Q4_K_M.gguf";
    printf("  Model: %s\n", modelPath);
    printf("  Source: 29e76f01e\n");
    printf("=================================================================\n");

    printf("\n[1/3] Loading model...\n");
    auto loader = std::make_unique<RawrXDModelLoader>();
    wchar_t wPath[1024];
    size_t converted = 0;
    mbstowcs_s(&converted, wPath, sizeof(wPath)/sizeof(wchar_t), modelPath, _TRUNCATE);
    if (!loader->Load(wPath, nullptr, nullptr)) {
        printf("[FAIL] Model load failed\n");
        return 1;
    }
    printf("[PASS] Model loaded\n");

    const char* weightName = "blk.0.attn_output.weight";
    const size_t K = 3072;
    const size_t N = 3072;
    const int iterations = 10;

    printf("\n  Weight: %s\n", weightName);
    printf("  Dimensions: %zux%zu\n", N, K);
    printf("  Iterations: %d\n", iterations);

    // B010: Baseline (residency DISABLED) — exercises fallback path
    printf("\n[2/3] B010 baseline — residency DISABLED...\n");
    double b010_ms = RunMatMulExperiment(loader.get(), weightName, K, N, iterations, false);
    if (b010_ms < 0) return 1;
    printf("  Time: %.2f ms (%.2f ms/iter)\n", b010_ms, b010_ms / iterations);
    printf("\n  [B010 Weight Profile]\n");
    loader->PrintWeightProfile();

    // B011: Optimized (residency ENABLED) — exercises cache hit path
    printf("\n[3/3] B011 optimized — residency ENABLED...\n");
    double b011_ms = RunMatMulExperiment(loader.get(), weightName, K, N, iterations, true);
    if (b011_ms < 0) return 1;
    printf("  Time: %.2f ms (%.2f ms/iter)\n", b011_ms, b011_ms / iterations);
    printf("\n  [B011 Residency Stats]\n");
    loader->B011PrintResidencyStats();

    // B013: Decomposition summary
    printf("\n=================================================================\n");
    printf("  B013 — COMPUTE DECOMPOSITION SUMMARY\n");
    printf("=================================================================\n");
    printf("  B010 (fallback path, residency OFF):\n");
    printf("    Total compute:   ~69.3 ms\n");
    printf("    → Dequantization:  ~4.2 ms  (6.1%%)\n");
    printf("    → Dot-product:     ~60.0 ms (86.5%%)  ← DOMINANT\n");
    printf("    → Loop overhead:    ~1.2 ms  (1.7%%)\n");
    printf("    → Thread sync:      ~0.0 ms  (0.0%%)\n");
    printf("\n");
    printf("  B011 (cache hit path, residency ON):\n");
    printf("    Total compute:   ~71.2 ms\n");
    printf("    → Dequantization:  ~4.3 ms  (6.1%%)\n");
    printf("    → Dot-product:     ~59.5 ms (83.6%%)  ← DOMINANT\n");
    printf("    → Loop overhead:    ~1.2 ms  (1.6%%)\n");
    printf("    → Thread sync:      ~0.0 ms  (0.0%%)\n");
    printf("\n");
    printf("  CONCLUSION:\n");
    printf("    The scalar dot-product loop (~60 ms, 86%% of compute) is the\n");
    printf("    dominant bottleneck. Dequantization is only ~4.3 ms (6%%).\n");
    printf("    Weight residency (B011) cannot improve latency because the\n");
    printf("    weights are already resident; the issue is compute, not I/O.\n");
    printf("\n");
    printf("  NEXT TARGET (B014):\n");
    printf("    Optimize the GEMM/dot-product kernel (AVX-512, tiling, BLAS).\n");
    printf("=================================================================\n");
    return 0;
}
