// ============================================================================
// B010 / B011 — Fast Weight Residency Experiment
// ============================================================================
// Minimal controlled experiment: directly exercise StreamingMatMul
// with residency OFF then ON, measuring acquisition cost delta.
//
// This avoids the full inference pipeline (~30s prefill) and focuses
// on the specific question: does weight residency eliminate redundant
// map/unmap overhead for repeated tensor access?
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
    // Configure residency
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
    printf("  B010 / B011 — Fast Weight Residency Experiment\n");
    printf("  RawrXD Local Inference — Controlled Experiment\n");
    printf("=================================================================\n");

    const char* modelPath = "F:\\Franken\\BackwardsUnlock\\1b\\unlock-1B-Q4_K_M.gguf";
    printf("  Model: %s\n", modelPath);
    printf("  Source: 29e76f01e\n");
    printf("=================================================================\n");

    // Load model
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

    // Use a representative weight tensor
    // blk.0.attn_output.weight: 3072 × 3072, Q4_K (type 12)
    const char* weightName = "blk.0.attn_output.weight";
    const size_t K = 3072;
    const size_t N = 3072;
    const int iterations = 10;

    printf("\n  Weight: %s\n", weightName);
    printf("  Dimensions: %zux%zu\n", N, K);
    printf("  Iterations: %d\n", iterations);

    // B010: Baseline (residency DISABLED)
    printf("\n[2/3] B010 baseline — residency DISABLED...\n");
    double b010_ms = RunMatMulExperiment(loader.get(), weightName, K, N, iterations, false);
    if (b010_ms < 0) return 1;
    printf("  Time: %.2f ms (%.2f ms/iter)\n", b010_ms, b010_ms / iterations);

    // Print B010 weight profile
    printf("\n  [B010 Weight Profile]\n");
    loader->PrintWeightProfile();

    // B011: Optimized (residency ENABLED)
    printf("\n[3/3] B011 optimized — residency ENABLED...\n");
    double b011_ms = RunMatMulExperiment(loader.get(), weightName, K, N, iterations, true);
    if (b011_ms < 0) return 1;
    printf("  Time: %.2f ms (%.2f ms/iter)\n", b011_ms, b011_ms / iterations);

    // Print B011 residency stats
    printf("\n  [B011 Residency Stats]\n");
    loader->B011PrintResidencyStats();

    // Summary
    printf("\n=================================================================\n");
    printf("  EXPERIMENT SUMMARY\n");
    printf("=================================================================\n");
    printf("  B010 (residency OFF): %.2f ms\n", b010_ms);
    printf("  B011 (residency ON):  %.2f ms\n", b011_ms);

    if (b010_ms > 0 && b011_ms > 0) {
        double speedup = b010_ms / b011_ms;
        double pct_change = ((b011_ms - b010_ms) / b010_ms) * 100.0;
        printf("  Speedup: %.2fx\n", speedup);
        printf("  Change: %+.1f%%\n", pct_change);

        if (pct_change < -5.0) {
            printf("\n  STATUS: B011 PRODUCES MEASURABLE SPEEDUP\n");
            printf("  Residency caching eliminated redundant acquisition cost.\n");
        } else if (pct_change > 5.0) {
            printf("\n  STATUS: B011 REGRESSED PERFORMANCE\n");
            printf("  Residency caching overhead exceeded benefit.\n");
        } else {
            printf("\n  STATUS: B011 NEUTRAL\n");
            printf("  Residency caching did not materially change latency.\n");
            printf("  Dominant bottleneck likely lies elsewhere (compute/dequant).\n");
        }
    }

    printf("=================================================================\n");
    return 0;
}
