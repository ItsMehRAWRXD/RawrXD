// ============================================================================
// vulkan_gemv_isolated_test.cpp — Minimal standalone Vulkan GEMV validation
// Tests DispatchGEMV() with synthetic FP32 data, no GGUF, no transformer.
// ============================================================================
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <cstring>

// Include the production VulkanCompute header
#include "vulkan_compute.h"

static bool NearlyEqual(float a, float b, float absTol, float relTol) {
    float diff = std::fabs(a - b);
    if (diff <= absTol) return true;
    float maxVal = std::max(std::fabs(a), std::fabs(b));
    return diff <= relTol * maxVal;
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("============================================================\n");
    printf("  Vulkan GEMV Isolated Test\n");
    printf("============================================================\n\n");

    // --- 1. Create and initialize VulkanCompute ---
    CPUInference::VulkanCompute compute;
    printf("[1/5] Initializing VulkanCompute...\n");
    if (!compute.Initialize()) {
        printf("      VulkanCompute::Initialize() returned FALSE.\n");
        printf("      Likely: no Vulkan runtime or no GPU found.\n");
        printf("      This is expected on systems without Vulkan.\n");
        printf("\nRESULT: SKIPPED (no Vulkan runtime)\n");
        return 0; // Not a failure — just no Vulkan available
    }
    printf("      VulkanCompute initialized OK.\n");

    CPUInference::VulkanDeviceInfo info = compute.GetDeviceInfo();
    printf("      Device: %s (vendor=0x%04X)\n", info.device_name.c_str(), info.vendor_id);

    // --- 2. Synthetic GEMV problem ---
    const uint32_t rows = 64;
    const uint32_t cols = 64;
    std::vector<float> weights(rows * cols);
    std::vector<float> input(cols);
    std::vector<float> outputGpu(rows, 0.0f);
    std::vector<float> outputCpu(rows, 0.0f);

    // Fill with deterministic pattern
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t c = 0; c < cols; ++c) {
            weights[r * cols + c] = float((r * 7 + c * 13) % 100) / 10.0f;
        }
    }
    for (uint32_t c = 0; c < cols; ++c) {
        input[c] = float((c * 3 + 11) % 50) / 5.0f;
    }

    // --- 3. CPU reference GEMV ---
    printf("[2/5] Computing CPU reference GEMV (%u x %u)...\n", rows, cols);
    for (uint32_t r = 0; r < rows; ++r) {
        float sum = 0.0f;
        for (uint32_t c = 0; c < cols; ++c) {
            sum += weights[r * cols + c] * input[c];
        }
        outputCpu[r] = sum;
    }
    printf("      CPU reference complete.\n");

    // --- 4. GPU GEMV via DispatchGEMV ---
    printf("[3/5] Dispatching GPU GEMV via VulkanCompute::DispatchGEMV...\n");
    bool ok = compute.DispatchGEMV(weights.data(), input.data(), outputGpu.data(), rows, cols);
    if (!ok) {
        printf("      DispatchGEMV() returned FALSE.\n");
        printf("\nRESULT: FAIL (GPU dispatch failed)\n");
        return 1;
    }
    printf("      GPU dispatch complete.\n");

    // --- 5. Validate ---
    printf("[4/5] Validating GPU vs CPU...\n");
    int failCount = 0;
    float maxAbsErr = 0.0f;
    float maxRelErr = 0.0f;
    for (uint32_t r = 0; r < rows; ++r) {
        float absErr = std::fabs(outputGpu[r] - outputCpu[r]);
        float relErr = absErr / (std::fabs(outputCpu[r]) + 1e-6f);
        if (absErr > maxAbsErr) maxAbsErr = absErr;
        if (relErr > maxRelErr) maxRelErr = relErr;
        if (!NearlyEqual(outputGpu[r], outputCpu[r], 1e-3f, 1e-3f)) {
            if (failCount < 5) {
                printf("      MISMATCH row=%u: GPU=%.6f CPU=%.6f absErr=%.6e\n",
                       r, outputGpu[r], outputCpu[r], absErr);
            }
            ++failCount;
        }
    }

    if (failCount == 0) {
        printf("      All %u rows match (maxAbsErr=%.6e, maxRelErr=%.6e).\n",
               rows, maxAbsErr, maxRelErr);
        printf("\nRESULT: PASS\n");
    } else {
        printf("      %d/%u rows mismatched (maxAbsErr=%.6e, maxRelErr=%.6e).\n",
               failCount, rows, maxAbsErr, maxRelErr);
        printf("\nRESULT: FAIL (numerical mismatch)\n");
        return 1;
    }

    // --- 6. Cleanup ---
    printf("[5/5] Cleaning up...\n");
    compute.Cleanup();
    printf("      Done.\n");
    return 0;
}
