// ============================================================================
// Batch21_Registry_Dispatch_Test.cpp
// Minimal test: load real GGUF Q4_K tensor → dispatch via QuantKernelRegistry
// → verify kernel executes → print Batch 21 counters.
// ============================================================================

#include "GGUFLoader.hpp"
#include "QuantKernelRegistry.hpp"
#include <cstdio>
#include <cstring>
#include <cmath>
#include <vector>
#include <string>

using namespace Deep2;

int main(int argc, char** argv) {
    const char* modelPath = argc > 1 ? argv[1]
        : "G:\\OllamaModels\\blobs\\sha256-9be227448d319e6a7acca8056b71bf7d9a2c6b2811986e6658a9dedc208d0ada";

    printf("=================================================================\n");
    printf(" Batch 21: Registry Dispatch Test\n");
    printf("=================================================================\n");
    printf("Model: %s\n\n", modelPath);

    // --- Step 1: Load GGUF metadata ---
    printf("[Step 1] Loading GGUF metadata...\n");
    GGUFLoadOptions options;
    options.loadTensors = true;
    options.mmap = true;

    GGUFLoadResult result = GGUFLoader::Load(modelPath, options);
    if (!result.success) {
        printf("[FAIL] GGUF load failed: %s\n", result.error);
        return 1;
    }
    printf("[PASS] GGUF loaded: %zu tensors, %.1f MB total\n",
           result.tensors.size(), result.totalSize / (1024.0 * 1024.0));

    // --- Step 2: Find a Q4_K tensor ---
    printf("\n[Step 2] Finding Q4_K tensor...\n");
    const TensorInfo* targetTensor = nullptr;
    for (const auto& t : result.tensors) {
        if (t.dimensions.size() >= 2 && t.dimensions[0] > 0 && t.dimensions[1] > 0) {
            if (t.type == GGMLType::GGML_TYPE_Q4_K) {
                targetTensor = &t;
                break;
            }
        }
    }
    if (!targetTensor) {
        printf("[FAIL] No Q4_K tensor found\n");
        return 1;
    }
    printf("[PASS] Selected: %s  dims=%llu x %llu  size=%zu bytes\n",
           targetTensor->name.c_str(),
           (unsigned long long)targetTensor->dimensions[0],
           (unsigned long long)targetTensor->dimensions[1],
           targetTensor->size);

    // --- Step 3: Initialize registry ---
    printf("\n[Step 3] Initializing QuantKernelRegistry...\n");
    auto& reg = QuantKernelRegistry::Instance();
    reg.Initialize();
    printf("[PASS] Registry initialized: %zu kernels registered\n", reg.GetRegisteredCount());

    // --- Step 4: Resolve kernel for Q4_K ---
    printf("\n[Step 4] Resolving Q4_K kernel...\n");
    auto kernel = reg.GetGEMV(static_cast<int>(GGMLType::GGML_TYPE_Q4_K));
    auto geom = reg.GetGeometry(static_cast<int>(GGMLType::GGML_TYPE_Q4_K));
    if (!kernel || geom.blockSize == 0) {
        printf("[FAIL] No Q4_K kernel registered\n");
        reg.GetBatch21Counters().registryMisses.fetch_add(1, std::memory_order_relaxed);
        return 1;
    }
    reg.GetBatch21Counters().registryHits.fetch_add(1, std::memory_order_relaxed);
    printf("[PASS] Kernel resolved: blockSize=%zu elemsPerBlock=%zu\n",
           geom.blockSize, geom.elemsPerBlock);

    // --- Step 5: Prepare input/output buffers ---
    size_t rows = static_cast<size_t>(targetTensor->dimensions[0]);
    size_t cols = static_cast<size_t>(targetTensor->dimensions[1]);
    std::vector<float> input(cols, 1.0f);
    std::vector<float> output(rows, 0.0f);

    // --- Step 6: Dispatch via registry ---
    printf("\n[Step 5] Dispatching GEMV via registry...\n");
    size_t blocksPerRow = (cols + geom.elemsPerBlock - 1) / geom.elemsPerBlock;
    size_t rowBytes = blocksPerRow * geom.blockSize;
    const uint8_t* weights = (const uint8_t*)targetTensor->data;

    reg.GetBatch21Counters().kernelInvocations.fetch_add(1, std::memory_order_relaxed);
    kernel(weights, input.data(), output.data(), rows, cols);

    // Validate output
    bool finite = true;
    double sum = 0.0;
    for (size_t i = 0; i < rows; ++i) {
        if (!std::isfinite(output[i])) { finite = false; break; }
        sum += output[i];
    }
    printf("  Output: sum=%.4f | finite=%s\n", sum, finite ? "YES" : "NO");
    if (!finite) {
        printf("[FAIL] Kernel produced non-finite output\n");
        return 1;
    }
    printf("[PASS] Kernel executed successfully\n");

    // --- Step 7: Print Batch 21 telemetry ---
    printf("\n[Step 6] Batch 21 telemetry:\n");
    reg.PrintBatch21Report();

    printf("\n=================================================================\n");
    printf(" PASS: Batch 21 registry dispatch verified on real Q4_K data\n");
    printf("=================================================================\n");
    return 0;
}
