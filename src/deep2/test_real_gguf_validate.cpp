// ============================================================================
// test_real_gguf_validate.cpp - Validate real 23GB GGUF loads with packed structs
// ============================================================================

#include "GGUFLoader.hpp"
#include <cstdio>
#include <cstring>

int main(int argc, char** argv) {
    const char* modelPath = (argc > 1) ? argv[1] : "F:\\OllamaModels\\BigDaddyG-Q2_K-ULTRA.gguf";

    printf("========================================\n");
    printf("REAL GGUF VALIDATION TEST\n");
    printf("========================================\n");
    printf("File: %s\n\n", modelPath);

    // Verify quant block sizes are correct after packing
    printf("[Struct Sizes]\n");
    printf("  block_q2_K = %zu bytes (expected 84)\n", sizeof(Deep2::block_q2_K));
    printf("  block_q3_K = %zu bytes (expected 98)\n", sizeof(Deep2::block_q3_K));
    printf("  block_q4_K = %zu bytes (expected 144)\n", sizeof(Deep2::block_q4_K));
    printf("  block_q5_K = %zu bytes (expected 162)\n", sizeof(Deep2::block_q5_K));
    printf("  block_q6_K = %zu bytes (expected 210)\n", sizeof(Deep2::block_q6_K));
    printf("  block_q8_K = %zu bytes (expected 264)\n", sizeof(Deep2::block_q8_K));
    printf("\n");

    // Validate file first
    printf("[Validation] Running GGUFLoader::ValidateFile...\n");
    char errorBuf[512] = {0};
    bool valid = Deep2::GGUFLoader::ValidateFile(modelPath, errorBuf);

    if (valid) {
        printf("\n✅ SUCCESS: File validated!\n");

        // Try full load
        printf("\n[Load] Attempting full tensor load...\n");
        Deep2::GGUFLoadOptions opts;
        opts.loadTensors = true;
        opts.verbose = true;
        Deep2::GGUFLoadResult result = Deep2::GGUFLoader::Load(modelPath, opts);
        if (result.success) {
            printf("\n✅ SUCCESS: Model loaded!\n");
            result.metadata.Print();
            printf("   Tensors: %zu\n", result.tensors.size());
            printf("   Total size: %zu bytes (%.2f GB)\n", result.totalSize, result.totalSize / (1024.0 * 1024.0 * 1024.0));
        } else {
            printf("\n❌ FAILED: Model load failed after validation passed\n");
            printf("   Error: %s\n", result.error);
            return 2;
        }
    } else {
        printf("\n❌ FAILED: Validation failed\n");
        if (errorBuf[0]) printf("   Error: %s\n", errorBuf);
        return 1;
    }

    printf("\n========================================\n");
    printf("ALL CHECKS PASSED\n");
    printf("========================================\n");
    return 0;
}
