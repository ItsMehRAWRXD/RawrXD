// test_inference_real.cpp - Simple test for real inference implementation
// ============================================================================

#include "ggml_fallback.h"
#include "../include/inference_engine_real.h"
#include <stdio>
#include <stdlib.h>
#include <string>

int main(int argc, char** argv) {
    printf("RawrXD Real Inference Test\n");
    printf("==========================\n\n");
    
    // Test 1: GGML Fallback Context
    printf("Test 1: GGML Fallback Context Creation\n");
    {
        ggml_fallback_init_params params = {};
        params.mem_size = 1024 * 1024; // 1MB
        params.mem_buffer = nullptr;
        params.no_alloc = false;
        
        ggml_fallback_context* ctx = ggml_fallback_init(params);
        if (!ctx) {
            printf("  FAILED: Could not create context\n");
            return 1;
        }
        printf("  PASSED: Context created\n");
        
        // Test tensor creation
        ggml_fallback_tensor* tensor = ggml_fallback_new_tensor_1d(ctx, GGML_FALLBACK_TYPE_F32, 256);
        if (!tensor) {
            printf("  FAILED: Could not create tensor\n");
            ggml_fallback_free(ctx);
            return 1;
        }
        printf("  PASSED: Tensor created (256 floats)\n");
        
        // Test tensor operations
        ggml_fallback_tensor* tensor2 = ggml_fallback_new_tensor_1d(ctx, GGML_FALLBACK_TYPE_F32, 256);
        if (!tensor2) {
            printf("  FAILED: Could not create second tensor\n");
            ggml_fallback_free(ctx);
            return 1;
        }
        
        ggml_fallback_tensor* result = ggml_fallback_add(ctx, tensor, tensor2);
        if (!result) {
            printf("  FAILED: Could not add tensors\n");
            ggml_fallback_free(ctx);
            return 1;
        }
        printf("  PASSED: Tensor addition operation created\n");
        
        ggml_fallback_free(ctx);
        printf("  PASSED: Context cleanup\n");
    }
    
    // Test 2: Inference Engine
    printf("\nTest 2: Inference Engine\n");
    {
        void* engine = RawrInferenceEngine_Create();
        if (!engine) {
            printf("  FAILED: Could not create engine\n");
            return 1;
        }
        printf("  PASSED: Engine created\n");
        
        // Initialize with small model config
        int result = RawrInferenceEngine_Initialize(engine, 1000, 128, 4, 2);
        if (result != 0) {
            printf("  FAILED: Could not initialize engine (error %d)\n", result);
            RawrInferenceEngine_Destroy(engine);
            return 1;
        }
        printf("  PASSED: Engine initialized (vocab=1000, embd=128, heads=4, layers=2)\n");
        
        // Check status
        if (!RawrInferenceEngine_IsInitialized(engine)) {
            printf("  FAILED: Engine not marked as initialized\n");
            RawrInferenceEngine_Destroy(engine);
            return 1;
        }
        printf("  PASSED: Engine status verified\n");
        
        // Cleanup
        RawrInferenceEngine_Cleanup(engine);
        printf("  PASSED: Engine cleanup\n");
        
        RawrInferenceEngine_Destroy(engine);
        printf("  PASSED: Engine destroyed\n");
    }
    
    // Test 3: Legacy API
    printf("\nTest 3: Legacy API Compatibility\n");
    {
        void* engine = InferenceEngine_Create(nullptr);
        if (!engine) {
            printf("  FAILED: Could not create engine via legacy API\n");
            return 1;
        }
        printf("  PASSED: Legacy engine created\n");
        
        // Note: We can't test Initialize with a real model path without a model file
        // So we just test the API exists
        printf("  INFO: Legacy API available\n");
        
        InferenceEngine_Destroy(engine);
        printf("  PASSED: Legacy engine destroyed\n");
    }
    
    printf("\n==========================\n");
    printf("All tests PASSED!\n");
    return 0;
}
