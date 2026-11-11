// tests/test_memory_stress.cpp
// Test: Memory stress and leak detection
#include "RawrXDCore.h"
#include <iostream>
#include <vector>
#include <cassert>

int main() {
    std::cout << "=== Test: Memory Stress ===" << std::endl;
    
    assert(RawrXDCore_Initialize() == true);
    
    // Get baseline memory
    RawrXDMemoryStats baseline;
    RawrXDCore_GetMemoryStats(&baseline);
    std::cout << "Baseline allocated: " << baseline.totalAllocated / (1024*1024) << " MB" << std::endl;
    
    // Stress test: create/destroy many models and contexts
    const int iterations = 1000;
    std::vector<RawrXDModel*> models;
    std::vector<RawrXDInferenceContext*> contexts;
    
    for (int i = 0; i < iterations; ++i) {
        // Create model
        char path[256];
        sprintf_s(path, "models/test_model_%d.gguf", i);
        RawrXDModel* model = RawrXDCore_LoadModel(path);
        assert(model != nullptr);
        models.push_back(model);
        
        // Create context
        RawrXDInferenceContext* ctx = RawrXDCore_CreateContext(model);
        assert(ctx != nullptr);
        contexts.push_back(ctx);
        
        // Run tiny inference
        RawrXDInferenceParams params;
        RawrXDCore_GetDefaultInferenceParams(&params);
        params.maxTokens = 1;
        
        RawrXDCore_RunInference(ctx, "x", &params,
            [](int, const char*, void*) { return true; }, nullptr);
        
        // Cleanup every 100 iterations to test reuse
        if ((i + 1) % 100 == 0) {
            for (auto ctx : contexts) {
                RawrXDCore_DestroyContext(ctx);
            }
            contexts.clear();
            
            for (auto model : models) {
                RawrXDCore_UnloadModel(model);
            }
            models.clear();
            
            // Check memory
            RawrXDMemoryStats current;
            RawrXDCore_GetMemoryStats(&current);
            std::cout << "  Iteration " << (i + 1) << ": " 
                      << current.totalAllocated / (1024*1024) << " MB" << std::endl;
        }
    }
    
    // Cleanup remaining
    for (auto ctx : contexts) {
        RawrXDCore_DestroyContext(ctx);
    }
    for (auto model : models) {
        RawrXDCore_UnloadModel(model);
    }
    
    // Final memory check
    RawrXDMemoryStats final;
    RawrXDCore_GetMemoryStats(&final);
    std::cout << "Final allocated: " << final.totalAllocated / (1024*1024) << " MB" << std::endl;
    
    // Trim memory
    RawrXDCore_TrimMemory();
    RawrXDMemoryStats afterTrim;
    RawrXDCore_GetMemoryStats(&afterTrim);
    std::cout << "After trim: " << afterTrim.totalAllocated / (1024*1024) << " MB" << std::endl;
    
    // Memory should not have grown excessively
    // (In real implementation, this would check for leaks)
    assert(final.totalAllocated < baseline.totalAllocated + 100 * 1024 * 1024); // < 100MB growth
    
    RawrXDCore_Shutdown();
    std::cout << "=== PASSED ===" << std::endl;
    return 0;
}