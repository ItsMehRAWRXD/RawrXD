//============================================================================
// benchmark_isa_dispatch.cpp
//
// VAL-032: ISA Dispatch Benchmark
//
// Reports:
//   - CPU features detected (AVX-512, AVX2, SSE4.2)
//   - Selected backend
//   - Performance metrics
//============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <memory>
#include <chrono>
#include "../kernels/tree_attention_dispatch.hpp"

using namespace RawrXD::Kernels;

//============================================================================
// CPU Feature String
//============================================================================
const char* GetFeatureString() {
    static char buffer[256];
    buffer[0] = '\0';
    
    bool first = true;
    
    auto add = [&first](const char* name) {
        if (!first) strcat(buffer, ", ");
        strcat(buffer, name);
        first = false;
    };
    
    if (TreeAttentionDispatcher::DetectAVX512()) add("AVX-512");
    if (TreeAttentionDispatcher::DetectAVX2()) add("AVX2");
    if (TreeAttentionDispatcher::DetectSSE42()) add("SSE4.2");
    
    if (buffer[0] == '\0') {
        strcpy(buffer, "None (Scalar only)");
    }
    
    return buffer;
}

//============================================================================
// Test Data Setup
//============================================================================
struct TestData {
    std::unique_ptr<float[]> candidate_logits;
    std::unique_ptr<float[]> draft_logits;
    std::unique_ptr<float[]> tree_mask;
    std::unique_ptr<float[]> output_probs;
    
    TestData() {
        candidate_logits = std::make_unique<float[]>(16 * 64);
        draft_logits = std::make_unique<float[]>(16);
        tree_mask = std::make_unique<float[]>(64);
        output_probs = std::make_unique<float[]>(16);
        
        // Initialize with test data
        for (int i = 0; i < 16 * 64; i++) {
            candidate_logits[i] = 0.5f + (i % 10) * 0.05f;
        }
        
        for (int i = 0; i < 16; i++) {
            draft_logits[i] = 0.4f + i * 0.02f;
        }
        
        // Tree mask: validity in first 2 bytes, draft probs in positions 16-31
        uint16_t validity = 0xFFFF;  // All valid
        memcpy(tree_mask.get(), &validity, sizeof(validity));
        memcpy(tree_mask.get() + 16, draft_logits.get(), 16 * sizeof(float));
    }
};

//============================================================================
// Benchmark
//============================================================================
int main() {
    printf("=================================================================\n");
    printf("VAL-032: ISA Dispatch Benchmark\n");
    printf("=================================================================\n\n");
    
    // Report CPU features
    printf("CPU Features Detected:\n");
    printf("  AVX-512: %s\n", TreeAttentionDispatcher::DetectAVX512() ? "YES" : "NO");
    printf("  AVX2:    %s\n", TreeAttentionDispatcher::DetectAVX2() ? "YES" : "NO");
    printf("  SSE4.2:  %s\n", TreeAttentionDispatcher::DetectSSE42() ? "YES" : "NO");
    printf("  Summary: %s\n\n", GetFeatureString());
    
    // Select and report kernel
    TreeAttentionKernel kernel = TreeAttentionDispatcher::SelectKernel();
    printf("Selected Backend: %s (version %d)\n\n", kernel.name, kernel.version);
    
    // Test each kernel variant
    TestData data;
    const int iterations = 10000;
    
    printf("Performance Test (%d iterations):\n", iterations);
    printf("-----------------------------------------------------------------\n");
    
    // Test selected kernel
    {
        auto start = std::chrono::high_resolution_clock::now();
        
        uint32_t result = 0;
        for (int i = 0; i < iterations; i++) {
            result = kernel.verify(
                data.candidate_logits.get(),
                data.draft_logits.get(),
                data.tree_mask.get(),
                data.output_probs.get(),
                16,
                0.6f
            );
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        printf("  %s Kernel:\n", kernel.name);
        printf("    Total time: %lld us\n", duration.count());
        printf("    Per call:   %.3f us\n", (double)duration.count() / iterations);
        printf("    Acceptance: 0x%04X\n", result);
    }
    
    // Test scalar kernel (for comparison)
    {
        TreeAttentionKernel scalar = TreeAttentionDispatcher::GetScalarKernel();
        
        auto start = std::chrono::high_resolution_clock::now();
        
        uint32_t result = 0;
        for (int i = 0; i < iterations; i++) {
            result = scalar.verify(
                data.candidate_logits.get(),
                data.draft_logits.get(),
                data.tree_mask.get(),
                data.output_probs.get(),
                16,
                0.6f
            );
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        printf("  Scalar Kernel (reference):\n");
        printf("    Total time: %lld us\n", duration.count());
        printf("    Per call:   %.3f us\n", (double)duration.count() / iterations);
        printf("    Acceptance: 0x%04X\n", result);
    }
    
    // Test AVX2 if available
    if (TreeAttentionDispatcher::DetectAVX2()) {
        TreeAttentionKernel avx2 = TreeAttentionDispatcher::GetAVX2Kernel();
        
        auto start = std::chrono::high_resolution_clock::now();
        
        uint32_t result = 0;
        for (int i = 0; i < iterations; i++) {
            result = avx2.verify(
                data.candidate_logits.get(),
                data.draft_logits.get(),
                data.tree_mask.get(),
                data.output_probs.get(),
                16,
                0.6f
            );
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        printf("  AVX2 Kernel:\n");
        printf("    Total time: %lld us\n", duration.count());
        printf("    Per call:   %.3f us\n", (double)duration.count() / iterations);
        printf("    Acceptance: 0x%04X\n", result);
    }
    
    printf("\n=================================================================\n");
    printf("Benchmark Complete\n");
    printf("=================================================================\n");
    
    return 0;
}
