//============================================================================
// test_avx512_gating.cpp
//
// Validates runtime AVX-512 detection and fallback behavior
//============================================================================

#include "../src/kernels/tree_attention_dispatch.hpp"
#include <stdio.h>
#include <string.h>

using namespace RawrXD::Kernels;

int main() {
    printf("=== AVX-512 Runtime Gating Test ===\n\n");
    
    // Test 1: Kernel selection
    printf("Test 1: Kernel Selection\n");
    auto kernel = TreeAttentionDispatcher::SelectKernel();
    printf("  Selected kernel: %s\n", kernel.name);
    printf("  Has AVX-512: %s\n", kernel.has_avx512() ? "YES" : "NO");
    
    // Test 2: Feature detection consistency
    printf("\nTest 2: Feature Detection Consistency\n");
    bool dispatcher_detects = TreeAttentionDispatcher::DetectAVX512();
    bool kernel_reports = kernel.has_avx512();
    
    if (dispatcher_detects == kernel_reports) {
        printf("  PASS: Dispatcher and kernel agree (%s)\n", 
               dispatcher_detects ? "AVX-512 available" : "AVX-512 not available");
    } else {
        printf("  FAIL: Mismatch (dispatcher=%s, kernel=%s)\n",
               dispatcher_detects ? "YES" : "NO",
               kernel_reports ? "YES" : "NO");
        return 1;
    }
    
    // Test 3: Execution engine initialization
    printf("\nTest 3: Execution Engine Initialization\n");
    TreeAttentionConfig config;
    config.max_candidates = 16;
    config.embedding_dim = 64;
    config.enable_telemetry = true;
    
    SpeculativeExecutionEngine engine(config);
    const auto& active_kernel = engine.GetKernel();
    printf("  Engine kernel: %s\n", active_kernel.name);
    
    // Verify safe execution (should not crash regardless of AVX-512)
    printf("\nTest 4: Safe Execution\n");
    alignas(64) float query[64];
    alignas(64) float keys[16 * 64];
    alignas(64) float tree_mask[64];
    alignas(64) float output_probs[16];
    
    memset(query, 0, sizeof(query));
    memset(keys, 0, sizeof(keys));
    memset(tree_mask, 0, sizeof(tree_mask));
    
    // Set validity mask
    *(uint16_t*)tree_mask = 0xFFFF;
    for (int i = 0; i < 16; i++) {
        tree_mask[16 + i] = 0.5f;
    }
    
    printf("  Running verification...\n");
    auto result = engine.VerifyCandidates(query, keys, tree_mask, output_probs);
    printf("  Result: %u accepted, mask=0x%04X\n", result.accepted_count, result.acceptance_mask);
    
    // Test 5: Telemetry
    printf("\nTest 5: Telemetry\n");
    const auto& telemetry = engine.GetTelemetry();
    printf("  Candidates verified: %llu\n", telemetry.candidates_verified);
    printf("  Tokens accepted: %llu\n", telemetry.tokens_accepted);
    printf("  Acceptance rate: %.2f%%\n", telemetry.GetAcceptanceRate() * 100);
    
    printf("\n=== All Tests Passed ===\n");
    return 0;
}
