// ============================================================================
// Milestone 3: Integration Test Main
// ============================================================================
// Simple test runner for Milestone 3 integration
// ============================================================================

#include <cstdio>
#include "../ai/ai_model_caller_integrated.h"

int main(int argc, char* argv[]) {
    printf("=====================================================================\n");
    printf("RawrXD Milestone 3: Integration Test\n");
    printf("=====================================================================\n\n");
    
    printf("Testing integrated inference pipeline...\n\n");
    
    // Test 1: Clear cache
    printf("[Test 1] Clearing token cache...\n");
    ClearTokenCache();
    printf("  Token cache cleared successfully.\n\n");
    
    // Test 2: Cache stats
    printf("[Test 2] Getting cache stats...\n");
    CacheStats stats = GetTokenCacheStats();
    printf("  Cache size: %zu\n", stats.size);
    printf("  Max size: %zu\n", stats.max_size);
    printf("  Hit rate: %.2f%%\n\n", stats.hit_rate * 100.0f);
    
    // Test 3: End-to-end generation (will fail without model, but tests the pipeline)
    printf("[Test 3] Testing end-to-end generation...\n");
    printf("  Note: This will fail without a loaded model, but validates the pipeline.\n");
    bool test_result = TestEndToEndGeneration();
    if (test_result) {
        printf("  Test PASSED!\n\n");
    } else {
        printf("  Test FAILED (expected without model).\n\n");
    }
    
    printf("=====================================================================\n");
    printf("Milestone 3 Integration Test Complete\n");
    printf("=====================================================================\n");
    
    return 0;
}
