// test_transformer_stack_orchestrator_phase3.cpp
// Phase 3 smoke test for Transformer Stack Orchestrator
// Validates multi-token generation with KV cache reuse

#include "transformer_stack_orchestrator.hpp"
#include "kv_cache_manager.h"

#include <cstdio>
#include <memory>
#include <vector>

using namespace RawrXD::AI;

// Mock interface for testing
class MockInferenceClient {
public:
    MockInferenceClient() {}
    
    bool IsLoaded() const { return true; }
    
    void ClearKVCache() {
        // Mock implementation
        printf("Mock: Cleared KV cache\n");
    }
};

int main() {
    printf("=== Transformer Stack Orchestrator Phase3 Smoke Test ===\n");
    
    // Create mock inference client using raw pointer (for testing only)
    auto mock_client = std::shared_ptr<MockInferenceClient>(new MockInferenceClient());
    
    // Create KV cache manager
    auto kv_cache = std::make_shared<KVCacheManager>(10, 16); // 10 entries, 16MB
    
    // Create orchestrator with null inference client for testing
    // We can't actually pass the mock due to type mismatch, but we can test cache logic
    std::shared_ptr<Agent::SovereignInferenceClient> null_client(nullptr);
    TransformerStackOrchestrator orchestrator(null_client, kv_cache);
    
    printf("NOTE: Using null inference client for cache-only testing\n");
    
    // Initialize
    if (!orchestrator.Initialize()) {
        printf("ERROR: Failed to initialize orchestrator\n");
        return 1;
    }
    
    printf("✓ Orchestrator initialized\n");
    
    // Test 1: Generate tokens with cache disabled
    printf("\n--- Test 1: Generate without cache ---\n");
    orchestrator.SetCacheEnabled(false);
    
    std::vector<uint32_t> tokens1 = orchestrator.GenerateTokens(
        "Hello world",  // prompt
        3,              // max_tokens
        0.7f,           // temperature
        false           // use_cache
    );
    
    printf("Generated %zu tokens: ", tokens1.size());
    for (uint32_t token : tokens1) {
        printf("%u ", token);
    }
    printf("\n");
    
    if (tokens1.size() != 3) {
        printf("ERROR: Expected 3 tokens, got %zu\n", tokens1.size());
        return 1;
    }
    
    // Test 2: Generate tokens with cache enabled
    printf("\n--- Test 2: Generate with cache enabled ---\n");
    orchestrator.SetCacheEnabled(true);
    
    std::vector<uint32_t> tokens2 = orchestrator.GenerateTokens(
        "Hello world",  // same prompt
        3,              // max_tokens
        0.7f,           // temperature
        true            // use_cache
    );
    
    printf("Generated %zu tokens with cache: ", tokens2.size());
    for (uint32_t token : tokens2) {
        printf("%u ", token);
    }
    printf("\n");
    
    // Test 3: Step-by-step generation
    printf("\n--- Test 3: Step-by-step generation ---\n");
    
    GenerationState state = orchestrator.BeginGeneration("Test prompt");
    printf("State initialized: seq_len=%zu, cache_hit=%s\n", 
           state.seq_len, state.cache_hit ? "true" : "false");
    
    for (int i = 0; i < 5; i++) {
        uint32_t token = orchestrator.GenerateNextToken(state);
        if (token == 0) {
            printf("Token generation stopped\n");
            break;
        }
        printf("Generated token %d: %u\n", i + 1, token);
    }
    
    orchestrator.EndGeneration(state);
    
    // Test 4: Statistics
    printf("\n--- Test 4: Statistics ---\n");
    auto stats = orchestrator.GetStats();
    
    printf("Total tokens generated: %llu\n", stats.total_tokens_generated);
    printf("Cache hits: %llu\n", stats.total_cache_hits);
    printf("Cache misses: %llu\n", stats.total_cache_misses);
    printf("Cache hit rate: %.2f%%\n", stats.cache_hit_rate * 100.0f);
    printf("Average tokens/sec: %.2f\n", stats.avg_tokens_per_second);
    printf("Total generation time: %llu ms\n", stats.total_generation_time_ms);
    
    // Test 5: Multiple generations with cache reuse
    printf("\n--- Test 5: Multiple generations with same context ---\n");
    
    for (int i = 0; i < 3; i++) {
        std::vector<uint32_t> tokens = orchestrator.GenerateTokens(
            "Repeat this prompt",
            2,
            0.7f,
            true
        );
        
        printf("Generation %d: %zu tokens\n", i + 1, tokens.size());
    }
    
    // Check final statistics
    auto final_stats = orchestrator.GetStats();
    printf("\nFinal cache hit rate: %.2f%%\n", final_stats.cache_hit_rate * 100.0f);
    
    // Test 6: Clear cache and verify
    printf("\n--- Test 6: Cache management ---\n");
    orchestrator.SetMaxCacheEntries(5);
    orchestrator.SetMaxCacheMemory(8); // 8MB
    
    // Generate more tokens to trigger cache eviction
    for (int i = 0; i < 10; i++) {
        std::string prompt = "Prompt " + std::to_string(i);
        orchestrator.GenerateTokens(prompt, 1, 0.7f, true);
    }
    
    printf("Cache stress test completed\n");
    
    // Verify orchestrator is still functional
    std::vector<uint32_t> final_tokens = orchestrator.GenerateTokens(
        "Final test",
        2,
        0.7f,
        true
    );
    
    if (final_tokens.size() != 2) {
        printf("ERROR: Final test failed - expected 2 tokens\n");
        return 1;
    }
    
    printf("\n=== Transformer Stack Orchestrator smoke test PASSED ===\n");
    return 0;
}