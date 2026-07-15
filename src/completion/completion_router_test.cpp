#include "completion_router.h"
#include "../semantic_index/SemanticCodeIndex.h"
#include "../KeywordHashTable.h"

#include <iostream>
#include <assert>
#include <chrono>

using namespace RawrXD;

// Mock KeywordHashTable for testing
class MockKeywordHashTable : public KeywordHashTable {
public:
    struct Match {
        std::string keyword;
        std::string type;
        float score;
    };
    
    std::vector<Match> find_prefix_matches(const std::string& prefix, int max_results) {
        std::vector<Match> matches;
        // Mock implementation - return dummy matches
        for (int i = 0; i < max_results && i < 3; ++i) {
            matches.push_back({prefix + "_match_" + std::to_string(i), "function", 0.9f - (i * 0.1f)});
        }
        return matches;
    }
};

void test_initialization() {
    std::cout << "[TEST] CompletionRouter initialization...\n";
    
    CompletionRouter router;
    
    // Should fail without trie
    assert(!router.initialize(nullptr, nullptr));
    
    // Should succeed with trie (semantic index optional)
    auto trie = std::make_unique<MockKeywordHashTable>();
    assert(router.initialize(nullptr, std::move(trie)));
    assert(router.is_initialized());
    assert(!router.has_semantic_index());
    
    std::cout << "  ✓ Initialization tests passed\n";
}

void test_trie_only_mode() {
    std::cout << "[TEST] Trie-only mode...\n";
    
    CompletionRouter router;
    auto trie = std::make_unique<MockKeywordHashTable>();
    router.initialize(nullptr, std::move(trie));
    
    router.set_mode(CompletionRouter::Mode::TRIE_ONLY);
    
    EditorContext ctx;
    ctx.file_path = "test.cpp";
    ctx.line_number = 10;
    ctx.column = 5;
    
    auto results = router.get_suggestions(ctx, "test", 5);
    
    assert(!results.empty());
    for (const auto& r : results) {
        assert(r.source == CompletionSuggestion::Source::TRIE_PREFIX);
    }
    
    std::cout << "  ✓ Trie-only mode tests passed (" << results.size() << " results)\n";
}

void test_hybrid_mode_without_semantic() {
    std::cout << "[TEST] Hybrid mode (no semantic index)...\n";
    
    CompletionRouter router;
    auto trie = std::make_unique<MockKeywordHashTable>();
    router.initialize(nullptr, std::move(trie));
    
    router.set_mode(CompletionRouter::Mode::HYBRID_FUSION);
    
    EditorContext ctx;
    ctx.file_path = "test.cpp";
    
    // Short query - should use trie only
    auto results = router.get_suggestions(ctx, "ab", 5);
    assert(!results.empty());
    
    // Longer query - still trie only (no semantic index)
    results = router.get_suggestions(ctx, "async file io", 5);
    assert(!results.empty());
    
    std::cout << "  ✓ Hybrid fallback tests passed\n";
}

void test_weight_configuration() {
    std::cout << "[TEST] Weight configuration...\n";
    
    CompletionRouter router;
    auto trie = std::make_unique<MockKeywordHashTable>();
    router.initialize(nullptr, std::move(trie));
    
    // Set custom weights
    CompletionRouter::FusionWeights weights{0.3f, 0.7f, 0.0f};
    router.set_weights(weights);
    
    auto retrieved = router.get_weights();
    assert(std::abs(retrieved.trie_weight - 0.3f) < 0.01f);
    assert(std::abs(retrieved.semantic_weight - 0.7f) < 0.01f);
    
    // Test normalization (weights that don't sum to 1.0)
    CompletionRouter::FusionWeights bad_weights{1.0f, 1.0f, 1.0f};
    router.set_weights(bad_weights);
    retrieved = router.get_weights();
    assert(std::abs(retrieved.trie_weight - 0.333f) < 0.01f);
    
    std::cout << "  ✓ Weight configuration tests passed\n";
}

void test_latency_budget() {
    std::cout << "[TEST] Latency budget enforcement...\n";
    
    CompletionRouter router;
    auto trie = std::make_unique<MockKeywordHashTable>();
    router.initialize(nullptr, std::move(trie));
    
    EditorContext ctx;
    ctx.file_path = "test.cpp";
    
    auto start = std::chrono::steady_clock::now();
    auto results = router.get_suggestions_with_budget(ctx, "test", 100, 5);
    auto end = std::chrono::steady_clock::now();
    
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    assert(elapsed_ms < 100);  // Should complete within budget
    std::cout << "  ✓ Latency budget tests passed (" << elapsed_ms << "ms)\n";
}

void test_statistics() {
    std::cout << "[TEST] Statistics tracking...\n";
    
    CompletionRouter router;
    auto trie = std::make_unique<MockKeywordHashTable>();
    router.initialize(nullptr, std::move(trie));
    
    router.reset_stats();
    
    EditorContext ctx;
    ctx.file_path = "test.cpp";
    
    // Make some requests
    for (int i = 0; i < 10; ++i) {
        router.get_suggestions(ctx, "query_" + std::to_string(i), 5);
    }
    
    auto stats = router.get_stats();
    assert(stats.total_requests == 10);
    assert(stats.trie_requests > 0);  // Should have trie requests
    
    std::cout << "  ✓ Statistics tests passed (" << stats.total_requests << " requests)\n";
}

void test_smart_fallback_mode() {
    std::cout << "[TEST] Smart fallback mode...\n";
    
    CompletionRouter router;
    auto trie = std::make_unique<MockKeywordHashTable>();
    router.initialize(nullptr, std::move(trie));
    
    router.set_mode(CompletionRouter::Mode::SMART_FALLBACK);
    
    EditorContext ctx;
    ctx.file_path = "test.cpp";
    
    // Short query - should use trie
    auto results_short = router.get_suggestions(ctx, "ab", 5);
    
    // Long query - would use semantic if available
    auto results_long = router.get_suggestions(ctx, "async file io pattern", 5);
    
    // Both should return results
    assert(!results_short.empty());
    assert(!results_long.empty());
    
    std::cout << "  ✓ Smart fallback tests passed\n";
}

int main() {
    std::cout << "========================================\n";
    std::cout << "CompletionRouter Smoke Tests\n";
    std::cout << "Phase 17C.2 Integration\n";
    std::cout << "========================================\n\n";
    
    try {
        test_initialization();
        test_trie_only_mode();
        test_hybrid_mode_without_semantic();
        test_weight_configuration();
        test_latency_budget();
        test_statistics();
        test_smart_fallback_mode();
        
        std::cout << "\n========================================\n";
        std::cout << "✓ All tests passed!\n";
        std::cout << "========================================\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\n✗ Test failed: " << e.what() << "\n";
        return 1;
    }
}
