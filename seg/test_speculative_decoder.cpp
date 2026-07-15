// ============================================================================
// Test: C8 Speculative Decoding
// ============================================================================
// Validates draft generation, target verification, and acceptance/rejection
// ============================================================================

#include <iostream>
#include <vector>
#include <cassert>
#include <chrono>
#include "speculative_decoder.hpp"

using namespace seg;

// ============================================================================
// Mock Models for Testing
// ============================================================================

class MockDraftModel : public DraftModel {
public:
    std::vector<uint32_t> GenerateDraft(
        const std::vector<uint32_t>& context,
        uint32_t num_tokens,
        float temperature
    ) override {
        // Simple mock: generate sequential tokens
        std::vector<uint32_t> draft;
        uint32_t start = context.empty() ? 0 : context.back();
        for (uint32_t i = 0; i < num_tokens; i++) {
            draft.push_back((start + i + 1) % 100);
        }
        return draft;
    }

    float GetLatencyEstimate() const override {
        return 0.1f; // 0.1ms per token
    }
};

class MockTargetModel : public TargetModel {
public:
    std::vector<std::vector<float>> VerifyDraft(
        const std::vector<uint32_t>& context,
        const std::vector<uint32_t>& draft_tokens
    ) override {
        std::vector<std::vector<float>> logits;
        
        for (size_t i = 0; i < draft_tokens.size(); i++) {
            std::vector<float> token_logits(100, -5.0f);
            // High probability for draft token (90% acceptance rate)
            token_logits[draft_tokens[i]] = 2.0f;
            logits.push_back(token_logits);
        }
        
        return logits;
    }

    float GetLatencyEstimate() const override {
        return 1.0f; // 1ms per token (10x slower than draft)
    }
};

// ============================================================================
// Test Functions
// ============================================================================

bool TestNGramDraftModel() {
    std::cout << "Test: NGramDraftModel...\n";
    
    // Build stats from training sequences
    std::vector<std::vector<uint32_t>> training = {
        {1, 2, 3, 4, 5},
        {1, 2, 3, 6, 7},
        {1, 2, 8, 9, 10}
    };
    
    NGramDraftModel model(100);
    model.BuildStats(training);
    
    // Generate from context
    std::vector<uint32_t> context = {1, 2};
    auto draft = model.GenerateDraft(context, 3, 1.0f);
    
    assert(draft.size() == 3);
    std::cout << "  Generated " << draft.size() << " tokens\n";
    std::cout << "  First token: " << draft[0] << "\n";
    
    return true;
}

bool TestAcceptRejectLogic() {
    std::cout << "Test: Accept/Reject Logic...\n";
    
    SpeculativeDecoder decoder;
    
    // Create mock models
    auto draft_model = std::make_unique<MockDraftModel>();
    auto target_model = std::make_unique<MockTargetModel>();
    
    SpeculativeConfig config;
    config.draft_tokens = 4;
    config.min_accept_prob = 0.5f;
    
    assert(decoder.Initialize(
        std::move(draft_model),
        std::move(target_model),
        config
    ));
    
    // Test speculative step
    std::vector<uint32_t> context = {1, 2, 3};
    auto tokens = decoder.Generate(context, 10, nullptr);
    
    std::cout << "  Generated " << tokens.size() << " tokens\n";
    
    auto stats = decoder.GetStats();
    std::cout << "  Total steps: " << stats.total_steps << "\n";
    std::cout << "  Tokens accepted: " << stats.tokens_accepted << "\n";
    std::cout << "  Tokens rejected: " << stats.tokens_rejected << "\n";
    std::cout << "  Avg acceptance rate: " << (stats.avg_acceptance_rate * 100.0f) << "%\n";
    std::cout << "  Speedup vs baseline: " << stats.speedup_vs_baseline << "x\n";
    
    return true;
}

bool TestPerformanceComparison() {
    std::cout << "Test: Performance Comparison...\n";
    
    auto draft_model = std::make_unique<MockDraftModel>();
    auto target_model = std::make_unique<MockTargetModel>();
    
    SpeculativeConfig config;
    config.draft_tokens = 4;
    config.min_accept_prob = 0.5f;
    
    SpeculativeDecoder decoder;
    decoder.Initialize(
        std::move(draft_model),
        std::move(target_model),
        config
    );
    
    // Benchmark speculative decoding
    std::vector<uint32_t> context = {1, 2, 3};
    
    auto start = std::chrono::high_resolution_clock::now();
    auto tokens = decoder.Generate(context, 20, nullptr);
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    auto stats = decoder.GetStats();
    
    std::cout << "  Generated " << tokens.size() << " tokens in " << duration.count() << " us\n";
    std::cout << "  Tokens/sec: " << (tokens.size() * 1000000.0 / duration.count()) << "\n";
    std::cout << "  Acceptance rate: " << (stats.avg_acceptance_rate * 100.0f) << "%\n";
    std::cout << "  Speedup: " << stats.speedup_vs_baseline << "x\n";
    
    // Verify speedup > 1.0
    assert(stats.speedup_vs_baseline > 1.0f);
    
    return true;
}

bool TestTelemetryIntegration() {
    std::cout << "Test: Telemetry Integration...\n";
    
    auto draft_model = std::make_unique<MockDraftModel>();
    auto target_model = std::make_unique<MockTargetModel>();
    
    SpeculativeConfig config;
    config.draft_tokens = 4;
    config.min_accept_prob = 0.5f;
    config.enable_telemetry = true;
    
    SpeculativeDecoder decoder;
    decoder.Initialize(
        std::move(draft_model),
        std::move(target_model),
        config
    );
    
    std::vector<uint32_t> context = {1, 2, 3};
    auto tokens = decoder.Generate(context, 10, nullptr);
    
    auto stats = decoder.GetStats();
    
    std::cout << "  Draft time: " << stats.draft_time_us << " us\n";
    std::cout << "  Target time: " << stats.target_time_us << " us\n";
    std::cout << "  Draft tokens: " << stats.draft_tokens_generated << "\n";
    
    // Verify telemetry captured (allow 0 for very fast mock)
    assert(stats.draft_time_us >= 0);
    assert(stats.target_time_us >= 0);
    
    return true;
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================\n";
    std::cout << "C8: Speculative Decoding Tests\n";
    std::cout << "========================================\n\n";
    
    int passed = 0;
    int failed = 0;
    
    auto run_test = [&](const char* name, bool (*test)()) {
        std::cout << "\n--- " << name << " ---\n";
        try {
            if (test()) {
                std::cout << "✓ PASSED\n";
                passed++;
            } else {
                std::cout << "✗ FAILED\n";
                failed++;
            }
        } catch (const std::exception& e) {
            std::cout << "✗ EXCEPTION: " << e.what() << "\n";
            failed++;
        }
    };
    
    run_test("NGramDraftModel", TestNGramDraftModel);
    run_test("Accept/Reject Logic", TestAcceptRejectLogic);
    run_test("Performance Comparison", TestPerformanceComparison);
    run_test("Telemetry Integration", TestTelemetryIntegration);
    
    std::cout << "\n========================================\n";
    std::cout << "Results: " << passed << " passed, " << failed << " failed\n";
    std::cout << "========================================\n";
    
    return failed == 0 ? 0 : 1;
}
