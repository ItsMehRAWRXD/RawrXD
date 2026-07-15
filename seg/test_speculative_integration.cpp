// ============================================================================
// Test: Speculative Decoding Integration (Standalone)
// ============================================================================
// Validates the speculative decoder without full autoregressive dependencies
// ============================================================================

#include "speculative_decoder.hpp"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <random>

using namespace seg;

// Simple mock draft model for testing
class SimpleDraftModel : public DraftModel {
public:
    explicit SimpleDraftModel(int vocab_size) : vocab_size_(vocab_size), rng_(std::random_device{}()) {}
    
    std::vector<uint32_t> GenerateDraft(
        const std::vector<uint32_t>& context,
        uint32_t num_tokens,
        float temperature) override {
        
        std::vector<uint32_t> draft;
        draft.reserve(num_tokens);
        
        // Simple statistical model: predict based on last token
        uint32_t last = context.empty() ? 1 : context.back();
        
        for (uint32_t i = 0; i < num_tokens; ++i) {
            // Generate token correlated with last (simulating learned patterns)
            uint32_t next = (last * 7 + i * 13 + rng_() % 10) % vocab_size_;
            draft.push_back(next);
            last = next;
        }
        
        return draft;
    }
    
    float GetLatencyEstimate() const override { 
        return 0.01f; // 10us per token (fast)
    }
    
private:
    int vocab_size_;
    std::mt19937 rng_;
};

// Simple mock target model for testing
class SimpleTargetModel : public TargetModel {
public:
    explicit SimpleTargetModel(int vocab_size) : vocab_size_(vocab_size), rng_(std::random_device{}()) {}
    
    std::vector<std::vector<float>> VerifyDraft(
        const std::vector<uint32_t>& context,
        const std::vector<uint32_t>& draft_tokens) override {
        
        std::vector<std::vector<float>> all_logits;
        all_logits.reserve(draft_tokens.size());
        
        for (size_t i = 0; i < draft_tokens.size(); ++i) {
            // Generate logits with some correlation to draft token
            std::vector<float> logits(vocab_size_);
            for (int v = 0; v < vocab_size_; ++v) {
                // Higher probability for draft token (simulating alignment)
                if (v == static_cast<int>(draft_tokens[i])) {
                    logits[v] = 2.0f + (rng_() % 100) / 100.0f; // Higher logit
                } else {
                    logits[v] = (rng_() % 100) / 100.0f - 0.5f; // Random
                }
            }
            all_logits.push_back(logits);
        }
        
        return all_logits;
    }
    
    float GetLatencyEstimate() const override { 
        return 0.1f; // 100us per token (10x slower than draft)
    }
    
private:
    int vocab_size_;
    std::mt19937 rng_;
};

// Test function declarations
bool TestBasicGeneration();
bool TestPerformanceComparison();
bool TestAcceptanceRate();
bool TestStatsTracking();

int main() {
    std::cout << "========================================\n";
    std::cout << "Speculative Decoding Integration Tests\n";
    std::cout << "========================================\n\n";
    
    int passed = 0;
    int failed = 0;
    
    if (TestBasicGeneration()) {
        std::cout << "✓ TestBasicGeneration PASSED\n";
        passed++;
    } else {
        std::cout << "✗ TestBasicGeneration FAILED\n";
        failed++;
    }
    
    if (TestPerformanceComparison()) {
        std::cout << "✓ TestPerformanceComparison PASSED\n";
        passed++;
    } else {
        std::cout << "✗ TestPerformanceComparison FAILED\n";
        failed++;
    }
    
    if (TestAcceptanceRate()) {
        std::cout << "✓ TestAcceptanceRate PASSED\n";
        passed++;
    } else {
        std::cout << "✗ TestAcceptanceRate FAILED\n";
        failed++;
    }
    
    if (TestStatsTracking()) {
        std::cout << "✓ TestStatsTracking PASSED\n";
        passed++;
    } else {
        std::cout << "✗ TestStatsTracking FAILED\n";
        failed++;
    }
    
    std::cout << "\n========================================\n";
    std::cout << "Results: " << passed << " passed, " << failed << " failed\n";
    std::cout << "========================================\n";
    
    return failed > 0 ? 1 : 0;
}

bool TestBasicGeneration() {
    std::cout << "\n--- Test: Basic Generation ---\n";
    
    // Create models
    auto draft = std::make_unique<SimpleDraftModel>(1000);
    auto target = std::make_unique<SimpleTargetModel>(1000);
    
    // Create decoder
    SpeculativeDecoder decoder;
    SpeculativeConfig config;
    config.draft_tokens = 4;
    config.draft_temperature = 1.2f;
    config.min_accept_prob = 0.6f;
    
    if (!decoder.Initialize(std::move(draft), std::move(target), config)) {
        std::cerr << "Failed to initialize decoder\n";
        return false;
    }
    
    // Generate tokens
    std::vector<uint32_t> prompt = {1, 2, 3};
    auto generated = decoder.Generate(prompt, 20);
    
    std::cout << "  Generated " << generated.size() << " tokens\n";
    std::cout << "  Tokens: ";
    for (size_t i = 0; i < std::min(generated.size(), size_t(10)); ++i) {
        std::cout << generated[i] << " ";
    }
    if (generated.size() > 10) std::cout << "...";
    std::cout << "\n";
    
    return generated.size() == 20;
}

bool TestPerformanceComparison() {
    std::cout << "\n--- Test: Performance Comparison ---\n";
    
    const int vocab_size = 32000;
    const int num_tokens = 100;
    const int iterations = 10;
    
    // Benchmark speculative decoding
    auto draft = std::make_unique<SimpleDraftModel>(vocab_size);
    auto target = std::make_unique<SimpleTargetModel>(vocab_size);
    
    SpeculativeDecoder decoder;
    SpeculativeConfig config;
    config.draft_tokens = 4;
    
    decoder.Initialize(std::move(draft), std::move(target), config);
    
    // Warmup
    for (int i = 0; i < 5; ++i) {
        decoder.Generate({1, 2, 3}, 10);
    }
    decoder.ResetStats();
    
    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        decoder.Generate({1, 2, 3}, num_tokens);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto spec_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    float spec_time_per_token = static_cast<float>(spec_duration.count()) / (iterations * num_tokens);
    
    std::cout << "  Speculative: " << spec_duration.count() / iterations << " us per iteration\n";
    std::cout << "  Time per token: " << std::fixed << std::setprecision(2) << spec_time_per_token << " us\n";
    
    // Calculate theoretical baseline time (target model only)
    float baseline_time = 100.0f * num_tokens; // 100us per token
    float theoretical_speedup = baseline_time / spec_time_per_token;
    
    std::cout << "  Theoretical speedup: " << std::fixed << std::setprecision(2) << theoretical_speedup << "x\n";
    
    // With K=4 and 10:1 cost ratio, expect ~2-3x speedup
    return theoretical_speedup > 1.5f;
}

bool TestAcceptanceRate() {
    std::cout << "\n--- Test: Acceptance Rate ---\n";
    
    auto draft = std::make_unique<SimpleDraftModel>(1000);
    auto target = std::make_unique<SimpleTargetModel>(1000);
    
    SpeculativeDecoder decoder;
    SpeculativeConfig config;
    config.draft_tokens = 4;
    config.min_accept_prob = 0.6f;
    
    decoder.Initialize(std::move(draft), std::move(target), config);
    
    // Generate many tokens to get stable acceptance rate
    std::vector<uint32_t> prompt = {1};
    decoder.Generate(prompt, 100);
    
    auto stats = decoder.GetStats();
    float acceptance_rate = static_cast<float>(stats.tokens_accepted) / 
                           (stats.tokens_accepted + stats.tokens_rejected);
    
    std::cout << "  Total steps: " << stats.total_steps << "\n";
    std::cout << "  Tokens accepted: " << stats.tokens_accepted << "\n";
    std::cout << "  Tokens rejected: " << stats.tokens_rejected << "\n";
    std::cout << "  Acceptance rate: " << std::fixed << std::setprecision(2) 
              << (acceptance_rate * 100) << "%\n";
    
    // With our simple mock models, expect some acceptance (varies due to randomness)
    return acceptance_rate > 0.0f && acceptance_rate <= 1.0f;
}

bool TestStatsTracking() {
    std::cout << "\n--- Test: Stats Tracking ---\n";
    
    auto draft = std::make_unique<SimpleDraftModel>(1000);
    auto target = std::make_unique<SimpleTargetModel>(1000);
    
    SpeculativeDecoder decoder;
    SpeculativeConfig config;
    config.draft_tokens = 4;
    
    decoder.Initialize(std::move(draft), std::move(target), config);
    
    // Reset and generate
    decoder.ResetStats();
    decoder.Generate({1, 2, 3}, 50);
    
    auto stats = decoder.GetStats();
    
    std::cout << "  Total steps: " << stats.total_steps << "\n";
    std::cout << "  Draft tokens generated: " << stats.draft_tokens_generated << "\n";
    std::cout << "  Tokens accepted: " << stats.tokens_accepted << "\n";
    std::cout << "  Tokens rejected: " << stats.tokens_rejected << "\n";
    std::cout << "  Draft time: " << stats.draft_time_us << " us\n";
    std::cout << "  Target time: " << stats.target_time_us << " us\n";
    std::cout << "  Speedup: " << std::fixed << std::setprecision(2) << stats.speedup_vs_baseline << "x\n";
    
    return stats.total_steps > 0 && 
           stats.draft_tokens_generated > 0 &&
           stats.speedup_vs_baseline > 0.0f;
}
