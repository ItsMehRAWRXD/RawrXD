// ============================================================================
// C5: Token Sampling Test Suite
// ============================================================================

#include "token_sampling.hpp"
#include <iostream>
#include <iomanip>
#include <cmath>
#include <map>

using namespace SEG;

// Test utilities
static bool FloatEquals(float a, float b, float epsilon = 1e-5f) {
    return std::abs(a - b) < epsilon;
}

static void PrintTestHeader(const char* name) {
    std::cout << "\n========================================" << std::endl;
    std::cout << "Test: " << name << std::endl;
    std::cout << "========================================" << std::endl;
}

// ============================================================================
// Test 1: Greedy Sampling
// ============================================================================
static bool TestGreedySampling() {
    PrintTestHeader("Greedy Sampling");
    
    // Simple logits: token 3 should be selected
    float logits[] = {1.0f, 2.0f, 3.0f, 10.0f, 5.0f};
    size_t vocab_size = 5;
    
    int result = GreedySample(logits, vocab_size);
    
    std::cout << "Logits: [";
    for (size_t i = 0; i < vocab_size; ++i) {
        std::cout << logits[i] << (i < vocab_size - 1 ? ", " : "");
    }
    std::cout << "]" << std::endl;
    std::cout << "Selected token: " << result << std::endl;
    std::cout << "Expected: 3" << std::endl;
    
    bool pass = (result == 3);
    std::cout << "Result: " << (pass ? "PASS" : "FAIL") << std::endl;
    return pass;
}

// ============================================================================
// Test 2: Temperature Scaling
// ============================================================================
static bool TestTemperatureScaling() {
    PrintTestHeader("Temperature Scaling");
    
    // Create logits with clear winner
    float logits[] = {5.0f, 4.0f, 3.0f, 2.0f, 1.0f};
    size_t vocab_size = 5;
    
    // Test with temperature = 0 (greedy)
    SamplingConfig config;
    config.temperature = 0.0f;
    config.seed = 42;
    
    SamplingContext ctx(config);
    int result = ctx.Sample(logits, vocab_size);
    
    std::cout << "Temperature = 0.0 (greedy): " << result << std::endl;
    bool pass = (result == 0);  // Should select highest logit
    
    // Test with high temperature (more random)
    config.temperature = 2.0f;
    ctx.SetConfig(config);
    
    // Sample multiple times to verify randomness
    std::map<int, int> counts;
    for (int i = 0; i < 100; ++i) {
        int r = ctx.Sample(logits, vocab_size);
        counts[r]++;
    }
    
    std::cout << "\nTemperature = 2.0 (100 samples):" << std::endl;
    for (const auto& [token, count] : counts) {
        std::cout << "  Token " << token << ": " << count << " times" << std::endl;
    }
    
    // With high temperature, should see some variety
    pass = pass && (counts.size() > 1);
    
    std::cout << "Result: " << (pass ? "PASS" : "FAIL") << std::endl;
    return pass;
}

// ============================================================================
// Test 3: Top-K Sampling
// ============================================================================
static bool TestTopKSampling() {
    PrintTestHeader("Top-K Sampling");
    
    // Create logits where we want to restrict to top 3
    float logits[] = {10.0f, 9.0f, 8.0f, 1.0f, 0.5f, 0.1f};
    size_t vocab_size = 6;
    
    SamplingConfig config;
    config.top_k = 3;
    config.temperature = 1.0f;
    config.seed = 42;
    
    SamplingContext ctx(config);
    
    // Sample many times
    std::map<int, int> counts;
    for (int i = 0; i < 1000; ++i) {
        int r = ctx.Sample(logits, vocab_size);
        counts[r]++;
    }
    
    std::cout << "Top-K = 3 (1000 samples):" << std::endl;
    for (const auto& [token, count] : counts) {
        std::cout << "  Token " << token << ": " << count << " times" << std::endl;
    }
    
    // Should only see tokens 0, 1, 2 (the top 3)
    bool pass = true;
    for (const auto& [token, count] : counts) {
        if (token >= 3) {
            pass = false;
            std::cout << "ERROR: Token " << token << " should not appear with top_k=3" << std::endl;
        }
    }
    
    std::cout << "Result: " << (pass ? "PASS" : "FAIL") << std::endl;
    return pass;
}

// ============================================================================
// Test 4: Top-P (Nucleus) Sampling
// ============================================================================
static bool TestTopPSampling() {
    PrintTestHeader("Top-P (Nucleus) Sampling");
    
    // Create logits with exponential decay
    float logits[] = {5.0f, 4.0f, 3.0f, 2.0f, 1.0f, 0.0f};
    size_t vocab_size = 6;
    
    // First, see the probability distribution
    auto probs = LogitsToProbs(logits, vocab_size);
    std::cout << "Probability distribution:" << std::endl;
    float cumsum = 0.0f;
    for (size_t i = 0; i < vocab_size; ++i) {
        cumsum += probs[i];
        std::cout << "  Token " << i << ": " << std::fixed << std::setprecision(4) 
                  << probs[i] << " (cumsum: " << cumsum << ")" << std::endl;
    }
    
    SamplingConfig config;
    config.top_p = 0.9f;  // Sample from tokens comprising 90% of probability mass
    config.temperature = 1.0f;
    config.seed = 42;
    
    SamplingContext ctx(config);
    
    // Sample many times
    std::map<int, int> counts;
    for (int i = 0; i < 1000; ++i) {
        int r = ctx.Sample(logits, vocab_size);
        counts[r]++;
    }
    
    std::cout << "\nTop-P = 0.9 (1000 samples):" << std::endl;
    for (const auto& [token, count] : counts) {
        std::cout << "  Token " << token << ": " << count << " times" << std::endl;
    }
    
    // With top_p=0.9, should mostly see tokens 0, 1, 2 (which comprise ~90%)
    bool pass = true;
    int low_prob_count = 0;
    for (const auto& [token, count] : counts) {
        if (token >= 4) {
            low_prob_count += count;
        }
    }
    
    // Allow some low-probability tokens due to sampling variance
    if (low_prob_count > 100) {
        pass = false;
        std::cout << "ERROR: Too many low-probability tokens: " << low_prob_count << std::endl;
    }
    
    std::cout << "Result: " << (pass ? "PASS" : "FAIL") << std::endl;
    return pass;
}

// ============================================================================
// Test 5: Repetition Penalty
// ============================================================================
static bool TestRepetitionPenalty() {
    PrintTestHeader("Repetition Penalty");
    
    // Create logits where token 2 is slightly favored
    float logits[] = {5.0f, 5.0f, 6.0f, 4.0f, 4.0f};
    size_t vocab_size = 5;
    
    // Token history with token 2 repeated
    std::vector<int> history = {2, 2, 2, 2, 2};
    
    SamplingConfig config;
    config.repetition_penalty = 2.0f;  // Strong penalty
    config.temperature = 0.1f;  // Low temp for deterministic test
    config.seed = 42;
    
    SamplingContext ctx(config);
    
    // Without penalty, token 2 would be selected
    int without_penalty = GreedySample(logits, vocab_size);
    std::cout << "Without penalty: token " << without_penalty << std::endl;
    
    // With penalty, should select different token
    int with_penalty = ctx.SampleWithPenalty(logits, vocab_size, history);
    std::cout << "With penalty (history=[2,2,2,2,2]): token " << with_penalty << std::endl;
    
    bool pass = (without_penalty == 2) && (with_penalty != 2);
    
    std::cout << "Result: " << (pass ? "PASS" : "FAIL") << std::endl;
    return pass;
}

// ============================================================================
// Test 6: Combined Sampling
// ============================================================================
static bool TestCombinedSampling() {
    PrintTestHeader("Combined Sampling (Top-K + Top-P + Temperature)");
    
    float logits[] = {10.0f, 8.0f, 6.0f, 4.0f, 2.0f, 1.0f, 0.5f, 0.1f};
    size_t vocab_size = 8;
    
    SamplingConfig config;
    config.temperature = 0.8f;
    config.top_k = 5;
    config.top_p = 0.95f;
    config.seed = 12345;
    
    SamplingContext ctx(config);
    
    // Sample many times
    std::map<int, int> counts;
    for (int i = 0; i < 1000; ++i) {
        int r = ctx.Sample(logits, vocab_size);
        counts[r]++;
    }
    
    std::cout << "Combined sampling (temp=0.8, top_k=5, top_p=0.95):" << std::endl;
    for (const auto& [token, count] : counts) {
        std::cout << "  Token " << token << ": " << count << " times" << std::endl;
    }
    
    // Should only see tokens 0-4 (top_k=5)
    bool pass = true;
    for (const auto& [token, count] : counts) {
        if (token >= 5) {
            pass = false;
            std::cout << "ERROR: Token " << token << " should not appear" << std::endl;
        }
    }
    
    std::cout << "Result: " << (pass ? "PASS" : "FAIL") << std::endl;
    return pass;
}

// ============================================================================
// Test 7: Probability Distribution
// ============================================================================
static bool TestProbabilityDistribution() {
    PrintTestHeader("Probability Distribution");
    
    float logits[] = {2.0f, 1.0f, 0.0f, -1.0f};
    size_t vocab_size = 4;
    
    auto probs = LogitsToProbs(logits, vocab_size);
    
    std::cout << "Logits: [2.0, 1.0, 0.0, -1.0]" << std::endl;
    std::cout << "Probabilities:" << std::endl;
    
    float sum = 0.0f;
    for (size_t i = 0; i < vocab_size; ++i) {
        std::cout << "  Token " << i << ": " << std::fixed << std::setprecision(6) 
                  << probs[i] << std::endl;
        sum += probs[i];
    }
    
    std::cout << "Sum: " << sum << std::endl;
    
    bool pass = FloatEquals(sum, 1.0f, 1e-5f);
    
    // Check ordering is preserved
    for (size_t i = 1; i < vocab_size; ++i) {
        if (probs[i] > probs[i-1]) {
            pass = false;
            std::cout << "ERROR: Probabilities not in descending order" << std::endl;
        }
    }
    
    std::cout << "Result: " << (pass ? "PASS" : "FAIL") << std::endl;
    return pass;
}

// ============================================================================
// Test 8: Get Top Tokens
// ============================================================================
static bool TestGetTopTokens() {
    PrintTestHeader("Get Top Tokens");
    
    float logits[] = {5.0f, 3.0f, 4.0f, 1.0f, 2.0f};
    size_t vocab_size = 5;
    
    auto top = GetTopTokens(logits, vocab_size, 3);
    
    std::cout << "Logits: [5.0, 3.0, 4.0, 1.0, 2.0]" << std::endl;
    std::cout << "Top 3 tokens:" << std::endl;
    
    int expected_tokens[] = {0, 2, 1};  // Sorted by logit
    bool pass = (top.size() == 3);
    
    for (size_t i = 0; i < top.size(); ++i) {
        std::cout << "  Token " << top[i].token_id << ": logit=" << top[i].logit
                  << ", prob=" << std::fixed << std::setprecision(4) << top[i].probability << std::endl;
        if (top[i].token_id != expected_tokens[i]) {
            pass = false;
        }
    }
    
    std::cout << "Result: " << (pass ? "PASS" : "FAIL") << std::endl;
    return pass;
}

// ============================================================================
// Test 9: Logit Validation
// ============================================================================
static bool TestLogitValidation() {
    PrintTestHeader("Logit Validation");
    
    // Valid logits
    float valid[] = {1.0f, 2.0f, 3.0f};
    bool pass = ValidateLogits(valid, 3);
    std::cout << "Valid logits: " << (pass ? "PASS" : "FAIL") << std::endl;
    
    // Invalid logits (NaN)
    float invalid_nan[] = {1.0f, std::nanf(""), 3.0f};
    pass = pass && !ValidateLogits(invalid_nan, 3);
    std::cout << "NaN in logits: " << (!pass ? "PASS" : "FAIL") << std::endl;
    
    // Invalid logits (Inf)
    float invalid_inf[] = {1.0f, std::numeric_limits<float>::infinity(), 3.0f};
    pass = pass && !ValidateLogits(invalid_inf, 3);
    std::cout << "Inf in logits: " << (!pass ? "PASS" : "FAIL") << std::endl;
    
    // Sanitize
    float to_sanitize[] = {1.0f, std::nanf(""), std::numeric_limits<float>::infinity()};
    SanitizeLogits(to_sanitize, 3);
    pass = pass && ValidateLogits(to_sanitize, 3);
    std::cout << "After sanitization: " << (pass ? "PASS" : "FAIL") << std::endl;
    
    std::cout << "Result: " << (pass ? "PASS" : "FAIL") << std::endl;
    return pass;
}

// ============================================================================
// Test 10: Deterministic Sampling
// ============================================================================
static bool TestDeterministicSampling() {
    PrintTestHeader("Deterministic Sampling (Fixed Seed)");
    
    float logits[] = {5.0f, 4.0f, 3.0f, 2.0f, 1.0f};
    size_t vocab_size = 5;
    
    SamplingConfig config;
    config.temperature = 1.0f;
    config.seed = 12345;  // Fixed seed
    
    SamplingContext ctx1(config);
    SamplingContext ctx2(config);
    
    // Sample multiple times from both contexts
    bool same = true;
    for (int i = 0; i < 10; ++i) {
        int r1 = ctx1.Sample(logits, vocab_size);
        int r2 = ctx2.Sample(logits, vocab_size);
        if (r1 != r2) {
            same = false;
            std::cout << "Mismatch at sample " << i << ": " << r1 << " vs " << r2 << std::endl;
        }
    }
    
    std::cout << "Same sequence with same seed: " << (same ? "YES" : "NO") << std::endl;
    
    // Reset and verify
    ctx1.Reset();
    ctx2.Reset();
    
    int first1 = ctx1.Sample(logits, vocab_size);
    int first2 = ctx2.Sample(logits, vocab_size);
    
    bool pass = same && (first1 == first2);
    std::cout << "After reset, same first sample: " << (pass ? "YES" : "NO") << std::endl;
    
    std::cout << "Result: " << (pass ? "PASS" : "FAIL") << std::endl;
    return pass;
}

// ============================================================================
// Main
// ============================================================================
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "C5: Token Sampling Test Suite" << std::endl;
    std::cout << "========================================" << std::endl;
    
    int passed = 0;
    int total = 0;
    
    if (TestGreedySampling()) ++passed; ++total;
    if (TestTemperatureScaling()) ++passed; ++total;
    if (TestTopKSampling()) ++passed; ++total;
    if (TestTopPSampling()) ++passed; ++total;
    if (TestRepetitionPenalty()) ++passed; ++total;
    if (TestCombinedSampling()) ++passed; ++total;
    if (TestProbabilityDistribution()) ++passed; ++total;
    if (TestGetTopTokens()) ++passed; ++total;
    if (TestLogitValidation()) ++passed; ++total;
    if (TestDeterministicSampling()) ++passed; ++total;
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "Results: " << passed << "/" << total << " tests passed" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return (passed == total) ? 0 : 1;
}
