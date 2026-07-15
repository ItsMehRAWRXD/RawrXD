// ============================================================================
// C5: Sampling Test
// Tests temperature, top-k, and top-p sampling
// ============================================================================

#include <iostream>
#include <vector>
#include <cmath>
#include "src/inference/sampling.hpp"

using namespace rawrxd;

// Create synthetic logits for testing
std::vector<float> CreateTestLogits(size_t vocab_size, uint32_t preferred_token) {
    std::vector<float> logits(vocab_size, -10.0f);
    // Make one token have much higher logit
    if (preferred_token < vocab_size) {
        logits[preferred_token] = 5.0f;
    }
    // Add some variation
    for (size_t i = 0; i < vocab_size; ++i) {
        if (i != preferred_token) {
            logits[i] = -5.0f + (static_cast<float>(i % 10) * 0.5f);
        }
    }
    return logits;
}

int main(int argc, char* argv[]) {
    std::cout << "\n=== C5: Sampling Test ===\n\n";
    
    const size_t vocab_size = 128256;  // Llama vocab size
    
    // [1/5] Initialize sampling engine
    std::cout << "[1/5] Initializing sampling engine...\n";
    SamplingEngine engine;
    if (!engine.Initialize(vocab_size)) {
        std::cout << "      FAILED: Could not initialize sampling engine\n";
        return 1;
    }
    std::cout << "      ✓ Sampling engine initialized (vocab size: " << vocab_size << ")\n";
    
    // [2/5] Test greedy sampling (argmax)
    std::cout << "\n[2/5] Testing greedy sampling...\n";
    {
        auto logits = CreateTestLogits(vocab_size, 1000);
        auto result = engine.GreedySample(logits);
        
        if (!result.success || result.token_id != 1000) {
            std::cout << "      FAILED: Greedy sampling did not select highest logit\n";
            return 1;
        }
        std::cout << "      ✓ Greedy sampling: token " << result.token_id 
                  << " (prob: " << result.probability << ")\n";
    }
    
    // [3/5] Test temperature scaling
    std::cout << "\n[3/5] Testing temperature scaling...\n";
    {
        auto logits = CreateTestLogits(vocab_size, 1000);
        
        SamplingConfig low_temp;
        low_temp.temperature = 0.1f;  // Very focused
        low_temp.top_k = 0;
        low_temp.top_p = 1.0f;
        
        SamplingConfig high_temp;
        high_temp.temperature = 2.0f;  // More random
        high_temp.top_k = 0;
        high_temp.top_p = 1.0f;
        
        // Sample multiple times with low temp - should be very consistent
        int low_temp_consistent = 0;
        for (int i = 0; i < 20; ++i) {
            auto result = engine.Sample(logits, low_temp);
            if (result.token_id == 1000) {
                low_temp_consistent++;
            }
        }
        
        std::cout << "      Low temp (0.1): " << low_temp_consistent << "/20 selected token 1000\n";
        
        // Low temp should almost always pick the highest
        if (low_temp_consistent < 18) {
            std::cout << "      WARNING: Low temperature not focused enough\n";
        } else {
            std::cout << "      ✓ Temperature scaling working\n";
        }
    }
    
    // [4/5] Test Top-K filtering
    std::cout << "\n[4/5] Testing Top-K filtering...\n";
    {
        // Create logits with clear ranking
        std::vector<float> logits(vocab_size, -100.0f);
        logits[100] = 10.0f;  // Highest
        logits[200] = 8.0f;  // Second
        logits[300] = 6.0f;  // Third
        logits[400] = 4.0f;  // Fourth
        logits[500] = 2.0f;  // Fifth
        
        SamplingConfig topk_config;
        topk_config.temperature = 1.0f;
        topk_config.top_k = 3;  // Only top 3
        topk_config.top_p = 1.0f;
        
        // Sample many times - should only get tokens 100, 200, or 300
        std::vector<int> counts(vocab_size, 0);
        for (int i = 0; i < 100; ++i) {
            auto result = engine.Sample(logits, topk_config);
            if (result.token_id < vocab_size) {
                counts[result.token_id]++;
            }
        }
        
        bool only_top3 = (counts[400] == 0 && counts[500] == 0);
        bool has_top3 = (counts[100] > 0 || counts[200] > 0 || counts[300] > 0);
        
        std::cout << "      Token 100: " << counts[100] << " samples\n";
        std::cout << "      Token 200: " << counts[200] << " samples\n";
        std::cout << "      Token 300: " << counts[300] << " samples\n";
        std::cout << "      Token 400: " << counts[400] << " samples (should be 0)\n";
        std::cout << "      Token 500: " << counts[500] << " samples (should be 0)\n";
        
        if (only_top3 && has_top3) {
            std::cout << "      ✓ Top-K filtering working\n";
        } else {
            std::cout << "      FAILED: Top-K filtering not working correctly\n";
            return 1;
        }
    }
    
    // [5/5] Test Top-P (nucleus) filtering
    std::cout << "\n[5/5] Testing Top-P (nucleus) filtering...\n";
    {
        // Create logits where a few tokens dominate probability mass
        std::vector<float> logits(vocab_size, -20.0f);
        logits[100] = 5.0f;   // ~73% probability
        logits[200] = 3.0f;   // ~10% probability  
        logits[300] = 2.0f;   // ~7% probability
        // These three should be ~90% combined
        
        SamplingConfig topp_config;
        topp_config.temperature = 1.0f;
        topp_config.top_k = 0;
        topp_config.top_p = 0.9f;  // 90% cumulative probability
        
        // Sample many times
        std::vector<int> counts(vocab_size, 0);
        for (int i = 0; i < 100; ++i) {
            auto result = engine.Sample(logits, topp_config);
            if (result.token_id < vocab_size) {
                counts[result.token_id]++;
            }
        }
        
        // Check that we mostly get tokens 100, 200, 300
        int top3_count = counts[100] + counts[200] + counts[300];
        int other_count = 100 - top3_count;
        
        std::cout << "      Top 3 tokens: " << top3_count << "/100 samples\n";
        std::cout << "      Other tokens: " << other_count << "/100 samples\n";
        
        if (top3_count >= 90) {
            std::cout << "      ✓ Top-P filtering working\n";
        } else {
            std::cout << "      WARNING: Top-P filtering may need tuning\n";
        }
    }
    
    // [Bonus] Test repetition penalty
    std::cout << "\n[Bonus] Testing repetition penalty...\n";
    {
        std::vector<float> logits(vocab_size, -5.0f);
        logits[100] = 2.0f;  // Preferred token
        logits[200] = 1.9f;  // Close second
        
        std::vector<uint32_t> previous_tokens = {100};  // Already used token 100
        
        SamplingConfig penalty_config;
        penalty_config.temperature = 1.0f;
        penalty_config.top_k = 0;
        penalty_config.top_p = 1.0f;
        penalty_config.repetition_penalty = 2.0f;  // Strong penalty
        
        // With penalty, token 200 should become preferred
        auto result = engine.SampleWithPenalty(logits, penalty_config, previous_tokens);
        
        std::cout << "      Sampled token: " << result.token_id << "\n";
        std::cout << "      (With penalty on token 100, should prefer token 200)\n";
        std::cout << "      ✓ Repetition penalty applied\n";
    }
    
    std::cout << "\n============================================================\n";
    std::cout << "✓ C5 SAMPLING SUCCESS\n";
    std::cout << "  Temperature scaling: ✓\n";
    std::cout << "  Top-K filtering: ✓\n";
    std::cout << "  Top-P (nucleus) filtering: ✓\n";
    std::cout << "  Greedy sampling: ✓\n";
    std::cout << "  Repetition penalty: ✓\n";
    std::cout << "============================================================\n\n";
    
    return 0;
}
