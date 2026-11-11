// ============================================================================
// Simple Speculative Decoding Benchmark
// ============================================================================
// Standalone benchmark comparing autoregressive vs speculative decoding
// ============================================================================

#include <iostream>
#include <chrono>
#include <vector>
#include <random>
#include <algorithm>
#include <iomanip>
#include <cmath>

using namespace std;

// Configuration
struct Config {
    uint32_t target_layers = 24;
    uint32_t target_hidden = 2048;
    uint32_t draft_layers = 6;
    uint32_t draft_hidden = 512;
    uint32_t vocab_size = 32000;
    uint32_t draft_tokens = 4;
    float draft_temp = 1.2f;
    float accept_threshold = 0.6f;
};

// Simulate target model forward pass (24 layers)
void TargetForward(const vector<uint32_t>& tokens, vector<float>& logits, const Config& config) {
    // Simulate compute: 24 layers × 2048 hidden
    // Cost: 24 * 2048 = 49,152 units of work
    volatile float accumulator = 0.0f;
    for (uint32_t layer = 0; layer < config.target_layers; layer++) {
        for (uint32_t i = 0; i < config.target_hidden; i++) {
            accumulator += 0.01f * (i + layer);
        }
    }
    
    // Output projection
    logits.resize(config.vocab_size);
    for (uint32_t v = 0; v < config.vocab_size; v++) {
        logits[v] = accumulator + (float)v * 0.0001f;
    }
}

// Simulate draft model forward pass (6 layers)
void DraftForward(const vector<uint32_t>& tokens, vector<float>& logits, const Config& config) {
    // Simulate compute: 6 layers × 512 hidden
    // Cost: 6 * 512 = 3,072 units of work (16x cheaper than target)
    volatile float accumulator = 0.0f;
    for (uint32_t layer = 0; layer < config.draft_layers; layer++) {
        for (uint32_t i = 0; i < config.draft_hidden; i++) {
            accumulator += 0.01f * (i + layer);
        }
    }
    
    // Output projection
    logits.resize(config.vocab_size);
    for (uint32_t v = 0; v < config.vocab_size; v++) {
        logits[v] = accumulator + (float)v * 0.0001f;
    }
}

// Sample from logits
uint32_t Sample(const vector<float>& logits, float temperature) {
    vector<float> probs(logits.size());
    float max_logit = *max_element(logits.begin(), logits.end());
    
    for (size_t i = 0; i < logits.size(); i++) {
        probs[i] = exp((logits[i] - max_logit) / temperature);
    }
    
    // Simple argmax for determinism
    return max_element(probs.begin(), probs.end()) - probs.begin();
}

// Autoregressive generation
vector<uint32_t> GenerateAutoregressive(const vector<uint32_t>& prompt, 
                                       uint32_t num_tokens,
                                       const Config& config) {
    vector<uint32_t> generated = prompt;
    
    for (uint32_t i = 0; i < num_tokens; i++) {
        vector<float> logits;
        TargetForward(generated, logits, config);
        uint32_t token = Sample(logits, 0.8f);
        generated.push_back(token);
    }
    
    return generated;
}

// Speculative generation - PROPER COST MODEL
// Real speculative decoding: K draft passes + 1 target pass (verifies all K at once)
// Cost = K * draft_cost + 1 * target_cost
// With K=4, draft_cost=1/16 target: Cost = 4*(1/16) + 1 = 1.25 target passes for 4 tokens
// Speedup = 4 / 1.25 = 3.2x (theoretical max with 100% acceptance)
vector<uint32_t> GenerateSpeculative(const vector<uint32_t>& prompt,
                                      uint32_t num_tokens,
                                      const Config& config,
                                      uint32_t& draft_proposed,
                                      uint32_t& draft_accepted) {
    vector<uint32_t> generated = prompt;
    draft_proposed = 0;
    draft_accepted = 0;
    
    while (generated.size() < prompt.size() + num_tokens) {
        // Generate draft tokens (K forward passes through draft model)
        vector<uint32_t> draft_tokens;
        vector<uint32_t> draft_context = generated;
        
        for (uint32_t i = 0; i < config.draft_tokens && 
             generated.size() + i < prompt.size() + num_tokens; i++) {
            vector<float> logits;
            DraftForward(draft_context, logits, config);
            uint32_t token = Sample(logits, config.draft_temp);
            draft_tokens.push_back(token);
            draft_context.push_back(token);
        }
        
        draft_proposed += draft_tokens.size();
        
        // OPTIMIZED: Single target forward pass to verify ALL draft tokens
        // In real implementation, target model uses KV cache to process
        // [context + draft_tokens] efficiently in one pass
        vector<uint32_t> verify_sequence = generated;
        verify_sequence.insert(verify_sequence.end(), draft_tokens.begin(), draft_tokens.end());
        
        vector<float> target_logits;
        TargetForward(verify_sequence, target_logits, config);
        
        // Accept/reject logic
        uint32_t accepted = 0;
        for (uint32_t i = 0; i < draft_tokens.size(); i++) {
            // Simulate acceptance check (80% acceptance rate)
            if ((float)rand() / RAND_MAX < 0.8f) {
                generated.push_back(draft_tokens[i]);
                accepted++;
            } else {
                // Reject - sample from target
                generated.push_back(Sample(target_logits, 0.8f));
                break;
            }
        }
        
        draft_accepted += accepted;
    }
    
    return generated;
}

int main() {
    cout << "========================================\n";
    cout << "Speculative Decoding Benchmark\n";
    cout << "========================================\n\n";
    
    Config config;
    uint32_t num_tokens = 128;
    uint32_t num_iterations = 5;
    
    cout << "Configuration:\n";
    cout << "  Target: " << config.target_layers << " layers, " 
         << config.target_hidden << " hidden\n";
    cout << "  Draft: " << config.draft_layers << " layers, " 
         << config.draft_hidden << " hidden\n";
    cout << "  Draft tokens: " << config.draft_tokens << "\n";
    cout << "  Tokens to generate: " << num_tokens << "\n";
    cout << "  Iterations: " << num_iterations << "\n\n";
    
    vector<uint32_t> prompt = {1, 2, 3, 4, 5};
    
    // Warmup
    cout << "Warming up...\n";
    for (uint32_t i = 0; i < 10; i++) {
        GenerateAutoregressive(prompt, 10, config);
        uint32_t dp, da;
        GenerateSpeculative(prompt, 10, config, dp, da);
    }
    
    // Benchmark autoregressive
    cout << "Benchmarking autoregressive...\n";
    auto start = chrono::high_resolution_clock::now();
    for (uint32_t iter = 0; iter < num_iterations; iter++) {
        GenerateAutoregressive(prompt, num_tokens, config);
    }
    auto end = chrono::high_resolution_clock::now();
    double auto_ms = chrono::duration_cast<chrono::microseconds>(end - start).count() / 1000.0;
    double auto_per_iter = auto_ms / num_iterations;
    float auto_tok_s = (num_tokens * 1000.0f) / auto_per_iter;
    
    // Benchmark speculative
    cout << "Benchmarking speculative...\n";
    uint32_t total_draft_proposed = 0;
    uint32_t total_draft_accepted = 0;
    
    start = chrono::high_resolution_clock::now();
    for (uint32_t iter = 0; iter < num_iterations; iter++) {
        uint32_t dp, da;
        GenerateSpeculative(prompt, num_tokens, config, dp, da);
        total_draft_proposed += dp;
        total_draft_accepted += da;
    }
    end = chrono::high_resolution_clock::now();
    double spec_ms = chrono::duration_cast<chrono::microseconds>(end - start).count() / 1000.0;
    double spec_per_iter = spec_ms / num_iterations;
    float spec_tok_s = (num_tokens * 1000.0f) / spec_per_iter;
    
    float accept_rate = (float)total_draft_accepted / total_draft_proposed;
    
    // Results
    cout << "\n========================================\n";
    cout << "Results\n";
    cout << "========================================\n";
    cout << fixed << setprecision(2);
    cout << "  Autoregressive:\n";
    cout << "    Time: " << auto_per_iter << " ms\n";
    cout << "    Tokens/sec: " << auto_tok_s << "\n\n";
    cout << "  Speculative:\n";
    cout << "    Time: " << spec_per_iter << " ms\n";
    cout << "    Tokens/sec: " << spec_tok_s << "\n";
    cout << "    Acceptance rate: " << (accept_rate * 100) << "%\n\n";
    cout << "  Speedup: " << (spec_tok_s / auto_tok_s) << "x\n";
    
    return 0;
}
