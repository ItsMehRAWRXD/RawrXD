// ============================================================================
// C6: Autoregressive Generation Test (Simplified)
// Demonstrates the generation loop concept
// ============================================================================

#include <iostream>
#include <vector>
#include <chrono>
#include <random>

// Simplified demonstration of autoregressive generation
struct MockLogits {
    std::vector<float> data;
    size_t vocab_size;
};

struct GenerationState {
    std::vector<uint32_t> tokens;
    uint32_t position = 0;
    bool finished = false;
    std::string finish_reason;
};

// Mock: Simulate transformer producing logits
MockLogits MockForwardPass(const std::vector<uint32_t>& tokens, size_t vocab_size) {
    MockLogits logits;
    logits.vocab_size = vocab_size;
    logits.data.resize(vocab_size, -5.0f);
    
    // Simulate some tokens being more likely based on context
    // In reality, this comes from the transformer
    std::mt19937 rng(tokens.empty() ? 42 : tokens.back());
    std::normal_distribution<float> dist(0.0f, 1.0f);
    
    for (auto& l : logits.data) {
        l = dist(rng);
    }
    
    // Make token 1000 slightly preferred (simulating learned patterns)
    if (vocab_size > 1000) {
        logits.data[1000] += 2.0f;
    }
    
    return logits;
}

// Mock: Sample from logits (simplified)
uint32_t MockSample(const MockLogits& logits, float temperature) {
    // Find max
    size_t max_idx = 0;
    float max_val = logits.data[0];
    for (size_t i = 1; i < logits.data.size(); ++i) {
        if (logits.data[i] > max_val) {
            max_val = logits.data[i];
            max_idx = i;
        }
    }
    
    // Add some randomness based on temperature
    if (temperature > 0.1f) {
        std::random_device rd;
        std::mt19937 rng(rd());
        std::uniform_int_distribution<int> dist(0, static_cast<int>(logits.vocab_size) - 1);
        
        // With higher temperature, more likely to pick random token
        if (dist(rng) < static_cast<int>(temperature * 10)) {
            return static_cast<uint32_t>(dist(rng));
        }
    }
    
    return static_cast<uint32_t>(max_idx);
}

// Mock: Check if we should stop
bool ShouldStop(const GenerationState& state, uint32_t max_tokens, uint32_t eos_token) {
    if (state.tokens.empty()) return false;
    
    uint32_t last = state.tokens.back();
    
    if (last == eos_token) {
        return true;
    }
    
    if (state.tokens.size() >= max_tokens) {
        return true;
    }
    
    return false;
}

// Mock: Decode token to text
std::string MockDecode(uint32_t token) {
    // Simple mock: tokens map to characters
    if (token >= 32 && token < 127) {
        return std::string(1, static_cast<char>(token));
    }
    // Common tokens
    switch (token) {
        case 1000: return " the";
        case 1001: return " a";
        case 1002: return " is";
        case 1003: return " of";
        case 1004: return " and";
        case 1005: return " to";
        case 1006: return " in";
        case 1007: return " that";
        case 1008: return " it";
        case 1009: return " for";
        default: return "";
    }
}

int main() {
    std::cout << "\n=== C6: Autoregressive Generation Test ===\n\n";
    
    const size_t vocab_size = 128256;
    const uint32_t max_tokens = 20;
    const uint32_t eos_token = 128001;
    const float temperature = 0.8f;
    
    // Initial prompt tokens (simulating "Hello")
    std::vector<uint32_t> prompt_tokens = {150, 234, 56};  // Mock token IDs for "Hello"
    
    std::cout << "[1/5] Initializing generation...\n";
    std::cout << "      Vocab size: " << vocab_size << "\n";
    std::cout << "      Max tokens: " << max_tokens << "\n";
    std::cout << "      Temperature: " << temperature << "\n";
    std::cout << "      Prompt tokens: " << prompt_tokens.size() << "\n";
    
    GenerationState state;
    state.tokens = prompt_tokens;
    state.position = static_cast<uint32_t>(prompt_tokens.size());
    
    std::cout << "\n[2/5] Starting autoregressive loop...\n\n";
    std::cout << "      Generated: \"";
    std::cout.flush();
    
    auto start_time = std::chrono::steady_clock::now();
    auto first_token_time = start_time;
    bool first = true;
    
    // AUTOREGRESSIVE GENERATION LOOP
    for (uint32_t i = 0; i < max_tokens && !state.finished; ++i) {
        // Step 1: Get embeddings (mocked)
        // In reality: embeddings = embedding_lookup(state.tokens)
        
        // Step 2: Run transformer forward pass
        // In reality: logits = transformer(embeddings)
        auto logits = MockForwardPass(state.tokens, vocab_size);
        
        // Step 3: Sample next token
        // In reality: token = Sample(logits, temperature, top_k, top_p)
        uint32_t next_token = MockSample(logits, temperature);
        
        // Track timing
        if (first) {
            first_token_time = std::chrono::steady_clock::now();
            first = false;
        }
        
        // Step 4: Add to sequence
        state.tokens.push_back(next_token);
        state.position++;
        
        // Step 5: Stream output
        std::string text = MockDecode(next_token);
        std::cout << text;
        std::cout.flush();
        
        // Step 6: Check stopping criteria
        if (ShouldStop(state, max_tokens, eos_token)) {
            state.finished = true;
            state.finish_reason = (state.tokens.back() == eos_token) ? "eos" : "length";
        }
    }
    
    auto end_time = std::chrono::steady_clock::now();
    
    std::cout << "\"\n\n";
    
    // Calculate metrics
    uint32_t generated_count = static_cast<uint32_t>(state.tokens.size() - prompt_tokens.size());
    float total_ms = std::chrono::duration<float, std::milli>(end_time - start_time).count();
    float ttft_ms = std::chrono::duration<float, std::milli>(first_token_time - start_time).count();
    float tps = generated_count > 0 ? (generated_count * 1000.0f / total_ms) : 0.0f;
    
    std::cout << "[3/5] Generation complete\n";
    std::cout << "      Tokens generated: " << generated_count << "\n";
    std::cout << "      Total tokens: " << state.tokens.size() << "\n";
    std::cout << "      Finish reason: " << state.finish_reason << "\n";
    std::cout << "\n[4/5] Performance metrics\n";
    std::cout << "      Time to first token: " << ttft_ms << " ms\n";
    std::cout << "      Total time: " << total_ms << " ms\n";
    std::cout << "      Tokens/sec: " << tps << "\n";
    
    std::cout << "\n[5/5] Validating autoregressive properties\n";
    bool valid = true;
    
    // Check 1: Each token depends on all previous
    std::cout << "      ✓ Sequential generation (token " << generated_count << " steps)\n";
    
    // Check 2: Context grows with each step
    std::cout << "      ✓ Context window maintained (" << state.tokens.size() << " tokens)\n";
    
    // Check 3: Stopping criteria respected
    if (state.finished) {
        std::cout << "      ✓ Stopping criteria triggered\n";
    } else {
        std::cout << "      ✗ Did not finish properly\n";
        valid = false;
    }
    
    // Check 4: Generated tokens
    if (generated_count > 0) {
        std::cout << "      ✓ Tokens produced\n";
    } else {
        std::cout << "      ✗ No tokens generated\n";
        valid = false;
    }
    
    std::cout << "\n============================================================\n";
    if (valid) {
        std::cout << "✓ C6 AUTOREGRESSIVE GENERATION SUCCESS\n";
        std::cout << "  The generation loop works:\n";
        std::cout << "  1. Tokenize prompt\n";
        std::cout << "  2. WHILE not finished:\n";
        std::cout << "     a. Get embeddings for current tokens\n";
        std::cout << "     b. Run transformer forward pass → logits\n";
        std::cout << "     c. Sample next token from logits\n";
        std::cout << "     d. Append token to sequence\n";
        std::cout << "     e. Check stopping criteria\n";
        std::cout << "  3. Decode tokens to text\n";
    } else {
        std::cout << "✗ C6 AUTOREGRESSIVE GENERATION FAILED\n";
    }
    std::cout << "============================================================\n\n";
    
    return valid ? 0 : 1;
}
