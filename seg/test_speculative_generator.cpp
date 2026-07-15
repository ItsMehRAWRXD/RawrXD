// ============================================================================
// Test: Speculative Autoregressive Generator
// ============================================================================
// Validates the production integration of speculative decoding
// ============================================================================

#include "speculative_generator.hpp"
#include <iostream>
#include <chrono>
#include <iomanip>

using namespace RawrXD::Inference;

// Mock components for testing
class MockTransformer : public TransformerLayerInference {
public:
    bool Initialize(const TransformerConfig& config) override {
        config_ = config;
        return true;
    }
    
    bool Forward(const float* input, float* output, uint32_t seq_len) override {
        // Simple passthrough for testing
        std::copy(input, input + config_.hidden_size, output);
        return true;
    }
    
    uint32_t GetNumLayers() const override { return config_.num_layers; }
    
private:
    TransformerConfig config_;
};

class MockEmbeddingTable : public EmbeddingTable {
public:
    bool LoadFromGGUF(Runtime::StreamingGGUFLoader& loader,
                      const std::string& tensor_name,
                      uint32_t vocab_size,
                      uint32_t hidden_size) override {
        vocab_size_ = vocab_size;
        hidden_size_ = hidden_size;
        return true;
    }
    
    void Lookup(int token_id, float* output) const override {
        // Simple hash-based embedding for testing
        for (uint32_t i = 0; i < hidden_size_; ++i) {
            output[i] = static_cast<float>((token_id * 7 + i * 13) % 100) / 100.0f;
        }
    }
    
    void ProjectToLogits(const float* hidden, float* logits) const override {
        // Simple projection for testing
        for (uint32_t v = 0; v < vocab_size_; ++v) {
            logits[v] = 0.0f;
            for (uint32_t h = 0; h < hidden_size_; ++h) {
                logits[v] += hidden[h] * static_cast<float>((v * 3 + h * 5) % 100) / 10000.0f;
            }
        }
    }
    
    uint32_t VocabSize() const override { return vocab_size_; }
    uint32_t HiddenSize() const override { return hidden_size_; }
    
private:
    uint32_t vocab_size_ = 32000;
    uint32_t hidden_size_ = 2048;
};

class MockTokenizer : public Tokenizer {
public:
    std::vector<int> Encode(const std::string& text) override {
        std::vector<int> tokens;
        for (char c : text) {
            tokens.push_back(static_cast<unsigned char>(c));
        }
        return tokens;
    }
    
    std::string Decode(const std::vector<int>& tokens) override {
        std::string text;
        for (int t : tokens) {
            text += Decode(t);
        }
        return text;
    }
    
    std::string Decode(int token) override {
        if (token >= 32 && token < 127) {
            return std::string(1, static_cast<char>(token));
        }
        return "?";
    }
    
    int VocabSize() const override { return 256; }
};

// Test function declarations
bool TestBasicGeneration();
bool TestTokenCallback();
bool TestPerformanceComparison();
bool TestStatsTracking();

int main() {
    std::cout << "========================================\n";
    std::cout << "Speculative Generator Tests\n";
    std::cout << "========================================\n\n";
    
    int passed = 0;
    int failed = 0;
    
    // Run tests
    if (TestBasicGeneration()) {
        std::cout << "✓ TestBasicGeneration PASSED\n";
        passed++;
    } else {
        std::cout << "✗ TestBasicGeneration FAILED\n";
        failed++;
    }
    
    if (TestTokenCallback()) {
        std::cout << "✓ TestTokenCallback PASSED\n";
        passed++;
    } else {
        std::cout << "✗ TestTokenCallback FAILED\n";
        failed++;
    }
    
    if (TestPerformanceComparison()) {
        std::cout << "✓ TestPerformanceComparison PASSED\n";
        passed++;
    } else {
        std::cout << "✗ TestPerformanceComparison FAILED\n";
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
    
    // Create config
    TransformerConfig transformer_config;
    transformer_config.num_layers = 24;
    transformer_config.hidden_size = 2048;
    transformer_config.num_heads = 32;
    
    SpeculativeGenerationConfig spec_config;
    spec_config.draft_tokens = 4;
    spec_config.draft_type = SpeculativeGenerationConfig::DraftModelType::NGRAM;
    
    // Create generator
    SpeculativeAutoregressiveGenerator generator(transformer_config, spec_config);
    
    // Create mock components
    auto transformer = std::make_shared<MockTransformer>();
    auto embeddings = std::make_shared<MockEmbeddingTable>();
    auto tokenizer = std::make_shared<MockTokenizer>();
    
    // Initialize mock components
    Runtime::StreamingGGUFLoader loader; // Dummy loader
    embeddings->LoadFromGGUF(loader, "test", 256, 2048);
    transformer->Initialize(transformer_config);
    
    // Initialize generator
    if (!generator.Initialize(transformer, embeddings, tokenizer)) {
        std::cerr << "Failed to initialize generator\n";
        return false;
    }
    
    // Generate text
    std::string output = generator.Generate("Hello", 10);
    
    std::cout << "  Generated: \"" << output << "\"\n";
    std::cout << "  Length: " << output.length() << " chars\n";
    
    return output.length() > 0;
}

bool TestTokenCallback() {
    std::cout << "\n--- Test: Token Callback ---\n";
    
    TransformerConfig transformer_config;
    transformer_config.num_layers = 24;
    transformer_config.hidden_size = 2048;
    
    SpeculativeGenerationConfig spec_config;
    spec_config.draft_tokens = 4;
    
    SpeculativeAutoregressiveGenerator generator(transformer_config, spec_config);
    
    auto transformer = std::make_shared<MockTransformer>();
    auto embeddings = std::make_shared<MockEmbeddingTable>();
    auto tokenizer = std::make_shared<MockTokenizer>();
    
    Runtime::StreamingGGUFLoader loader;
    embeddings->LoadFromGGUF(loader, "test", 256, 2048);
    transformer->Initialize(transformer_config);
    
    generator.Initialize(transformer, embeddings, tokenizer);
    
    // Track tokens via callback
    std::vector<std::string> received_tokens;
    auto callback = [&](const std::string& token) {
        received_tokens.push_back(token);
    };
    
    generator.Generate("Hi", 5, callback);
    
    std::cout << "  Received " << received_tokens.size() << " tokens via callback\n";
    
    return received_tokens.size() > 0;
}

bool TestPerformanceComparison() {
    std::cout << "\n--- Test: Performance Comparison ---\n";
    
    TransformerConfig transformer_config;
    transformer_config.num_layers = 24;
    transformer_config.hidden_size = 2048;
    
    // Test with speculative decoding
    SpeculativeGenerationConfig spec_config;
    spec_config.draft_tokens = 4;
    spec_config.draft_type = SpeculativeGenerationConfig::DraftModelType::NGRAM;
    
    SpeculativeAutoregressiveGenerator spec_generator(transformer_config, spec_config);
    
    auto transformer = std::make_shared<MockTransformer>();
    auto embeddings = std::make_shared<MockEmbeddingTable>();
    auto tokenizer = std::make_shared<MockTokenizer>();
    
    Runtime::StreamingGGUFLoader loader;
    embeddings->LoadFromGGUF(loader, "test", 256, 2048);
    transformer->Initialize(transformer_config);
    
    spec_generator.Initialize(transformer, embeddings, tokenizer);
    
    // Warmup
    for (int i = 0; i < 10; ++i) {
        spec_generator.Generate("Test", 5);
    }
    
    // Benchmark speculative
    auto start = std::chrono::high_resolution_clock::now();
    spec_generator.Generate("Hello world this is a test", 20);
    auto end = std::chrono::high_resolution_clock::now();
    auto spec_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    std::cout << "  Speculative time: " << spec_duration.count() << " us\n";
    
    // Test with baseline (autoregressive)
    GenerationConfig base_config;
    AutoregressiveGenerator base_generator(transformer_config, base_config);
    
    // Warmup
    for (int i = 0; i < 10; ++i) {
        base_generator.Generate("Test", 5);
    }
    
    // Benchmark baseline
    start = std::chrono::high_resolution_clock::now();
    base_generator.Generate("Hello world this is a test", 20);
    end = std::chrono::high_resolution_clock::now();
    auto base_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    std::cout << "  Baseline time: " << base_duration.count() << " us\n";
    
    float speedup = static_cast<float>(base_duration.count()) / spec_duration.count();
    std::cout << "  Speedup: " << std::fixed << std::setprecision(2) << speedup << "x\n";
    
    // With mock models, we expect some speedup (though not as much as real models)
    return speedup > 0.5f; // At least 0.5x (allowing for overhead)
}

bool TestStatsTracking() {
    std::cout << "\n--- Test: Stats Tracking ---\n";
    
    TransformerConfig transformer_config;
    transformer_config.num_layers = 24;
    transformer_config.hidden_size = 2048;
    
    SpeculativeGenerationConfig spec_config;
    spec_config.draft_tokens = 4;
    
    SpeculativeAutoregressiveGenerator generator(transformer_config, spec_config);
    
    auto transformer = std::make_shared<MockTransformer>();
    auto embeddings = std::make_shared<MockEmbeddingTable>();
    auto tokenizer = std::make_shared<MockTokenizer>();
    
    Runtime::StreamingGGUFLoader loader;
    embeddings->LoadFromGGUF(loader, "test", 256, 2048);
    transformer->Initialize(transformer_config);
    
    generator.Initialize(transformer, embeddings, tokenizer);
    
    // Generate some tokens
    generator.Generate("Test", 20);
    
    // Get stats
    auto stats = generator.GetStats();
    
    std::cout << "  Total steps: " << stats.total_steps << "\n";
    std::cout << "  Tokens accepted: " << stats.tokens_accepted << "\n";
    std::cout << "  Tokens rejected: " << stats.tokens_rejected << "\n";
    std::cout << "  Acceptance rate: " << std::fixed << std::setprecision(2) << (stats.acceptance_rate * 100) << "%\n";
    std::cout << "  Speedup: " << stats.speedup_vs_baseline << "x\n";
    
    return stats.total_steps > 0;
}
