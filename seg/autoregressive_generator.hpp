// ============================================================================
// C6: Autoregressive Generator
// ============================================================================
// Complete end-to-end text generation pipeline
// ============================================================================

#ifndef AUTOREGRESSIVE_GENERATOR_HPP
#define AUTOREGRESSIVE_GENERATOR_HPP

#include "transformer_layer_inference.hpp"
#include "token_sampling.hpp"
#include "../runtime/streaming_gguf_loader_v2.hpp"
#include <string>
#include <vector>
#include <memory>

namespace RawrXD {
namespace Inference {

// Sampling strategy enum
enum class SamplingStrategy {
    GREEDY,
    TEMPERATURE,
    TOP_K,
    TOP_P
};

// ============================================================================
// Generation Configuration
// ============================================================================
struct GenerationConfig {
    // Sampling parameters
    float temperature = 0.8f;
    int top_k = 40;
    float top_p = 0.95f;
    float repetition_penalty = 1.1f;
    SamplingStrategy strategy = SamplingStrategy::TOP_P;
    
    // Generation limits
    uint32_t max_tokens = 256;
    uint32_t max_context_length = 4096;
    
    // Special tokens
    int eos_token_id = 2;      // End of sequence
    int pad_token_id = 0;      // Padding
    int bos_token_id = 1;      // Beginning of sequence
    
    // Stop sequences
    std::vector<std::string> stop_sequences;
    
    // Seeding
    uint64_t seed = 0;  // 0 = random
};

// ============================================================================
// Tokenizer Interface (simplified)
// ============================================================================
class Tokenizer {
public:
    virtual ~Tokenizer() = default;
    virtual std::vector<int> Encode(const std::string& text) = 0;
    virtual std::string Decode(const std::vector<int>& tokens) = 0;
    virtual std::string Decode(int token) = 0;
    virtual int VocabSize() const = 0;
};

// Simple ASCII tokenizer for testing
class ASCIITokenizer : public Tokenizer {
public:
    std::vector<int> Encode(const std::string& text) override;
    std::string Decode(const std::vector<int>& tokens) override;
    std::string Decode(int token) override;
    int VocabSize() const override { return 256; }
};

// ============================================================================
// Embedding Table
// ============================================================================
class EmbeddingTable {
public:
    bool LoadFromGGUF(Runtime::StreamingGGUFLoader& loader, 
                      const std::string& tensor_name,
                      uint32_t vocab_size, 
                      uint32_t hidden_size);
    
    // Lookup embedding for token
    void Lookup(int token_id, float* output) const;
    
    // Project hidden state to logits
    void ProjectToLogits(const float* hidden, float* logits) const;
    
    uint32_t VocabSize() const { return vocab_size_; }
    uint32_t HiddenSize() const { return hidden_size_; }
    
private:
    std::vector<float> embeddings_;  // [vocab_size, hidden_size]
    std::vector<float> lm_head_;     // [hidden_size, vocab_size] (often tied)
    uint32_t vocab_size_ = 0;
    uint32_t hidden_size_ = 0;
    bool use_tied_weights_ = true;
};

// ============================================================================
// Token Callback Type
// ============================================================================
using TokenCallback = std::function<void(const std::string& token, int token_id)>;

// ============================================================================
// Autoregressive Generator
// ============================================================================
class AutoregressiveGenerator {
public:
    AutoregressiveGenerator(const TransformerConfig& config,
                           const GenerationConfig& gen_config);
    
    // Initialize with model weights
    bool Initialize(Runtime::StreamingGGUFLoader& loader,
                    std::unique_ptr<Tokenizer> tokenizer);
    
    // Generate text from prompt
    std::string Generate(const std::string& prompt);
    
    // Generate with callback for streaming
    std::string Generate(const std::string& prompt, TokenCallback callback);
    
    // Get generation statistics
    struct GenerationStats {
        uint32_t tokens_generated = 0;
        uint32_t prompt_tokens = 0;
        float time_seconds = 0.0f;
        float tokens_per_second = 0.0f;
        uint32_t cache_hits = 0;
    };
    GenerationStats GetStats() const { return stats_; }
    
    // Reset for new generation
    void Reset();
    
private:
    // Core generation step
    int GenerateNextToken(const float* hidden, const std::vector<int>& context);
    
    // Forward pass through all layers
    bool ForwardPass(const float* input_embedding, float* output_hidden, 
                     uint32_t position);
    
    // Load all layer weights
    bool LoadLayerWeights(Runtime::StreamingGGUFLoader& loader);
    
    TransformerConfig transformer_config_;
    GenerationConfig gen_config_;
    std::unique_ptr<Tokenizer> tokenizer_;
    std::unique_ptr<EmbeddingTable> embeddings_;
    
    // Transformer layers
    std::vector<std::unique_ptr<TransformerLayer>> layers_;
    std::vector<LayerWeights> layer_weights_;
    
    // KV cache for all layers
    std::vector<KVCache> kv_caches_;
    
    // Working buffers
    std::vector<float> hidden_buffer_;
    std::vector<float> output_buffer_;
    std::vector<float> logits_;
    
    // Token history for repetition penalty
    std::vector<int> token_history_;
    
    // Statistics
    GenerationStats stats_;
    
    // Random number generator
    std::mt19937_64 rng_;
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick generation with default settings
std::string GenerateText(const std::string& model_path,
                         const std::string& prompt,
                         const GenerationConfig& config = GenerationConfig{});

// Streaming generation
void GenerateTextStreaming(const std::string& model_path,
                           const std::string& prompt,
                           TokenCallback callback,
                           const GenerationConfig& config = GenerationConfig{});

} // namespace Inference
} // namespace RawrXD

#endif // AUTOREGRESSIVE_GENERATOR_HPP
