// ============================================================================
// sovereign_inference_pipeline.hpp - End-to-End Sovereign Inference
// ============================================================================
// Complete inference pipeline: Text → Tokens → Model → Tokens → Text
// Zero external dependencies. Fully sovereign.
//
// Architecture:
//   Input Text
//      ↓
//   SovereignTokenizer (BPE)
//      ↓
//   Token IDs
//      ↓
//   StreamingMultiLayerBackend (70B+ capable)
//      ↓
//   Logits → Sampling
//      ↓
//   Token IDs
//      ↓
//   SovereignTokenizer (Decode)
//      ↓
//   Output Text
// ============================================================================

#pragma once

#include "sovereign_tokenizer.hpp"
#include "streaming_multi_layer_backend.hpp"
#include <memory>
#include <string>
#include <vector>

namespace RawrXD {
namespace Runtime {

// ============================================================================
// Generation Configuration
// ============================================================================
struct GenerationConfig {
    // Token sampling
    float temperature = 0.8f;      // 0.0 = greedy, 1.0 = random
    int top_k = 40;              // 0 = disabled
    float top_p = 0.95f;         // Nucleus sampling
    
    // Length limits
    size_t max_new_tokens = 256;
    size_t max_context_length = 4096;
    
    // Special tokens
    bool add_bos = true;         // Add BOS to prompt
    bool add_eos = false;        // Stop on EOS
    
    // Stopping criteria
    std::vector<std::string> stop_strings;  // Stop on these strings
    
    // Callback
    using TokenCallback = void(*)(uint32_t token_id, const std::string& token_text, void* user_data);
    TokenCallback on_token = nullptr;
    void* user_data = nullptr;
};

// ============================================================================
// SovereignInferencePipeline - Complete Text-to-Text Inference
// ============================================================================
class SovereignInferencePipeline {
public:
    SovereignInferencePipeline();
    ~SovereignInferencePipeline();

    // Initialize pipeline
    // tokenizer_path: path to tokenizer.json
    // model_path: path to GGUF model
    bool Initialize(
        const std::string& tokenizer_path,
        const std::string& model_path
    );
    
    // Check if initialized
    bool IsInitialized() const { return m_initialized; }

    // Generate text from prompt
    // prompt: input text
    // config: generation parameters
    // Returns: generated text
    std::string Generate(
        const std::string& prompt,
        const GenerationConfig& config = {}
    );
    
    // Generate with streaming output
    // callback called for each generated token
    void GenerateStreaming(
        const std::string& prompt,
        const GenerationConfig& config,
        std::string& output_accumulator
    );

    // Token counting (useful for context management)
    size_t CountTokens(const std::string& text) const;
    
    // Get tokenizer info
    size_t GetVocabSize() const;
    std::string GetModelInfo() const;

    // Reset conversation state
    void Reset();

private:
    // Components
    std::unique_ptr<SovereignTokenizer> m_tokenizer;
    std::unique_ptr<StreamingMultiLayerBackend> m_backend;
    std::unique_ptr<StreamingGGUFLoader> m_loader;
    
    // State
    bool m_initialized = false;
    std::vector<uint32_t> m_conversation_history;  // For multi-turn
    
    // Sampling helpers
    uint32_t SampleToken(const float* logits, const GenerationConfig& config);
    uint32_t GreedySample(const float* logits);
    uint32_t TopKSample(const float* logits, int k, float temperature);
    uint32_t TopPSample(const float* logits, float p, float temperature);
};

// ============================================================================
// Convenience Functions
// ============================================================================
// Quick generation without managing pipeline
std::string SovereignGenerate(
    const std::string& tokenizer_path,
    const std::string& model_path,
    const std::string& prompt,
    const GenerationConfig& config = {}
);

} // namespace Runtime
} // namespace RawrXD
