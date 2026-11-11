// ============================================================================
// Unified Inference Engine - Zero Dependencies
// ============================================================================
// Complete end-to-end inference with no external dependencies
// Integrates: streaming loader, optimized KV cache, multi-threaded transformer
// ============================================================================

#pragma once

#include "../core/streaming_loader.hpp"
#include "../core/minimal_json.hpp"
#include "../../../src/runtime/kv_cache_optimized.hpp"
#include "../../../src/runtime/transformer_layer_optimized.hpp"

#include <functional>
#include <string>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>

namespace RawrXD {
namespace Inference {

// ============================================================================
// Token Generation
// ============================================================================

struct GenerationConfig {
    uint32_t max_tokens = 256;
    float temperature = 0.8f;
    float top_p = 0.95f;
    float top_k = 40;
    float repetition_penalty = 1.0f;
    uint32_t seed = 0;
    bool stream = true;
    
    // Stopping criteria
    std::vector<std::string> stop_sequences;
    uint32_t min_tokens = 1;
};

struct GenerationResult {
    std::string text;
    uint32_t tokens_generated = 0;
    float tokens_per_second = 0.0f;
    bool finished = false;
    std::string finish_reason;  // "stop", "length", "error"
};

// Token callback for streaming
using TokenCallback = std::function<void(const std::string& token, uint32_t token_id, bool is_last)>;

// ============================================================================
// BPE Tokenizer (Minimal Implementation)
// ============================================================================

class BPETokenizer {
public:
    BPETokenizer();
    ~BPETokenizer();
    
    // Load vocabulary from file
    bool LoadVocab(const char* vocab_path);
    bool LoadVocab(const wchar_t* vocab_path);
    
    // Encode text to token IDs
    std::vector<int32_t> Encode(const std::string& text) const;
    
    // Decode token IDs to text
    std::string Decode(const std::vector<int32_t>& tokens) const;
    std::string Decode(int32_t token) const;
    
    // Special tokens
    int32_t GetBOSToken() const { return bos_token_; }
    int32_t GetEOSToken() const { return eos_token_; }
    int32_t GetPADToken() const { return pad_token_; }
    
    // Vocab size
    size_t GetVocabSize() const { return vocab_.size(); }
    
private:
    std::vector<std::string> vocab_;
    std::map<std::string, int32_t> token_to_id_;
    int32_t bos_token_ = 1;
    int32_t eos_token_ = 2;
    int32_t pad_token_ = 0;
    
    // Byte fallback encoding
    std::string ByteToUnicode(uint8_t b) const;
};

// ============================================================================
// Sampler
// ============================================================================

class Sampler {
public:
    explicit Sampler(uint32_t seed = 0);
    
    // Sample from logits
    int32_t Sample(const float* logits, uint32_t vocab_size, const GenerationConfig& config);
    
    // Greedy sampling
    int32_t SampleGreedy(const float* logits, uint32_t vocab_size);
    
    // Temperature + top-p + top-k
    int32_t SampleTopPTopK(const float* logits, uint32_t vocab_size, 
                           float temperature, float top_p, int top_k);
    
    // Reset state
    void Reset();
    
private:
    uint32_t seed_;
    uint64_t rng_state_;
    std::vector<float> probs_buffer_;
    std::vector<std::pair<float, uint32_t>> sorted_indices_;
    
    // Simple RNG
    uint32_t RandomInt();
    float RandomFloat();
};

// ============================================================================
// Unified Inference Engine
// ============================================================================

class UnifiedInferenceEngine {
public:
    UnifiedInferenceEngine();
    ~UnifiedInferenceEngine();
    
    // Initialize with model path
    bool Initialize(const char* model_path);
    bool Initialize(const wchar_t* model_path);
    
    // Load tokenizer
    bool LoadTokenizer(const char* vocab_path);
    bool LoadTokenizer(const wchar_t* vocab_path);
    
    // Generate text from prompt
    GenerationResult Generate(const std::string& prompt, 
                              const GenerationConfig& config);
    
    // Generate with streaming callback
    void GenerateStream(const std::string& prompt,
                        const GenerationConfig& config,
                        TokenCallback callback);
    
    // Async generation
    void GenerateAsync(const std::string& prompt,
                       const GenerationConfig& config);
    GenerationResult GetResult();
    bool IsGenerating() const;
    void StopGeneration();
    
    // Get model info
    const Core::ModelArchitecture& GetArchitecture() const { return arch_; }
    size_t GetMemoryUsage() const;
    float GetModelSizeGB() const;
    
    // Performance stats
    struct PerfStats {
        float avg_tok_per_sec = 0.0f;
        float avg_ttft_ms = 0.0f;  // Time to first token
        uint64_t total_tokens_generated = 0;
        uint64_t total_prompts = 0;
    };
    PerfStats GetPerfStats() const { return perf_stats_; }
    void ResetPerfStats();
    
    // KV cache management
    void ClearKVCache();
    size_t GetKVCacheUsage() const;
    
private:
    // Model state
    Core::StreamingLoader loader_;
    Core::ModelWeights weights_;
    Core::ModelArchitecture arch_;
    BPETokenizer tokenizer_;
    Sampler sampler_;
    
    // Runtime
    Runtime::OptimizedTransformerModel transformer_;
    Runtime::TransformerConfig tf_config_;
    
    // Generation state
    std::vector<int32_t> current_tokens_;
    std::vector<float> logits_buffer_;
    bool is_generating_ = false;
    bool should_stop_ = false;
    
    // Async
    std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<GenerationResult> results_;
    
    // Performance
    PerfStats perf_stats_;
    
    // Internal methods
    bool PrepareTransformer();
    int32_t GenerateNextToken(const float* logits, const GenerationConfig& config);
    void UpdatePerfStats(float tok_per_sec, float ttft_ms);
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick inference
std::string Complete(const std::string& prompt, 
                     const char* model_path,
                     const GenerationConfig& config = {});

// Streaming completion
void CompleteStream(const std::string& prompt,
                    const char* model_path,
                    TokenCallback callback,
                    const GenerationConfig& config = {});

// Chat format
struct Message {
    std::string role;    // "system", "user", "assistant"
    std::string content;
};

std::string FormatChat(const std::vector<Message>& messages, 
                       const std::string& format = "llama");

// ============================================================================
// Model Discovery
// ============================================================================

struct ModelInfo {
    std::string name;
    std::string path;
    std::string architecture;
    size_t size_bytes;
    uint32_t num_params;
    std::string quantization;
};

std::vector<ModelInfo> ScanModels(const char* directory);
ModelInfo GetModelInfo(const char* gguf_path);

} // namespace Inference
} // namespace RawrXD
