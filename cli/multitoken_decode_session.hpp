#pragma once
// ============================================================================
// MultiTokenDecodeSession — Native multi-token decoding with persistent KV cache
// ============================================================================
// Purpose: Execute multi-token generation using native IR executor with
// persistent MLA KV cache, position-aware RoPE, and causal attention
// ============================================================================

#include <string>
#include <vector>
#include <array>
#include <memory>
#include <cstdint>
#include <functional>
#include <chrono>

#include "model_context.hpp"
#include "kv_cache.hpp"

namespace RawrXD {
namespace CLI {

// Forward declarations for IR executor types
namespace Generated {
    struct OperationIR;
    struct ModelConfig;
    enum class TensorId : uint32_t;
}

namespace ModelGenie {
    enum class Primitive : uint32_t;
    enum class OperandDomain : uint32_t;
    struct OperandRef;
    enum class GGMLType : uint32_t;
}

// MLA KV Cache for multi-token decoding
class MlaKVCache {
public:
    struct LayerCache {
        // Compressed latent: [max_seq_len, rank + rope] = [max_seq_len, 576]
        std::vector<float> latent;
        
        // Expanded K/V: [max_seq_len, heads * (key + value)] = [max_seq_len, 5120]
        std::vector<float> kv;
        
        size_t max_seq_len = 0;
        size_t rank_plus_rope = 0;  // 512 + 64 = 576
        size_t kv_size = 0;         // 16 * (192 + 128) = 5120
        size_t current_len = 0;
        
        void Init(size_t max_seq_len_, size_t rank_plus_rope_, size_t kv_size_) {
            max_seq_len = max_seq_len_;
            rank_plus_rope = rank_plus_rope_;
            kv_size = kv_size_;
            latent.assign(max_seq_len * rank_plus_rope, 0.0f);
            kv.assign(max_seq_len * kv_size, 0.0f);
            current_len = 0;
        }
        
        // Write latent and expanded K/V at current position, advance position
        bool Write(const float* latent_in, const float* kv_in) {
            if (current_len >= max_seq_len) return false;
            float* latent_dst = latent.data() + current_len * rank_plus_rope;
            float* kv_dst = kv.data() + current_len * kv_size;
            std::memcpy(latent_dst, latent_in, rank_plus_rope * sizeof(float));
            std::memcpy(kv_dst, kv_in, kv_size * sizeof(float));
            current_len++;
            return true;
        }
        
        // Read latent at specific position
        const float* ReadLatent(size_t pos) const {
            if (pos >= current_len) return nullptr;
            return latent.data() + pos * rank_plus_rope;
        }
        
        // Read K/V at specific position
        const float* ReadKV(size_t pos) const {
            if (pos >= current_len) return nullptr;
            return kv.data() + pos * kv_size;
        }
        
        // Read all K/V up to current_len (for attention)
        const float* ReadAllKV() const {
            return kv.data();
        }
        
        size_t Size() const { return current_len; }
        void Reset() { current_len = 0; }
    };
    
    // Per-layer cache array
    std::array<LayerCache, Generated::ModelConfig::kBlockCount> layers;
    size_t max_seq_len = 0;
    
    void Init(size_t max_seq_len_) {
        max_seq_len = max_seq_len_;
        const size_t rank_plus_rope = Generated::ModelConfig::kKvLoraRank + 
                                       Generated::ModelConfig::kRopeDimensionCount; // 576
        const size_t kv_size = Generated::ModelConfig::kHeadCount * 
                               (Generated::ModelConfig::kKeyLength + Generated::ModelConfig::kValueLength); // 5120
        for (auto& layer : layers) {
            layer.Init(max_seq_len, rank_plus_rope, kv_size);
        }
    }
    
    void Reset() {
        for (auto& layer : layers) layer.Reset();
    }
    
    size_t CurrentLen() const { return layers[0].Size(); }
    size_t MaxSeqLen() const { return max_seq_len; }
};

// Decode session configuration
struct DecodeConfig {
    std::string model_path;
    std::string evidence_dir;          // For ModelGenome loading
    uint32_t max_seq_len = 1024;       // KV cache capacity
    uint32_t max_tokens = 64;          // Max tokens to generate
    float temperature = 1.0f;
    int top_k = 40;
    float top_p = 0.9f;
    uint32_t seed = 42;
    bool verbose = false;
    bool capture_activations = false;  // Capture activations for comparison
    std::string activation_output_dir; // Directory for activation dumps
    
    // Reference comparison
    bool enable_reference_comparison = false;
    std::string llama_cpp_path;
};

// Decode step result
struct DecodeStepResult {
    uint32_t token_id = 0;
    std::vector<float> logits;         // Full logits [vocab_size]
    std::vector<ReferenceActivation> activations; // Captured activations
    uint64_t cycles = 0;
    double step_time_ms = 0.0;
    bool success = false;
    std::string error_message;
    
    // Telemetry
    uint32_t position = 0;
    uint32_t seq_len = 0;
};

// Multi-token decode session
class MultiTokenDecodeSession {
public:
    MultiTokenDecodeSession() = default;
    ~MultiTokenDecodeSession() = default;
    
    // Initialize session with model
    bool Initialize(const DecodeConfig& config);
    
    // Prefill: process prompt tokens without generating
    bool Prefill(const std::vector<uint32_t>& prompt_tokens);
    
    // Single decode step: generate next token
    DecodeStepResult DecodeStep();
    
    // Run full generation: prefill + decode
    std::vector<DecodeStepResult> Generate(const std::vector<uint32_t>& prompt_tokens,
                                           uint32_t max_tokens);
    
    // Reset session for new sequence
    void Reset();
    
    // Get current state
    uint32_t GetPosition() const { return m_position; }
    uint32_t GetTokensGenerated() const { return m_tokens_generated; }
    uint32_t GetCurrentSeqLen() const { return m_seq_len; }
    const MlaKVCache& GetKVCache() const { return m_kv_cache; }
    
    // Get telemetry
    struct Telemetry {
        double total_time_ms = 0.0;
        double prefill_time_ms = 0.0;
        double decode_time_ms = 0.0;
        uint64_t total_cycles = 0;
        uint32_t tokens_generated = 0;
        float tokens_per_sec = 0.0f;
    };
    Telemetry GetTelemetry() const { return m_telemetry; }
    
    // Activation capture callback
    using ActivationCallback = std::function<void(uint32_t op_index, const std::string& op_name, 
                                                   const float* data, size_t count, uint32_t position)>;
    void SetActivationCallback(ActivationCallback cb) { m_activation_callback = cb; }
    
    // Check if session is ready
    bool IsReady() const { return m_initialized; }
    
private:
    DecodeConfig m_config;
    bool m_initialized = false;
    
    // Model components
    ModelContext m_model_context;
    MlaKVCache m_kv_cache;
    
    // Execution state
    uint32_t m_position = 0;
    uint32_t m_seq_len = 0;
    uint32_t m_tokens_generated = 0;
    std::vector<uint32_t> m_generated_tokens;
    
    // IR Executor (forward declared)
    class IRExecutorWrapper;
    std::unique_ptr<IRExecutorWrapper> m_executor;
    
    // Telemetry
    Telemetry m_telemetry;
    
    // Activation callback
    ActivationCallback m_activation_callback;
    
    // Helpers
    bool LoadModel();
    bool ExecuteToken(uint32_t token_id, uint32_t position, uint32_t seq_len, 
                      std::vector<float>& logits);
    uint32_t SampleToken(const std::vector<float>& logits);
    void UpdateTelemetry(const DecodeStepResult& step);
};

// IR Executor Wrapper - wraps the native IR executor
class MultiTokenDecodeSession::IRExecutorWrapper {
public:
    IRExecutorWrapper(const std::string& gguf_path, const std::string& evidence_dir);
    ~IRExecutorWrapper();
    
    bool Initialize();
    bool Execute(uint32_t token_id, uint32_t position, uint32_t seq_len, 
                 MlaKVCache* kv_cache, std::vector<float>& logits);
    void Reset();
    
    // Activation capture
    void SetActivationCallback(std::function<void(uint32_t, const std::string&, 
                                                   const float*, size_t, uint32_t)> cb);
    
private:
    std::string m_gguf_path;
    std::string m_evidence_dir;
    
    // Internal IR executor state
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

// Native IR execution context (extends the IRExecutor from rawrxd_modelgenie_ir_executor.cpp)
struct NativeExecutionContext {
    // Model data
    std::string gguf_path;
    std::string evidence_dir;
    
    // Runtime components
    // ROMResolver rom_resolver;
    // ActivationArena arena;
    // MlaKVCache* kv_cache = nullptr;
    
    // Execution state
    uint32_t token_id = 0;
    uint32_t position = 0;
    uint32_t seq_len = 0;
    
    // Buffers (reused across steps)
    std::vector<float> logits_buffer;
    std::vector<float> hidden_buffer;
    std::vector<float> temp_buffer;
    
    // Callbacks
    std::function<void(uint32_t, const std::string&, const float*, size_t, uint32_t)> activation_callback;
    
    // Telemetry
    uint64_t cycles = 0;
    double step_time_ms = 0.0;
};

} // namespace CLI
} // namespace RawrXD