// ============================================================================
// RawrXD Inference Pipeline - Zero Dependencies
// Complete inference system: GGUF loading → Tokenization → Forward pass → Sampling
// ============================================================================

#pragma once

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <unordered_map>
#include <random>
#include <cmath>

// Include hash_chain for checkpoint types
#include "hash_chain.hpp"

// Forward declarations from sovereign_gguf_loader.h
extern "C" {
typedef struct SovereignGGUFModel* SovereignGGUFModelHandle;
typedef struct SovereignGGUFTensorInfo SovereignGGUFTensorInfo;
typedef struct SovereignModelConfig SovereignModelConfig;
typedef struct SovereignLoaderConfig SovereignLoaderConfig;

// Function declarations
__declspec(dllimport) SovereignGGUFModelHandle Sovereign_LoadModel(const char* filepath, const SovereignLoaderConfig* config);
__declspec(dllimport) void Sovereign_UnloadModel(SovereignGGUFModelHandle model);
__declspec(dllimport) int Sovereign_Model_GetConfig(SovereignGGUFModelHandle model, SovereignModelConfig* config);
}

using namespace RawrXD::Core;

namespace RawrXD {
namespace Inference {

// ============================================================================
// Configuration
// ============================================================================

struct InferenceConfig {
    // Model dimensions (loaded from GGUF)
    uint32_t vocab_size = 32000;
    uint32_t hidden_size = 4096;
    uint32_t num_layers = 32;
    uint32_t num_heads = 32;
    uint32_t num_kv_heads = 32;
    uint32_t intermediate_size = 11008;
    uint32_t max_seq_len = 4096;
    float rms_norm_eps = 1e-6f;
    float rope_theta = 10000.0f;
    
    // Sampling parameters
    float temperature = 0.8f;
    float top_p = 0.9f;
    uint32_t top_k = 40;
    uint32_t max_tokens = 256;
    
    // KV cache
    uint32_t cache_seq_len = 8192;
};

// ============================================================================
// Tensor View (zero-copy reference to GGUF data)
// ============================================================================

struct TensorView {
    const void* data = nullptr;
    uint32_t n_dims = 0;
    uint64_t dims[4] = {0};
    uint32_t type = 0;  // GGML type
    uint64_t size_bytes = 0;
    
    bool IsValid() const { return data != nullptr; }
    uint64_t NumElements() const;
    uint64_t Stride(uint32_t dim) const;
};

// ============================================================================
// KV Cache
// ============================================================================

struct KVCache {
    // Per-layer K and V caches
    // Layout: [layer][seq_len][num_kv_heads][head_dim]
    std::vector<std::vector<float>> k_cache;  // One per layer
    std::vector<std::vector<float>> v_cache;  // One per layer
    
    uint32_t num_layers = 0;
    uint32_t num_kv_heads = 0;
    uint32_t head_dim = 0;
    uint32_t max_seq_len = 0;
    uint32_t current_len = 0;  // Current sequence length
    
    bool Initialize(uint32_t layers, uint32_t kv_heads, uint32_t h_dim, uint32_t max_len);
    void Reset();
    bool Resize(uint32_t new_len);
    
    // Get cache identities for checkpointing
    void GetIdentities(std::vector<KVCacheIdentity>& identities) const;
};

// ============================================================================
// Tokenizer (BPE)
// ============================================================================

class Tokenizer {
public:
    struct MergeRule {
        std::string left, right;
        uint32_t rank;
        bool operator<(const MergeRule& other) const { return rank < other.rank; }
    };
    
    bool Load(const std::string& vocab_path);
    bool LoadFromGGUF(const void* gguf_data, size_t size);
    
    // Encode/decode
    std::vector<uint32_t> Encode(const std::string& text, bool bos = true, bool eos = false) const;
    std::string Decode(const std::vector<uint32_t>& tokens) const;
    
    // Special tokens
    uint32_t GetBOS() const { return bos_id_; }
    uint32_t GetEOS() const { return eos_id_; }
    uint32_t GetPAD() const { return pad_id_; }
    uint32_t GetUNK() const { return unk_id_; }
    
    uint32_t VocabSize() const { return static_cast<uint32_t>(vocab_.size()); }
    bool IsLoaded() const { return !vocab_.empty(); }
    
private:
    std::unordered_map<std::string, uint32_t> vocab_;
    std::unordered_map<uint32_t, std::string> reverse_vocab_;
    std::vector<MergeRule> merges_;
    std::unordered_map<uint64_t, uint32_t> merge_ranks_;  // (left<<32|right) -> rank
    
    uint32_t bos_id_ = 1, eos_id_ = 2, pad_id_ = 0, unk_id_ = 3;
    
    std::vector<std::string> PreTokenize(const std::string& text) const;
    std::vector<uint32_t> EncodeWord(const std::string& word) const;
    uint64_t HashToken(const std::string& token) const;
};

// ============================================================================
// Model Weights (references to GGUF tensors)
// ============================================================================

struct ModelWeights {
    // Token embeddings
    TensorView token_embd;
    
    // Output
    TensorView output_norm;
    TensorView output_weight;
    
    // Per-layer weights
    struct LayerWeights {
        TensorView attn_norm;
        TensorView attn_q;
        TensorView attn_k;
        TensorView attn_v;
        TensorView attn_o;
        TensorView ffn_norm;
        TensorView ffn_gate;  // For SwiGLU
        TensorView ffn_up;
        TensorView ffn_down;
    };
    std::vector<LayerWeights> layers;
    
    bool LoadFromGGUF(void* gguf_handle, const InferenceConfig& config);
    TensorView GetTensor(const std::string& name) const;
};

// ============================================================================
// Quantization Helpers
// ============================================================================

namespace Quant {
    // Dequantize Q4_0 to float
    void DequantizeQ4_0(const void* src, float* dst, uint32_t n, uint32_t stride = 0);
    
    // Dequantize Q8_0 to float
    void DequantizeQ8_0(const void* src, float* dst, uint32_t n, uint32_t stride = 0);
    
    // Dequantize Q4_K to float
    void DequantizeQ4_K(const void* src, float* dst, uint32_t n);
    
    // Matrix-vector multiplication with quantized weights
    void QuantizedMatVecMul(const TensorView& weights, const float* input, 
                            float* output, uint32_t out_dim, uint32_t in_dim);
}

// ============================================================================
// Transformer Operations
// ============================================================================

namespace Ops {
    // RMS Normalization: x = x / sqrt(mean(x^2) + eps)
    void RMSNorm(const float* input, float* output, uint32_t n, float eps, const float* weight = nullptr);
    
    // Softmax: x = exp(x - max) / sum(exp(x - max))
    void Softmax(float* x, uint32_t n, float temperature = 1.0f);
    
    // RoPE (Rotary Position Embedding)
    void RoPE(float* q, float* k, uint32_t dim, uint32_t head_dim, 
              uint32_t pos, float theta);
    
    // Matrix multiplication: C = A * B
    void MatMul(const float* A, const float* B, float* C, 
                uint32_t M, uint32_t N, uint32_t K, bool transpose_B = false);
    
    // SwiGLU activation: x = silu(x1) * x2
    void SwiGLU(const float* gate, const float* up, float* output, uint32_t n);
    
    // SiLU: x = x * sigmoid(x)
    float SiLU(float x);
    
    // Attention: Q @ K^T / sqrt(head_dim) @ V
    void Attention(const float* q, const float* k, const float* v, float* output,
                   uint32_t seq_len, uint32_t num_heads, uint32_t num_kv_heads,
                   uint32_t head_dim, uint32_t pos);
}

// ============================================================================
// Sampler
// ============================================================================

class Sampler {
public:
    struct SampleResult {
        uint32_t token_id;
        float probability;
        bool is_eos;
    };
    
    void SetConfig(float temp, float p, uint32_t k);
    
    SampleResult Sample(const float* logits, uint32_t vocab_size, uint32_t eos_id);
    SampleResult SampleGreedy(const float* logits, uint32_t vocab_size);
    
    // For deterministic reproduction
    void SetSeed(uint32_t seed);
    
private:
    float temperature_ = 0.8f;
    float top_p_ = 0.9f;
    uint32_t top_k_ = 40;
    std::mt19937 rng_;
    
    void ApplyTemperature(float* logits, uint32_t n);
    void ApplyTopK(float* logits, uint32_t n, uint32_t k);
    void ApplyTopP(float* logits, uint32_t n, float p);
    uint32_t MultinomialSample(const float* probs, uint32_t n);
};

// ============================================================================
// Main Inference Pipeline
// ============================================================================

class Pipeline {
public:
    Pipeline();
    ~Pipeline();
    
    // Initialize
    bool Initialize(const std::string& model_path);
    bool Initialize(void* gguf_handle);  // From sovereign loader
    
    // Run inference
    std::string Generate(const std::string& prompt, const InferenceConfig& config);
    std::vector<uint32_t> GenerateTokens(const std::vector<uint32_t>& prompt_tokens,
                                          const InferenceConfig& config);
    
    // Single forward pass
    std::vector<float> Forward(const std::vector<uint32_t>& tokens, uint32_t start_pos);
    
    // State management
    bool SaveCheckpoint(const std::string& path);
    bool LoadCheckpoint(const std::string& path);
    ExecutionSnapshot CaptureSnapshot();
    bool RestoreSnapshot(const ExecutionSnapshot& snapshot);
    
    // Getters
    bool IsLoaded() const { return loaded_; }
    const InferenceConfig& GetConfig() const { return config_; }
    const Tokenizer& GetTokenizer() const { return tokenizer_; }
    KVCache& GetKVCache() { return kv_cache_; }
    
    void ResetCache() { kv_cache_.Reset(); }
    
private:
    bool loaded_ = false;
    InferenceConfig config_;
    
    Tokenizer tokenizer_;
    ModelWeights weights_;
    KVCache kv_cache_;
    Sampler sampler_;
    
    // Working buffers
    std::vector<float> activation_buffer_;
    std::vector<float> residual_buffer_;
    std::vector<float> q_buffer_, k_buffer_, v_buffer_;
    std::vector<float> attn_output_buffer_;
    std::vector<float> ffn_buffer_;
    std::vector<float> logits_buffer_;
    
    // GGUF handle (if using sovereign loader)
    void* gguf_handle_ = nullptr;
    
    bool AllocateBuffers();
    void FreeBuffers();
    
    // Layer forward pass
    void ForwardLayer(uint32_t layer_idx, const float* input, float* output,
                      uint32_t seq_len, uint32_t pos);
    void ForwardAttention(uint32_t layer_idx, const float* input, float* output,
                          uint32_t seq_len, uint32_t pos);
    void ForwardFFN(uint32_t layer_idx, const float* input, float* output,
                    uint32_t seq_len);
};

// ============================================================================
// Utility Functions
// ============================================================================

// Load GGUF and return handle compatible with sovereign loader
void* LoadGGUFModel(const std::string& path, InferenceConfig* out_config);
void UnloadGGUFModel(void* handle);

// Quick inference
std::string RunInference(const std::string& model_path, 
                         const std::string& prompt,
                         const InferenceConfig& config);

} // namespace Inference
} // namespace RawrXD
