// =============================================================================
// sovereign_transformer_forward.h
// Hybrid C++/MASM Transformer Forward Pass
// C++ orchestration + MASM kernels = maximum velocity
// =============================================================================

#ifndef SOVEREIGN_TRANSFORMER_FORWARD_H
#define SOVEREIGN_TRANSFORMER_FORWARD_H

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <vector>
#include <windows.h>

namespace Sovereign {

// =============================================================================
// Quantized Weight Storage (Memory-Efficient)
// =============================================================================
struct QuantizedWeightData {
    uint8_t* data = nullptr;      // Raw quantized bytes
    uint64_t size = 0;            // Size in bytes
    uint32_t n_elements = 0;      // Number of elements when dequantized
    int quant_type = 0;           // 0=F32, 1=Q3_K, 2=Q6_K, etc.
    
    void Free() {
        if (data) {
            VirtualFree(data, 0, MEM_RELEASE);
            data = nullptr;
            size = 0;
        }
    }
};

// =============================================================================
// Model Weight Pointers (mapped from GGUF)
// =============================================================================
struct ModelWeights {
    // Model dimensions (from GGUF metadata)
    uint32_t n_layers = 0;
    uint32_t n_heads = 0;
    uint32_t n_kv_heads = 0;      // GQA: grouped query attention
    uint32_t head_dim = 0;
    uint32_t hidden_dim = 0;
    uint32_t ffn_dim = 0;
    uint32_t vocab_size = 0;
    uint32_t seq_len = 0;
    
    // Embedding
    float* token_embeddings = nullptr;  // [vocab_size, hidden_dim]
    
    // Layer weights (pointers to arrays of size [n_layers])
    // Attention
    float** wq = nullptr;  // Query projection [n_layers, hidden_dim, hidden_dim]
    float** wk = nullptr;  // Key projection [n_layers, hidden_dim, n_kv_heads * head_dim]
    float** wv = nullptr;  // Value projection [n_layers, hidden_dim, n_kv_heads * head_dim]
    float** wo = nullptr;  // Output projection [n_layers, hidden_dim, hidden_dim]
    
    // Attention norms
    float** attn_norm = nullptr;  // Pre-attention RMSNorm [n_layers, hidden_dim]
    
    // FFN
    float** w_up = nullptr;    // Up projection [n_layers, hidden_dim, ffn_dim]
    float** w_gate = nullptr;  // Gate projection (for SwiGLU) [n_layers, hidden_dim, ffn_dim]
    float** w_down = nullptr;  // Down projection [n_layers, ffn_dim, hidden_dim]
    
    // FFN norm
    float** ffn_norm = nullptr;  // Pre-FFN RMSNorm [n_layers, hidden_dim]
    
    // Final output
    float* output_norm = nullptr;  // Final RMSNorm [hidden_dim]
    float* lm_head = nullptr;      // Language model head [vocab_size, hidden_dim]
    
    // Quantization info (if using Q4_K_M, etc.)
    void** q4_blocks = nullptr;  // Quantized blocks for MASM dequantization
    
    // Memory-efficient quantized storage (NEW: keeps weights compressed)
    // These store the raw quantized bytes instead of dequantized floats
    QuantizedWeightData* q_wq = nullptr;   // [n_layers] - quantized query weights
    QuantizedWeightData* q_wk = nullptr;   // [n_layers] - quantized key weights
    QuantizedWeightData* q_wv = nullptr;   // [n_layers] - quantized value weights
    QuantizedWeightData* q_wqkv = nullptr; // [n_layers] - fused QKV weights (for models like Phi-3)
    QuantizedWeightData* q_wo = nullptr;   // [n_layers] - quantized output weights
    QuantizedWeightData* q_w_up = nullptr;   // [n_layers] - quantized up weights
    QuantizedWeightData* q_w_gate = nullptr; // [n_layers] - quantized gate weights
    QuantizedWeightData* q_w_down = nullptr; // [n_layers] - quantized down weights
    QuantizedWeightData q_token_embeddings;    // Quantized token embeddings
    QuantizedWeightData q_lm_head;             // Quantized LM head
    
    bool use_quantized = false;  // If true, use quantized storage for matmul
};

// =============================================================================
// Quantized Matrix-Vector Multiplication Helper
// =============================================================================
void QuantizedMatVecMul_Q3_K_S(const QuantizedWeightData& q_weights, 
                                const float* input, 
                                float* output,
                                uint32_t output_dim,
                                uint32_t input_dim);

void QuantizedMatVecMul_Q4_0(const QuantizedWeightData& q_weights,
                                const float* input,
                                float* output,
                                uint32_t output_dim,
                                uint32_t input_dim);

// =============================================================================
// RoPE (Rotary Position Embedding)
// =============================================================================
void ApplyRoPE(float* q, float* k, uint32_t pos, uint32_t head_dim, 
               uint32_t n_heads, uint32_t n_kv_heads);

// =============================================================================
// KV Cache Management
// =============================================================================
struct KVCache {
    float* k_cache = nullptr;  // [n_layers, max_seq, n_kv_heads, head_dim]
    float* v_cache = nullptr;  // [n_layers, max_seq, n_kv_heads, head_dim]
    uint32_t max_seq_len = 0;
    uint32_t current_pos = 0;  // Current sequence position
    
    bool Initialize(uint32_t n_layers, uint32_t max_seq, uint32_t n_kv_heads, uint32_t head_dim);
    void Reset();
    void Cleanup();
};

// =============================================================================
// Transformer Forward Pass
// =============================================================================
class TransformerForward {
public:
    TransformerForward(const ModelWeights& weights, KVCache& kv_cache);
    ~TransformerForward();
    
    // Main entry: process tokens through transformer
    // input_tokens: array of token IDs [seq_len]
    // seq_len: number of input tokens
    // output_logits: output buffer [vocab_size] - logits for next token
    // Returns: true on success
    bool Forward(const uint32_t* input_tokens, uint32_t seq_len, float* output_logits);
    
    // Single token forward (for generation)
    // token_id: single input token
    // pos: position in sequence (for KV cache)
    // output_logits: output buffer [vocab_size]
    bool ForwardToken(uint32_t token_id, uint32_t pos, float* output_logits);
    
    // Utility functions exposed for integration
    void Softmax(float* logits, uint32_t size);
    uint32_t SampleToken(const float* logits);
    uint32_t SampleTokenWithHistory(const float* logits, const std::vector<uint32_t>& generated_tokens);
    
private:
    // FIX: Use pointer with validation instead of reference
    // This prevents dangling reference issues if ModelWeights is moved/reallocated
    const ModelWeights* weights_ptr_ = nullptr;
    uint64_t weights_guard_ = 0xDEADBEEFCAFEBABEULL; // validation cookie
    
    KVCache& kv_cache_;
    
    // Validate weights pointer before access
    const ModelWeights& weights() const {
        extern bool g_debug;
        if (g_debug) {
            printf("[weights()] Enter: ptr=%p, guard=%llx\n", (void*)weights_ptr_, weights_guard_); fflush(stdout);
        }
        uint64_t expected = (uint64_t)weights_ptr_ ^ 0xDEADBEEFCAFEBABEULL;
        if (g_debug) {
            printf("[weights()] Computed expected=%llx\n", expected); fflush(stdout);
        }
        if (expected != weights_guard_ || !weights_ptr_) {
            fprintf(stderr, "[FATAL] ModelWeights pointer corrupted or null! ptr=%p guard=%llx expected=%llx\n",
                    (void*)weights_ptr_, weights_guard_, expected);
            fflush(stderr);
            // Return a dummy to avoid crash - this is a safety net
            static ModelWeights dummy;
            dummy.use_quantized = false; // Force non-quantized path to minimize damage
            return dummy;
        }
        if (g_debug) {
            printf("[weights()] Validation passed, returning weights at %p\n", (void*)weights_ptr_); fflush(stdout);
        }
        return *weights_ptr_;
    }
    
    // Scratch buffers (allocated once, reused)
    float* hidden_states_ = nullptr;     // [hidden_dim]
    float* attn_out_ = nullptr;          // [n_heads, head_dim] - attention output before projection
    float* attn_output_ = nullptr;       // [hidden_dim]
    float* ffn_intermediate_ = nullptr;  // [ffn_dim]
    float* q_proj_ = nullptr;            // [n_heads, head_dim]
    float* k_proj_ = nullptr;            // [n_kv_heads, head_dim]
    float* v_proj_ = nullptr;            // [n_kv_heads, head_dim]
    float* attn_scores_ = nullptr;       // [n_heads, max_seq] - attention weights
    
    // Persistent KV cache - survives across ForwardToken calls
    // Layout: [n_layers][max_seq][n_kv_heads * head_dim]
    float* k_cache_ = nullptr;
    float* v_cache_ = nullptr;
    uint32_t max_seq_ = 2048;
    uint32_t n_layers_ = 0;
    uint32_t n_kv_heads_ = 0;
    uint32_t head_dim_ = 0;
    bool kv_cache_initialized_ = false;
    
    bool AllocateScratchBuffers();
    void FreeScratchBuffers();
    bool InitializePersistentKVCache();
    void FreePersistentKVCache();
    
    // Layer operations
    void EmbeddingLookup(uint32_t token_id, float* output);
    void RMSNorm(const float* input, const float* weight, float* output, uint32_t size, float eps = 1e-6f);
    void AttentionLayer(uint32_t layer_idx, uint32_t pos);
    void FFNLayer(uint32_t layer_idx);
    void ResidualAdd(float* output, const float* residual);
    
    // MASM kernel wrappers (inline for speed)
    void Kernel_MatMul(const float* a, const float* b, float* c, 
                       uint32_t m, uint32_t n, uint32_t k);
    void Kernel_RMSNorm(float* x, const float* weight, uint32_t size, float eps);
    void Kernel_Softmax(float* x, uint32_t size);
};

// =============================================================================
// Model Weights Loader (maps GGUF to ModelWeights)
// =============================================================================
bool MapGGUFToModelWeights(void* gguf_handle, ModelWeights& out_weights);
void FreeModelWeights(ModelWeights& weights);

} // namespace Sovereign

#endif // SOVEREIGN_TRANSFORMER_FORWARD_H
