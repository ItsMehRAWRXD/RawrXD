// sovereign_runtime.h - Sovereign Runtime Bridge
// Connects GGUF loader to transformer execution
// Phase 8.1 - Production Runtime Integration
// NO DEPENDENCIES - Pure Win32 API

#ifndef SOVEREIGN_RUNTIME_H
#define SOVEREIGN_RUNTIME_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// EXPORT MACROS
// ============================================================================

#ifdef SOVEREIGN_RUNTIME_EXPORTS
#define SOVEREIGN_RUNTIME_API __declspec(dllexport)
#else
#define SOVEREIGN_RUNTIME_API __declspec(dllimport)
#endif

// ============================================================================
// STATUS CODES
// ============================================================================

typedef enum {
    SOVEREIGN_RUNTIME_SUCCESS = 0,
    SOVEREIGN_RUNTIME_ERROR = -1,
    SOVEREIGN_RUNTIME_ERROR_NULL_POINTER = -2,
    SOVEREIGN_RUNTIME_ERROR_INVALID_MODEL = -3,
    SOVEREIGN_RUNTIME_ERROR_INVALID_TENSOR = -4,
    SOVEREIGN_RUNTIME_ERROR_OUT_OF_MEMORY = -5,
    SOVEREIGN_RUNTIME_ERROR_TOKENIZER = -6,
    SOVEREIGN_RUNTIME_ERROR_INFERENCE = -7,
    SOVEREIGN_RUNTIME_ERROR_KV_CACHE = -8,
    SOVEREIGN_RUNTIME_ERROR_SAMPLING = -9
} SovereignRuntimeStatus;

// ============================================================================
// TENSOR TYPES (GGUF compatible)
// ============================================================================

typedef enum {
    TENSOR_TYPE_F32 = 0,
    TENSOR_TYPE_F16 = 1,
    TENSOR_TYPE_Q4_0 = 2,
    TENSOR_TYPE_Q4_1 = 3,
    TENSOR_TYPE_Q5_0 = 6,
    TENSOR_TYPE_Q5_1 = 7,
    TENSOR_TYPE_Q8_0 = 8,
    TENSOR_TYPE_Q2_K = 10,
    TENSOR_TYPE_Q3_K = 11,
    TENSOR_TYPE_Q4_K = 12,
    TENSOR_TYPE_Q5_K = 13,
    TENSOR_TYPE_Q6_K = 14,
    TENSOR_TYPE_Q8_K = 15
} TensorType;

// ============================================================================
// TENSOR VIEW - Maps GGUF tensors to execution
// ============================================================================

typedef struct {
    const char* name;           // Tensor name (e.g., "token_embd.weight")
    TensorType type;            // Quantization type
    uint32_t n_dims;            // Number of dimensions
    uint64_t ne[4];             // Shape (ne[0]=rows, ne[1]=cols, etc.)
    const void* data;           // Pointer to tensor data (mmap'd)
    size_t size;                // Size in bytes
    uint64_t offset;            // Offset in file
} TensorView;

// ============================================================================
// KERNEL REGISTRY - Transformer operations
// ============================================================================

typedef struct {
    // RMSNorm kernel
    void (*rmsnorm)(float* output, const float* input, const float* weight, 
                    int n_elements, float epsilon);
    
    // RoPE kernel (Rotary Position Embedding)
    void (*rope)(float* query, float* key, int n_heads, int head_dim,
                 int position, float freq_base);
    
    // Attention kernel
    void (*attention)(float* output, const float* query, const float* key,
                      const float* value, int n_heads, int seq_len, int head_dim);
    
    // Softmax kernel
    void (*softmax)(float* output, const float* input, int n_elements);
    
    // MatMul kernel (quantized)
    void (*matmul)(float* output, const void* input, const void* weight,
                   int m, int n, int k, TensorType weight_type);
    
    // Dequantization kernel
    void (*dequantize)(float* output, const void* input, int n_elements, 
                       TensorType type);
} KernelRegistry;

// ============================================================================
// KV CACHE - Key-Value cache for autoregressive generation
// ============================================================================

typedef struct {
    float* k_cache;             // Key cache [n_layers][n_heads][max_seq_len][head_dim]
    float* v_cache;             // Value cache [n_layers][n_heads][max_seq_len][head_dim]
    int n_layers;               // Number of transformer layers
    int n_heads;                // Number of attention heads
    int head_dim;               // Dimension per head
    int max_seq_len;            // Maximum sequence length
    int current_len;            // Current cache length
    size_t size;                 // Total size in bytes
} KVCache;

// ============================================================================
// TOKENIZER BRIDGE - Encode/decode operations
// ============================================================================

typedef struct {
    // Vocabulary
    char** vocab;               // Token strings
    float* vocab_scores;        // Token scores (for BPE)
    int vocab_size;             // Number of tokens
    int n_bytes;                // Bytes per token
    
    // Special tokens
    int bos_token;              // Beginning of sequence
    int eos_token;              // End of sequence
    int pad_token;              // Padding token
    int unk_token;              // Unknown token
    
    // Tokenizer type
    int tokenizer_type;         // 0=SPM, 1=BPE, 2=ByteLevel
} TokenizerBridge;

// ============================================================================
// MODEL CONTEXT - Complete model state
// ============================================================================

typedef struct {
    // Model configuration
    int n_layers;               // Number of transformer layers
    int n_heads;                // Number of attention heads
    int head_dim;               // Dimension per head
    int hidden_dim;             // Hidden dimension
    int vocab_size;             // Vocabulary size
    int max_position;           // Maximum position embeddings
    float rms_norm_eps;         // RMSNorm epsilon
    float rope_freq_base;       // RoPE frequency base
    
    // Tensor views (mapped from GGUF)
    TensorView* token_embd;     // Token embeddings
    TensorView* position_embd;  // Position embeddings (optional)
    TensorView* norm_final;     // Final layer norm
    TensorView* output;         // Output projection
    
    // Per-layer tensors
    struct {
        TensorView* attention_norm;     // Attention layer norm
        TensorView* attention_q;         // Query projection
        TensorView* attention_k;         // Key projection
        TensorView* attention_v;         // Value projection
        TensorView* attention_o;         // Output projection
        TensorView* ffn_norm;            // FFN layer norm
        TensorView* ffn_gate;            // FFN gate (SwiGLU)
        TensorView* ffn_up;              // FFN up projection
        TensorView* ffn_down;            // FFN down projection
    }* layers;
    
    // Runtime state
    KVCache kv_cache;           // Key-value cache
    TokenizerBridge tokenizer;   // Tokenizer
    KernelRegistry kernels;      // Kernel operations
    
    // Memory management
    void* model_data;           // Mmap'd model data
    size_t model_size;          // Size of mmap'd data
    int model_id;                // Model identifier
} ModelContext;

// ============================================================================
// SAMPLER - Token sampling strategies
// ============================================================================

typedef struct {
    float temperature;           // Sampling temperature
    int top_k;                   // Top-k sampling
    float top_p;                 // Top-p (nucleus) sampling
    float repeat_penalty;        // Repetition penalty
    int* repeat_tokens;          // Tokens to penalize
    int n_repeat;                // Number of repeat tokens
    unsigned int seed;           // Random seed
} SamplerConfig;

// ============================================================================
// RUNTIME API - Gate Functions (G1-G7)
// ============================================================================

// G1: GGUF tensor → TensorView mapping
SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_MapTensors(
    ModelContext* ctx,
    const void* gguf_data,
    size_t gguf_size
);

// G2: Tokenizer encode/decode round trip
SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_InitTokenizer(
    ModelContext* ctx,
    const char* vocab_data,
    size_t vocab_size
);

SOVEREIGN_RUNTIME_API int Sovereign_Runtime_Encode(
    ModelContext* ctx,
    const char* text,
    int* tokens,
    int max_tokens
);

SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_Decode(
    ModelContext* ctx,
    const int* tokens,
    int n_tokens,
    char* text,
    int max_text_len
);

SOVEREIGN_RUNTIME_API const char* Sovereign_Runtime_DecodeSingle(
    ModelContext* ctx,
    int token_id
);

// G3: Embedding lookup from loaded model
SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_GetEmbedding(
    ModelContext* ctx,
    int token_id,
    float* embedding,
    int embedding_dim
);

// G4: RMSNorm/RoPE/Attention execution
SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_RMSNorm(
    ModelContext* ctx,
    float* output,
    const float* input,
    const TensorView* weight,
    int n_elements
);

SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_RoPE(
    ModelContext* ctx,
    float* query,
    float* key,
    int position
);

SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_Attention(
    ModelContext* ctx,
    int layer_idx,
    const float* query,
    float* output,
    int seq_len
);

// G5: KV cache append/retrieve
SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_KVCache_Init(
    ModelContext* ctx,
    int n_layers,
    int n_heads,
    int head_dim,
    int max_seq_len
);

SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_KVCache_Append(
    ModelContext* ctx,
    int layer_idx,
    const float* key,
    const float* value,
    int seq_len
);

SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_KVCache_Retrieve(
    ModelContext* ctx,
    int layer_idx,
    float* key,
    float* value,
    int position
);

SOVEREIGN_RUNTIME_API void Sovereign_Runtime_KVCache_Free(
    ModelContext* ctx
);

// G6: First generated token from real weights
SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_Forward(
    ModelContext* ctx,
    const int* tokens,
    int n_tokens,
    float* logits
);

// G7: Streaming callback receives real token IDs
SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_Generate(
    ModelContext* ctx,
    const char* prompt,
    int max_tokens,
    SamplerConfig* sampler,
    void (*on_token)(int token_id, const char* token_text, void* user_data),
    void* user_data
);

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_Init(
    ModelContext* ctx,
    int model_id
);

SOVEREIGN_RUNTIME_API void Sovereign_Runtime_Free(
    ModelContext* ctx
);

// ============================================================================
// KERNEL REGISTRATION
// ============================================================================

SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_RegisterKernels(
    ModelContext* ctx,
    const KernelRegistry* kernels
);

#ifdef __cplusplus
}
#endif

#endif // SOVEREIGN_RUNTIME_H