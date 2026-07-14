//=============================================================================
// rawrxd_inference.h
// Zero-Dependency Inference Engine
// Supports: LLaMA, Qwen, Phi, Gemma architectures
// Quantization: Q4_0, Q4_1, Q5_0, Q5_1, Q8_0, Q2_K, Q3_K, Q4_K, Q5_K, Q6_K
//=============================================================================
#pragma once

#include "rawrxd_core.h"

#ifdef __cplusplus
extern "C" {
#endif

//=============================================================================
// Architecture Types
//=============================================================================

typedef enum {
    RAWRXD_ARCH_UNKNOWN = 0,
    RAWRXD_ARCH_LLAMA,      // LLaMA, LLaMA2, LLaMA3
    RAWRXD_ARCH_QWEN,       // Qwen, Qwen2
    RAWRXD_ARCH_PHI,        // Phi-2, Phi-3
    RAWRXD_ARCH_GEMMA,      // Gemma, Gemma 2
    RAWRXD_ARCH_MISTRAL,    // Mistral, Mixtral
    RAWRXD_ARCH_FALCON,     // Falcon
    RAWRXD_ARCH_GPT2,       // GPT-2
    RAWRXD_ARCH_BERT,       // BERT (encoder-only)
    RAWRXD_ARCH_T5,         // T5
    RAWRXD_ARCH_COUNT
} rawrxd_architecture;

//=============================================================================
// Model Configuration
//=============================================================================

typedef struct rawrxd_model_config {
    rawrxd_architecture arch;
    
    // Dimensions
    u32 vocab_size;
    u32 hidden_size;
    u32 intermediate_size;
    u32 num_layers;
    u32 num_heads;
    u32 num_kv_heads;       // For GQA
    u32 head_dim;
    u32 max_seq_len;
    u32 context_length;
    
    // Architecture flags
    bool use_gqa;           // Grouped Query Attention
    bool use_sliding_window;
    u32 sliding_window_size;
    
    // Normalization
    f32 rms_norm_eps;
    f32 layer_norm_eps;
    
    // RoPE
    f32 rope_theta;
    u32 rope_scaling_type;
    f32 rope_scaling_factor;
    
    // Activations
    enum { ACT_SILU, ACT_GELU, ACT_RELU, ACT_SWIGLU } hidden_act;
    
    // Tokenizer
    u32 bos_token_id;
    u32 eos_token_id;
    u32 pad_token_id;
    u32 unk_token_id;
    
    // Quantization
    u32 default_quant;      // Default GGML type
    bool mixed_quant;         // Different types per tensor
    
    // Performance
    u32 batch_size;
    u32 num_threads;
    bool use_flash_attn;
    bool use_kv_cache;
    
    // Memory
    u64 max_memory;           // Max bytes to use
    bool memory_lock;         // mlock on Unix
    bool zero_copy;           // Avoid copies where possible
} rawrxd_model_config;

//=============================================================================
// Tensor Storage
//=============================================================================

typedef struct rawrxd_tensor {
    char name[64];
    void* data;
    u64 size;
    u32 type;               // GGML type
    u32 ndims;
    u64 dims[4];
    u64 stride[4];
    
    // Quantization params
    union {
        struct { f32 scale; } q4_0;
        struct { f32 scale; f32 min; } q4_1;
        struct { f32 scale; } q8_0;
        struct { f32 d; f32 dmin; } q4_k;
    } quant;
    
    // Memory management
    bool owned;             // Free on cleanup?
    u32 refcount;
} rawrxd_tensor;

//=============================================================================
// KV Cache
//=============================================================================

typedef struct rawrxd_kv_cache {
    // Per-layer cache
    u32 n_layers;
    u32 n_heads;
    u32 head_dim;
    u32 max_seq_len;
    u32 current_len;
    
    // Cache data: [layer][kv][head][seq][dim]
    f16* k_cache;           // Key cache
    f16* v_cache;           // Value cache
    
    // Sequence management
    u32* seq_ids;           // Token IDs for each position
    bool* seq_mask;           // Which positions are valid
    
    // Quantization
    bool quantized;
    u32 cache_quant_type;
    
    // Memory
    u64 cache_size;
    void* cache_buffer;
} rawrxd_kv_cache;

RAWRXD_EXPORT rawrxd_kv_cache* rawrxd_kv_cache_create(const rawrxd_model_config* config);
RAWRXD_EXPORT void rawrxd_kv_cache_clear(rawrxd_kv_cache* cache);
RAWRXD_EXPORT void rawrxd_kv_cache_resize(rawrxd_kv_cache* cache, u32 new_len);
RAWRXD_EXPORT void rawrxd_kv_cache_destroy(rawrxd_kv_cache* cache);

// Cache operations
RAWRXD_EXPORT void rawrxd_kv_cache_store(rawrxd_kv_cache* cache,
                                          u32 layer,
                                          u32 head,
                                          u32 pos,
                                          const f16* key,
                                          const f16* value);
RAWRXD_EXPORT void rawrxd_kv_cache_fetch(const rawrxd_kv_cache* cache,
                                          u32 layer,
                                          u32 head,
                                          u32 pos,
                                          f16* key_out,
                                          f16* value_out);

//=============================================================================
// Model Structure
//=============================================================================

typedef struct rawrxd_model {
    rawrxd_model_config config;
    
    // Tensors
    rawrxd_tensor* tensors;
    u32 num_tensors;
    rawrxd_strmap* tensor_map;  // name -> index
    
    // Special tensors
    rawrxd_tensor* token_embeddings;
    rawrxd_tensor* output_norm;
    rawrxd_tensor* output_weight;
    
    // Per-layer tensors
    struct rawrxd_layer_weights {
        rawrxd_tensor* input_norm;
        rawrxd_tensor* q_proj;
        rawrxd_tensor* k_proj;
        rawrxd_tensor* v_proj;
        rawrxd_tensor* o_proj;
        rawrxd_tensor* post_attn_norm;
        rawrxd_tensor* gate_proj;   // For MLP
        rawrxd_tensor* up_proj;
        rawrxd_tensor* down_proj;
    }* layers;
    
    // KV cache
    rawrxd_kv_cache* kv_cache;
    
    // Tokenizer
    struct rawrxd_tokenizer* tokenizer;
    
    // State
    bool loaded;
    u64 memory_used;
    
    // Threading
    rawrxd_thread** workers;
    u32 num_workers;
    rawrxd_mutex* forward_mutex;
} rawrxd_model;

//=============================================================================
// Model Loading
//=============================================================================

RAWRXD_EXPORT rawrxd_model* rawrxd_model_load(const char* path,
                                               const rawrxd_model_config* config);
RAWRXD_EXPORT rawrxd_model* rawrxd_model_load_streaming(rawrxd_model_stream* stream,
                                                         const rawrxd_model_config* config);
RAWRXD_EXPORT void rawrxd_model_unload(rawrxd_model* model);

// Load specific tensors
RAWRXD_EXPORT rawrxd_result rawrxd_model_load_tensor(rawrxd_model* model,
                                                      const char* name,
                                                      void* data,
                                                      u64 size,
                                                      u32 type);

//=============================================================================
// Tokenization
//=============================================================================

typedef struct rawrxd_tokenizer {
    u32 vocab_size;
    
    // Vocabulary
    rawrxd_string* vocab;
    rawrxd_strmap* token_to_id;
    
    // Special tokens
    u32 bos_id, eos_id, pad_id, unk_id;
    
    // BPE merges
    struct rawrxd_bpe_merge {
        u32 first, second;
        u32 result;
    }* merges;
    u32 num_merges;
    
    // SentencePiece
    bool use_sp;
    void* sp_model;
    
    // TikToken
    bool use_tiktoken;
    void* tiktoken_encoder;
} rawrxd_tokenizer;

RAWRXD_EXPORT rawrxd_tokenizer* rawrxd_tokenizer_load(const char* path);
RAWRXD_EXPORT void rawrxd_tokenizer_free(rawrxd_tokenizer* tok);

// Encode/decode
RAWRXD_EXPORT u32* rawrxd_tokenizer_encode(rawrxd_tokenizer* tok,
                                          const char* text,
                                          u32* num_tokens,
                                          bool add_bos,
                                          bool add_eos);
RAWRXD_EXPORT char* rawrxd_tokenizer_decode(rawrxd_tokenizer* tok,
                                           const u32* tokens,
                                           u32 num_tokens);
RAWRXD_EXPORT u32 rawrxd_tokenizer_bos(rawrxd_tokenizer* tok);
RAWRXD_EXPORT u32 rawrxd_tokenizer_eos(rawrxd_tokenizer* tok);

//=============================================================================
// Inference Context
//=============================================================================

typedef struct rawrxd_context {
    rawrxd_model* model;
    
    // Input/output
    u32* input_tokens;
    u32 num_input_tokens;
    
    f32* logits;
    u32 vocab_size;
    
    // Working buffers
    f32* attn_scores;
    f32* attn_probs;
    f16* qkv_buffer;
    f32* mlp_buffer;
    f32* norm_buffer;
    
    // Activation cache
    f32* layer_input;
    f32* layer_output;
    
    // Position
    u32 current_pos;
    u32 total_len;
    
    // Sampling state
    rawrxd_rng rng;
    f32 temperature;
    f32 top_p;
    u32 top_k;
    f32 repetition_penalty;
    
    // Performance
    u64 forward_count;
    double total_forward_time;
    double last_forward_time;
} rawrxd_context;

RAWRXD_EXPORT rawrxd_context* rawrxd_context_create(rawrxd_model* model);
RAWRXD_EXPORT void rawrxd_context_destroy(rawrxd_context* ctx);
RAWRXD_EXPORT void rawrxd_context_reset(rawrxd_context* ctx);

//=============================================================================
// Forward Pass
//=============================================================================

// Single token forward
RAWRXD_EXPORT rawrxd_result rawrxd_forward(rawrxd_context* ctx,
                                            u32 token_id,
                                            f32* logits_out);

// Batch forward
RAWRXD_EXPORT rawrxd_result rawrxd_forward_batch(rawrxd_context* ctx,
                                                  const u32* token_ids,
                                                  u32 num_tokens,
                                                  f32* logits_out);

// Full sequence forward (prefill)
RAWRXD_EXPORT rawrxd_result rawrxd_prefill(rawrxd_context* ctx,
                                          const u32* tokens,
                                          u32 num_tokens);

// Generate next token
RAWRXD_EXPORT u32 rawrxd_sample_token(rawrxd_context* ctx,
                                      const f32* logits,
                                      u32 vocab_size);

//=============================================================================
// Generation
//=============================================================================

typedef struct rawrxd_generation_params {
    u32 max_tokens;
    f32 temperature;
    f32 top_p;
    u32 top_k;
    f32 repetition_penalty;
    u32 repeat_last_n;
    
    // Stopping
    const char** stop_strings;
    u32 num_stop_strings;
    u32* stop_token_ids;
    u32 num_stop_tokens;
    
    // Callbacks
    void (*on_token)(u32 token_id, const char* text, void* user);
    bool (*should_stop)(void* user);
    void* user_data;
} rawrxd_generation_params;

RAWRXD_EXPORT rawrxd_result rawrxd_generate(rawrxd_context* ctx,
                                           const char* prompt,
                                           rawrxd_generation_params* params,
                                           char** output);

RAWRXD_EXPORT rawrxd_result rawrxd_generate_tokens(rawrxd_context* ctx,
                                                    const u32* prompt_tokens,
                                                    u32 num_prompt_tokens,
                                                    rawrxd_generation_params* params,
                                                    u32** output_tokens,
                                                    u32* num_output_tokens);

// Streaming generation
RAWRXD_EXPORT rawrxd_result rawrxd_generate_stream(rawrxd_context* ctx,
                                                    const char* prompt,
                                                    rawrxd_generation_params* params);

//=============================================================================
// Quantization
//=============================================================================

// Dequantize to float
RAWRXD_EXPORT void rawrxd_dequantize_q4_0(const void* src, f32* dst, u64 n);
RAWRXD_EXPORT void rawrxd_dequantize_q4_1(const void* src, f32* dst, u64 n);
RAWRXD_EXPORT void rawrxd_dequantize_q5_0(const void* src, f32* dst, u64 n);
RAWRXD_EXPORT void rawrxd_dequantize_q5_1(const void* src, f32* dst, u64 n);
RAWRXD_EXPORT void rawrxd_dequantize_q8_0(const void* src, f32* dst, u64 n);
RAWRXD_EXPORT void rawrxd_dequantize_q4_k(const void* src, f32* dst, u64 n);
RAWRXD_EXPORT void rawrxd_dequantize_q5_k(const void* src, f32* dst, u64 n);
RAWRXD_EXPORT void rawrxd_dequantize_q6_k(const void* src, f32* dst, u64 n);

// Quantize from float
RAWRXD_EXPORT void rawrxd_quantize_q4_0(const f32* src, void* dst, u64 n);
RAWRXD_EXPORT void rawrxd_quantize_q4_1(const f32* src, void* dst, u64 n);
RAWRXD_EXPORT void rawrxd_quantize_q8_0(const f32* src, void* dst, u64 n);

// Quantized matrix-vector multiplication
RAWRXD_EXPORT void rawrxd_q4_0_mat_vec(const void* mat, const f32* vec,
                                        f32* out, u64 nrows, u64 ncols);
RAWRXD_EXPORT void rawrxd_q4_1_mat_vec(const void* mat, const f32* vec,
                                        f32* out, u64 nrows, u64 ncols);
RAWRXD_EXPORT void rawrxd_q8_0_mat_vec(const void* mat, const f32* vec,
                                        f32* out, u64 nrows, u64 ncols);
RAWRXD_EXPORT void rawrxd_q4_k_mat_vec(const void* mat, const f32* vec,
                                        f32* out, u64 nrows, u64 ncols);

//=============================================================================
// Attention
//=============================================================================

// Self-attention
RAWRXD_EXPORT void rawrxd_self_attention(f32* output,
                                          const f32* query,
                                          const f32* key_cache,
                                          const f32* value_cache,
                                          u32 seq_len,
                                          u32 n_heads,
                                          u32 head_dim,
                                          f32 scale);

// Flash attention (if available)
RAWRXD_EXPORT bool rawrxd_flash_attention_available(void);
RAWRXD_EXPORT void rawrxd_flash_attention(f32* output,
                                         const f32* query,
                                         const f32* key,
                                         const f32* value,
                                         u32 seq_len,
                                         u32 n_heads,
                                         u32 head_dim);

// RoPE (Rotary Position Embedding)
RAWRXD_EXPORT void rawrxd_rope(f32* x, u32 n_dims, u32 seq_len, f32 theta);
RAWRXD_EXPORT void rawrxd_rope_inplace(f32* q, f32* k,
                                        u32 n_heads, u32 head_dim,
                                        u32 pos, f32 theta);

//=============================================================================
// Normalization
//=============================================================================

RAWRXD_EXPORT void rawrxd_rms_norm(f32* output, const f32* input,
                                  u32 size, f32 eps);
RAWRXD_EXPORT void rawrxd_layer_norm(f32* output, const f32* input,
                                    u32 size, f32 eps);
RAWRXD_EXPORT void rawrxd_softmax(f32* x, u32 size);
RAWRXD_EXPORT void rawrxd_softmax_inplace(f32* x, u32 size);

//=============================================================================
// Activations
//=============================================================================

RAWRXD_EXPORT void rawrxd_silu(f32* x, u32 n);
RAWRXD_EXPORT void rawrxd_gelu(f32* x, u32 n);
RAWRXD_EXPORT void rawrxd_relu(f32* x, u32 n);
RAWRXD_EXPORT void rawrxd_swiglu(f32* output, const f32* gate, const f32* up, u32 n);

//=============================================================================
// Performance
//=============================================================================

typedef struct rawrxd_perf_stats {
    u64 tokens_generated;
    double total_time_sec;
    double tokens_per_sec;
    double ms_per_token;
    u64 memory_used;
    u64 cache_hits;
    u64 cache_misses;
} rawrxd_perf_stats;

RAWRXD_EXPORT void rawrxd_get_perf_stats(const rawrxd_context* ctx,
                                        rawrxd_perf_stats* stats);
RAWRXD_EXPORT void rawrxd_reset_perf_stats(rawrxd_context* ctx);

#ifdef __cplusplus
}
#endif
