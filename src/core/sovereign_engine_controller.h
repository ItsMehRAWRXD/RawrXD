// =============================================================================
// sovereign_engine_controller.h
// Phase 22: Inference Engine Integration
// Unified controller for end-to-end inference pipeline
// =============================================================================

#ifndef SOVEREIGN_ENGINE_CONTROLLER_H
#define SOVEREIGN_ENGINE_CONTROLLER_H

#include "sovereign_gguf_loader.h"
#include "sovereign_kv_cache.h"
#include "sovereign_memory_pool.h"
#include "sovereign_thread_pool.h"
#include <inttypes.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Configuration
// =============================================================================

#define SOVEREIGN_MAX_BATCH_SIZE      1
#define SOVEREIGN_MAX_SEQ_LEN         32768
#define SOVEREIGN_VOCAB_SIZE          32000
#define SOVEREIGN_MAX_LAYERS          128
#define SOVEREIGN_MAX_GENERATION_LEN  4096

// =============================================================================
// Opaque Handles
// =============================================================================

typedef struct SovereignEngine* SovereignEngineHandle;
typedef struct SovereignInferenceSession* SovereignSessionHandle;
typedef struct SovereignTokenizer* SovereignTokenizerHandle;

// =============================================================================
// Token Types
// =============================================================================

typedef uint32_t SovereignToken;

#define SOVEREIGN_TOKEN_EOS           2
#define SOVEREIGN_TOKEN_BOS           1
#define SOVEREIGN_TOKEN_PAD           0
#define SOVEREIGN_TOKEN_UNK           0

// =============================================================================
// Inference Configuration
// =============================================================================

typedef struct SovereignInferenceConfig {
    // Generation parameters
    uint32_t max_tokens;           // Maximum tokens to generate
    float temperature;             // Sampling temperature (0.0 = greedy)
    float top_p;                   // Nucleus sampling threshold
    uint32_t top_k;                // Top-k sampling
    float repetition_penalty;      // Penalty for repeated tokens
    
    // Performance
    uint32_t num_threads;          // Thread pool size
    uint32_t use_amx;              // Use AMX kernels
    uint32_t use_int8;             // Use INT8 quantization
    uint32_t use_bf16;             // Use BF16 compute
    
    // Memory
    uint64_t max_memory_bytes;     // Memory limit
    uint32_t enable_kv_cache;      // Enable KV caching
} SovereignInferenceConfig;

// =============================================================================
// Generation Result
// =============================================================================

typedef struct SovereignGenerationResult {
    SovereignToken token_id;       // Generated token
    float logit;                   // Raw logit value
    float probability;             // Softmax probability
    uint32_t is_eos;               // End of sequence
    uint32_t generation_index;     // Position in generation
    double generation_time_ms;     // Time to generate this token
} SovereignGenerationResult;

// =============================================================================
// Engine Statistics
// =============================================================================

typedef struct SovereignEngineStats {
    // Timing
    double init_time_ms;
    double load_time_ms;
    double first_token_time_ms;    // TTFT
    double avg_token_time_ms;      // TPS inverse
    double total_inference_time_ms;
    
    // Throughput
    double tokens_per_sec;
    uint64_t tokens_generated;
    uint64_t tokens_prompt;
    uint64_t total_tokens;
    
    // Memory
    uint64_t model_memory_bytes;
    uint64_t kv_cache_memory_bytes;
    uint64_t working_memory_bytes;
    uint64_t peak_memory_bytes;
    
    // Cache efficiency
    double kv_cache_hit_rate;
    uint64_t kv_cache_hits;
    uint64_t kv_cache_misses;
} SovereignEngineStats;

// =============================================================================
// Engine Lifecycle
// =============================================================================

// Create engine instance
__declspec(dllexport) SovereignEngineHandle Sovereign_Engine_Create(
    const SovereignLoaderConfig* loader_config,
    const SovereignInferenceConfig* inference_config
);

// Destroy engine
__declspec(dllexport) void Sovereign_Engine_Destroy(SovereignEngineHandle engine);

// Initialize engine (load model, setup caches)
__declspec(dllexport) int Sovereign_Engine_Initialize(
    SovereignEngineHandle engine,
    const char* model_path
);

// Check if engine is ready
__declspec(dllexport) int Sovereign_Engine_IsReady(SovereignEngineHandle engine);

// Get engine statistics
__declspec(dllexport) int Sovereign_Engine_GetStats(
    SovereignEngineHandle engine,
    SovereignEngineStats* stats
);

// =============================================================================
// Session Management
// =============================================================================

// Create inference session
__declspec(dllexport) SovereignSessionHandle Sovereign_Session_Create(
    SovereignEngineHandle engine,
    uint64_t session_id
);

// Destroy session
__declspec(dllexport) void Sovereign_Session_Destroy(SovereignSessionHandle session);

// Reset session (clear KV cache)
__declspec(dllexport) void Sovereign_Session_Reset(SovereignSessionHandle session);

// =============================================================================
// Tokenization
// =============================================================================

// Tokenize text
__declspec(dllexport) int Sovereign_Tokenize(
    SovereignEngineHandle engine,
    const char* text,
    SovereignToken* tokens,
    uint32_t* num_tokens,
    uint32_t max_tokens
);

// Detokenize tokens
__declspec(dllexport) int Sovereign_Detokenize(
    SovereignEngineHandle engine,
    const SovereignToken* tokens,
    uint32_t num_tokens,
    char* text,
    uint32_t max_text_len
);

// Get token string
__declspec(dllexport) const char* Sovereign_GetTokenString(
    SovereignEngineHandle engine,
    SovereignToken token
);

// =============================================================================
// Inference Pipeline
// =============================================================================

// Process prompt (prefill phase)
__declspec(dllexport) int Sovereign_Session_ProcessPrompt(
    SovereignSessionHandle session,
    const SovereignToken* tokens,
    uint32_t num_tokens
);

// Generate single token (decoding phase)
__declspec(dllexport) int Sovereign_Session_GenerateToken(
    SovereignSessionHandle session,
    SovereignGenerationResult* result
);

// Generate complete response
__declspec(dllexport) int Sovereign_Session_Generate(
    SovereignSessionHandle session,
    const char* prompt,
    char* response,
    uint32_t max_response_len,
    uint32_t* num_generated_tokens
);

// =============================================================================
// Streaming Generation
// =============================================================================

typedef void (*SovereignTokenCallback)(
    const SovereignGenerationResult* result,
    void* user_data
);

// Generate with streaming callback
__declspec(dllexport) int Sovereign_Session_GenerateStreaming(
    SovereignSessionHandle session,
    const char* prompt,
    SovereignTokenCallback callback,
    void* user_data,
    uint32_t* num_generated_tokens
);

// =============================================================================
// Sampling
// =============================================================================

// Greedy sampling (argmax)
__declspec(dllexport) SovereignToken Sovereign_Sample_Greedy(
    const float* logits,
    uint32_t vocab_size
);

// Temperature sampling
__declspec(dllexport) SovereignToken Sovereign_Sample_Temperature(
    const float* logits,
    uint32_t vocab_size,
    float temperature
);

// Top-p (nucleus) sampling
__declspec(dllexport) SovereignToken Sovereign_Sample_TopP(
    const float* logits,
    uint32_t vocab_size,
    float top_p,
    float temperature
);

// Top-k sampling
__declspec(dllexport) SovereignToken Sovereign_Sample_TopK(
    const float* logits,
    uint32_t vocab_size,
    uint32_t top_k,
    float temperature
);

// =============================================================================
// Forward Pass (Low-level)
// =============================================================================

// Run single forward pass
__declspec(dllexport) int Sovereign_Forward(
    SovereignSessionHandle session,
    const SovereignToken* tokens,
    uint32_t num_tokens,
    float* logits_output,
    uint32_t vocab_size
);

// Run embedding lookup
__declspec(dllexport) int Sovereign_Embedding_Lookup(
    SovereignSessionHandle session,
    SovereignToken token,
    float* embedding,
    uint32_t embedding_dim
);

// Run transformer layer
__declspec(dllexport) int Sovereign_Transformer_Layer(
    SovereignSessionHandle session,
    uint32_t layer_id,
    float* hidden_states,
    uint32_t seq_len,
    uint32_t hidden_dim
);

// =============================================================================
// MASM Bridge Functions
// =============================================================================

// Dispatch table for MASM kernels
typedef struct SovereignKernelDispatch {
    // Attention kernels
    void (*attention_qk)(const float* q, const float* k, float* scores,
                         uint32_t seq_len, uint32_t head_dim);
    void (*attention_softmax)(float* scores, uint32_t seq_len);
    void (*attention_out)(const float* scores, const float* v, float* out,
                          uint32_t seq_len, uint32_t head_dim);
    
    // FFN kernels
    void (*ffn_silu)(const float* gate, const float* up, float* out,
                     uint32_t hidden_dim);
    void (*ffn_matmul)(const float* a, const float* b, float* c,
                       uint32_t m, uint32_t n, uint32_t k);
    
    // RMS Norm
    void (*rms_norm)(const float* x, const float* weight, float* out,
                     uint32_t hidden_dim, float eps);
    
    // Quantization
    void (*dequantize_q4)(const void* weights, float* out,
                          uint32_t num_weights, float scale);
    void (*quantize_q4)(const float* input, void* out,
                        uint32_t num_weights, float* scale);
} SovereignKernelDispatch;

// Get kernel dispatch table
__declspec(dllexport) const SovereignKernelDispatch* Sovereign_GetKernelDispatch(void);

// Set kernel dispatch table (for testing/custom kernels)
__declspec(dllexport) void Sovereign_SetKernelDispatch(
    const SovereignKernelDispatch* dispatch
);

// =============================================================================
// Debug & Diagnostics
// =============================================================================

// Dump engine state
__declspec(dllexport) void Sovereign_Engine_DumpState(SovereignEngineHandle engine);

// Dump session state
__declspec(dllexport) void Sovereign_Session_DumpState(SovereignSessionHandle session);

// Validate engine integrity
__declspec(dllexport) int Sovereign_Engine_Validate(SovereignEngineHandle engine);

// Get last error
__declspec(dllexport) const char* Sovereign_Engine_GetLastError(SovereignEngineHandle engine);

// Enable debug mode
__declspec(dllexport) void Sovereign_Engine_SetDebugMode(int enable);

#ifdef __cplusplus
}
#endif

#endif // SOVEREIGN_ENGINE_CONTROLLER_H
