// sovereign_unified_model_loader.h - Unified Model Loading Interface
// Integrates GGUF loader, inference engine, and streaming
// NO DEPENDENCIES - Pure Win32 API

#ifndef SOVEREIGN_UNIFIED_MODEL_LOADER_H
#define SOVEREIGN_UNIFIED_MODEL_LOADER_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// CONFIGURATION
// ============================================================================

#define SOVEREIGN_MAX_MODELS          16
#define SOVEREIGN_MAX_CONTEXT_LENGTH   131072
#define SOVEREIGN_MAX_TOKENS           8192
#define SOVEREIGN_MAX_BATCH_SIZE       512

// ============================================================================
// ENUMS
// ============================================================================

typedef enum {
    SOVEREIGN_BACKEND_GGUF = 0,      // Local GGUF file
    SOVEREIGN_BACKEND_OLLAMA,        // Ollama API
    SOVEREIGN_BACKEND_OPENAI,        // OpenAI API
    SOVEREIGN_BACKEND_ANTHROPIC,     // Anthropic API
    SOVEREIGN_BACKEND_CUSTOM         // Custom HTTP endpoint
} SovereignBackendType;

typedef enum {
    SOVEREIGN_QUANT_F32 = 0,
    SOVEREIGN_QUANT_F16,
    SOVEREIGN_QUANT_Q4_0,
    SOVEREIGN_QUANT_Q4_1,
    SOVEREIGN_QUANT_Q5_0,
    SOVEREIGN_QUANT_Q5_1,
    SOVEREIGN_QUANT_Q8_0,
    SOVEREIGN_QUANT_Q8_1,
    SOVEREIGN_QUANT_Q2_K,
    SOVEREIGN_QUANT_Q3_K,
    SOVEREIGN_QUANT_Q4_K,
    SOVEREIGN_QUANT_Q5_K,
    SOVEREIGN_QUANT_Q6_K,
    SOVEREIGN_QUANT_Q8_K
} SovereignQuantType;

typedef enum {
    SOVEREIGN_STATUS_OK = 0,
    SOVEREIGN_STATUS_ERROR,
    SOVEREIGN_STATUS_LOADING,
    SOVEREIGN_STATUS_READY,
    SOVEREIGN_STATUS_INFERRING,
    SOVEREIGN_STATUS_STREAMING,
    SOVEREIGN_STATUS_CANCELLED
} SovereignStatus;

typedef enum {
    SOVEREIGN_SAMPLER_GREEDY = 0,
    SOVEREIGN_SAMPLER_TOP_P,
    SOVEREIGN_SAMPLER_TOP_K,
    SOVEREIGN_SAMPLER_TEMPERATURE,
    SOVEREIGN_SAMPLER_MIN_P,
    SOVEREIGN_SAMPLER_TYPICAL
} SovereignSamplerType;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

typedef struct {
    uint32_t n_vocab;
    uint32_t n_embd;
    uint32_t n_head;
    uint32_t n_head_kv;
    uint32_t n_layer;
    uint32_t n_ctx;
    uint32_t n_ff;
    float rope_freq_base;
    float rope_freq_scale;
    char architecture[64];
    char name[256];
    char description[512];
} SovereignModelConfig;

typedef struct {
    void* hFile;
    void* hMapping;
    void* data;
    uint64_t size;
    SovereignModelConfig config;
    SovereignQuantType quant_type;
    bool loaded;
} SovereignModel;

typedef struct {
    float* logits;
    int32_t* tokens;
    int n_tokens;
    int n_past;
    float temperature;
    float top_p;
    int top_k;
    int max_new_tokens;
    SovereignSamplerType sampler;
} SovereignInferenceState;

typedef struct {
    void* token_embeddings;
    void* output_weight;
    void* output_norm;
    void* layers;
    int n_layers;
} SovereignModelWeights;

typedef struct {
    float* k_cache;
    float* v_cache;
    int n_ctx;
    int n_embd;
    int n_head;
    int n_layer;
    int pos;
} SovereignKVCache;

// Streaming callback
typedef void (*SovereignStreamCallback)(const char* token, void* user_data);

// Progress callback
typedef void (*SovereignProgressCallback)(float progress, const char* status, void* user_data);

// ============================================================================
// API FUNCTIONS
// ============================================================================

// Initialization
SOVEREIGN_API SovereignStatus sovereign_init(void);
SOVEREIGN_API void sovereign_cleanup(void);

// Model management
SOVEREIGN_API SovereignStatus sovereign_load_model(
    const wchar_t* path,
    SovereignModel** model,
    SovereignProgressCallback progress,
    void* user_data
);

SOVEREIGN_API void sovereign_unload_model(SovereignModel* model);
SOVEREIGN_API SovereignStatus sovereign_get_model_config(
    const SovereignModel* model,
    SovereignModelConfig* config
);

// Inference
SOVEREIGN_API SovereignStatus sovereign_inference(
    SovereignModel* model,
    const char* prompt,
    char** response,
    int max_tokens,
    float temperature,
    float top_p
);

SOVEREIGN_API SovereignStatus sovereign_inference_stream(
    SovereignModel* model,
    const char* prompt,
    SovereignStreamCallback callback,
    void* user_data,
    int max_tokens,
    float temperature,
    float top_p
);

SOVEREIGN_API SovereignStatus sovereign_cancel_inference(SovereignModel* model);

// Tokenization
SOVEREIGN_API int sovereign_tokenize(
    SovereignModel* model,
    const char* text,
    int32_t** tokens
);

SOVEREIGN_API char* sovereign_detokenize(
    SovereignModel* model,
    const int32_t* tokens,
    int n_tokens
);

// KV Cache management
SOVEREIGN_API SovereignStatus sovereign_kv_cache_init(
    SovereignModel* model,
    int n_ctx
);

SOVEREIGN_API void sovereign_kv_cache_free(SovereignModel* model);
SOVEREIGN_API SovereignStatus sovereign_kv_cache_clear(SovereignModel* model);

// Batch inference
SOVEREIGN_API SovereignStatus sovereign_batch_inference(
    SovereignModel* model,
    const int32_t* tokens,
    int n_tokens,
    float** logits
);

// Utility functions
SOVEREIGN_API const char* sovereign_status_string(SovereignStatus status);
SOVEREIGN_API const char* sovereign_quant_string(SovereignQuantType quant);
SOVEREIGN_API uint64_t sovereign_get_model_size(const SovereignModel* model);
SOVEREIGN_API bool sovereign_is_model_loaded(const SovereignModel* model);

#ifdef __cplusplus
}
#endif

#endif // SOVEREIGN_UNIFIED_MODEL_LOADER_H