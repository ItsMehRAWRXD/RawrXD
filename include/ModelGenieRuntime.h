// ModelGenieRuntime.h - C API for ModelGenie IR Execution Runtime
// This is the public interface for RawrXDCore.dll to use the ModelGenie IR executor

#pragma once

#include <cstdint>
#include <cstddef>

#ifdef _WIN32
#define MG_RUNTIME_API __declspec(dllexport)
#else
#define MG_RUNTIME_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handles
typedef struct mg_model_t mg_model_t;
typedef struct mg_context_t mg_context_t;

// Error codes
typedef enum {
    MG_SUCCESS = 0,
    MG_ERROR_INVALID_ARGUMENT = -1,
    MG_ERROR_FILE_NOT_FOUND = -2,
    MG_ERROR_GGUF_PARSE = -3,
    MG_ERROR_OUT_OF_MEMORY = -4,
    MG_ERROR_EXECUTION_FAILED = -5,
    MG_ERROR_INVALID_STATE = -6,
    MG_ERROR_KV_CACHE_FULL = -7,
    MG_ERROR_KV_CACHE_MISMATCH = -8
} mg_error_t;

// Model configuration
typedef struct {
    size_t max_seq_len;
    bool use_kv_cache;
    size_t num_threads;
} mg_model_config_t;

// Generation configuration
typedef struct {
    size_t max_tokens;
    float temperature;
    float top_p;
    int top_k;
    float repeat_penalty;
    uint64_t seed;
} mg_generation_config_t;

// Callback for token generation
// Return true to continue, false to stop
typedef bool (*mg_token_callback_t)(uint32_t token_id, const char* token_text, void* user_data);

// Log callback
typedef void (*mg_log_callback_t)(int level, const char* message, void* user_data);

// Log levels
typedef enum {
    MG_LOG_DEBUG = 0,
    MG_LOG_INFO = 1,
    MG_LOG_WARNING = 2,
    MG_LOG_ERROR = 3
} mg_log_level_t;

// Model loading
MG_RUNTIME_API mg_error_t mg_model_load(
    const char* gguf_path,
    const mg_model_config_t* config,
    mg_model_t** out_model
);

MG_RUNTIME_API void mg_model_free(mg_model_t* model);

// Context management
MG_RUNTIME_API mg_error_t mg_context_create(
    mg_model_t* model,
    mg_context_t** out_context
);

MG_RUNTIME_API void mg_context_free(mg_context_t* context);

// Inference
MG_RUNTIME_API mg_error_t mg_context_generate(
    mg_context_t* context,
    const uint32_t* prompt_tokens,
    size_t prompt_token_count,
    const mg_generation_config_t* config,
    mg_token_callback_t callback,
    void* callback_user_data
);

// Model introspection
MG_RUNTIME_API size_t mg_model_vocab_size(const mg_model_t* model);
MG_RUNTIME_API uint32_t mg_model_eos_token_id(const mg_model_t* model);
MG_RUNTIME_API uint32_t mg_model_bos_token_id(const mg_model_t* model);
MG_RUNTIME_API size_t mg_model_max_seq_len(const mg_model_t* model);
MG_RUNTIME_API size_t mg_model_embedding_dim(const mg_model_t* model);

// Context state
MG_RUNTIME_API size_t mg_context_position(const mg_context_t* context);
MG_RUNTIME_API void mg_context_reset(mg_context_t* context);

// Logits access (after generation)
MG_RUNTIME_API const float* mg_context_logits(const mg_context_t* context, size_t* out_count);

// Logging
MG_RUNTIME_API void mg_set_log_callback(mg_log_callback_t callback, void* user_data);
MG_RUNTIME_API void mg_set_log_level(mg_log_level_t level);

// Version info
MG_RUNTIME_API const char* mg_runtime_version(void);

// ---- Additional production-runtime surface --------------------------------

// Last tokens produced by mg_context_generate().
MG_RUNTIME_API mg_error_t mg_context_last_tokens(
    const mg_context_t* context,
    uint32_t* out_tokens,
    size_t out_capacity,
    size_t* out_count
);

// Token text (utf-8, sentencepiece escapes already resolved), null-terminated.
// Returns false when the id is out of range or the vocab is unavailable.
MG_RUNTIME_API bool mg_model_token_text(
    const mg_model_t* model,
    uint32_t token_id,
    char* out_buf,
    size_t out_buf_size
);

// SentencePiece text -> token ids. in_out_count holds buffer capacity on entry
// and receives the token count on exit (including the required capacity when
// the supplied buffer is too small).
MG_RUNTIME_API mg_error_t mg_model_tokenize(
    mg_model_t* model,
    const char* text,
    uint32_t* out_tokens,
    size_t* in_out_count
);

// Prompt text -> generated token ids in one call (tokenize + generate).
MG_RUNTIME_API mg_error_t mg_context_generate_text(
    mg_context_t* context,
    const char* prompt_text,
    const mg_generation_config_t* config,
    mg_token_callback_t callback,
    void* callback_user_data
);

// Prompt tokens -> generated token ids. Non-volatile variant of
// mg_context_generate() that simply returns the ids it produced.
MG_RUNTIME_API mg_error_t mg_context_capture_tokens(
    mg_context_t* context,
    const uint32_t* prompt_tokens,
    size_t prompt_token_count,
    uint32_t max_tokens,
    uint32_t* out_tokens,
    size_t out_capacity,
    size_t* out_count
);

// Prefill a prompt sequence and return the LM-head logits of the final
// position without generating. Used by one-token parity checks.
MG_RUNTIME_API mg_error_t mg_context_eval_buffer(
    mg_context_t* context,
    const uint32_t* prompt_tokens,
    size_t prompt_token_count,
    float* out_logits,
    size_t* in_out_count
);

// Number of tokens produced by the last successful generation.
MG_RUNTIME_API size_t mg_context_token_count(const mg_context_t* context);

// Execute exactly one forward step. Kept so the DLL can prove one-token
// equivalence against the standalone harness.
MG_RUNTIME_API mg_error_t mg_context_eval(
    mg_context_t* context,
    uint32_t token_id,
    float* out_logits,
    size_t* in_out_logits
);

// True when the last Execute() dispatched every one of the IR operations.
MG_RUNTIME_API uint32_t mg_context_ops_dispatched(const mg_context_t* context);
MG_RUNTIME_API uint32_t mg_context_ops_skipped(const mg_context_t* context);
MG_RUNTIME_API uint32_t mg_context_ops_visited(const mg_context_t* context);

#ifdef __cplusplus
}
#endif