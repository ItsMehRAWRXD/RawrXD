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
    MG_ERROR_KV_CACHE_MISMATCH = -8,
    MG_ERROR_CANCELLED = -9
} mg_error_t;

// Outcome of the last mg_context_generate()/mg_context_generate_text() on a
// context (RAWRXD_STREAM_CANCEL_001). Tokens are streamed to the callback
// while decoding runs; a false return from the callback stops the decode
// immediately (no further forward pass) and terminates the stream.
typedef enum {
    MG_GENERATE_COMPLETED = 0,     // every requested token was produced
    MG_GENERATE_CANCELLED = 1,     // the callback returned false (or the terminator)
    MG_GENERATE_EXECUTION_FAILED = 2 // a forward pass failed
} mg_generate_status_t;

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

// Authority-reported model facts (DEEP2_RUNTIME_OWNERSHIP_001). These are the
// single source of truth for anything describing the loaded model; clients
// must not re-derive them from their own GGUF mappings.
MG_RUNTIME_API size_t mg_model_layer_count(const mg_model_t* model);
// Size of the GGUF file this session mapped, in bytes (0 when unavailable).
MG_RUNTIME_API uint64_t mg_model_file_bytes(const mg_model_t* model);
// Cached floats per position across all layers in the authority's KV cache.
MG_RUNTIME_API size_t mg_context_kv_floats_per_position(const mg_context_t* context);

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

// Outcome of the last generate() call and, when it failed with
// MG_GENERATE_EXECUTION_FAILED, the IR op id that failed (0 otherwise).
MG_RUNTIME_API mg_generate_status_t mg_context_last_generate_status(
    const mg_context_t* context);

MG_RUNTIME_API uint32_t mg_context_last_failed_op(
    const mg_context_t* context);

// Forward passes (prefill + decode) executed since the context was created,
// cumulative across calls. Exposes that a cancelled stream costs no extra
// forward pass: the count stops advancing at the cancellation point.
MG_RUNTIME_API uint32_t mg_context_forward_passes(
    const mg_context_t* context);

// Token text (utf-8, sentencepiece escapes already resolved), null-terminated.
// Returns false when the id is out of range or the vocab is unavailable.
MG_RUNTIME_API bool mg_model_token_text(
    const mg_model_t* model,
    uint32_t token_id,
    char* out_buf,
    size_t out_buf_size
);

// Detokenize ids -> unescaped UTF-8 text: vocab pieces with the GPT-2
// byte-to-Unicode escapes reversed (llama.cpp detokenize parity for
// gpt2/deepseek-llm vocab). out_size reports the required size (including
// the null terminator) when the buffer is too small; returns the length
// written (excluding the null terminator), or 0 when the buffer is too small.
MG_RUNTIME_API size_t mg_model_detokenize(
    const mg_model_t* model,
    const uint32_t* token_ids,
    size_t token_count,
    char* out_buf,
    size_t* out_size
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