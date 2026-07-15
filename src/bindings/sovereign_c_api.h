// =============================================================================
// sovereign_c_api.h
// Phase 22B: C-API Language Bindings
// Clean C interface for cross-language consumption
// =============================================================================

#ifndef SOVEREIGN_C_API_H
#define SOVEREIGN_C_API_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Export Macros
// =============================================================================

#ifdef _WIN32
    #define SOVEREIGN_API __declspec(dllexport)
#else
    #define SOVEREIGN_API __attribute__((visibility("default")))
#endif

// =============================================================================
// Version Information
// =============================================================================

#define SOVEREIGN_API_VERSION_MAJOR 1
#define SOVEREIGN_API_VERSION_MINOR 0
#define SOVEREIGN_API_VERSION_PATCH 0

// =============================================================================
// Opaque Handles
// =============================================================================

typedef struct SovereignEngine* sovereign_engine_t;
typedef struct SovereignSession* sovereign_session_t;
typedef struct SovereignTokenizer* sovereign_tokenizer_t;

// =============================================================================
// Error Codes
// =============================================================================

typedef enum {
    SOVEREIGN_OK = 0,
    SOVEREIGN_ERROR_INVALID_ARGUMENT = -1,
    SOVEREIGN_ERROR_OUT_OF_MEMORY = -2,
    SOVEREIGN_ERROR_MODEL_LOAD_FAILED = -3,
    SOVEREIGN_ERROR_NOT_INITIALIZED = -4,
    SOVEREIGN_ERROR_SESSION_NOT_FOUND = -5,
    SOVEREIGN_ERROR_GENERATION_FAILED = -6,
    SOVEREIGN_ERROR_TOKENIZATION_FAILED = -7,
    SOVEREIGN_ERROR_UNSUPPORTED_OPERATION = -8,
    SOVEREIGN_ERROR_HARDWARE_NOT_AVAILABLE = -9
} sovereign_error_t;

// =============================================================================
// Configuration Structures
// =============================================================================

typedef struct {
    int use_memory_mapping;
    int use_zero_copy;
    int use_prefetch;
    int enable_amx_tiling;
    uint32_t num_threads;
    uint64_t max_memory_bytes;
} sovereign_loader_config_t;

typedef struct {
    uint32_t max_tokens;
    float temperature;
    float top_p;
    uint32_t top_k;
    uint32_t num_threads;
    int use_amx;
    int use_int8;
    int enable_kv_cache;
    uint64_t max_memory_bytes;
} sovereign_inference_config_t;

typedef struct {
    uint64_t tokens_generated;
    uint64_t total_tokens;
    double avg_tokens_per_second;
    double avg_latency_ms;
    uint64_t model_memory_bytes;
    uint64_t kv_cache_memory_bytes;
    double load_time_ms;
} sovereign_stats_t;

typedef struct {
    uint32_t token_id;
    float logit;
    float probability;
    uint32_t generation_index;
    double generation_time_ms;
    int is_eos;
} sovereign_generation_result_t;

// =============================================================================
// Lifecycle Management
// =============================================================================

SOVEREIGN_API sovereign_error_t sovereign_init(void);
SOVEREIGN_API void sovereign_shutdown(void);
SOVEREIGN_API const char* sovereign_version_string(void);
SOVEREIGN_API void sovereign_get_version(int* major, int* minor, int* patch);

// =============================================================================
// Engine Management
// =============================================================================

SOVEREIGN_API sovereign_error_t sovereign_engine_create(
    const sovereign_loader_config_t* loader_config,
    const sovereign_inference_config_t* inference_config,
    sovereign_engine_t* out_engine);

SOVEREIGN_API void sovereign_engine_destroy(sovereign_engine_t engine);

SOVEREIGN_API sovereign_error_t sovereign_engine_load_model(
    sovereign_engine_t engine,
    const char* model_path);

SOVEREIGN_API int sovereign_engine_is_ready(sovereign_engine_t engine);

SOVEREIGN_API sovereign_error_t sovereign_engine_get_stats(
    sovereign_engine_t engine,
    sovereign_stats_t* out_stats);

SOVEREIGN_API const char* sovereign_engine_get_last_error(sovereign_engine_t engine);

// =============================================================================
// Session Management
// =============================================================================

SOVEREIGN_API sovereign_error_t sovereign_session_create(
    sovereign_engine_t engine,
    uint64_t session_id,
    sovereign_session_t* out_session);

SOVEREIGN_API void sovereign_session_destroy(sovereign_session_t session);

SOVEREIGN_API sovereign_error_t sovereign_session_reset(sovereign_session_t session);

// =============================================================================
// Tokenization
// =============================================================================

SOVEREIGN_API sovereign_error_t sovereign_tokenize(
    sovereign_engine_t engine,
    const char* text,
    uint32_t* out_tokens,
    size_t* inout_num_tokens);

SOVEREIGN_API sovereign_error_t sovereign_detokenize(
    sovereign_engine_t engine,
    const uint32_t* tokens,
    size_t num_tokens,
    char* out_text,
    size_t* inout_text_len);

SOVEREIGN_API const char* sovereign_token_to_string(
    sovereign_engine_t engine,
    uint32_t token_id);

// =============================================================================
// Generation
// =============================================================================

SOVEREIGN_API sovereign_error_t sovereign_generate(
    sovereign_session_t session,
    const char* prompt,
    char* out_response,
    size_t* inout_response_len,
    uint32_t* out_num_tokens);

SOVEREIGN_API sovereign_error_t sovereign_generate_token(
    sovereign_session_t session,
    sovereign_generation_result_t* out_result);

SOVEREIGN_API sovereign_error_t sovereign_process_prompt(
    sovereign_session_t session,
    const uint32_t* tokens,
    size_t num_tokens);

// =============================================================================
// Sampling Configuration
// =============================================================================

SOVEREIGN_API sovereign_error_t sovereign_set_temperature(
    sovereign_session_t session,
    float temperature);

SOVEREIGN_API sovereign_error_t sovereign_set_top_p(
    sovereign_session_t session,
    float top_p);

SOVEREIGN_API sovereign_error_t sovereign_set_top_k(
    sovereign_session_t session,
    uint32_t top_k);

// =============================================================================
// Streaming Callbacks
// =============================================================================

typedef void (*sovereign_token_callback_t)(
    uint32_t token_id,
    const char* token_text,
    void* user_data);

SOVEREIGN_API sovereign_error_t sovereign_generate_streaming(
    sovereign_session_t session,
    const char* prompt,
    sovereign_token_callback_t callback,
    void* user_data,
    uint32_t* out_num_tokens);

// =============================================================================
// Batch Processing
// =============================================================================

SOVEREIGN_API sovereign_error_t sovereign_generate_batch(
    sovereign_engine_t engine,
    const char** prompts,
    size_t num_prompts,
    char** out_responses,
    size_t* response_lens,
    uint32_t* out_num_tokens);

// =============================================================================
// Hardware Information
// =============================================================================

typedef struct {
    int has_avx2;
    int has_avx512;
    int has_amx;
    int num_physical_cores;
    int num_logical_cores;
    uint64_t total_memory_bytes;
    uint64_t available_memory_bytes;
} sovereign_hardware_info_t;

SOVEREIGN_API sovereign_error_t sovereign_get_hardware_info(
    sovereign_hardware_info_t* out_info);

// =============================================================================
// Memory Management
// =============================================================================

SOVEREIGN_API sovereign_error_t sovereign_get_memory_usage(
    sovereign_engine_t engine,
    uint64_t* out_model_bytes,
    uint64_t* out_kv_cache_bytes,
    uint64_t* out_working_bytes);

SOVEREIGN_API sovereign_error_t sovereign_compact_memory(
    sovereign_engine_t engine);

// =============================================================================
// Debug & Diagnostics
// =============================================================================

SOVEREIGN_API void sovereign_dump_engine_state(sovereign_engine_t engine);
SOVEREIGN_API void sovereign_dump_session_state(sovereign_session_t session);
SOVEREIGN_API void sovereign_set_log_level(int level);

#ifdef __cplusplus
}
#endif

#endif // SOVEREIGN_C_API_H
